#!/usr/bin/env python3
"""Build the pinned, offline Semgrep Community security rule pack."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


RULE_SOURCE_PATH = "tests/semgrep-rules"
RULE_SOURCE_REPOSITORY = "https://github.com/returntocorp/semgrep-rules"
EXPECTED_CONFIG_FILE_COUNT = 1603
EXPECTED_RULE_COUNT = 1620
MAX_RULE_FILE_BYTES = 1024 * 1024
MAX_RULE_PACK_BYTES = 16 * 1024 * 1024
TEST_FILE_ENDINGS = (
    ".test.yaml",
    ".test.yml",
    ".fixed.test.yaml",
    ".fixed.test.yml",
)


@dataclass(frozen=True)
class LockedSource:
    repository: str
    revision: str
    digest: str
    size: int
    archive: str


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def load_locked_source(lock_path: Path) -> LockedSource:
    matches: list[LockedSource] = []
    for raw_line in lock_path.read_text(encoding="utf-8").splitlines():
        if not raw_line or raw_line.startswith("#"):
            continue
        fields = raw_line.split("|")
        if len(fields) != 6:
            raise ValueError(f"invalid Semgrep submodule lock record: {raw_line}")
        path, repository, revision, digest, size_text, archive = fields
        if path != RULE_SOURCE_PATH:
            continue
        if (
            repository != RULE_SOURCE_REPOSITORY
            or not re.fullmatch(r"[0-9a-f]{40}", revision)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
            or not re.fullmatch(r"[1-9][0-9]*", size_text)
            or not re.fullmatch(r"[a-z0-9_.-]+\.tar\.gz", archive)
        ):
            raise ValueError("the pinned semgrep-rules lock record is invalid")
        matches.append(LockedSource(repository, revision, digest, int(size_text), archive))
    if len(matches) != 1:
        raise ValueError("the lock must contain exactly one semgrep-rules source record")
    return matches[0]


def is_selected_rule_path(relative_path: PurePosixPath) -> bool:
    if relative_path.suffix not in {".yaml", ".yml"}:
        return False
    if relative_path.name.endswith(TEST_FILE_ENDINGS):
        return False
    parts = relative_path.parts
    # Semgrep CE 1.174.0 advertises Apex but requires an unavailable proprietary
    # parser plugin when these rules are loaded. Keep the offline OSS pack free
    # of rules the embedded engine cannot execute.
    if parts[0] == "apex":
        return False
    return (
        "security" in parts
        or "secrets" in parts
        or parts[:2] == ("ai", "ai-best-practices")
    )


def validate_rule_text(relative_path: PurePosixPath, data: bytes) -> int:
    if not data or len(data) > MAX_RULE_FILE_BYTES or b"\x00" in data:
        raise ValueError(f"invalid rule file size or content: {relative_path}")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"rule file is not UTF-8: {relative_path}") from error
    required_patterns = {
        "rules": r"(?m)^rules:\s*$",
        "rule id": r"(?m)^(?:\s*-\s+|\s+)id:\s*[^\s#]",
        "languages": r"(?m)^\s+languages:\s*",
        "message": r"(?m)^\s+message:\s*",
        "severity": r"(?m)^\s+severity:\s*(?:INFO|WARNING|ERROR)\s*$",
        "metadata": r"(?m)^\s+metadata:\s*$",
    }
    for label, pattern in required_patterns.items():
        if re.search(pattern, text) is None:
            raise ValueError(f"selected YAML lacks {label}: {relative_path}")
    categories = re.findall(r"(?m)^\s+category:\s*([A-Za-z0-9_-]+)\s*$", text)
    if not categories:
        raise ValueError(f"selected YAML lacks an upstream category: {relative_path}")
    severities = re.findall(r"(?m)^\s+severity:\s*(?:INFO|WARNING|ERROR)\s*$", text)
    if len(categories) != len(severities):
        raise ValueError(f"selected YAML has inconsistent rule metadata: {relative_path}")
    if not all(category == "security" for category in categories):
        return 0
    return len(categories)


def safe_relative_member(name: str, expected_root: str) -> PurePosixPath | None:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"unsafe path in semgrep-rules archive: {name}")
    if path.parts[0] != expected_root:
        raise ValueError(f"unexpected root in semgrep-rules archive: {name}")
    if len(path.parts) == 1:
        return None
    relative = PurePosixPath(*path.parts[1:])
    if any(not part or part in {".", ".."} for part in relative.parts):
        raise ValueError(f"unsafe relative path in semgrep-rules archive: {name}")
    return relative


def build_rule_pack(
    archive_path: Path,
    lock_path: Path,
    output_path: Path,
    source_date_epoch: int,
) -> dict[str, object]:
    if source_date_epoch < 0:
        raise ValueError("source date epoch must be non-negative")
    locked = load_locked_source(lock_path)
    archive_size = archive_path.stat().st_size
    archive_digest = sha256_file(archive_path)
    if archive_size != locked.size or f"sha256:{archive_digest}" != locked.digest:
        raise ValueError("semgrep-rules archive does not match the pinned lock")
    if output_path.exists():
        raise ValueError("rule-pack output path already exists")

    expected_root = f"semgrep-rules-{locked.revision}"
    selected: dict[str, bytes] = {}
    selected_rule_count = 0
    license_bytes: bytes | None = None
    readme_bytes: bytes | None = None
    total_bytes = 0
    with tarfile.open(archive_path, mode="r:gz") as archive:
        for member in archive:
            relative = safe_relative_member(member.name, expected_root)
            if relative is None or member.isdir():
                continue
            if not member.isfile():
                raise ValueError(f"non-regular archive member is not accepted: {member.name}")
            if relative.as_posix() in {"LICENSE", "README.md"}:
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ValueError(f"could not read source record: {relative}")
                value = extracted.read(MAX_RULE_FILE_BYTES + 1)
                if len(value) > MAX_RULE_FILE_BYTES:
                    raise ValueError(f"source record is too large: {relative}")
                if relative.as_posix() == "LICENSE":
                    license_bytes = value
                else:
                    readme_bytes = value
                continue
            if not is_selected_rule_path(relative):
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ValueError(f"could not read selected rule: {relative}")
            value = extracted.read(MAX_RULE_FILE_BYTES + 1)
            rule_count = validate_rule_text(relative, value)
            if rule_count == 0:
                continue
            key = relative.as_posix()
            if key in selected:
                raise ValueError(f"duplicate selected rule path: {key}")
            selected[key] = value
            selected_rule_count += rule_count
            total_bytes += len(value)
            if total_bytes > MAX_RULE_PACK_BYTES:
                raise ValueError("selected Semgrep rule pack exceeds its size bound")

    if len(selected) != EXPECTED_CONFIG_FILE_COUNT:
        raise ValueError(
            f"expected {EXPECTED_CONFIG_FILE_COUNT} selected rule files, found {len(selected)}"
        )
    if selected_rule_count != EXPECTED_RULE_COUNT:
        raise ValueError(
            f"expected {EXPECTED_RULE_COUNT} selected rules, found {selected_rule_count}"
        )
    if license_bytes is None or readme_bytes is None:
        raise ValueError("semgrep-rules license or README is missing")

    rules_path = output_path / "rules"
    rules_path.mkdir(parents=True)
    manifest_lines: list[str] = []
    for relative_text in sorted(selected):
        value = selected[relative_text]
        destination = rules_path.joinpath(*PurePosixPath(relative_text).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(value)
        manifest_lines.append(f"{sha256_bytes(value)}  {relative_text}\n")

    manifest = "".join(manifest_lines).encode("utf-8")
    (output_path / "RULES.sha256").write_bytes(manifest)
    (output_path / "LICENSE").write_bytes(license_bytes)
    (output_path / "UPSTREAM-README.md").write_bytes(readme_bytes)
    metadata: dict[str, object] = {
        "schema_version": "ai-security-scanner.semgrep-rule-pack/v1",
        "upstream": {
            "repository": locked.repository,
            "revision": locked.revision,
            "archive": locked.archive,
            "archive_sha256": f"sha256:{archive_digest}",
        },
        "selection": {
            "included_path_components": ["security", "secrets"],
            "included_path_prefixes": ["ai/ai-best-practices/"],
            "required_metadata_category": "security",
            "excluded_filename_markers": [".test.", ".fixed.test."],
            "excluded_path_prefixes": ["apex/"],
            "rule_files": len(selected),
            "validated_rules": selected_rule_count,
            "rule_bytes": total_bytes,
        },
        "rules_manifest_sha256": f"sha256:{sha256_bytes(manifest)}",
    }
    (output_path / "PACK-METADATA.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    for path in sorted(output_path.rglob("*"), reverse=True):
        os.chmod(path, 0o755 if path.is_dir() else 0o644)
        os.utime(path, (source_date_epoch, source_date_epoch), follow_symlinks=False)
    os.chmod(output_path, 0o755)
    os.utime(output_path, (source_date_epoch, source_date_epoch), follow_symlinks=False)
    return metadata


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        metadata = build_rule_pack(
            args.archive, args.lock, args.output, args.source_date_epoch
        )
    except (OSError, ValueError, tarfile.TarError) as error:
        print(f"could not build Semgrep rule pack: {error}", file=sys.stderr)
        return 1
    selection = metadata["selection"]
    assert isinstance(selection, dict)
    print(
        f"Built {selection['rule_files']} upstream Semgrep configs "
        f"({selection['validated_rules']} rules)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
