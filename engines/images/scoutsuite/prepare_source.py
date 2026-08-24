#!/usr/bin/env python3
"""Apply the audited JSON-only ScoutSuite profile without a shell."""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path


EXPECTED = {
    "ScoutSuite/output/result_encoder.py": "b97c3dca0910fda2ebf88ccd26c7ad6dc934434398868bc18b56406cbb323fec",
    "ScoutSuite/__main__.py": "234d77dd44e629e04dc142e0d2ad36ad85447e9e415bace081fcbc3b3ec41f44",
    "requirements.txt": "2bc03e2880795dc9e63ca061e1fcc516eb235b0208b0871ebb413e6739f5e6ff",
}

REPLACEMENTS = {
    "ScoutSuite/output/result_encoder.py": (
        ("from sqlitedict import SqliteDict\n", ""),
        (
            "        return SqliteDict(config_path, autocommit=True).data\n",
            "        from sqlitedict import SqliteDict\n"
            "        return SqliteDict(config_path, autocommit=True).data\n",
        ),
        (
            "                return SqliteDict(config_filename)\n",
            "                from sqlitedict import SqliteDict\n"
            "                return SqliteDict(config_filename)\n",
        ),
    ),
    "ScoutSuite/__main__.py": (
        ("from ScoutSuite.core.server import Server\n", ""),
        (
            "        if database_name:\n"
            "            database_file, _ = get_filename('RESULTS', report_name, report_dir, file_extension=\"db\")\n",
            "        if database_name:\n"
            "            from ScoutSuite.core.server import Server\n"
            "            database_file, _ = get_filename('RESULTS', report_name, report_dir, file_extension=\"db\")\n",
        ),
    ),
    "requirements.txt": (
        ("sqlitedict>=1.6.0\n", ""),
        ("cherrypy>=18.1.0\n", ""),
        ("cherrypy-cors>=1.6\n", ""),
    ),
}


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def transform(root: Path) -> None:
    for relative, expected in EXPECTED.items():
        path = root / relative
        content = path.read_bytes()
        if digest(content) != expected:
            raise SystemExit(f"unexpected upstream content: {relative}")
        text = content.decode("utf-8")
        for old, new in REPLACEMENTS[relative]:
            if text.count(old) != 1:
                raise SystemExit(f"audited replacement does not match once: {relative}")
            text = text.replace(old, new)
        path.write_text(text, encoding="utf-8", newline="\n")


def normalize(root: Path, epoch: int) -> None:
    for path in [root, *sorted(root.rglob("*"))]:
        if path.is_symlink():
            target = os.readlink(path)
            resolved = (path.parent / target).resolve(strict=False)
            if os.path.isabs(target) or root not in [resolved, *resolved.parents]:
                raise SystemExit(f"source symlink escapes its archive: {path.relative_to(root)}")
        os.utime(path, (epoch, epoch), follow_symlinks=False)


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: prepare_source.py SOURCE_ROOT SOURCE_DATE_EPOCH")
    root = Path(sys.argv[1]).resolve(strict=True)
    epoch = int(sys.argv[2])
    if not root.is_dir() or epoch <= 0:
        raise SystemExit("source root or epoch is invalid")
    transform(root)
    normalize(root, epoch)


if __name__ == "__main__":
    main()
