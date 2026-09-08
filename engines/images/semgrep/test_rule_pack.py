#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SEMGREP_DIR = Path(__file__).resolve().parent
ROOT = SEMGREP_DIR.parents[2]
MODULE_SPEC = importlib.util.spec_from_file_location(
    "semgrep_rule_pack", SEMGREP_DIR / "build_rule_pack.py"
)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
RULE_PACK = importlib.util.module_from_spec(MODULE_SPEC)
sys.modules[MODULE_SPEC.name] = RULE_PACK
MODULE_SPEC.loader.exec_module(RULE_PACK)


class RulePackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.archive = (
            ROOT
            / ".engine-cache/offline/semgrep-submodules/tests__semgrep-rules.tar.gz"
        )
        self.lock = SEMGREP_DIR / "submodules.lock"

    def build(self, parent: Path) -> Path:
        output = parent / "pack"
        RULE_PACK.build_rule_pack(self.archive, self.lock, output, 1787250577)
        return output

    def test_pack_is_pinned_broad_and_reproducible(self) -> None:
        with (
            tempfile.TemporaryDirectory() as first_temp,
            tempfile.TemporaryDirectory() as second_temp,
        ):
            first = self.build(Path(first_temp))
            second = self.build(Path(second_temp))
            first_manifest = (first / "RULES.sha256").read_bytes()
            second_manifest = (second / "RULES.sha256").read_bytes()
            self.assertEqual(first_manifest, second_manifest)
            self.assertEqual(len(first_manifest.splitlines()), 1603)
            self.assertEqual(
                hashlib.sha256(first_manifest).hexdigest(),
                "ace912dd7a12516d60f0b37bf28b51a7c7c5384cdc79bb290892b0345f153ec8",
            )
            metadata = json.loads((first / "PACK-METADATA.json").read_text())
            self.assertEqual(metadata["selection"]["validated_rules"], 1620)
            self.assertEqual(
                metadata["upstream"]["revision"],
                "947bf05744d4c95153173a24879f30b3ba1a65aa",
            )
            self.assertEqual(
                (first / "LICENSE").read_text(encoding="utf-8"),
                "Semgrep Rules License v1.0. For more details, visit "
                "https://semgrep.dev/legal/rules-license\n",
            )
            self.assertIn("# semgrep-rules", (first / "UPSTREAM-README.md").read_text())
            for line in first_manifest.decode("utf-8").splitlines():
                digest, relative = line.split("  ", 1)
                self.assertEqual(
                    hashlib.sha256((first / "rules" / relative).read_bytes()).hexdigest(),
                    digest,
                )

    def test_pack_retains_representative_upstream_security_rules(self) -> None:
        expected = {
            "python/django/security/injection/command/command-injection-os-system.yaml": (
                "python",
                "command-injection-os-system",
            ),
            "javascript/express/security/audit/xss/direct-response-write.yaml": (
                "javascript",
                "direct-response-write",
            ),
            "java/spring/security/audit/spel-injection.yaml": ("java", "spel-injection"),
            "go/lang/security/audit/crypto/math_random.yaml": ("go", "math-random-used"),
            "terraform/aws/security/aws-athena-database-unencrypted.yaml": (
                "hcl",
                "aws-athena-database-unencrypted",
            ),
            "yaml/kubernetes/security/privileged-container.yaml": (
                "yaml",
                "privileged-container",
            ),
            "dockerfile/security/missing-user.yaml": (
                "dockerfile",
                "missing-user",
            ),
            "ai/ai-best-practices/mcp-command-injection/mcp-command-injection.yaml": (
                "python",
                "mcp-command-injection-python",
            ),
        }
        with tempfile.TemporaryDirectory() as temp:
            pack = self.build(Path(temp)) / "rules"
            for relative, (language, rule_id) in expected.items():
                text = (pack / relative).read_text(encoding="utf-8")
                self.assertRegex(text, rf"(?m)^\s*-\s+id:\s*{rule_id}\s*$")
                self.assertIn(language, text)
                self.assertRegex(text, r"(?m)^\s+category:\s*security\s*$")

    def test_pack_excludes_test_and_non_security_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            rules = self.build(Path(temp)) / "rules"
            relative_paths = [path.relative_to(rules).as_posix() for path in rules.rglob("*")]
            self.assertFalse(any(".test." in path for path in relative_paths))
            self.assertFalse(any(path.startswith(".github/") for path in relative_paths))
            self.assertFalse(any(path.startswith("apex/") for path in relative_paths))
            self.assertFalse(any(path.startswith("stats/") for path in relative_paths))
            self.assertFalse((rules / "template.yaml").exists())


if __name__ == "__main__":
    unittest.main()
