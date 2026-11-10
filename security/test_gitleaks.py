"""Regression tests for the secret scanner's coverage boundary."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from security import run as gate


class GitleaksTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.out = Path(self.directory.name)
        self.paths = []
        self.commands = []
        self.patch_out = patch.object(gate, "OUT", self.out)
        self.patch_out.start()
        self.addCleanup(self.patch_out.stop)
        self.patch_have = patch.object(gate, "have", return_value=True)
        self.patch_have.start()
        self.addCleanup(self.patch_have.stop)

    def scan(self, code=0, report="[]", git_range=None):
        def invoke(cmd, **kwargs):
            self.commands.append(cmd)
            path = Path(cmd[cmd.index("--report-path") + 1])
            self.paths.append(path)
            self.assertFalse(path.exists())
            if report is not None:
                path.write_text(report)
            return code, "", "scan diagnostic"
        with patch.object(gate, "run", side_effect=invoke):
            return gate.check_gitleaks(git_range)

    def test_failed_scan_cannot_reuse_stale_clean_report(self):
        (self.out / "gitleaks.json").write_text("[]")
        for code in (1, 124, 127):
            with self.subTest(code=code):
                self.assertEqual(self.scan(code, None).status, "failed")

    def test_failed_scan_rejects_even_current_parseable_report(self):
        self.assertEqual(self.scan(1).status, "failed")

    def test_success_requires_valid_current_report(self):
        for report in (None, "", "{", "null", "{}", "[null]"):
            with self.subTest(report=report):
                self.assertEqual(self.scan(report=report).status, "failed")

    def test_successful_scans_use_unique_paths_and_preserve_range(self):
        for _ in range(2):
            result = self.scan(git_range="A..B")
            self.assertEqual(result.status, "ok")
            self.assertEqual(result.findings, [])
            self.assertEqual(self.commands[-1][-3:], ["--log-opts", "A..B", "."])
        self.assertNotEqual(*self.paths)
        self.assertTrue(all(not path.parent.exists() for path in self.paths))

    def test_successful_scan_still_reports_secrets(self):
        result = self.scan(report=json.dumps([{
            "RuleID": "test-rule", "Commit": "a" * 40,
            "Description": "synthetic fixture", "File": "fixture.txt", "StartLine": 3,
        }]))
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].severity, "critical")
        self.assertEqual(result.findings[0].path, "fixture.txt")

    def test_failed_scan_blocks_gate_and_reports_coverage_gap(self):
        failed = gate.ToolResult("gitleaks", "failed", "scan failed")
        with patch.object(gate, "check_gitleaks", return_value=failed), \
                patch.object(gate.sys, "argv", ["run.py", "--only", "gitleaks"]), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(gate.main(), 1)
        self.assertTrue(gate.coverage_gaps([failed]))
        self.assertIn("PARTIAL COVERAGE", (self.out / "report.md").read_text())


if __name__ == "__main__":
    unittest.main()
