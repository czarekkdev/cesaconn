"""Regression tests for dependency-check coverage and reviewed exceptions."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from security import run as gate


def diagnostic(severity, code="duplicate", message="policy finding"):
    return json.dumps({"type": "diagnostic", "fields": {
        "severity": severity, "code": code, "message": message}})


class DenyCoverageTests(unittest.TestCase):
    def check(self, responses):
        with patch.object(gate, "have_cargo_sub", return_value=True), \
                patch.object(gate, "run", side_effect=responses) as run:
            result = gate.check_deny()
        self.assertEqual([call.args[0][-1] for call in run.call_args_list],
                         ["sources", "bans", "licenses"])
        return result

    def test_clean_and_warning_only_checks_complete(self):
        result = self.check([(0, "", ""), (0, "", diagnostic("warning")), (0, "", "")])
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(gate.coverage_gaps([result]), [])

    def test_policy_errors_explain_only_the_matching_exit(self):
        result = self.check([(8, "", diagnostic("error")),
                             (2, "", diagnostic("error")),
                             (4, "", diagnostic("error"))])
        self.assertEqual([f.severity for f in result.findings],
                         ["critical", "warning", "warning"])
        self.assertEqual(gate.coverage_gaps([result]), [])

    def test_unexplained_exits_are_gaps_for_each_check(self):
        for index in range(3):
            for code in (1, 2, 4, 8, 124, 127, -9):
                for err in ("", "not JSON", diagnostic("warning"),
                            diagnostic("error")):
                    with self.subTest(index=index, code=code, err=err):
                        responses = [(0, "", "")] * 3
                        responses[index] = (code, "", err)
                        result = self.check(responses)
                        explained = code == (8, 2, 4)[index] and err == diagnostic("error")
                        self.assertEqual(len(gate.coverage_gaps([result])),
                                         0 if explained else 1)

    def test_accepted_warning_cannot_hide_later_failure(self):
        for code in (1, 124, 127):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as tmp:
                accepted = Path(tmp) / "accepted.json"
                accepted.write_text(json.dumps({"duplicates": {"example": {
                    "versions": ["1", "2"], "reason": "reviewed upstream"}}}))
                result = self.check([(0, "", ""),
                    (0, "", diagnostic("warning", message="duplicate entries for crate 'example'")),
                    (code, "", "TIMEOUT" if code == 124 else "failed")])
                results = [result]
                with patch.object(gate, "ACCEPTED", accepted), \
                        patch.object(gate, "lock_versions", return_value={"example": {"1", "2"}}):
                    gate.apply_accepted(results)
                self.assertTrue(gate.is_note(result.findings[0]))
                self.assertEqual(len(gate.coverage_gaps(results)), 1)
                with patch.object(gate, "OUT", Path(tmp)), \
                        patch.object(gate, "run", return_value=(0, "test-sha", "")):
                    crit, warn, report = gate.write_report(results, "fast")
                self.assertEqual((crit, warn), (0, 0))
                self.assertIn("BLOCKED - PARTIAL COVERAGE", report)
                with patch.object(gate, "check_deny", return_value=result), \
                        patch.object(gate, "apply_accepted"), \
                        patch.object(gate, "OUT", Path(tmp)), \
                        patch.object(gate, "run", return_value=(0, "test-sha", "")), \
                        patch("sys.argv", ["security/run.py", "--only", "deny"]), \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(gate.main(), 1)


if __name__ == "__main__":
    unittest.main()
