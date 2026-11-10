"""Regression tests for Clippy coverage accounting (no Rust toolchain needed)."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from security import run as gate


def diagnostic(lint="unused_imports", level="warning", path="cesa_conn_crypto/src/lib.rs"):
    """One compiler message in cargo's JSON format."""
    return json.dumps({"reason": "compiler-message", "message": {
        "level": level, "code": {"code": lint}, "message": "fixture diagnostic",
        "spans": [{"is_primary": True, "file_name": path, "line_start": 1}],
    }})


class ClippyCoverageTests(unittest.TestCase):
    def test_each_configuration_failure_blocks_independently(self):
        """Each failed run (crate, feature set) is its own gap."""
        count = len(gate.CRATES) * 2
        for index in range(count):
            for code in (1, 101, 124, 127, -9):
                with self.subTest(index=index, code=code):
                    responses = [(0, "", "")] * count
                    responses[index] = (code, "not JSON", "fixture execution failure")
                    with patch.object(gate, "run", side_effect=responses) as runner:
                        result = gate.check_clippy()
                    self.assertEqual(runner.call_count, count)
                    gaps = gate.coverage_gaps([result])
                    self.assertEqual(len(gaps), 1)
                    self.assertIn(gate.CRATES[index // 2], gaps[0])
                    self.assertIn("all features" if index % 2 else "default features", gaps[0])
                    self.assertIn(f"exited with {code}", gaps[0])
                    self.assertIn("fixture execution failure", result.findings[0].message)

    def test_unreported_errors_leave_a_gap(self):
        """Errors the report doesn't show (warnings only, outside the workspace, no span, no JSON) don't explain an exit."""
        no_span = json.dumps({"reason": "compiler-message", "message": {
            "level": "error", "message": "aborting", "spans": []}})
        for output in (diagnostic(), diagnostic("E0001", "error", "external/src/lib.rs"),
                       no_span, "not JSON"):
            with self.subTest(output=output), patch.object(
                gate, "run", return_value=(101, output, "failed")
            ):
                result = gate.check_clippy()
                failed = [f for f in result.findings if f.rule == "invocation-failed"]
                self.assertEqual(len(failed), len(gate.CRATES) * 2)

    def test_reported_errors_explain_the_exit(self):
        """An error in the crate's own file, or in clippy.toml, explains its exit."""
        for lint, own_file in (("clippy::mem_forget", True), ("E0308", True),
                               ("clippy::unknown_conf", False)):
            def own(cmd, **kwargs):
                """Fake clippy: the error is in the crate being run (or clippy.toml)."""
                crate = cmd[cmd.index("-p") + 1]
                path = f"{crate}/src/lib.rs" if own_file else "clippy.toml"
                return 101, diagnostic(lint, "error", path), "failed"
            with self.subTest(lint=lint), patch.object(gate, "run", side_effect=own):
                result = gate.check_clippy()
                self.assertEqual([f for f in result.findings if f.rule == "invocation-failed"], [])
                self.assertTrue(result.findings)

    def test_error_in_a_dependency_is_a_gap_for_the_dependent(self):
        """A crate whose run fails on another crate's error was never linted."""
        error = diagnostic("clippy::mem_forget", "error", f"{gate.CRATES[0]}/src/lib.rs")
        with patch.object(gate, "run", return_value=(101, error, "failed")):
            result = gate.check_clippy()
        failed = [f for f in result.findings if f.rule == "invocation-failed"]
        self.assertEqual(len(failed), (len(gate.CRATES) - 1) * 2)
        self.assertFalse(any(f.path == gate.CRATES[0] for f in failed))
        self.assertEqual([f.severity for f in result.findings
                          if f.rule != "invocation-failed"], ["critical"])

    def test_timeout_is_a_gap_even_with_reported_errors(self):
        """A timed-out run printed only part of its output: always a gap."""
        with patch.object(gate, "run",
                          return_value=(124, diagnostic("clippy::mem_forget", "error"), "TIMEOUT")):
            result = gate.check_clippy()
        failed = [f for f in result.findings if f.rule == "invocation-failed"]
        self.assertEqual(len(failed), len(gate.CRATES) * 2)

    def test_success_with_unused_notes_has_no_gap(self):
        """A clean run with unused-code notes has no gap."""
        with patch.object(gate, "run", return_value=(0, diagnostic(), "")):
            result = gate.check_clippy()
        self.assertEqual(gate.coverage_gaps([result]), [])
        self.assertEqual(len(result.findings), 1)
        self.assertTrue(gate.is_note(result.findings[0]))

    def test_main_blocks_and_reports_incomplete_analysis(self):
        """The gate exits 1 and the report says BLOCKED on a gap."""
        for code, verdict in ((0, "PASSED"), (124, "BLOCKED")):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                output = io.StringIO()
                with patch.object(gate, "OUT", Path(directory)), patch.object(
                    gate, "run", return_value=(code, "", "TIMEOUT" if code else "")
                ), patch("sys.argv", ["run.py", "--only", "clippy"]), patch.dict(
                    "os.environ", {"GITHUB_STEP_SUMMARY": ""}
                ), contextlib.redirect_stdout(output):
                    self.assertEqual(gate.main(), int(code != 0))
                report = (Path(directory) / "report.md").read_text()
                self.assertIn(verdict, report)
                self.assertIn(f"RESULT: {verdict}", output.getvalue())


if __name__ == "__main__":
    unittest.main()
