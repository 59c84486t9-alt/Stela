#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Process/provenance controls only, not execution of the Linux C oracle.

UNRUN at authorship. Run explicitly when a qualification slot is assigned:
python3 crates/stela-drivers/src/audio/intel_dsp/reference_controls.py
"""
import hashlib
import json
from pathlib import Path
import signal
import sys
import tempfile
import unittest

import reference


class ProcessControls(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="sof-process-controls-")
        self.addCleanup(self.scratch.cleanup)
        self.output = Path(self.scratch.name) / "trace.txt"
        self.evidence = reference.Evidence(self.output)

    def receipt(self):
        return json.loads((self.evidence.root / "receipt.json").read_text())

    def test_nonzero_retains_output_and_failure_status(self):
        with self.assertRaisesRegex(RuntimeError, "failed \\(7\\)"):
            self.evidence.command("nonzero", [sys.executable, "-c",
                "import sys; print('partial trace'); print('failure', file=sys.stderr); sys.exit(7)"], 5)
        command = self.receipt()["commands"][0]
        self.assertEqual(command["returncode"], 7)
        self.assertEqual((self.evidence.root / "nonzero.stdout").read_bytes(), b"partial trace\n")
        self.assertEqual((self.evidence.root / "nonzero.stderr").read_bytes(), b"failure\n")
        self.assertEqual(command["stdout_sha256"], hashlib.sha256(b"partial trace\n").hexdigest())
        self.assertFalse(self.output.exists())

    def test_timeout_records_killed_and_reaped_command(self):
        with self.assertRaisesRegex(RuntimeError, "timed out"):
            self.evidence.command("timeout", [sys.executable, "-c",
                "import time; time.sleep(30)"], 0.1)
        command = self.receipt()["commands"][0]
        self.assertTrue(command["timed_out"])
        self.assertEqual(command["returncode"], -signal.SIGKILL)
        self.assertFalse(self.output.exists())

    def test_actual_child_environment_disables_fetch_and_prompts(self):
        actual = self.evidence.command("environment", [sys.executable, "-c",
            "import os; print(os.environ['GIT_NO_LAZY_FETCH'], os.environ['GIT_TERMINAL_PROMPT'], os.environ['LC_ALL'])"], 5)
        self.assertEqual(actual, b"1 0 C\n")

    def test_existing_evidence_and_trace_are_preserved(self):
        original = (self.evidence.root / "receipt.json").read_bytes()
        with self.assertRaises(FileExistsError):
            reference.Evidence(self.output)
        self.assertEqual((self.evidence.root / "receipt.json").read_bytes(), original)
        trace = self.output.parent / "existing.txt"
        trace.write_bytes(b"historical evidence\n")
        with self.assertRaisesRegex(SystemExit, "refusing existing trace"):
            reference.Evidence(trace)
        self.assertEqual(trace.read_bytes(), b"historical evidence\n")
        self.assertFalse((trace.parent / (trace.name + ".evidence")).exists())

    def test_truncated_original_body_refuses_before_compilation(self):
        with self.assertRaisesRegex(SystemExit, "unterminated original function"):
            reference.function("static void selected(void) {", "selected")


if __name__ == "__main__":
    unittest.main()
