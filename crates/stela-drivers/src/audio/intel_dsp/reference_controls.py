#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Process/provenance controls only, not execution of the Linux C oracle.

UNRUN at authorship. Run explicitly when a qualification slot is assigned:
python3 crates/stela-drivers/src/audio/intel_dsp/reference_controls.py
"""
import hashlib
import json
import fcntl
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
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

    def test_actual_harness_signals_reap_command_and_kill_its_descendants(self):
        for cancellation, spawning in ((signal.SIGTERM, False), (signal.SIGINT, False),
                                       (signal.SIGTERM, True)):
            with self.subTest(signal=cancellation, during_spawn=spawning):
                tag = f"{cancellation}-{spawning}"
                output = self.output.parent / f"signal-{tag}.txt"
                ready = self.output.parent / f"ready-{tag}.txt"
                gate = self.output.parent / f"gate-{tag}.txt"
                # The inherited file lock stays held until both the direct
                # command and its forked descendant close their descriptors.
                command = (
                    "import fcntl, os, time\n"
                    f"gate = open({str(gate)!r}, 'w')\n"
                    "fcntl.flock(gate, fcntl.LOCK_EX)\n"
                    "child = os.fork()\n"
                    "if child == 0:\n"
                    "    time.sleep(30)\n"
                    "    os._exit(0)\n"
                    f"open({str(ready)!r}, 'w').write(str(os.getpid()))\n"
                    "time.sleep(30)\n"
                )
                helper = (
                    "import sys\n"
                    f"sys.path.insert(0, {str(Path(reference.__file__).parent)!r})\n"
                    "import reference\n"
                    "def controlled(evidence, args):\n"
                    f"    evidence.command('descendants', [sys.executable, '-c', {command!r}], 20)\n"
                    "reference.generate = controlled\n"
                    f"sys.argv = ['reference', '--linux-git-dir', 'unused', '--output', {str(output)!r}]\n"
                )
                if spawning:
                    # Deliver SIGTERM after the real child exists, but before
                    # its Popen call returns ownership to Evidence.command.
                    helper += (
                        "import os, signal, time\n"
                        "from pathlib import Path\n"
                        "original_popen = reference.subprocess.Popen\n"
                        "def interrupted_spawn(*args, **kwargs):\n"
                        "    child = original_popen(*args, **kwargs)\n"
                        "    deadline = time.monotonic() + 5\n"
                        f"    while not Path({str(ready)!r}).exists():\n"
                        "        if time.monotonic() >= deadline:\n"
                        "            os.killpg(child.pid, signal.SIGKILL)\n"
                        "            child.wait()\n"
                        "            raise RuntimeError('spawn readiness timed out')\n"
                        "        time.sleep(0.01)\n"
                        "    os.kill(os.getpid(), signal.SIGTERM)\n"
                        "    return child\n"
                        "reference.subprocess.Popen = interrupted_spawn\n"
                    )
                helper += "reference.main()\n"
                harness = subprocess.Popen([sys.executable, "-c", helper],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=True)
                command_pid = None
                cleaned = False
                try:
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        if ready.exists() and ready.read_text():
                            command_pid = int(ready.read_text())
                            break
                        self.assertIsNone(harness.poll(), "harness exited before readiness")
                        time.sleep(0.01)
                    self.assertIsNotNone(command_pid, "command failed to become ready")
                    if not spawning:
                        os.kill(harness.pid, cancellation)
                    self.assertNotEqual(harness.wait(timeout=5), 0)
                    receipt = json.loads((output.parent / (output.name + ".evidence") / "receipt.json").read_text())
                    self.assertEqual(receipt["status"], "failed")
                    self.assertEqual(receipt["commands"][0]["returncode"], -signal.SIGKILL)
                    with self.assertRaises(ProcessLookupError):
                        os.kill(command_pid, 0)
                    with gate.open() as lock:
                        deadline = time.monotonic() + 2
                        while True:
                            try:
                                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                                break
                            except BlockingIOError:
                                if time.monotonic() >= deadline:
                                    self.fail("descendant retained its inherited lock after cancellation")
                                time.sleep(0.01)
                    self.assertFalse(output.exists())
                    cleaned = True
                finally:
                    # A successful control proved both original owners retired;
                    # never signal their now-stale numeric process-group ID.
                    if not cleaned and harness.poll() is None and command_pid is not None:
                        try:
                            os.killpg(command_pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    if harness.poll() is None:
                        harness.kill()
                    harness.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
