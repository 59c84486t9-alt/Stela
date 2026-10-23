#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Process/provenance controls only, not execution of the Linux C oracle.

UNRUN at authorship. Run explicitly when a qualification slot is assigned:
python3 crates/stela-drivers/src/audio/intel_dsp/reference_controls.py
"""
import hashlib
import importlib.util
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
from unittest import mock

import reference


class ProcessControls(unittest.TestCase):
    runner = reference

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="sof-process-controls-")
        self.addCleanup(self.scratch.cleanup)
        self.output = Path(self.scratch.name) / "trace.txt"
        self.evidence = self.runner.Evidence(self.output)

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
            self.runner.Evidence(self.output)
        self.assertEqual((self.evidence.root / "receipt.json").read_bytes(), original)
        trace = self.output.parent / "existing.txt"
        trace.write_bytes(b"historical evidence\n")
        with self.assertRaisesRegex(SystemExit, "refusing existing trace"):
            self.runner.Evidence(trace)
        self.assertEqual(trace.read_bytes(), b"historical evidence\n")
        self.assertFalse((trace.parent / (trace.name + ".evidence")).exists())

    def test_truncated_original_body_refuses_before_compilation(self):
        if self.runner is not reference:
            self.skipTest("SOF donor extraction control")
        with self.assertRaisesRegex(SystemExit, "unterminated original function"):
            self.runner.function("static void selected(void) {", "selected")

    def test_backend_identity_and_helper_hash_are_retained(self):
        self.evidence.command("backend", [sys.executable, "-c", "pass"], 5)
        receipt = self.receipt()
        self.assertEqual(receipt["wait_backend"], self.evidence.waiter.backend)
        self.assertEqual(receipt["child_wait_sha256"],
                         hashlib.sha256(self.runner._WAIT_PATH.read_bytes()).hexdigest())

    def test_lost_leader_ownership_refuses_group_signal(self):
        def externally_reaped(pid):
            # Deliberately violate exclusive reaping; the child is genuinely
            # retired before the runner sees ECHILD, so no group signal is safe.
            self.assertEqual(os.waitpid(pid, 0)[0], pid)
            raise ChildProcessError("control: original leader already reaped")

        with mock.patch.object(self.evidence.waiter, "exited_unreaped", externally_reaped), \
                mock.patch.object(self.runner.os, "killpg") as kill_group:
            with self.assertRaises(ChildProcessError):
                self.evidence.command("lost-owner", [sys.executable, "-c", "pass"], 5)
            kill_group.assert_not_called()
        command = self.receipt()["commands"][0]
        self.assertEqual(command["leader_ownership"], "lost; refused group signal")
        self.assertNotIn("returncode", command)
        self.assertIn("stdout_sha256", command)

    def test_foreign_reaper_policy_refuses_before_spawn(self):
        with mock.patch.object(self.runner.signal, "getsignal", return_value=signal.SIG_IGN), \
                mock.patch.object(self.runner.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(RuntimeError, "exclusive child-reaping"):
                self.evidence.command("foreign-reaper", [sys.executable, "-c", "pass"], 5)
            spawn.assert_not_called()

    def test_actual_harness_signals_reap_command_and_kill_its_descendants(self):
        for cancellation, phase in ((signal.SIGTERM, "wait"), (signal.SIGINT, "wait"),
                                    (signal.SIGTERM, "spawn"), (signal.SIGTERM, "exit")):
            with self.subTest(signal=cancellation, phase=phase):
                tag = f"{cancellation}-{phase}"
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
                    + ("time.sleep(0.1)\n" if phase == "exit" else "time.sleep(30)\n")
                )
                helper = (
                    "import sys\n"
                    "import importlib.util\n"
                    f"spec = importlib.util.spec_from_file_location('reference', {str(Path(self.runner.__file__).resolve())!r})\n"
                    "reference = importlib.util.module_from_spec(spec)\n"
                    "spec.loader.exec_module(reference)\n"
                    "def controlled(evidence, args):\n"
                    f"    evidence.command('descendants', [sys.executable, '-c', {command!r}], 20)\n"
                    "reference.generate = controlled\n"
                    f"sys.argv = ['reference', '--linux-git-dir', 'unused', '--output', {str(output)!r}]\n"
                )
                if phase == "spawn":
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
                if phase == "exit":
                    helper += (
                        "import os, signal\n"
                        "original_waitid = reference.child_wait.ChildWaiter.exited_unreaped\n"
                        "def interrupted_exit(*args):\n"
                        "    result = original_waitid(*args)\n"
                        "    if result:\n"
                        "        os.kill(os.getpid(), signal.SIGTERM)\n"
                        "    return result\n"
                        "reference.child_wait.ChildWaiter.exited_unreaped = interrupted_exit\n"
                    )
                helper += "reference.main()\n"
                harness = subprocess.Popen([sys.executable, "-c", helper],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=True)
                command_pid = None
                try:
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        if ready.exists() and ready.read_text():
                            command_pid = int(ready.read_text())
                            break
                        self.assertIsNone(harness.poll(), "harness exited before readiness")
                        time.sleep(0.01)
                    self.assertIsNotNone(command_pid, "command failed to become ready")
                    if phase == "wait":
                        os.kill(harness.pid, cancellation)
                    self.assertNotEqual(harness.wait(timeout=5), 0)
                    receipt = json.loads((output.parent / (output.name + ".evidence") / "receipt.json").read_text())
                    self.assertEqual(receipt["status"], "failed")
                    expected = 0 if phase == "exit" else -signal.SIGKILL
                    self.assertEqual(receipt["commands"][0]["returncode"], expected)
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
                finally:
                    # A successful control proved both original owners retired;
                    # never signal their now-stale numeric process-group ID.
                    if harness.poll() is None:
                        # Ask the still-owned harness to clean its retained
                        # command. Its liveness alone cannot authorize killing
                        # a numeric command PGID that it may already have reaped.
                        harness.terminate()
                        try:
                            harness.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            harness.kill()
                            harness.wait(timeout=5)
                    harness.wait(timeout=5)


_amd_path = Path(reference.__file__).resolve().parents[3] / "tests/reference/amd_gpio_oracle.py"
_amd_spec = importlib.util.spec_from_file_location("amd_gpio_oracle", _amd_path)
amd_gpio_oracle = importlib.util.module_from_spec(_amd_spec)
_amd_spec.loader.exec_module(amd_gpio_oracle)


class AmdProcessControls(ProcessControls):
    runner = amd_gpio_oracle


class WaitBackendControls(unittest.TestCase):
    def test_missing_python_waitid_refuses_unknown_platform(self):
        helper = reference.child_wait
        with mock.patch.object(helper.os, "waitid", None, create=True), \
                mock.patch.object(helper.sys, "platform", "unsupported"), \
                mock.patch.object(helper.ctypes, "CDLL") as load:
            with self.assertRaisesRegex(RuntimeError, "unsupported waitid ABI"):
                helper.ChildWaiter()
            load.assert_not_called()

    @unittest.skipUnless(sys.platform == "darwin", "Darwin libc fallback only")
    def test_real_darwin_fallback_retains_leader_until_explicit_reap(self):
        helper = reference.child_wait
        with mock.patch.object(helper.os, "waitid", None, create=True):
            waiter = helper.ChildWaiter()
        self.assertEqual(waiter.backend, "darwin-libSystem.waitid-lp64")
        child = subprocess.Popen([sys.executable, "-c", "pass"], start_new_session=True)
        try:
            deadline = time.monotonic() + 5
            while not waiter.exited_unreaped(child.pid):
                if time.monotonic() >= deadline:
                    self.fail("Darwin waitid did not observe exited child")
                time.sleep(0.01)
            # A second real WNOWAIT observation proves the first did not reap.
            self.assertTrue(waiter.exited_unreaped(child.pid))
            self.assertIsNone(child.returncode)
            self.assertEqual(child.wait(timeout=5), 0)
            with self.assertRaises(ChildProcessError):
                waiter.exited_unreaped(child.pid)
        finally:
            if child.returncode is None:
                child.kill()
                child.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
