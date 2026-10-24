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


class GroupCleanupProofControls(unittest.TestCase):
    """UNRUN: refusal controls use synthetic receipts, never numeric OS kills."""

    def setUp(self):
        self.helper = reference.child_wait
        self.waiter = object.__new__(self.helper.ChildWaiter)
        self.receipt = {}

    def proof(self, observation, snapshot):
        return (mock.patch.object(self.waiter, "exited_unreaped", side_effect=observation),
                mock.patch.object(self.waiter, "_darwin_group_snapshot", return_value=snapshot),
                mock.patch.object(self.helper.sys, "platform", "darwin"),
                mock.patch.object(self.helper.os, "killpg",
                                  side_effect=PermissionError(1, "control EPERM")))

    def test_eperm_accepts_only_complete_original_exited_leader_snapshot(self):
        snapshot = {"bytes": 4, "capacity_bytes": 8, "errno": 0, "pids": [123]}
        observation, inspect, platform, signal_group = self.proof([True, True, True], snapshot)
        with observation as owned, inspect as listed, platform, signal_group as kill:
            self.waiter.cleanup_owned_group(123, self.receipt)
        self.assertEqual(owned.call_count, 3)
        listed.assert_called_once_with(123)
        kill.assert_called_once_with(123, signal.SIGKILL)
        self.assertEqual(self.receipt["group_signal_errno"], 1)
        self.assertEqual(self.receipt["darwin_group_snapshot"], snapshot)
        self.assertIn("sole retained exited leader proven", self.receipt["group_cleanup"])

    def test_eperm_never_accepts_empty_error_truncated_or_other_member(self):
        for size, error, members in ((0, 0, []), (0, 1, []), (-1, 0, []),
                                     (3, 0, []), (8, 0, [123, 456]),
                                     (12, 0, [123]), (4, 0, [456]), (4, 5, [123])):
            with self.subTest(size=size, error=error, members=members):
                snapshot = {"bytes": size, "errno": error, "pids": members}
                observation, inspect, platform, signal_group = self.proof([True, True], snapshot)
                with observation, inspect, platform, signal_group as kill:
                    with self.assertRaises(PermissionError):
                        self.waiter.cleanup_owned_group(123, {})
                kill.assert_called_once_with(123, signal.SIGKILL)

    def test_eperm_live_leader_refuses_without_snapshot(self):
        observation, inspect, platform, signal_group = self.proof([False, False], {})
        with observation, inspect as listed, platform, signal_group:
            with self.assertRaises(PermissionError):
                self.waiter.cleanup_owned_group(123, self.receipt)
        listed.assert_not_called()

    def test_lost_lease_before_group_action_never_signals(self):
        with mock.patch.object(self.waiter, "exited_unreaped", side_effect=ChildProcessError), \
                mock.patch.object(self.helper.os, "killpg") as kill:
            with self.assertRaises(ChildProcessError):
                self.waiter.cleanup_owned_group(123, self.receipt)
        kill.assert_not_called()

    def test_lost_lease_before_snapshot_never_inspects_group(self):
        observation, inspect, platform, signal_group = self.proof(
            [True, ChildProcessError("control reaper")], {})
        with observation, inspect as listed, platform, signal_group as kill:
            with self.assertRaises(ChildProcessError):
                self.waiter.cleanup_owned_group(123, self.receipt)
        listed.assert_not_called()
        kill.assert_called_once_with(123, signal.SIGKILL)

    def test_non_darwin_eperm_has_no_platform_exception(self):
        with mock.patch.object(self.waiter, "exited_unreaped", return_value=True), \
                mock.patch.object(self.helper.sys, "platform", "linux"), \
                mock.patch.object(self.waiter, "_darwin_group_snapshot") as listed, \
                mock.patch.object(self.helper.os, "killpg", side_effect=PermissionError(1, "denied")):
            with self.assertRaises(PermissionError):
                self.waiter.cleanup_owned_group(123, self.receipt)
        listed.assert_not_called()

    def test_snapshot_binding_passes_exact_bounded_pid_buffer(self):
        library = mock.Mock()
        def listpids(kind, group, buffer, size):
            self.assertEqual((kind, group, size), (2, 123, 8))
            buffer[0] = 123
            return 4
        library.proc_listpids.side_effect = listpids
        with mock.patch.object(self.helper.sys, "platform", "darwin"), \
                mock.patch.object(self.helper.platform, "machine", return_value="x86_64"), \
                mock.patch.object(self.helper.ctypes, "CDLL", return_value=library) as load:
            snapshot = self.waiter._darwin_group_snapshot(123)
        load.assert_called_once_with("/usr/lib/libSystem.B.dylib", use_errno=True)
        self.assertEqual(snapshot["bytes"], 4)
        self.assertEqual(snapshot["capacity_bytes"], 8)
        self.assertEqual(snapshot["pids"], [123])
        self.assertEqual(snapshot["errno"], 0)

    def test_lost_lease_after_snapshot_refuses_success_and_never_resignals(self):
        snapshot = {"bytes": 4, "errno": 0, "pids": [123]}
        observation, inspect, platform, signal_group = self.proof(
            [True, True, ChildProcessError("control reaper")], snapshot)
        with observation, inspect, platform, signal_group as kill:
            with self.assertRaises(ChildProcessError):
                self.waiter.cleanup_owned_group(123, self.receipt)
        kill.assert_called_once_with(123, signal.SIGKILL)
        self.assertNotIn("proven", self.receipt["group_cleanup"])


class AdditionalActualGroupControls(unittest.TestCase):
    """UNRUN actual bounded group controls; original controls stay unchanged."""

    runner = reference
    setUp = ProcessControls.setUp
    receipt = ProcessControls.receipt

    def test_refused_cleanup_is_not_retried_or_reaped(self):
        process = mock.Mock(pid=123, returncode=None)
        with mock.patch.object(self.runner.subprocess, "Popen", return_value=process), \
                mock.patch.object(self.evidence.waiter, "exited_unreaped", return_value=True), \
                mock.patch.object(self.evidence.waiter, "cleanup_owned_group",
                                  side_effect=PermissionError(1, "refused proof")) as cleanup:
            with self.assertRaises(PermissionError):
                self.evidence.command("refused-cleanup", ["unused-control"], 5)
        cleanup.assert_called_once()
        process.wait.assert_not_called()
        self.assertIs(self.evidence.quarantined_commands[0], process)
        self.assertIs(self.runner.child_wait._QUARANTINED_COMMANDS[-1], process)
        command = self.receipt()["commands"][0]
        self.assertEqual(command["cleanup_error"], "PermissionError")
        self.assertEqual(command["cleanup_error_errno"], 1)
        self.assertIn("refused proof", command["cleanup_error_repr"])
        self.assertFalse(command["leader_reaped"])
        self.assertNotIn("returncode", command)

    def test_normal_exit_records_original_pid_group_and_reap(self):
        output = self.evidence.command("normal-owner", [sys.executable, "-c",
            "import os; print(os.getpid(), os.getpgrp())"], 5)
        pid, pgid = map(int, output.split())
        command = self.receipt()["commands"][0]
        self.assertEqual(command["pid"], pid)
        self.assertEqual(command["pgid"], pgid)
        self.assertEqual(pid, pgid)
        self.assertEqual(command["cleanup_pid"], pid)
        self.assertEqual(command["cleanup_pgid"], pgid)
        self.assertEqual(command["returncode"], 0)
        self.assertTrue(command["leader_reaped"])
        self.assertTrue(command["leader_exited_before_cleanup"])

    def test_exited_leader_cleanup_releases_live_descendant_lock(self):
        gate = self.output.parent / "normal-descendant.lock"
        source = ("import fcntl, os, time\n"
                  f"gate = open({str(gate)!r}, 'w')\n"
                  "fcntl.flock(gate, fcntl.LOCK_EX)\n"
                  "child = os.fork()\n"
                  "if child == 0:\n"
                  "    time.sleep(5)\n"
                  "    os._exit(0)\n"
                  "print(os.getpid(), os.getpgrp(), child, flush=True)\n"
                  "os._exit(0)\n")
        output = self.evidence.command("normal-descendant", [sys.executable, "-c", source], 5)
        pid, pgid, child = map(int, output.split())
        self.assertNotEqual(pid, child)
        command = self.receipt()["commands"][0]
        self.assertEqual((command["pid"], command["pgid"]), (pid, pgid))
        self.assertTrue(command["leader_reaped"])
        self.assertEqual(command["returncode"], 0)
        self.assertEqual(command["group_cleanup"], "SIGKILL before original leader reap")
        with gate.open() as lock:
            deadline = time.monotonic() + 2
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        self.fail("live descendant survived completed-leader cleanup")
                    time.sleep(0.01)


class AmdAdditionalActualGroupControls(AdditionalActualGroupControls):
    runner = amd_gpio_oracle


class ActualDarwinGroupSnapshotControls(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "darwin", "Darwin group snapshot only")
    def test_real_sole_zombie_snapshot_preserves_original_reaping_owner(self):
        helper = reference.child_wait
        waiter = helper.ChildWaiter()
        child = subprocess.Popen([sys.executable, "-c", "pass"], start_new_session=True)
        try:
            deadline = time.monotonic() + 5
            while not waiter.exited_unreaped(child.pid):
                if time.monotonic() >= deadline:
                    self.fail("child did not exit before snapshot deadline")
                time.sleep(0.01)
            snapshot = waiter._darwin_group_snapshot(child.pid)
            self.assertEqual(snapshot["bytes"], 4)
            self.assertEqual(snapshot["capacity_bytes"], 8)
            self.assertEqual(snapshot["errno"], 0)
            self.assertEqual(snapshot["pids"], [child.pid])
            self.assertTrue(waiter.exited_unreaped(child.pid))
            self.assertIsNone(child.returncode)
            self.assertEqual(child.wait(timeout=5), 0)
        finally:
            if child.returncode is None:
                waiter.cleanup_owned_group(child.pid, {})
                child.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
