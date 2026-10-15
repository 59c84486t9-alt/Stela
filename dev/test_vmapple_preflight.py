import contextlib
import importlib.util
import io
import json
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile


SPEC = importlib.util.spec_from_file_location(
    "vmapple_preflight", Path(__file__).with_name("vmapple-preflight.py"))
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)


class QemuInventoryTests(unittest.TestCase):
    def inventory(self, machines="pc Standard PC\n", target="x86_system", failure=None, accelerators="tcg\nhvf\n"):
        with tempfile.TemporaryDirectory() as directory:
            launcher = Path(directory) / "QEMU ; $(literal) executable"
            launcher.write_bytes(b"launcher bytes")
            commands = []

            def run(argv, **kwargs):
                self.assertIsInstance(argv, list)
                self.assertNotIn("shell", kwargs)
                self.assertEqual(argv[0], str(launcher.resolve()))
                self.assertEqual(kwargs["timeout"], preflight.PROBE_TIMEOUT_SECONDS)
                commands.append(argv)
                if failure:
                    if isinstance(failure, Exception):
                        raise failure
                    return subprocess.CompletedProcess(argv, failure, "", "failed help")
                output = {"--version": "QEMU emulator version test\n",
                          "-machine": machines, "-accel": accelerators}[argv[1]]
                return subprocess.CompletedProcess(argv, 0, output, "")

            with patch.object(preflight.subprocess, "run", side_effect=run):
                result = preflight.qemu_inventory(launcher, target)
            self.assertEqual(len(commands), 3)
            return result

    def test_argv_handles_literal_spaces_and_metacharacters_and_binds_launcher(self):
        result = self.inventory()
        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["observed_target"], "x86_system")
        self.assertEqual(result["launcher_sha256"], preflight.sha256(b"launcher bytes"))
        self.assertEqual(result["file_identity_before"], result["file_identity_after"])
        self.assertTrue(result["pc_listed"])
        self.assertTrue(result["tcg_listed"])
        self.assertFalse(result["vmapple_listed"])

    def test_arm_emulator_cannot_satisfy_x86_debug_role(self):
        result = self.inventory("virt ARM machine\nvmapple Apple VM\n")
        self.assertEqual(result["status"], "target_mismatch")
        self.assertEqual(result["observed_target"], "arm_system")
        self.assertTrue(result["vmapple_listed"])
        messages = preflight.setup_diagnostics(result, result)
        self.assertIn("requires x86_system", messages[0]["message"])
        self.assertEqual(messages[-1]["status"], "unverified_requirements")

    def test_x86_emulator_cannot_satisfy_arm_reference_role(self):
        self.assertEqual(self.inventory(target="arm_system")["status"], "target_mismatch")

    def test_x86_debug_requires_tcg_even_when_target_is_correct(self):
        result = self.inventory(accelerators="hvf\n")
        self.assertEqual(result["observed_target"], "x86_system")
        self.assertEqual(result["status"], "capability_unavailable")
        self.assertIn("tcg accelerator", preflight.setup_diagnostics(result, result)[0]["message"])

    def test_unknown_machine_set_is_not_inferred_from_filename(self):
        self.assertEqual(self.inventory("none empty machine\n")["status"], "target_mismatch")

    def test_timeouts_and_nonzero_exits_preserve_unknown_capabilities(self):
        for failure in (subprocess.TimeoutExpired("help", 10), OSError("cannot execute"), 1):
            with self.subTest(failure=failure):
                result = self.inventory(failure=failure)
                self.assertEqual(result["status"], "probe_failed")
                self.assertIsNone(result["pc_listed"])
                self.assertIsNone(result["tcg_listed"])
                self.assertIsNone(result["vmapple_listed"])

    def test_missing_binary_is_actionable_without_traceback(self):
        for path in (None, Path("/nonexistent/stela-qemu")):
            result = preflight.qemu_inventory(path, "x86_system")
            self.assertEqual(result["status"], "unavailable")
            self.assertIn("Install QEMU", preflight.setup_diagnostics(result, result)[0]["message"])

    def test_launcher_changed_during_probe_is_not_credited(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = Path(directory) / "qemu"
            launcher.write_bytes(b"before")

            def run(argv, **kwargs):
                launcher.write_bytes(b"changed during help")
                return subprocess.CompletedProcess(argv, 0, "pc PC\ntcg\n", "")

            with patch.object(preflight.subprocess, "run", side_effect=run):
                result = preflight.qemu_inventory(launcher, "x86_system")
            self.assertEqual(result["status"], "input_changed")
            self.assertIn("Stop tool installation", preflight.setup_diagnostics(result, result)[0]["message"])

    def test_discovery_prefers_executable_local_tool_then_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            local = root / ".tools/qemu/bin/qemu-system-x86_64"
            local.parent.mkdir(parents=True)
            local.write_bytes(b"local")
            with patch.object(preflight, "ROOT", root), patch.object(
                    preflight.shutil, "which", return_value="/installed/qemu"):
                self.assertEqual(preflight.discover_qemu(local.name), Path("/installed/qemu"))
                local.chmod(0o755)
                self.assertEqual(preflight.discover_qemu(local.name), local)


class PreflightCommandTests(unittest.TestCase):
    def invoke(self, root, arguments, archive=None):
        out, err = io.StringIO(), io.StringIO()
        inventory = {"path": None, "status": "unavailable", "commands": {}}
        with patch.object(preflight, "ROOT", root), patch.object(
                preflight, "archive_inventory", return_value=archive), patch.object(
                preflight, "qemu_inventory", return_value=inventory), patch.object(
                preflight, "discover_qemu", return_value=None), patch.object(
                sys, "argv", ["vmapple-preflight.py", "original.ipsw", *arguments]), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                preflight.main()
                code = 0
            except SystemExit as error:
                code = error.code
        return code, out.getvalue(), err.getvalue()

    def test_default_destinations_are_fresh_and_boot_request_fails_after_receipt(self):
        archive = {"build": "fixture-build", "model": "fixture-model",
                   "device_tree": {"node_count": 1}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            first = self.invoke(root, [], archive)
            second = self.invoke(root, ["--require-translated-boot"], archive)
            self.assertEqual(first[0], 0)
            self.assertEqual(second[0], 2)
            first_path = Path(json.loads(first[1])["output"])
            second_path = Path(json.loads(second[1])["output"])
            self.assertNotEqual(first_path, second_path)
            report = json.loads(second_path.read_text())
            self.assertEqual(report["schema_version"], 2)
            self.assertFalse(report["stela_translated_system_verified"])
            self.assertIn("No translated macOS system launch contract", second[2])
            self.assertIn("Translated macOS boot unavailable", second[2])

    def test_explicit_receipt_cannot_overwrite_or_escape_private_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            existing = root / ".stela" / "existing.json"
            existing.parent.mkdir()
            original = b"immutable historical receipt\n"
            existing.write_bytes(original)
            for output in (existing, root / "public.json"):
                code, stdout, stderr = self.invoke(root, ["--output", str(output)])
                self.assertEqual(code, 2)
                self.assertEqual(stdout, "")
                self.assertIn("error:", stderr)
            self.assertEqual(existing.read_bytes(), original)

    def test_explicit_failed_tool_returns_failure_after_private_receipt(self):
        archive = {"build": "fixture-build", "model": "fixture-model",
                   "device_tree": {"node_count": 1}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for option in ("--qemu", "--x86-qemu"):
                code, stdout, stderr = self.invoke(root, [option, "missing-qemu"], archive)
                self.assertEqual(code, 2)
                receipt = Path(json.loads(stdout)["output"])
                self.assertTrue(receipt.is_file())
                self.assertIn("Explicit QEMU prerequisite failed", stderr)

    def test_malformed_manifest_shapes_fail_without_traceback_or_receipt(self):
        valid_identity = {"Ap,ProductType": "VirtualMac2,1",
                          "Info": {"Variant": "fixture", "DeviceClass": "fixture"}, "Manifest": {}}
        malformed = [[], {}, {"ProductVersion": "fixture", "ProductBuildVersion": "fixture",
                                "BuildIdentities": "wrong"}]
        for identity in ([], {**valid_identity, "Info": []}, {**valid_identity, "Manifest": []},
                         {**valid_identity, "Manifest": {"DeviceTree": []}},
                         {**valid_identity, "Manifest": {"DeviceTree": {"Info": []}}},
                         {**valid_identity, "Manifest": {"DeviceTree": {"Info": {"Path": 123}}}}):
            malformed.append({"ProductVersion": "fixture", "ProductBuildVersion": "fixture",
                              "BuildIdentities": [identity]})
        malformed.append(b'<?xml version="1.0"?><plist><dict><key>x</key>')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for index, manifest in enumerate(malformed):
                with self.subTest(manifest=manifest):
                    ipsw = root / f"malformed-{index}.ipsw"
                    receipt = root / ".stela" / f"report-{index}.json"
                    with zipfile.ZipFile(ipsw, "w") as archive:
                        archive.writestr("BuildManifest.plist", manifest if isinstance(manifest, bytes)
                                         else plistlib.dumps(manifest))
                    err = io.StringIO()
                    with patch.object(preflight, "ROOT", root), patch.object(
                            sys, "argv", ["preflight", str(ipsw), "--output", str(receipt)]), \
                            contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as failure:
                        preflight.main()
                    self.assertEqual(failure.exception.code, 2)
                    self.assertIn("Preflight failed; no receipt written", err.getvalue())
                    self.assertNotIn("Traceback", err.getvalue())
                    self.assertFalse(receipt.exists())


if __name__ == "__main__":
    unittest.main()
