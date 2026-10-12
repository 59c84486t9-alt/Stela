"""Filesystem acquisition tests use owned temporary trees and mocked tools only."""
import importlib.util
import json
from pathlib import Path
import plistlib
import shutil
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("apple_filesystem", Path(__file__).with_name("apple-filesystem.py"))
apple = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(apple)


def thin(cpu=0x0100000c, subtype=2):
    return b"\xcf\xfa\xed\xfe" + struct.pack("<IIIIIII", cpu, subtype, 2, 0, 0, 0, 0)


class GuestPathTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "usr/bin").mkdir(parents=True)
        (self.root / "usr/bin/example").write_bytes(thin())

    def tearDown(self):
        self.temporary.cleanup()

    def test_absolute_symlink_uses_guest_root_even_when_host_target_exists(self):
        (self.root / "bin").symlink_to("/usr/bin")
        path, resolved, links = apple.resolve_guest(self.root, "/bin/example")
        self.assertEqual(path, self.root / "usr/bin/example")
        self.assertEqual(resolved, "/usr/bin/example")
        self.assertEqual(links, [{"path": "/bin", "target": "/usr/bin"}])

    def test_relative_link_and_parent_stay_in_guest_root(self):
        (self.root / "usr/bin/link").symlink_to("../bin/example")
        self.assertEqual(apple.resolve_guest(self.root, "/usr/bin/link")[0], self.root / "usr/bin/example")

    def test_guest_cryptex_absolute_link_never_resolves_host_system(self):
        (self.root / "System").mkdir()
        (self.root / "System/Cryptexes").symlink_to("/private/preboot/Cryptexes")
        (self.root / "private/preboot/Cryptexes").mkdir(parents=True)
        (self.root / "private/preboot/Cryptexes/data").write_bytes(b"guest")
        path, _, _ = apple.resolve_guest(self.root, "/System/Cryptexes/data")
        self.assertEqual(path.read_bytes(), b"guest")

    def test_escape_and_cycle_decline(self):
        for target in ("../../outside", "/../outside"):
            link = self.root / "link"
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "escapes"):
                apple.resolve_guest(self.root, "/link")
            link.unlink()
        (self.root / "a").symlink_to("b")
        (self.root / "b").symlink_to("a")
        with self.assertRaisesRegex(ValueError, "cycle"):
            apple.resolve_guest(self.root, "/a")

    def test_invalid_user_paths_decline(self):
        for path in ("relative", "/../../host", "/\0bad", "/bin/../example"):
            with self.assertRaises(ValueError):
                apple.validate_guest_path(path)

    def test_cross_device_directory_declined_before_traversing_children(self):
        original = Path.lstat
        visited = []

        def directory_on_another_device(path):
            visited.append(path)
            info = original(path)
            if path == self.root / "usr":
                return SimpleNamespace(st_dev=info.st_dev + 1, st_mode=info.st_mode)
            return info

        with patch.object(Path, "lstat", directory_on_another_device):
            with self.assertRaisesRegex(ValueError, "owned volume"):
                apple.resolve_guest(self.root, "/usr/bin/example")
        self.assertEqual(visited, [self.root / "usr"])

    def test_directory_and_fifo_are_not_acquired(self):
        for path in ("/usr/bin",):
            with self.assertRaisesRegex(ValueError, "ordinary file"):
                apple.inspect_file(self.root, path)
        import os
        os.mkfifo(self.root / "fifo")
        with self.assertRaisesRegex(ValueError, "ordinary file"):
            apple.inspect_file(self.root, "/fifo")

    def test_copy_preserves_bytes_and_records_guest_symlink_resolution(self):
        (self.root / "link").symlink_to("/usr/bin/example")
        target = self.root / "copies/link"
        result = apple.inspect_file(self.root, "/link", target)
        self.assertEqual(target.read_bytes(), thin())
        self.assertEqual(result["sha256"], apple.digest(thin()))
        self.assertEqual(result["destination_sha256"], result["sha256"])
        self.assertEqual(result["resolved_guest_path"], "/usr/bin/example")
        self.assertEqual(result["format"]["architectures"][0]["name"], "arm64e")
        with self.assertRaises(FileExistsError):
            apple.inspect_file(self.root, "/link", target)


class FileFormatTests(unittest.TestCase):
    def test_apple_x1_and_unreviewed_subtypes_are_not_baseline_arm64(self):
        for subtype, name in [(0x8000000c, "arm64e.x1"), (0x8000007f, "arm64-subtype-127")]:
            result = apple.file_format(thin(subtype=subtype), 32)["architectures"][0]
            self.assertEqual(result["name"], name)
            self.assertEqual(result["cpu_subtype"], subtype)

    def test_thin_endianness_and_arm_subtype_capability_bits(self):
        self.assertEqual(apple.file_format(thin(subtype=0x80000002), 32)["architectures"][0]["name"], "arm64e")
        header = b"\xfe\xed\xfa\xcf" + struct.pack(">IIIIIII", 0x01000007, 3, 2, 0, 0, 0, 0)
        self.assertEqual(apple.file_format(header, 32)["architectures"][0]["name"], "x86_64")

    def test_fat_and_fat64_slice_metadata(self):
        for wide in (False, True):
            header = (b"\xca\xfe\xba\xbf" if wide else b"\xca\xfe\xba\xbe") + struct.pack(">I", 1)
            entry = struct.pack(">IIQQII", 0x0100000c, 2, 4096, 32, 12, 0) if wide else struct.pack(">IIIII", 0x0100000c, 2, 4096, 32, 12)
            result = apple.file_format(header + entry, 4128)
            self.assertEqual(result["kind"], "fat_mach_o")
            self.assertEqual(result["architectures"][0]["offset"], 4096)

    def test_malformed_headers_decline(self):
        for prefix, size in [(thin()[:8], 8), (b"\xca\xfe\xba\xbe" + struct.pack(">I", 129), 4096),
                             (b"\xca\xfe\xba\xbe" + struct.pack(">I", 1) + struct.pack(">IIIII", 12, 0, 4096, 32, 12), 4096)]:
            with self.assertRaises(ValueError):
                apple.file_format(prefix, size)

    def test_cache_and_other_are_inventory_only(self):
        self.assertEqual(apple.file_format(b"dyld_v1  arm64e\0\0", 16)["kind"], "dyld_shared_cache")
        self.assertEqual(apple.file_format(b"data", 4)["kind"], "other")


class FakeTools:
    def __init__(self, image, readonly=True, detach_ok=True, raw=False, attach_exit=0):
        self.image = image
        self.readonly, self.detach_ok, self.raw, self.attach_exit = readonly, detach_ok, raw, attach_exit
        self.attached = False
        self.mount = None
        self.calls = []
        self.outside_mount = False
        self.pretend_existing = False
        self.keep_after_detach = False
        self.backing_virtual = True
        self.attach_response = "valid"
        self.residual_child = False
        self.detached_once = False

    def entities(self):
        result = [{"dev-entry": "/dev/disk40", "content-hint": "Apple_APFS" if self.raw else "GUID_partition_scheme"}]
        if not self.raw:
            result.append({"dev-entry": "/dev/disk40s1", "content-hint": "7C3457EF-0000-11AA-AA11-00306543ECAC"})
        result.extend([{"dev-entry": "/dev/disk41", "content-hint": "EF57347C-0000-11AA-AA11-00306543ECAC"},
                       {"dev-entry": "/dev/disk41s1", "mount-point": str(self.mount)}])
        return result

    def image_record(self):
        return {"image-path": str(self.image), "writeable": not self.readonly, "system-entities": self.entities()}

    def __call__(self, argv, **options):
        self.calls.append(argv)
        assert options["stdin"] == subprocess.DEVNULL
        assert options["capture_output"] is True
        assert options["timeout"] == 300
        code, payload = 0, None
        if argv[:3] == ["/usr/bin/hdiutil", "info", "-plist"]:
            records = [self.image_record()] if self.attached or self.pretend_existing else []
            if self.detached_once and self.residual_child:
                records.append({"image-path": str(self.image.parent / "other.dmg"),
                                "system-entities": [{"dev-entry": "/dev/disk41s1", "mount-point": str(self.mount)}]})
            payload = {"images": records}
        elif argv[:2] == ["/usr/bin/hdiutil", "attach"]:
            for flag in ("-readonly", "-nobrowse", "-noautoopen", "-noautofsck", "-plist"):
                assert flag in argv
            base = Path(argv[argv.index("-mountroot") + 1])
            self.mount = base / "System"
            if self.outside_mount:
                self.mount = base.parent / "outside"
            (self.mount / "bin").mkdir(parents=True)
            (self.mount / "bin/example").write_bytes(thin())
            (self.mount / "System/Library/CoreServices").mkdir(parents=True)
            (self.mount / "System/Library/CoreServices/SystemVersion.plist").write_bytes(
                plistlib.dumps({"ProductName": "macOS", "ProductVersion": "27.0", "ProductBuildVersion": "26A434"}))
            cache = self.mount / "System/Library/dyld"
            cache.mkdir()
            for suffix in ("", ".01", ".25.data", ".symbols"):
                (cache / ("dyld_shared_cache_arm64e" + suffix)).write_bytes(b"dyld_v1  arm64e\0\0" + suffix.encode())
            (cache / "dyld_shared_cache_x86_64").write_bytes(b"host architecture excluded")
            self.attached = True
            payload, code = {"system-entities": self.entities()}, self.attach_exit
            if self.attach_response == "timeout":
                raise subprocess.TimeoutExpired(argv, 300, output=b"partial attach", stderr=b"timeout")
            if self.attach_response in ("invalid", "absent"):
                return subprocess.CompletedProcess(argv, 0, b"not a plist" if self.attach_response == "invalid" else b"", b"")
        elif argv[:3] == ["/usr/sbin/diskutil", "info", "-plist"]:
            device = argv[3]
            payload = {"DeviceIdentifier": device.removeprefix("/dev/"), "Writable": not self.readonly}
            if device == "/dev/disk40":
                payload.update(WholeDisk=True, ParentWholeDisk="disk40",
                               VirtualOrPhysical="Virtual" if self.backing_virtual else "Physical")
            elif device == "/dev/disk41":
                payload.update(WholeDisk=True, APFSPhysicalStores=[{"APFSPhysicalStore": "disk40" if self.raw else "disk40s1"}])
            elif device == "/dev/disk40s1":
                payload["ParentWholeDisk"] = "disk40"
            elif device == "/dev/disk41s1":
                payload.update(MountPoint=str(self.mount), FilesystemType="apfs", WritableMedia=not self.readonly,
                               WritableVolume=not self.readonly, Encryption=False, Sealed="Yes")
        elif argv[:2] == ["/usr/bin/hdiutil", "detach"]:
            assert argv[2] == "/dev/disk40", "Must detach backing disk, never synthesized APFS container"
            assert "-force" not in argv
            code = 0 if self.detach_ok else 1
            self.detached_once = True
            if self.detach_ok and not self.keep_after_detach:
                self.attached = False
                shutil.rmtree(self.mount)
        else:
            raise AssertionError(f"Unexpected subprocess: {argv}")
        return subprocess.CompletedProcess(argv, code, plistlib.dumps(payload) if payload is not None else b"", b"mock failure" if code else b"")


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.image = self.root / "decoded.dmg"
        self.image.write_bytes(b"synthetic decoded image")
        self.output = self.root / ".stela/acquired"
        self.root_patch = patch.object(apple, "ROOT", self.root)
        self.root_patch.start()
        self.writer_patch = patch.object(apple, "write_evidence", self.write_receipt)
        self.writer_patch.start()

    def tearDown(self):
        self.writer_patch.stop()
        self.root_patch.stop()
        self.temporary.cleanup()

    @staticmethod
    def write_receipt(path, report):
        path.write_text(json.dumps(report))
        return path

    def acquire(self, tools, paths=("/bin/example",), **kwargs):
        return apple.Acquisition(self.image, self.output, paths, runner=tools, **kwargs).run()

    def test_success_records_provenance_copy_build_and_owned_detach(self):
        tools = FakeTools(self.image)
        report = self.acquire(tools, shared_cache=True)
        self.assertTrue(report["acquired"])
        self.assertTrue(report["readonly_verified"])
        self.assertEqual((self.output / "files/bin/example").read_bytes(), thin())
        self.assertEqual(report["image_sha256"], apple.digest(self.image.read_bytes()))
        self.assertEqual(report["volumes"][0]["build_plists"][0]["values"]["ProductBuildVersion"], "26A434")
        self.assertEqual(len(report["shared_cache_inventory"]), 4)
        self.assertTrue(report["cleanup"]["verified"])
        self.assertTrue(report["cleanup"]["mount_root_removed"])
        self.assertTrue((self.output / "receipt.json").is_file())

    def test_raw_apfs_backing_disk_resolved_from_physical_store(self):
        report = self.acquire(FakeTools(self.image, raw=True))
        self.assertTrue(report["acquired"])
        self.assertEqual(report["owned_backing_device"], "/dev/disk40")

    def test_optional_missing_path_recorded_and_cache_family_copied_completely(self):
        report = self.acquire(FakeTools(self.image), paths=(), optional_paths=("/missing", "/bin/example"),
                              copy_shared_cache=True)
        self.assertTrue(report["acquired"])
        self.assertEqual(report["optional_missing"], ["/missing"])
        self.assertEqual(len(report["files"]), 5)
        for item in report["shared_cache_inventory"]:
            destination = self.output / item["destination"]
            self.assertEqual(apple.digest(destination.read_bytes()), item["sha256"])

    def test_cache_explicit_path_is_not_copied_twice(self):
        report = self.acquire(FakeTools(self.image), paths=("/System/Library/dyld/dyld_shared_cache_arm64e",),
                              copy_shared_cache=True)
        self.assertTrue(report["acquired"])
        self.assertEqual(len(report["files"]), 4)

    def test_readonly_failure_still_detaches_but_never_claims_acquisition(self):
        tools = FakeTools(self.image, readonly=False)
        report = self.acquire(tools)
        self.assertFalse(report["acquired"])
        self.assertFalse(report["readonly_verified"])
        self.assertTrue(report["cleanup"]["verified"])
        self.assertFalse((self.output / "files").exists())

    def test_detach_failure_keeps_receipt_and_marks_acquisition_unsuccessful(self):
        report = self.acquire(FakeTools(self.image, detach_ok=False))
        self.assertFalse(report["acquired"])
        self.assertTrue(report["cleanup"]["attempted"])
        self.assertFalse(report["cleanup"]["detached"])
        self.assertTrue((self.output / "receipt.json").is_file())

    def test_detach_exit_zero_without_inventory_disappearance_is_not_proof(self):
        tools = FakeTools(self.image)
        tools.keep_after_detach = True
        report = self.acquire(tools)
        self.assertFalse(report["acquired"])
        self.assertTrue(report["cleanup"]["detached"])
        self.assertFalse(report["cleanup"]["verified"])

    def test_missing_file_failure_still_detaches_and_keeps_receipt(self):
        report = self.acquire(FakeTools(self.image), paths=("/missing",))
        self.assertFalse(report["acquired"])
        self.assertTrue(report["cleanup"]["verified"])
        self.assertTrue((self.output / "receipt.json").is_file())

    def test_outside_mountpoint_declined_without_copy_and_owned_disk_detached(self):
        tools = FakeTools(self.image)
        tools.outside_mount = True
        report = self.acquire(tools)
        self.assertFalse(report["acquired"])
        self.assertIn("exclusive mount root", report["error"])
        self.assertTrue(report["cleanup"]["verified"])

    def test_failed_attach_with_owned_plist_is_cleaned_up(self):
        report = self.acquire(FakeTools(self.image, attach_exit=1))
        self.assertFalse(report["acquired"])
        self.assertEqual(report["error"], "Image attach failed")
        self.assertTrue(report["cleanup"]["verified"])

    def test_nonvirtual_backing_proof_failure_never_assigns_or_detaches_device(self):
        tools = FakeTools(self.image)
        tools.backing_virtual = False
        report = self.acquire(tools)
        self.assertFalse(report["acquired"])
        self.assertNotIn("owned_backing_device", report)
        self.assertFalse(report["cleanup"]["attempted"])
        self.assertFalse(any(command[1] == "detach" for command in tools.calls))

    def test_invalid_absent_and_timed_out_attach_responses_recover_only_owned_inventory(self):
        for response in ("invalid", "absent", "timeout"):
            with self.subTest(response=response):
                self.output = self.root / (".stela/failed-" + response)
                tools = FakeTools(self.image)
                tools.attach_response = response
                report = self.acquire(tools)
                self.assertFalse(report["acquired"])
                self.assertTrue(report["ownership_recovered_from_inventory"])
                self.assertTrue(report["cleanup"]["verified"])
                self.assertFalse((self.output / "files").exists())

    def test_disappearing_backing_disk_without_all_children_is_not_cleanup_proof(self):
        tools = FakeTools(self.image)
        tools.residual_child = True
        report = self.acquire(tools)
        self.assertFalse(report["acquired"])
        self.assertFalse(report["cleanup"]["verified"])
        self.assertEqual(report["cleanup"]["remaining_owned_devices"], ["/dev/disk41s1"])
        self.assertEqual(report["cleanup"]["remaining_owned_mountpoints"], [str(tools.mount)])

    def test_existing_output_is_not_overwritten(self):
        self.output.mkdir(parents=True)
        (self.output / "sentinel").write_text("owned by someone else")
        tools = FakeTools(self.image)
        with self.assertRaises(FileExistsError):
            self.acquire(tools)
        self.assertEqual(tools.calls, [])
        self.assertEqual((self.output / "sentinel").read_text(), "owned by someone else")

    def test_existing_attachment_is_not_borrowed_or_detached(self):
        tools = FakeTools(self.image)
        tools.pretend_existing = True
        tools.mount = self.root / "preexisting"
        report = self.acquire(tools)
        self.assertFalse(report["acquired"])
        self.assertIn("already attached", report["error"])
        self.assertFalse(report["cleanup"]["attempted"])
        self.assertFalse(any(command[1] == "detach" for command in tools.calls))

    def test_output_outside_ignored_root_rejected_before_subprocess(self):
        tools = FakeTools(self.image)
        with self.assertRaisesRegex(ValueError, "inside"):
            apple.Acquisition(self.image, self.root / "outside", [], runner=tools).run()
        self.assertEqual(tools.calls, [])

    def test_unsupported_volume_selection_still_detaches(self):
        report = self.acquire(FakeTools(self.image), volume="not-this-volume")
        self.assertFalse(report["acquired"])
        self.assertTrue(report["cleanup"]["verified"])

    def test_plist_data_serializes_without_losing_raw_provenance(self):
        self.assertEqual(apple.json_ready({"value": b"\x00\xff"}), {"value": {"plist_data_hex": "00ff"}})


if __name__ == "__main__":
    unittest.main()
