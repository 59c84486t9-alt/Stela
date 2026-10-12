#!/usr/bin/env python3
"""Acquire selected guest files from a locally decoded Apple disk image.

Uses the host filesystem driver read-only. This does not establish compatibility
with a newer APFS format, decrypt APFS volumes, or extract dyld cache dylibs.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import stat
import struct
import subprocess
import tempfile

from evidence import write_evidence

ROOT = Path(__file__).resolve().parents[1]
DEVICE = re.compile(r"/dev/disk[0-9]+(?:s[0-9]+)*\Z")
WHOLE_DEVICE = re.compile(r"/dev/disk[0-9]+\Z")
SCHEMES = {"GUID_partition_scheme", "Apple_partition_scheme", "FDisk_partition_scheme"}
BUILD_PATHS = (
    "/System/Library/CoreServices/SystemVersion.plist",
    "/System/Library/CoreServices/SystemVersionCompat.plist",
    "/System/Library/CoreServices/ServerVersion.plist",
)
CACHE_DIRS = (
    "/System/Library/dyld",
    "/System/Library/Caches/com.apple.dyld",
    "/System/Cryptexes/OS/System/Library/dyld",
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld",
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_ready(value):
    if isinstance(value, dict):
        return {key: json_ready(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_ready(item) for item in value]
    if isinstance(value, bytes):
        return {"plist_data_hex": value.hex()}
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    return value


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def validate_guest_path(path):
    if not isinstance(path, str) or not path.startswith("/") or "\0" in path:
        raise ValueError(f"Expected an absolute guest path: {path!r}")
    parts = []
    for component in path.split("/"):
        if component in ("", "."):
            continue
        if component == "..":
            raise ValueError(f"Requested guest paths must not contain '..': {path!r}")
        else:
            parts.append(component)
    return "/" + "/".join(parts)


def resolve_guest(root, guest_path):
    """Resolve symlinks component by component; absolute targets are guest paths.

    Path.resolve() on a guest child would incorrectly interpret an absolute
    symlink target in the host filesystem. Never use it here.
    """
    pending = validate_guest_path(guest_path).split("/")[1:]
    parts, links, visited = [], [], set()
    root_device = root.stat().st_dev
    while pending:
        component = pending.pop(0)
        if component in ("", "."):
            continue
        if component == "..":
            if not parts:
                raise ValueError("Guest symlink escapes root")
            parts.pop()
            continue
        candidate = root.joinpath(*parts, component)
        info = candidate.lstat()
        if info.st_dev != root_device:
            raise ValueError("Guest path crosses outside its owned volume")
        if stat.S_ISLNK(info.st_mode):
            key = (tuple(parts), component, tuple(pending))
            if key in visited or len(links) >= 40:
                raise ValueError("Guest symlink cycle or depth limit")
            visited.add(key)
            target = os.readlink(candidate)
            links.append({"path": "/" + "/".join([*parts, component]), "target": target})
            if target.startswith("/"):
                parts = []
            pending = target.split("/") + pending
        else:
            if pending and not stat.S_ISDIR(info.st_mode):
                raise ValueError("Guest path traverses a non-directory")
            parts.append(component)
    return root.joinpath(*parts), "/" + "/".join(parts), links


def architecture(cpu, subtype):
    base = subtype & 0xffffff
    name = {7: "i386", 0x01000007: "x86_64", 12: "arm", 0x0100000c: "arm64"}.get(cpu, "unknown")
    if cpu == 0x0100000c:
        # LLVM MachO.h 4a0a7e3ddc3b names subtype12 arm64e.x1. Format naming
        # does not imply support for its instruction/ABI execution profile.
        name = {0: "arm64", 2: "arm64e", 12: "arm64e.x1"}.get(base, f"arm64-subtype-{base}")
    return {"name": name, "cpu_type": cpu, "cpu_subtype": subtype}


def file_format(prefix, size):
    magic = prefix[:4]
    result = {"kind": "other", "magic_hex": magic.hex(), "architectures": []}
    thin = {
        b"\xcf\xfa\xed\xfe": ("<", 32), b"\xce\xfa\xed\xfe": ("<", 28),
        b"\xfe\xed\xfa\xcf": (">", 32), b"\xfe\xed\xfa\xce": (">", 28),
    }
    fat = {
        b"\xca\xfe\xba\xbe": (">", False), b"\xbe\xba\xfe\xca": ("<", False),
        b"\xca\xfe\xba\xbf": (">", True), b"\xbf\xba\xfe\xca": ("<", True),
    }
    if magic in thin:
        endian, header_size = thin[magic]
        if len(prefix) < header_size:
            raise ValueError("Truncated Mach-O header")
        cpu, subtype = struct.unpack_from(endian + "II", prefix, 4)
        result.update(kind="mach_o", architectures=[architecture(cpu, subtype)])
    elif magic in fat:
        endian, wide = fat[magic]
        if len(prefix) < 8:
            raise ValueError("Truncated fat Mach-O header")
        count = struct.unpack_from(endian + "I", prefix, 4)[0]
        entry_size = 32 if wide else 20
        if not 0 < count <= 128 or len(prefix) < 8 + count * entry_size:
            raise ValueError("Invalid or oversized fat Mach-O architecture table")
        entries = []
        for index in range(count):
            fields = struct.unpack_from(endian + ("IIQQII" if wide else "IIIII"), prefix, 8 + index * entry_size)
            cpu, subtype, offset, length, alignment = fields[:5]
            if offset < 8 + count * entry_size or length == 0 or offset > size or length > size - offset:
                raise ValueError("Fat Mach-O slice outside file")
            if alignment > 63 or offset % (1 << alignment):
                raise ValueError("Invalid fat Mach-O slice alignment")
            entry = architecture(cpu, subtype)
            entry.update(offset=offset, bytes=length, alignment=alignment)
            entries.append(entry)
        result.update(kind="fat_mach_o", architectures=entries)
    elif prefix.startswith(b"dyld_v"):
        result.update(kind="dyld_shared_cache", cache_magic=prefix[:16].decode("ascii", "replace").rstrip("\0 "))
    return result


def inspect_file(root, guest_path, destination=None):
    path, resolved, links = resolve_guest(root, guest_path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_dev != root.stat().st_dev:
        raise ValueError(f"Selected guest path is not an ordinary file on its owned volume: {guest_path}")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        opened = os.fstat(source.fileno())
        if identity(opened) != identity(info):
            raise ValueError("Guest file changed before opening")
        writer = None
        try:
            if destination is not None:
                destination.parent.mkdir(parents=True, exist_ok=True)
                writer = destination.open("xb")
            checksum, prefix, count = hashlib.sha256(), b"", 0
            while chunk := source.read(4 * 1024 * 1024):
                checksum.update(chunk)
                if len(prefix) < 8192:
                    prefix += chunk[:8192 - len(prefix)]
                count += len(chunk)
                if writer is not None:
                    writer.write(chunk)
            if identity(os.fstat(source.fileno())) != identity(opened) or count != info.st_size:
                raise ValueError("Guest file changed during acquisition")
            if writer is not None:
                writer.flush()
                os.fsync(writer.fileno())
        finally:
            if writer is not None:
                writer.close()
    result = {
        "guest_path": validate_guest_path(guest_path), "resolved_guest_path": resolved,
        "symlinks": links, "bytes": count, "sha256": checksum.hexdigest(),
        "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid,
        "format": file_format(prefix, count),
    }
    if destination is not None:
        copied_hash = hashlib.sha256()
        with destination.open("rb") as copied:
            while chunk := copied.read(4 * 1024 * 1024):
                copied_hash.update(chunk)
        if destination.stat().st_size != count or copied_hash.hexdigest() != result["sha256"]:
            raise ValueError("Copied guest file differs from source bytes")
        result.update(copied=True, destination_sha256=copied_hash.hexdigest())
    return result


class Acquisition:
    def __init__(self, image, output, paths, shared_cache=False, volume=None, runner=subprocess.run,
                 optional_paths=(), copy_shared_cache=False):
        self.image, self.output = image.resolve(), output.resolve()
        self.paths = [validate_guest_path(path) for path in paths]
        self.optional_paths = [validate_guest_path(path) for path in optional_paths]
        if len(set(self.paths + self.optional_paths)) != len(self.paths + self.optional_paths):
            raise ValueError("Duplicate selected guest paths")
        self.shared_cache = shared_cache or copy_shared_cache
        self.copy_shared_cache, self.volume, self.runner = copy_shared_cache, volume, runner
        self.mount_root = None
        self.owned_device = None
        self.owned_devices = set()
        self.owned_mountpoints = set()
        self.attach_attempted = False
        self.before_devices = set()
        self.device_info = {}
        self.receipt = {
            "schema_version": 1, "kind": "apple_filesystem_acquisition", "acquired": False,
            "image_path": str(self.image), "output": str(self.output),
            "requested_guest_paths": self.paths,
            "optional_guest_paths": self.optional_paths, "optional_missing": [],
            "harness_sha256": digest(Path(__file__).read_bytes()), "commands": [],
            "host": {"architecture": platform.machine(), "macos_version": platform.mac_ver()[0]},
            "volumes": [], "files": [], "shared_cache_inventory": [],
            "readonly_verified": False,
            "cleanup": {"attempted": False, "detached": False, "verified": False},
            "limits": "Host read-only filesystem access only; newer APFS compatibility, APFS decryption, dyld cache extraction and guest execution are not established. Magic/architecture inventory is header inspection, not complete Mach-O load validation.",
        }

    def command(self, argv, plist=False, allow_failure=False):
        record = {"argv": [str(value) for value in argv]}
        self.receipt["commands"].append(record)
        try:
            completed = self.runner(record["argv"], stdin=subprocess.DEVNULL, capture_output=True, timeout=300)
        except (OSError, subprocess.TimeoutExpired) as error:
            record["error"] = str(error)
            if isinstance(error, subprocess.TimeoutExpired):
                record["stdout"] = (error.stdout or b"").decode("utf-8", "replace")
                record["stderr"] = (error.stderr or b"").decode("utf-8", "replace")
            raise
        record.update(exit_code=completed.returncode,
                      stdout=completed.stdout.decode("utf-8", "replace"),
                      stderr=completed.stderr.decode("utf-8", "replace"))
        parsed = None
        if plist and completed.stdout:
            try:
                parsed = plistlib.loads(completed.stdout)
            except Exception as error:
                record["plist_error"] = str(error)
                raise ValueError("Tool returned an invalid plist") from error
            record["plist"] = parsed
        if completed.returncode != 0 and not allow_failure:
            raise RuntimeError(f"Command failed ({completed.returncode}): {' '.join(record['argv'])}")
        return parsed if plist else completed

    def image_records(self):
        document = self.command(["/usr/bin/hdiutil", "info", "-plist"], plist=True)
        if not isinstance(document, dict) or not isinstance(document.get("images"), list):
            raise ValueError("Invalid hdiutil image inventory")
        return document["images"]

    @staticmethod
    def entities(record):
        entities = record.get("system-entities")
        if not isinstance(entities, list) or not entities:
            raise ValueError("No disk entities returned")
        for entity in entities:
            if not isinstance(entity, dict) or not DEVICE.fullmatch(entity.get("dev-entry", "")):
                raise ValueError("Invalid disk-image device entry")
        if len({entity["dev-entry"] for entity in entities}) != len(entities):
            raise ValueError("Duplicate disk-image device entries")
        return entities

    def info(self, device):
        if not DEVICE.fullmatch(device):
            raise ValueError("Invalid disk device identifier")
        if device not in self.device_info:
            result = self.command(["/usr/sbin/diskutil", "info", "-plist", device], plist=True)
            if not isinstance(result, dict) or result.get("DeviceIdentifier") != device.removeprefix("/dev/"):
                raise ValueError("diskutil returned a different device")
            self.device_info[device] = result
        return self.device_info[device]

    def establish_ownership(self, attachment):
        entities = self.entities(attachment)
        devices = {entity["dev-entry"] for entity in entities}
        if devices & self.before_devices:
            raise ValueError("Attachment reused a pre-existing device; ownership unproven")
        matches = [record for record in self.image_records()
                   if Path(record.get("image-path", "")).resolve() == self.image]
        if len(matches) != 1 or not devices.issubset({entity["dev-entry"] for entity in self.entities(matches[0])}):
            raise ValueError("Returned devices are not uniquely associated with the requested image")
        roots = {entity["dev-entry"] for entity in entities
                 if entity.get("content-hint") in SCHEMES and WHOLE_DEVICE.fullmatch(entity["dev-entry"])}
        if not roots:
            for device in devices:
                for store in self.info(device).get("APFSPhysicalStores", []):
                    physical = "/dev/" + store.get("APFSPhysicalStore", "")
                    if physical not in devices:
                        raise ValueError("APFS physical store was not returned by this attachment")
                    backing = "/dev/" + self.info(physical).get("ParentWholeDisk", "")
                    if not WHOLE_DEVICE.fullmatch(backing) or backing not in devices:
                        raise ValueError("APFS backing disk ownership unproven")
                    roots.add(backing)
        if len(roots) != 1:
            raise ValueError("Cannot identify one owned backing disk")
        backing_device = roots.pop()
        backing_info = self.info(backing_device)
        if (backing_info.get("WholeDisk") is not True
                or backing_info.get("VirtualOrPhysical") != "Virtual"):
            raise ValueError("Owned whole virtual backing-device proof failed")
        self.owned_device = backing_device
        self.owned_devices = devices
        self.owned_mountpoints = {entity["mount-point"] for entity in entities if "mount-point" in entity}
        self.receipt.update(owned_backing_device=self.owned_device,
                            owned_devices=sorted(self.owned_devices),
                            owned_mountpoints=sorted(self.owned_mountpoints))
        if matches[0].get("writeable") is not False or backing_info.get("Writable") is not False:
            raise ValueError("Read-only backing image/device is unproven")
        return entities

    def recover_ownership(self):
        """One bounded inventory recovery after an unsuccessful attach response.

        New devices and exact image identity alone can be ambiguous with another
        process. Require a mounted volume inside this invocation's unique root.
        An attachment without that additional proof is left for manual review.
        """
        matches = [record for record in self.image_records()
                   if Path(record.get("image-path", "")).resolve() == self.image]
        if len(matches) != 1:
            raise ValueError("No unique same-image attachment for ownership recovery")
        points = [Path(entity["mount-point"]) for entity in self.entities(matches[0])
                  if "mount-point" in entity]
        if (not points or any(not point.is_absolute() or point.is_symlink()
                              or point.resolve() == self.mount_root
                              or not point.resolve().is_relative_to(self.mount_root) for point in points)):
            raise ValueError("Incomplete attach has no exclusive mount-root ownership proof; manual review required")
        self.establish_ownership(matches[0])
        self.receipt["ownership_recovered_from_inventory"] = True

    def inspect_volumes(self, entities):
        mounted = []
        for entity in entities:
            if "mount-point" not in entity:
                continue
            point = Path(entity["mount-point"])
            if (not point.is_absolute() or not point.is_dir() or point.is_symlink()
                    or point.resolve() == self.mount_root
                    or not point.resolve().is_relative_to(self.mount_root)):
                raise ValueError("Returned mount point is outside the exclusive mount root")
            info = self.info(entity["dev-entry"])
            if (info.get("MountPoint") != str(point)
                    or any(info.get(key) is not False for key in ("Writable", "WritableMedia", "WritableVolume"))):
                raise ValueError("Read-only mounted volume is unproven")
            volume = {"device": entity["dev-entry"], "mount_point": str(point),
                      "diskutil": info, "build_plists": []}
            self.receipt["volumes"].append(volume)
            for path in BUILD_PATHS:
                try:
                    resolved, _, _ = resolve_guest(point, path)
                except FileNotFoundError:
                    continue
                if resolved.stat().st_size > 1024 * 1024:
                    raise ValueError("Oversized system-version plist")
                metadata = inspect_file(point, path)
                values = plistlib.loads(resolved.read_bytes())
                if not isinstance(values, dict):
                    raise ValueError("System-version plist is not a dictionary")
                metadata["values"] = {key: values[key] for key in
                                      ("ProductName", "ProductVersion", "ProductBuildVersion") if key in values}
                volume["build_plists"].append(metadata)
            mounted.append((point, volume))
        if not mounted:
            raise ValueError("Attachment returned no readable mounted volumes")
        self.receipt["readonly_verified"] = True
        if self.volume is not None:
            mounted = [(point, record) for point, record in mounted
                       if self.volume in (record["device"], record["device"].removeprefix("/dev/"), point.name)]
        if len(mounted) != 1:
            raise ValueError("Select exactly one mounted volume using --volume")
        return mounted[0]

    def acquire_files(self, point):
        paths = list(self.paths)
        for path in self.optional_paths:
            try:
                resolve_guest(point, path)
            except FileNotFoundError:
                self.receipt["optional_missing"].append(path)
                continue
            paths.append(path)
        copied = {}
        for path in paths:
            destination = self.output / "files" / path.lstrip("/")
            metadata = inspect_file(point, path, destination)
            metadata["destination"] = str(destination.relative_to(self.output))
            self.receipt["files"].append(metadata)
            copied[path] = metadata
        if self.shared_cache:
            seen = set()
            for directory in CACHE_DIRS:
                try:
                    resolved, _, _ = resolve_guest(point, directory)
                except FileNotFoundError:
                    continue
                if not resolved.is_dir():
                    continue
                for child in sorted(resolved.iterdir()):
                    if not child.name.startswith("dyld_shared_cache_arm64"):
                        continue
                    path = directory + "/" + child.name
                    canonical, _, _ = resolve_guest(point, path)
                    if canonical in seen:
                        continue
                    seen.add(canonical)
                    if path in copied:
                        metadata = copied[path]
                    elif self.copy_shared_cache:
                        destination = self.output / "files" / path.lstrip("/")
                        metadata = inspect_file(point, path, destination)
                        metadata["destination"] = str(destination.relative_to(self.output))
                        self.receipt["files"].append(metadata)
                    else:
                        metadata = inspect_file(point, path)
                    self.receipt["shared_cache_inventory"].append(metadata)

    def cleanup(self):
        if self.owned_device is None:
            self.receipt["cleanup"]["reason"] = "No provably owned backing device was established"
            return
        status = self.receipt["cleanup"]
        status["attempted"] = True
        try:
            completed = self.command(["/usr/bin/hdiutil", "detach", self.owned_device], allow_failure=True)
            status["detached"] = completed.returncode == 0
            if status["detached"]:
                records = self.image_records()
                remaining = {entity["dev-entry"] for record in records for entity in self.entities(record)}
                mounts = {entity["mount-point"] for record in records for entity in self.entities(record)
                          if "mount-point" in entity}
                status["remaining_owned_devices"] = sorted(self.owned_devices & remaining)
                status["remaining_image_associations"] = sum(
                    Path(record.get("image-path", "")).resolve() == self.image for record in records)
                status["remaining_owned_mountpoints"] = sorted(
                    point for point in self.owned_mountpoints if point in mounts or Path(point).is_mount())
                status["verified"] = (not status["remaining_owned_devices"]
                                      and not status["remaining_image_associations"]
                                      and not status["remaining_owned_mountpoints"])
        except Exception as error:
            status["error"] = str(error)

    def run(self):
        if self.output == (ROOT / ".stela").resolve() or not self.output.is_relative_to((ROOT / ".stela").resolve()):
            raise ValueError("Output must be a new exclusive directory inside this repository's .stela")
        self.output.mkdir(parents=True, exist_ok=False, mode=0o700)
        acquisition_complete = False
        try:
            image_before = self.image.stat()
            if not stat.S_ISREG(image_before.st_mode):
                raise ValueError("Image must be an ordinary local file")
            checksum = hashlib.sha256()
            with self.image.open("rb") as image:
                while chunk := image.read(4 * 1024 * 1024):
                    checksum.update(chunk)
            self.receipt.update(image_sha256=checksum.hexdigest(), image_bytes=image_before.st_size)
            before = self.image_records()
            if any(Path(record.get("image-path", "")).resolve() == self.image for record in before):
                raise ValueError("Image is already attached; refusing to borrow or detach its devices")
            self.before_devices = {entity["dev-entry"] for record in before for entity in self.entities(record)}
            parent = ROOT / ".stela/mounts"
            parent.mkdir(parents=True, exist_ok=True)
            self.mount_root = Path(tempfile.mkdtemp(prefix="apple-", dir=parent)).resolve()
            self.receipt["mount_root"] = str(self.mount_root)
            self.attach_attempted = True
            attachment = self.command([
                "/usr/bin/hdiutil", "attach", str(self.image), "-readonly", "-nobrowse",
                "-noautoopen", "-noautofsck", "-mount", "required", "-mountroot",
                str(self.mount_root), "-plist",
            ], plist=True, allow_failure=True)
            attach_exit_code = self.receipt["commands"][-1].get("exit_code")
            entities = self.establish_ownership(attachment)
            if attach_exit_code != 0:
                raise ValueError("Image attach failed")
            point, volume = self.inspect_volumes(entities)
            self.receipt["selected_volume_device"] = volume["device"]
            self.acquire_files(point)
            if identity(self.image.stat()) != identity(image_before):
                raise ValueError("Backing image changed during acquisition")
            acquisition_complete = True
        except Exception as error:
            self.receipt["error"] = str(error)
        finally:
            if self.attach_attempted and self.owned_device is None:
                try:
                    self.recover_ownership()
                except Exception as error:
                    self.receipt["ownership_recovery_error"] = str(error)
            self.cleanup()
            if digest(Path(__file__).read_bytes()) != self.receipt["harness_sha256"]:
                acquisition_complete = False
                self.receipt["error"] = "Acquisition helper changed during execution"
            status = self.receipt["cleanup"]
            self.receipt["acquired"] = (acquisition_complete and self.receipt["readonly_verified"]
                                         and status["detached"] and status["verified"])
            if self.mount_root is not None:
                try:
                    self.mount_root.rmdir()
                    status["mount_root_removed"] = True
                except OSError:
                    status["mount_root_removed"] = False
            self.receipt = json_ready(self.receipt)
            write_evidence(self.output / "receipt.json", self.receipt)
        return self.receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="Local DMG after AEA decoding")
    parser.add_argument("--output", type=Path, required=True, help="New directory inside .stela")
    parser.add_argument("--path", action="append", default=[], help="Absolute guest file path; repeat to select files")
    parser.add_argument("--optional-path", action="append", default=[], help="Copy if present; record missing paths explicitly")
    parser.add_argument("--volume", help="Select mounted volume by device identifier or mount-directory name")
    parser.add_argument("--shared-cache", action="store_true", help="Hash ARM dyld cache families and sibling subcaches; inventory only")
    parser.add_argument("--copy-shared-cache", action="store_true", help="Also copy discovered ARM cache families and all their sibling files")
    arguments = parser.parse_args()
    try:
        report = Acquisition(arguments.image, arguments.output, arguments.path,
                             arguments.shared_cache, arguments.volume,
                             optional_paths=arguments.optional_path,
                             copy_shared_cache=arguments.copy_shared_cache).run()
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps({"acquired": report["acquired"], "receipt": str(arguments.output / "receipt.json"),
                      "files": len(report["files"]), "shared_cache_files": len(report["shared_cache_inventory"]),
                      "cleanup": report["cleanup"], "error": report.get("error")}, indent=2))
    raise SystemExit(0 if report["acquired"] else 1)


if __name__ == "__main__":
    main()
