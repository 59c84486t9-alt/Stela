#!/usr/bin/env python3
"""Inventory original restore inputs and VMApple prerequisites without booting.

Reports describe archive templates, not live firmware/kernel state. Apple payloads
remain in memory and reports must stay under the repository's ignored .stela/.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import struct
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_TREE_BYTES = 4 * 1024 * 1024
MAX_TREE_DEPTH = 64
PROPERTY_NAME_BYTES = 32
PROPERTY_TEMPLATE = 1 << 31
PROPERTY_LENGTH_MASK = PROPERTY_TEMPLATE - 1
PROPERTY_ALIGNMENT = 4
NODE_HEADER = struct.Struct("<II")
PROPERTY_LENGTH = struct.Struct("<I")
DER_SEQUENCE = 0x30
DER_IA5_STRING = 0x16
DER_OCTET_STRING = 0x04
DER_INTEGER = 0x02
DER_HIGH_TAG_MASK = 31
DER_LONG_LENGTH = 128
DER_LENGTH_WIDTH_MASK = DER_LONG_LENGTH - 1
DER_MAX_LENGTH_WIDTH = 8
COMPRESSION_LZFSE = 0x801
IM4P_COMPRESSION_LZFSE = 1
PROBE_TIMEOUT_SECONDS = 10


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def take(data, offset, size):
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError(f"Input range exceeds bounds at {offset:#x}, size {size}")
    return data[offset:offset + size]


def der_element(data, offset):
    tag, length = take(data, offset, 2)
    offset += 2
    if tag & DER_HIGH_TAG_MASK == DER_HIGH_TAG_MASK:
        raise ValueError("High-number DER tag is unsupported")
    if length & DER_LONG_LENGTH:
        width = length & DER_LENGTH_WIDTH_MASK
        if not 0 < width <= DER_MAX_LENGTH_WIDTH:
            raise ValueError("Indefinite or oversized DER length")
        encoded = take(data, offset, width)
        length = int.from_bytes(encoded, "big")
        if encoded[0] == 0 or length < DER_LONG_LENGTH:
            raise ValueError("Non-minimal DER length")
        offset += width
    return tag, take(data, offset, length), offset + length


def device_tree_payload(container):
    tag, sequence, end = der_element(container, 0)
    if tag != DER_SEQUENCE or end != len(container):
        raise ValueError("Expected one complete bare IM4P sequence")
    fields = []
    offset = 0
    while offset < len(sequence):
        tag, value, offset = der_element(sequence, offset)
        fields.append((tag, value))
    if [tag for tag, _ in fields[:4]] != [
        DER_IA5_STRING, DER_IA5_STRING, DER_IA5_STRING, DER_OCTET_STRING
    ] or fields[0][1] != b"IM4P" or fields[1][1] != b"dtre":
        raise ValueError("Expected an unencrypted DeviceTree IM4P payload")
    if len(fields) != 5 or fields[4][0] != DER_SEQUENCE:
        raise ValueError("DeviceTree requires one reviewed compression metadata sequence")
    compression = fields[4][1]
    tag, algorithm, offset = der_element(compression, 0)
    size_tag, declared_size, end = der_element(compression, offset)
    if tag != DER_INTEGER or size_tag != DER_INTEGER or end != len(compression):
        raise ValueError("Unexpected DeviceTree compression metadata")
    for integer in (algorithm, declared_size):
        if not integer or integer[0] & DER_LONG_LENGTH or (
            len(integer) > 1 and integer[0] == 0 and not integer[1] & DER_LONG_LENGTH
        ):
            raise ValueError("Invalid positive compression metadata integer")
    expected_size = int.from_bytes(declared_size, "big")
    if int.from_bytes(algorithm, "big") != IM4P_COMPRESSION_LZFSE or not 0 < expected_size <= MAX_TREE_BYTES:
        raise ValueError("Unsupported compression or excessive decoded DeviceTree size")
    payload = fields[3][1]
    metadata = {
        "container_sha256": sha256(container),
        "description": fields[2][1].decode("ascii"),
        "payload_sha256": sha256(payload),
        "payload_bytes": len(payload),
        "declared_uncompressed_bytes": expected_size,
    }
    if not payload.startswith(b"bvx2"):
        raise ValueError("Only the reviewed plaintext LZFSE DeviceTree is supported")
    if platform.system() != "Darwin":
        raise ValueError("DeviceTree decompression currently requires Apple Compression")
    library = ctypes.CDLL("/usr/lib/libcompression.dylib")
    decode = library.compression_decode_buffer
    decode.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                       ctypes.c_size_t, ctypes.c_void_p, ctypes.c_int]
    decode.restype = ctypes.c_size_t
    destination = ctypes.create_string_buffer(expected_size + 1)
    source = ctypes.create_string_buffer(payload)
    size = decode(destination, len(destination), source, len(payload), None, COMPRESSION_LZFSE)
    if size != expected_size:
        raise ValueError("DeviceTree decode disagrees with its declared output size")
    decoded = destination.raw[:size]
    metadata.update(decoded_sha256=sha256(decoded), decoded_bytes=size)
    return decoded, metadata


def c_string(data):
    text, separator, suffix = data.partition(b"\0")
    if not separator or any(suffix) or not text or any(c < 32 or c > 126 for c in text):
        raise ValueError("Expected a printable NUL-terminated name")
    return text.decode("ascii")


def parse_device_tree(data):
    nodes = []
    paths = set()

    def parse_node(offset, parent, depth):
        if depth > MAX_TREE_DEPTH:
            raise ValueError("DeviceTree exceeds depth bound")
        start = offset
        property_count, child_count = NODE_HEADER.unpack(take(data, offset, NODE_HEADER.size))
        offset += NODE_HEADER.size
        if property_count == 0 or property_count > len(data) // (PROPERTY_NAME_BYTES + PROPERTY_LENGTH.size):
            raise ValueError("Invalid DeviceTree property count")
        if child_count > len(data) // NODE_HEADER.size:
            raise ValueError("Invalid DeviceTree child count")
        properties = {}
        for _ in range(property_count):
            name = c_string(take(data, offset, PROPERTY_NAME_BYTES))
            encoded_length, = PROPERTY_LENGTH.unpack(
                take(data, offset + PROPERTY_NAME_BYTES, PROPERTY_LENGTH.size))
            offset += PROPERTY_NAME_BYTES + PROPERTY_LENGTH.size
            length = encoded_length & PROPERTY_LENGTH_MASK
            value = take(data, offset, length)
            padded = (length + PROPERTY_ALIGNMENT - 1) & -PROPERTY_ALIGNMENT
            take(data, offset, padded)
            offset += padded
            if name in properties:
                raise ValueError(f"Duplicate DeviceTree property: {name}")
            properties[name] = {"bytes": length, "template": bool(encoded_length & PROPERTY_TEMPLATE),
                                "sha256": sha256(value), "hex": value.hex()}
        if "name" not in properties or properties["name"]["template"]:
            raise ValueError("DeviceTree node requires a concrete name")
        name = c_string(bytes.fromhex(properties["name"]["hex"]))
        if "/" in name:
            raise ValueError("DeviceTree node name contains a path separator")
        path = parent + "/" + name
        if path in paths:
            raise ValueError(f"Duplicate DeviceTree path: {path}")
        paths.add(path)
        nodes.append({"path": path, "offset": start, "properties": properties,
                      "child_count": child_count})
        for _ in range(child_count):
            offset = parse_node(offset, path, depth + 1)
        return offset

    if parse_node(0, "", 0) != len(data):
        raise ValueError("Trailing bytes after DeviceTree")
    return nodes


def bounded_member(archive, member, limit):
    info = archive.getinfo(member)
    if info.file_size > limit:
        raise ValueError(f"Archive member exceeds {limit}-byte bound: {member}")
    return archive.read(info)


def file_identity(stat):
    return {"device": stat.st_dev, "inode": stat.st_ino, "bytes": stat.st_size,
            "mtime_ns": stat.st_mtime_ns, "ctime_ns": stat.st_ctime_ns}


def archive_inventory(path, model):
    path_before = file_identity(path.stat())
    with path.open("rb") as source, zipfile.ZipFile(source) as archive:
        opened_before = file_identity(os.fstat(source.fileno()))
        if path_before != opened_before:
            raise ValueError("Archive path changed while opening")
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("Archive contains duplicate member names")
        manifest_bytes = bounded_member(archive, "BuildManifest.plist", MAX_MANIFEST_BYTES)
        manifest = plistlib.loads(manifest_bytes)
        identities = []
        tree_members = set()
        for identity in manifest["BuildIdentities"]:
            if identity.get("Ap,ProductType") != model:
                continue
            info = identity["Info"]
            components = {}
            for name, component in identity["Manifest"].items():
                member = component.get("Info", {}).get("Path")
                if member is None:
                    continue
                entry = archive.getinfo(member)
                components[name] = {"member": member, "bytes": entry.file_size,
                                    "zip_crc32": f"{entry.CRC:08x}"}
                if name == "DeviceTree":
                    tree_members.add(member)
            identities.append({"variant": info["Variant"], "device_class": info["DeviceClass"],
                               "minimum_cpus": info.get("VirtualMachineMinCPUCount"),
                               "minimum_memory_mb": info.get("VirtualMachineMinMemorySizeMB"),
                               "minimum_host_os": info.get("VirtualMachineMinHostOS"),
                               "components": components})
        if not identities or len(tree_members) != 1:
            raise ValueError("Expected model identities with one shared original DeviceTree")
        member, = tree_members
        container = bounded_member(archive, member, MAX_TREE_BYTES)
        decoded, metadata = device_tree_payload(container)
        nodes = parse_device_tree(decoded)
        tree_model = nodes[0]["properties"].get("model")
        if tree_model is None or tree_model["template"] or c_string(bytes.fromhex(tree_model["hex"])) != model:
            raise ValueError("Original DeviceTree model disagrees with the selected restore identity")
        metadata.update(member=member, node_count=len(nodes), nodes=nodes,
                        template_property_count=sum(p["template"] for n in nodes
                                                    for p in n["properties"].values()))
        opened_after = file_identity(os.fstat(source.fileno()))
        path_after = file_identity(path.stat())
        if opened_before != opened_after or opened_after != path_after:
            raise ValueError("Archive identity changed during inspection")
    return {"path": str(path.resolve()), "bytes": opened_before["bytes"],
            "file_identity_before": opened_before, "file_identity_after": opened_after,
            "path_identity_before": path_before, "path_identity_after": path_after,
            "archive_member_count": len(names), "whole_archive_hash_verified": False,
            "build_manifest_sha256": sha256(manifest_bytes),
            "product_version": manifest["ProductVersion"], "build": manifest["ProductBuildVersion"],
            "model": model, "identities": identities, "device_tree": metadata}


def qemu_inventory(path):
    commands = {"version": ["--version"], "machines": ["-machine", "help"],
                "accelerators": ["-accel", "help"]}
    result = {"path": str(path.resolve()), "launcher_sha256": sha256(path.read_bytes()), "commands": {}}
    for name, arguments in commands.items():
        command = [str(path.resolve()), *arguments]
        try:
            completed = subprocess.run(command, capture_output=True, text=True,
                                       timeout=PROBE_TIMEOUT_SECONDS, check=False)
            observed = {"argv": command, "exit_code": completed.returncode,
                        "stdout": completed.stdout, "stderr": completed.stderr}
        except (OSError, subprocess.TimeoutExpired) as error:
            observed = {"argv": command, "exit_code": None, "stdout": "", "stderr": str(error)}
        result["commands"][name] = observed
    machines = result["commands"]["machines"]
    accelerators = result["commands"]["accelerators"]
    result["vmapple_listed"] = any(
        line.split()[:1] == ["vmapple"] for line in machines["stdout"].splitlines()
    ) if machines["exit_code"] == 0 else None
    result["hvf_listed"] = "hvf" in accelerators["stdout"].split() if accelerators["exit_code"] == 0 else None
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ipsw", type=Path)
    parser.add_argument("--model", default="VirtualMac2,1")
    parser.add_argument("--qemu", type=Path, help="Optional bounded help-only capability subprocesses")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.output.resolve().is_relative_to(ROOT / ".stela"):
        parser.error("Reports containing original property bytes must stay under .stela/")
    if args.output.exists():
        parser.error("Output already exists; use a fresh evidence path")
    report = {"schema_version": 1, "kind": "vmapple_restore_input_preflight",
              "producer_sha256": sha256(Path(__file__).read_bytes()),
              "host_architecture": platform.machine(), "archive": archive_inventory(args.ipsw, args.model),
              "qemu": qemu_inventory(args.qemu) if args.qemu else None,
              "macos_boot_verified": False, "stela_translated_system_verified": False,
              "physical_bare_metal_verified": False,
              "limits": "Read-only archive template inspection, not a live boot DeviceTree. No IMG4 signature/personalization, installed APFS/auxiliary storage, hardware model, PAC/MMU/EL1/interrupt/device execution or full macOS compatibility is verified. Whole IPSW hash is not recomputed; metadata checks do not lock the input. QEMU launcher hash does not bind child executable bytes. Capability listing does not execute Apple code or test Stela."}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as destination:
        json.dump(report, destination, indent=2)
        destination.write("\n")
    print(json.dumps({"output": str(args.output), "build": report["archive"]["build"],
                      "device_tree_nodes": report["archive"]["device_tree"]["node_count"],
                      "macos_boot_verified": False}))


if __name__ == "__main__":
    main()
