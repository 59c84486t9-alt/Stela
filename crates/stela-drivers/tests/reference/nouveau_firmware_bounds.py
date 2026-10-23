#!/usr/bin/env python3
"""Prepare a source-bound parser test unit; never compile or execute it.

Use the patched Linux source tree and its exact declaration tree for authored
fixtures. An explicitly selected unchanged bootloader adds a separate retained
input test. Generated files (including vendor bytes) must remain in
the repository's ignored .stela directory. The C test requires the real Linux
compat build environment and CRC implementation; this generator supplies no
device, allocation, firmware-request or cryptographic service substitutes.
"""

import argparse
import hashlib
import json
from pathlib import Path


PATCHED = {
    "drivers/gpu/drm/nouveau/nvkm/subdev/gsp/rm/r535/gsp.c":
        "588e6e50b38cf5445bc125c51777e6d0fed4368c47cc751888d8d14b740ca9de",
    "drivers/gpu/drm/nouveau/nvkm/subdev/gsp/gh100.c":
        "09abd16777afcef6eaa25b3b76265e140dc93ee1eaab7b1ba82705b9323bd8ae",
}
DECLARATIONS = {
    "drivers/gpu/drm/nouveau/include/nvfw/fw.h":
        "29524e3b1586a674924d5019a2f694b5eb47737032e75c91b4ba2c443cf5e27a",
    "drivers/gpu/drm/nouveau/nvkm/subdev/gsp/rm/r535/nvrm/gsp.h":
        "5cd27171015fbfa5c0d23cb5fd9b9f72c6c15f30ee65cc3094ae770ef2b43b28",
    "include/uapi/linux/elf.h":
        "15613d116a6c77c4826036740dd5023c6a7779c776acd3ac7a1a661fe7432b3c",
    "drivers/gpu/drm/nouveau/include/nvkm/subdev/gsp.h":
        "3cccc225a53518cb86899d95efb71b2e495fb77f6f56f416a17d77bde0499905",
}
BOOTLOADER_SHA256 = "d40b48e431d1707dc77af3605db358ed7a32ebfc2830eb74de2eddb4d3025071"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def checked(root, relative, digest):
    data = (root / relative).read_bytes()
    if sha256(data) != digest:
        raise ValueError(f"source identity mismatch: {root / relative}")
    return data.decode()


def complete_helper(source, name):
    """Copy the entire static function from these exact hash-bound sources."""
    signature = source.index("\n" + name + "(")
    start = source.rindex("\nstatic ", 0, signature) + 1
    opening = source.index("{", signature)
    depth = 1
    end = opening + 1
    while depth:
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
        end += 1
    return source[start:end] + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux-source", type=Path, required=True)
    parser.add_argument("--patched-source", type=Path, required=True)
    parser.add_argument("--bootloader", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[4]
    output = args.output.resolve()
    if not output.is_relative_to(repository / ".stela"):
        raise ValueError("generated firmware/test artifacts must stay in ignored .stela")
    linux = args.linux_source.resolve()
    patched = args.patched_source.resolve()
    sources = {name: checked(patched, name, digest) for name, digest in PATCHED.items()}
    for name, digest in DECLARATIONS.items():
        checked(linux, name, digest)
    boot = args.bootloader.read_bytes() if args.bootloader is not None else None
    if boot is not None and (len(boot) != 200812 or sha256(boot) != BOOTLOADER_SHA256):
        raise ValueError("unchanged retained bootloader identity mismatch")

    r535, gh100 = sources.values()
    helpers = {}
    r535_license = r535[:r535.index("#include")]
    gh100_license = gh100[:gh100.index("#include")]
    definitions_start = gh100.index("/* The sh_flags value")
    definitions_end = gh100.index("\n};", definitions_start) + len("\n};")
    pieces = [r535_license]
    for name in ("r535_gsp_radix3_size", "r535_gsp_fw_sizes",
                 "r535_gsp_rm_boot_parse", "r535_gsp_elf_section"):
        body = complete_helper(r535, name)
        helpers[name] = sha256(body.encode())
        pieces.append(body)
    pieces.extend((gh100_license, gh100[definitions_start:definitions_end]))
    for name in ("elf_validate_sections", "elf_section"):
        body = complete_helper(gh100, name)
        helpers[name] = sha256(body.encode())
        pieces.append(body)
    unit = "\n".join(pieces) + "\n"
    firmware = None
    if boot is not None:
        rows = [", ".join(f"0x{byte:02x}" for byte in boot[start:start + 16])
                for start in range(0, len(boot), 16)]
        firmware = ("/* Retained unchanged NVIDIA input; ignored test artifact only.\n"
                    " * Terms: LICENCE.nvidia in its acquisition evidence directory. */\n"
                    "static const u8 nouveau_real_bootloader[] = {\n\t" +
                    ",\n\t".join(rows) + "\n};\n")
    tests = {
        "nouveau_firmware_authored": "crates/stela-drivers/src/gpu/nouveau/tests/firmware.c",
        "nouveau_firmware_retained": "crates/stela-drivers/src/gpu/nouveau/tests/firmware_retained.c",
    }
    retained_status = ("source_identity_checked_execution_unrun"
                       if boot is not None else "not_requested")
    prepared_entries = ["nouveau_firmware_authored"]
    if boot is not None:
        prepared_entries.append("nouveau_firmware_retained")
    receipt = {
        "scope": "Source preparation only; bounded actual helper tests, no full driver",
        "selection": "retained" if boot is not None else "authored",
        "prepared_test_entries": prepared_entries,
        "executed_test_count": 0,
        "generator": {"path": str(Path(__file__).resolve().relative_to(repository)),
                      "sha256": sha256(Path(__file__).read_bytes())},
        "source_roots": {"linux": str(linux), "patched": str(patched)},
        "upstream_linux": "cc9de5d4b5ab6459f5774946aa3195ad51236fa8",
        "patched_sources": PATCHED,
        "declaration_sources": DECLARATIONS,
        "helper_sha256": helpers,
        "test_sources": {name: {"path": path, "sha256": sha256((repository / path).read_bytes())}
                         for name, path in tests.items()},
        "test_status": {
            "nouveau_firmware_authored": "prepared_execution_unrun",
            "nouveau_firmware_retained": retained_status,
        },
        "bootloader_sha256": BOOTLOADER_SHA256 if boot is not None else None,
        "retained_input": retained_status,
        "generated_helpers_sha256": sha256(unit.encode()),
        "generated_firmware_include_sha256": (sha256(firmware.encode())
                                              if firmware is not None else None),
        "compiled": False,
        "executed": False,
        "dependencies": [
            "real Linux compat test include/configuration environment",
            "nouveau's five exact Kbuild include roots",
            "real Linux crc32_le implementation and hosted test/assert/string support",
            "parent-owned test build integration; no unresolved-function discard",
        ],
    }
    output.mkdir(parents=True, exist_ok=False)
    (output / "nouveau_firmware_helpers.inc").write_text(unit)
    if firmware is not None:
        (output / "nouveau_firmware_real_boot.inc").write_text(firmware)
    (output / "source-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"output": str(output), "retained_input": retained_status,
                      "prepared_test_entries": prepared_entries, "executed_test_count": 0,
                      "compiled": False, "executed": False}))


if __name__ == "__main__":
    main()
