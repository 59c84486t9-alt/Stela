#!/usr/bin/env python3
"""Test identified kernel scalar getters/setters with valid controlled RAM.

Selection is restricted to one scalar immediate memory instruction and RET.
These are instruction/leaf semantics tests, not execution of kernel services.
No random pointer-bearing kernel functions are called without a memory model.
"""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_OP_MEM, CS_OP_REG
from differential import ROOT
from evidence import write_evidence


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "dev" / filename)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


leaves = module("stela_kernel_leaves", "kernel-leaves.py")
memory = module("stela_memory_differential", "memory-differential.py")
MEMORY_MNEMONICS = {"ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw", "ldur", "ldurb", "ldurh", "ldursb", "ldursh", "ldursw", "str", "strb", "strh", "stur", "sturb", "sturh"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("collection", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    data = args.collection.read_bytes()
    manifest = json.loads(args.manifest.read_text())
    if hashlib.sha256(data).hexdigest() != manifest["container_sha256"] or len(data) != manifest["container_bytes"]:
        raise ValueError("Kernel collection identity differs")
    image = next(image for image in manifest["images"] if image["id"] == "com.apple.kernel")
    addresses, candidates = leaves.candidates(data, image, MEMORY_MNEMONICS | {"ret"})
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    decoder.detail = True
    eligible = []
    for entry in candidates:
        if len(entry["code"]) != 8:
            continue
        decoded = list(decoder.disasm(entry["code"], entry["address"]))
        first = decoded[0]
        if first.mnemonic not in MEMORY_MNEMONICS or first.writeback or len(first.operands) != 2:
            continue
        target, address = first.operands
        if target.type != CS_OP_REG or address.type != CS_OP_MEM:
            continue
        base = first.reg_name(address.mem.base)
        data_register = first.reg_name(target.reg)
        load = first.mnemonic.startswith("ld")
        if base != "x0" or address.mem.index or not -256 <= address.mem.disp <= 32760:
            continue
        allowed_data = ("x0", "w0") if load else ("x1", "w1", "xzr", "wzr")
        if data_register not in allowed_data:
            continue
        words = list(struct.unpack("<II", entry["code"]))
        word = words[0]
        # Capstone's operand gate above defines the test input contract; the
        # compiler independently decides whether this encoding is supported.
        eligible.append((entry, {"words": words, "size": word >> 30, "opcode": (word >> 22) & 3,
                                  "rn": 0, "rt": word & 31, "offset": address.mem.disp,
                                  "mode": "unsigned" if word & (1 << 24) else "unscaled", "state_count": 16,
                                  "assembly": f"{first.mnemonic} {first.op_str}"}))
    subprocess.run([str(ROOT / "dev/cargo"), "build", "--locked", "-p", "stela-cli"], check=True)
    cli = ROOT / "target/debug/stela"
    compiled, verified, declined = [], [], []
    compiler = None
    with tempfile.TemporaryDirectory(prefix="stela-kernel-ram-") as temporary:
        source_path = Path(temporary) / "source.arm64"
        for entry, case in eligible:
            code = entry.pop("code")
            entry["source_sha256"] = hashlib.sha256(code).hexdigest()
            source_path.write_bytes(code)
            process = subprocess.run([str(cli), "prepare-leaf", str(source_path), "--guest-base", hex(entry["address"])], capture_output=True, text=True)
            if process.returncode:
                declined.append({**entry, "reason": process.stderr.strip()})
                continue
            prepared = json.loads(process.stdout)
            fingerprint = prepared["manifest"]["identity"]["compiler_source_sha256"]
            if compiler is not None and compiler != fingerprint:
                raise AssertionError("Compiler changed during kernel RAM suite")
            compiler = fingerprint
            native_path = Path(prepared["directory"]) / "native.bin"
            case["native"] = native_path.read_bytes()
            compiled.append(case)
            verified.append({**entry, "assembly": case["assembly"], "cache_key": prepared["key"],
                             "native_artifact": str(native_path), "native_sha256": prepared["manifest"]["native_sha256"],
                             "compiler_source_sha256": fingerprint, "state_and_memory_comparisons": 16, "passed": True})
        if not compiled:
            raise AssertionError("No kernel memory leaves selected")
        result = memory.bounded_cases(compiled)
    report = {"kind": "real_kernel_controlled_ram_leafs", "passed": True, "container_sha256": manifest["container_sha256"],
              "fileset_manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
              "compiler_source_sha256": compiler, "compiler_executable_sha256": hashlib.sha256(cli.read_bytes()).hexdigest(),
              "harness_sources_sha256": {name: hashlib.sha256((ROOT / "dev" / name).read_bytes()).hexdigest() for name in ("kernel-memory-leaves.py", "kernel-leaves.py", "memory-differential.py", "differential.py")},
              "kernel_function_starts": len(addresses), "filtered_memory_candidates": len(eligible),
              "verified": verified, "declined": declined, **result,
              "limits": "Two-instruction named function prefixes only: one scalar immediate load/store through argument x0 and RET. Valid private RAM and controlled argument values; compare all modeled registers/flags and 64 KiB RAM. Reference mapping uses a low code PC because these functions have no PC-relative operations; compiled source maps retain original PCs. No kernel objects, locking, service behavior, PAC, exception delivery or boot is demonstrated."}
    write_evidence(args.output, report)
    print(json.dumps({"report": str(args.output), "passed": True, "verified_functions": len(verified), "declined": len(declined),
                      "state_and_memory_comparisons": result["state_and_memory_comparisons"],
                      "instruction_patterns": dict(Counter(item["assembly"].split()[0] for item in verified)),
                      "function_sample": [item["names"] for item in verified[:12]]}, indent=2))


if __name__ == "__main__":
    main()
