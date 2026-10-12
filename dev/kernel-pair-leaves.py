#!/usr/bin/env python3
"""Test pinned real kernel pair routines with reviewed RAM and pointer graphs.

The contract manifest pins the inspected source hashes without embedding Apple
code. These are bounded instruction/leaf tests, not functioning kernel services.
"""
import argparse
import hashlib
import importlib.util
import json
import mmap
import ctypes
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from differential import ROOT, MASK, State, native, reference, states
from evidence import write_evidence


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "dev" / filename)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


leaves = module("stela_kernel_leaves", "kernel-leaves.py")
pairs = module("stela_pair_differential", "pair-differential.py")


def u64(data, offset, value):
    struct.pack_into("<Q", data, offset, value & MASK)


def initial_case(kind, ram_address, original_ram, initial, index, value, second_value):
    state = State.from_buffer_copy(initial)
    ram = bytearray(original_ram)
    first, second = 1024, 8192
    if kind in ("mbuf_status", "mbuf_flowid", "mbuf_tx_data") and index & 8:
        first = pairs.RAM_SIZE - 0xb8
    elif kind == "async_reference64" and index & 8:
        first = pairs.RAM_SIZE - 24
    state.x[0], state.x[1], state.x[2] = ram_address + first, ram_address + second, second_value
    state.sp = ram_address + pairs.RAM_SIZE // 2
    result = state.x[0]
    if kind == "used_bytes":
        length = value & 2047
        u64(ram, first + 8, ram_address + 16384)
        u64(ram, first + 16, ram_address + 16384 + length)
        result = length + 16
    elif kind == "mbuf_counts":
        state.x[0] = 0 if index & 1 else state.x[0]
        state.x[1] = 0 if index & 2 else state.x[1]
        struct.pack_into("<H", ram, first + 0x1e, 2 if index & 4 else 0)
        ram[first + 0x76] = 16 if index & 8 else 0
        struct.pack_into("<II", ram, first + 0x80, value & 0xffffffff, second_value & 0xffffffff)
        result = 0 if (index & 3) == 0 and (index & 12) == 12 else 22
    elif kind == "chain_counts":
        state.x[1] = value
    elif kind == "list_insert":
        count = index % 4
        nodes = [ram_address + 8192 + offset * 4096 for offset in range(count)]
        for at, node in enumerate(nodes):
            u64(ram, node - ram_address + 0x130, nodes[at + 1] if at + 1 < count else 0)
        head = nodes[0] if nodes else 0
        candidate = ram_address + 24576
        selection = index // 4 % 3
        if nodes and selection:
            candidate = nodes[0] if selection == 1 else nodes[-1]
        state.x[1] = candidate
        u64(ram, first + 16, head)
        u64(ram, first + 24, count)
        result = 0
    elif kind in ("mbuf_status", "mbuf_flowid", "mbuf_tx_data"):
        # Each of 16 edge/random values sees all eight independent combinations
        # of null object, packet-header flag, and initialized completion flags.
        scenario = index // 16
        state.x[0] = 0 if scenario & 1 else state.x[0]
        state.x[1] = value
        state.x[2] = second_value
        header_flags = (second_value & 0xffff & ~2) | (2 if scenario & 2 else 0)
        packet_flags = (value & 0xffffffff & ~0x2000000) | (0x2000000 if scenario & 4 else 0)
        struct.pack_into("<H", ram, first + 0x1e, header_flags)
        struct.pack_into("<I", ram, first + 0x74, packet_flags)
        result = 0 if not scenario & 1 and scenario & 2 else 22
    elif kind == "async_reference64":
        # x1 is an opaque port value and is combined without dereferencing it.
        # The caller supplies a live writable three-word reference array in x0.
        state.x[1], state.x[2] = value, second_value
        old_word = (second_value & ~3) | (index // 16)
        u64(ram, first, old_word)
    elif kind not in ("gate_init", "clear16", "clear16_at16", "self_links", "iterator_init", "iterator_restart"):
        raise AssertionError(f"Missing reviewed input contract: {kind}")
    expected_ram = bytearray(ram)
    if kind == "gate_init":
        expected_ram[second:second + 24] = struct.pack("<QQQ", 0, 0, 0x60001)
    elif kind == "mbuf_counts" and result == 0:
        struct.pack_into("<I", expected_ram, second, (value + second_value) & 0xffffffff)
    elif kind in ("clear16", "clear16_at16"):
        at = first + (16 if kind == "clear16_at16" else 0)
        expected_ram[at:at + 16] = b"\0" * 16
    elif kind == "chain_counts":
        struct.pack_into("<II", expected_ram, first + 0xdc, value & 0xffffffff, second_value & 0xffffffff)
    elif kind == "list_insert" and candidate not in nodes:
        u64(expected_ram, candidate - ram_address + 0x130, head)
        u64(expected_ram, first + 16, candidate)
        u64(expected_ram, first + 24, count + 1)
    elif kind in ("mbuf_status", "mbuf_flowid", "mbuf_tx_data") and result == 0:
        if not packet_flags & 0x2000000:
            struct.pack_into("<I", expected_ram, first + 0x74, packet_flags | 0x2000000)
            expected_ram[first + 0xa0:first + 0xb8] = bytes(24)
        if kind == "mbuf_status":
            struct.pack_into("<I", expected_ram, first + 0xb0, value & 0xffffffff)
        elif kind == "mbuf_flowid":
            struct.pack_into("<H", expected_ram, first + 0xb4, value & 0xffff)
        else:
            struct.pack_into("<QQ", expected_ram, first + 0xa0, value, second_value)
    elif kind == "async_reference64":
        expected_ram[first:first + 24] = struct.pack("<QQQ", (old_word & 3) | state.x[1], state.x[2], state.x[3])
    elif kind == "self_links":
        expected_ram[first + 16:first + 32] = struct.pack("<QQ", ram_address + first + 16, ram_address + first + 16)
        result = 1
    elif kind == "iterator_init":
        expected_ram[second:second + 24] = struct.pack("<QQQ", state.x[0], 0, 0)
        result = 1
    elif kind == "iterator_restart":
        expected_ram[first + 8:first + 24] = b"\0" * 16
        result = 1
    return state, bytes(ram), result, bytes(expected_ram)


def case_count(kind):
    if kind in ("mbuf_status", "mbuf_flowid", "mbuf_tx_data"):
        return 128
    if kind == "async_reference64":
        return 64
    return 16


def execute_cases(compiled):
    comparisons = 0
    reference_only_comparisons = 0
    randomizer = random.Random(0x50e77a)
    original_ram = randomizer.randbytes(pairs.RAM_SIZE)
    values = [0, MASK, 1, 0x80000000, 0x7fffffff, 0x8000000000000000, 0x7fffffffffffffff, 0xdeadbeef01234567]
    values.extend(randomizer.getrandbits(64) for _ in range(8))
    initial_states = states(all_flags=True)
    with mmap.mmap(-1, pairs.RAM_SIZE, prot=mmap.PROT_READ | mmap.PROT_WRITE) as region:
        marker = ctypes.c_char.from_buffer(region)
        address = ctypes.addressof(marker)
        del marker
        for entry in compiled:
            for index in range(case_count(entry["contract"])):
                value = values[index % len(values)]
                state, ram, result, expected_ram = initial_case(entry["contract"], address, original_ram,
                    initial_states[index % len(initial_states)], index, value, values[(index + 5) % len(values)])
                expected = reference(entry["source"], state, (address, ram))
                if entry["native"] is None:
                    if expected["x"][0] != result or expected["memory"] != expected_ram or expected["sp"] != state.sp:
                        raise AssertionError(f"Original ARM RAM-contract mismatch: {entry['name']}, input {index}")
                    reference_only_comparisons += 1
                    continue
                region[:] = ram
                actual = native(entry["native"], state)
                actual["memory"] = region[:]
                if expected != actual or actual["x"][0] != result or actual["memory"] != expected_ram:
                    raise AssertionError(f"Real kernel pair mismatch: {entry['name']}, input {index}")
                comparisons += 1
    return {"programs": sum(entry["native"] is not None for entry in compiled),
            "state_and_memory_comparisons": comparisons,
            "reference_only_programs": sum(entry["native"] is None for entry in compiled),
            "reference_only_contract_comparisons": reference_only_comparisons}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("collection", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    contracts_path = ROOT / "tests/kernel-pair-contracts.json"
    contracts = json.loads(contracts_path.read_text())
    data = args.collection.read_bytes()
    manifest = json.loads(args.manifest.read_text())
    if hashlib.sha256(data).hexdigest() != manifest["container_sha256"] or len(data) != manifest["container_bytes"] or manifest["container_sha256"] != contracts["container_sha256"]:
        raise ValueError("Kernel collection differs from reviewed input contracts")
    image = next(image for image in manifest["images"] if image["id"] == "com.apple.kernel")
    addresses, candidates = leaves.candidates(data, image, leaves.ALLOWED | {"ldp", "stp", "ldpsw", "ldr", "ldur", "str", "stur", "ldrb", "strb", "ldrh", "strh"})
    by_name = {name: entry for entry in candidates for name in entry["names"]}
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    subprocess.run([str(ROOT / "dev/cargo"), "build", "--locked", "-p", "stela-cli"], check=True)
    cli = ROOT / "target/debug/stela"
    compiled, verified, declined = [], [], []
    compiler = None
    with tempfile.TemporaryDirectory(prefix="stela-real-pairs-") as temporary:
        source_path = Path(temporary) / "source.arm64"
        for contract in contracts["functions"]:
            name = contract["name"]
            if name not in by_name:
                raise AssertionError(f"Reviewed source function missing: {name}")
            entry = {**by_name[name]}
            source = entry.pop("code")
            if hashlib.sha256(source).hexdigest() != contract["source_sha256"]:
                raise AssertionError(f"Reviewed input contract changed: {name}")
            entry.update({"source_sha256": contract["source_sha256"], "contract": contract["contract"],
                          "assembly": [f"{mnemonic} {operands}".strip() for _, _, mnemonic, operands in decoder.disasm_lite(source, entry["address"])]})
            source_path.write_bytes(source)
            process = subprocess.run([str(cli), "prepare-leaf", str(source_path), "--guest-base", hex(entry["address"])], capture_output=True, text=True)
            if process.returncode:
                decline = {**entry, "reason": process.stderr.strip()}
                if contract["contract"] is not None:
                    compiled.append({"name": name, "contract": contract["contract"], "source": source, "native": None})
                    decline.update({"reference_only_contract_comparisons": case_count(contract["contract"]),
                                    "reference_only_checked": ["x0 return value", "SP preserved", "all 65536 RAM bytes"],
                                    "native_verified": False})
                declined.append(decline)
                continue
            if contract["contract"] is None:
                declined.append({**entry, "reason": "Compiled, but no reviewed executable RAM contract is defined"})
                continue
            prepared = json.loads(process.stdout)
            fingerprint = prepared["manifest"]["identity"]["compiler_source_sha256"]
            if compiler is not None and compiler != fingerprint:
                raise AssertionError("Compiler changed during kernel pair suite")
            compiler = fingerprint
            native_path = Path(prepared["directory"]) / "native.bin"
            compiled.append({"name": name, "contract": contract["contract"], "source": source, "native": native_path.read_bytes()})
            verified.append({**entry, "cache_key": prepared["key"], "native_artifact": str(native_path),
                             "native_sha256": prepared["manifest"]["native_sha256"], "compiler_source_sha256": fingerprint,
                             "state_and_memory_comparisons": case_count(contract["contract"]), "passed": True})
        if not verified:
            raise AssertionError("No reviewed kernel pair functions compiled")
        result = pairs.bounded_cases(compiled, execute=execute_cases)
    report = {"kind": "real_kernel_pair_leafs_with_ram_contracts", "passed": True, "target": contracts["target"],
              "container_sha256": manifest["container_sha256"], "fileset_manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
              "input_contracts_sha256": hashlib.sha256(contracts_path.read_bytes()).hexdigest(),
              "compiler_source_sha256": compiler, "compiler_executable_sha256": hashlib.sha256(cli.read_bytes()).hexdigest(),
              "harness_sources_sha256": {name: hashlib.sha256((ROOT / "dev" / name).read_bytes()).hexdigest() for name in ("kernel-pair-leaves.py", "kernel-leaves.py", "pair-differential.py", "differential.py")},
              "kernel_function_starts": len(addresses), "reviewed_candidates": len(contracts["functions"]), **result,
              "verified": verified, "declined": declined,
              "limits": "Pinned bounded kernel function prefixes, original-vs-native register/flag/64 KiB RAM checks and independent byte-contract checks. Controlled pointer graphs, early-return/error cases and a linked-list traversal are exercised. Completion setters have explicit null/header/initialization scenarios; async-reference arrays include all low tag bits and a RAM-end boundary. Out-of-prefix compiler branches remain declines. No kernel ABI integration, locking, device access, PAC, concurrent atomicity, guest exception delivery or kernel boot."}
    write_evidence(args.output, report)
    print(json.dumps({"report": str(args.output), "passed": True, "verified_functions": len(verified), "declined": len(declined),
                      "state_and_memory_comparisons": result["state_and_memory_comparisons"],
                      "reference_only_contract_comparisons": result["reference_only_contract_comparisons"],
                      "source_sizes": sorted(set(entry["source_bytes"] for entry in verified)),
                      "function_names": [entry["names"] for entry in verified]}, indent=2))


if __name__ == "__main__":
    main()
