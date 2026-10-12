#!/usr/bin/env python3
"""Probe one pinned Rosetta lookup helper in ARM Unicorn with synthetic tables.

No Rosetta installer, process runtime, translator or native ARM library is run.
This is a behavioral experiment for the inspected metadata helper only.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from differential import ROOT, State, reference, states
from unicorn import UcError
from evidence import write_evidence

BINARY_SHA256 = "2285868ea879cc62d7dbde393a161f2b7452e94a74cb92be2df2d9465df03208"
FUNCTION_SHA256 = "c8822c4fa899675b4bf7e9c90713cd7483ea039f408eb11ccaa2c42aff220da4"
RAM = 0x200000
RAM_SIZE = 0x10000


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if hashlib.sha256(args.binary.read_bytes()).hexdigest() != BINARY_SHA256:
        raise ValueError("Rosetta binary differs from reviewed build 26A434")
    subprocess.run([str(ROOT / "dev/cargo"), "build", "--locked", "-p", "stela-cli"], check=True)
    row = json.loads(subprocess.check_output([str(ROOT / "target/debug/stela"), "binary-text", str(args.binary)]))[0]["slice"]
    symbol, address = next((name, value) for name, value in row["defined_text_symbols"].items() if "30find_arm_offset_for_x86_offset" in name)
    section = next(s for s in row["sections"] if s["guest_address"] <= address < s["guest_address"] + len(bytes.fromhex(s["data_hex"])))
    offset = address - section["guest_address"]
    code = bytes.fromhex(section["data_hex"])[offset:offset + 116]
    if hashlib.sha256(code).hexdigest() != FUNCTION_SHA256:
        raise ValueError("Rosetta lookup function differs from inspected source")
    reports = []
    # Disassembly shows begin/end pointers at +0x38/+0x40 and a 12-byte stride.
    # Each row compares word 0 to the requested key and returns word 1.
    for count in (0, 1, 2, 7, 128):
        entries = [(i * 8, 0x100 + i * 12, 0xfedc0000 + i) for i in range(count)]
        queries = {0, 1, 6, 0xffffffff}
        if entries:
            queries.update((entries[0][0], entries[count // 2][0], entries[-1][0], entries[-1][0] + 1))
        for query in sorted(queries):
            for flags, original in enumerate(states(all_flags=True)):
                initial = State.from_buffer_copy(original)
                initial.x[0], initial.x[1], initial.x[2] = RAM, query, RAM + 0x1000
                initial.sp = RAM + 0x8000
                memory = bytearray(b"\xa5" * RAM_SIZE)
                struct.pack_into("<QQ", memory, 0x38, RAM + 0x200, RAM + 0x200 + 12 * count)
                for index, entry in enumerate(entries):
                    struct.pack_into("<III", memory, 0x200 + index * 12, *entry)
                expected = bytearray(memory)
                hit = next((entry for entry in entries if entry[0] == query), None)
                if hit is not None:
                    struct.pack_into("<I", expected, 0x1000, hit[1])
                result = reference(code, initial, (RAM, bytes(memory)))
                if result["x"][0] != int(hit is not None) or result["memory"] != bytes(expected):
                    raise AssertionError(f"Rosetta exact-lookup model mismatch: {count}, {query}, {flags}")
                if result["sp"] != initial.sp or result["x"][15:] != list(initial.x)[15:]:
                    raise AssertionError("Lookup helper changed unexpected register state")
                reports.append({"entries": count, "query": query, "initial_nzcv": initial.nzcv, "found": hit is not None,
                                "arm_offset": hit[1] if hit else None, "passed": True})
    # The inspected unsigned high-index decrement relies on an input invariant:
    # querying below a nonzero first key underflows the search's upper index.
    # Record the observed failure, without claiming real Rosetta constructs
    # such a table or permits that query through its callers.
    invalid_state = State()
    invalid_state.x[0], invalid_state.x[1], invalid_state.x[2] = RAM, 0, RAM + 0x1000
    invalid_memory = bytearray(RAM_SIZE)
    struct.pack_into("<QQ", invalid_memory, 0x38, RAM + 0x200, RAM + 0x20c)
    struct.pack_into("<III", invalid_memory, 0x200, 4, 0x100, 0)
    try:
        reference(code, invalid_state, (RAM, bytes(invalid_memory)))
    except UcError as error:
        invalid_observation = {"first_key": 4, "query": 0, "reference_error": str(error), "caller_invariant": "unknown"}
    else:
        raise AssertionError("Previously observed below-first-key behavior changed")
    report = {"kind": "pinned_rosetta_offset_lookup_probe", "passed": True, "build": "26A434", "binary_sha256": BINARY_SHA256,
              "symbol": symbol, "original_guest_address": address, "function_sha256": FUNCTION_SHA256, "function_bytes": len(code),
              "state_and_memory_comparisons": len(reports), "reference": "Unicorn ARM64 2.1.4",
              "probe_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "shared_runner_sha256": hashlib.sha256((ROOT / "dev/differential.py").read_bytes()).hexdigest(),
              "observed_model": {"table_begin_offset": 0x38, "table_end_offset": 0x40, "entry_stride": 12,
                                 "key_offset": 0, "value_offset": 4, "search": "unsigned 32-bit exact-key binary search",
                                 "hit": "return 1 and write the ARM offset", "miss": "return 0 and leave output unchanged",
                                 "tested_domain": "empty tables or sorted unique tables beginning with key zero"},
              "outside_tested_domain": invalid_observation,
              "results": reports,
              "limits": "One pinned metadata helper on empty tables or sorted synthetic tables beginning with key zero. The below-first-key probe faults on crafted metadata; actual caller/table invariants are unproven. No actual x86 translation, emitted Rosetta code, hardware execution, cache loading or JIT fallback is demonstrated. Other record fields/structure layout remain unknown."}
    write_evidence(args.output, report)
    print(json.dumps({key: value for key, value in report.items() if key != "results"}, indent=2))


if __name__ == "__main__":
    main()
