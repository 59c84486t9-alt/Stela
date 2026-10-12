#!/usr/bin/env python3
"""Compare first/second-element pair faults, partial stores and staged loads.

These tests establish a baseline private-RAM fault boundary against Unicorn.
They do not claim Apple-silicon FEAT_LSE2 atomicity or deliver guest exceptions.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import signal
import struct
import subprocess
import tempfile

from differential import compiler_cli, ROOT, BASE, State, move
from evidence import write_evidence


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "dev" / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


pairs = module("pair_suite", "pair-differential.py")
faults = module("fault_suite", "memory-faults.py")


def cases():
    result = []
    for opcode, loading in ((0, False), (0, True), (2, False), (2, True), (1, True)):
        size = 8 if opcode == 2 else 4
        for mode, offset in (("offset", 0), ("pre", -16), ("post", 16)):
            for rn, rt, rt2 in ((0, 1, 2), (31, 1, 2), (0, 31, 1), (0, 1, 31)):
                result.append({"opcode": opcode, "loading": loading, "bytes": size, "rn": rn, "rt": rt, "rt2": rt2,
                               "mode": mode, "offset": offset, "protection": "guard"})
            for rt, rt2 in ((1, 2), (31, 1), (1, 31)):
                result.append({"opcode": opcode, "loading": loading, "bytes": size, "rn": 0, "rt": rt, "rt2": rt2,
                               "mode": mode, "offset": offset, "protection": "pair_second"})
            if not loading:
                for protection in ("readonly", "pair_readonly"):
                    result.append({"opcode": opcode, "loading": loading, "bytes": size, "rn": 0, "rt": 1, "rt2": 2,
                                   "mode": mode, "offset": offset, "protection": protection})
        # A pre-index offset can make the effective address straddle a page
        # while the original SP remains 16-byte aligned.
        result.append({"opcode": opcode, "loading": loading, "bytes": size, "rn": 31, "rt": 1, "rt2": 2,
                       "mode": "pre", "offset": -size, "protection": "pair_second"})
        for protection, mode, offset in (("sp_alignment", "offset", 0), ("sp_alignment8", "pre", -8), ("sp_alignment", "post", 16)):
            result.append({"opcode": opcode, "loading": loading, "bytes": size, "rn": 31, "rt": 1, "rt2": 2,
                           "mode": mode, "offset": offset, "protection": protection})
    return result


def main():
    cli = compiler_cli(__doc__)
    compiler = None
    results = []
    partial_stores = 0
    with tempfile.TemporaryDirectory(prefix="stela-pair-faults-") as temporary:
        directory = Path(temporary)
        observer = directory / "observer"
        observer_source = ROOT / "dev/native-memory-faults.c"
        subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", str(observer_source), "-o", str(observer)], check=True)
        observer_hash = hashlib.sha256(observer.read_bytes()).hexdigest()
        for index, case in enumerate(cases()):
            word = pairs.encoding(case["opcode"], case["loading"], case["rt"], case["rt2"], case["rn"], case["offset"], case["mode"])
            source = struct.pack("<III", move(2, 1, 7, 99), word, pairs.RET)
            input_path = directory / "source.bin"
            input_path.write_bytes(source)
            output = directory / str(index)
            manifest = json.loads(subprocess.check_output([str(cli), "compile-leaf", str(input_path), "--output-dir", str(output)]))
            if compiler is not None and compiler != manifest["compiler_source_sha256"]:
                raise AssertionError("Compiler changed during pair fault suite")
            compiler = manifest["compiler_source_sha256"]
            pre_offset = case["offset"] if case["mode"] in ("pre", "offset") else 0
            arguments = [str(observer), str(output / "native.bin"), case["protection"], str(case["rn"]), str(pre_offset)]
            if case["protection"] in ("pair_second", "pair_readonly"):
                arguments.append(str(case["bytes"]))
            data = subprocess.check_output(arguments, timeout=10)
            code_address, ram_address, page_size = struct.unpack_from("<3Q", data)
            initial = State.from_buffer_copy(data[24:288])
            number, native_pc, fault_address = struct.unpack_from("<3Q", data, 288)
            final = State.from_buffer_copy(data[312:576])
            ram = data[576:]
            observed_bytes = page_size * (2 if case["protection"] == "pair_readonly" else 1)
            if len(ram) != observed_bytes or number == 0:
                raise AssertionError(f"Missing/truncated native pair fault: {case}")
            native_offset = native_pc - code_address
            mapped_pc = next((pc for pc, offset in reversed(manifest["source_map"]) if offset <= native_offset), None)
            if mapped_pc != BASE + 4:
                raise AssertionError(f"Pair fault mapped to wrong ARM instruction: {case}")
            expected_state = State.from_buffer_copy(initial)
            expected_state.x[7] = 99
            if case["protection"].startswith("sp_alignment"):
                expected, expected_ram = expected_state, b"\xa5" * observed_bytes
                observed_arm_faults = None
                if number != signal.SIGILL:
                    raise AssertionError("SP alignment did not stop at explicit fault boundary")
            else:
                if number not in (signal.SIGSEGV, signal.SIGBUS):
                    raise AssertionError(f"Unexpected native signal: {number}")
                expected, expected_ram, observed_arm_faults = faults.arm_fault(source, initial, ram_address, page_size,
                    case["protection"] == "readonly", second_readonly=case["protection"] == "pair_readonly")
                if any(item["pc"] != BASE + 4 for item in observed_arm_faults):
                    raise AssertionError("Reference fault PC differs")
                inaccessible = ram_address + 512 if case["protection"] == "readonly" else ram_address + page_size
                if fault_address != inaccessible:
                    raise AssertionError(f"Native pair fault address differs: {case}")
            if bytes(final) != bytes(expected) or ram != expected_ram:
                raise AssertionError(f"Pair fault mismatch in registers, writeback or partial RAM effects: {case}")
            # Neither element's guest register update nor writeback can commit.
            if bytes(final) != bytes(expected_state):
                raise AssertionError(f"Failed pair changed guest registers/writeback: {case}")
            changed = ram != b"\xa5" * observed_bytes
            expect_partial = not case["loading"] and case["protection"] in ("pair_second", "pair_readonly")
            if changed != expect_partial:
                raise AssertionError(f"Unexpected partial store behavior: {case}")
            partial_stores += changed
            results.append({**case, "passed": True, "partial_first_store": changed, "native_signal": number,
                            "native_fault_offset": native_offset, "guest_fault_pc": mapped_pc,
                            "source_sha256": hashlib.sha256(source).hexdigest(), "native_sha256": manifest["native_sha256"],
                            "ram_after_sha256": hashlib.sha256(ram).hexdigest(), "arm_faults": observed_arm_faults})
    report = {"kind": "integer_pair_fault_boundaries", "passed": True, "cases": len(results), "partial_first_store_cases": partial_stores,
              "compiler_source_sha256": compiler, "compiler_executable_sha256": hashlib.sha256(cli.read_bytes()).hexdigest(),
              "harness_sources_sha256": {name: hashlib.sha256((ROOT / "dev" / name).read_bytes()).hexdigest() for name in ("pair-faults.py", "pair-differential.py", "memory-faults.py", "differential.py", "native-memory-faults.c")},
              "observer_executable_sha256": observer_hash, "results": results,
              "limits": "Private ordinary-RAM baseline compared against Unicorn; first/second access fault mapping, staged guest loads and partial store effects. SP checks follow the enabled policy. No FEAT_LSE2/concurrent atomicity, Apple hardware fault equivalence, guest exception delivery or recovery."}
    write_evidence(ROOT / ".stela/pair-faults-report.json", report)
    print(json.dumps({key: value for key, value in report.items() if key not in ("results", "harness_sources_sha256")}, indent=2))


if __name__ == "__main__":
    main()
