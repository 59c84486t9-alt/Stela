#!/usr/bin/env python3
"""Check scalar register-offset protected accesses and pre-access SP policy."""
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import signal
import struct
import subprocess
import tempfile

from differential import parse_fault_record, compiler_cli, ROOT, BASE, State, move
from evidence import write_evidence


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "dev" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


offset_suite = load_module("offset_suite", "register-offset-differential.py")
fault_suite = load_module("fault_suite", "memory-faults.py")


def cases():
    result = []
    for size in range(4):
        for opcode in range(4):
            if not offset_suite.valid_transfer(size, opcode):
                continue
            for option in (2, 3, 6, 7):
                for scaled in (False, True):
                    for rn, rt in ((0, 1), (31, 31), (0, 0), (0, 3)):
                        result.append({"size": size, "opcode": opcode, "option": option,
                                       "scaled": scaled, "rn": rn, "rt": rt, "protection": "guard"})
        for option in (2, 3, 6, 7):
            for scaled in (False, True):
                result.append({"size": size, "opcode": 0, "option": option, "scaled": scaled,
                               "rn": 0, "rt": 3, "protection": "readonly"})
    for option in (2, 3, 6, 7):
        for scaled in (False, True):
            result.append({"size": 3, "opcode": 1, "option": option, "scaled": scaled,
                           "rn": 0, "rt": 1, "protection": "crossing"})
        for opcode in (0, 1):
            for protection in ("sp_alignment", "sp_alignment8"):
                result.append({"size": 3, "opcode": opcode, "option": option, "scaled": False,
                               "rn": 31, "rt": 0, "protection": protection})
    return result


def source_for(case):
    if case["protection"].startswith("sp_alignment"):
        # Offset would align the final address, but incoming SP must fault first.
        raw = 8 if case["protection"].endswith("8") else 15
    else:
        raw = -16 if case["option"] in (6, 7) else 16
    words = [move(2, 1, 7, 99), move(2 if raw >= 0 else 0, 1, 3, raw if raw >= 0 else ~raw)]
    if case["option"] == 2:
        words.append(move(3, 1, 3, 0xabcd, 32))  # UXTW must discard high half
    word = offset_suite.encoding(case["size"], case["opcode"], case["rt"], case["rn"], 3,
                                 case["option"], case["scaled"])
    fault_pc = BASE + 4 * len(words)
    source = struct.pack("<" + "I" * (len(words) + 2), *words, word, offset_suite.RET)
    shift = case["size"] if case["scaled"] else 0
    return source, fault_pc, raw << shift, raw


def main():
    cli = compiler_cli(__doc__)
    compiler = None
    reports = []
    corpus = hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix="stela-register-offset-faults-") as temporary:
        directory = Path(temporary)
        observer = directory / "observer"
        observer_source = ROOT / "dev/native-memory-faults.c"
        subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
                        str(observer_source), "-o", str(observer)], check=True)
        observer_hash = hashlib.sha256(observer.read_bytes()).hexdigest()
        for index, case in enumerate(cases()):
            source, fault_pc, displacement, raw = source_for(case)
            corpus.update(source)
            input_path = directory / "source.bin"
            input_path.write_bytes(source)
            output = directory / str(index)
            manifest = json.loads(subprocess.check_output([str(cli), "compile-leaf", str(input_path),
                                                            "--output-dir", str(output)]))
            if compiler is not None and compiler != manifest["compiler_source_sha256"]:
                raise AssertionError("Compiler changed during fault suite")
            compiler = manifest["compiler_source_sha256"]
            data = subprocess.check_output([str(observer), str(output / "native.bin"), case["protection"],
                                            str(case["rn"]), str(displacement)], timeout=10)
            (code_address, ram_address, page_size), initial, (number, native_pc, fault_address), final, ram = parse_fault_record(data)
            if len(ram) != page_size or number == 0:
                raise AssertionError(f"Missing fault or truncated observer output: {case}")
            native_offset = native_pc - code_address
            mapped_pc = None
            for guest_pc, offset in manifest["source_map"]:
                if offset <= native_offset:
                    mapped_pc = guest_pc
            if mapped_pc != fault_pc:
                raise AssertionError(f"Native fault mapped to wrong guest instruction: {case}")
            if case["protection"].startswith("sp_alignment"):
                expected = State.from_buffer_copy(initial)
                expected.x[7] = 99
                expected.x[3] = raw | (0xabcd << 32) if case["option"] == 2 else raw
                expected_ram = b"\xa5" * page_size
                if number != signal.SIGILL:
                    raise AssertionError("Incoming SP check did not fault at UD2")
                faults = None
            else:
                if number not in (signal.SIGSEGV, signal.SIGBUS):
                    raise AssertionError(f"Unexpected native fault kind: {number}")
                expected, expected_ram, faults = fault_suite.arm_fault(
                    source, initial, ram_address, page_size, case["protection"] == "readonly")
                if any(fault["pc"] != fault_pc for fault in faults):
                    raise AssertionError("Original ARM faulted at wrong instruction")
                base = initial.sp if case["rn"] == 31 else initial.x[case["rn"]]
                effective = (base + displacement) & ((1 << 64) - 1)
                inaccessible = ram_address + page_size if case["protection"] == "crossing" else effective
                if fault_address != inaccessible:
                    raise AssertionError(f"Native fault address differs: {case}")
            if bytes(expected) != bytes(final) or ram != expected_ram:
                raise AssertionError(f"Fault changed registers or RAM: {case}")
            reports.append({**case, "source_sha256": hashlib.sha256(source).hexdigest(),
                            "native_sha256": manifest["native_sha256"], "guest_fault_pc": mapped_pc,
                            "native_fault_offset": native_offset, "native_signal": number,
                            "arm_faults": faults, "passed": True})
    report = {"kind": "register_offset_fault_boundaries", "passed": True, "cases": len(reports),
              "compiler_source_sha256": compiler, "corpus_sha256": corpus.hexdigest(),
              "compiler_executable_sha256": hashlib.sha256(cli.read_bytes()).hexdigest(),
              "harness_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "shared_sources_sha256": {name: hashlib.sha256((ROOT / "dev" / name).read_bytes()).hexdigest()
                                        for name in ("differential.py", "memory-faults.py", "memory-differential.py",
                                                     "register-offset-differential.py")},
              "observer_source_sha256": hashlib.sha256(observer_source.read_bytes()).hexdigest(),
              "observer_executable_sha256": observer_hash, "results": reports,
              "limits": "Native host signal/state/RAM and source-PC boundaries. SP alignment checked against declared enabled pre-access policy; Unicorn does not enforce it. No guest syndrome/exception delivery, MMIO, atomics, tags/PAC or concurrency."}
    write_evidence(ROOT / ".stela/register-offset-faults-report.json", report)
    print(json.dumps({key: value for key, value in report.items() if key != "results"}, indent=2))


if __name__ == "__main__":
    main()
