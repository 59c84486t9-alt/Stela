#!/usr/bin/env python3
"""Compare register-offset ARM accesses with native x86, independent math and RAM."""
import argparse
import ctypes
import importlib.util
import hashlib
import json
import mmap
import multiprocessing
from pathlib import Path
import random
import signal
import struct
import subprocess
import tempfile
import time

from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_ARM, CS_MODE_64
from differential import ROOT, BASE, MASK, State, native, reference, states, state_dict, parse_fault_record, move
from evidence import write_evidence, retain_native_evidence

RAM_SIZE = 0x10000
RET = 0xd65f03c0
SIMD_REGISTER_OFFSET = 0x3c200800
ZERO_REGISTER = 31
VECTOR_BYTES = 16
OPTION_UXTW, OPTION_LSL, OPTION_SXTW, OPTION_SXTX = 2, 3, 6, 7
INDEX_OPTIONS = (OPTION_UXTW, OPTION_LSL, OPTION_SXTW, OPTION_SXTX)


def encoding(size, opcode, rt, rn, rm, option, scaled):
    return ((size << 30) | 0x38200800 | (opcode << 22) | (rm << 16)
            | (option << 13) | (int(scaled) << 12) | (rn << 5) | rt)


def valid_transfer(size, opcode):
    return opcode < 2 or (opcode == 2 and size < 3) or (opcode == 3 and size < 2)


def cases():
    result = []
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for size in range(4):
        for opcode in range(4):
            if not valid_transfer(size, opcode):
                continue
            for option in (2, 3, 6, 7):
                for scaled in (False, True):
                    roles = [(0, 1, 2), (7, 30, 9), (31, 0, 2), (31, 31, 31),
                             (0, 31, 2), (7, 7, 9), (0, 2, 2)]
                    if option in (3, 7):
                        roles.append((0, 1, 0))  # base/index alias
                    for rn, rt, rm in roles:
                        word = encoding(size, opcode, rt, rn, rm, option, scaled)
                        instruction = next(decoder.disasm(struct.pack("<I", word), 0), None)
                        if instruction is None or not instruction.mnemonic.startswith(("ldr", "str")):
                            raise AssertionError(f"Independent decoder declined {word:#x}")
                        result.append({"word": word, "size": size, "opcode": opcode, "rn": rn,
                                       "rt": rt, "rm": rm, "option": option, "scaled": scaled,
                                       "assembly": f"{instruction.mnemonic} {instruction.op_str}"})
    return result



def simd_encoding(size, load, rt, rn, rm, option, scaled):
    if size not in range(5) or option not in INDEX_OPTIONS:
        raise ValueError("Invalid SIMD register-offset operands")
    encoded_size = 0 if size == 4 else size
    opcode = int(load) | (2 if size == 4 else 0)
    return (SIMD_REGISTER_OFFSET | (encoded_size << 30) | (opcode << 22)
            | (rm << 16) | (option << 13) | (int(scaled) << 12) | (rn << 5) | rt)


def simd_cases():
    result = []
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    roles = ((0, 1, 2), (7, 31, 9), (31, 31, 31), (31, 0, 2),
             (7, 7, 9), (0, 2, 2), (0, 1, 0))
    for size in range(5):
        for load in (False, True):
            for option in INDEX_OPTIONS:
                for scaled in (False, True):
                    for rn, rt, rm in roles:
                        if rn == rm and rn != ZERO_REGISTER and option in (OPTION_UXTW, OPTION_SXTW):
                            continue  # A canonical host pointer cannot also be a 32-bit index.
                        word = simd_encoding(size, load, rt, rn, rm, option, scaled)
                        instruction = next(decoder.disasm(struct.pack("<I", word), BASE), None)
                        if instruction is None or instruction.mnemonic not in ("ldr", "str"):
                            raise AssertionError(f"Independent decoder declined {word:#x}")
                        result.append({"word": word, "size": size, "opcode": int(load),
                                       "rn": rn, "rt": rt, "rm": rm, "option": option,
                                       "scaled": scaled, "simd": True,
                                       "assembly": f"{instruction.mnemonic} {instruction.op_str}"})
    return result


def mathematical_reference(case, initial, ram_address, ram):
    result = state_dict(initial)
    memory = bytearray(ram)
    raw = 0 if case["rm"] == ZERO_REGISTER else initial.x[case["rm"]]
    displacement = extended(raw, case["option"]) << (case["size"] if case["scaled"] else 0)
    base = initial.sp if case["rn"] == ZERO_REGISTER else initial.x[case["rn"]]
    position = ((base + displacement) & MASK) - ram_address
    width = 1 << case["size"]
    if not 0 <= position <= len(memory) - width:
        raise ValueError("Mathematical access outside supplied RAM")
    if case.get("simd"):
        if case["opcode"]:
            value = int.from_bytes(memory[position:position + width], "little")
            result["v"][case["rt"]] = [value & MASK, value >> 64]
        else:
            vector = initial.v[case["rt"]]
            memory[position:position + width] = (vector[0] | (vector[1] << 64)).to_bytes(VECTOR_BYTES, "little")[:width]
    else:
        raise ValueError("Independent math currently covers the SIMD cohort")
    result["memory"] = bytes(memory)
    return result

def extended(raw, option):
    if option == 2:
        return raw & 0xffffffff
    if option == 6:
        low = raw & 0xffffffff
        return low - (1 << 32) if low & 0x80000000 else low
    return raw


def execute_cases(compiled):
    randomizer = random.Random(0x50e77a)
    initial_ram = randomizer.randbytes(RAM_SIZE)
    values = (0, MASK, 1, 0x8000000080008080, 0x7fffffff7fff7f7f,
              0x123456789abcdef0, 0x80, 0x8000)
    indices = (0, 1, 16, 0xaaaaaaaa00000003, MASK, 0x80000000,
               0x1234567880000001, 0x8000000000000000)
    comparisons = 0
    inputs = hashlib.sha256()
    with mmap.mmap(-1, RAM_SIZE, prot=mmap.PROT_READ | mmap.PROT_WRITE) as region:
        marker = ctypes.c_char.from_buffer(region)
        ram_address = ctypes.addressof(marker)
        del marker
        for number, case in enumerate(compiled):
            for index, (value, raw) in enumerate(zip(values, indices)):
                state = State.from_buffer_copy(states()[index % len(states())])
                state.nzcv = ((number + index) % 16) << 28
                if case.get("simd"):
                    state.reserved = 0xa5c39e71
                shift = case["size"] if case["scaled"] else 0
                raw = 0 if case["rm"] == 31 else raw
                displacement = (extended(raw, case["option"]) << shift) & MASK
                effective = ram_address + 0x4000
                if case["rn"] == case["rm"] and case["rn"] != 31:
                    factor = 1 + (1 << shift)
                    base = effective // 2 if factor == 2 else (effective * pow(factor, -1, 1 << 64)) & MASK
                    raw = base
                else:
                    effective += (displacement & 15) if case["rn"] == 31 else (0, 1, 7, 2, 3, 5, 9, 15)[index]
                    base = (effective - displacement) & MASK
                if case["rn"] == 31:
                    state.sp = base
                    assert base % 16 == 0
                else:
                    state.x[case["rn"]] = base
                if case["rm"] != 31:
                    state.x[case["rm"]] = raw
                if case["rt"] not in (31, case["rn"], case["rm"]):
                    state.x[case["rt"]] = value
                ram = bytearray(initial_ram)
                position = effective - ram_address
                ram[position:position + (1 << case["size"])] = (value | (0xfedcba9876543210 << 64)).to_bytes(VECTOR_BYTES, "little")[:1 << case["size"]]
                source = struct.pack("<II", case["word"], RET)
                inputs.update(bytes(state))
                inputs.update(ram)
                expected = reference(source, state, (ram_address, bytes(ram)))
                if case.get("simd") and expected != mathematical_reference(case, state, ram_address, ram):
                    raise AssertionError(f"Independent SIMD memory math differs: {case['assembly']}")
                region[:] = ram
                actual = native(case["native"], state)
                actual["memory"] = region[:]
                if expected != actual:
                    detail = {key: val for key, val in case.items() if key != "native"}
                    detail["input_index"] = hex(raw)
                    for label, outcome in (("expected", expected), ("actual", actual)):
                        detail[label] = {**outcome, "memory": hashlib.sha256(outcome["memory"]).hexdigest()}
                    raise AssertionError(json.dumps(detail, indent=2))
                comparisons += 1
    return {"programs": len(compiled), "state_and_memory_comparisons": comparisons,
            "state_and_memory_input_corpus_sha256": inputs.hexdigest()}


def worker(pipe, compiled):
    try:
        pipe.send(execute_cases(compiled))
    except BaseException as error:
        pipe.send({"error": repr(error)})
    finally:
        pipe.close()


def bounded_cases(compiled, timeout=180):
    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=worker, args=(send, compiled))
    process.start()
    send.close()
    try:
        deadline = time.monotonic() + timeout
        while not receive.poll(1):
            if process.exitcode is not None or time.monotonic() >= deadline:
                raise AssertionError(f"Native register-offset worker failed/timed out: exit={process.exitcode}")
        result = receive.recv()
        process.join(timeout=2)
        if process.exitcode != 0 or "error" in result:
            raise AssertionError(f"Register-offset suite failed: {result}, exit={process.exitcode}")
    finally:
        if process.is_alive():
            process.kill()
        process.join()
        receive.close()
    return result




def instruction_intervals(decoded, native_bytes, manifest):
    rows = manifest["source_map"]
    return [{"guest_pc": pc, "native_offset": start,
             "native_bytes": (rows[index + 1][1] if index + 1 < len(rows) else len(native_bytes)) - start,
             "native_instructions": sum(start <= item.address < (rows[index + 1][1] if index + 1 < len(rows) else len(native_bytes)) for item in decoded)}
            for index, (pc, start) in enumerate(rows)]

def check_faults(cli, directory, compiler):
    spec = importlib.util.spec_from_file_location("memory_faults", ROOT / "dev/memory-faults.py")
    memory_faults = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(memory_faults)
    observer = directory / "observer"
    observer_source = ROOT / "dev/native-memory-faults.c"
    subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
                    str(observer_source), "-o", str(observer)], check=True)
    cases = []
    for size in range(5):
        for load in (False, True):
            for rt in (0, ZERO_REGISTER):
                cases.append((size, load, rt, 0, "guard", OPTION_SXTW, True, None))
            if not load:
                cases.append((size, load, ZERO_REGISTER, 0, "readonly", OPTION_UXTW, False, None))
            for tail in (1, 2, 4, 8):
                if tail < 1 << size:
                    cases.append((size, load, ZERO_REGISTER, 0, "crossing", OPTION_SXTX, False, tail))
            cases.append((size, load, ZERO_REGISTER, ZERO_REGISTER, "sp_alignment", OPTION_LSL, False, None))
    reports = []
    for index, (size, load, rt, rn, protection, option, scaled, tail) in enumerate(cases):
        # A completed MOV survives; a negative SXTW index exercises the shared
        # address path before the fault. SP-policy cases use the zero index.
        rm = ZERO_REGISTER if rn == ZERO_REGISTER else 2
        displacement = -(2 << size) if scaled else -2
        if rm == ZERO_REGISTER:
            displacement = 0
        words = [move(2, 1, 7, 99)]
        if rm != ZERO_REGISTER:
            words.append(move(0, 1, rm, 1))  # MOVN X2,#1 = -2; UXTW uses the low word.
            if option == OPTION_UXTW:
                words[-1] = move(2, 1, rm, 2)
                displacement = 2
        words.extend((simd_encoding(size, load, rt, rn, rm, option, scaled), RET))
        source = struct.pack("<" + "I" * len(words), *words)
        fault_pc = BASE + (len(words) - 2) * 4
        input_path = directory / "fault-source.bin"
        input_path.write_bytes(source)
        output = directory / f"fault-{index}"
        manifest = json.loads(subprocess.check_output([str(cli), "compile-leaf", str(input_path), "--cpu-target", "baseline",
                                                      "--output-dir", str(output)]))
        if compiler != manifest["compiler_source_sha256"]:
            raise AssertionError("Compiler changed during fault checks")
        command = [str(observer), str(output / "native.bin"), protection, str(rn), str(displacement)]
        if tail is not None:
            command.append(str(tail))
        data = subprocess.check_output(command, timeout=10)
        (code_address, ram_address, page_size), initial, (number, pc, address), final, ram = parse_fault_record(data)
        mapped_pc = max((guest_pc for guest_pc, offset in manifest["source_map"] if offset <= pc - code_address), default=None)
        if mapped_pc != fault_pc:
            raise AssertionError("SIMD fault source map does not identify original instruction")
        if protection == "sp_alignment":
            expected = State.from_buffer_copy(initial)
            expected.x[7] = 99
            expected_ram = b"\xa5" * page_size
            faults = None
            if number != signal.SIGILL:
                raise AssertionError("SP alignment policy failed")
        else:
            expected, expected_ram, faults = memory_faults.arm_fault(source, initial, ram_address, page_size, protection == "readonly")
            if number not in (signal.SIGBUS, signal.SIGSEGV) or any(fault["pc"] != fault_pc for fault in faults):
                raise AssertionError("Native/original fault boundary differs")
            effective = (initial.sp if rn == ZERO_REGISTER else initial.x[rn]) + displacement
            expected_address = ram_address + page_size if protection == "crossing" else effective
            if address != expected_address:
                raise AssertionError("Native fault address differs")
        if bytes(expected) != bytes(final) or expected_ram != ram:
            differences = [index for index, (left, right) in enumerate(zip(expected_ram, ram)) if left != right]
            raise AssertionError(json.dumps({"case": (size, load, rt, rn, protection, option, scaled, tail),
                "expected_state": state_dict(expected), "native_state": state_dict(final),
                "memory_differences": differences[:32]}))
        reports.append({"size": size, "load": load, "rt": rt, "rn": rn, "protection": protection, "crossing_bytes": tail,
                        "source_sha256": hashlib.sha256(source).hexdigest(), "native_sha256": manifest["native_sha256"],
                        "guest_fault_pc": mapped_pc, "native_fault_offset": pc - code_address,
                        "native_signal": number, "arm_faults": faults,
                        "retained": retain_native_evidence("register-offset-fault", source,
                            (output / "native.bin").read_bytes(), manifest,
                            {"guest_fault_pc": mapped_pc, "native_signal": number,
                             "native_fault_offset": pc - code_address}, Path(__file__).read_bytes())})
    return {"cases": len(reports), "results": reports,
            "observer_source_sha256": hashlib.sha256(observer_source.read_bytes()).hexdigest(),
            "observer_executable_sha256": hashlib.sha256(observer.read_bytes()).hexdigest(),
            "shared_fault_harness_sha256": hashlib.sha256((ROOT / "dev/memory-faults.py").read_bytes()).hexdigest()}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--focus", choices=("scalar", "simd", "all"), default="scalar")
    parser.add_argument("--faults", action="store_true", help="Also check focused SIMD fault boundaries")
    arguments = parser.parse_args()
    if arguments.faults and arguments.focus == "scalar":
        parser.error("--faults requires --focus simd or all")
    if not arguments.no_build:
        subprocess.run([str(ROOT / "dev/cargo"), "build", "--locked", "-p", "stela-cli"], check=True)
    cli = ROOT / "target/debug/stela"
    executable_hash = hashlib.sha256(cli.read_bytes()).hexdigest()
    compiled = (cases() if arguments.focus in ("scalar", "all") else [])
    compiled += simd_cases() if arguments.focus in ("simd", "all") else []
    compiler = None
    corpus = hashlib.sha256()
    artifacts = []
    with tempfile.TemporaryDirectory(prefix="stela-register-offset-") as temporary:
        directory = Path(temporary)
        for index, case in enumerate(compiled):
            source = struct.pack("<II", case["word"], RET)
            corpus.update(source)
            input_path = directory / "source.bin"
            input_path.write_bytes(source)
            output = directory / str(index)
            manifest = json.loads(subprocess.check_output([str(cli), "compile-leaf", str(input_path), "--cpu-target", "baseline", "--output-dir", str(output)]))
            if compiler is not None and compiler != manifest["compiler_source_sha256"]:
                raise AssertionError("Compiler changed during suite")
            compiler = manifest["compiler_source_sha256"]
            case["native"] = (output / "native.bin").read_bytes()
            decoded = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(case["native"], 0))
            if sum(item.size for item in decoded) != len(case["native"]):
                raise AssertionError("Native output contains undecodable bytes")
            accounting = {"source_sha256": hashlib.sha256(source).hexdigest(),
                          "native_sha256": hashlib.sha256(case["native"]).hexdigest(),
                          "native_bytes": len(case["native"]), "native_instructions": len(decoded),
                          "source_map": manifest["source_map"],
                          "instruction_intervals": instruction_intervals(decoded, case["native"], manifest)}
            artifacts.append({**accounting, "case": {key: value for key, value in case.items() if key != "native"},
                "retained": retain_native_evidence(
                "register-offset", source, case["native"], manifest, accounting, Path(__file__).read_bytes())})
        result = bounded_cases(compiled)
        fault_results = check_faults(cli, directory, compiler) if arguments.faults else None
    if executable_hash != hashlib.sha256(cli.read_bytes()).hexdigest():
        raise AssertionError("Compiler executable changed during suite")
    report = {"kind": "register_offset_arm_vs_native_x86", "passed": True, **result,
              "reference": "Unicorn ARM64 2.1.4", "native": "direct x86-64 SysV calls in isolated worker",
              "tested_state": ["V0..V31 including SIMD scalar-load upper-bit clearing", "FPCR and FPSR preservation", "x0..x30", "SP", "NZCV", "all 65536 mapped RAM bytes"],
              "corpus_sha256": corpus.hexdigest(), "compiler_source_sha256": compiler,
              "compiler_executable_sha256": executable_hash, "focus": arguments.focus,
              "artifacts": artifacts, "faults": fault_results,
              "harness_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "shared_runner_sha256": hashlib.sha256((ROOT / "dev/differential.py").read_bytes()).hexdigest(),
              "shared_sources_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                  for name in ("dev/evidence.py", "dev/differential.py", "dev/memory-faults.py", "dev/native-memory-faults.c")},
              "limits": "Ordinary private RAM at identical guest/native addresses, aligned incoming SP, tags/PAC disabled. SIMD cases compare independent math as well as original ARM. Optional native signals establish fault state/PC boundaries, not guest exception delivery; Unicorn does not enforce SP alignment. No MMIO, atomics or concurrency."}
    write_evidence(ROOT / f".stela/register-offset-{arguments.focus}-differential-report.json" if arguments.focus != "scalar" else ROOT / ".stela/register-offset-differential-report.json", report)
    print(json.dumps({key: value for key, value in report.items() if key not in ("artifacts", "faults")}, indent=2))


if __name__ == "__main__":
    main()
