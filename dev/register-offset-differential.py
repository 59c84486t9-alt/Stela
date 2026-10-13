#!/usr/bin/env python3
"""Compare scalar register-offset ARM accesses with native x86 and full RAM."""
import ctypes
import hashlib
import json
import mmap
import multiprocessing
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import time

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from differential import compiler_cli, ROOT, MASK, State, native, reference, states
from evidence import write_evidence

RAM_SIZE = 0x10000
RET = 0xd65f03c0


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
    with mmap.mmap(-1, RAM_SIZE, prot=mmap.PROT_READ | mmap.PROT_WRITE) as region:
        marker = ctypes.c_char.from_buffer(region)
        ram_address = ctypes.addressof(marker)
        del marker
        for number, case in enumerate(compiled):
            for index, (value, raw) in enumerate(zip(values, indices)):
                state = State.from_buffer_copy(states()[index % len(states())])
                state.nzcv = ((number + index) % 16) << 28
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
                ram[position:position + (1 << case["size"])] = value.to_bytes(8, "little")[:1 << case["size"]]
                source = struct.pack("<II", case["word"], RET)
                expected = reference(source, state, (ram_address, bytes(ram)))
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
    return {"programs": len(compiled), "state_and_memory_comparisons": comparisons}


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


def main():
    cli = compiler_cli(__doc__)
    compiled = cases()
    compiler = None
    corpus = hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix="stela-register-offset-") as temporary:
        directory = Path(temporary)
        for index, case in enumerate(compiled):
            source = struct.pack("<II", case["word"], RET)
            corpus.update(source)
            input_path = directory / "source.bin"
            input_path.write_bytes(source)
            output = directory / str(index)
            manifest = json.loads(subprocess.check_output([str(cli), "compile-leaf", str(input_path), "--output-dir", str(output)]))
            if compiler is not None and compiler != manifest["compiler_source_sha256"]:
                raise AssertionError("Compiler changed during suite")
            compiler = manifest["compiler_source_sha256"]
            case["native"] = (output / "native.bin").read_bytes()
        result = bounded_cases(compiled)
    report = {"kind": "register_offset_arm_vs_native_x86", "passed": True, **result,
              "reference": "Unicorn ARM64 2.1.4", "native": "direct x86-64 SysV calls in isolated worker",
              "tested_state": ["V0..V31, FPCR and FPSR preservation", "x0..x30", "SP", "NZCV", "all 65536 mapped RAM bytes"],
              "corpus_sha256": corpus.hexdigest(), "compiler_source_sha256": compiler,
              "compiler_executable_sha256": hashlib.sha256(cli.read_bytes()).hexdigest(),
              "harness_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "shared_runner_sha256": hashlib.sha256((ROOT / "dev/differential.py").read_bytes()).hexdigest(),
              "limits": "Ordinary private RAM at identical guest/native addresses, aligned incoming SP, tags/PAC disabled. Faults tested separately. No MMIO, atomics, concurrency, SIMD instructions or guest exception delivery."}
    write_evidence(ROOT / ".stela/register-offset-differential-report.json", report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
