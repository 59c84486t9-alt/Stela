#!/usr/bin/env python3
"""Compare direct native RAM accesses with original ARM instructions and RAM.

Guest pointers equal the native mapping's addresses in both engines. Neither
engine maps the other's state or executable code into the guest RAM region.
Native execution is isolated in a bounded subprocess; crashes fail the suite.
"""
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
from differential import ROOT, MASK, State, arithmetic, move, native, reference, states
from evidence import write_evidence

RAM_SIZE = 0x10000
RET = 0xd65f03c0


def encoding(size, opcode, rt, rn, offset, mode):
    if mode == "unsigned":
        assert offset % (1 << size) == 0
        return (size << 30) | 0x39000000 | (opcode << 22) | ((offset >> size) << 10) | (rn << 5) | rt
    assert -256 <= offset <= 255
    indexing = {"unscaled": 0, "post": 1, "pre": 3}[mode]
    return (size << 30) | 0x38000000 | (opcode << 22) | ((offset & 511) << 12) | (indexing << 10) | (rn << 5) | rt


def cases():
    result = []
    disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for size in range(4):
        for opcode in range(4):
            if opcode >= 2 and (size == 3 or (opcode == 3 and size >= 2)):
                continue
            for mode in ("unsigned", "unscaled", "pre", "post"):
                offsets = (0, 1 << size, 4095 << size) if mode == "unsigned" else (-256, -1, 0, 255)
                for offset in offsets:
                    for rn, rt in ((0, 1), (7, 30), (31, 0), (31, 31), (0, 31), (7, 7)):
                        if mode in ("pre", "post") and rn == rt and rn != 31:
                            continue
                        word = encoding(size, opcode, rt, rn, offset, mode)
                        instruction = next(disassembler.disasm(struct.pack("<I", word), 0), None)
                        if instruction is None or not instruction.mnemonic.startswith(("ldr", "str", "ldur", "stur")):
                            raise AssertionError(f"Independent decoder declined {word:#x}")
                        result.append({"words": [word, RET], "size": size, "opcode": opcode,
                                       "rn": rn, "rt": rt, "offset": offset, "mode": mode,
                                       "assembly": f"{instruction.mnemonic} {instruction.op_str}"})
    # A realistic memory/control-flow interaction: copy eight 64-bit values and
    # accumulate their sum. Post-indexed pointers advance independently.
    result.append({"words": [move(2, 1, 3, 8), move(2, 1, 2, 0),
                              encoding(3, 1, 4, 0, 8, "post"),
                              encoding(3, 0, 4, 1, 8, "post"),
                              0x8b040042,  # add x2,x2,x4
                              arithmetic(1, 1, 1, 3, 3, 1),
                              0x54ffff81, RET],  # b.ne back to LDR
                   "workload": "copy_and_sum"})
    # The same SP serves as base for stores/loads around a temporary stack frame.
    result.append({"words": [encoding(3, 0, 7, 31, -16, "pre"),
                              encoding(3, 1, 0, 31, 16, "post"), RET],
                   "workload": "stack_round_trip"})
    return result


def execute_cases(compiled):
    comparisons = 0
    randomizer = random.Random(0x50e77a)
    initial_ram = randomizer.randbytes(RAM_SIZE)
    values = (0, MASK, 1, 0x8000000080008080, 0x7fffffff7fff7f7f, 0x123456789abcdef0)
    with mmap.mmap(-1, RAM_SIZE, prot=mmap.PROT_READ | mmap.PROT_WRITE) as region:
        marker = ctypes.c_char.from_buffer(region)
        ram_address = ctypes.addressof(marker)
        del marker
        if ram_address % 4096 != 0:
            raise AssertionError("Native RAM is not page aligned")
        for case_index, case in enumerate(compiled):
            for index in range(case.get("state_count", len(values))):
                value = values[index % len(values)]
                state = State.from_buffer_copy(states()[index % len(states())])
                # Across the corpus exercise every input NZCV combination.
                state.nzcv = ((case_index + index) % 16) << 28
                ram = bytearray(initial_ram)
                if "workload" not in case:
                    base = ram_address + 1024
                    if case["rn"] == 31:
                        state.sp = base
                    else:
                        # Ordinary bases can be unaligned, including accesses
                        # crossing a page boundary in otherwise mapped RAM.
                        base += (0, 1, 3069, 7, 2, 3)[index % 6]
                        state.x[case["rn"]] = base
                    if case["rt"] != 31 and case["rt"] != case["rn"]:
                        state.x[case["rt"]] = value
                    effective = base + (0 if case["mode"] == "post" else case["offset"])
                    position = effective - ram_address
                    assert 0 <= position and position + (1 << case["size"]) <= RAM_SIZE
                    ram[position:position + (1 << case["size"])] = value.to_bytes(8, "little")[:1 << case["size"]]
                elif case["workload"] == "copy_and_sum":
                    state.x[0], state.x[1] = ram_address + 1024, ram_address + 8192
                    numbers = [(value + i) & MASK for i in range(8)]
                    ram[1024:1088] = struct.pack("<8Q", *numbers)
                else:
                    state.sp = ram_address + 1024
                    state.x[7] = value
                source = struct.pack("<" + "I" * len(case["words"]), *case["words"])
                expected = reference(source, state, (ram_address, bytes(ram)))
                region[:] = ram
                actual = native(case["native"], state)
                actual["memory"] = region[:]
                if expected != actual:
                    detail = {key: val for key, val in case.items() if key != "native"}
                    for label, result in (("expected", expected), ("actual", actual)):
                        detail[label] = {**result, "memory": hashlib.sha256(result["memory"]).hexdigest()}
                    raise AssertionError(json.dumps(detail, indent=2))
                if case.get("workload") == "copy_and_sum":
                    assert actual["x"][2] == sum(numbers) & MASK
                    assert actual["memory"][8192:8256] == ram[1024:1088]
                elif case.get("workload") == "stack_round_trip":
                    assert actual["x"][0] == value and actual["sp"] == state.sp
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
                raise AssertionError(f"Native memory worker failed or timed out: exit={process.exitcode}")
        result = receive.recv()
        process.join(timeout=2)
        if process.exitcode != 0 or "error" in result:
            raise AssertionError(f"Memory suite failed: {result}, exit={process.exitcode}")
    finally:
        if process.is_alive():
            process.kill()
        process.join()
        receive.close()
    return result


def main():
    subprocess.run([str(ROOT / "dev/cargo"), "build", "--locked", "-p", "stela-cli"], check=True)
    cli = ROOT / "target/debug/stela"
    compiled = cases()
    compiler = None
    corpus = hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix="stela-memory-") as temporary:
        directory = Path(temporary)
        for index, case in enumerate(compiled):
            source = struct.pack("<" + "I" * len(case["words"]), *case["words"])
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
    report = {"kind": "direct_ram_arm_vs_native_x86", "passed": True, **result,
              "reference": "Unicorn ARM64 2.1.4", "native": "direct x86-64 SysV calls in isolated worker",
              "tested_state": ["x0..x30", "SP", "NZCV", "all 65536 mapped RAM bytes"],
              "corpus_sha256": corpus.hexdigest(), "compiler_source_sha256": compiler,
              "compiler_executable_sha256": hashlib.sha256(cli.read_bytes()).hexdigest(),
              "harness_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "shared_runner_sha256": hashlib.sha256((ROOT / "dev/differential.py").read_bytes()).hexdigest(),
              "limits": "Ordinary private RAM, identical guest/native addresses, aligned incoming SP, tags/PAC disabled. Fault tests are separate. No MMIO, atomics, concurrency, SIMD, guest exception delivery or OS boot."}
    write_evidence(ROOT / ".stela/memory-differential-report.json", report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
