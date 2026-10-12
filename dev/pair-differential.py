#!/usr/bin/env python3
"""Compare integer LDP/STP/LDPSW native code with ARM and all private RAM."""
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
from differential import compiler_cli, ROOT, MASK, State, arithmetic, move, native, reference, states
from evidence import write_evidence

RAM_SIZE = 0x10000
RET = 0xd65f03c0


def encoding(opcode, loading, rt, rt2, rn, offset, mode):
    element_bytes = 8 if opcode == 2 else 4
    assert offset % element_bytes == 0 and -64 <= offset // element_bytes <= 63
    index = {"post": 1, "offset": 2, "pre": 3}[mode]
    return (opcode << 30) | 0x28000000 | (index << 23) | (int(loading) << 22) | (((offset // element_bytes) & 127) << 15) | (rt2 << 10) | (rn << 5) | rt


def cases():
    result = []
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for opcode, loading in ((0, False), (0, True), (2, False), (2, True), (1, True)):
        element_bytes = 8 if opcode == 2 else 4
        for mode in ("offset", "pre", "post"):
            for scaled_offset in (-64, -1, 0, 1, 63):
                for rn, rt, rt2 in ((0, 1, 2), (7, 29, 30), (31, 0, 30), (31, 31, 7), (31, 7, 31), (0, 31, 1), (0, 1, 31), (0, 0, 2), (0, 1, 0), (7, 29, 29), (31, 31, 31)):
                    if (loading and rt == rt2) or (mode != "offset" and rn != 31 and rn in (rt, rt2)):
                        continue
                    offset = scaled_offset * element_bytes
                    word = encoding(opcode, loading, rt, rt2, rn, offset, mode)
                    instruction = next(decoder.disasm(struct.pack("<I", word), 0), None)
                    expected = "ldpsw" if opcode == 1 else "ldp" if loading else "stp"
                    if instruction is None or instruction.mnemonic != expected:
                        raise AssertionError(f"Independent decoder differs for {word:#x}")
                    result.append({"words": [word, RET], "opcode": opcode, "loading": loading,
                                   "bytes": element_bytes, "rn": rn, "rt": rt, "rt2": rt2,
                                   "offset": offset, "mode": mode,
                                   "assembly": f"{instruction.mnemonic} {instruction.op_str}"})
    result.append({"words": [encoding(2, False, 29, 30, 31, -16, "pre"),
                              move(2, 1, 29, 0), move(2, 1, 30, 0),
                              encoding(2, True, 29, 30, 31, 16, "post"),
                              0x8b1e03a0, RET],  # add x0,x29,x30
                   "workload": "stack_round_trip"})
    result.append({"words": [move(2, 1, 3, 4), move(2, 1, 2, 0),
                              encoding(2, True, 4, 5, 0, 16, "post"),
                              encoding(2, False, 4, 5, 1, 16, "post"),
                              0x8b040042, 0x8b050042,
                              arithmetic(1, 1, 1, 3, 3, 1), 0x54ffff61, RET],
                   "workload": "copy_and_sum"})
    return result


def execute_cases(compiled):
    comparisons = 0
    randomizer = random.Random(0x50e77a)
    initial_ram = randomizer.randbytes(RAM_SIZE)
    values = [0, MASK, 1, 0x80000000, 0x7fffffff, 0x8000000000000000, 0x7fffffffffffffff, 0xdeadbeef01234567]
    values.extend(randomizer.getrandbits(64) for _ in range(8))
    initial_states = states(all_flags=True)
    with mmap.mmap(-1, RAM_SIZE, prot=mmap.PROT_READ | mmap.PROT_WRITE) as region:
        marker = ctypes.c_char.from_buffer(region)
        ram_address = ctypes.addressof(marker)
        del marker
        if ram_address % 4096:
            raise AssertionError("Native RAM is not page aligned")
        for case in compiled:
            for index, first_value in enumerate(values):
                second_value = values[(index + 5) % len(values)]
                state = State.from_buffer_copy(initial_states[index])
                ram = bytearray(initial_ram)
                workload = case.get("workload")
                if workload is None:
                    base = ram_address + 1024
                    if case["rn"] == 31:
                        state.sp = base
                    else:
                        base += (0, 1, 3064, 3065, 3068, 3069, 7, 8)[index % 8]
                        state.x[case["rn"]] = base
                    for register, value in ((case["rt"], first_value), (case["rt2"], second_value)):
                        if register != 31 and register != case["rn"]:
                            state.x[register] = value
                    effective = base + (0 if case["mode"] == "post" else case["offset"])
                    position = effective - ram_address
                    size = case["bytes"]
                    assert 0 <= position and position + 2 * size <= RAM_SIZE
                    ram[position:position + 2 * size] = first_value.to_bytes(8, "little")[:size] + second_value.to_bytes(8, "little")[:size]
                elif workload in ("stack_round_trip", "kernel_stack"):
                    state.sp = ram_address + RAM_SIZE // 2
                    state.x[29], state.x[30] = first_value, second_value
                elif workload == "copy_and_sum":
                    state.x[0], state.x[1] = ram_address + 1024, ram_address + 8192
                    numbers = [(first_value + i) & MASK for i in range(8)]
                    ram[1024:1088] = struct.pack("<8Q", *numbers)
                else:
                    raise AssertionError(f"Unknown workload: {workload}")
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
                if workload == "copy_and_sum":
                    assert actual["x"][2] == sum(numbers) & MASK
                    assert actual["memory"][8192:8256] == ram[1024:1088]
                elif workload == "stack_round_trip":
                    assert actual["x"][0] == (first_value + second_value) & MASK
                    assert actual["sp"] == state.sp and actual["x"][29:31] == [first_value, second_value]
                comparisons += 1
    return {"programs": len(compiled), "state_and_memory_comparisons": comparisons}


def worker(pipe, compiled, execute):
    try:
        pipe.send(execute(compiled))
    except BaseException as error:
        pipe.send({"error": repr(error)})
    finally:
        pipe.close()


def bounded_cases(compiled, timeout=180, execute=execute_cases):
    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=worker, args=(send, compiled, execute))
    process.start()
    send.close()
    try:
        deadline = time.monotonic() + timeout
        while not receive.poll(1):
            if process.exitcode is not None or time.monotonic() >= deadline:
                raise AssertionError(f"Native pair worker failed or timed out: exit={process.exitcode}")
        result = receive.recv()
        process.join(timeout=2)
        if process.exitcode != 0 or "error" in result:
            raise AssertionError(f"Pair suite failed: {result}, exit={process.exitcode}")
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
    with tempfile.TemporaryDirectory(prefix="stela-pairs-") as temporary:
        directory = Path(temporary)
        for index, case in enumerate(compiled):
            source = struct.pack("<" + "I" * len(case["words"]), *case["words"])
            corpus.update(source)
            input_path = directory / "source.bin"
            input_path.write_bytes(source)
            output = directory / str(index)
            manifest = json.loads(subprocess.check_output([str(cli), "compile-leaf", str(input_path), "--output-dir", str(output)]))
            if compiler is not None and compiler != manifest["compiler_source_sha256"]:
                raise AssertionError("Compiler changed during pair suite")
            compiler = manifest["compiler_source_sha256"]
            case["native"] = (output / "native.bin").read_bytes()
        result = bounded_cases(compiled)
    report = {"kind": "integer_pairs_arm_vs_native_x86", "passed": True, **result,
              "reference": "Unicorn ARM64 2.1.4", "native": "direct x86-64 calls in isolated worker",
              "tested_state": ["x0..x30", "SP", "all 16 NZCV combinations", "all 65536 mapped RAM bytes"],
              "corpus_sha256": corpus.hexdigest(), "compiler_source_sha256": compiler,
              "compiler_executable_sha256": hashlib.sha256(cli.read_bytes()).hexdigest(),
              "harness_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "shared_runner_sha256": hashlib.sha256((ROOT / "dev/differential.py").read_bytes()).hexdigest(),
              "limits": "Private ordinary RAM with identical guest/native addresses and enabled SP alignment checks. No concurrency or FEAT_LSE2 single-copy atomicity, MMIO, SIMD, guest exception delivery or OS boot. Fault tests are separate."}
    write_evidence(ROOT / ".stela/pair-differential-report.json", report)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
