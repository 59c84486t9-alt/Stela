#!/usr/bin/env python3
"""Compare original ARM64 execution with independently emitted native x86.

Unicorn executes the original instructions as a development oracle only.
The native output is produced by the CLI before being mapped RX and called.
No ARM decoder, interpreter or runtime recompiler runs on the native path.
"""
import ctypes
from contextlib import contextmanager
import hashlib
import json
import mmap
import multiprocessing
import platform
from pathlib import Path
import random
import struct
import subprocess
import tempfile

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as arm
from evidence import write_evidence

ROOT = Path(__file__).resolve().parents[1]
BASE = 0x100000
MASK = (1 << 64) - 1
ARM_REGISTERS = [getattr(arm, f"UC_ARM64_REG_X{index}") for index in range(31)]


class State(ctypes.Structure):
    _fields_ = [("x", ctypes.c_uint64 * 31), ("sp", ctypes.c_uint64), ("nzcv", ctypes.c_uint32), ("reserved", ctypes.c_uint32)]


def reference(code, initial, memory=None):
    machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    machine.mem_map(BASE, 0x10000)
    machine.mem_write(BASE, code)
    if memory is not None:
        address, data = memory
        machine.mem_map(address, len(data))
        machine.mem_write(address, data)
    for register, value in zip(ARM_REGISTERS, initial.x):
        machine.reg_write(register, value)
    machine.reg_write(arm.UC_ARM64_REG_SP, initial.sp)
    machine.reg_write(arm.UC_ARM64_REG_NZCV, initial.nzcv)
    returned = False
    def boundary(machine, address, size, _):
        nonlocal returned
        if bytes(machine.mem_read(address,size)) == b"\xc0\x03\x5f\xd6":
            returned = True
            machine.emu_stop()
    machine.hook_add(UC_HOOK_CODE,boundary)
    # The harness owns leaf returns, including early RET paths. Bound loops.
    machine.emu_start(BASE, BASE + len(code), count=10000)
    if not returned:
        raise AssertionError("ARM reference did not return within its instruction budget")
    result = {"x": [machine.reg_read(r) for r in ARM_REGISTERS],
            "sp": machine.reg_read(arm.UC_ARM64_REG_SP),
            "nzcv": machine.reg_read(arm.UC_ARM64_REG_NZCV) & 0xf0000000}
    if memory is not None:
        result["memory"] = bytes(machine.mem_read(address, len(data)))
    return result


@contextmanager
def executable(code):
    if platform.machine() not in ("x86_64", "AMD64"):
        raise RuntimeError("Native differential runner requires an x86-64 host; use QEMU on ARM hosts.")
    region = mmap.mmap(-1, len(code), prot=mmap.PROT_READ | mmap.PROT_WRITE)
    region.write(code)
    marker = ctypes.c_char.from_buffer(region)
    address = ctypes.addressof(marker)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    libc.mprotect.restype = ctypes.c_int
    if libc.mprotect(address, len(code), mmap.PROT_READ | mmap.PROT_EXEC) != 0:
        raise OSError(ctypes.get_errno(), "mprotect RX failed")
    try:
        yield address
    finally:
        del marker
        region.close()


def native(code, initial):
    state = State.from_buffer_copy(initial)
    with executable(code) as address:
        ctypes.CFUNCTYPE(None, ctypes.POINTER(State))(address)(ctypes.byref(state))
    return {"x": list(state.x), "sp": state.sp, "nzcv": state.nzcv}


def native_worker(pipe, code, initial_states):
    try:
        pipe.send([native(code,State.from_buffer_copy(state)) for state in initial_states])
    except BaseException as error:
        pipe.send({"error":repr(error)})
    finally:
        pipe.close()


def bounded_native(code, initial_states):
    """A branch-emission bug must fail a test instead of hanging the runner."""
    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=native_worker,args=(send,code,[bytes(s) for s in initial_states]))
    process.start()
    send.close()
    try:
        if not receive.poll(10):
            raise AssertionError("Native control-flow test timed out")
        results = receive.recv()
        process.join(timeout=2)
        if process.exitcode != 0 or isinstance(results,dict):
            raise AssertionError(f"Native worker failed: {results}, exit={process.exitcode}")
        return results
    finally:
        if process.is_alive():
            process.kill()
        process.join()
        receive.close()


def move(kind, width, destination, immediate, shift=0):
    return (width << 31) | (kind << 29) | 0x12800000 | ((shift // 16) << 21) | (immediate << 5) | destination


def arithmetic(subtract, flags, width, destination, source, immediate, shifted=False):
    return (width << 31) | (subtract << 30) | (flags << 29) | 0x11000000 | (int(shifted) << 22) | (immediate << 10) | (source << 5) | destination


def register_operation(logical, operation, flags_or_invert, width, destination, left, right, shift, amount):
    fixed = 0x0a000000 if logical else 0x0b000000
    flags = (flags_or_invert << 21) if logical else (flags_or_invert << 29)
    return (width << 31) | (operation << (29 if logical else 30)) | flags | fixed | (shift << 22) | (right << 16) | (amount << 10) | (left << 5) | destination


def programs():
    # Exercises each immediate family, source/destination roles, widths, shifts,
    # flag-setting variants and unaffected-register preservation.
    result = []
    for width in (0, 1):
        for kind in (0, 2, 3):
            for shift in range(0, 32 if width == 0 else 64, 16):
                for destination in (0, 7, 30, 31):
                    for immediate in (0, 0xffff, 0x8001):
                        result.append([move(kind, width, destination, immediate, shift)])
        for subtract in (0, 1):
            for flags in (0, 1):
                for source in (0, 7, 31):
                    for destination in (0, 7, 31):
                        for immediate, shifted in ((0,False),(1,False),(4095,False),(4095,True)):
                            result.append([arithmetic(subtract, flags, width, destination, source, immediate, shifted)])
    result.extend([
        [move(2,1,0,40), arithmetic(0,0,1,0,0,2)],
        [move(2,1,0,0xffff,48), move(3,1,0,0x1234,16), arithmetic(1,1,1,3,0,4095,True)],
        [arithmetic(1,1,0,31,31,1), move(0,0,31,0), arithmetic(0,0,0,31,7,1)],
        [0xd503201f],
    ])
    for width in (0,1):
        for logical in (False,True):
            for operation in range(4 if logical else 2):
                for flags in (0,1):
                    for shift in range(4 if logical else 3):
                        for amount in (0,1,31 if width == 0 else 63):
                            for destination,left,right in ((0,0,7),(7,7,0),(31,31,7),(30,0,31)):
                                result.append([register_operation(logical,operation,flags,width,destination,left,right,shift,amount)])
    # Both outcomes of all ARM conditions, with non-adjacent targets.
    for condition in range(16):
        result.append([0x54000000 | (3 << 5) | condition, move(2,1,0,0), 0x14000002, move(2,1,0,1)])
    for width in (0,1):
        for nonzero in (0,1):
            for source in (0,7,31):
                result.append([(width<<31)|(nonzero<<24)|0x34000000|(3<<5)|source,move(2,1,0,0),0x14000002,move(2,1,0,1)])
    for bit in (0,31,32,63):
        for nonzero in (0,1):
            for source in (0,7,31):
                result.append([((bit>>5)<<31)|(nonzero<<24)|0x36000000|((bit&31)<<19)|(3<<5)|source,move(2,1,0,0),0x14000002,move(2,1,0,1)])
    result.extend([
        # Finite backward branch: x1 += 3, seven times; x0 <- x1.
        [move(2,1,0,7),move(2,1,1,0),arithmetic(0,0,1,1,1,3),arithmetic(1,1,1,0,0,1),0x54ffffc1,0xaa0103e0],
        # Early return when x7 == 0, later return on the other path.
        [0xb5000047,0xd65f03c0,move(2,1,0,99)],
    ])
    return result


def states(all_flags=False):
    randomizer = random.Random(0x50e77a)
    values = (0,1,MASK,MASK-1,0x7fffffffffffffff,0x8000000000000000,
              0xffffffff,0x7fffffff,0x80000000,0xfffffffffffff000)
    result = []
    for value in values:
        state = State()
        for index in range(31):
            state.x[index] = value if index in (0,7) else randomizer.getrandbits(64)
        state.sp = value
        state.nzcv = randomizer.randrange(16) << 28
        result.append(state)
    if all_flags:
        result = [State.from_buffer_copy(result[index % len(result)]) for index in range(16)]
        for flags,state in enumerate(result):
            state.nzcv = flags << 28
    return result


def main():
    subprocess.run([str(ROOT / "dev/cargo"), "build", "--locked", "-p", "stela-cli"], check=True)
    cli = ROOT / "target/debug/stela"
    cases = 0
    corpus = hashlib.sha256()
    compiler_source = None
    report = {"kind": "arm64_leaf_differential", "source_oracle": "Unicorn ARM64 2.1.4",
              "target": "native x86-64 SysV", "tested_state": ["x0..x30", "sp", "nzcv"],
              "limits": "Integer/register/internal-branch suite only. Guest memory operations, faults, external calls, SIMD, PAC and OS ABI are not exercised here; memory and fault suites are separate."}
    with tempfile.TemporaryDirectory(prefix="stela-diff-") as temporary:
        directory = Path(temporary)
        for index, words in enumerate(programs()):
            code = struct.pack("<" + "I" * (len(words)+1), *words, 0xd65f03c0)
            source = directory / "source.bin"
            source.write_bytes(code)
            output = directory / str(index)
            subprocess.run([str(cli), "compile-leaf", str(source), "--output-dir", str(output)], check=True, stdout=subprocess.DEVNULL)
            emitted = (output / "native.bin").read_bytes()
            manifest = json.loads((output / "manifest.json").read_text())
            if compiler_source is None:
                compiler_source = manifest["compiler_source_sha256"]
            if compiler_source != manifest["compiler_source_sha256"]:
                raise AssertionError("Compiler implementation changed during differential run")
            corpus.update(code)
            control_flow = any((word & 0xfc000000 == 0x14000000) or (word & 0xff000010 == 0x54000000) or (word & 0x7e000000 in (0x34000000,0x36000000)) for word in words)
            initial_states = states(all_flags=control_flow)
            expected_states = [reference(code,initial) for initial in initial_states]
            actual_states = bounded_native(emitted,initial_states) if control_flow else [native(emitted,initial) for initial in initial_states]
            for initial,expected,actual in zip(initial_states,expected_states,actual_states):
                if expected != actual:
                    raise AssertionError(json.dumps({"words": [hex(w) for w in words], "initial": {"x":list(initial.x), "sp":initial.sp, "nzcv":initial.nzcv}, "expected":expected, "actual":actual}, indent=2))
                cases += 1
    report.update({"passed":True,"programs":len(programs()),"state_comparisons":cases,
                   "corpus_sha256":corpus.hexdigest(), "compiler_source_sha256":compiler_source,
                   "compiler_executable_sha256":hashlib.sha256(cli.read_bytes()).hexdigest()})
    destination = ROOT / ".stela/differential-report.json"
    destination.parent.mkdir(exist_ok=True)
    write_evidence(destination,report)
    print(json.dumps(report,indent=2))


if __name__ == "__main__":
    main()
