#!/usr/bin/env python3
"""Compare original ARM64 execution with independently emitted native x86.

Unicorn executes the original instructions as a development oracle only.
The native output is produced by the CLI before being mapped RX and called.
No ARM decoder, interpreter or runtime recompiler runs on the native path.
"""
import argparse
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
ARM_VECTORS = [getattr(arm, f"UC_ARM64_REG_Q{index}") for index in range(32)]


class State(ctypes.Structure):
    _fields_ = [("x", ctypes.c_uint64 * 31), ("sp", ctypes.c_uint64), ("nzcv", ctypes.c_uint32), ("reserved", ctypes.c_uint32),
                ("v", (ctypes.c_uint64 * 2) * 32), ("fpcr", ctypes.c_uint32), ("fpsr", ctypes.c_uint32)]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        seed_extended_state(self)


def seed_extended_state(state, seed=None):
    """Dirty appended fields without consuming any existing GPR random stream."""
    seed = hashlib.sha256(bytes(state)[:264]).digest() if seed is None else seed
    rng = random.Random(seed)
    for vector in state.v:
        vector[:] = [rng.getrandbits(64), rng.getrandbits(64)]
    # Architectural fields implemented by Unicorn; avoid RES0 discrepancies.
    state.fpcr = rng.getrandbits(32) & 0x07c00000
    state.fpsr = rng.getrandbits(32) & 0x0800001f
    return state


def extended_state(state):
    return {"v": [list(vector) for vector in state.v], "fpcr": state.fpcr, "fpsr": state.fpsr}


def state_dict(state):
    return {"x": list(state.x), "sp": state.sp, "nzcv": state.nzcv,
            "reserved": state.reserved, **extended_state(state)}


def initialize_extended_arm(machine, initial):
    machine.reg_write_batch([(register, value[0] | (value[1] << 64))
                             for register, value in zip(ARM_VECTORS, initial.v)] +
                            [(arm.UC_ARM64_REG_FPCR, initial.fpcr), (arm.UC_ARM64_REG_FPSR, initial.fpsr)])


def initialize_arm(machine, initial):
    registers = ARM_REGISTERS + [arm.UC_ARM64_REG_SP, arm.UC_ARM64_REG_NZCV] + ARM_VECTORS + [arm.UC_ARM64_REG_FPCR, arm.UC_ARM64_REG_FPSR]
    values = [*initial.x, initial.sp, initial.nzcv] + [value[0] | (value[1] << 64) for value in initial.v] + [initial.fpcr, initial.fpsr]
    machine.reg_write_batch(list(zip(registers, values)))


def capture_arm(machine, initial=None, reserved=None):
    state = State.from_buffer_copy(initial) if initial is not None else State()
    registers = ARM_REGISTERS + [arm.UC_ARM64_REG_SP, arm.UC_ARM64_REG_NZCV] + ARM_VECTORS + [arm.UC_ARM64_REG_FPCR, arm.UC_ARM64_REG_FPSR]
    values = machine.reg_read_batch(registers)
    state.x[:] = values[:31]
    state.sp, state.nzcv = values[31], values[32] & 0xf0000000
    for index, value in enumerate(values[33:65]):
        state.v[index][:] = [value & MASK, value >> 64]
    state.fpcr, state.fpsr = values[65:67]
    if reserved is not None:
        state.reserved = reserved
    return state


def parse_fault_record(data):
    """C observer framing: header3Q, initialState, event3Q, finalState, RAM."""
    header_bytes = event_bytes = struct.calcsize("<3Q")
    state_bytes = ctypes.sizeof(State)
    event_offset = header_bytes + state_bytes
    final_offset = event_offset + event_bytes
    ram_offset = final_offset + state_bytes
    if len(data) < ram_offset:
        raise AssertionError("Truncated native fault observer record")
    return (struct.unpack_from("<3Q", data), State.from_buffer_copy(data[header_bytes:event_offset]),
            struct.unpack_from("<3Q", data, event_offset),
            State.from_buffer_copy(data[final_offset:ram_offset]), data[ram_offset:])


assert ctypes.sizeof(State) == 784 and State.v.offset == 264 and State.fpcr.offset == 776 and State.fpsr.offset == 780


def reference(code, initial, memory=None):
    machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    machine.mem_map(BASE, 0x10000)
    machine.mem_write(BASE, code)
    if memory is not None:
        address, data = memory
        machine.mem_map(address, len(data))
        machine.mem_write(address, data)
    initialize_arm(machine, initial)
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
    result = state_dict(capture_arm(machine, initial))
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
    return state_dict(state)


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
        seed_extended_state(state)
        result.append(state)
    if all_flags:
        result = [State.from_buffer_copy(result[index % len(result)]) for index in range(16)]
        for flags,state in enumerate(result):
            state.nzcv = flags << 28
    return result


def compiler_cli(description):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--no-build', action='store_true', help='Use the already built, frozen CLI')
    arguments = parser.parse_args()
    if not arguments.no_build:
        subprocess.run([str(ROOT / 'dev/cargo'), 'build', '--locked', '-p', 'stela-cli'], check=True)
    return ROOT / 'target/debug/stela'


def main():
    cli = compiler_cli(__doc__)
    cases = 0
    corpus = hashlib.sha256()
    compiler_source = None
    report = {"kind": "arm64_leaf_differential", "source_oracle": "Unicorn ARM64 2.1.4",
              "target": "native x86-64 SysV", "tested_state": ["x0..x30", "sp", "nzcv", "reserved", "v0..v31", "fpcr", "fpsr"],
              "limits": "Integer/register/internal-branch suite only. Guest memory operations, faults, external calls, SIMD instructions, PAC and OS ABI are not exercised here; memory and fault suites are separate."}
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
                   "compiler_executable_sha256":hashlib.sha256(cli.read_bytes()).hexdigest(),
                   "harness_source_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
    destination = ROOT / ".stela/differential-report.json"
    destination.parent.mkdir(exist_ok=True)
    write_evidence(destination,report)
    print(json.dumps(report,indent=2))


if __name__ == "__main__":
    main()
