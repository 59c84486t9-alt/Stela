#!/usr/bin/env python3
"""Check native fault PC mapping, unchanged state/writeback and protected RAM.

Data-abort cases compare original ARM execution in Unicorn. SP alignment cases
check the compiler's explicitly enabled alignment policy against Arm's specified
pre-access check. Native signals are evidence boundaries, not guest exceptions.
"""
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import signal
import struct
import subprocess
import tempfile

from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_INVALID, UC_PROT_READ
from unicorn import arm64_const as arm
from differential import ROOT, BASE, State, ARM_REGISTERS, move
from evidence import write_evidence

spec = importlib.util.spec_from_file_location("memory_suite", ROOT / "dev/memory-differential.py")
memory_suite = importlib.util.module_from_spec(spec)
spec.loader.exec_module(memory_suite)


def arm_fault(source, initial, ram_address, page_size, readonly):
    machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    machine.mem_map(BASE, 0x10000)
    machine.mem_write(BASE, source)
    machine.mem_map(ram_address, page_size)
    machine.mem_write(ram_address, b"\xa5" * page_size)
    if readonly:
        machine.mem_protect(ram_address, page_size, UC_PROT_READ)
    for register, value in zip(ARM_REGISTERS, initial.x):
        machine.reg_write(register, value)
    machine.reg_write(arm.UC_ARM64_REG_SP, initial.sp)
    machine.reg_write(arm.UC_ARM64_REG_NZCV, initial.nzcv)
    faults = []
    def fault(machine, access, address, size, value, _):
        faults.append({"access": access, "address": address, "size": size, "pc": machine.reg_read(arm.UC_ARM64_REG_PC)})
        return False
    machine.hook_add(UC_HOOK_MEM_INVALID, fault)
    try:
        machine.emu_start(BASE, BASE + len(source), count=20)
    except UcError:
        if not faults:
            raise
    if not faults:
        raise AssertionError("ARM reference did not fault")
    final = State()
    for index, register in enumerate(ARM_REGISTERS):
        final.x[index] = machine.reg_read(register)
    final.sp = machine.reg_read(arm.UC_ARM64_REG_SP)
    final.nzcv = machine.reg_read(arm.UC_ARM64_REG_NZCV)
    return final, bytes(machine.mem_read(ram_address, page_size)), faults


def cases():
    result = []
    for size in range(4):
        for opcode in range(4):
            if opcode >= 2 and (size == 3 or (opcode == 3 and size >= 2)):
                continue
            for mode, offset in (("unsigned", 0), ("unscaled", -16), ("pre", -16), ("post", 16)):
                for rn, rt in ((0, 1), (31, 31), (0, 0)):
                    if mode in ("pre", "post") and rn == rt and rn != 31:
                        continue
                    # Unscaled offset is part of the faulting effective address,
                    # just like pre-index, but must never update the base.
                    result.append({"size": size, "opcode": opcode, "rn": rn, "rt": rt, "offset": offset,
                                   "mode": mode, "protection": "guard"})
        # A store must honor a mapped page's write protection, not just bounds.
        result.append({"size": size, "opcode": 0, "rn": 0, "rt": 1,
                       "offset": 16, "mode": "post", "protection": "readonly"})
    result.append({"size": 3, "opcode": 1, "rn": 0, "rt": 1,
                   "offset": 0, "mode": "unsigned", "protection": "crossing"})
    for opcode in (0, 1):
        for mode, offset in (("unsigned", 0), ("pre", -1), ("post", 16)):
            result.append({"size": 3, "opcode": opcode, "rn": 31, "rt": 0,
                           "offset": offset, "mode": mode, "protection": "sp_alignment"})
    return result


def main():
    subprocess.run([str(ROOT / "dev/cargo"), "build", "--locked", "-p", "stela-cli"], check=True)
    cli = ROOT / "target/debug/stela"
    reports = []
    compiler = None
    with tempfile.TemporaryDirectory(prefix="stela-faults-") as temporary:
        directory = Path(temporary)
        observer = directory / "observer"
        observer_source = ROOT / "dev/native-memory-faults.c"
        subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", str(observer_source), "-o", str(observer)], check=True)
        observer_hash = hashlib.sha256(observer.read_bytes()).hexdigest()
        for index, case in enumerate(cases()):
            word = memory_suite.encoding(case["size"], case["opcode"], case["rt"], case["rn"], case["offset"], case["mode"])
            # Prior completed instructions survive the subsequent fault.
            source = struct.pack("<III", move(2, 1, 7, 99), word, memory_suite.RET)
            input_path = directory / "source.bin"
            input_path.write_bytes(source)
            output = directory / str(index)
            manifest = json.loads(subprocess.check_output([str(cli), "compile-leaf", str(input_path), "--output-dir", str(output)]))
            if compiler is not None and compiler != manifest["compiler_source_sha256"]:
                raise AssertionError("Compiler changed during fault suite")
            compiler = manifest["compiler_source_sha256"]
            pre_offset = case["offset"] if case["mode"] in ("pre", "unscaled") else 0
            data = subprocess.check_output([str(observer), str(output / "native.bin"), case["protection"], str(case["rn"]), str(pre_offset)], timeout=10)
            code_address, ram_address, page_size = struct.unpack_from("<3Q", data)
            initial = State.from_buffer_copy(data[24:288])
            number, native_pc, fault_address = struct.unpack_from("<3Q", data, 288)
            final = State.from_buffer_copy(data[312:576])
            ram = data[576:]
            if len(ram) != page_size:
                raise AssertionError("Truncated fault observer output")
            if number == 0:
                raise AssertionError(f"Native access failed to fault: {case}")
            native_offset = native_pc - code_address
            mapped_pc = None
            for guest_pc, offset in manifest["source_map"]:
                if offset <= native_offset:
                    mapped_pc = guest_pc
            if mapped_pc != BASE + 4:
                raise AssertionError(f"Fault mapped to wrong ARM instruction: {mapped_pc}, {case}")
            if case["protection"] == "sp_alignment":
                expected = State.from_buffer_copy(initial)
                expected.x[7] = 99
                expected_ram = b"\xa5" * page_size
                if number != signal.SIGILL:
                    raise AssertionError("SP policy did not fault at UD2 boundary")
                faults = None
            else:
                if number not in (signal.SIGSEGV, signal.SIGBUS):
                    raise AssertionError(f"Unexpected native fault kind: {number}")
                expected, expected_ram, faults = arm_fault(source, initial, ram_address, page_size, case["protection"] == "readonly")
                if any(fault["pc"] != BASE + 4 for fault in faults):
                    raise AssertionError("Reference fault PC differs")
                effective = (initial.sp if case["rn"] == 31 else initial.x[case["rn"]])
                if case["mode"] != "post":
                    effective += case["offset"]
                # A cross-page x86 fault names the inaccessible page; ARM's
                # oracle may name the transfer's start or inaccessible subaccess.
                inaccessible = ram_address + page_size if case["protection"] == "crossing" else effective
                if fault_address != inaccessible:
                    raise AssertionError("Native fault address differs")
            if bytes(expected) != bytes(final) or ram != expected_ram:
                raise AssertionError(f"Fault changed guest registers/writeback or RAM: {case}")
            reports.append({**case, "source_sha256": hashlib.sha256(source).hexdigest(),
                            "native_sha256": manifest["native_sha256"], "native_fault_offset": native_offset,
                            "guest_fault_pc": mapped_pc, "native_signal": number, "arm_faults": faults, "passed": True})
    report = {"kind": "direct_ram_fault_boundaries", "passed": True, "cases": len(reports),
              "compiler_source_sha256": compiler, "compiler_executable_sha256": hashlib.sha256(cli.read_bytes()).hexdigest(),
              "harness_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "shared_runner_sha256": hashlib.sha256((ROOT / "dev/differential.py").read_bytes()).hexdigest(),
              "observer_source_sha256": hashlib.sha256(observer_source.read_bytes()).hexdigest(),
              "observer_executable_sha256": observer_hash, "results": reports,
              "limits": "Host signal boundary, state/writeback and guest-PC mapping only. SP alignment checked against the declared enabled policy; Unicorn does not enforce it here. No guest syndrome/exception delivery, tagged pointers, MMIO or concurrency."}
    write_evidence(ROOT / ".stela/memory-faults-report.json", report)
    print(json.dumps({key: value for key, value in report.items() if key != "results"}, indent=2))


if __name__ == "__main__":
    main()
