#!/usr/bin/env python3
"""Execute original Stela ARM tasks on the freestanding x86 QEMU debug machine.

Host page-fault retry and PIT delivery are exercised inside actual translated
code. This does not implement ARM EL1 exception delivery or an ARM MMU.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import time

import vm
from evidence import write_evidence

ROOT = Path(__file__).resolve().parents[1]
GUEST_BASE = 0x100000
STATE_BYTES = 784
STATE_A = 0x6000
STATE_B = 0x6400
TASK_DATA = (0x8000, 0x8010)
TIMER_TICKS = 0x8040
TRACE = 0x9000
FAULT_STATE = 0xB000
FAULT_RAM = 0xB400
FAULT_ADDRESS = 0x200000
NATIVE_BASE = 0x10000
MINIMUM_NATIVE_IRQS = 4
INITIAL_X3 = 0xDEADBEEF
PAGE_FAULT_WORD_INDEX = 5
LOOP_WORDS = 12
INITIAL_NZCV = 0xB0000000
NZCV_OFFSET = 256
GPR_COUNT = 32
BLOCK_ABI = "x86_64-sysv-guest-state-v2-block-exit-direct-ram"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def task_words():
    """Named A64 encodings for an original two-task polling/fault fixture."""
    mov_register = 0xAA0003E0
    ldr_unsigned_x = 0xF9400000
    str_unsigned_x = 0xF9000000
    add_immediate_x = 0x91000000
    movz_x = 0xD2800000
    cmp_immediate_x = 0xF100001F
    branch_condition = 0x54000000
    condition_carry_clear = 3
    brk = 0xD4200000
    branch_word_index = LOOP_WORDS - 1
    backward_word_offset = (-branch_word_index) & ((1 << 19) - 1)
    return [
        mov_register | (5 << 16),                      # MOV X0,X5
        ldr_unsigned_x | 1,                            # LDR X1,[X0]
        add_immediate_x | (1 << 10) | (1 << 5) | 1,    # ADD X1,X1,#1
        str_unsigned_x | 1,                            # STR X1,[X0]
        movz_x | (1 << 21) | (0x20 << 5) | 2,          # MOV X2,#0x200000
        ldr_unsigned_x | (2 << 5) | 3,                  # LDR X3,[X2]
        add_immediate_x | (7 << 10) | (3 << 5) | 3,    # ADD X3,X3,#7
        str_unsigned_x | (1 << 10) | 3,                 # STR X3,[X0,#8]
        movz_x | (TIMER_TICKS << 5) | 4,                # MOV X4,#timer
        ldr_unsigned_x | (4 << 5) | 4,                  # LDR X4,[X4]
        cmp_immediate_x | (MINIMUM_NATIVE_IRQS << 10) | (4 << 5),
        branch_condition | (backward_word_offset << 5) | condition_carry_clear,
        brk | (0x10 << 5),
    ]


def initial_state(task):
    registers = [0x0123456700000000 + task * 0x10000 + index for index in range(GPR_COUNT)]
    registers[3] = INITIAL_X3
    registers[5] = TASK_DATA[task]
    registers[31] = 0x700000 + task * 0x1000
    vectors = bytes((index * 13 + task * 7 + 1) & 0xFF for index in range(512))
    return struct.pack("<32QII", *registers, INITIAL_NZCV, 0x11223344) + vectors + struct.pack("<II", 0x400000, 0x8000000)


def compile_tasks(stela, directory):
    from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_64

    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    words = task_words()
    source = struct.pack(f"<{len(words)}I", *words)
    original = directory / "task.arm64"
    original.write_bytes(source)
    arm_decoder = Cs(CS_ARCH_ARM64, 0)
    arm_instructions = [{"pc": instruction.address, "bytes": instruction.bytes.hex(),
                         "mnemonic": instruction.mnemonic, "operands": instruction.op_str}
                        for instruction in arm_decoder.disasm(source, GUEST_BASE)]
    if len(arm_instructions) != len(words):
        raise RuntimeError("Original ARM fixture did not decode completely")
    (directory / "original-inspection.json").write_text(json.dumps(arm_instructions, indent=2) + "\n")
    for task, name in enumerate(("a", "b")):
        (directory / f"state-{name}.bin").write_bytes(initial_state(task))
    manifests = []
    for name, offset in (("loop", 0), ("trap", LOOP_WORDS * 4)):
        input_path = directory / f"{name}.arm64"
        input_path.write_bytes(source[offset:])
        output = directory / name
        result = subprocess.run(
            [str(stela), "compile-block", str(input_path), "--cpu-target", "baseline",
             "--guest-base", hex(GUEST_BASE + offset), "--output-dir", str(output)],
            check=True, capture_output=True, text=True,
        )
        (directory / f"{name}-compile.stdout").write_text(result.stdout)
        manifest = json.loads((output / "manifest.json").read_text())
        native = (output / "native.bin").read_bytes()
        if manifest["abi"] != BLOCK_ABI or manifest["native_sha256"] != sha256(native):
            raise RuntimeError("Compiler block ABI or native identity differs")
        consumed = manifest["source_bytes"]
        expected_bytes = LOOP_WORDS * 4 if name == "loop" else 4
        if consumed != expected_bytes or manifest["source_sha256"] != sha256(source[offset:offset + consumed]):
            raise RuntimeError("Compiler consumed unexpected original instructions")
        instructions = [{"offset": instruction.address, "bytes": instruction.bytes.hex(),
                         "mnemonic": instruction.mnemonic, "operands": instruction.op_str}
                        for instruction in decoder.disasm(native, 0)]
        if sum(len(bytes.fromhex(item["bytes"])) for item in instructions) != len(native):
            raise RuntimeError("Native block inspection did not decode all bytes")
        (directory / f"{name}-native-inspection.json").write_text(json.dumps(instructions, indent=2) + "\n")
        manifests.append(manifest)
    return source, manifests


def elf64_symbols(path):
    data = path.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise RuntimeError("Expected little-endian ELF64 payload")
    table = struct.unpack_from("<Q", data, 40)[0]
    stride, count = struct.unpack_from("<HH", data, 58)
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, table + index * stride) for index in range(count)]
    symbols = {}
    for section in sections:
        if section[1] != 2:  # ELF SHT_SYMTAB
            continue
        strings_section = sections[section[6]]
        strings = data[strings_section[4]:strings_section[4] + strings_section[5]]
        for offset in range(section[4], section[4] + section[5], section[9]):
            name, _, _, _, value, _ = struct.unpack_from("<IBBHQQ", data, offset)
            label = strings[name:].split(b"\0", 1)[0].decode()
            if label:
                symbols[label] = value
    return symbols


def build_payload(directory, assembly):
    template = assembly.read_text()
    for name in ("loop", "trap"):
        path = str(directory / name / "native.bin")
        if any(character in path for character in ('"', "\n", "\\")):
            raise RuntimeError("Payload include path is not representable")
        template = template.replace(f"{name.upper()}_NATIVE_PATH", path)
    for name in ("a", "b"):
        template = template.replace(f"STATE_{name.upper()}_PATH", str(directory / f"state-{name}.bin"))
    definitions = (
        f".set GUEST_LOOP_PC, {GUEST_BASE}\n"
        f".set GUEST_TRAP_PC, {GUEST_BASE + LOOP_WORDS * 4}\n"
        f".set GUEST_FAULT_PC, {GUEST_BASE + PAGE_FAULT_WORD_INDEX * 4}\n"
    )
    source = directory / "payload.S"
    source.write_text(definitions + template)
    clang = shutil.which("clang") or "/usr/bin/clang"
    subprocess.run([clang, "--target=x86_64-unknown-none-elf", "-c", str(source), "-o", str(directory / "payload.o")], check=True)
    candidates = list((ROOT / ".tools/rust/rustup/toolchains").glob("*/lib/rustlib/*/bin/rust-lld"))
    linker = shutil.which("ld.lld") or (str(candidates[0]) if candidates else None)
    if linker is None:
        raise RuntimeError("LLVM linker is unavailable")
    base = [linker, "-flavor", "gnu"] if Path(linker).name == "rust-lld" else [linker]
    environment = os.environ.copy()
    if Path(linker).name == "rust-lld" and os.uname().sysname == "Darwin":
        environment["DYLD_LIBRARY_PATH"] = str(Path(linker).resolve().parents[3])
    arguments = ["-m", "elf_x86_64", "--image-base", "0", "-Ttext", hex(NATIVE_BASE), "-e", "_start", str(directory / "payload.o")]
    elf = directory / "payload.elf"
    native = directory / "payload.bin"
    subprocess.run([*base, *arguments, "-o", str(elf)], check=True, env=environment)
    subprocess.run([*base, *arguments, "--oformat", "binary", "-o", str(native)], check=True, env=environment)
    return native, elf64_symbols(elf)


def source_pc(native_rip, symbols, manifest):
    offset = native_rip - symbols["loop_native"]
    if not 0 <= offset < manifest["native_bytes"]:
        raise RuntimeError("Observed native instruction is outside translated work")
    mapping = manifest["source_map"]
    matches = [int(pc) for pc, native_offset in mapping if int(native_offset) <= offset]
    if not matches:
        raise RuntimeError("Observed native instruction has no source mapping")
    return matches[-1], offset


def inspect_memory(monitor, directory):
    dump = directory / "physical-ram.bin"
    monitor.execute("pmemsave", {"val": STATE_A, "size": FAULT_RAM + 72 - STATE_A, "filename": str(dump)})
    data = dump.read_bytes()

    def region(address, length):
        return data[address - STATE_A:address - STATE_A + length]

    def u64(address):
        return struct.unpack("<Q", region(address, 8))[0]

    return region, u64


def verify(monitor, directory, manifests, symbols):
    region, u64 = inspect_memory(monitor, directory)
    trace = struct.unpack("<15Q", region(TRACE, 120))
    dispatches, done_a, done_b, faults, address, error, rip, irq_rip, _, _, declared_pc, before_x3, _, _, all_irqs = trace
    fault_pc, fault_offset = source_pc(rip, symbols, manifests[0])
    irq_pc, irq_offset = source_pc(irq_rip, symbols, manifests[0])
    expected_fault_pc = GUEST_BASE + PAGE_FAULT_WORD_INDEX * 4
    if (done_a, done_b, faults, address, error, fault_pc, declared_pc, before_x3) != (
        1, 1, 1, FAULT_ADDRESS, 0, expected_fault_pc, expected_fault_pc, INITIAL_X3
    ):
        raise RuntimeError(f"Unexpected task/fault observations: {trace}")
    ticks = u64(TIMER_TICKS)
    if not MINIMUM_NATIVE_IRQS <= ticks <= all_irqs or dispatches < 4:
        raise RuntimeError("PIT did not interrupt translated work enough times")
    if trace[12:14] != (GUEST_BASE + LOOP_WORDS * 4,) * 2:
        raise RuntimeError("Task completion did not retain both BRK guest PCs")
    states = []
    for task, (state_address, task_address) in enumerate(zip((STATE_A, STATE_B), TASK_DATA)):
        state = region(state_address, STATE_BYTES)
        registers = list(struct.unpack("<32Q", state[:256]))
        count, stored_result = struct.unpack("<QQ", region(task_address, 16))
        expected = bytearray(initial_state(task))
        for index, value in enumerate((task_address, count, FAULT_ADDRESS, 7, registers[4])):
            struct.pack_into("<Q", expected, index * 8, value)
        expected_nzcv = 0x60000000 if registers[4] == MINIMUM_NATIVE_IRQS else 0x20000000
        struct.pack_into("<I", expected, NZCV_OFFSET, expected_nzcv)
        if state != expected or count == 0 or stored_result != 7 or not MINIMUM_NATIVE_IRQS <= registers[4] <= ticks:
            raise RuntimeError("Translated task complete architectural/RAM state differs")
        states.append({"address": state_address, "sha256": sha256(state), "iterations": count,
                       "registers": registers, "nzcv": expected_nzcv, "stored_result": stored_result})
    fault_state = region(FAULT_STATE, STATE_BYTES)
    expected_fault = bytearray(initial_state(0))
    for index, value in enumerate((TASK_DATA[0], 1, FAULT_ADDRESS)):
        struct.pack_into("<Q", expected_fault, index * 8, value)
    if fault_state != expected_fault:
        raise RuntimeError("Fault snapshot does not retain exact reached guest prefix")
    fault_ram = struct.unpack("<9Q", region(FAULT_RAM, 72))
    if fault_ram[:8] != (1, 0, 0, 0, 0, 0, 0, 0) or fault_ram[8] > ticks:
        raise RuntimeError("Fault snapshot RAM prefix differs")
    return {"dispatches": dispatches, "tasks": states, "fault": {
        "count": faults, "address": address, "error": error, "native_rip": rip,
        "native_offset": fault_offset, "source_pc": fault_pc,
        "snapshot_sha256": sha256(fault_state), "destination_before": before_x3,
        "ticks_at_fault": fault_ram[8],
        "retry": "unchanged native RIP; #PF handler installs identity page then IRETQ",
    }, "pit": {"total_interrupts": all_irqs, "translated_interrupts": ticks,
                 "native_rip": irq_rip, "native_offset": irq_offset, "source_pc": irq_pc}}


def run(stela, directory, assembly, qmp_port, gdb_port):
    owned_sources = (Path(__file__), assembly, ROOT / "dev/vm.py", ROOT / "dev/vm/boot.S")
    source_hashes = {str(path.relative_to(ROOT)): sha256(path.read_bytes()) for path in owned_sources}
    cli_sha256 = sha256(stela.read_bytes())
    source, manifests = compile_tasks(stela, directory)
    native, symbols = build_payload(directory, assembly)
    vm.STATE = directory / "vm"
    vm.QMP_PORT, vm.GDB_PORT = qmp_port, gdb_port
    args = vm.command(paused=True, native=native)
    for port in (qmp_port, gdb_port):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))
    (vm.STATE / "debug.log").write_text("")
    monitor = None
    with (directory / "qemu.stderr").open("w") as log:
        process = subprocess.Popen(args, stdout=log, stderr=log)
        launch = {"pid": process.pid, "started_unix_ns": time.time_ns(), "command": args}
        (directory / "launch.json").write_text(json.dumps(launch, indent=2) + "\n")
        print(json.dumps({"qemu_pid": process.pid, "output_dir": str(directory)}), flush=True)
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("QEMU exited before monitor connection")
                try:
                    monitor = vm.Monitor()
                    break
                except OSError:
                    time.sleep(0.05)
            if monitor is None:
                raise RuntimeError("QMP did not start")
            with socket.create_connection(("127.0.0.1", gdb_port), timeout=5) as debug:
                debug.sendall(b"$?#3f")
                reply = b""
                while b"#" not in reply:
                    chunk = debug.recv(4096)
                    if not chunk:
                        raise RuntimeError("GDB stub disconnected")
                    reply += chunk
                if b"$T" not in reply and b"$S" not in reply:
                    raise RuntimeError("GDB stub did not report stopped CPU")
                debug.sendall(b"+")
            monitor.execute("cont")
            while time.monotonic() < deadline:
                output = (vm.STATE / "debug.log").read_text()
                if "OK\n" in output or "E" in output:
                    break
                if process.poll() is not None:
                    raise RuntimeError("QEMU stopped while executing fixture")
                time.sleep(0.01)
            monitor.execute("stop")
            registers = monitor.human("info registers")
            (directory / "registers.txt").write_text(registers)
            inspect_memory(monitor, directory)
            if "OK\n" not in (vm.STATE / "debug.log").read_text():
                raise RuntimeError("Translated system fixture did not complete")
            match = re.search(r"RIP=([0-9a-fA-F]+)", registers)
            if match is None or not symbols["completed"] <= int(match.group(1), 16) < symbols["completed"] + 3:
                raise RuntimeError("Stopped native RIP is outside the completion halt loop")
            observations = verify(monitor, directory, manifests, symbols)
            if source_hashes != {str(path.relative_to(ROOT)): sha256(path.read_bytes()) for path in owned_sources} or cli_sha256 != sha256(stela.read_bytes()):
                raise RuntimeError("Sources or frozen compiler changed during execution")
            report = {
                "schema_version": 1, "kind": "translated_x86_platform_boundaries", "passed": True,
                "original_arm_sha256": sha256(source),
                "original_inspection_sha256": sha256((directory / "original-inspection.json").read_bytes()), "stela_sha256": cli_sha256,
                "compiler_source_sha256": manifests[0]["compiler_source_sha256"],
                "native_payload_sha256": sha256(native.read_bytes()), "block_manifests": manifests,
                "native_inspection_sha256": {name: sha256((directory / f"{name}-native-inspection.json").read_bytes()) for name in ("loop", "trap")},
                "boot_image_sha256": sha256((vm.STATE / "boot.img").read_bytes()),
                "boot_elf_sha256": sha256((vm.STATE / "boot.elf").read_bytes()),
                "source_sha256": source_hashes,
                "initial_state_sha256": [sha256(initial_state(task)) for task in (0, 1)],
                "qemu_sha256": sha256(Path(vm.qemu_binary()).read_bytes()),
                "symbols": {key: symbols[key] for key in ("_start", "page_fault", "timer_irq", "loop_native", "loop_native_end", "trap_native", "completed")},
                "qemu": subprocess.check_output([vm.qemu_binary(), "--version"], text=True).splitlines()[0],
                "qemu_command": args, "gdb_stub": "initial stopped-state handshake passed",
                "observations": observations,
                "limits": ["Host x86 page-fault retry and PIT IRQ; no ARM architectural exception delivery",
                           "Fixed identity direct-RAM profile; no ARM MMU, TLB or device emulation",
                           "Two serialized guest states, not ARM preemptive task scheduling",
                           "AOT block execution only; runtime compilation/cache not linked in freestanding image",
                           "No macOS boot or application acceptance; QEMU TCG timing is not native performance"],
            }
            monitor.execute("quit")
            process.wait(timeout=5)
            report["process"] = {**launch, "returncode": process.returncode, "finished_unix_ns": time.time_ns()}
            if process.returncode != 0:
                raise RuntimeError("QEMU did not exit cleanly after successful observations")
            write_evidence(directory / "receipt.json", report)
            return report
        finally:
            if monitor:
                monitor.close()
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            launch.update({"returncode": process.returncode, "finished_unix_ns": time.time_ns()})
            (directory / "launch.json").write_text(json.dumps(launch, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stela", type=Path, required=True, help="Existing frozen Stela compiler executable")
    parser.add_argument("--output-dir", type=Path, required=True, help="Fresh ignored evidence directory")
    parser.add_argument("--qmp-port", type=int, default=4447)
    parser.add_argument("--gdb-port", type=int, default=1237)
    arguments = parser.parse_args()
    directory = arguments.output_dir.resolve()
    ignored_root = (ROOT / ".stela").resolve()
    if not directory.is_relative_to(ignored_root):
        parser.error("output directory must be under ignored .stela/")
    if not all(1 <= port <= 65535 for port in (arguments.qmp_port, arguments.gdb_port)) or arguments.qmp_port == arguments.gdb_port:
        parser.error("QMP/GDB ports must be distinct and in 1..65535")
    directory.mkdir(parents=True, exist_ok=False)
    assembly = ROOT / "dev/vm/x86_64_boot.S"
    report = run(arguments.stela.resolve(), directory, assembly, arguments.qmp_port, arguments.gdb_port)
    print(json.dumps({"passed": report["passed"], "receipt": str(directory / "receipt.json"),
                      "observations": report["observations"]}, indent=2))


if __name__ == "__main__":
    main()
