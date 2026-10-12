#!/usr/bin/env python3
"""Run pinned Rosetta code generation and compare its output on our own x86 fixtures.

The Apple compiler runs only inside ARM Unicorn with explicit host-call models.
Generated runtime helpers are mapped to traps, never successful substitutes.
Only reviewed register-only SysV fixtures execute as native host x86 code.
"""
import ctypes
from collections import Counter
import hashlib
import json
import multiprocessing
from pathlib import Path
import random
import struct
import subprocess
import tempfile

from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM64, CS_MODE_64, CS_MODE_ARM, CS_OP_MEM, CS_OP_IMM
from unicorn import Uc, UC_ARCH_ARM64, UC_ARCH_X86, UC_MODE_ARM, UC_MODE_64, UC_HOOK_CODE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn import arm64_const as arm, x86_const as intel
from differential import ROOT, executable
from evidence import write_evidence
from rosetta_execution import Harness, P, PINNED_SHA256

ARM_CODE = 0x60000000
RUNTIME = 0x60010000
ARM_STOP = 0x61000000
X86_CODE = 0x100000000
X86_STOP = 0x40000000
RAM = 0x80000000
RAM_SIZE = 0x10000
GPRS = ("RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")
X86_REGS = [getattr(intel, "UC_X86_REG_" + name) for name in GPRS]
ARM_REGS = [getattr(arm, "UC_ARM64_REG_X" + str(index)) for index in range(16)]
CODEGEN_CONTEXT = {
    "schema_version": 1,
    "library_sha256": PINNED_SHA256,
    "code_base": ARM_CODE,
    "runtime_base": RUNTIME,
    "runtime_offset_stride": 16,
    "guest_image_base": X86_CODE,
    "ir_flags": 0,
    "entry_offsets": [0],
    "data_in_code_entries": [],
    "invocation_profile": "synthetic-register-only-leaf-v1",
}


def artifact_identity(source):
    identity = dict(CODEGEN_CONTEXT, source_sha256=hashlib.sha256(source).hexdigest())
    key = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return key, identity


def requires_reserved_nzcv_bits(generated):
    """Recognize the observed adjacent MRS/UBFX Apple flag-assist sequence."""
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    decoder.detail = True
    instructions = list(decoder.disasm(generated, ARM_CODE))
    for first, second in zip(instructions, instructions[1:]):
        if first.mnemonic != "mrs" or not first.op_str.endswith(", nzcv") or second.mnemonic != "ubfx":
            continue
        operands = second.operands
        if len(operands) != 4 or operands[2].imm not in (26, 27) or operands[3].imm != 1:
            continue
        # MRS writes Xn; UBFX can consume its Wn view.
        written = first.reg_name(first.operands[0].reg).lstrip("xw")
        consumed = second.reg_name(operands[1].reg).lstrip("xw")
        if written == consumed:
            return True
    return False


def reviewed_source(code):
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(code, 0))
    if not instructions or sum(i.size for i in instructions) != len(code) or instructions[-1].mnemonic != "ret":
        raise ValueError("Expected complete fixture ending in RET")
    allowed = {"mov", "movabs", "xor", "add", "adc", "shl", "inc", "test", "cmp", "je", "jb", "setb", "setl", "seto", "setp", "ret"}
    callee_saved = {"rbx", "ebx", "bx", "bl", "bh", "rsp", "esp", "sp", "spl", "rbp", "ebp", "bp", "bpl"}
    callee_saved.update(f"r{index}{suffix}" for index in range(12, 16) for suffix in ("", "d", "w", "b"))
    addresses = {i.address for i in instructions}
    for instruction in instructions:
        if instruction.mnemonic not in allowed or any(op.type == CS_OP_MEM for op in instruction.operands):
            raise ValueError("Unreviewed fixture instruction")
        if instruction.mnemonic == "ret":
            if instruction.operands:
                raise ValueError("Only plain RET is allowed")
            continue
        _, written = instruction.regs_access()
        if any(instruction.reg_name(reg) in callee_saved for reg in written):
            raise ValueError("Fixture violates native SysV callee-save/stack rules")
        if instruction.mnemonic.startswith("j"):
            if len(instruction.operands) != 1 or instruction.operands[0].type != CS_OP_IMM or instruction.operands[0].imm not in addresses:
                raise ValueError("Fixture branch leaves reviewed source")
    return instructions


def native_worker(pipe, code, arguments):
    try:
        with executable(code) as address:
            function = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64)(address)
            pipe.send([function(first, second) for first, second in arguments])
    except BaseException as error:
        pipe.send({"error": repr(error)})
    finally:
        pipe.close()


def native_results(code, arguments):
    reviewed_source(code)
    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=native_worker, args=(send, code, arguments))
    process.start()
    send.close()
    try:
        if not receive.poll(10):
            raise AssertionError("Native source fixture timed out")
        results = receive.recv()
        process.join(timeout=2)
        if process.exitcode != 0 or isinstance(results, dict):
            raise AssertionError(f"Native fixture failed: {results}, exit={process.exitcode}")
        return results
    finally:
        if process.is_alive():
            process.kill()
        process.join()
        receive.close()


def execute(source, generated, registers):
    memory = bytearray(RAM_SIZE)
    struct.pack_into("<Q", memory, 0x4000, X86_STOP)
    struct.pack_into("<QQ", memory, 0x8000, X86_STOP, ARM_STOP)
    original = Uc(UC_ARCH_X86, UC_MODE_64)
    original.mem_map(X86_CODE, 0x10000)
    original.mem_write(X86_CODE, source)
    original.mem_map(RAM, RAM_SIZE)
    original.mem_write(RAM, bytes(memory))
    for register, value in zip(X86_REGS, registers):
        original.reg_write(register, value)
    original.emu_start(X86_CODE, X86_STOP, timeout=1_000_000, count=10000)
    if original.reg_read(intel.UC_X86_REG_RIP) != X86_STOP:
        raise AssertionError("Original x86 did not return within budget")
    translated = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    translated.ctl_set_cpu_model(arm.UC_CPU_ARM64_MAX)  # FlagM/CFINV are used by this build.
    translated.mem_map(ARM_CODE, 0x10000)
    translated.mem_write(ARM_CODE, generated)
    translated.mem_protect(ARM_CODE, 0x10000, UC_PROT_READ | UC_PROT_EXEC)
    translated.mem_map(RUNTIME, 0x10000)
    translated.mem_write(RUNTIME, bytes.fromhex("000020d4") * (0x10000 // 4))
    translated.mem_protect(RUNTIME, 0x10000, UC_PROT_READ | UC_PROT_EXEC)
    translated.mem_map(RAM, RAM_SIZE, UC_PROT_READ | UC_PROT_WRITE)
    translated.mem_write(RAM, bytes(memory))
    for register, value in zip(ARM_REGS, registers):
        translated.reg_write(register, value)
    translated.reg_write(arm.UC_ARM64_REG_X21, RAM + 0x8000)
    def no_helper(machine, pc, size, _):
        raise AssertionError(f"Generated code entered unimplemented runtime helper at {pc:#x}")
    translated.hook_add(UC_HOOK_CODE, no_helper, begin=RUNTIME, end=RUNTIME + 0xffff)
    translated.emu_start(ARM_CODE, ARM_STOP, timeout=1_000_000, count=10000)
    if translated.reg_read(arm.UC_ARM64_REG_PC) != ARM_STOP:
        raise AssertionError("Generated ARM did not return within budget")
    expected = [original.reg_read(register) for register in X86_REGS]
    actual = [translated.reg_read(register) for register in ARM_REGS]
    if expected[1:] != actual[1:] or bytes(original.mem_read(RAM, RAM_SIZE)) != bytes(translated.mem_read(RAM, RAM_SIZE)):
        raise AssertionError(json.dumps({"expected": expected, "actual": actual}))
    if translated.reg_read(arm.UC_ARM64_REG_X21) != RAM + 0x8010:
        raise AssertionError("Unexpected Rosetta return-stack consumption")
    return actual[0], expected[0]


def main():
    subprocess.run([str(ROOT / "dev/cargo"), "build", "--locked", "-p", "stela-cli"], check=True)
    cli = ROOT / "target/debug/stela"
    assembly = ROOT / "tests/fixtures/rosetta-x86.S"
    reports = []
    randomizer = random.Random(0x50e77a)
    with tempfile.TemporaryDirectory(prefix="stela-rosetta-codegen-") as temporary:
        object_path = Path(temporary) / "fixtures.o"
        subprocess.run(["clang", "--target=x86_64-apple-macos", "-c", str(assembly), "-o", str(object_path)], check=True)
        row = json.loads(subprocess.check_output([str(cli), "binary-text", str(object_path)]))[0]["slice"]
        section = row["sections"][0]
        text = bytes.fromhex(section["data_hex"])
        entries = sorted((address, name) for name, address in row["defined_text_symbols"].items() if name.startswith("_rosetta_"))
        for index, (address, name) in enumerate(entries):
            end = entries[index + 1][0] if index + 1 < len(entries) else section["guest_address"] + len(text)
            source = text[address - section["guest_address"]:end - section["guest_address"]]
            reviewed_source(source)
            harness = Harness()
            generated, routine_names = harness.translate(source, RUNTIME, ARM_CODE)
            if harness.mappings:
                raise AssertionError("Rosetta left an anonymous compiler arena mapped after cleanup")
            arguments = [(0, 0), (1, 2), ((1 << 64) - 1, 1), (0x8000000000000000, 0x7fffffffffffffff),
                         (0xffffffff, 0x100000000), (0x80000000, 0x7fffffff), (0x55, 0xaa), (0x80, 0x7f)]
            if name.endswith("sum_loop"):
                arguments = [(number, 0) for number in (0, 1, 2, 3, 7, 8, 15, 16)]
            host_results = native_results(source, arguments)
            requires_reserved_nzcv = requires_reserved_nzcv_bits(generated)
            mismatches = []
            for (first, second), expected in zip(arguments, host_results):
                registers = [randomizer.getrandbits(64) for _ in range(16)]
                registers[4], registers[7], registers[6] = RAM + 0x4000, first, second
                actual, reference_result = execute(source, generated, registers)
                if reference_result != expected:
                    raise AssertionError(f"Original x86 oracle/hardware mismatch for {name}")
                if actual != expected:
                    if not requires_reserved_nzcv:
                        raise AssertionError(f"Rosetta/original hardware mismatch for {name}")
                    mismatches.append({"first_argument": first, "second_argument": second, "original_result": expected, "generic_arm_result": actual})
            if requires_reserved_nzcv and not mismatches:
                raise AssertionError("Expected missing CPU-assist evidence was not observed")
            key, identity = artifact_identity(source)
            destination = ROOT / ".stela/rosetta/26A434/codegen" / key
            destination.mkdir(parents=True, exist_ok=True)
            native_path = destination / "arm64.bin"
            if native_path.exists() and native_path.read_bytes() != generated:
                raise AssertionError("Same input/library generated different output")
            if not native_path.exists():
                with native_path.open("xb") as output:
                    output.write(generated)
            artifact_manifest = {"identity": identity, "generated_sha256": hashlib.sha256(generated).hexdigest(),
                                 "generated_bytes": len(generated), "behavior_verified": not requires_reserved_nzcv}
            manifest_path = destination / "manifest.json"
            manifest_bytes = (json.dumps(artifact_manifest, sort_keys=True, indent=2) + "\n").encode()
            if manifest_path.exists() and manifest_path.read_bytes() != manifest_bytes:
                raise AssertionError("Existing generated artifact manifest differs")
            if not manifest_path.exists():
                with manifest_path.open("xb") as output:
                    output.write(manifest_bytes)
            decoded = list(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm_lite(generated, ARM_CODE))
            reports.append({"fixture": name, "source_sha256": hashlib.sha256(source).hexdigest(), "source_bytes": len(source),
                            "generated_sha256": hashlib.sha256(generated).hexdigest(), "generated_bytes": len(generated),
                            "generated_artifact": str(native_path), "generated_assembly": [[pc, mnemonic, operands] for pc, _, mnemonic, operands in decoded],
                            "comparisons": len(arguments), "verified": not requires_reserved_nzcv,
                            "execution_status": "unsupported_reserved_nzcv_cpu_assist" if requires_reserved_nzcv else "matched", "observed_mismatches": mismatches, "return_stack_miss_routine_index": routine_names.index("return_stack_miss"),
                            "artifact_identity": identity, "library_fixups": harness.fixup_counts, "host_calls": dict(Counter(event[0] for event in harness.events))})
    report = {"kind": "original_rosetta_codegen_and_behavior", "code_generation_completed": True, "behavior_verification": "partial", "build": "26A434", "binary_sha256": PINNED_SHA256,
              "assembly_sha256": hashlib.sha256(assembly.read_bytes()).hexdigest(), "fixtures": len(reports),
              "verified_fixtures": sum(row["verified"] for row in reports), "unsupported_cpu_fixtures": sum(not row["verified"] for row in reports),
              "verified_register_and_memory_comparisons": sum(row["comparisons"] for row in reports if row["verified"]),
              "unsupported_cpu_comparisons": sum(row["comparisons"] for row in reports if not row["verified"]), "results": reports,
              "research_sources_sha256": {name: hashlib.sha256((ROOT / "dev" / name).read_bytes()).hexdigest() for name in ("rosetta-codegen-probe.py", "rosetta_execution.py", "differential.py")},
              "execution_paths": ["original x86 on native host (result)", "original x86 in Unicorn (16 GPRs/RAM)", "Rosetta-produced ARM in Unicorn MAX (16 mapped GPRs/RAM)"],
              "limits": "Own register-only SysV leaf fixtures, fixed synthetic IR invocation and matching Rosetta return-stack entries. Runtime helpers are traps and are never entered in passing cases. No full EFLAGS/SIMD comparison, Apple-silicon hardware, general Mach-O launch, JIT invalidation, syscall emulation or macOS boot."}
    write_evidence(ROOT / ".stela/rosetta/26A434/codegen-report.json", report)
    print(json.dumps({key: value for key, value in report.items() if key not in ("results", "research_sources_sha256")}, indent=2))


if __name__ == "__main__":
    main()
