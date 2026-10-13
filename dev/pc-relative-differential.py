#!/usr/bin/env python3
"""Compare PC-relative addresses and literal loads with native output and math.

Wrapping-address cases use only native output and mathematical expectations;
Unicorn is deliberately not presented as evidence for unmappable guest PCs.
"""
import argparse
import ctypes
import hashlib
import json
import importlib.util
import mmap
import random
import signal
import multiprocessing
from pathlib import Path
import struct
import subprocess
import tempfile
import time

from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_ARM, CS_MODE_64
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_READ
from unicorn import arm64_const as arm
from differential import capture_arm, initialize_arm, state_dict as complete_state
from differential import ROOT, MASK, ARM_REGISTERS, State, executable, states, arithmetic, parse_fault_record, move
from evidence import write_evidence, retain_native_evidence

RET = 0xd65f03c0
NOP = 0xd503201f
LITERAL_IMMEDIATE_BITS = 19
LITERAL_IMMEDIATE_SCALE = 4
LITERAL_RAM_BYTES = 0x400000
LITERAL_MAPPING_BASE = 0x30000000000
LITERAL_FORMS = {
    "w": (0x18000000, 4), "x": (0x58000000, 8), "ldrsw": (0x98000000, 4),
    "s": (0x1c000000, 4), "d": (0x5c000000, 8), "q": (0x9c000000, 16),
}


class BlockExit(ctypes.Structure):
    _fields_ = [('next_pc', ctypes.c_uint64), ('kind', ctypes.c_uint64)]


def encoding(page, immediate, destination):
    if not -(1 << 20) <= immediate < (1 << 20) or not 0 <= destination < 32:
        raise ValueError('ADR/ADRP immediate or destination out of bounds')
    value = immediate % (1 << 21)
    return (0x90000000 if page else 0x10000000) | ((value % 4) << 29) | ((value // 4) << 5) | destination


def make_case(page, immediate, destination, base=0x100ff8, prefix=1, chain=False, wrap=False):
    operations = [('nop',)] * prefix + [('address', page, immediate, destination)]
    if chain:
        # Consume the freshly formed address as a register operand, then replace
        # it from a later instruction PC. This catches stale-PC reuse.
        operations.extend([('add', 8, destination, 7), ('address', not page, -1, destination)])
    words = []
    for operation in operations:
        if operation[0] == 'nop':
            words.append(NOP)
        elif operation[0] == 'address':
            _, mode, offset, register = operation
            words.append(encoding(mode, offset, register))
        else:
            _, register, source, immediate = operation
            words.append(arithmetic(0, 0, 1, register, source, immediate))
    words.append(RET)
    return {'base': base, 'words': words, 'operations': operations, 'wrapping_math_only': wrap}


def cases():
    result = []
    offsets = (-(1 << 20), -(1 << 20) + 1, -4096, -4, -3, -2, -1, 0, 1, 2, 3, 4095, (1 << 20) - 1)
    for page in (False, True):
        for offset in offsets:
            for destination in range(32):
                result.append(make_case(page, offset, destination))
            # Bases span both 4 KiB and 16 KiB page edges. Prefixes ensure
            # instruction PC differs from the region's base.
            for base, prefix in ((0x100ffc, 1), (0x101000, 0), (0x103ff8, 3), (0x104000, 2)):
                for destination in (0, 30, 31):
                    result.append(make_case(page, offset, destination, base, prefix))
        for base in (0x100ff8, 0x103ff8):
            for offset in (-1, 0, 1):
                result.append(make_case(page, offset, 7, base, 2, chain=True))
        # Source PCs remain representable and aligned; only computed data
        # addresses wrap. Full source ranges do not cross the 64-bit boundary.
        for base, offset in ((0, -(1 << 20)), (0, -1), (MASK - 15, (1 << 20) - 1), (MASK - 15, 1)):
            for destination in (0, 30, 31):
                result.append(make_case(page, offset, destination, base, 1, wrap=True))
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for case in result:
        source = struct.pack('<' + 'I' * len(case['words']), *case['words'])
        decoded = list(decoder.disasm(source, case['base']))
        if len(decoded) != len(case['words']) or any(instruction.mnemonic not in ('adr', 'adrp', 'nop', 'add', 'ret') for instruction in decoded):
            raise AssertionError(f'Independent decoder rejected {case}')
    return result



def literal_encoding(form, immediate, destination):
    limit = 1 << (LITERAL_IMMEDIATE_BITS - 1)
    if form not in LITERAL_FORMS or not -limit <= immediate < limit or not 0 <= destination < 32:
        raise ValueError("Literal operands outside architectural bounds")
    return LITERAL_FORMS[form][0] | ((immediate % (1 << LITERAL_IMMEDIATE_BITS)) << 5) | destination


def literal_cases():
    result = []
    limit = 1 << (LITERAL_IMMEDIATE_BITS - 1)
    offsets = (-limit, -limit + 1, -3, -1, 0, 1, 3, limit - 1)
    for form in LITERAL_FORMS:
        for immediate in offsets:
            destinations = (0, 30, 31) if immediate in (-1, 0, 1) else (0,)
            for destination in destinations:
                for placement, prefix in ((0x1ffffc, 1), (0x200000, 3)):
                    result.append({"form": form, "immediate": immediate, "destination": destination,
                                   "placement": placement, "prefix": prefix})
    return result


def literal_math(case, initial, ram_address, ram):
    result = snapshot(initial)
    width = LITERAL_FORMS[case["form"]][1]
    pc = case["base"] + case["prefix"] * 4
    position = ((pc + case["immediate"] * LITERAL_IMMEDIATE_SCALE) & MASK) - ram_address
    if not 0 <= position <= len(ram) - width:
        raise ValueError("Literal mathematical target outside supplied RAM")
    value = int.from_bytes(ram[position:position + width], "little")
    destination = case["destination"]
    if case["form"] in ("s", "d", "q"):
        result["v"][destination] = [value & MASK, value >> 64]
    elif destination != 31:
        if case["form"] == "ldrsw" and value & (1 << 31):
            value -= 1 << 32
        result["x"][destination] = value & MASK
    result["memory"] = bytes(ram)
    return result


def decode_accounting(source, native, manifest):
    instructions = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(native, 0))
    if sum(item.size for item in instructions) != len(native):
        raise AssertionError("Native literal output contains undecodable bytes")
    return {"source_sha256": hashlib.sha256(source).hexdigest(),
            "native_sha256": hashlib.sha256(native).hexdigest(), "native_bytes": len(native),
            "native_instructions": len(instructions), "source_map": manifest["source_map"],
            "instruction_intervals": [
                {"guest_pc": pc, "native_offset": start,
                 "native_bytes": (manifest["source_map"][index + 1][1] if index + 1 < len(manifest["source_map"]) else len(native)) - start,
                 "native_instructions": sum(start <= item.address < (manifest["source_map"][index + 1][1] if index + 1 < len(manifest["source_map"]) else len(native)) for item in instructions)}
                for index, (pc, start) in enumerate(manifest["source_map"])]}


def execute_literal_cases(cli):
    counts = {"programs": 0, "three_way_state_and_memory_comparisons": 0, "native_block_exit_checks": 0}
    compiler = None
    artifacts = []
    corpus = hashlib.sha256()
    seed_ram = random.Random(0x117e2a1).randbytes(LITERAL_RAM_BYTES)
    incoming = states(all_flags=True)
    incoming = [incoming[index] for index in (0, 10, 15)]
    for index, initial in enumerate(incoming):
        initial.sp = 0xfeed000000000003 + index * 16  # Literal accesses must not check SP alignment.
        initial.reserved = 0xa5c39e71
    with mmap.mmap(-1, LITERAL_RAM_BYTES, prot=mmap.PROT_READ | mmap.PROT_WRITE) as region, tempfile.TemporaryDirectory(prefix="stela-literal-") as temporary:
        marker = ctypes.c_char.from_buffer(region)
        ram_address = ctypes.addressof(marker)
        del marker
        directory = Path(temporary)
        for index, template in enumerate(literal_cases()):
            case = {**template, "base": ram_address + template["placement"]}
            words = [NOP] * case["prefix"] + [literal_encoding(case["form"], case["immediate"], case["destination"]), RET]
            source = struct.pack("<" + "I" * len(words), *words)
            decoded = list(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(source, case["base"]))
            if len(decoded) != len(words) or decoded[-2].mnemonic not in ("ldr", "ldrsw"):
                raise AssertionError("Independent ARM decoder declined literal fixture")
            corpus.update(source)
            corpus.update(struct.pack("<Q", case["base"]))
            ram = bytearray(seed_ram)
            ram[case["placement"]:case["placement"] + len(source)] = source
            machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            machine.mem_map(ram_address, LITERAL_RAM_BYTES)
            machine.mem_write(ram_address, bytes(ram))
            input_path = directory / "source.bin"
            input_path.write_bytes(source)
            modes = {}
            for mode in ("leaf", "block"):
                output = directory / f"{index}-{mode}"
                manifest = json.loads(subprocess.check_output([str(cli), f"compile-{mode}", str(input_path),
                                                              "--cpu-target", "baseline", "--guest-base", hex(case["base"]),
                                                              "--output-dir", str(output)]))
                if compiler is not None and compiler != manifest["compiler_source_sha256"]:
                    raise AssertionError("Compiler changed during literal suite")
                compiler = manifest["compiler_source_sha256"]
                if [row[0] for row in manifest["source_map"]] != [case["base"] + i * 4 for i in range(len(words))]:
                    raise AssertionError("Literal source map lost original instruction PCs")
                modes[mode] = (output / "native.bin").read_bytes()
                accounting = decode_accounting(source, modes[mode], manifest)
                artifacts.append({"mode": mode, "case": template, **accounting,
                                  "retained": retain_native_evidence("literal", source, modes[mode], manifest,
                                                                     accounting, Path(__file__).read_bytes())})
            counts["programs"] += 1
            with executable(modes["leaf"]) as leaf_address, executable(modes["block"]) as block_address:
                functions = (("leaf", ctypes.CFUNCTYPE(None, ctypes.POINTER(State))(leaf_address)),
                             ("block", ctypes.CFUNCTYPE(BlockExit, ctypes.POINTER(State))(block_address)))
                for initial in incoming:
                    expected = literal_math(case, initial, ram_address, ram)
                    initialize_arm(machine, initial)
                    end = case["base"] + (len(words) - 1) * 4
                    machine.emu_start(case["base"], end, count=len(words) - 1)
                    actual_arm = snapshot(capture_arm(machine, initial))
                    actual_arm["memory"] = bytes(machine.mem_read(ram_address, LITERAL_RAM_BYTES))
                    if actual_arm != expected or machine.reg_read(arm.UC_ARM64_REG_PC) != end:
                        raise AssertionError(f"Original literal execution differs from independent math: {template}")
                    for mode, function in functions:
                        region[:] = ram
                        actual = State.from_buffer_copy(initial)
                        returned = function(ctypes.byref(actual))
                        observed = snapshot(actual)
                        observed["memory"] = region[:]
                        if observed != expected:
                            raise AssertionError(f"Native {mode} literal state or RAM differs: {template}")
                        if mode == "block":
                            if returned.kind != 4 or returned.next_pc != expected["x"][30]:
                                raise AssertionError("Literal block RET exit differs")
                            counts["native_block_exit_checks"] += 1
                        counts["three_way_state_and_memory_comparisons"] += 1
    return {**counts, "compiler_source_sha256": compiler, "corpus_sha256": corpus.hexdigest(),
            "state_corpus_sha256": hashlib.sha256(b"".join(bytes(initial) for initial in incoming)).hexdigest(),
            "initial_ram_seed_sha256": hashlib.sha256(seed_ram).hexdigest(), "artifacts": artifacts}

def snapshot(state):
    return complete_state(state)


def mathematical_reference(case, initial):
    result = snapshot(initial)
    for index, operation in enumerate(case['operations']):
        pc = case['base'] + index * 4
        if operation[0] == 'address':
            _, page, immediate, destination = operation
            # Fixture metadata supplies the signed value; do not share the
            # compiler's bit extraction or sign-extension implementation.
            value = ((pc // 4096) * 4096 + immediate * 4096 if page else pc + immediate) % (1 << 64)
        elif operation[0] == 'add':
            _, destination, source, immediate = operation
            value = (result['x'][source] + immediate) % (1 << 64)
        else:
            continue
        if destination != 31:
            result['x'][destination] = value
    return result


def original_arm(machine, case, initial):
    initialize_arm(machine, initial)
    # Execute the actual address instructions, stopping before the harness-owned
    # RET. X30 is free to be an instruction destination and may be noncanonical.
    end = case['base'] + len(case['operations']) * 4
    machine.emu_start(case['base'], end, count=len(case['operations']))
    if machine.reg_read(arm.UC_ARM64_REG_PC) != end:
        raise AssertionError('ARM reference did not reach the expected leaf boundary')
    return complete_state(capture_arm(machine, initial))


def execute_cases(compiled):
    counts = {'programs': len(compiled), 'three_way_register_state_comparisons': 0,
              'wrapping_native_vs_math_comparisons': 0, 'native_block_exit_checks': 0}
    incoming = states(all_flags=True)
    for index, state in enumerate(incoming):
        # Distinct dirty upper halves and an unaligned SP prove neither ADR nor
        # discarded XZR destinations read or write SP or perform memory accesses.
        state.sp = 0xfeed000000000003 + index
        state.reserved = 0xa5c39e71
        for register in range(31):
            state.x[register] |= 0xdeadbeef00000000
    corpus = hashlib.sha256()
    for case in compiled:
        machine = None
        if not case['wrapping_math_only']:
            machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            start = case['base'] // 4096 * 4096
            machine.mem_map(start, 0x3000)
            machine.mem_write(case['base'], struct.pack('<' + 'I' * len(case['words']), *case['words']))
        with executable(case['leaf']) as leaf_address, executable(case['block']) as block_address:
            leaf = ctypes.CFUNCTYPE(None, ctypes.POINTER(State))(leaf_address)
            block = ctypes.CFUNCTYPE(BlockExit, ctypes.POINTER(State))(block_address)
            for initial in incoming:
                expected = mathematical_reference(case, initial)
                if machine is not None:
                    arm_state = original_arm(machine, case, initial)
                    if expected != arm_state:
                        raise AssertionError(json.dumps({'case': case['operations'], 'base': case['base'], 'math': expected, 'arm': arm_state}))
                for mode, function in (('leaf', leaf), ('block', block)):
                    state = State.from_buffer_copy(initial)
                    returned = function(ctypes.byref(state))
                    if snapshot(state) != expected:
                        raise AssertionError(json.dumps({'mode': mode, 'case': case['operations'], 'base': case['base'], 'expected': expected, 'native': snapshot(state)}))
                    if mode == 'block':
                        if returned.kind != 4 or returned.next_pc != expected['x'][30]:
                            raise AssertionError('Block RET exit differs from independently computed X30')
                        counts['native_block_exit_checks'] += 1
                    key = 'wrapping_native_vs_math_comparisons' if machine is None else 'three_way_register_state_comparisons'
                    counts[key] += 1
                corpus.update(struct.pack('<Q', case['base']))
                corpus.update(bytes(initial))
    return {**counts, 'state_corpus_sha256': corpus.hexdigest()}


def worker(pipe, compiled):
    try:
        pipe.send(execute_literal_cases(compiled["cli"]) if isinstance(compiled, dict) else execute_cases(compiled))
    except BaseException as error:
        pipe.send({'error': repr(error)})
    finally:
        pipe.close()


def bounded_cases(compiled):
    context = multiprocessing.get_context('spawn')
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=worker, args=(send, compiled))
    process.start()
    send.close()
    try:
        deadline = time.monotonic() + 300
        while not receive.poll(1):
            if process.exitcode is not None or time.monotonic() >= deadline:
                raise AssertionError(f'PC-relative worker failed/timed out: {process.exitcode}')
        result = receive.recv()
        process.join(timeout=2)
        if process.exitcode != 0 or 'error' in result:
            raise AssertionError(f'PC-relative suite failed: {result}, exit={process.exitcode}')
        return result
    finally:
        if process.is_alive():
            process.kill()
        process.join()
        receive.close()



def literal_faults(cli, compiler):
    spec = importlib.util.spec_from_file_location("memory_faults", ROOT / "dev/memory-faults.py")
    memory_faults = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(memory_faults)
    reports = []
    with tempfile.TemporaryDirectory(prefix="stela-literal-faults-") as temporary:
        directory = Path(temporary)
        observer = directory / "observer"
        observer_source = ROOT / "dev/native-memory-faults.c"
        subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", str(observer_source), "-o", str(observer)], check=True)
        page_size = mmap.PAGESIZE
        for form, (_, width) in LITERAL_FORMS.items():
            for protection in ("guard", "readonly", "crossing"):
                if protection == "crossing" and width <= 4:
                    continue  # Literal addresses are four-aligned, so a four-byte load cannot straddle a page.
                for destination in (0, 31):
                    base = LITERAL_MAPPING_BASE - 0x10000
                    ram_address = LITERAL_MAPPING_BASE + page_size
                    target = ram_address + (512 if protection == "readonly" else page_size)
                    if protection == "crossing":
                        target -= 4
                    immediate = (target - (base + 4)) // LITERAL_IMMEDIATE_SCALE
                    words = (move(2, 1, 7, 99), literal_encoding(form, immediate, destination), RET)
                    source = struct.pack("<III", *words)
                    input_path = directory / "source.bin"
                    input_path.write_bytes(source)
                    output = directory / str(len(reports))
                    manifest = json.loads(subprocess.check_output([str(cli), "compile-leaf", str(input_path),
                                                                  "--guest-base", hex(base), "--cpu-target", "baseline", "--output-dir", str(output)]))
                    if manifest["compiler_source_sha256"] != compiler:
                        raise AssertionError("Compiler changed during literal faults")
                    data = subprocess.check_output([str(observer), str(output / "native.bin"), protection,
                                                    "0", "0", "--mapping-base", hex(LITERAL_MAPPING_BASE)], timeout=10)
                    (code_address, actual_ram, actual_page), initial, (number, pc, address), final, ram = parse_fault_record(data)
                    if (actual_ram, actual_page) != (ram_address, page_size):
                        raise AssertionError("Observer refused exact isolated RAM placement")
                    if protection == "readonly":
                        machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
                        machine.mem_map(base, 0x10000)
                        machine.mem_write(base, source)
                        machine.mem_map(ram_address, page_size)
                        machine.mem_write(ram_address, b"\xa5" * page_size)
                        machine.mem_protect(ram_address, page_size, UC_PROT_READ)
                        initialize_arm(machine, initial)
                        machine.emu_start(base, base + 8, count=2)
                        expected = capture_arm(machine, initial)
                        expected_ram = bytes(machine.mem_read(ram_address, page_size))
                        faults = None
                        mapped_pc = None
                        if number != 0:
                            raise AssertionError("Literal read-only page load faulted")
                    else:
                        expected, expected_ram, faults = memory_faults.arm_fault(source, initial, ram_address, page_size, False, guest_base=base)
                        mapped_pc = max((guest_pc for guest_pc, offset in manifest["source_map"] if offset <= pc - code_address), default=None)
                        if number not in (signal.SIGBUS, signal.SIGSEGV) or mapped_pc != base + 4 or any(fault["pc"] != base + 4 for fault in faults):
                            raise AssertionError("Literal native/original fault PC differs")
                        if address != target + (4 if protection == "crossing" else 0):
                            raise AssertionError("Literal native fault address differs")
                    if bytes(expected) != bytes(final) or expected_ram != ram:
                        raise AssertionError("Literal access changed incorrect state or RAM")
                    reports.append({"form": form, "destination": destination, "protection": protection,
                                    "source_sha256": hashlib.sha256(source).hexdigest(), "native_sha256": manifest["native_sha256"],
                                    "native_signal": number, "guest_fault_pc": mapped_pc,
                                    "native_fault_offset": pc - code_address if number else None, "arm_faults": faults,
                                    "retained": retain_native_evidence("literal-fault", source,
                                        (output / "native.bin").read_bytes(), manifest,
                                        {"guest_fault_pc": mapped_pc, "native_signal": number,
                                         "native_fault_offset": pc - code_address if number else None}, Path(__file__).read_bytes())})
        return {"cases": len(reports), "results": reports,
                "observer_source_sha256": hashlib.sha256(observer_source.read_bytes()).hexdigest(),
                "observer_executable_sha256": hashlib.sha256(observer.read_bytes()).hexdigest(),
                "shared_fault_harness_sha256": hashlib.sha256((ROOT / "dev/memory-faults.py").read_bytes()).hexdigest()}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true', help='Use the already built CLI')
    parser.add_argument('--focus', choices=('address', 'literal'), default='address')
    parser.add_argument('--faults', action='store_true', help='Also run focused literal fault boundaries')
    arguments = parser.parse_args()
    if arguments.faults and arguments.focus != "literal":
        parser.error("--faults requires --focus literal")
    if not arguments.no_build:
        subprocess.run([str(ROOT / 'dev/cargo'), 'build', '--locked', '-p', 'stela-cli'], check=True)
    cli = ROOT / 'target/debug/stela'
    executable_hash = hashlib.sha256(cli.read_bytes()).hexdigest()
    if arguments.focus == "literal":
        result = bounded_cases({"cli": str(cli)})
        faults = literal_faults(cli, result["compiler_source_sha256"]) if arguments.faults else None
        if executable_hash != hashlib.sha256(cli.read_bytes()).hexdigest():
            raise AssertionError("Compiler executable changed during literal suite")
        report = {"kind": "literal_arm_math_native_x86", "passed": True, **result,
                  "faults": faults, "compiler_executable_sha256": executable_hash,
                  "harness_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  "shared_runner_sha256": hashlib.sha256((ROOT / "dev/differential.py").read_bytes()).hexdigest(),
                  "shared_sources_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                  for name in ("dev/evidence.py", "dev/differential.py", "dev/memory-faults.py", "dev/native-memory-faults.c")},
                  "tested_state": "All 784 GuestState bytes, all 4MiB RAM, native leaf/block return, original per-instruction PC, six load forms, Rt31/XZR and V31, dirty upper vector/GPR bits, signed imm19 extrema and 4/8/16-byte alignments",
                  "limits": "Ordinary private RAM, baseline x86-64, tags/PAC disabled. Unicorn stops before harness RET; flags 0/A/F are sampled rather than a Cartesian full-flag sweep. Optional native signals prove pre-fault state and source mapping, not guest exception delivery. No MMIO, concurrency or process/application readiness."}
        write_evidence(ROOT / ".stela/literal-differential-report.json", report)
        print(json.dumps({key: value for key, value in report.items() if key not in ("artifacts", "faults")}, indent=2))
        return
    compiled, compiler, corpus = cases(), None, hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix='stela-pcrel-') as temporary:
        directory = Path(temporary)
        for index, case in enumerate(compiled):
            source = struct.pack('<' + 'I' * len(case['words']), *case['words'])
            corpus.update(struct.pack('<Q', case['base']))
            corpus.update(source)
            input_path = directory / 'source.bin'
            input_path.write_bytes(source)
            for mode in ('leaf', 'block'):
                output = directory / f'{index}-{mode}'
                manifest = json.loads(subprocess.check_output([str(cli), f'compile-{mode}', str(input_path),
                                                              '--guest-base', hex(case['base']), '--output-dir', str(output)]))
                if compiler is not None and compiler != manifest['compiler_source_sha256']:
                    raise AssertionError('Compiler changed during PC-relative suite')
                compiler = manifest['compiler_source_sha256']
                actual_pcs = [row[0] for row in manifest['source_map']]
                expected_pcs = [case['base'] + offset * 4 for offset in range(len(case['words']))]
                if actual_pcs != expected_pcs:
                    raise AssertionError(f'{mode} source map lost guest PCs: {actual_pcs} != {expected_pcs}')
                case[mode] = (output / 'native.bin').read_bytes()
                offsets = [row[1] for row in manifest['source_map']]
                if offsets != sorted(set(offsets)) or offsets[0] != 0 or offsets[-1] >= len(case[mode]):
                    raise AssertionError(f'{mode} source map lacks nonempty ordered native intervals: {offsets}')
        result = bounded_cases(compiled)
    if executable_hash != hashlib.sha256(cli.read_bytes()).hexdigest():
        raise AssertionError('Compiler executable changed during PC-relative suite')
    report = {'kind': 'pc_relative_arm_vs_native_x86', 'passed': True, **result,
              'operations': ['ADR', 'ADRP'],
              'reference': 'Unicorn ARM64 2.1.4 and independent unbounded fixture arithmetic',
              'native': 'baseline x86-64 leaf and block ABIs in isolated worker',
              'tested_state': ["V0..V31, FPCR and FPSR preservation", 'x0..x30', 'SP, NZCV and reserved-word preservation', 'all 16 incoming NZCV combinations',
                               'all destinations including discarded XZR', 'dirty GPR upper halves', 'per-instruction guest PC and source maps',
                               '4 KiB ADRP granule across 4 KiB and 16 KiB boundaries', 'signed 21-bit extrema and immlo combinations',
                               'address result consumption and repeated destination writes', 'native block RET result after X30 replacement'],
              'corpus_sha256': corpus.hexdigest(), 'compiler_source_sha256': compiler,
              'compiler_executable_sha256': executable_hash,
              'harness_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'shared_runner_sha256': hashlib.sha256((ROOT / 'dev/differential.py').read_bytes()).hexdigest(),
              'limits': 'Unicorn stops before harness-owned RET. Wrapping guest data addresses have native/math evidence only; no original-ARM claim for those cases. No application loading, memory dereferences, guest faults or macOS boot.'}
    write_evidence(ROOT / '.stela/pc-relative-differential-report.json', report)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
