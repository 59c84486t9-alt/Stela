#!/usr/bin/env python3
"""Original Apple-used A64 control flow versus native block exits and dispatch.

Unicorn runs each complete original block, including its terminator. Its real PC
is compared with the native return tuple and an independent branch/state oracle.
The host loop and actual Rust runtime exercise the same multiblock programs.
A separate SVC/BRK section observes genuine original interrupts and returns
bounded trap metadata; it does not deliver exceptions or invoke host services.
This does not claim application loading or macOS execution.
"""
import argparse
from contextlib import ExitStack
import ctypes
import hashlib
import json
import multiprocessing
from pathlib import Path
import struct
import subprocess
import tempfile
import time

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_ARCH_X86, CS_MODE_64
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR, UC_ERR_FETCH_UNMAPPED
from unicorn import arm64_const as arm

from differential import capture_arm, initialize_arm, state_dict as complete_state
from differential import ROOT, BASE, MASK, ARM_REGISTERS, State, executable, arithmetic, move, states
from evidence import write_evidence

ABI = 'x86_64-sysv-guest-state-v2-block-exit-direct-ram'
KINDS = {'fallthrough': 0, 'direct': 1, 'indirect': 2, 'call': 3, 'return': 4, 'trap': 5}


class BlockExit(ctypes.Structure):
    _fields_ = [('next_pc', ctypes.c_uint64), ('kind', ctypes.c_uint64)]


def snapshot(state):
    return complete_state(state)


def holds(condition, flags):
    n, z, c, v = (bool(flags & (1 << bit)) for bit in (31, 30, 29, 28))
    return (z, not z, c, not c, n, not n, v, not v,
            c and not z, not c or z, n == v, n != v,
            not z and n == v, z or n != v, True, True)[condition]


def direct(call, words):
    return (0x94000000 if call else 0x14000000) | (words & 0x3ffffff)


def conditional(condition, words):
    return 0x54000000 | ((words & 0x7ffff) << 5) | condition


def compare_branch(width, nonzero, register, words):
    return (width << 31) | (nonzero << 24) | 0x34000000 | ((words & 0x7ffff) << 5) | register


def test_branch(nonzero, register, bit, words):
    return ((bit >> 5) << 31) | (nonzero << 24) | 0x36000000 | ((bit & 31) << 19) | ((words & 0x3fff) << 5) | register


def indirect(operation, register):
    return {'br': 0xd61f0000, 'blr': 0xd63f0000, 'ret': 0xd65f0000}[operation] | (register << 5)


def prefix_step(operation, state):
    """Fixture-level integer oracle; does not decode or invoke compiler helpers."""
    kind, destination, source, immediate = operation
    value = state.x[source] if source != 31 else 0
    if kind == 'move':
        result = immediate
    elif kind in ('add', 'subtract_flags'):
        total = value + immediate if kind == 'add' else value - immediate
        result = total & MASK
        if kind == 'subtract_flags':
            signed = value - (1 << 64) if value & (1 << 63) else value
            signed_total = signed - immediate
            state.nzcv = ((int(bool(result & (1 << 63))) << 31)
                          | (int(result == 0) << 30) | (int(value >= immediate) << 29)
                          | (int(not -(1 << 63) <= signed_total < (1 << 63)) << 28))
    else:
        raise AssertionError(operation)
    if destination != 31:
        state.x[destination] = result


def oracle(case, initial):
    state = State.from_buffer_copy(initial)
    for operation in case['prefix']:
        prefix_step(operation, state)
    pc = (case['base'] + 4 * len(case['prefix'])) & MASK
    transfer = case['transfer']
    operation = transfer['op']
    next_pc, kind = (pc + (4 if operation != 'fallthrough' else 0)) & MASK, 'fallthrough'
    if operation in ('b', 'bl'):
        next_pc = (pc + transfer['offset'] * 4) & MASK
        kind = 'call' if operation == 'bl' else 'direct'
    elif operation == 'condition':
        if holds(transfer['condition'], state.nzcv):
            next_pc, kind = (pc + transfer['offset'] * 4) & MASK, 'direct'
    elif operation in ('compare', 'test'):
        register = transfer['register']
        value = state.x[register] if register != 31 else 0
        if operation == 'compare':
            value &= (1 << transfer['bits']) - 1
        else:
            value &= 1 << transfer['bit']
        if bool(value) == bool(transfer['nonzero']):
            next_pc, kind = (pc + transfer['offset'] * 4) & MASK, 'direct'
    elif operation in ('br', 'blr', 'ret'):
        register = transfer['register']
        # Capture before BLR overwrites X30; register31 is XZR, never SP.
        next_pc = state.x[register] if register != 31 else 0
        kind = {'br': 'indirect', 'blr': 'call', 'ret': 'return'}[operation]
    elif operation in ('svc', 'brk'):
        next_pc, kind = pc, 'trap'
    elif operation != 'fallthrough':
        raise AssertionError(transfer)
    if operation in ('bl', 'blr'):
        state.x[30] = (pc + 4) & MASK
    return snapshot(state), {'next_pc': next_pc, 'kind': KINDS[kind]}


def make_case(name, transfer, prefix=None, base=BASE, trailing=False):
    prefix = prefix if prefix is not None else [('add', 9, 9, 1)]
    words = []
    for kind, destination, source, immediate in prefix:
        if kind == 'move':
            words.append(move(2, 1, destination, immediate))
        else:
            words.append(arithmetic(int(kind == 'subtract_flags'), int(kind == 'subtract_flags'),
                                    1, destination, source, immediate))
    operation = transfer['op']
    if operation in ('b', 'bl'):
        words.append(direct(operation == 'bl', transfer['offset']))
    elif operation == 'condition':
        words.append(conditional(transfer['condition'], transfer['offset']))
    elif operation == 'compare':
        words.append(compare_branch(int(transfer['bits'] == 64), transfer['nonzero'], transfer['register'], transfer['offset']))
    elif operation == 'test':
        words.append(test_branch(transfer['nonzero'], transfer['register'], transfer['bit'], transfer['offset']))
    elif operation in ('br', 'blr', 'ret'):
        words.append(indirect(operation, transfer['register']))
    elif operation in ('svc', 'brk'):
        words.append((0xd4000001 if operation == 'svc' else 0xd4200000) | (transfer['immediate'] << 5))
    elif operation != 'fallthrough':
        raise AssertionError(transfer)
    consumed = len(words) * 4
    if trailing:
        # UDF is deliberately outside the compiled block, not silently accepted.
        words.extend([0, 0xffffffff])
    return {'name': name, 'base': base, 'words': words, 'source_bytes': consumed,
            'prefix': prefix, 'transfer': transfer}


def cases():
    result = []
    for operation in ('b', 'bl'):
        for offset in (-(1 << 25), -5, 0, 1, 5, (1 << 25) - 1):
            result.append(make_case(f'{operation}-{offset}', {'op': operation, 'offset': offset}, base=0x10000000, trailing=True))
    for condition in range(16):
        for offset in (-(1 << 18), -3, 3, (1 << 18) - 1):
            result.append(make_case(f'condition-{condition}-{offset}',
                                   {'op': 'condition', 'condition': condition, 'offset': offset}))
        result.append(make_case(f'fresh-flags-{condition}',
                               {'op': 'condition', 'condition': condition, 'offset': 9},
                               [('subtract_flags', 31, 1, 1), ('add', 9, 9, 1)]))
    for bits in (32, 64):
        for nonzero in (0, 1):
            for register in (0, 7, 31):
                for offset in (-(1 << 18), 3, (1 << 18) - 1):
                    result.append(make_case(f'compare-{bits}-{nonzero}-{register}-{offset}',
                                           {'op': 'compare', 'bits': bits, 'nonzero': nonzero,
                                            'register': register, 'offset': offset}))
    for bit in (0, 31, 32, 63):
        for nonzero in (0, 1):
            for register in (0, 7, 31):
                for offset in (-(1 << 13), 3, (1 << 13) - 1):
                    result.append(make_case(f'test-{bit}-{nonzero}-{register}-{offset}',
                                           {'op': 'test', 'bit': bit, 'nonzero': nonzero,
                                            'register': register, 'offset': offset}))
    for operation in ('br', 'blr', 'ret'):
        for register in range(32):
            result.append(make_case(f'{operation}-x{register}', {'op': operation, 'register': register}, trailing=True))
    result.extend([make_case('fallthrough', {'op': 'fallthrough'}),
                   make_case('fallthrough-flags', {'op': 'fallthrough'}, [('subtract_flags', 0, 0, 1)]),
                   make_case('window-cap-fallthrough', {'op': 'fallthrough'},
                             [('add', 9, 9, 1)] * 256, trailing=True)])
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for case in result:
        source = struct.pack('<' + 'I' * len(case['words']), *case['words'])[:case['source_bytes']]
        decoded = list(decoder.disasm(source, case['base']))
        if len(decoded) * 4 != case['source_bytes']:
            raise AssertionError(f'Independent decoder rejected fixture {case}')
    return result


def initial_states():
    result = []
    for flags in range(16):
        for value in (0, 1, 0x80000000, 0x100000000, 0x8000000000000000, MASK):
            state = State.from_buffer_copy(states()[flags % 10])
            state.x[0] = state.x[1] = state.x[7] = value
            state.sp = 0x1234000056780000
            state.nzcv = flags << 28
            state.reserved = 0xa5c39e71
            result.append(state)
    return result


def machine_for(blocks, initial):
    machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    pages = set()
    for case in blocks.values():
        pages.update(range(case['base'] & ~0xfff, (case['base'] + case['source_bytes'] + 0xfff) & ~0xfff, 0x1000))
    for page in sorted(pages):
        machine.mem_map(page, 0x1000)
    for case in blocks.values():
        machine.mem_write(case['base'], struct.pack('<' + 'I' * len(case['words']), *case['words'])[:case['source_bytes']])
    initialize_arm(machine, initial)
    return machine


def original_block(machine, case, reserved):
    addresses = []
    handle = machine.hook_add(UC_HOOK_CODE, lambda _machine, address, _size, _data: addresses.append(address))
    try:
        try:
            machine.emu_start(case['base'], 0, count=case['source_bytes'] // 4)
        except UcError as error:
            # Unicorn may fetch the target before honoring its instruction
            # counter. Accept only that fetch after the exact original block;
            # the PC and full state still have to match the independent oracle.
            if error.errno != UC_ERR_FETCH_UNMAPPED or len(addresses) != case['source_bytes'] // 4:
                raise
    finally:
        machine.hook_del(handle)
    expected_addresses = list(range(case['base'], case['base'] + case['source_bytes'], 4))
    if addresses != expected_addresses:
        raise AssertionError(f'Original did not execute exactly the consumed block: {addresses}, expected {expected_addresses}')
    return complete_state(capture_arm(machine, reserved=reserved)), machine.reg_read(arm.UC_ARM64_REG_PC)


def trap_cases():
    result = []
    prefixes = [('bare', []), ('preserved_flags', [('add', 9, 9, 1), ('move', 0, 0, 0x1234)]),
                ('fresh_flags', [('subtract_flags', 31, 1, 1), ('add', 9, 9, 1)])]
    for operation in ('svc', 'brk'):
        for immediate in (0, 1, 0x80, 0x7fff, 0xffff):
            for label, prefix in prefixes:
                case = make_case(f'{operation}-{immediate:#x}-{label}',
                                 {'op': operation, 'immediate': immediate}, prefix, trailing=True)
                source = struct.pack('<' + 'I' * len(case['words']), *case['words'])[:case['source_bytes']]
                decoded = list(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(source, case['base']))
                if len(decoded) * 4 != case['source_bytes'] or decoded[-1].mnemonic != operation:
                    raise AssertionError('Independent decoder rejected trap fixture ' + case['name'])
                result.append(case)
    return result


def trap_record(case):
    pc = case['base'] + case['source_bytes'] - 4
    operation = case['transfer']['op']
    return {'kind': 'supervisor_call' if operation == 'svc' else 'software_breakpoint',
            'immediate': case['transfer']['immediate'], 'instruction_pc': pc,
            'exception_return_pc': pc + 4 if operation == 'svc' else pc}


def trap_initial_states():
    incoming = initial_states()
    return [incoming[flags * 6 + flags % 6] for flags in range(16)]


def original_trap(case, initial):
    # Map trailing invalid words too. A successful boundary observation must
    # come from the genuine SVC/BRK interrupt, never a later UDF/fetch fault.
    mapped_case = {**case, 'source_bytes': len(case['words']) * 4}
    machine = machine_for({case['base']: mapped_case}, initial)
    trace, interrupts = [], []
    expected_addresses = list(range(case['base'], case['base'] + case['source_bytes'], 4))
    def instruction(machine, address, size, _):
        trace.append(address)
        if size != 4 or trace != expected_addresses[:len(trace)]:
            raise AssertionError('Original executed beyond the reviewed trap boundary')
    def interrupt(machine, number, _):
        interrupts.append({'number': number, 'observed_pc': machine.reg_read(arm.UC_ARM64_REG_PC)})
        machine.emu_stop()
    machine.hook_add(UC_HOOK_CODE, instruction)
    machine.hook_add(UC_HOOK_INTR, interrupt)
    machine.emu_start(case['base'], 0, count=len(case['words']) + 4)
    record = trap_record(case)
    expected_number = 2 if case['transfer']['op'] == 'svc' else 7
    if trace != expected_addresses or interrupts != [{'number': expected_number, 'observed_pc': record['exception_return_pc']}]:
        raise AssertionError(f'Original trap observation differs: {case["name"]}, {trace}, {interrupts}')
    state = complete_state(capture_arm(machine, initial))
    return state, {'trap': record, 'interrupt': interrupts[0], 'executed_addresses': trace}


def execute_trap_cases(compiled):
    rows, state_hash = [], hashlib.sha256()
    for case in compiled:
        decoded = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(case['native'], 0))
        if sum(instruction.size for instruction in decoded) != len(case['native']) or any(
                instruction.mnemonic in ('syscall', 'sysenter', 'int', 'int1', 'int3', 'hlt') for instruction in decoded):
            raise AssertionError('Native trap block contains a host syscall/trap or incomplete decode')
        comparisons = []
        with executable(case['native']) as address:
            function = ctypes.CFUNCTYPE(BlockExit, ctypes.POINTER(State))(address)
            for initial in trap_initial_states():
                expected, expected_exit = oracle(case, initial)
                original_state, observation = original_trap(case, initial)
                state = State.from_buffer_copy(initial)
                returned = function(ctypes.byref(state))
                native_exit = {'next_pc': returned.next_pc, 'kind': returned.kind}
                if expected != original_state or snapshot(state) != original_state or native_exit != expected_exit:
                    raise AssertionError(f'Trap state/exit differs: {case["name"]}, {observation}, {native_exit}')
                state_hash.update(bytes(initial))
                state_hash.update(bytes(state))
                state_hash.update(struct.pack('<QQ', returned.next_pc, returned.kind))
                comparisons.append({'initial': snapshot(initial), 'original_state': original_state,
                                    'original': observation, 'native_state': snapshot(state), 'native_exit': native_exit})
        rows.append({'name': case['name'], 'trap': trap_record(case), 'comparisons': comparisons})
    return {'trap_state_exit_comparisons': sum(len(row['comparisons']) for row in rows),
            'synchronous_traps': {'programs': len(compiled), 'state_corpus_sha256': state_hash.hexdigest(),
                                  'raw_native_comparisons': rows,
                                  'limits': 'SVC/BRK stop metadata only. Unicorn interrupt-hook PCs are observed directly; no exception-vector dispatch, ELR/ESR delivery, Darwin service implementation or host syscall is exercised.'}}


def trap_runtime_cases(cli, directory, fixtures, compiler):
    reports, count, compiled, disk_hits = [], 0, 0, 0
    for index, case in enumerate(fixtures):
        source = struct.pack('<' + 'I' * len(case['words']), *case['words'])
        source_path = directory / f'trap-runtime-{index}.bin'
        source_path.write_bytes(source)
        cache = directory / 'trap-runtime-cache'
        comparisons = []
        for initial in trap_initial_states():
            expected, expected_exit = oracle(case, initial)
            original_state, observation = original_trap(case, initial)
            state_path = directory / 'trap-state.json'
            state_path.write_text(json.dumps(snapshot(initial)))
            actual = json.loads(subprocess.check_output([str(cli), 'run-blocks', str(source_path),
                               '--guest-base', hex(case['base']), '--state', str(state_path), '--block-budget', '8',
                               '--cache-dir', str(cache)], timeout=10))
            outcome = actual['outcome']
            if (expected != original_state or actual['state'] != original_state or actual['pc'] != expected_exit['next_pc']
                    or outcome['reason'] != {'kind': 'synchronous_trap', 'trap': trap_record(case)}
                    or outcome['last_exit'] != [expected_exit['next_pc'], 5] or outcome['blocks_executed'] != 1
                    or actual['abi'] != ABI or actual['compiler_source_sha256'] != compiler
                    or actual['source_sha256'] != hashlib.sha256(source).hexdigest()
                    or actual['complete_binary_verified'] is not False):
                raise AssertionError(json.dumps({'name': case['name'], 'original': observation, 'runtime': actual}, indent=2))
            first = not comparisons
            if outcome['compiled_blocks'] != (1 if first else 0) or outcome['disk_cache_hits'] != (0 if first else 1):
                raise AssertionError('Trap cold compilation/disk reuse differs')
            count += 1
            compiled += outcome['compiled_blocks']
            disk_hits += outcome['disk_cache_hits']
            comparisons.append({'initial': snapshot(initial), 'original': observation, 'native': actual})
        reports.append({'name': case['name'], 'source_sha256': hashlib.sha256(source).hexdigest(), 'comparisons': comparisons})
    return count, {'runtime_comparisons': reports, 'runtime_compiled_blocks': compiled, 'runtime_disk_cache_hits': disk_hits}


def declined_trap_neighbors(cli, directory):
    result = []
    for name, opcode in [('hvc', 0xd4000002), ('smc', 0xd4000003), ('hlt', 0xd4400000),
                         ('reserved_svc_low_zero', 0xd4000000), ('reserved_svc_low_bit', 0xd4000011),
                         ('reserved_brk_low_bit', 0xd4200001)]:
        for immediate in (0, 1, 0x80, 0x7fff, 0xffff):
            word = opcode | (immediate << 5)
            source = struct.pack('<II', word, 0xd65f03c0)
            path = directory / 'declined-trap.bin'
            path.write_bytes(source)
            completed = subprocess.run([str(cli), 'compile-block', str(path), '--guest-base', hex(BASE),
                                       '--output-dir', str(directory / f'declined-{name}-{immediate}')], capture_output=True, text=True)
            if completed.returncode == 0 or not completed.stderr:
                raise AssertionError(f'Unsupported trap neighbor compiled: {name}, {word:#x}')
            result.append({'name': name, 'word': f'{word:08x}', 'immediate': immediate,
                           'source_sha256': hashlib.sha256(source).hexdigest(), 'stderr': completed.stderr.strip(),
                           'execution_attempted': False})
    return result


def multiblock_cases():
    def block(offset, prefix, transfer):
        return make_case(f'multi-{offset}', transfer, prefix, base=BASE + offset)
    nested = [block(0, [('add', 20, 30, 0), ('move', 0, 0, 1)], {'op': 'bl', 'offset': (0x40 - 8) // 4}),
              block(12, [('add', 0, 0, 16), ('add', 30, 20, 0)], {'op': 'ret', 'register': 30}),
              block(0x40, [('add', 0, 0, 2), ('add', 19, 30, 0)], {'op': 'bl', 'offset': (0x80 - 0x48) // 4}),
              block(0x4c, [('add', 0, 0, 8), ('add', 30, 19, 0)], {'op': 'ret', 'register': 30}),
              block(0x80, [('add', 0, 0, 4)], {'op': 'ret', 'register': 30})]
    mixed = [block(0, [('move', 0, 0, 3)], {'op': 'fallthrough'}),
             block(4, [('add', 0, 0, 2)], {'op': 'br', 'register': 7}),
             block(0x40, [('add', 0, 0, 4)], {'op': 'b', 'offset': (0x80 - 0x44) // 4}),
             block(0x80, [('add', 0, 0, 8)], {'op': 'ret', 'register': 5})]
    loop = [block(0, [('subtract_flags', 0, 0, 1)], {'op': 'condition', 'condition': 1, 'offset': -1}),
            block(8, [], {'op': 'ret', 'register': 5})]
    budget = [block(0, [('add', 0, 0, 1)], {'op': 'b', 'offset': -1})]
    return [{'name': 'nested-call-return', 'blocks': nested, 'budget': 32, 'stop': 'unmapped', 'x0': 31},
            {'name': 'fallthrough-indirect-tailcall', 'blocks': mixed, 'budget': 32, 'stop': 'unmapped', 'x0': 17},
            {'name': 'backward-counted-loop', 'blocks': loop, 'budget': 32, 'stop': 'unmapped', 'x0': 0},
            {'name': 'bounded-infinite-loop', 'blocks': budget, 'budget': 16, 'stop': 'budget', 'x0': 23}]


def execute_cases(compiled, multi):
    comparisons, block_steps = 0, 0
    state_corpus = hashlib.sha256()
    all_states = initial_states()
    for case in compiled:
        with executable(case['native']) as address:
            function = ctypes.CFUNCTYPE(BlockExit, ctypes.POINTER(State))(address)
            for initial in all_states:
                state = State.from_buffer_copy(initial)
                expected_state, expected_exit = oracle(case, initial)
                machine = machine_for({case['base']: case}, initial)
                arm_state, arm_pc = original_block(machine, case, initial.reserved)
                actual_exit = function(ctypes.byref(state))
                actual = {'next_pc': actual_exit.next_pc, 'kind': actual_exit.kind}
                if arm_state != expected_state or arm_pc != expected_exit['next_pc'] or snapshot(state) != arm_state or actual != expected_exit:
                    raise AssertionError(json.dumps({'name': case['name'], 'initial': snapshot(initial),
                                                     'oracle_state': expected_state, 'arm_state': arm_state,
                                                     'native_state': snapshot(state), 'oracle_exit': expected_exit,
                                                     'arm_pc': arm_pc, 'native_exit': actual}, indent=2))
                state_corpus.update(bytes(initial))
                state_corpus.update(struct.pack('<QQ', actual_exit.next_pc, actual_exit.kind))
                comparisons += 1
    traces = []
    for fixture in multi:
        blocks = {case['base']: case for case in fixture['blocks']}
        for incoming_flags in range(16):
            initial = State.from_buffer_copy(all_states[incoming_flags * 6])
            initial.x[0] = 7
            initial.x[5] = initial.x[30] = BASE + 0x900
            initial.x[7] = BASE + 0x40
            state = State.from_buffer_copy(initial)
            machine = machine_for(blocks, initial)
            pc, trace = BASE, []
            with ExitStack() as stack:
                functions = {pc: ctypes.CFUNCTYPE(BlockExit, ctypes.POINTER(State))(
                    stack.enter_context(executable(case['native']))) for pc, case in blocks.items()}
                for _ in range(fixture['budget']):
                    if pc not in blocks:
                        stop = 'unmapped'
                        break
                    case = blocks[pc]
                    expected_state, expected_exit = oracle(case, state)
                    arm_state, arm_pc = original_block(machine, case, initial.reserved)
                    returned = functions[pc](ctypes.byref(state))
                    actual_exit = {'next_pc': returned.next_pc, 'kind': returned.kind}
                    if snapshot(state) != expected_state or arm_state != expected_state or arm_pc != returned.next_pc or actual_exit != expected_exit:
                        raise AssertionError(f'Multiblock mismatch {fixture["name"]}, PC={pc:#x}, {trace}')
                    trace.append([pc, returned.next_pc, returned.kind])
                    state_corpus.update(bytes(state))
                    state_corpus.update(struct.pack('<QQQ', pc, returned.next_pc, returned.kind))
                    pc = returned.next_pc
                    block_steps += 1
                else:
                    stop = 'budget'
            if stop != fixture['stop'] or state.x[0] != fixture['x0']:
                raise AssertionError(f'Wrong dispatch result {fixture["name"]}: {stop}, {state.x[0]}, {trace}')
            traces.append({'name': fixture['name'], 'incoming_nzcv': initial.nzcv, 'stop': stop,
                           'blocks': len(trace), 'next_pc': pc, 'x0': state.x[0], 'final_state': snapshot(state), 'trace': trace})
    return {'single_block_state_exit_comparisons': comparisons,
            'multiblock_execution_comparisons': len(traces), 'multiblock_state_exit_comparisons': block_steps,
            'state_corpus_sha256': state_corpus.hexdigest(), 'dispatch_traces': traces}


def runtime_cases(cli, directory, fixtures, traces, compiler):
    """Exercise the actual Rust dispatcher and disk cache, not just host dispatch."""
    executions, compiled_count, disk_hits, memory_hits = 0, 0, 0, 0
    reports, source_corpus = [], hashlib.sha256()
    initial_corpus = initial_states()
    for fixture in fixtures:
        end = max(case['base'] + case['source_bytes'] for case in fixture['blocks'])
        source = bytearray(end - BASE)
        for case in fixture['blocks']:
            encoded = struct.pack('<' + 'I' * len(case['words']), *case['words'])[:case['source_bytes']]
            source[case['base'] - BASE:case['base'] - BASE + len(encoded)] = encoded
        source_corpus.update(source)
        input_path = directory / (fixture['name'] + '.bin')
        input_path.write_bytes(source)
        cache = directory / (fixture['name'] + '-runtime-cache')
        fixture_reports = []
        for trace in (trace for trace in traces if trace['name'] == fixture['name']):
            initial = State.from_buffer_copy(initial_corpus[(trace['incoming_nzcv'] >> 28) * 6])
            initial.x[0] = 7
            initial.x[5] = initial.x[30] = BASE + 0x900
            initial.x[7] = BASE + 0x40
            state_path = directory / 'runtime-state.json'
            state_path.write_text(json.dumps(snapshot(initial)))
            actual = json.loads(subprocess.check_output(
                [str(cli), 'run-blocks', str(input_path), '--guest-base', hex(BASE),
                 '--state', str(state_path), '--block-budget', str(fixture['budget']),
                 '--cache-dir', str(cache)], timeout=10))
            reason = 'budget_exhausted' if fixture['stop'] == 'budget' else 'unmapped_target'
            outcome = actual['outcome']
            if (actual['state'] != trace['final_state'] or actual['pc'] != trace['next_pc']
                    or outcome['reason']['kind'] != reason or actual['abi'] != ABI
                    or actual['compiler_source_sha256'] != compiler
                    or actual['source_sha256'] != hashlib.sha256(source).hexdigest()
                    or actual['complete_binary_verified'] is not False):
                raise AssertionError(json.dumps({'fixture': fixture['name'], 'expected': trace, 'runtime': actual}, indent=2))
            if fixture['name'] == 'bounded-infinite-loop' and outcome['blocks_executed'] != fixture['budget']:
                raise AssertionError('Rust runtime did not honor block budget')
            executions += 1
            compiled_count += outcome['compiled_blocks']
            disk_hits += outcome['disk_cache_hits']
            memory_hits += outcome['memory_cache_hits']
            fixture_reports.append(outcome)
        if fixture_reports[0]['compiled_blocks'] == 0 or fixture_reports[1]['disk_cache_hits'] == 0:
            raise AssertionError('Cold compilation and disk-cache reuse were not observed')
        reports.append({'name': fixture['name'], 'executions': len(fixture_reports),
                        'cold': fixture_reports[0], 'warm_disk_cache': fixture_reports[1]})
    return {'rust_runtime_execution_comparisons': executions,
            'rust_runtime_compiled_blocks': compiled_count,
            'rust_runtime_disk_cache_hits': disk_hits, 'rust_runtime_memory_cache_hits': memory_hits,
            'runtime_input_corpus_sha256': source_corpus.hexdigest(), 'runtime_dispatch': reports}


def worker(pipe, compiled, multi, compiled_traps):
    try:
        result = execute_cases(compiled, multi)
        result.update(execute_trap_cases(compiled_traps))
        pipe.send(result)
    except BaseException as error:
        pipe.send({'error': repr(error)})
    finally:
        pipe.close()


def bounded_cases(compiled, multi, compiled_traps):
    context = multiprocessing.get_context('spawn')
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=worker, args=(send, compiled, multi, compiled_traps))
    process.start()
    send.close()
    try:
        deadline = time.monotonic() + 300
        while not receive.poll(1):
            if process.exitcode is not None or time.monotonic() >= deadline:
                raise AssertionError(f'Block worker failed/timed out: {process.exitcode}')
        result = receive.recv()
        process.join(timeout=2)
        if process.exitcode != 0 or 'error' in result:
            raise AssertionError(f'Block suite failed: {result}, exit={process.exitcode}')
        return result
    finally:
        if process.is_alive():
            process.kill()
        process.join()
        receive.close()


CONDITIONAL_BRANCH_CLASS = 0x54000000
CONSISTENT_HINT_BIT = 1 << 4
CONDITION_MASK = 15
WORD_BYTES = 4
NZCV_SHIFT = 28
BRANCH_TAKEN = KINDS['direct']
BRANCH_FALLTHROUGH = KINDS['fallthrough']
BC_ENCODING_MASK = 0xff000010
BRANCH_IMMEDIATE_BITS = 19
BRANCH_IMMEDIATE_SHIFT = 5
BRANCH_IMMEDIATE_MASK = (1 << BRANCH_IMMEDIATE_BITS) - 1


def bc_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def compile_bc_body(cli, directory, pc, word, label):
    source = struct.pack('<I', word)
    path = directory / (label + '.arm64')
    path.write_bytes(source)
    output = directory / label
    manifest = json.loads(subprocess.check_output([
        str(cli), 'compile-block', str(path), '--guest-base', hex(pc),
        '--cpu-target', 'baseline', '--output-dir', str(output)], timeout=30))
    native = (output / 'native.bin').read_bytes()
    assert manifest['abi'] == ABI
    assert manifest['source_bytes'] == WORD_BYTES
    assert manifest['source_sha256'] == hashlib.sha256(source).hexdigest()
    assert manifest['native_sha256'] == hashlib.sha256(native).hexdigest()
    assert manifest['source_map'] == [[pc, 0]]
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(native, 0))
    assert sum(ins.size for ins in decoded) == len(native)
    return native, manifest, [{'mnemonic': ins.mnemonic, 'operands': ins.op_str,
                                'size': ins.size} for ins in decoded]

def bc_original_native(cli, case_index_path, output_dir):
    cli = Path(cli).resolve()
    output_dir = Path(output_dir)
    case_index_path = Path(case_index_path)
    output_dir.mkdir(parents=True, exist_ok=False)
    cli_hash = bc_sha(cli)
    harness_hash = bc_sha(__file__)
    shared_hash = bc_sha(ROOT / 'dev/differential.py')
    oracle_hash = bc_sha(case_index_path)
    cases = json.loads(case_index_path.read_text())
    if isinstance(cases, dict):
        cases = cases['cases']
    assert {(row['condition'], row['nzcv']) for row in cases} == {
        (condition, flags) for condition in range(16) for flags in range(16)}
    assert len(cases) == 256
    artifacts, rows = {}, []
    compiler = None
    for index, case in enumerate(cases):
        word, pc = case['word'], case['source_pc']
        condition = case['condition']
        assert word & CONDITION_MASK == condition
        assert word & BC_ENCODING_MASK == CONDITIONAL_BRANCH_CLASS | CONSISTENT_HINT_BIT
        assert struct.unpack_from('<I', bytes.fromhex(case['source_hex']))[0] == word
        displacement = (word >> BRANCH_IMMEDIATE_SHIFT) & BRANCH_IMMEDIATE_MASK
        if displacement & (1 << (BRANCH_IMMEDIATE_BITS - 1)):
            displacement -= 1 << BRANCH_IMMEDIATE_BITS
        nzcv = case['nzcv'] << NZCV_SHIFT
        taken = holds(condition, nzcv)
        expected_pc = pc + (displacement * WORD_BYTES if taken else WORD_BYTES)
        assert case['observed_next_pc'] == expected_pc
        assert case['observed_elr'] == expected_pc + WORD_BYTES
        assert case['translation_terminator']['original_pc'] == expected_pc
        initial = bytes.fromhex(case['initial_state_hex'])
        original = bytes.fromhex(case['state_hex'])
        assert len(initial) == len(original) == ctypes.sizeof(State)
        assert State.from_buffer_copy(initial).nzcv == nzcv
        assert original == initial, 'BC has no architectural register effects'
        key = (pc, word)
        if key not in artifacts:
            label = 'case-' + str(len(artifacts))
            native, manifest, decoded = compile_bc_body(cli, output_dir, pc, word, label)
            ordinary, ordinary_manifest, _ = compile_bc_body(
                cli, output_dir, pc, word & ~CONSISTENT_HINT_BIT, label + '-ordinary')
            assert ordinary == native, 'B.cond/BC actual emitted bodies differ'
            if compiler is None:
                compiler = manifest['compiler_source_sha256']
            assert manifest['compiler_source_sha256'] == ordinary_manifest['compiler_source_sha256'] == compiler
            artifacts[key] = (native, manifest, decoded)
        native, manifest, decoded = artifacts[key]
        state = State.from_buffer_copy(initial)
        with executable(native) as address:
            function = ctypes.CFUNCTYPE(BlockExit, ctypes.POINTER(State))(address)
            returned = function(ctypes.byref(state))
        expected_kind = BRANCH_TAKEN if taken else BRANCH_FALLTHROUGH
        assert bytes(state) == original
        assert (returned.next_pc, returned.kind) == (expected_pc, expected_kind)
        rows.append({'case_index': index, 'condition': condition, 'nzcv': nzcv,
                     'original_next_pc': case['observed_next_pc'], 'native_next_pc': returned.next_pc,
                     'native_exit_kind': returned.kind, 'state_sha256': hashlib.sha256(bytes(state)).hexdigest(),
                     'native_sha256': manifest['native_sha256']})
    assert bc_sha(cli) == cli_hash
    assert bc_sha(__file__) == harness_hash
    assert bc_sha(ROOT / 'dev/differential.py') == shared_hash
    assert bc_sha(case_index_path) == oracle_hash
    report = {'kind': 'arm64_bc_cond_original_native_differential', 'passed': True,
              'compiler_executable_sha256': cli_hash, 'compiler_source_sha256': compiler,
              'abi': ABI, 'harness_source_sha256': harness_hash,
              'shared_sources_sha256': {'dev/differential.py': shared_hash},
              'original_case_index_sha256': oracle_hash,
              'target': 'baseline', 'comparisons': len(rows), 'state_exit_comparisons': len(rows),
              'actual_b_cond_byte_bridges': len(artifacts), 'state_bytes': ctypes.sizeof(State),
              'cases': rows,
              'artifacts': [{'pc': pc, 'word': word, 'manifest': manifest,
                             'native_bytes': len(native), 'instructions_including_exit_returns': len(decoded),
                             'decoded': decoded} for (pc, word), (native, manifest, decoded) in artifacts.items()],
              'limits': 'Bounded genuine QEMU original path and full-State comparison. No Apple hardware, host branch-prediction timing, application or OS boot claim.'}
    (output_dir / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


# Named encoding and observation-layout facts for the narrow synchronization cohort.
SYNCHRONIZATION_YIELD = 0xd503203f
SYNCHRONIZATION_CSDB = 0xd503229f
SYNCHRONIZATION_SB = 0xd50330ff
SYNCHRONIZATION_SB_MASK = 0xfffff0ff
SYNCHRONIZATION_RET = 0xd65f03c0
SYNCHRONIZATION_DIRECT_FUNCTIONS = 3
SYNCHRONIZATION_FUNCTIONS = 18
SYNCHRONIZATION_INPUT_STRIDE = 800
SYNCHRONIZATION_STATE_OFFSET = 8
SYNCHRONIZATION_GUARD_BYTES = 32
SYNCHRONIZATION_PAUSE_BODY = bytes.fromhex('f390')
SYNCHRONIZATION_CPUID_BODY = bytes.fromhex('4989d831c00fa24c89c3')
SYNCHRONIZATION_UNKNOWN_A64_ESR = 1 << 25
SYNCHRONIZATION_LEAF_ABI = 'x86_64-sysv-guest-state-v3-direct-ram'


def synchronization_original_native(cli, receipt_path, output_dir):
    """Bridge the integrated compiler to genuine original State observations.

    Nonzero SB CRm selects execute-as-zero here and UNDEF in QEMU. Those frames
    are reported as policy checks, separately from direct original equality.
    The unchanged native bodies inherit the prior State/host-ABI mapping proof.
    """
    cli, receipt_path = Path(cli).resolve(), Path(receipt_path).resolve()
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    frozen = {cli: bc_sha(cli), Path(__file__): bc_sha(__file__),
              ROOT / 'dev/differential.py': bc_sha(ROOT / 'dev/differential.py'),
              receipt_path: bc_sha(receipt_path)}
    receipt = json.loads(receipt_path.read_text())
    assert receipt['passed'] is True
    assert receipt['kind'] == 'genuine_original_synchronization_full_state_capture'
    assert receipt['state_bytes'] == ctypes.sizeof(State)
    original_dir = receipt_path.parent
    for name, identity in receipt['files'].items():
        path = original_dir / name
        assert path.parent == original_dir, 'Oracle files must be local receipt siblings'
        assert path.stat().st_size == identity['bytes']
        assert bc_sha(path) == identity['sha256']
        frozen[path] = identity['sha256']
    inputs = (original_dir / 'inputs.bin').read_bytes()
    originals = (original_dir / 'states.bin').read_bytes()
    cases = json.loads((original_dir / 'cases.json').read_text())
    assert len(cases) == receipt['cases'] == 320
    assert len(inputs) == len(cases) * SYNCHRONIZATION_INPUT_STRIDE
    assert len(originals) == len(cases) * ctypes.sizeof(State)
    subjects = {row['function_index']: row for row in receipt['subjects']}
    soft = {row['case_index']: row for row in receipt['observations']['soft_undefined_observations']}
    artifacts, rows, compiler = {}, [], None
    selected_flags = set()
    direct_comparisons = policy_comparisons = 0
    for index, case in enumerate(cases):
        function = case['function_index']
        if function >= SYNCHRONIZATION_FUNCTIONS:
            continue  # SSBB/PSSBB are deliberately outside this admission.
        subject = subjects[function]
        source = bytes.fromhex(subject['canonical_source_hex'])
        word, trailing_ret = struct.unpack('<II', source)
        assert trailing_ret == SYNCHRONIZATION_RET
        assert (word in (SYNCHRONIZATION_YIELD, SYNCHRONIZATION_CSDB)
                or word & SYNCHRONIZATION_SB_MASK == SYNCHRONIZATION_SB)
        assert subject['executed_source_hex'].startswith(source[:WORD_BYTES].hex())
        assert hashlib.sha256(source).hexdigest() == subject['canonical_source_sha256']
        pc = subject['instruction_pc']
        assert subject['svc_pc'] == pc + WORD_BYTES
        assert subject['expected_elr'] == subject['svc_pc'] + WORD_BYTES
        input_offset = index * SYNCHRONIZATION_INPUT_STRIDE
        assert struct.unpack_from('<Q', inputs, input_offset)[0] == function
        initial = inputs[input_offset + SYNCHRONIZATION_STATE_OFFSET:
                         input_offset + SYNCHRONIZATION_STATE_OFFSET + ctypes.sizeof(State)]
        original = originals[index * ctypes.sizeof(State):(index + 1) * ctypes.sizeof(State)]
        assert hashlib.sha256(initial).hexdigest() == case['initial_state_sha256']
        assert State.from_buffer_copy(initial).nzcv == case['nzcv'] << NZCV_SHIFT
        assert initial == original, 'Synchronization must preserve complete State'
        selected_flags.add((function, case['nzcv']))
        is_direct = function < SYNCHRONIZATION_DIRECT_FUNCTIONS
        assert (index not in soft) == is_direct
        if not is_direct:
            assert soft[index]['word'] == word and soft[index]['elr'] == pc
            assert soft[index]['esr'] == SYNCHRONIZATION_UNKNOWN_A64_ESR  # EC=unknown, IL=one A64 word.
        expected_body = (SYNCHRONIZATION_PAUSE_BODY if word == SYNCHRONIZATION_YIELD else SYNCHRONIZATION_CPUID_BODY)
        for mode in ('leaf', 'block'):
            key = (function, mode)
            if key not in artifacts:
                label = f'synchronization-{function}-{mode}'
                path = output_dir / (label + '.arm64')
                path.write_bytes(source if mode == 'leaf' else source[:WORD_BYTES])
                directory = output_dir / label
                manifest = json.loads(subprocess.check_output([
                    str(cli), 'compile-' + mode, str(path), '--guest-base', hex(pc),
                    '--cpu-target', 'baseline', '--output-dir', str(directory)], timeout=30))
                native = (directory / 'native.bin').read_bytes()
                assert manifest['abi'] == (SYNCHRONIZATION_LEAF_ABI if mode == 'leaf' else ABI)
                assert manifest['source_sha256'] == bc_sha(path)
                assert manifest['native_sha256'] == hashlib.sha256(native).hexdigest()
                assert manifest['source_map'] == ([[pc, 0], [pc + WORD_BYTES, len(expected_body)]]
                                                   if mode == 'leaf' else [[pc, 0]])
                assert native[:len(expected_body)] == expected_body
                if mode == 'leaf':
                    assert native == expected_body + b'\xc3'
                decoded = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(native, 0))
                assert sum(ins.size for ins in decoded) == len(native)
                if compiler is None:
                    compiler = manifest['compiler_source_sha256']
                assert compiler == manifest['compiler_source_sha256']
                artifacts[key] = (native, manifest, {
                    'function_index': function, 'mode': mode, 'word': hex(word),
                    'body_bytes': len(expected_body), 'body_instructions': 1 if word == SYNCHRONIZATION_YIELD else 4,
                    'native_sha256': manifest['native_sha256'], 'manifest': manifest,
                    'decoded': [{'mnemonic': ins.mnemonic, 'operands': ins.op_str, 'size': ins.size} for ins in decoded]})
            native, manifest, _ = artifacts[key]
            frame = ctypes.create_string_buffer(b'\xa5' * (ctypes.sizeof(State) + 2 * SYNCHRONIZATION_GUARD_BYTES))
            state = State.from_buffer(frame, SYNCHRONIZATION_GUARD_BYTES)
            ctypes.memmove(ctypes.byref(state), initial, len(initial))
            before = bytes(frame)
            with executable(native) as address:
                if mode == 'leaf':
                    ctypes.CFUNCTYPE(None, ctypes.POINTER(State))(address)(ctypes.byref(state))
                else:
                    returned = ctypes.CFUNCTYPE(BlockExit, ctypes.POINTER(State))(address)(ctypes.byref(state))
                    assert (returned.next_pc, returned.kind) == (pc + WORD_BYTES, 0)
            assert bytes(frame) == before and bytes(state) == original
            direct_comparisons += is_direct
            policy_comparisons += not is_direct
            rows.append({'case_index': index, 'function_index': function, 'mode': mode,
                         'comparison': 'direct_original' if is_direct else 'permitted_undefined_vs_execute_as_zero',
                         'state_sha256': hashlib.sha256(bytes(state)).hexdigest(),
                         'native_sha256': manifest['native_sha256']})
    assert selected_flags == {(function, flags) for function in range(SYNCHRONIZATION_FUNCTIONS) for flags in range(16)}
    for path, identity in frozen.items():
        assert bc_sha(path) == identity, f'Frozen input changed: {path}'
    report = {'kind': 'arm64_synchronization_original_native_differential', 'passed': True,
              'compiler_source_sha256': compiler, 'compiler_executable_sha256': frozen[cli],
              'harness_source_sha256': frozen[Path(__file__)],
              'shared_sources_sha256': {'dev/differential.py': frozen[ROOT / 'dev/differential.py']},
              'original_receipt_sha256': frozen[receipt_path], 'target': 'baseline',
              'state_bytes': ctypes.sizeof(State), 'state_comparisons': len(rows),
              'direct_original_state_comparisons': direct_comparisons,
              'soft_undefined_policy_state_comparisons': policy_comparisons,
              'actual_body_bridges': len(artifacts), 'cases': rows,
              'artifacts': [row[2] for row in artifacts.values()],
              'limits': ['Direct original equality covers CSDB/YIELD/SB CRm=0 only.',
                         'Nonzero SB uses a permitted source policy differing from QEMU UNDEF; no direct equality credit.',
                         'State observations do not prove speculation suppression; CPUID serialization requires the reviewed host guarantee.',
                         'Exact body bridges reuse prior host ABI preservation evidence; no application/OS/performance claim.']}
    (output_dir / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--cli', type=Path, help='Use an explicitly frozen compiler executable')
    parser.add_argument('--synchronization-oracle', type=Path, help='Run only CSDB/SB/YIELD from a genuine original receipt')
    parser.add_argument('--bc-oracle', type=Path, help='Run only focused BC originals from this observations index')
    parser.add_argument('--output-dir', type=Path, help='Fresh artifact directory required with --bc-oracle')
    args = parser.parse_args()
    if args.bc_oracle is not None and args.synchronization_oracle is not None:
        parser.error('Choose one focused oracle cohort')
    if not args.no_build:
        subprocess.run([str(ROOT / 'dev/cargo'), 'build', '--locked', '-p', 'stela-cli'], check=True)
    cli = (args.cli or ROOT / 'target/debug/stela').resolve()
    if args.synchronization_oracle is not None:
        if args.output_dir is None:
            parser.error('--synchronization-oracle requires a fresh --output-dir')
        report = synchronization_original_native(cli, args.synchronization_oracle, args.output_dir)
        write_evidence(ROOT / '.stela/synchronization-differential-report.json', report)
        print(json.dumps({key: report[key] for key in ('passed', 'direct_original_state_comparisons', 'soft_undefined_policy_state_comparisons', 'actual_body_bridges')}))
        return
    if args.bc_oracle is not None:
        if args.output_dir is None:
            parser.error('--bc-oracle requires a fresh --output-dir')
        report = bc_original_native(cli, args.bc_oracle, args.output_dir)
        write_evidence(ROOT / '.stela/bc-cond-differential-report.json', report)
        print(json.dumps({key: report[key] for key in ('passed', 'comparisons', 'actual_b_cond_byte_bridges')}))
        return
    executable_hash = hashlib.sha256(cli.read_bytes()).hexdigest()
    harness_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    shared_paths = [ROOT / 'dev/differential.py', ROOT / 'crates/stela-runtime/src/blocks.rs',
                    ROOT / 'crates/stela-runtime/src/lib.rs', ROOT / 'crates/stela-runtime/src/execution.rs']
    shared_hashes = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in shared_paths}
    compiled, multi, compiled_traps = cases(), multiblock_cases(), trap_cases()
    compiler, corpus, manifests = None, hashlib.sha256(), []
    all_cases = compiled + [case for fixture in multi for case in fixture['blocks']]
    with tempfile.TemporaryDirectory(prefix='stela-block-diff-') as temporary:
        directory = Path(temporary)
        for index, case in enumerate(all_cases):
            source = struct.pack('<' + 'I' * len(case['words']), *case['words'])
            corpus.update(struct.pack('<QI', case['base'], len(source)))
            corpus.update(source)
            input_path = directory / 'source.bin'
            input_path.write_bytes(source)
            output = directory / str(index)
            manifest = json.loads(subprocess.check_output([str(cli), 'compile-block', str(input_path),
                                                          '--guest-base', hex(case['base']), '--output-dir', str(output)]))
            if manifest['abi'] != ABI or manifest['source_bytes'] != case['source_bytes']:
                raise AssertionError(f'Wrong block manifest ABI/boundary: {manifest}, case={case}')
            if compiler is not None and compiler != manifest['compiler_source_sha256']:
                raise AssertionError('Compiler changed during block suite')
            compiler = manifest['compiler_source_sha256']
            case['native'] = (output / 'native.bin').read_bytes()
            if manifest['native_sha256'] != hashlib.sha256(case['native']).hexdigest():
                raise AssertionError('Native output hash mismatch')
            manifests.append({'name': case['name'], 'guest_base': case['base'], 'source_bytes': case['source_bytes'],
                              'native_sha256': manifest['native_sha256'],
                              'input_source_sha256': hashlib.sha256(source).hexdigest()})
        trap_manifests = []
        for index, case in enumerate(compiled_traps):
            source = struct.pack('<' + 'I' * len(case['words']), *case['words'])
            input_path = directory / 'trap-source.bin'
            input_path.write_bytes(source)
            output = directory / f'trap-{index}'
            manifest = json.loads(subprocess.check_output([str(cli), 'compile-block', str(input_path),
                                  '--guest-base', hex(case['base']), '--output-dir', str(output)]))
            if (manifest['abi'] != ABI or manifest['source_bytes'] != case['source_bytes']
                    or manifest['source_sha256'] != hashlib.sha256(source[:case['source_bytes']]).hexdigest()
                    or manifest['compiler_source_sha256'] != compiler):
                raise AssertionError('Trap compiler ABI/source/consumed boundary differs')
            case['native'] = (output / 'native.bin').read_bytes()
            if hashlib.sha256(case['native']).hexdigest() != manifest['native_sha256']:
                raise AssertionError('Trap native artifact hash differs')
            source_map = manifest['source_map']
            if ([row[0] for row in source_map] != list(range(case['base'], case['base'] + case['source_bytes'], 4))
                    or any(not 0 <= row[1] < len(case['native']) for row in source_map)
                    or [row[1] for row in source_map] != sorted(row[1] for row in source_map)):
                raise AssertionError('Trap consumed source map includes trailing code or invalid native offsets')
            trap_manifests.append({'name': case['name'], 'input_source_sha256': hashlib.sha256(source).hexdigest(), 'manifest': manifest})
        declines = declined_trap_neighbors(cli, directory)
        result = bounded_cases(compiled, multi, compiled_traps)
        trap_runtime_count, runtime_details = trap_runtime_cases(cli, directory, compiled_traps, compiler)
        result['trap_rust_runtime_execution_comparisons'] = trap_runtime_count
        result['synchronous_traps'].update(runtime_details)
        result['synchronous_traps'].update({'compiled_blocks': trap_manifests, 'declined_neighbors': declines})
        result.update(runtime_cases(cli, directory, multi, result['dispatch_traces'], compiler))
    if executable_hash != hashlib.sha256(cli.read_bytes()).hexdigest():
        raise AssertionError('Compiler executable changed during block suite')
    if harness_hash != hashlib.sha256(Path(__file__).read_bytes()).hexdigest() or shared_hashes != {
            str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in shared_paths}:
        raise AssertionError('Harness/shared runtime source changed during block suite')
    report = {'kind': 'arm64_block_control_flow_differential', 'passed': True,
              'programs': len(compiled), 'multiblock_fixtures': len(multi), **result,
              'reference': 'Original A64 Unicorn execution and independent integer/control-flow oracle',
              'native': 'Native x86-64 BlockExit SysV RAX/RDX return, RX mappings, Python host dispatch and actual Rust runtime',
              'abi': ABI, 'tested_state': ["V0..V31, FPCR and FPSR preservation", 'x0..x30', 'SP', 'NZCV', 'reserved ABI field', 'actual next guest PC',
                                            'taken/untaken exit kind', 'BL/BLR link register', 'BLR X30 target capture',
                                            'all 16 conditions and all 16 NZCV states', 'fresh flags before branch',
                                            'CBZ/CBNZ W32/X64 and XZR', 'TBZ/TBNZ bits0/31/32/63 and XZR',
                                            'signed branch displacement edges', 'all BR/BLR/RET register fields',
                                            'first terminator source boundary', '256-word fallthrough window boundary', 'nested calls/returns',
                                            'fallthrough/indirect/tail transfers', 'counted and bounded infinite loops',
                                            'explicit unmapped target stop'],
              'corpus_sha256': corpus.hexdigest(), 'compiled_blocks': manifests,
              'compiler_source_sha256': compiler, 'compiler_executable_sha256': executable_hash,
              'harness_source_sha256': harness_hash,
              'shared_runner_sha256': hashlib.sha256((ROOT / 'dev/differential.py').read_bytes()).hexdigest(),
              'shared_sources_sha256': shared_hashes,
              'limits': 'Bounded ordinary integer blocks with private state. Unmapped target fetch after a fully consumed original block is a boundary observation, not fault-delivery evidence. The flat Rust runtime image may coalesce adjacent fixture blocks. No PAC, platform ABI, memory faults, arbitrary guest binaries or macOS boot.'}
    write_evidence(ROOT / '.stela/block-differential-report.json', report)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
