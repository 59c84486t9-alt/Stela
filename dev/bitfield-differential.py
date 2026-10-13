#!/usr/bin/env python3
"""Exhaustive Apple A64 bitfield immediates: bit oracle, original ARM, native x86.

Leaf batches contain independent [bitfield, RET] mini-functions. Every native
source-map entry is called separately; every original instruction is observed
before the harness-owned RET. Thus later instructions cannot hide earlier
results. Representative block programs additionally execute the actual RET.
"""
import argparse
from collections import Counter
import ctypes
import hashlib
import json
import multiprocessing
from pathlib import Path
import random
import struct
import subprocess
import tempfile
import time

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn import arm64_const as arm
import unicorn

from differential import initialize_arm, capture_arm, state_dict as complete_state
from differential import ROOT, BASE, MASK, ARM_REGISTERS, State, executable
from evidence import write_evidence

RET = 0xd65f03c0
STOP = 0x700000
LEAF_ABI = 'x86_64-sysv-guest-state-v3-direct-ram'
BLOCK_ABI = 'x86_64-sysv-guest-state-v2-block-exit-direct-ram'
FORMS = {'SBFM32': 0x13000000, 'BFM32': 0x33000000, 'UBFM32': 0x53000000,
         'SBFM64': 0x93400000, 'BFM64': 0xb3400000, 'UBFM64': 0xd3400000}
ROLES = {'distinct': (0, 1), 'alias': (7, 7), 'zero_source': (30, 31), 'discard': (31, 1)}
BATCH_FUNCTIONS = 4096
MNEMONICS = {'sbfm', 'bfm', 'ubfm', 'sbfx', 'sbfiz', 'ubfx', 'ubfiz', 'bfi', 'bfxil', 'bfc',
             'asr', 'lsr', 'lsl', 'sxtb', 'sxth', 'sxtw', 'uxtb', 'uxth', 'uxtw'}
REGISTERS = ARM_REGISTERS + [arm.UC_ARM64_REG_SP, arm.UC_ARM64_REG_NZCV]


class BlockExit(ctypes.Structure):
    _fields_ = [('next_pc', ctypes.c_uint64), ('kind', ctypes.c_uint64)]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoding(form, rotation, last, destination, source):
    width = int(form[-2:])
    if not (0 <= rotation < width and 0 <= last < width
            and 0 <= destination < 32 and 0 <= source < 32):
        raise ValueError('Invalid bitfield fixture fields')
    return FORMS[form] | rotation << 16 | last << 10 | source << 5 | destination


def operation(form, rotation, last, destination=0, source=1):
    return (form, rotation, last, destination, source)


def bit_reference(op, source, previous):
    """Copy individual bits into a linear field; no DecodeBitMasks/rotate masks.

    An unwrapped field extracts source[R:S] to bit0. A wrapped field inserts
    source[0:S] at bit(width-R). Signed forms fill the upper bits from source[S].
    This models the field placement directly, independently of A64 mask logic.
    """
    form, rotation, last, _, _ = op
    width = int(form[-2:])
    if rotation <= last:
        start, first, length = 0, rotation, last - rotation + 1
    else:
        start, first, length = width - rotation, 0, last + 1
    result = previous & ((1 << width) - 1) if form.startswith('BFM') else 0
    for index in range(length):
        bit = 1 << (start + index)
        result = (result & ~bit) | (((source >> (first + index)) & 1) << (start + index))
    if form.startswith('SBFM') and source & (1 << last):
        for index in range(start + length, width):
            result |= 1 << index
    return result


def mathematical_reference(operations, initial):
    result = State.from_buffer_copy(initial)
    for op in operations:
        _, _, _, destination, source = op
        value = bit_reference(op, result.x[source] if source != 31 else 0,
                              result.x[destination] if destination != 31 else 0)
        if destination != 31:
            result.x[destination] = value
    return result


def canonical_pairs():
    return {(form, rotation, last) for form in FORMS
            for rotation in range(int(form[-2:])) for last in range(int(form[-2:]))}


def exhaustive_functions():
    functions = []
    for form in FORMS:
        width = int(form[-2:])
        for rotation in range(width):
            for last in range(width):
                for role, (destination, source) in ROLES.items():
                    functions.append({'kind': 'exhaustive', 'role': role,
                                      'operations': [operation(form, rotation, last, destination, source)]})
    return functions


def supplementary_functions():
    result = []
    for form in FORMS:
        width = int(form[-2:])
        for destination in range(32):
            result.append({'kind': 'all_registers', 'operations': [
                operation(form, (destination * 7) % width, (destination * 11 + 3) % width,
                          destination, (destination + 13) % 32)]})
        for seed in range(8):
            # Repeated BFM inserts keep bits from prior destinations; aliases
            # feed those preserved bits into later instructions and widths.
            operations = [operation(form, (seed * 9 + i * 13) % width,
                                    (seed * 3 + i * 7) % width,
                                    (0, 7, 0, 3, 7, 3, 0, 7)[i],
                                    (1, 0, 0, 7, 3, 3, 7, 0)[i]) for i in range(8)]
            result.append({'kind': 'dependency_chain', 'operations': operations})
    for width in (32, 64):
        for seed in range(16):
            result.append({'kind': 'mixed_preservation_chain', 'operations': [
                operation(f'{kind}{bits}', (seed * 5 + i * 17) % bits,
                          (seed + i * 11) % bits, (0, 7, 3)[i % 3], (1, 0, 7)[i % 3])
                for i, (kind, bits) in enumerate([(kind, width if i % 2 else 96 - width)
                                                  for i, kind in enumerate(['BFM', 'UBFM', 'SBFM'] * 8)])]})
    return result


def block_functions():
    result = []
    for form in FORMS:
        width = int(form[-2:])
        for rotation, last in ((0, width - 1), (width - 1, 0), (width // 2, width // 2),
                               (3, width - 2)):
            result.append({'kind': 'block', 'operations': [operation(form, rotation, last)]})
    result.extend({'kind': 'block_chain', 'operations': case['operations']}
                  for case in supplementary_functions() if case['kind'] == 'dependency_chain'
                  and case['operations'][0][1] in (0, 9))
    return result


def invalid_words():
    result = {}
    for form, base in FORMS.items():
        word = encoding(form, 1, 0, 0, 1)
        for reason, bad in (('N_sf_mismatch', word ^ (1 << 22)),
                            ('sf_N_mismatch', word ^ (1 << 31)),
                            ('reserved_opc', word | (3 << 29))):
            result.setdefault(bad, reason)
        if form.endswith('32'):
            result[word | (1 << 21)] = '32bit_immr_high_bit'
            result[word | (1 << 15)] = '32bit_imms_high_bit'
    return result


def initial_states():
    rng = random.Random(0x534f524554544142)
    result = []
    for flags in range(16):
        state = State()
        for index in range(31):
            state.x[index] = rng.getrandbits(64)
        state.sp, state.nzcv, state.reserved = 0x123456789abc0000, flags << 28, rng.getrandbits(32)
        result.append(state)
    return result


def input_state(template, operations, index, block=False):
    state = State.from_buffer_copy(template)
    _, rotation, last, destination, source = operations[0]
    # Every W source/destination has deliberately nonzero upper halves. The
    # corpus includes sparse and dense fields, sign edges and independent old
    # destination bits; remaining GPRs and the ABI reserved field stay dirty.
    values = (0, MASK, 0xaaaaaaaaaaaaaaaa, 0x5555555555555555,
              1, 1 << 63, 0x7fffffffffffffff, 0x8000000000000001,
              1 << rotation, 1 << last, MASK ^ (1 << rotation), MASK ^ (1 << last),
              template.x[1], template.x[7], template.x[13], template.x[23])
    if destination != 31:
        state.x[destination] = values[(index + 7) % 16]
        if operations[0][0].endswith('32'):
            state.x[destination] = (state.x[destination] & 0xffffffff) | 0xa5a5f00d00000000
    if source != 31:
        state.x[source] = values[index]
        if operations[0][0].endswith('32'):
            state.x[source] = (state.x[source] & 0xffffffff) | 0xdeadc0de00000000
    if block:
        state.x[30] = STOP
    return state


def raw_source(functions):
    words = []
    entries = []
    for function in functions:
        entries.append(len(words))
        words.extend(encoding(*op) for op in function['operations'])
        words.append(RET)
    return struct.pack('<' + 'I' * len(words), *words), entries


def validate_manifest(manifest, source, native, block):
    wanted_kind = 'raw_arm64_block_aot' if block else 'raw_arm64_leaf_aot'
    if (manifest['schema_version'] != 1 or manifest['kind'] != wanted_kind
            or manifest['abi'] != (BLOCK_ABI if block else LEAF_ABI)
            or manifest['guest_base'] != BASE or manifest['source_sha256'] != digest(source)
            or manifest['native_sha256'] != digest(native) or manifest['native_bytes'] != len(native)
            or manifest['verified'] is not False):
        raise AssertionError('Compilation manifest does not bind source/native bytes and ABI')
    if (manifest['source_bytes'] if block else manifest['guest_instructions'] * 4) != len(source):
        raise AssertionError('Compilation consumed only a prefix of the fixture')
    source_map = manifest['source_map']
    if ([row[0] for row in source_map] != list(range(BASE, BASE + len(source), 4))
            or any(not 0 <= row[1] < len(native) for row in source_map)
            or any(left[1] >= right[1] for left, right in zip(source_map, source_map[1:]))):
        raise AssertionError('Every original instruction needs a distinct ordered native source-map entry')
    return [row[1] for row in source_map]


def compile_batch(cli, directory, functions, index, block=False):
    source, entries = raw_source(functions)
    if block and (len(functions) != 1 or len(source) > 256 * 4):
        raise AssertionError('Representative block exceeds its bounded input window')
    decoded = list(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(source, BASE))
    if len(decoded) != len(source) // 4 or any(instruction.mnemonic not in MNEMONICS | {'ret'}
                                             for instruction in decoded):
        raise AssertionError('Independent decoder rejected the original fixture')
    path = directory / f'{index}.arm64'
    path.write_bytes(source)
    output = directory / f'{index}.native'
    manifest = json.loads(subprocess.check_output([str(cli), 'compile-block' if block else 'compile-leaf',
                                                   str(path), '--guest-base', hex(BASE),
                                                   '--output-dir', str(output)], timeout=60))
    native = (output / 'native.bin').read_bytes()
    offsets = validate_manifest(manifest, source, native, block)
    if not block:
        for entry, function in zip(entries, functions):
            if native[offsets[entry + len(function['operations'])]] != 0xc3:
                raise AssertionError('Leaf mini-function has no mapped host RET boundary')
    return {'functions': functions, 'source': source, 'native': native, 'entries': entries,
            'offsets': [offsets[entry] for entry in entries], 'block': block,
            'compiler_source_sha256': manifest['compiler_source_sha256'],
            'receipt': {'source_sha256': digest(source), 'native_sha256': digest(native),
                        'source_map_sha256': digest(json.dumps(manifest['source_map']).encode()),
                        'functions': len(functions), 'source_instructions': len(source) // 4,
                        'native_bytes': len(native), 'block': block,
                        'independent_decoded_mnemonics': dict(sorted(Counter(i.mnemonic for i in decoded).items()))}}


def original_state(machine, initial, start, instruction_count, block):
    initialize_arm(machine, initial)
    end = STOP if block else start + instruction_count * 4
    machine.emu_start(start, end, count=instruction_count + int(block))
    if machine.reg_read(arm.UC_ARM64_REG_PC) != end:
        raise AssertionError('Original ARM did not reach the exact owned return boundary')
    return capture_arm(machine, initial)


def describe(state):
    return complete_state(state)


def execute_batches(batches, progress):
    counts = Counter()
    observed = {role: set() for role in ROLES}
    corpus = hashlib.sha256()
    incoming = initial_states()
    for batch_index, batch in enumerate(batches):
        machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        source = batch['source']
        machine.mem_map(BASE, (len(source) + 0xfff) & ~0xfff)
        machine.mem_write(BASE, source)
        with executable(batch['native']) as address:
            for function, entry, offset in zip(batch['functions'], batch['entries'], batch['offsets']):
                operations = function['operations']
                function_type = ctypes.CFUNCTYPE(BlockExit if batch['block'] else None, ctypes.POINTER(State))
                invoke = function_type(address + offset)
                for index, template in enumerate(incoming):
                    initial = input_state(template, operations, index, batch['block'])
                    expected = mathematical_reference(operations, initial)
                    original = original_state(machine, initial, BASE + entry * 4,
                                              len(operations), batch['block'])
                    actual = State.from_buffer_copy(initial)
                    boundary = invoke(ctypes.byref(actual))
                    if bytes(expected) != bytes(original) or bytes(original) != bytes(actual):
                        raise AssertionError(json.dumps({'function': function, 'initial': describe(initial),
                                                         'mathematical': describe(expected),
                                                         'original_arm': describe(original),
                                                         'native_x86': describe(actual)}))
                    if batch['block'] and (boundary.next_pc, boundary.kind) != (STOP, 4):
                        raise AssertionError('Native block returned the wrong actual RET PC/kind')
                    corpus.update(bytes(initial))
                    corpus.update(bytes(actual))
                    counts[function['kind']] += 1
                if function['kind'] == 'exhaustive':
                    observed[function['role']].add(tuple(operations[0][:3]))
        progress.send({'progress': batch_index + 1, 'batches': len(batches),
                       'comparisons': sum(counts.values())})
    wanted = canonical_pairs()
    if len(wanted) != 15360 or any(pairs != wanted for pairs in observed.values()):
        raise AssertionError('Not every canonical immediate pair was actually compared in every role')
    return {'three_way_register_state_comparisons': sum(counts.values()),
            'comparisons_by_program_kind': dict(counts),
            'exhaustive_immediate_pairs': len(wanted),
            'observed_immediate_pairs_by_role': {role: len(pairs) for role, pairs in observed.items()},
            'observed_pair_set_sha256': digest(json.dumps(sorted(wanted)).encode()),
            'leaf_mini_functions_executed': sum(len(batch['functions']) for batch in batches if not batch['block']),
            'block_programs_executed': sum(batch['block'] for batch in batches),
            'block_state_and_actual_ret_comparisons': counts['block'] + counts['block_chain'],
            'state_corpus_sha256': corpus.hexdigest()}


def worker(pipe, batches):
    try:
        pipe.send({'result': execute_batches(batches, pipe)})
    except BaseException as error:
        pipe.send({'error': repr(error)})
    finally:
        pipe.close()


def bounded_cases(batches):
    context = multiprocessing.get_context('spawn')
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=worker, args=(send, batches))
    process.start()
    send.close()
    try:
        deadline = time.monotonic() + 600
        while True:
            if receive.poll(1):
                message = receive.recv()
                if 'progress' in message:
                    print(f"bitfields: {message['progress']}/{message['batches']} batches, "
                          f"{message['comparisons']} full-state comparisons", flush=True)
                    continue
                process.join(timeout=2)
                if 'error' in message or process.exitcode != 0:
                    raise AssertionError(f'Bitfield worker failed: {message}, exit={process.exitcode}')
                return message['result']
            if process.exitcode is not None or time.monotonic() >= deadline:
                raise AssertionError(f'Bitfield worker failed/timed out: {process.exitcode}')
    finally:
        if process.is_alive():
            process.kill()
        process.join()
        receive.close()


def decline_invalid(cli, directory):
    result = []
    for index, (word, reason) in enumerate(sorted(invalid_words().items())):
        path = directory / f'invalid-{index}.arm64'
        path.write_bytes(struct.pack('<II', word, RET))
        output = directory / f'invalid-{index}.native'
        completed = subprocess.run([str(cli), 'compile-leaf', str(path), '--output-dir', str(output)],
                                   capture_output=True, text=True, timeout=15)
        if completed.returncode == 0 or output.exists():
            raise AssertionError(f'Reserved bitfield encoding accepted: {word:#010x}')
        result.append({'word': f'{word:#010x}', 'reason': reason,
                       'compiler_error': completed.stderr.strip()})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true', help='Use the already built, frozen CLI')
    arguments = parser.parse_args()
    if not arguments.no_build:
        subprocess.run([str(ROOT / 'dev/cargo'), 'build', '--locked', '-p', 'stela-cli'], check=True)
    cli = ROOT / 'target/debug/stela'
    identity_paths = {'compiler_executable_sha256': cli, 'harness_source_sha256': Path(__file__),
                      'shared_runner_sha256': ROOT / 'dev/differential.py',
                      'evidence_writer_sha256': ROOT / 'dev/evidence.py'}
    identities = {key: digest(path.read_bytes()) for key, path in identity_paths.items()}
    started = time.monotonic()
    functions = exhaustive_functions() + supplementary_functions()
    with tempfile.TemporaryDirectory(prefix='stela-bitfield-') as temporary:
        directory = Path(temporary)
        batches = [compile_batch(cli, directory, functions[start:start + BATCH_FUNCTIONS], index)
                   for index, start in enumerate(range(0, len(functions), BATCH_FUNCTIONS))]
        for function in block_functions():
            batches.append(compile_batch(cli, directory, [function], len(batches), block=True))
        fingerprints = {batch['compiler_source_sha256'] for batch in batches}
        if len(fingerprints) != 1:
            raise AssertionError('Compiler source changed during bitfield compilation')
        declined = decline_invalid(cli, directory)
        result = bounded_cases(batches)
    if any(identities[key] != digest(path.read_bytes()) for key, path in identity_paths.items()):
        raise AssertionError('CLI, harness or shared helper changed during the evidence run')
    report = {'kind': 'bitfield_arm_vs_native_x86', 'passed': True, **result, **identities,
              'compiler_source_sha256': fingerprints.pop(), 'operations': list(FORMS),
              'canonical_pairs_by_form': {form: int(form[-2:]) ** 2 for form in FORMS},
              'reference': f'Unchanged original ARM instructions in Unicorn {unicorn.__version__}; independent per-bit linear field copy/sign-fill oracle',
              'native': 'Direct baseline x86-64 leaf mini-functions and block ABI in a bounded isolated process',
              'incoming_nzcv_combinations': 16, 'roles': ROLES,
              'tested_state': ["V0..V31, FPCR and FPSR preservation", 'all 31 GPRs, SP, all saved NZCV bits and ABI reserved field',
                               'every valid immr/imms in SBFM/BFM/UBFM W32 and X64',
                               'each result observed separately, including zero and aliased operands',
                               'deliberately dirty W source/destination upper halves',
                               'all destination/source register encodings in supplemental programs',
                               'BFM old-destination preservation and mixed-width dependency chains',
                               'representative native block exit tuple and original actual RET PC'],
              'compilation_batches': [batch['receipt'] for batch in batches],
              'reserved_encodings_declined_before_execution': declined,
              'elapsed_seconds': round(time.monotonic() - started, 3),
              'limits': 'Register bitfield semantics and representative raw block returns only; no full PSTATE, memory, exceptions, Apple PAC, complete process or OS execution coverage.'}
    snapshot = write_evidence(ROOT / '.stela/bitfield-differential-report.json', report)
    print(json.dumps({key: value for key, value in report.items()
                      if key not in ('compilation_batches', 'reserved_encodings_declined_before_execution')}, indent=2))
    print(f'Evidence: {snapshot}')


if __name__ == '__main__':
    main()
