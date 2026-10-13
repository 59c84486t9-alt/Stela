#!/usr/bin/env python3
"""Three-way carry and extended-register arithmetic; complete architectural state."""
import argparse
import hashlib
import ctypes
import json
import multiprocessing
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import time

from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_ARM, CS_MODE_64
from differential import state_dict as complete_state
from differential import ROOT, State, arithmetic, executable, initialize_arm, capture_arm, states
from evidence import write_evidence

RET = 0xd65f03c0
MASK = (1 << 64) - 1
LEGACY_CARRY_CORPUS = '5cea082d8e1f903412a26c0fc364f6508686c0f7488880531215721f92de74ab'
STATE_CORPUS = '5a6a330a0a666d818f34bf90be5ef8bbe09f40e9322d0a46b3b9913b61574dae'
FLAG_FORMS = {'CFINV': 0xd500401f, 'RMIF': 0xba000400, 'SETF8': 0x3a00080d,
              'SETF16': 0x3a00480d, 'AXFLAG': 0xd500405f, 'XAFLAG': 0xd500403f}
FLAG_SYSTEM_MASK = 0xfffff0ff
RMIF_MASK = 0xffe07c10
SETF_MASK = 0xfffffc1f
SOURCE_REGISTER_SHIFT = 5
RMIF_ROTATE_SHIFT = 15
IGNORED_CRM_SHIFT = 8
NZCV_SHIFT = 28
CARRY_FLAG = 1 << 29
ZERO_REGISTER = 31
REGISTER_COUNT = 32
FLAG_NIBBLE_MASK = 15
ROTATE_MASK = 63
HOST_RET = 0xc3
FLAG_SEMANTIC_ARCHIVE = ROOT / '.stela/isa/ISA_A64_xml_A_profile-2026-06.tar.gz'
FLAG_SEMANTIC_ARCHIVE_SHA256 = '63a01a1696483bbe2edfef9e0f0cd053d6c1c619ec0587876cb7a60bb344f354'
BASELINE_FLAG_MNEMONICS = frozenset({
    'adc', 'add', 'and', 'bt', 'btr', 'bts', 'cmova', 'cmovae', 'cmovb', 'cmovbe', 'cmove',
    'cmovg', 'cmovge', 'cmovl', 'cmovle', 'cmovne', 'cmp', 'je', 'jmp', 'jne', 'lea', 'mov',
    'movabs', 'movzx', 'neg', 'nop', 'not', 'or', 'pop', 'pushfq', 'ret', 'rol', 'ror', 'sar',
    'sete', 'setne', 'shl', 'shr', 'sub', 'test', 'xor'})


def encoding(width, subtract, flags, destination, left, right):
    return ((width << 31) | (subtract << 30) | (flags << 29)
            | 0x1a000000 | (right << 16) | (left << 5) | destination)


def carry_cases():
    result = []
    for width in (0, 1):
        for subtract in (0, 1):
            for flags in (0, 1):
                for destination in range(32):
                    result.append({'words': [encoding(width, subtract, flags, destination,
                                                       (destination + 5) % 32, (destination + 13) % 32), RET],
                                   'kind': 'all_registers'})
                for destination, left, right in ((0, 1, 2), (1, 1, 2), (2, 1, 2), (31, 1, 2),
                                                 (0, 31, 2), (0, 1, 31), (0, 31, 31), (31, 31, 31),
                                                 (0, 1, 1), (30, 0, 7)):
                    result.append({'words': [encoding(width, subtract, flags, destination, left, right), RET],
                                   'kind': 'boundaries', 'width': width, 'left': left, 'right': right})
                # Low-to-high four-limb chains exercise freshly saved C and
                # deliberate nonflag carry operations that preserve guest NZCV.
                for mixed_flags in (False, True):
                    words = [encoding(width, subtract, flags if not mixed_flags else int(limb % 2 == 0),
                                      limb, limb, limb + 4) for limb in range(4)]
                    result.append({'words': words + [RET], 'kind': 'dependency_chain', 'width': width})
                # Nonflag ADD clobbers host carry before the ARM carry consumer.
                result.append({'words': [arithmetic(0, 0, width, 28, 28, 1),
                                          encoding(width, subtract, flags, 0, 31, 31), RET],
                               'kind': 'host_flag_clobber'})
                # Carry flag itself becomes a value; nonflag variants must leave
                # all incoming N/Z/V bits intact, including with discarded Rd.
                result.append({'words': [encoding(width, subtract, flags, 31, 1, 2),
                                          encoding(width, 0, 0, 0, 31, 31), RET],
                               'kind': 'discarded_result_carry_consumer'})
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for case in result:
        for word in case['words']:
            decoded = next(decoder.disasm(struct.pack('<I', word), 0), None)
            if decoded is None or decoded.mnemonic not in ('adc', 'adcs', 'sbc', 'sbcs', 'ngc', 'ngcs', 'add', 'ret'):
                raise AssertionError(f'Independent decoder rejected {word:#x}')
    return result


def carry_reference(words, initial):
    registers = list(initial.x)
    nzcv = initial.nzcv
    for word in words[:-1]:
        bits = 64 if word >> 31 else 32
        mask = (1 << bits) - 1
        destination, left, right = word & 31, (word >> 5) & 31, (word >> 16) & 31
        first = (registers[left] if left != 31 else 0) & mask
        if word & 0x1f800000 == 0x11000000:
            # The only noncarry fixture instruction is nonflag ADD #1.
            if ((word >> 10) & 0xfff) != 1 or word & (3 << 29):
                raise AssertionError('Unexpected mathematical fixture')
            value = (first + 1) & mask
        else:
            second = (registers[right] if right != 31 else 0) & mask
            carry = (nzcv >> 29) & 1
            subtract = bool(word & (1 << 30))
            total = first - second - (1 - carry) if subtract else first + second + carry
            value = total & mask
            if word & (1 << 29):
                sign = 1 << (bits - 1)
                first_signed = first - (1 << bits) if first & sign else first
                second_signed = second - (1 << bits) if second & sign else second
                signed_total = (first_signed - second_signed - (1 - carry) if subtract else
                                first_signed + second_signed + carry)
                negative = int(bool(value & sign))
                zero = int(value == 0)
                outgoing_carry = int(total >= 0) if subtract else int(total > mask)
                overflow = int(not -sign <= signed_total < sign)
                nzcv = (negative << 31) | (zero << 30) | (outgoing_carry << 29) | (overflow << 28)
        if destination != 31:
            registers[destination] = value
    return {**complete_state(initial), 'x': registers, 'sp': initial.sp, 'nzcv': nzcv}


def extended_encoding(width, subtract, flags, destination, left, right, option, shift):
    return ((width << 31) | (subtract << 30) | (flags << 29) | 0x0b200000
            | (right << 16) | (option << 13) | (shift << 10) | (left << 5) | destination)


def extended_cases():
    result = []
    aliases = [(1, 1, 2), (2, 1, 2), (0, 1, 1), (1, 1, 1), (31, 31, 31),
               (0, 31, 2), (0, 1, 31), (31, 1, 2), (31, 31, 2), (30, 30, 30)]
    for width in (0, 1):
        for subtract in (0, 1):
            for flags in (0, 1):
                for option in range(8):
                    for shift in range(5):
                        fields = {'family': 'extended', 'width': width, 'subtract': subtract,
                                  'flags': flags, 'option': option, 'shift': shift}
                        result.append({**fields, 'kind': 'all_registers', 'words': [
                            extended_encoding(width, subtract, flags, d, (d + 5) % 32,
                                              (d + 13) % 32, option, shift) for d in range(32)] + [RET]})
                        result.append({**fields, 'kind': 'extended_boundaries', 'words': [
                            extended_encoding(width, subtract, flags, 0, 1, 2, option, shift), RET]})
                        for d, n, m in aliases:
                            result.append({**fields, 'kind': 'extended_aliases', 'words': [
                                extended_encoding(width, subtract, flags, d, n, m, option, shift), RET]})
                # New flags flow through a real carry consumer, and nonflag
                # extended arithmetic must retain the incoming architectural C.
                result.append({'family': 'extended', 'kind': 'extended_chain',
                    'width': width, 'words': [extended_encoding(width, subtract, flags, 0, 1, 2, 4, 3),
                    encoding(width, 0, 0, 4, 31, 31),
                    extended_encoding(width, subtract, flags, 1, 0, 4, 6, 4), RET]})
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for case in result:
        for word in case['words']:
            decoded = next(decoder.disasm(struct.pack('<I', word), 0), None)
            if decoded is None or decoded.mnemonic not in ('add', 'adds', 'sub', 'subs', 'cmp', 'cmn', 'adc', 'ret'):
                raise AssertionError(f'Independent decoder rejected extended word {word:#x}')
    return result


def extend_value(value, width, option, shift):
    bits = 32 << width
    source_bits = min(8 << (option & 3), bits)
    low = value & ((1 << source_bits) - 1)
    if option & 4 and low & (1 << (source_bits - 1)):
        low -= 1 << source_bits
    return (low << shift) & ((1 << bits) - 1)


def mathematical_reference(words, initial):
    state = State.from_buffer_copy(initial)
    for word in words[:-1]:
        if word & 0x1fe00000 != 0x0b200000:
            result = carry_reference([word, RET], state)
            state.x[:], state.sp, state.nzcv = result['x'], result['sp'], result['nzcv']
            continue
        width, subtract, flags = word >> 31, bool(word & (1 << 30)), bool(word & (1 << 29))
        bits, d, n, m = 32 << width, word & 31, (word >> 5) & 31, (word >> 16) & 31
        mask, sign = (1 << bits) - 1, 1 << (bits - 1)
        first = (state.sp if n == 31 else state.x[n]) & mask
        second = extend_value(state.x[m] if m != 31 else 0, width, (word >> 13) & 7, (word >> 10) & 7)
        total = first - second if subtract else first + second
        value = total & mask
        if flags:
            signed_first = first - (1 << bits) if first & sign else first
            signed_second = second - (1 << bits) if second & sign else second
            signed_total = signed_first - signed_second if subtract else signed_first + signed_second
            state.nzcv = (int(bool(value & sign)) << 31) | (int(value == 0) << 30) | (
                int(total >= 0 if subtract else total > mask) << 29) | (int(not -sign <= signed_total < sign) << 28)
        if d != 31:
            state.x[d] = value
        elif not flags:
            state.sp = value
    return complete_state(state)


def extended_boundary_pairs(case):
    bits = 32 << case['width']
    mask, sign = (1 << bits) - 1, 1 << (bits - 1)
    source_bits = min(8 << (case['option'] & 3), bits)
    source_mask, source_sign = (1 << source_bits) - 1, 1 << (source_bits - 1)
    right_values = {0, 1, source_sign - 1, source_sign, source_sign + 1, source_mask - 1, source_mask}
    right_values |= {value | (MASK ^ source_mask) for value in tuple(right_values)}
    pairs = set()
    for right in right_values:
        extended = extend_value(right, case['width'], case['option'], case['shift'])
        left_values = {0, 1, mask, sign - 1, sign}
        for target in (0, sign - 1, sign, mask):
            left_values.add((target + extended if case['subtract'] else target - extended) & mask)
        pairs.update((left, right) for left in left_values)
    return sorted(pairs)


def initialize_extended_inputs(case, state, pair):
    word = case['words'][0]
    n, m = (word >> 5) & 31, (word >> 16) & 31
    poison = 0xdeadc0de00000000 if case['width'] == 0 else 0
    first, second = pair
    if n == 31:
        state.sp = first | poison
    else:
        state.x[n] = first | poison
    # Rm==31 is always ZR, even when Rn/Rd designate SP. For a real alias,
    # both operands necessarily observe the last assigned physical register.
    if m != 31:
        state.x[m] = second | poison


def boundary_pairs(width):
    bits = 32 << width
    mask = (1 << bits) - 1
    sign = 1 << (bits - 1)
    return [(0, 0), (0, 1), (1, 0), (1, 1), (mask, 0), (mask, 1), (mask, mask),
            (sign - 1, 0), (sign - 1, 1), (sign - 1, sign - 1),
            (sign, 0), (sign, 1), (sign, mask), (sign, sign), (0, mask),
            (0xaaaaaaaaaaaaaaaa & mask, 0x5555555555555555 & mask)]


def reusable_reference(code, cpu_model=None, oracle_declines=False):
    """One unchanged straight-line program, fully reset before each observation."""
    from differential import BASE
    from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_ERR_EXCEPTION
    from unicorn import arm64_const as arm
    words = struct.unpack('<' + 'I' * (len(code) // 4), code)
    if words[-1] != RET or RET in words[:-1] or len(code) > 4096:
        raise ValueError('Reusable arithmetic oracle requires one final RET')
    machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    if cpu_model is not None:
        machine.ctl_set_cpu_model(cpu_model)
    machine.mem_map(BASE, 4096)
    machine.mem_write(BASE, code)
    returned = False

    def boundary(machine, address, size, _):
        nonlocal returned
        if address == BASE + len(code) - 4:
            returned = True
            machine.emu_stop()

    machine.hook_add(UC_HOOK_CODE, boundary)

    def run(initial):
        nonlocal returned
        returned = False
        initialize_arm(machine, initial)
        try:
            machine.emu_start(BASE, BASE + len(code), count=10000)
        except UcError as error:
            if (not oracle_declines or error.errno != UC_ERR_EXCEPTION
                    or machine.reg_read(arm.UC_ARM64_REG_PC) != BASE
                    or complete_state(capture_arm(machine, initial)) != complete_state(initial)):
                raise
            return None
        if oracle_declines:
            raise AssertionError('Original oracle unexpectedly accepted a classified unavailable encoding')
        if not returned:
            raise AssertionError('Arithmetic reference did not reach its RET')
        return complete_state(capture_arm(machine, initial))

    return run


def execute_cases(compiled):
    comparisons = 0
    counts = {'carry': {'programs': 0, 'comparisons': 0}, 'extended': {'programs': 0, 'comparisons': 0}}
    corpus = hashlib.sha256()
    initial_states = states(all_flags=True)
    for case in compiled:
        family = case.get('family', 'carry')
        counts[family]['programs'] += 1
        code = struct.pack('<' + 'I' * len(case['words']), *case['words'])
        pairs = boundary_pairs(case['width']) if case['kind'] in ('boundaries', 'dependency_chain') else [None]
        if case['kind'] == 'extended_boundaries':
            pairs = extended_boundary_pairs(case)
        elif case['kind'] == 'extended_aliases':
            bits = 32 << case['width']
            source_sign = 1 << (min(8 << (case['option'] & 3), bits) - 1)
            pairs = [(0, (1 << bits) - 1), ((1 << bits) - 1, source_sign),
                     (1 << (bits - 1), source_sign - 1), ((1 << (bits - 1)) - 1, source_sign + 1)]
        original = reusable_reference(code)
        with executable(case['native']) as address:
            function = ctypes.CFUNCTYPE(None, ctypes.POINTER(State))(address)
            for pair in pairs:
                for initial in initial_states:
                    state = State.from_buffer_copy(initial)
                    if pair is not None:
                        if family == 'extended':
                            initialize_extended_inputs(case, state, pair)
                        else:
                            # Dirty W upper halves retain the original carry cohort.
                            poison = 0xdeadc0de00000000 if case['width'] == 0 else 0
                            inputs = (zip((case['left'], case['right']), pair) if case['kind'] == 'boundaries' else
                                      [(limb, pair[0]) for limb in range(4)] +
                                      [(limb + 4, pair[1]) for limb in range(4)])
                            for register, value in inputs:
                                if register != 31:
                                    state.x[register] = value | poison
                    state.reserved = 0x5a17c0de
                    corpus.update(code); corpus.update(bytes(state))
                    expected_math = mathematical_reference(case['words'], state)
                    expected_arm = original(state)
                    actual_state = State.from_buffer_copy(state)
                    function(ctypes.byref(actual_state))
                    actual = complete_state(actual_state)
                    if expected_math != expected_arm or expected_arm != actual:
                        raise AssertionError(json.dumps({**{k: v for k, v in case.items() if k != 'native'},
                                                         'initial': list(state.x), 'incoming_nzcv': state.nzcv,
                                                         'mathematical': expected_math, 'arm': expected_arm,
                                                         'native': actual}, indent=2))
                    comparisons += 1
                    counts[family]['comparisons'] += 1
    assert counts['carry'] == {'programs': 368, 'comparisons': 28928}
    assert corpus.hexdigest() == STATE_CORPUS, 'Verification context reuse must preserve every input'
    return {'programs': len(compiled), 'three_way_register_state_comparisons': comparisons,
            'groups': counts, 'state_corpus_sha256': corpus.hexdigest(),
            'carry_three_way_register_state_comparisons': counts['carry']['comparisons'],
            'extended_three_way_register_state_comparisons': counts['extended']['comparisons']}



def scalar_control_cases():
    """Focused implementation cohort; no new Cartesian matrix for each opcode."""
    result = []
    roles = ((0, 1, 2), (1, 1, 2), (2, 1, 2), (0, 1, 1),
             (31, 1, 2), (0, 31, 2), (0, 1, 31), (31, 31, 31))
    for width in (0, 1):
        for shift in range(4):
            for d, n, m in roles:
                result.append({'family': 'scalar_control', 'width': width, 'roles': (d, n, m),
                    'words': [(width << 31) | 0x1ac02000 | (shift << 10) | (m << 16) | (n << 5) | d, RET]})
        for amount in range(32 << width):
            # Every immediate plus rotation, source/destination overlap and ZR.
            d, n, m = roles[amount % len(roles)]
            result.append({'family': 'scalar_control', 'width': width, 'roles': (d, n, m),
                'words': [(0x93c00000 if width else 0x13800000) | (amount << 10)
                          | (m << 16) | (n << 5) | d, RET]})
        for subtract in (0, 1):
            for immediate in (0, 1):
                for condition in range(18):
                    # AL/NV always take the comparison; EQ additionally covers
                    # fallback nibbles 14/15, unreachable under those conditions.
                    cond, fallback = (condition, condition) if condition < 16 else (0, condition - 2)
                    _, n, m = roles[condition % len(roles)]
                    result.append({'family': 'scalar_control', 'width': width, 'roles': (31, n, m),
                        'words': [(width << 31) | (subtract << 30) | 0x3a400000
                                  | (immediate << 11) | (m << 16) | (cond << 12) | (n << 5) | fallback, RET]})
    # Original dyld encodings and freshly generated flags consumed by a second
    # conditional compare, followed by a carry consumer (no application behavior).
    for word in (0x1ac22108, 0xfa489320, 0x93cb116b, 0x7a411904, 0x7a490100):
        result.append({'family': 'scalar_control', 'width': word >> 31, 'roles': (0, 1, 2), 'words': [word, RET]})
    for width in (0, 1):
        result.append({'family': 'scalar_control', 'width': width, 'roles': (0, 1, 2),
            'words': [(width << 31) | 0x7a420020, (width << 31) | 0x3a41c82f,
                      encoding(width, 0, 0, 0, 31, 31), RET]})
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for case in result:
        for word in case['words']:
            instruction = next(decoder.disasm(struct.pack('<I', word), 0), None)
            assert instruction is not None and instruction.mnemonic in (
                'lsl', 'lsr', 'asr', 'ror', 'extr', 'ccmp', 'ccmn', 'adc', 'ret'), hex(word)
    return result


def scalar_control_reference(words, initial):
    registers, flags = list(initial.x), initial.nzcv
    for word in words[:-1]:
        bits = 64 if word >> 31 else 32
        mask, sign = (1 << bits) - 1, 1 << (bits - 1)
        d, n, m = word & 31, (word >> 5) & 31, (word >> 16) & 31
        a, b = ((registers[r] if r != 31 else 0) & mask for r in (n, m))
        if word & 0x7fe0f000 == 0x1ac02000:
            count, operation = b % bits, (word >> 10) & 3
            values = (a << count, a >> count,
                      (a - (1 << bits) if a & sign else a) >> count,
                      (a >> count) | (a << (bits - count)))
            value = values[operation] & mask
        elif word & 0x7fa00000 == 0x13800000:
            value = (((a << bits) | b) >> ((word >> 10) & 63)) & mask
        elif word & 0x3fe00410 == 0x3a400000:
            negative, zero, carry, overflow = (bool(flags & (1 << bit)) for bit in (31, 30, 29, 28))
            predicates = (zero, not zero, carry, not carry, negative, not negative, overflow, not overflow,
                          carry and not zero, not carry or zero, negative == overflow, negative != overflow,
                          not zero and negative == overflow, zero or negative != overflow, True, True)
            if not predicates[(word >> 12) & 15]:
                flags = (word & 15) << 28
            else:
                if word & (1 << 11): b = m
                subtract = bool(word & (1 << 30))
                total = a - b if subtract else a + b
                signed_a, signed_b = (v - (1 << bits) if v & sign else v for v in (a, b))
                signed_total = signed_a - signed_b if subtract else signed_a + signed_b
                flags = ((int(bool(total & sign)) << 31) | (int((total & mask) == 0) << 30)
                         | (int(total >= 0 if subtract else total > mask) << 29)
                         | (int(not -sign <= signed_total < sign) << 28))
            continue
        elif word & 0x7fe0fc00 == 0x1a000000:
            value = (a + b + ((flags >> 29) & 1)) & mask
        else: raise AssertionError(hex(word))
        if d != 31: registers[d] = value
    return {**complete_state(initial), 'x': registers, 'nzcv': flags}


def execute_scalar_control(compiled):
    corpus, comparisons = hashlib.sha256(), 0
    initial_states = states(all_flags=True)
    for case in compiled:
        source = struct.pack('<' + 'I' * len(case['words']), *case['words'])
        original = reusable_reference(source)
        bits = 32 << case['width']
        pairs = ((0, 0), (0x8000000080000000, 1), (0xffffffffffffffff, bits - 1),
                 (0x7fffffff7fffffff, bits), (0xdeadc0de00000001, bits + 1),
                 (0x0123456789abcdef, 0xffffffffffffffff))
        with executable(case['native']) as address:
            function = ctypes.CFUNCTYPE(None, ctypes.POINTER(State))(address)
            for first, second in pairs:
                for initial in initial_states:
                    state = State.from_buffer_copy(initial)
                    for register, value in zip(case['roles'][1:], (first, second)):
                        if register != 31: state.x[register] = value
                    state.reserved = 0x5a17c0de
                    expected = scalar_control_reference(case['words'], state)
                    arm = original(state)
                    actual = State.from_buffer_copy(state)
                    function(ctypes.byref(actual))
                    if expected != arm or arm != complete_state(actual):
                        raise AssertionError(json.dumps({'case': {k:v for k,v in case.items() if k != 'native'},
                            'initial': complete_state(state), 'math': expected, 'arm': arm,
                            'native': complete_state(actual)}))
                    corpus.update(source); corpus.update(bytes(state)); comparisons += 1
    return {'programs': len(compiled), 'three_way_register_state_comparisons': comparisons,
            'state_corpus_sha256': corpus.hexdigest()}


def run_scalar_control(cli):
    compiled, compiler, corpus = scalar_control_cases(), None, hashlib.sha256()
    executable_hash = hashlib.sha256(cli.read_bytes()).hexdigest()
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='stela-scalar-control-') as temporary:
        directory = Path(temporary)
        for index, case in enumerate(compiled):
            source = struct.pack('<' + 'I' * len(case['words']), *case['words'])
            corpus.update(source)
            path = directory / 'source.bin'; path.write_bytes(source)
            output = directory / str(index)
            manifest = json.loads(subprocess.check_output([str(cli), 'compile-leaf', str(path), '--output-dir', str(output)]))
            assert compiler in (None, manifest['compiler_source_sha256'])
            compiler = manifest['compiler_source_sha256']
            case['native'] = (output / 'native.bin').read_bytes()
        result = bounded_cases(compiled)
    assert hashlib.sha256(cli.read_bytes()).hexdigest() == executable_hash
    report = {'kind': 'scalar_control_arm_vs_native_x86', 'passed': True, **result,
        'compiler_source_sha256': compiler, 'compiler_executable_sha256': executable_hash,
        'harness_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'shared_runner_sha256': hashlib.sha256((ROOT / 'dev/differential.py').read_bytes()).hexdigest(),
        'corpus_sha256': corpus.hexdigest(), 'verification_wall_seconds': time.monotonic() - started,
        'limits': 'Focused scalar implementation checks, not the full regression checkpoint or application performance.'}
    write_evidence(ROOT / '.stela/scalar-control-differential-report.json', report)
    print(json.dumps(report, indent=2))


def flag_encoding(form, source=1, rotation=0, mask=FLAG_NIBBLE_MASK, crm=0):
    if form == 'RMIF':
        if not 0 <= rotation <= ROTATE_MASK or not 0 <= mask <= FLAG_NIBBLE_MASK:
            raise ValueError('RMIF rotation/mask outside architectural fields')
        return FLAG_FORMS[form] | (rotation << RMIF_ROTATE_SHIFT) | (source << SOURCE_REGISTER_SHIFT) | mask
    if form in ('SETF8', 'SETF16'):
        return FLAG_FORMS[form] | (source << SOURCE_REGISTER_SHIFT)
    if not 0 <= crm <= FLAG_NIBBLE_MASK:
        raise ValueError('Ignored CRm field outside four bits')
    return FLAG_FORMS[form] | (crm << IGNORED_CRM_SHIFT)


def flag_cases():
    """Exhaust immediates; bound source-pattern coverage instead of multiplying it."""
    result = []
    for form in ('CFINV', 'AXFLAG', 'XAFLAG'):
        for crm in range(16):
            result.append({'family': 'flags', 'form': form, 'kind': 'ignored_crm', 'source': None,
                           'oracle_declines': crm != 0, 'words': [flag_encoding(form, crm=crm), RET]})
    for rotation in range(64):
        for mask in range(16):
            result.append({'family': 'flags', 'form': 'RMIF', 'kind': 'immediates', 'source': 1,
                           'words': [flag_encoding('RMIF', rotation=rotation, mask=mask), RET]})
    for form in ('RMIF', 'SETF8', 'SETF16'):
        for source in range(REGISTER_COUNT):
            result.append({'family': 'flags', 'form': form, 'kind': 'source_registers', 'source': source,
                           'words': [flag_encoding(form, source, rotation=(source * 7) & ROTATE_MASK), RET]})
    for form in FLAG_FORMS:
        first = flag_encoding(form, rotation=63, mask=0b1010)
        # ADD dirties host flags without changing guest NZCV. ADC consumes the
        # resulting guest C; CCMP additionally checks a predicate of fresh C/Z.
        consumers = ([arithmetic(0, 0, 1, 28, 28, 1), encoding(1, 0, 0, 0, 31, 31)],
                     [0xfa42802f, encoding(1, 0, 0, 0, 31, 31)])
        for index, words in enumerate(consumers):
            result.append({'family': 'flags', 'form': form, 'kind': 'carry_chain' if index == 0 else 'conditional_chain',
                           'source': 1, 'words': [first, *words, RET]})
    return result


def flag_values(case):
    if case['source'] is None:
        return (None,)
    if case['form'] == 'RMIF':
        rotation = (case['words'][0] >> RMIF_ROTATE_SHIFT) & ROTATE_MASK
        # Rotation places the chosen nibble at bit zero, including wrap at 63.
        values = (0, MASK, 0x0123456789abcdea, 0xfedcba9876543215)
        return tuple(((value << rotation) | (value >> (64 - rotation))) & MASK for value in values)
    if case['form'] in ('SETF8', 'SETF16'):
        bits = 8 if case['form'] == 'SETF8' else 16
        sign = 1 << (bits - 1)
        poison = 0xdeadc0de00000000
        # Bit `bits` participates in V, even though the low-width result is zero.
        return tuple(poison | value for value in (0, 1, sign - 1, sign, sign + 1,
                                                  (1 << bits) - 1, 1 << bits, (1 << bits) | sign))
    return (None,)


def flag_reference(words, initial):
    """Independent Arm XML model; no translated-byte or host-flag dependence."""
    state = State.from_buffer_copy(initial)
    for word in words[:-1]:
        nibble = state.nzcv >> NZCV_SHIFT
        zero, carry, overflow = (bool(nibble & bit) for bit in (4, 2, 1))
        system = word & FLAG_SYSTEM_MASK
        if system == FLAG_FORMS['CFINV']:
            state.nzcv ^= CARRY_FLAG
        elif system == FLAG_FORMS['AXFLAG']:
            state.nzcv = ((int(zero or overflow) << 2) | (int(carry and not overflow) << 1)) << NZCV_SHIFT
        elif system == FLAG_FORMS['XAFLAG']:
            state.nzcv = ((int(not carry and not zero) << 3) | (int(zero and carry) << 2)
                          | (int(carry or zero) << 1) | int(not carry and zero)) << NZCV_SHIFT
        elif word & RMIF_MASK == FLAG_FORMS['RMIF']:
            source = (word >> SOURCE_REGISTER_SHIFT) & ZERO_REGISTER
            value = state.x[source] if source != ZERO_REGISTER else 0
            rotation = (word >> RMIF_ROTATE_SHIFT) & ROTATE_MASK
            selected = (((value << 64) | value) >> rotation) & FLAG_NIBBLE_MASK
            mask = word & FLAG_NIBBLE_MASK
            state.nzcv = ((nibble & ~mask) | (selected & mask)) << NZCV_SHIFT
        elif word & SETF_MASK in (FLAG_FORMS['SETF8'], FLAG_FORMS['SETF16']):
            source = (word >> SOURCE_REGISTER_SHIFT) & ZERO_REGISTER
            value = state.x[source] if source != ZERO_REGISTER else 0
            bits = 16 if word & SETF_MASK == FLAG_FORMS['SETF16'] else 8
            negative = (value >> (bits - 1)) & 1
            overflow = ((value >> bits) & 1) ^ negative
            zero = (value & ((1 << bits) - 1)) == 0
            state.nzcv = (state.nzcv & CARRY_FLAG) | (negative << 31) | (int(zero) << 30) | (overflow << 28)
        elif word & 0x7f800000 == 0x11000000:
            # Only the explicit nonflag ADD #1 consumer fixture is permitted.
            if word != arithmetic(0, 0, 1, 28, 28, 1):
                raise AssertionError(f'Unexpected flag-chain arithmetic {word:#x}')
            state.x[28] = (state.x[28] + 1) & MASK
        else:
            expected = scalar_control_reference([word, RET], state)
            state.x[:], state.nzcv = expected['x'], expected['nzcv']
    return complete_state(state)


def execute_flags(compiled):
    from unicorn import arm64_const as arm
    corpus, comparisons, declines = hashlib.sha256(), 0, 0
    groups = {form: {'programs': 0, 'three_way_comparisons': 0, 'native_math_only_comparisons': 0}
              for form in FLAG_FORMS}
    templates = states(all_flags=True)
    for case in compiled:
        groups[case['form']]['programs'] += 1
        source = struct.pack('<' + 'I' * len(case['words']), *case['words'])
        oracle_declines = case.get('oracle_declines', False)
        original = reusable_reference(source, arm.UC_CPU_ARM64_MAX, oracle_declines)
        with executable(case['native']) as address:
            function = ctypes.CFUNCTYPE(None, ctypes.POINTER(State))(address)
            for value in flag_values(case):
                for template in templates:
                    initial = State.from_buffer_copy(template)
                    if value is not None and case['source'] != ZERO_REGISTER:
                        initial.x[case['source']] = value
                    initial.reserved = 0x5a17c0de
                    expected, observed = flag_reference(case['words'], initial), original(initial)
                    actual = State.from_buffer_copy(initial)
                    function(ctypes.byref(actual))
                    if expected != complete_state(actual) or (not oracle_declines and expected != observed):
                        raise AssertionError(json.dumps({'case': {k: v for k, v in case.items() if k != 'native'},
                            'initial': complete_state(initial), 'math': expected, 'arm': observed,
                            'native': complete_state(actual)}))
                    corpus.update(source); corpus.update(bytes(initial))
                    comparisons += 1
                    declines += int(oracle_declines)
                    groups[case['form']]['native_math_only_comparisons' if oracle_declines else 'three_way_comparisons'] += 1
    return {'programs': len(compiled), 'three_way_complete_state_comparisons': comparisons - declines,
            'native_math_complete_state_comparisons': comparisons, 'native_math_only_complete_state_comparisons': declines,
            'unicorn_crm_decline_complete_state_pc_observations': declines,
            'groups': groups, 'state_corpus_sha256': corpus.hexdigest()}


def flag_binary_accounting(compiled, native):
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(native, 0))
    if sum(instruction.size for instruction in decoded) != len(native):
        raise AssertionError('Flag native disassembly does not cover every byte')
    if any(instruction.mnemonic not in BASELINE_FLAG_MNEMONICS for instruction in decoded):
        raise AssertionError('Flag baseline binary contains an unreviewed or optional host instruction')
    boundaries = {instruction.address: index for index, instruction in enumerate(decoded)}
    boundaries[len(native)] = len(decoded)
    shapes, offset, bodies, body_bytes = {}, 0, 0, 0
    for case in compiled:
        code = case['native']
        if code[-1] != HOST_RET:
            raise AssertionError('Flag mini-function lacks exact host RET')
        if offset not in boundaries or offset + len(code) not in boundaries:
            raise AssertionError('Flag mini-function boundary splits a native instruction')
        local = decoded[boundaries[offset]:boundaries[offset + len(code)]]
        if sum(instruction.size for instruction in local) != len(code) or local[-1].mnemonic != 'ret':
            raise AssertionError('Flag source map splits a native instruction')
        bodies += len(local) - 1; body_bytes += len(code) - 1
        if len(case['words']) == 2:
            shape = shapes.setdefault(case['form'], {'programs': 0, 'body_bytes_min': len(code) - 1,
                'body_bytes_max': 0, 'body_instructions_min': len(local) - 1, 'body_instructions_max': 0})
            shape['programs'] += 1
            for field, value in (('body_bytes', len(code) - 1), ('body_instructions', len(local) - 1)):
                shape[field + '_min'] = min(shape[field + '_min'], value)
                shape[field + '_max'] = max(shape[field + '_max'], value)
        for boundary in case['native_offsets']:
            if offset + boundary not in boundaries:
                raise AssertionError('Flag source-map boundary is inside a host instruction')
        offset += len(code)
    if offset != len(native) or bodies + len(compiled) != len(decoded):
        raise AssertionError('Flag body/RET accounting does not partition emitted bytes')
    return {'native_sha256': hashlib.sha256(native).hexdigest(), 'static_native_bytes_including_ret': len(native),
        'static_native_instructions_including_ret': len(decoded), 'harness_ret_bytes': len(compiled),
        'harness_ret_instructions': len(compiled), 'static_body_native_bytes': body_bytes,
        'static_body_native_instructions': bodies, 'single_operation_forms': shapes,
        'opcode_histogram': {mnemonic: sum(i.mnemonic == mnemonic for i in decoded)
                             for mnemonic in sorted({i.mnemonic for i in decoded})},
        'limits': 'Actual emitted baseline bytes, completely decoded and partitioned by source maps. '
                  'Each leaf has one one-byte harness RET, excluded from body counts. Static counts are not timings.'}


def retain_flag_binary_evidence(source, output, accounting):
    files = {'source.bin': source, 'native.bin': (output / 'native.bin').read_bytes(),
             'manifest.json': (output / 'manifest.json').read_bytes(),
             'accounting.json': (json.dumps(accounting, sort_keys=True, indent=2) + '\n').encode()}
    key = hashlib.sha256(b''.join(files.values()) + Path(__file__).read_bytes()).hexdigest()
    directory = ROOT / '.stela/native-evidence/flags' / key
    directory.mkdir(parents=True, exist_ok=True)
    receipts = {}
    for name, data in files.items():
        path = directory / name
        if path.exists() and path.read_bytes() != data:
            raise AssertionError(f'Immutable flag native evidence changed: {path}')
        if not path.exists():
            path.write_bytes(data)
        receipts[name] = {'path': str(path.relative_to(ROOT)), 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
    return receipts


def flag_blocks(cli, directory):
    """Small shared-dispatch check: every form, every incoming flag, actual ARM RET."""
    from differential import BASE
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
    from unicorn import arm64_const as arm
    stop = BASE + 0x800
    source, state_path = directory / 'flags-block.arm64', directory / 'flags-state.json'
    comparisons = cold = disk = 0
    corpus = hashlib.sha256()
    probes = [(form, 0b1010) for form in FLAG_FORMS] + [('RMIF', 0)]
    zero_map_receipt = None
    for form, mask in probes:
        words = [flag_encoding(form, rotation=63, mask=mask),
                 arithmetic(0, 0, 1, 28, 28, 1), encoding(1, 0, 0, 0, 31, 31), RET]
        code = struct.pack('<' + 'I' * len(words), *words)
        source.write_bytes(code)
        if form == 'RMIF' and mask == 0:
            output = directory / 'rmif-zero-block'
            manifest = json.loads(subprocess.check_output([str(cli), 'compile-block', str(source),
                '--guest-base', hex(BASE), '--output-dir', str(output), '--cpu-target', 'baseline'], timeout=15))
            native = (output / 'native.bin').read_bytes()
            offsets = [row[1] for row in manifest['source_map']]
            boundaries = {instruction.address for instruction in Cs(CS_ARCH_X86, CS_MODE_64).disasm(native, 0)}
            if (manifest['source_sha256'] != hashlib.sha256(code).hexdigest()
                    or manifest['native_sha256'] != hashlib.sha256(native).hexdigest()
                    or [row[0] for row in manifest['source_map']] != list(range(BASE, BASE + len(code), 4))
                    or any(a >= b for a, b in zip(offsets, offsets[1:]))
                    or any(offset not in boundaries for offset in offsets)):
                raise AssertionError('RMIF mask-zero block lacks distinct, aligned source-map intervals')
            zero_map_receipt = {'source_sha256': manifest['source_sha256'], 'native_sha256': manifest['native_sha256'],
                                'rmif_body_bytes': offsets[1] - offsets[0], 'source_map': manifest['source_map']}
            zero_map_receipt['retained_native_evidence'] = retain_flag_binary_evidence(code, output, zero_map_receipt)
        machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        machine.ctl_set_cpu_model(arm.UC_CPU_ARM64_MAX)
        machine.mem_map(BASE, 4096); machine.mem_write(BASE, code)
        for flag, template in enumerate(states(all_flags=True)):
            initial = State.from_buffer_copy(template)
            initial.x[1] = (0, MASK, 0xdeadc0de00000100, 0xdeadc0de00018000)[flag % 4]
            initial.x[30], initial.reserved = stop, 0x5a17c0de
            expected = flag_reference(words, initial)
            initialize_arm(machine, initial)
            machine.emu_start(BASE, stop, count=len(words) + 1)
            if machine.reg_read(arm.UC_ARM64_REG_PC) != stop or complete_state(capture_arm(machine, initial)) != expected:
                raise AssertionError('Original FlagM block/RET differs from mathematical state/PC')
            state_path.write_text(json.dumps(complete_state(initial)))
            result = json.loads(subprocess.check_output([str(cli), 'run-blocks', str(source), '--state', str(state_path),
                '--guest-base', hex(BASE), '--stop-pc', hex(stop), '--block-budget', '1', '--cpu-target', 'baseline',
                '--cache-dir', str(directory / 'flags-cache')], timeout=15))
            outcome = result['outcome']
            if (result['state'] != expected or result['pc'] != stop
                    or result['source_sha256'] != hashlib.sha256(code).hexdigest()
                    or result['abi'] != 'x86_64-sysv-guest-state-v2-block-exit-direct-ram'
                    or result['complete_binary_verified'] is not False
                    or outcome['reason'] != {'kind': 'stop_address'} or outcome['blocks_executed'] != 1
                    or outcome['compiled_blocks'] != int(flag == 0) or outcome['disk_cache_hits'] != int(flag != 0)):
                raise AssertionError('Native FlagM block/RET state, provenance or cache accounting mismatch')
            corpus.update(code); corpus.update(bytes(initial))
            corpus.update(json.dumps(result, sort_keys=True, separators=(',', ':')).encode())
            comparisons += 1; cold += outcome['compiled_blocks']; disk += outcome['disk_cache_hits']
    return {'original_math_native_state_pc_comparisons': comparisons, 'cold_compiles': cold,
            'disk_cache_hits': disk, 'result_corpus_sha256': corpus.hexdigest(),
            'rmif_mask_zero_source_map': zero_map_receipt}


def flag_semantic_sources():
    digest = hashlib.sha256(FLAG_SEMANTIC_ARCHIVE.read_bytes()).hexdigest()
    if digest != FLAG_SEMANTIC_ARCHIVE_SHA256:
        raise AssertionError('Flag semantic archive differs from the pinned Arm release')
    with tarfile.open(FLAG_SEMANTIC_ARCHIVE) as archive:
        sources = {name + '.xml': hashlib.sha256(archive.extractfile(
            f'ISA_A64_xml_A_profile-2026-06/{name}.xml').read()).hexdigest()
            for name in ('cfinv', 'rmif', 'setf', 'axflag', 'xaflag')}
    return {'archive': str(FLAG_SEMANTIC_ARCHIVE.relative_to(ROOT)), 'archive_sha256': digest,
            'xml_sha256': sources}


def run_flags(cli):
    from differential import BASE
    compiled, entries, words = flag_cases(), [], []
    executable_hash = hashlib.sha256(cli.read_bytes()).hexdigest()
    started = time.monotonic()
    for case in compiled:
        entries.append(len(words)); words.extend(case['words'])
    source = struct.pack('<' + 'I' * len(words), *words)
    with tempfile.TemporaryDirectory(prefix='stela-flags-') as temporary:
        directory = Path(temporary)
        path, output = directory / 'flags.arm64', directory / 'native'
        path.write_bytes(source)
        manifest = json.loads(subprocess.check_output([str(cli), 'compile-leaf', str(path), '--guest-base', hex(BASE),
            '--output-dir', str(output), '--cpu-target', 'baseline'], timeout=60))
        native = (output / 'native.bin').read_bytes()
        mapping = manifest['source_map']
        if (manifest['target_cpu'] != 'x86_64-baseline' or manifest['verified'] is not False
                or manifest['source_sha256'] != hashlib.sha256(source).hexdigest()
                or manifest['native_sha256'] != hashlib.sha256(native).hexdigest()
                or manifest['guest_instructions'] != len(words)
                or [row[0] for row in mapping] != list(range(BASE, BASE + len(source), 4))):
            raise AssertionError('Flag manifest does not bind baseline source/native bytes and every guest word')
        offsets = [row[1] for row in mapping] + [len(native)]
        if offsets[0] != 0 or any(a >= b for a, b in zip(offsets, offsets[1:])):
            raise AssertionError('Flag source-map intervals must remain nonempty, including RMIF mask zero')
        for case, entry in zip(compiled, entries):
            start, end = offsets[entry], offsets[entry + len(case['words'])]
            case['native'] = native[start:end]
            case['native_offsets'] = [offset - start for offset in offsets[entry:entry + len(case['words'])]]
        accounting = flag_binary_accounting(compiled, native)
        retained = retain_flag_binary_evidence(source, output, accounting)
        result = bounded_cases(compiled)
        blocks = flag_blocks(cli, directory)
    if hashlib.sha256(cli.read_bytes()).hexdigest() != executable_hash:
        raise AssertionError('Compiler executable changed during flag verification')
    report = {'kind': 'flagm_flagm2_arm_math_native_x86', 'passed': True, **result,
        'target_cpu': 'x86_64-baseline', 'forms': list(FLAG_FORMS), 'shared_block_dispatch': blocks,
        'native_binary_accounting': accounting, 'compiler_source_sha256': manifest['compiler_source_sha256'],
        'retained_native_evidence': retained,
        'compiler_executable_sha256': executable_hash, 'harness_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'shared_runner_sha256': hashlib.sha256((ROOT / 'dev/differential.py').read_bytes()).hexdigest(),
        'corpus_sha256': hashlib.sha256(source).hexdigest(), 'verification_wall_seconds': time.monotonic() - started,
        'semantic_sources': flag_semantic_sources(),
        'reference': 'Unicorn ARM64 MAX and independent Arm 2026-06 XML Boolean/integer semantics.',
        'limits': 'All 784 GuestState bytes compared; flag-only instructions do not access guest memory. '
                  'Leaf oracle stops before its final RET; shared-dispatch checks execute original RET. '
                  'Default Unicorn CPU lacks FlagM/FlagM2; MAX is explicitly selected. '
                  'Unicorn MAX rejects all 45 nonzero-CRm system encodings despite Arm XML ignored fields; '
                  'these have native/math-only credit and separate complete-state/PC rejection observations. '
                  'No disabled-feature exceptions, full PSTATE/DIT, hardware or application performance claim.'}
    write_evidence(ROOT / '.stela/flags-differential-report.json', report)
    print(json.dumps(report, indent=2))


def worker(pipe, compiled):
    try:
        family = compiled[0].get('family')
        execute = {'scalar_control': execute_scalar_control, 'flags': execute_flags}.get(family, execute_cases)
        pipe.send(execute(compiled))
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
        deadline = time.monotonic() + 600
        while not receive.poll(1):
            if process.exitcode is not None or time.monotonic() >= deadline:
                raise AssertionError(f'Arithmetic worker failed/timed out: {process.exitcode}')
        result = receive.recv()
        process.join(timeout=2)
        if process.exitcode != 0 or 'error' in result:
            raise AssertionError(f'Arithmetic suite failed: {result}, exit={process.exitcode}')
        return result
    finally:
        if process.is_alive():
            process.kill()
        process.join()
        receive.close()


def extended_blocks(cli, directory):
    """Run every option/shift through original RET and the shared native dispatcher."""
    from differential import initialize_arm, capture_arm
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
    from unicorn import arm64_const as arm
    base, stop = 0x100000, 0x100800
    source, state_path = directory / 'extended.arm64', directory / 'extended-state.json'
    checks = cold = disk = 0
    corpus = hashlib.sha256()
    samples = []
    for width in (0, 1):
        for subtract in (0, 1):
            for flags in (0, 1):
                for option in range(8):
                    for shift in range(5):
                        d = 31 if (option + shift) % 3 == 0 else 0
                        n = 31 if (option + shift) % 2 == 0 else 1
                        m = 31 if (option + shift) % 5 == 0 else 2
                        code = struct.pack('<2I', extended_encoding(width, subtract, flags, d, n, m, option, shift), RET)
                        source.write_bytes(code)
                        for index, template in enumerate(states(all_flags=True)):
                            initial = State.from_buffer_copy(template)
                            initial.reserved, initial.x[30] = 0x5a17c0de, stop
                            expected = mathematical_reference(list(struct.unpack('<2I', code)), initial)
                            machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
                            machine.mem_map(base, 4096); machine.mem_write(base, code)
                            machine.reg_write(arm.UC_ARM64_REG_PSTATE, 0)
                            initialize_arm(machine, initial)
                            machine.emu_start(base, stop, count=4)
                            assert machine.reg_read(arm.UC_ARM64_REG_PC) == stop
                            assert complete_state(capture_arm(machine, initial)) == expected
                            state_path.write_text(json.dumps(complete_state(initial)))
                            result = json.loads(subprocess.check_output([str(cli), 'run-blocks', str(source),
                                '--state', str(state_path), '--guest-base', hex(base), '--stop-pc', hex(stop),
                                '--block-budget', '1', '--cache-dir', str(directory / 'extended-cache')], timeout=15))
                            assert result['state'] == expected and result['pc'] == stop
                            assert result['source_sha256'] == hashlib.sha256(code).hexdigest()
                            assert result['abi'] == 'x86_64-sysv-guest-state-v2-block-exit-direct-ram'
                            assert result['complete_binary_verified'] is False
                            outcome = result['outcome']
                            assert outcome['reason'] == {'kind': 'stop_address'} and outcome['blocks_executed'] == 1
                            assert outcome['compiled_blocks'] == int(index == 0)
                            assert outcome['disk_cache_hits'] == int(index != 0)
                            checks += 1; cold += outcome['compiled_blocks']; disk += outcome['disk_cache_hits']
                            corpus.update(code); corpus.update(bytes(initial))
                            corpus.update(json.dumps(result, sort_keys=True, separators=(',', ':')).encode())
                            if option == 0 and shift == 0 and index == 0:
                                samples.append(result)
    return {'original_arm_math_native_state_pc_comparisons': checks, 'cold_compiles': cold,
            'disk_cache_hits': disk, 'result_corpus_sha256': corpus.hexdigest(), 'samples': samples}


def reject_reserved_extended(cli, directory):
    from differential import initialize_arm
    from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_ERR_EXCEPTION
    from unicorn import arm64_const as arm
    source = directory / 'reserved.arm64'
    comparisons = 0
    for width in (0, 1):
        for subtract in (0, 1):
            for flags in (0, 1):
                for option in range(8):
                    for shift in (5, 6, 7):
                        word = extended_encoding(width, subtract, flags, 0, 1, 2, option, shift)
                        code = struct.pack('<2I', word, RET)
                        source.write_bytes(code)
                        output = directory / f'reserved-{word:08x}'
                        native = subprocess.run([str(cli), 'compile-leaf', str(source), '--output-dir', str(output)],
                                                capture_output=True, text=True, timeout=15)
                        assert native.returncode and not output.exists(), native.stderr
                        machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
                        machine.mem_map(0x100000, 4096); machine.mem_write(0x100000, code)
                        initialize_arm(machine, states(all_flags=True)[0])
                        try:
                            machine.emu_start(0x100000, 0x100008, count=1)
                        except UcError as error:
                            assert error.errno == UC_ERR_EXCEPTION and machine.reg_read(arm.UC_ARM64_REG_PC) == 0x100000
                        else:
                            raise AssertionError(f'Reserved extended shift executed: {word:#x}')
                        comparisons += 1
    return comparisons


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--focus', choices=['scalar-control', 'flags'], help='Run only the selected implementation cohort')
    arguments = parser.parse_args()
    if not arguments.no_build:
        subprocess.run([str(ROOT / 'dev/cargo'), 'build', '--locked', '-p', 'stela-cli'], check=True)
    cli = ROOT / 'target/debug/stela'
    if arguments.focus == 'flags':
        run_flags(cli)
        return
    if arguments.focus == 'scalar-control':
        run_scalar_control(cli)
        return
    executable_hash = hashlib.sha256(cli.read_bytes()).hexdigest()
    compiled = carry_cases()
    legacy = hashlib.sha256(b''.join(struct.pack('<' + 'I' * len(c['words']), *c['words']) for c in compiled)).hexdigest()
    assert legacy == LEGACY_CARRY_CORPUS
    compiled += extended_cases()
    compiler = None
    corpus = hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix='stela-arithmetic-') as temporary:
        directory = Path(temporary)
        for index, case in enumerate(compiled):
            source = struct.pack('<' + 'I' * len(case['words']), *case['words'])
            corpus.update(source)
            input_path = directory / 'source.bin'
            input_path.write_bytes(source)
            output = directory / str(index)
            manifest = json.loads(subprocess.check_output([str(cli), 'compile-leaf', str(input_path),
                                                          '--output-dir', str(output)]))
            if compiler is not None and compiler != manifest['compiler_source_sha256']:
                raise AssertionError('Compiler changed during carry suite')
            compiler = manifest['compiler_source_sha256']
            case['native'] = (output / 'native.bin').read_bytes()
        result = bounded_cases(compiled)
        blocks = extended_blocks(cli, directory)
        reserved = reject_reserved_extended(cli, directory)
    assert hashlib.sha256(cli.read_bytes()).hexdigest() == executable_hash
    report = {'kind': 'add_sub_arithmetic_arm_vs_native_x86', 'passed': True, **result,
              'operations': ['ADC', 'ADCS', 'SBC/NGC', 'SBCS/NGCS',
                             'ADD/ADDS/SUB/SUBS extended W32/X64, including CMP/CMN aliases'],
              'reference': 'Unicorn ARM64 2.1.4 and independent unbounded signed/unsigned integer arithmetic',
              'native': 'direct x86-64 calls in isolated worker',
              'tested_state': ["V0..V31, FPCR and FPSR preservation", 'x0..x30', 'SP preservation', 'all 16 incoming NZCV combinations',
                               'W32 upper-half clearing', 'ZR sources/discarded destinations',
                               'carry/borrow and signed overflow boundaries', 'carry dependency chains',
                               'all eight extensions and five legal shifts per width/op/flags',
                               'SP left/nonflag destination versus ZR right/flag destination',
                               'extended-result aliases, sign-extension and fresh-flag chains'],
              'corpus_sha256': corpus.hexdigest(), 'compiler_source_sha256': compiler,
              'legacy_carry_corpus_sha256': legacy, 'extended_block_dispatch': blocks,
              'reserved_shift_original_undefined_native_declines': reserved,
              'compiler_executable_sha256': executable_hash,
              'harness_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'shared_runner_sha256': hashlib.sha256((ROOT / 'dev/differential.py').read_bytes()).hexdigest(),
              'limits': 'Register arithmetic and complete GPR/SP/NZCV/reserved/V/FP state, plus real RET/shared block dispatch. Full PSTATE, guest exception delivery, memory, SIMD arithmetic, PAC and OS boot are not covered.'}
    write_evidence(ROOT / '.stela/arithmetic-differential-report.json', report)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
