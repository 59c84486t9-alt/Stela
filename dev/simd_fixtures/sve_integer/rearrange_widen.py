"""Pure streaming-SVE extension, pair arithmetic and narrowing-high semantics.

P, GPR/SP, NZCV, FPCR/FPSR, FFR, ZA/ZT and RAM are unchanged. Shared execution
guards own feature/mode and MOVPRFX checks; this module has no state ABI.
"""
from __future__ import annotations
from dataclasses import dataclass

BITS_PER_BYTE = 8
VECTOR_REGISTER_COUNT = 32
PREDICATE_REGISTER_COUNT = 16
PREDICATE_ENCODING_COUNT = 8
MIN_VECTOR_BITS = 128
MAX_VECTOR_BITS = 2048
SIZE_SHIFT = 22
SOURCE_SHIFT = 5
SECOND_SOURCE_SHIFT = 16
PREDICATE_SHIFT = 10
REGISTER_MASK = VECTOR_REGISTER_COUNT - 1
PREDICATE_MASK = PREDICATE_ENCODING_COUNT - 1
SIZE_MASK = 3
FORM_ENCODINGS = {
    'ADDHNB': ('addhnb_z_zz_', 0xff20fc00, 0x45206000),
    'ADDHNT': ('addhnt_z_zz_', 0xff20fc00, 0x45206400),
    'ADDP': ('addp_z_p_zz_', 0xff3fe000, 0x4411a000),
    'RADDHNB': ('raddhnb_z_zz_', 0xff20fc00, 0x45206800),
    'RADDHNT': ('raddhnt_z_zz_', 0xff20fc00, 0x45206c00),
    'RSUBHNB': ('rsubhnb_z_zz_', 0xff20fc00, 0x45207800),
    'RSUBHNT': ('rsubhnt_z_zz_', 0xff20fc00, 0x45207c00),
    'SADALP': ('sadalp_z_p_z_', 0xff3fe000, 0x4404a000),
    'SMAXP': ('smaxp_z_p_zz_', 0xff3fe000, 0x4414a000),
    'SMINP': ('sminp_z_p_zz_', 0xff3fe000, 0x4416a000),
    'SUBHNB': ('subhnb_z_zz_', 0xff20fc00, 0x45207000),
    'SUBHNT': ('subhnt_z_zz_', 0xff20fc00, 0x45207400),
    'SUNPKHI': ('sunpkhi_z_z_', 0xff3ffc00, 0x05313800),
    'SUNPKLO': ('sunpklo_z_z_', 0xff3ffc00, 0x05303800),
    'SXTB': ('sxtb_z_p_z_m', 0xff3fe000, 0x0410a000),
    'SXTH': ('sxth_z_p_z_m', 0xff3fe000, 0x0412a000),
    'SXTW': ('sxtw_z_p_z_m', 0xff3fe000, 0x0414a000),
    'UADALP': ('uadalp_z_p_z_', 0xff3fe000, 0x4405a000),
    'UMAXP': ('umaxp_z_p_zz_', 0xff3fe000, 0x4415a000),
    'UMINP': ('uminp_z_p_zz_', 0xff3fe000, 0x4417a000),
    'UUNPKHI': ('uunpkhi_z_z_', 0xff3ffc00, 0x05333800),
    'UUNPKLO': ('uunpklo_z_z_', 0xff3ffc00, 0x05323800),
    'UXTB': ('uxtb_z_p_z_m', 0xff3fe000, 0x0411a000),
    'UXTH': ('uxth_z_p_z_m', 0xff3fe000, 0x0413a000),
    'UXTW': ('uxtw_z_p_z_m', 0xff3fe000, 0x0415a000),
}
CANONICAL_FORMS = tuple(row[0] for row in FORM_ENCODINGS.values())
VECTOR_LENGTHS = (16, 32, 64, 128, 256)
FORMS = frozenset(FORM_ENCODINGS)
PAIRWISE = frozenset(('ADDP', 'SMAXP', 'SMINP', 'UMAXP', 'UMINP'))
ACCUMULATE = frozenset(('SADALP', 'UADALP'))
UNPACK = frozenset(('SUNPKHI', 'SUNPKLO', 'UUNPKHI', 'UUNPKLO'))
EXTEND = frozenset(('SXTB', 'SXTH', 'SXTW', 'UXTB', 'UXTH', 'UXTW'))
NARROW = frozenset(FORMS) - PAIRWISE - ACCUMULATE - UNPACK - EXTEND
EXTEND_INPUT_BITS = {'B': 8, 'H': 16, 'W': 32}


@dataclass(frozen=True)
class Operand:
    operation: str
    destination: int
    left: int = 0
    right: int | None = None
    predicate: int | None = None
    element_bytes: int = 1


def allocated_widths(mnemonic):
    if mnemonic not in FORMS:
        raise ValueError('unknown operation')
    if mnemonic in PAIRWISE:
        return (8, 16, 32, 64)
    if mnemonic in EXTEND:
        source_bits = EXTEND_INPUT_BITS[mnemonic[-1]]
        return tuple(bits for bits in (16, 32, 64) if bits > source_bits)
    return (16, 32, 64)


def encode(op):
    if op.operation not in FORMS or (op.element_bytes * BITS_PER_BYTE) not in allocated_widths(op.operation):
        raise ValueError('unallocated mnemonic or element width')
    for register in (op.destination, op.left, op.right):
        if register is not None and not 0 <= register < VECTOR_REGISTER_COUNT:
            raise ValueError('vector register out of range')
    _, _, encoding_value = FORM_ENCODINGS[op.operation]
    size = op.element_bytes.bit_length() - 1
    word = encoding_value | size << SIZE_SHIFT | op.destination
    if op.operation in PAIRWISE:
        if op.left != op.destination or op.right is None:
            raise ValueError('pairwise first input must be old destination')
        word |= op.right << SOURCE_SHIFT
    else:
        word |= op.left << SOURCE_SHIFT
    if op.operation in NARROW:
        if op.right is None:
            raise ValueError('narrowing requires both sources')
        word |= op.right << SECOND_SOURCE_SHIFT
    elif op.operation not in PAIRWISE and op.right is not None:
        raise ValueError('unexpected second source')
    if op.operation in PAIRWISE | ACCUMULATE | EXTEND:
        if op.predicate is None or not 0 <= op.predicate < PREDICATE_ENCODING_COUNT:
            raise ValueError('predicate must be P0..P7')
        word |= op.predicate << PREDICATE_SHIFT
    elif op.predicate is not None:
        raise ValueError('unexpected predicate')
    return word


def decode(word):
    if not 0 <= word < 1 << 32:
        raise ValueError('word out of range')
    for name, (_, encoding_mask, encoding_value) in FORM_ENCODINGS.items():
        if word & encoding_mask != encoding_value:
            continue
        bits = BITS_PER_BYTE << ((word >> SIZE_SHIFT) & SIZE_MASK)
        if bits not in allocated_widths(name):
            raise ValueError('reserved size')
        destination = word & REGISTER_MASK
        source = (word >> SOURCE_SHIFT) & REGISTER_MASK
        second = (word >> SECOND_SOURCE_SHIFT) & REGISTER_MASK if name in NARROW else None
        predicate = (word >> PREDICATE_SHIFT) & PREDICATE_MASK if name in PAIRWISE | ACCUMULATE | EXTEND else None
        if name in PAIRWISE:
            source, second = destination, source
        return Operand(name, destination, source, second, predicate, bits // BITS_PER_BYTE)
    return None


def _signed(value, bits):
    sign_bit = 1 << (bits - 1)
    return (value ^ sign_bit) - sign_bit


def _lanes(raw, bits):
    size = bits // BITS_PER_BYTE
    return [int.from_bytes(raw[offset:offset + size], 'little') for offset in range(0, len(raw), size)]


def _bytes(lanes, bits):
    lane_mask = (1 << bits) - 1
    size = bits // BITS_PER_BYTE
    return b''.join((lane & lane_mask).to_bytes(size, 'little') for lane in lanes)


def _active(predicate, lane, element_bits):
    bit = lane * (element_bits // BITS_PER_BYTE)
    return bool(predicate[bit // BITS_PER_BYTE] & (1 << (bit % BITS_PER_BYTE)))


def _validate_state(z, p):
    if len(z) != VECTOR_REGISTER_COUNT or len(p) != PREDICATE_REGISTER_COUNT:
        raise ValueError('complete Z/P register banks required')
    vector_bytes = len(z[0])
    vector_bits = vector_bytes * BITS_PER_BYTE
    if not MIN_VECTOR_BITS <= vector_bits <= MAX_VECTOR_BITS or vector_bits & (vector_bits - 1):
        raise ValueError('streaming VL must be 128..2048 bits and a power of two')
    if any(len(register) != vector_bytes for register in z):
        raise ValueError('inconsistent Z widths')
    if any(len(register) * BITS_PER_BYTE != vector_bytes for register in p):
        raise ValueError('P register requires one bit per vector byte')


def apply(op: Operand, z, p) -> tuple[bytes, ...]:
    """Return a full immutable Z bank. P and every non-vector state field are unchanged.

    All sources and old destination are immutable snapshots, including every alias.
    element_bytes is source width for narrowing, result width for other families.
    """
    _validate_state(z, p)
    encode(op)
    z = tuple(bytes(vector) for vector in z)
    p = tuple(bytes(predicate) for predicate in p)
    name, bits = op.operation, (op.element_bytes * BITS_PER_BYTE)
    old = _lanes(z[op.destination], bits)
    source = _lanes(z[op.left], bits)
    predicate = p[op.predicate] if op.predicate is not None else None
    if name in UNPACK:
        half_bits = bits // 2
        inputs = _lanes(z[op.left], half_bits)
        offset = len(old) if name.endswith('HI') else 0
        selected = inputs[offset:offset + len(old)]
        result = [_signed(value, half_bits) if name.startswith('S') else value for value in selected]
        raw = _bytes(result, bits)
    elif name in EXTEND:
        low_bits = EXTEND_INPUT_BITS[name[-1]]
        low_mask = (1 << low_bits) - 1
        result = list(old)
        for lane, value in enumerate(source):
            if _active(predicate, lane, bits):
                value &= low_mask
                result[lane] = _signed(value, low_bits) if name.startswith('S') else value
        raw = _bytes(result, bits)
    elif name in NARROW:
        half_bits = bits // 2
        second = _lanes(z[op.right], bits)
        top = name.endswith('T')
        rounded = name.startswith('R')
        subtract = 'SUB' in name
        result = _lanes(z[op.destination], half_bits) if top else [0] * (len(old) * 2)
        rounding = 1 << (half_bits - 1) if rounded else 0
        for lane, (left, right) in enumerate(zip(source, second)):
            total = left - right if subtract else left + right
            result[2 * lane + int(top)] = (total + rounding) >> half_bits
        raw = _bytes(result, half_bits)
    elif name in ACCUMULATE:
        half_bits = bits // 2
        inputs = _lanes(z[op.left], half_bits)
        result = list(old)
        for lane, accumulator in enumerate(old):
            if _active(predicate, lane, bits):
                left, right = inputs[2 * lane:2 * lane + 2]
                if name.startswith('S'):
                    left, right = _signed(left, half_bits), _signed(right, half_bits)
                result[lane] = accumulator + left + right
        raw = _bytes(result, bits)
    else:
        second = _lanes(z[op.right], bits)
        result = list(old)
        for lane in range(len(old)):
            if not _active(predicate, lane, bits):
                continue
            inputs = old if lane % 2 == 0 else second
            pair = lane & ~1
            left, right = inputs[pair:pair + 2]
            if name.startswith('S'):
                left, right = _signed(left, bits), _signed(right, bits)
            if name == 'ADDP':
                result[lane] = left + right
            elif 'MAX' in name:
                result[lane] = max(left, right)
            else:
                result[lane] = min(left, right)
        raw = _bytes(result, bits)
    result_z = list(z)
    result_z[op.destination] = raw
    return tuple(result_z)



def _fixture_plans():
    for name in sorted(FORMS):
        for bits in allocated_widths(name):
            for destination, left, right, alias in ((0, 1, 2, 'distinct'), (31, 31, 31, 'all_alias')):
                yield name, bits, destination, left, right, alias, 'all'
        bits = min(allocated_widths(name))
        for destination, left, right, alias in ((7, 7, 8, 'destination_left'), (7, 8, 7, 'destination_right')):
            yield name, bits, destination, left, right, alias, 'all'
        if name in PAIRWISE | ACCUMULATE | EXTEND:
            for predicate in ('empty_dirty', 'first_dirty', 'last_dirty', 'alternating_dirty'):
                yield name, bits, 7, 8, 9, 'distinct_predicate', predicate


def _fixture_edge_vector(length, bits, offset):
    mask = (1 << bits) - 1
    half = bits // 2
    threshold = 1 << (half - 1)
    values = (0, mask, 1 << (bits - 1), (1 << (bits - 1)) - 1,
              (1 << half) - 1, 1 << half, threshold - 1, threshold, threshold + 1, 1)
    return b''.join(values[(lane + offset) % len(values)].to_bytes(bits // 8, 'little')
                    for lane in range(length * 8 // bits))


def lazy_cases(vector_bytes):
    """Yield bounded full-frame fixture cases through the shared lazy API.

    Full architectural banks stay portable; no native context offsets are used.
    Original FFR/FPMR access remains unobserved in the SME-only oracle profile.
    """
    from dataclasses import asdict
    import struct
    import scalable_frame as frame

    length = frame.require_sme_length(vector_bytes)
    for index, (name, bits, destination, left, right, alias, mode) in enumerate(_fixture_plans()):
        predicated = name in PAIRWISE | ACCUMULATE | EXTEND
        if name in PAIRWISE: left = destination
        op = Operand(name, destination, left, right if name in PAIRWISE | NARROW else None,
                             7 if predicated else None, bits // 8)
        word = encode(op)
        initial = frame.seeded_snapshot(length, f'widen-{length}-{index}-{word:08x}'.encode())
        primary = bytearray(initial.primary)
        fpcr = 0x03c00000 if index % 2 else 0
        fpsr = 0x0800001f if index % 2 else 0
        struct.pack_into('<II', primary, frame.PRIMARY_FPCR_OFFSET, fpcr, fpsr)
        vectors = list(initial.z)
        input_bits = bits // 2 if name in UNPACK | ACCUMULATE else bits
        for register in {destination, left, right}:
            vectors[register] = _fixture_edge_vector(length, input_bits, index + register)
        predicates = list(initial.p)
        if predicated:
            element_bytes = bits // 8
            irrelevant = sum(1 << bit for bit in range(length) if bit % element_bytes)
            if mode == 'all': mask = (1 << length) - 1
            elif mode == 'empty_dirty': mask = irrelevant
            elif mode == 'first_dirty': mask = irrelevant | 1
            elif mode == 'last_dirty': mask = irrelevant | 1 << (length - element_bytes)
            else: mask = irrelevant | sum(1 << bit for bit in range(0, length, element_bytes * 2))
            predicates[7] = mask.to_bytes(length // 8, 'little')
        initial = frame.snapshot_from_banks(length, primary=bytes(primary), z=tuple(vectors), p=tuple(predicates),
                                           ffr=initial.ffr, za=initial.za, zt0=initial.zt0, valid=initial.valid,
                                           controls={**initial.controls, 'requested_fpcr': fpcr, 'requested_fpsr': fpsr})
        output = apply(op, initial.z, initial.p)
        expected = frame.snapshot_from_banks(length, primary=initial.primary, z=output, p=initial.p,
                                            ffr=initial.ffr, za=initial.za, zt0=initial.zt0,
                                            valid=initial.valid, controls=initial.controls)
        yield {'operation': {'word': word, 'canonical_id': FORM_ENCODINGS[name][0],
                             'operand': asdict(op), 'alias': alias, 'predicate_mode': mode},
               'initial': initial, 'expected': expected, 'required': int(initial.valid)}
