"""Independent streaming current-SVL byte model.

state = {'z': tuple[bytes]*32, 'p': tuple[int]*16, 'x': tuple[int]*31,
         ...opaque full architectural fields...}; all non-Z fields preserved.
Predicate bit n represents architectural predicate bit n (one per byte).
"""
from dataclasses import dataclass
REGISTER_COUNT = 32
SEGMENT_BYTES = 16
MIN_VECTOR_BYTES = 16
MAX_VECTOR_BYTES = 256
SIZE_SHIFT = 22
SIZE_MASK = 3
SOURCE_SHIFT = 5
SECOND_SHIFT = 16
PREDICATE_SHIFT = 10
BITS_PER_BYTE = 8
QWORD_BYTES = SEGMENT_BYTES // 2
EXT_LOW_BITS = 3
EXT_LOW_MASK = 7
EXT_MAXIMUM = 255
LOGICAL_FIELD_MASK = 63
LOGICAL_ROTATION_SHIFT = 6
LOGICAL_N_SHIFT = 12
LOGICAL_ELEMENT_BITS = 64
LOGICAL_IMMEDIATE_MASK = (1 << 13) - 1
DUPQ_SIZE_MASK = 15
IMMEDIATE_SIGN_BIT = 16
IMMEDIATE_SIGN_MODULUS = 32
REGISTER_MASK = 31
PREDICATE_MASK = 7

@dataclass(frozen=True)
class Operation:
    canonical: str
    mnemonic: str
    destination: int
    source: int
    second: int
    element_bytes: int
    predicate: int
    immediate: int
    segment: bool
FORMS = ({'id': 'dupq_z_zi_',
  'mnemonic': 'DUPQ',
  'encoding_mask': '0xffe0fc00',
  'encoding_value': '0x05202400'},
 {'id': 'ext_z_zi_con',
  'mnemonic': 'EXT',
  'encoding_mask': '0xffe0e000',
  'encoding_value': '0x05600000'},
 {'id': 'ext_z_zi_des',
  'mnemonic': 'EXT',
  'encoding_mask': '0xffe0e000',
  'encoding_value': '0x05200000'},
 {'id': 'extq_z_zi_des',
  'mnemonic': 'EXTQ',
  'encoding_mask': '0xfff0fc00',
  'encoding_value': '0x05602400'},
 {'id': 'rev_z_z_',
  'mnemonic': 'REV',
  'encoding_mask': '0xff3ffc00',
  'encoding_value': '0x05383800'},
 {'id': 'revd_z_p_z_m',
  'mnemonic': 'REVD',
  'encoding_mask': '0xffffe000',
  'encoding_value': '0x052e8000'},
 {'id': 'splice_z_p_zz_con',
  'mnemonic': 'SPLICE',
  'encoding_mask': '0xff3fe000',
  'encoding_value': '0x052d8000'},
 {'id': 'splice_z_p_zz_des',
  'mnemonic': 'SPLICE',
  'encoding_mask': '0xff3fe000',
  'encoding_value': '0x052c8000'},
 {'id': 'tbl_z_zz_1',
  'mnemonic': 'TBL',
  'encoding_mask': '0xff20fc00',
  'encoding_value': '0x05203000'},
 {'id': 'tbl_z_zz_2',
  'mnemonic': 'TBL',
  'encoding_mask': '0xff20fc00',
  'encoding_value': '0x05202800'},
 {'id': 'tblq_z_zz_',
  'mnemonic': 'TBLQ',
  'encoding_mask': '0xff20fc00',
  'encoding_value': '0x4400f800'},
 {'id': 'tbx_z_zz_',
  'mnemonic': 'TBX',
  'encoding_mask': '0xff20fc00',
  'encoding_value': '0x05202c00'},
 {'id': 'tbxq_z_zz_',
  'mnemonic': 'TBXQ',
  'encoding_mask': '0xff20fc00',
  'encoding_value': '0x05203400'},
 {'id': 'trn1_z_zz_',
  'mnemonic': 'TRN1',
  'encoding_mask': '0xff20fc00',
  'encoding_value': '0x05207000'},
 {'id': 'trn2_z_zz_',
  'mnemonic': 'TRN2',
  'encoding_mask': '0xff20fc00',
  'encoding_value': '0x05207400'},
 {'id': 'uzp1_z_zz_',
  'mnemonic': 'UZP1',
  'encoding_mask': '0xff20fc00',
  'encoding_value': '0x05206800'},
 {'id': 'uzp2_z_zz_',
  'mnemonic': 'UZP2',
  'encoding_mask': '0xff20fc00',
  'encoding_value': '0x05206c00'},
 {'id': 'uzpq1_z_zz_',
  'mnemonic': 'UZPQ1',
  'encoding_mask': '0xff20fc00',
  'encoding_value': '0x4400e800'},
 {'id': 'uzpq2_z_zz_',
  'mnemonic': 'UZPQ2',
  'encoding_mask': '0xff20fc00',
  'encoding_value': '0x4400ec00'},
 {'id': 'zip1_z_zz_',
  'mnemonic': 'ZIP1',
  'encoding_mask': '0xff20fc00',
  'encoding_value': '0x05206000'},
 {'id': 'zip2_z_zz_',
  'mnemonic': 'ZIP2',
  'encoding_mask': '0xff20fc00',
  'encoding_value': '0x05206400'},
 {'id': 'zipq1_z_zz_',
  'mnemonic': 'ZIPQ1',
  'encoding_mask': '0xff20fc00',
  'encoding_value': '0x4400e000'},
 {'id': 'zipq2_z_zz_',
  'mnemonic': 'ZIPQ2',
  'encoding_mask': '0xff20fc00',
  'encoding_value': '0x4400e400'},
 {'id': 'dupm_z_i_',
  'mnemonic': 'DUPM',
  'encoding_mask': '0xfffc0000',
  'encoding_value': '0x05c00000'},
 {'id': 'index_z_ii_',
  'mnemonic': 'INDEX',
  'encoding_mask': '0xff20fc00',
  'encoding_value': '0x04204000'},
 {'id': 'index_z_ir_',
  'mnemonic': 'INDEX',
  'encoding_mask': '0xff20fc00',
  'encoding_value': '0x04204800'},
 {'id': 'index_z_ri_',
  'mnemonic': 'INDEX',
  'encoding_mask': '0xff20fc00',
  'encoding_value': '0x04204400'},
 {'id': 'index_z_rr_',
  'mnemonic': 'INDEX',
  'encoding_mask': '0xff20fc00',
  'encoding_value': '0x04204c00'})


def decode(word):
    if type(word) is not int or not 0 <= word < 1 << 32:
        raise ValueError('instruction word must be u32')
    matches = [f for f in FORMS if word & int(f['encoding_mask'], 16) == int(f['encoding_value'], 16)]
    if not matches:
        return None
    if len(matches) != 1:
        raise AssertionError('overlapping exact forms')
    f = matches[0]
    name = f['mnemonic']
    width = 1 << (word >> SIZE_SHIFT & SIZE_MASK)
    d, n, m = (word & REGISTER_MASK, word >> SOURCE_SHIFT & REGISTER_MASK, word >> SECOND_SHIFT & REGISTER_MASK)
    pred = word >> PREDICATE_SHIFT & PREDICATE_MASK
    immediate = 0
    if name == 'DUPQ':
        tsz = word >> SECOND_SHIFT & 15
        if not tsz:
            raise ValueError('DUPQ reserved tsz=0')
        lowbit = (tsz & -tsz).bit_length() - 1
        width = 1 << lowbit
        immediate = (word >> SECOND_SHIFT & 31) >> lowbit + 1
    elif name == 'REVD':
        width = SEGMENT_BYTES
    elif name in {'EXT', 'EXTQ'}:
        width = 1
        immediate = (word >> SECOND_SHIFT & 31) * 8 + (word >> PREDICATE_SHIFT & 7) if name == 'EXT' else word >> SECOND_SHIFT & 15
    elif name == 'DUPM':
        width = 8
        immediate = decode_bitmask(word >> SOURCE_SHIFT & 8191)
    return Operation(f['id'], name, d, n, m, width, pred, immediate, 'Q' in name)

def decode_bitmask(imm13):
    n, imms, immr = (imm13 >> LOGICAL_N_SHIFT, imm13 & LOGICAL_FIELD_MASK, imm13 >> LOGICAL_ROTATION_SHIFT & LOGICAL_FIELD_MASK)
    length = (n << LOGICAL_ROTATION_SHIFT | imms ^ LOGICAL_FIELD_MASK).bit_length() - 1
    if length < 1:
        raise ValueError('DUPM reserved element length')
    levels = (1 << length) - 1
    s, r = (imms & levels, immr & levels)
    if s == levels:
        raise ValueError('DUPM reserved all-ones element')
    width = 1 << length
    ones = (1 << s + 1) - 1
    rotated = (ones >> r | ones << (width - r) % width) & (1 << width) - 1
    result = 0
    for shift in range(0, LOGICAL_ELEMENT_BITS, width):
        result |= rotated << shift
    return result

def _signed_five(value):
    return value - IMMEDIATE_SIGN_MODULUS if value & IMMEDIATE_SIGN_BIT else value

def _elements(data, width):
    return [data[i:i + width] for i in range(0, len(data), width)]

def execute(state, word):
    op = decode(word)
    if op is None:
        raise ValueError('not an assigned rearrange encoding')
    vectors = tuple(state['z'])
    vl = len(vectors[0])
    if vl < MIN_VECTOR_BYTES or vl > MAX_VECTOR_BYTES or vl & vl - 1 or (len(vectors) != REGISTER_COUNT) or any((len(z) != vl for z in vectors)):
        raise ValueError('invalid current-SVL Z bank')
    name, width = (op.mnemonic, op.element_bytes)
    n, m, d = (op.source, op.second, op.destination)
    src, other, old = (vectors[n], vectors[m], vectors[d])
    if name in {'EXT', 'SPLICE'}:
        if op.canonical.endswith('_con'):
            src, other = (vectors[n], vectors[(n + 1) % REGISTER_COUNT])
        else:
            src, other = (old, vectors[n])
    if name == 'DUPM':
        result = op.immediate.to_bytes(8, 'little') * (vl // 8)
    elif name == 'INDEX':
        suffix = op.canonical.split('_')[2]
        first = _signed_five(n) if suffix[0] == 'i' else state['x'][n] if n != 31 else 0
        step = _signed_five(m) if suffix[1] == 'i' else state['x'][m] if m != 31 else 0
        mask = (1 << width * 8) - 1
        result = b''.join(((first + i * step & mask).to_bytes(width, 'little') for i in range(vl // width)))
    elif name == 'EXT':
        offset = op.immediate if op.immediate < vl else 0
        result = (src + other)[offset:offset + vl]
    elif name == 'SPLICE':
        active = [i for i in range(vl // width) if state['p'][op.predicate] >> i * width & 1]
        prefix = src[active[0] * width:(active[-1] + 1) * width] if active else b''
        result = prefix + other[:vl - len(prefix)]
    elif name == 'REV':
        result = b''.join(reversed(_elements(src, width)))
    elif name == 'REVD':
        result = b''.join((src[i + QWORD_BYTES:i + SEGMENT_BYTES] + src[i:i + QWORD_BYTES] if state['p'][op.predicate] >> i & 1 else old[i:i + SEGMENT_BYTES] for i in range(0, vl, SEGMENT_BYTES)))
    else:
        segment_bytes = SEGMENT_BYTES if op.segment else vl
        output = []
        for start in range(0, vl, segment_bytes):
            a, b, c = (_elements(src[start:start + segment_bytes], width), _elements(other[start:start + segment_bytes], width), _elements(old[start:start + segment_bytes], width))
            count = len(a)
            part = 1 if name.endswith('2') else 0
            if name in {'ZIP1', 'ZIP2', 'ZIPQ1', 'ZIPQ2'}:
                base = part * (count // 2)
                lanes = [x for pair in zip(a[base:base + count // 2], b[base:base + count // 2]) for x in pair]
            elif name in {'TRN1', 'TRN2'}:
                lanes = [x for pair in zip(a[part::2], b[part::2]) for x in pair]
            elif name in {'UZP1', 'UZP2', 'UZPQ1', 'UZPQ2'}:
                lanes = a[part::2] + b[part::2]
            elif name == 'DUPQ':
                lanes = [a[op.immediate]] * count
            elif name == 'EXTQ':
                chunk = old[start:start + SEGMENT_BYTES] + vectors[n][start:start + SEGMENT_BYTES]
                lanes = [chunk[op.immediate:op.immediate + SEGMENT_BYTES]]
            elif name in {'TBL', 'TBX', 'TBLQ', 'TBXQ'}:
                table = a
                if op.canonical == 'tbl_z_zz_2':
                    table = a + _elements(vectors[(n + 1) % REGISTER_COUNT], width)
                lanes = []
                for index, prior in zip(b, c):
                    ix = int.from_bytes(index, 'little')
                    lanes.append(table[ix] if ix < len(table) else prior if name.startswith('TBX') else bytes(width))
            else:
                raise AssertionError(name)
            output.append(b''.join(lanes))
        result = b''.join(output)
    if len(result) != vl:
        raise AssertionError((op, len(result), vl))
    updated = list(vectors)
    updated[d] = result
    return {**state, 'z': tuple(updated)}


CANONICAL_FORMS = tuple(form['id'] for form in FORMS)

def _fixture_words(form, length):
    base = int(form['encoding_value'], 16)
    mask = int(form['encoding_mask'], 16)
    name = form['mnemonic']
    sizes = range(SIZE_MASK + 1) if not mask & SIZE_MASK << SIZE_SHIFT else (0,)
    for size in sizes:
        value = base | size << SIZE_SHIFT
        immediates = (0,)
        if name == 'EXT':
            immediates = tuple(dict.fromkeys((0, 1, 15, 16, length - 1, min(length, EXT_MAXIMUM), EXT_MAXIMUM)))
        elif name == 'EXTQ':
            immediates = (0, 1, 15)
        elif name == 'DUPQ':
            immediates = (1, 3, 2, 6, 4, 12, 8, 24)
        elif name == 'DUPM':
            immediates = (0, 4096, 8064, 3840)
        for immediate in immediates:
            for alias, source, second, destination in (('distinct', 1, 2, 3), ('inplace', 1, 2, 1), ('wrap', 31, 0, 31)):
                word = value | (source << SOURCE_SHIFT | second << SECOND_SHIFT | destination) & ~mask
                if name == 'DUPQ':
                    word = base | immediate << SECOND_SHIFT | source << SOURCE_SHIFT | destination
                elif name == 'DUPM':
                    word = base | immediate << SOURCE_SHIFT | destination
                elif name == 'EXT':
                    word = base | immediate >> EXT_LOW_BITS << SECOND_SHIFT | (immediate & EXT_LOW_MASK) << PREDICATE_SHIFT | source << SOURCE_SHIFT | destination
                elif name == 'EXTQ':
                    word = base | immediate << SECOND_SHIFT | source << SOURCE_SHIFT | destination
                yield (word, alias)

def lazy_cases(vector_bytes):
    """Yield complete immutable frames for the shared original/native family runner.

    The bounded directed cohort covers every allocated width, streaming length,
    source alias and wrap boundary. FFR/FPMR receive no architectural credit.
    """
    import scalable_frame as frame
    length = frame.require_sme_length(vector_bytes)
    for form in FORMS:
        for word, alias in _fixture_words(form, length):
            op = decode(word)
            seed = f'{length}/{word:08x}/{alias}'.encode()
            initial = frame.seeded_snapshot(length, seed)
            state = frame.snapshot_to_state(initial)
            if op.mnemonic in {'SPLICE', 'REVD'}:
                predicates = (0, (1 << length) - 1, 1 << op.element_bytes | 1 << 3 * op.element_bytes)
            else:
                predicates = (state['p'][op.predicate],)
            for predicate in predicates:
                current = {**state, 'p': list(state['p'])}
                current['p'][op.predicate] = predicate & (1 << length) - 1
                if op.mnemonic in {'TBL', 'TBX', 'TBLQ', 'TBXQ'}:
                    vectors = list(current['z'])
                    count = (SEGMENT_BYTES if op.segment else length) // op.element_bytes
                    if op.canonical == 'tbl_z_zz_2':
                        count *= 2
                    maximum = (1 << BITS_PER_BYTE * op.element_bytes) - 1
                    values = tuple((value for value in (0, count - 1, count, maximum) if value <= maximum))
                    vectors[op.second] = b''.join((values[i % len(values)].to_bytes(op.element_bytes, 'little') for i in range(length // op.element_bytes)))
                    current['z'] = vectors
                initial_case = frame.snapshot_from_state(initial, current)
                expected = frame.snapshot_from_state(initial_case, execute(current, word))
                yield {'operation': {'word': word, 'canonical_id': op.canonical, 'alias': alias}, 'initial': initial_case, 'expected': expected, 'required': int(initial_case.valid)}
