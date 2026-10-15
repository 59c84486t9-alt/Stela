"""Pure SME2 register-only table and group rearrangement fixtures.

Z/P/ZT0 storage and streaming guards belong to the shared streaming harness.
Selection reuses the shared CounterToPredicate helper; tests may inject an oracle.
"""
from dataclasses import dataclass

from simd_fixtures.sve_memory.counter import counter_bits

VECTOR_REGISTER_COUNT = 32
BYTE_BITS = 8
ZT0_BYTES = 64
MIN_SVL_BITS = 128
MAX_SVL_BITS = 2048
COUNTER_PREDICATE_BASE = 8
FORMS = {
    'luti2_mz2_ztz_1': (0xc08c4000, 0xfffc4c01, {'i3': (15, 3), 'size': (12, 2), 'Zn': (5, 5), 'Zd': (1, 4)}),
    'luti2_mz2_ztz_8': (0xc09c4000, 0xfffc4c08, {'i3': (15, 3), 'size': (12, 2), 'Zn': (5, 5), 'D': (4, 1), 'Zd': (0, 3)}),
    'luti2_mz4_ztz_1': (0xc08c8000, 0xfffccc03, {'i2': (16, 2), 'size': (12, 2), 'Zn': (5, 5), 'Zd': (2, 3)}),
    'luti2_mz4_ztz_4': (0xc09c8000, 0xfffccc0c, {'i2': (16, 2), 'size': (12, 2), 'Zn': (5, 5), 'D': (4, 1), 'Zd': (0, 2)}),
    'luti2_z_ztz_': (0xc0cc0000, 0xfffc0c00, {'i4': (14, 4), 'size': (12, 2), 'Zn': (5, 5), 'Zd': (0, 5)}),
    'luti4_mz2_ztz_1': (0xc08a4000, 0xfffe4c01, {'i2': (15, 2), 'size': (12, 2), 'Zn': (5, 5), 'Zd': (1, 4)}),
    'luti4_mz2_ztz_8': (0xc09a4000, 0xfffe4c08, {'i2': (15, 2), 'size': (12, 2), 'Zn': (5, 5), 'D': (4, 1), 'Zd': (0, 3)}),
    'luti4_mz4_ztz_1': (0xc08a8000, 0xfffecc03, {'i1': (16, 1), 'size': (12, 2), 'Zn': (5, 5), 'Zd': (2, 3)}),
    'luti4_mz4_ztz_4': (0xc09a8000, 0xfffecc0c, {'i1': (16, 1), 'size': (12, 2), 'Zn': (5, 5), 'D': (4, 1), 'Zd': (0, 2)}),
    'luti4_z_ztz_': (0xc0ca0000, 0xfffe0c00, {'i3': (14, 3), 'size': (12, 2), 'Zn': (5, 5), 'Zd': (0, 5)}),
    'sel_mz_p_zz_2': (0xc1208000, 0xff21e021, {'size': (22, 2), 'Zm': (17, 4), 'PNv': (10, 3), 'Zn': (6, 4), 'Zd': (1, 4)}),
    'sel_mz_p_zz_4': (0xc1218000, 0xff23e063, {'size': (22, 2), 'Zm': (18, 3), 'PNv': (10, 3), 'Zn': (7, 3), 'Zd': (2, 3)}),
    'sunpk_mz_z_2': (0xc125e000, 0xff3ffc01, {'size': (22, 2), 'Zn': (5, 5), 'Zd': (1, 4)}),
    'sunpk_mz_z_4': (0xc135e000, 0xff3ffc23, {'size': (22, 2), 'Zn': (6, 4), 'Zd': (2, 3)}),
    'uunpk_mz_z_2': (0xc125e001, 0xff3ffc01, {'size': (22, 2), 'Zn': (5, 5), 'Zd': (1, 4)}),
    'uunpk_mz_z_4': (0xc135e001, 0xff3ffc23, {'size': (22, 2), 'Zn': (6, 4), 'Zd': (2, 3)}),
    'uzp_mz_z_4': (0xc136e002, 0xff3ffc63, {'size': (22, 2), 'Zn': (7, 3), 'Zd': (2, 3)}),
    'uzp_mz_z_4q': (0xc137e002, 0xfffffc63, {'Zn': (7, 3), 'Zd': (2, 3)}),
    'uzp_mz_zz_2': (0xc120d001, 0xff20fc01, {'size': (22, 2), 'Zm': (16, 5), 'Zn': (5, 5), 'Zd': (1, 4)}),
    'uzp_mz_zz_2q': (0xc120d401, 0xffe0fc01, {'Zm': (16, 5), 'Zn': (5, 5), 'Zd': (1, 4)}),
    'zip_mz_z_4': (0xc136e000, 0xff3ffc63, {'size': (22, 2), 'Zn': (7, 3), 'Zd': (2, 3)}),
    'zip_mz_z_4q': (0xc137e000, 0xfffffc63, {'Zn': (7, 3), 'Zd': (2, 3)}),
    'zip_mz_zz_2': (0xc120d000, 0xff20fc01, {'size': (22, 2), 'Zm': (16, 5), 'Zn': (5, 5), 'Zd': (1, 4)}),
    'zip_mz_zz_2q': (0xc120d400, 0xffe0fc01, {'Zm': (16, 5), 'Zn': (5, 5), 'Zd': (1, 4)}),
}
CANONICAL_FORMS = tuple(FORMS)


@dataclass(frozen=True)
class Operand:
    canonical_id: str
    kind: str
    destination: tuple
    sources: tuple
    element_bits: int
    feature: str = 'FEAT_SME2'
    index_bits: int = 0
    segment: int = 0
    predicate: int = 0
    signed: bool = False

    @property
    def minimum_svl_bits(self):
        return max(MIN_SVL_BITS, self.element_bits * len(self.destination)) if self.kind in ('zip', 'uzp') else MIN_SVL_BITS


def _group(first, count, stride=1):
    registers = tuple(first + r * stride for r in range(count))
    if any(not 0 <= register < VECTOR_REGISTER_COUNT for register in registers):
        raise ValueError('SME register groups do not wrap')
    return registers


def decode(word):
    """Decode allocated operands; feature/mode/SVL checks are separate."""
    if type(word) is not int or not 0 <= word < 1 << 32:
        return None
    for name, (value, mask, fields) in FORMS.items():
        if word & mask != value:
            continue
        field = {key: (word >> shift) & ((1 << width) - 1)
                 for key, (shift, width) in fields.items()}
        size = field.get('size', 0)
        element_bits = BYTE_BITS << size
        if name.startswith('luti'):
            index_bits = int(name[4])
            count = 2 if '_mz2_' in name else 4 if '_mz4_' in name else 1
            strided = name.endswith(('_8', '_4'))
            stride = 16 // count if strided else 1
            if size == 3 or (strided and size == 2) or (index_bits == 4 and count == 4 and size == 0):
                return None
            first = ((field['D'] << 4) | field['Zd']) if strided else field['Zd'] * count
            immediate = next(v for k, v in field.items() if k.startswith('i'))
            return Operand(name, 'lookup', _group(first, count, stride), (field['Zn'],),
                           element_bits, 'FEAT_SME2p1' if strided else 'FEAT_SME2',
                           index_bits, immediate)
        count = 4 if name.endswith(('_4', '_4q')) else 2
        destination = _group(field['Zd'] * count, count)
        if name.startswith('sel'):
            return Operand(name, 'select', destination,
                           (_group(field['Zn'] * count, count), _group(field['Zm'] * count, count)),
                           element_bits, predicate=COUNTER_PREDICATE_BASE + field['PNv'])
        if name.startswith(('sunpk', 'uunpk')):
            if size == 0:
                return None
            source_count = count // 2
            return Operand(name, 'unpack', destination,
                           _group(field['Zn'] * source_count, source_count),
                           element_bits, signed=name.startswith('sunpk'))
        if name.startswith(('zip', 'uzp')):
            sources = (field['Zn'], field['Zm']) if count == 2 else _group(field['Zn'] * count, count)
            return Operand(name, name[:3], destination, sources,
                           128 if name.endswith('q') else element_bits)
    return None


def operation(canonical_id, **fields):
    value, _, layout = FORMS[canonical_id]
    if fields.keys() - layout.keys():
        raise ValueError('Unknown SME encoding field')
    word = value
    for name, field in fields.items():
        shift, width = layout[name]
        if type(field) is not int or not 0 <= field < 1 << width:
            raise ValueError('SME field outside encoded width')
        word |= field << shift
    op = decode(word)
    if op is None:
        raise ValueError('Reserved SME operand size')
    return {'word': word, 'canonical_id': canonical_id, 'operand': op}


def execute(op, z, predicates, zt0, *, counter_to_predicate=None,
            streaming=True, za=True, zt_enabled=True, features=('FEAT_SME2', 'FEAT_SME2p1'),
            max_svl_bits=MAX_SVL_BITS):
    """Independent integer-bit model; return Z bank while leaving other state intact."""
    if len(z) != VECTOR_REGISTER_COUNT or not z or len({len(register) for register in z}) != 1:
        raise ValueError('Expected complete uniformly sized Z bank')
    svl_bits = len(z[0]) * BYTE_BITS
    if not MIN_SVL_BITS <= svl_bits <= MAX_SVL_BITS or svl_bits & (svl_bits - 1):
        raise ValueError('SME SVL must be a power of two in128..2048')
    if op.feature not in features or not streaming:
        raise ValueError('SME feature or streaming access disabled')
    if svl_bits > max_svl_bits or max_svl_bits < op.minimum_svl_bits or svl_bits < op.minimum_svl_bits:
        raise ValueError('SME operation requires a larger current/maximum SVL')
    if op.kind == 'lookup' and (not za or not zt_enabled):
        raise ValueError('ZT0 access disabled')
    if len(predicates) != 16 or any(len(predicate) != svl_bits // (BYTE_BITS * BYTE_BITS) for predicate in predicates):
        raise ValueError('Expected complete uniformly sized predicate bank')
    element_mask = (1 << op.element_bits) - 1
    elements = svl_bits // op.element_bits
    packed = tuple(int.from_bytes(register, 'little') for register in z)
    results = []
    if op.kind == 'lookup':
        if len(zt0) != ZT0_BYTES:
            raise ValueError('ZT0 is exactly512bits')
        table = int.from_bytes(zt0, 'little')
        indexes = packed[op.sources[0]]
        segments = op.element_bits // (op.index_bits * len(op.destination))
        segment = op.segment % segments
        for register_index in range(len(op.destination)):
            base = (segment * len(op.destination) + register_index) * elements
            result = 0
            for lane in range(elements):
                index = (indexes >> ((base + lane) * op.index_bits)) & ((1 << op.index_bits) - 1)
                result |= ((table >> (index * 32)) & element_mask) << (lane * op.element_bits)
            results.append(result)
    elif op.kind == 'select':
        predicate_bits = svl_bits // BYTE_BITS
        width = predicate_bits * len(op.destination)
        counter = int.from_bytes(predicates[op.predicate][:2], 'little')
        mask = (counter_bits(counter, predicate_bits) & ((1 << width) - 1)
                if counter_to_predicate is None else counter_to_predicate(counter, svl_bits, width))
        for register_index, (left, right) in enumerate(zip(*op.sources)):
            result = 0
            for lane in range(elements):
                predicate_bit = (register_index * elements + lane) * (op.element_bits // BYTE_BITS)
                source = left if (mask >> predicate_bit) & 1 else right
                result |= ((packed[source] >> (lane * op.element_bits)) & element_mask) << (lane * op.element_bits)
            results.append(result)
    elif op.kind == 'unpack':
        half_bits = op.element_bits // 2
        half_mask = (1 << half_bits) - 1
        for source in op.sources:
            for half in range(2):
                result = 0
                for lane in range(elements):
                    value = (packed[source] >> ((half * elements + lane) * half_bits)) & half_mask
                    if op.signed and value & (1 << (half_bits - 1)):
                        value -= 1 << half_bits
                    result |= (value & element_mask) << (lane * op.element_bits)
                results.append(result)
    else:
        count = len(op.destination)
        block = elements // count
        for register_index in range(count):
            result = 0
            for lane in range(elements):
                if op.kind == 'zip':
                    source = op.sources[lane % count]
                    source_lane = register_index * block + lane // count
                else:
                    source = op.sources[lane // block]
                    source_lane = count * (lane % block) + register_index
                result |= ((packed[source] >> (source_lane * op.element_bits)) & element_mask) << (lane * op.element_bits)
            results.append(result)
    output = list(z)
    for destination, result in zip(op.destination, results):
        output[destination] = result.to_bytes(svl_bits // BYTE_BITS, 'little')
    return tuple(output)


def functions():
    """Allocated sizes, segment immediates, boundary groups and source aliases."""
    result = {}
    for name, (_, _, fields) in FORMS.items():
        sizes = range(1 << fields['size'][1]) if 'size' in fields else (None,)
        for size in sizes:
            layouts = [{key: 0 for key in fields},
                       {key: (1 << width) - 1 for key, (_, width) in fields.items()}]
            for layout in layouts:
                if size is not None:
                    layout['size'] = size
                try:
                    row = operation(name, **layout)
                except ValueError:
                    continue
                result.setdefault(row['word'], row)
            base = {key: 0 for key in fields}
            if size is not None:
                base['size'] = size
            immediate = next((key for key in fields if key.startswith('i')), None)
            if immediate:
                for value in range(1 << fields[immediate][1]):
                    layout = dict(base, **{immediate: value, 'Zn': 31})
                    try:
                        row = operation(name, **layout)
                    except ValueError:
                        continue
                    result.setdefault(row['word'], row)
            if name.startswith('sel'):
                maximum = (1 << fields['Zn'][1]) - 1
                for destination, left, right in ((0, 0, maximum), (0, maximum, 0),
                                                  (maximum, 0, maximum), (maximum, maximum, 0)):
                    layout = dict(base, Zd=destination, Zn=left, Zm=right, PNv=7)
                    row = operation(name, **layout)
                    result.setdefault(row['word'], row)
    return tuple(result.values())


def expected(operation_row, initial, ram=None):
    """Adapt the pure model to the one shared full-scalable snapshot contract."""
    from dataclasses import replace
    from scalable_frame import PRIMARY_VECTOR_OFFSET, FIXED_VECTOR_BYTES
    op = decode(operation_row['word'])
    if op is None or op.canonical_id != operation_row['canonical_id']:
        raise ValueError('SME table operation identity differs')
    output = execute(op, initial.z, initial.p, initial.zt0,
                     streaming=bool(initial.control('svcr') & 1),
                     za=bool(initial.control('svcr') & 2))
    primary = bytearray(initial.primary)
    for index, register in enumerate(output):
        offset = PRIMARY_VECTOR_OFFSET + index * FIXED_VECTOR_BYTES
        primary[offset:offset + FIXED_VECTOR_BYTES] = register[:FIXED_VECTOR_BYTES]
    return replace(initial, primary=bytes(primary), z=output), ram, None


def scalable_cases(svl_bytes):
    """Full-state original/native inputs with directed PN and alias boundaries."""
    import random
    import struct
    from scalable_frame import Component, Provenance, Snapshot, require_sme_length
    require_sme_length(svl_bytes)
    randomizer = random.Random(0x534d455441424c45 + svl_bytes)
    case_index = 0
    counters = (0, 0x8000, 1, 2, 4, 8, 3, 9, 33, 129, 257, 0xffff,
                0x8011, 0x8012, 0x8014, 0x8018, 0x40f1, 0x0808)
    required = Component.PRIMARY | Component.Z | Component.P | Component.ZA | Component.ZT0 | Component.SVCR
    for function_index, row in enumerate(functions()):
        op = row['operand']
        if op.minimum_svl_bits > svl_bytes * BYTE_BITS:
            continue
        for counter in counters if op.kind == 'select' else (0,):
            z = tuple(bytes(randomizer.getrandbits(BYTE_BITS) for _ in range(svl_bytes))
                      for _ in range(VECTOR_REGISTER_COUNT))
            p = tuple(counter.to_bytes(2, 'little') + bytes(randomizer.getrandbits(BYTE_BITS)
                      for _ in range(svl_bytes // BYTE_BITS - 2)) for _ in range(16))
            zt0 = bytes(randomizer.getrandbits(BYTE_BITS) for _ in range(ZT0_BYTES))
            primary = struct.pack('<31QQII', *(randomizer.getrandbits(64) for _ in range(31)),
                                  0x40077000, (case_index % 16) << 28, 0)
            primary += b''.join(register[:16] for register in z)
            primary += struct.pack('<II', 0x00c00000, 0x0800001f)
            controls = {'svcr': 3, 'requested_svcr': 3, 'requested_fpcr': 0x00c00000,
                        'requested_fpsr': 0x0800001f}
            initial = Snapshot(svl_bytes, primary, z, p, bytes(svl_bytes // BYTE_BITS),
                               bytes(randomizer.getrandbits(BYTE_BITS) for _ in range(svl_bytes * svl_bytes)),
                               zt0, required, controls, Provenance.MODEL, svl_bytes, case_index, function_index)
            operation_row = {'word': row['word'], 'canonical_id': row['canonical_id'], 'kind': 'sme_tables'}
            output, _, _ = expected(operation_row, initial)
            yield {'operation': operation_row, 'initial': initial, 'expected': output, 'required': required}
            case_index += 1
