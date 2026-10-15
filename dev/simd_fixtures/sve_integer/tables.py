"""Whole-VL LUT-extension models, including wrapping two-register tables.

Independent integer-bit model only; original FEAT_LUT execution is unavailable
on the current M1 oracle and must not be inferred from these fixtures.
"""
from dataclasses import dataclass, replace

FORMS = {
    'luti2_z_zz_8': (0x4520b000, 0xff20fc00, 1, 2, 1, 4),
    'luti2_z_zz_16': (0x4520a800, 0xff20ec00, 2, 2, 1, 8),
    'luti4_z_zz_8': (0x4560a400, 0xff60fc00, 1, 4, 1, 2),
    'luti4_z_zz_2x16': (0x4520b400, 0xff20fc00, 2, 4, 2, 4),
    'luti4_z_zz_1x16': (0x4520bc00, 0xff20fc00, 2, 4, 1, 4),
}
CANONICAL_FORMS = tuple(FORMS)

@dataclass(frozen=True)
class Operand:
    canonical_id: str
    destination: int
    table: int
    indexes: int
    element_bytes: int
    index_bits: int
    table_registers: int
    part: int

    @property
    def minimum_vl_bits(self):
        return 256 if self.canonical_id == 'luti4_z_zz_1x16' else 128


def decode(word):
    if type(word) is not int or not 0 <= word < 1 << 32:
        return None
    for name, (base, mask, element, bits, registers, _) in FORMS.items():
        if word & mask != base:
            continue
        part = (word >> 22) & 3
        if name == 'luti2_z_zz_16':
            part = (part << 1) | ((word >> 12) & 1)
        elif name == 'luti4_z_zz_8':
            part >>= 1
        return Operand(name, word & 31, (word >> 5) & 31, (word >> 16) & 31,
                       element, bits, registers, part)
    return None


def operation(canonical_id, *, destination=0, table=1, indexes=2, part=0):
    base, _, _, _, _, parts = FORMS[canonical_id]
    if any(type(x) is not int or not 0 <= x < 32 for x in (destination, table, indexes)) or not 0 <= part < parts:
        raise ValueError('LUT register/part outside encoding')
    encoded = ((part >> 1) << 22) | ((part & 1) << 12) if canonical_id == 'luti2_z_zz_16' else part << (23 if canonical_id == 'luti4_z_zz_8' else 22)
    word = base | encoded | destination | (table << 5) | (indexes << 16)
    return {'word': word, 'canonical_id': canonical_id, 'kind': 'sve_tables'}


def execute(op, z, *, max_vl_bytes=256):
    if len(z) != 32 or len({len(r) for r in z}) != 1:
        raise ValueError('LUT needs complete Z bank')
    length = len(z[0])
    if length not in (16, 32, 64, 128, 256) or length * 8 < op.minimum_vl_bits or max_vl_bytes * 8 < op.minimum_vl_bits:
        raise ValueError('LUT unsupported current/maximum vector length')
    table = z[op.table]
    if op.table_registers == 2:
        table = table[:16] + z[(op.table + 1) % 32][:16]
    packed = int.from_bytes(z[op.indexes], 'little')
    lanes = length // op.element_bytes
    base = lanes * op.part
    output = bytearray()
    for lane in range(lanes):
        index = (packed >> ((base + lane) * op.index_bits)) & ((1 << op.index_bits) - 1)
        offset = index * op.element_bytes
        output.extend(table[offset:offset + op.element_bytes])
    result = list(z)
    result[op.destination] = bytes(output)
    return tuple(result)


def functions():
    for name, (_, _, _, _, _, parts) in FORMS.items():
        for part in range(parts):
            for destination, table, indexes in ((0, 1, 2), (1, 1, 2), (2, 1, 2), (0, 31, 0), (31, 31, 31), (0, 31, 31)):
                yield operation(name, destination=destination, table=table, indexes=indexes, part=part)


def expected(operation_row, initial, ram=None):
    from scalable_frame import PRIMARY_VECTOR_OFFSET, FIXED_VECTOR_BYTES
    op = decode(operation_row['word'])
    if op is None or op.canonical_id != operation_row['canonical_id']:
        raise ValueError('LUT canonical identity mismatch')
    z = execute(op, initial.z)
    primary = bytearray(initial.primary)
    for register, data in enumerate(z):
        offset = PRIMARY_VECTOR_OFFSET + register * FIXED_VECTOR_BYTES
        primary[offset:offset + FIXED_VECTOR_BYTES] = data[:FIXED_VECTOR_BYTES]
    return replace(initial, primary=bytes(primary), z=z), ram, None


def scalable_cases(svl_bytes):
    import random, struct
    from scalable_frame import Component, Provenance, Snapshot, require_sme_length
    require_sme_length(svl_bytes)
    required = Component.PRIMARY | Component.Z | Component.P | Component.ZA | Component.ZT0 | Component.SVCR
    randomizer = random.Random(0x4c555435 + svl_bytes)
    for function_index, row in enumerate(functions()):
        op = decode(row['word'])
        if svl_bytes * 8 < op.minimum_vl_bits:
            continue
        for pattern in range(3):
            z = tuple(bytes(randomizer.getrandbits(8) for _ in range(svl_bytes)) for _ in range(32))
            if pattern < 2:
                z = list(z)
                z[op.indexes] = bytes([0 if pattern == 0 else 255]) * svl_bytes
                z = tuple(z)
            p = tuple(bytes(randomizer.getrandbits(8) for _ in range(svl_bytes // 8)) for _ in range(16))
            primary = struct.pack('<31QQII', *(randomizer.getrandbits(64) for _ in range(31)), 0x40077000, (pattern << 28), 0)
            primary += b''.join(register[:16] for register in z) + struct.pack('<II', 0x03c00000, 0x0800001f)
            initial = Snapshot(svl_bytes, primary, z, p, bytes(svl_bytes // 8), bytes(svl_bytes * svl_bytes), bytes(range(64)), required,
                               {'svcr': 3, 'requested_svcr': 3, 'requested_fpcr': 0x03c00000, 'requested_fpsr': 0x0800001f},
                               Provenance.MODEL, svl_bytes, function_index * 3 + pattern, function_index)
            output, _, _ = expected(row, initial)
            yield {'operation': row, 'initial': initial, 'expected': output, 'required': required}
