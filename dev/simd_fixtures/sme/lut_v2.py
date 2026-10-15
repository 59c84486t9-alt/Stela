"""Pure SME_LUTv2 fixtures; execution uses the consolidated scalable adapters."""
from dataclasses import replace

from scalable_frame import Component, PRIMARY_VECTOR_OFFSET, seeded_snapshot, require_sme_length

CANONICAL_FORMS = ('luti4_mz4_ztmz2_1', 'luti4_mz4_ztmz2_4', 'movt_zt_z_')
FORMS = {
    CANONICAL_FORMS[0]: (0xc08b0000, 0xffffcc23),
    CANONICAL_FORMS[1]: (0xc09b0000, 0xffffcc2c),
    CANONICAL_FORMS[2]: (0xc04f03e0, 0xffffcfe0),
}


def operation(canonical_id, *, source=0, first=0, immediate=0):
    base, _ = FORMS[canonical_id]
    if not 0 <= source < 32:
        raise ValueError('LUT source outside register bank')
    if canonical_id == 'movt_zt_z_':
        if not 0 <= immediate < 4:
            raise ValueError('MOVT offset outside allocated range')
        return {'word': base | immediate << 12 | source, 'canonical_id': canonical_id,
                'source': source, 'immediate': immediate, 'kind': 'move'}
    stride = 1 if canonical_id.endswith('_1') else 4
    if source % 2 or not 0 <= first < 32 or (first % 4 if stride == 1 else first & 12):
        raise ValueError('LUT groups must be aligned and cannot wrap')
    return {'word': base | source << 5 | first, 'canonical_id': canonical_id,
            'source': source, 'destination': tuple(first + r * stride for r in range(4)),
            'kind': 'lookup', 'immediate': 0}


def expected(op, initial, *, streaming=True, za=True, zt_enabled=True,
             lut_v2=True, sme2p1=True):
    length = require_sme_length(initial.svl_bytes)
    if not all((streaming, za, zt_enabled, lut_v2)) or op['canonical_id'].endswith('_4') and not sme2p1:
        raise ValueError('SME_LUTv2 feature or mode requirement absent')
    if op['kind'] == 'move':
        count = min(length, 64)
        offset = op['immediate'] % (64 // count) * count
        table = bytearray(64) if op['immediate'] == 0 else bytearray(initial.zt0)
        table[offset:offset + count] = initial.z[op['source']][:count]
        return replace(initial, zt0=bytes(table))
    packed = int.from_bytes(initial.z[op['source']] + initial.z[op['source'] + 1], 'little')
    registers = list(initial.z)
    primary = bytearray(initial.primary)
    for r, destination in enumerate(op['destination']):
        result = bytes(initial.zt0[((packed >> ((r * length + lane) * 4)) & 15) * 4]
                       for lane in range(length))
        registers[destination] = result
        offset = PRIMARY_VECTOR_OFFSET + destination * 16
        primary[offset:offset + 16] = result[:16]
    return replace(initial, z=tuple(registers), primary=bytes(primary))


def functions():
    result = []
    for name in CANONICAL_FORMS[:2]:
        for first, source in ((0, 4), (0, 0), (0, 2), (16, 16), (16, 18), (16, 30)):
            result.append(operation(name, first=first, source=source))
        if name.endswith('_4'):
            # Exercise both low destination bits, second-source aliases and the
            # highest strided destination Z31 without register wrapping.
            for first, source in ((1, 0), (19, 30), (2, 2), (3, 2)):
                result.append(operation(name, first=first, source=source))
    result.extend(operation('movt_zt_z_', source=source, immediate=immediate)
                  for source in (0, 31) for immediate in range(4))
    return result


def cases(length):
    require_sme_length(length)
    for op in functions():
        for pattern in range(4):
            initial = seeded_snapshot(length, bytes([0x40 + pattern]))
            if pattern < 2:
                # Low-byte all-index-zero/all-index-fifteen rows still retain
                # complete unrelated banks and all four bytes of each table row.
                z = tuple(bytes([255 * pattern]) * length for _ in range(32))
                primary = bytearray(initial.primary)
                for register, value in enumerate(z):
                    offset = PRIMARY_VECTOR_OFFSET + register * 16
                    primary[offset:offset + 16] = value[:16]
                initial = replace(initial, z=z, primary=bytes(primary))
            yield {'operation': op, 'initial': initial, 'expected': expected(op, initial),
                   'required': Component.PRIMARY | Component.Z | Component.P | Component.ZA | Component.ZT0 | Component.SVCR | Component.TPIDR2,
                   'label': f'{op["canonical_id"]}_pattern{pattern}'}
