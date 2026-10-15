"""Independent SME movement model; full scalable storage and explicit mode gates.

ZA is a byte matrix of physical vectors. Tiles/slices alias that matrix; they
never have separate copies. Inactive Z/ZA storage follows explicit architectural
preserve-or-zero policy choices. Ordinary execution cannot execute debug MOVT.
No compiler/backend calls are used to compute expected results.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

BITS_PER_BYTE = 8
MAX_VECTOR_BYTES = 256
MIN_VECTOR_BYTES = 16
VECTOR_REGISTER_COUNT = 32
PREDICATE_REGISTER_COUNT = 16
ZT0_BYTES = 64
GPR_MASK = (1 << 64) - 1
W_MASK = (1 << 32) - 1
TILE_INDEX_BASE = 12
VECTOR_INDEX_BASE = 8
DOUBLE_QUAD_MINIMUM_BYTES = 32

# Canonical fixed bits and named fields, generated from pinned 2026-06 XML.
# Tuple: id, mask, value, source page, feature, element bytes, count, groups, fields.
FORM_DATA = (
    ('mova_mz2_za_b1', 4294909697, 3221618688, 'mova_mz2_za', 'FEAT_SME2', 1, 2, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'off3': [5, 3], 'Zd': [1, 4]}),
    ('mova_mz2_za_d1', 4294909697, 3234201600, 'mova_mz2_za', 'FEAT_SME2', 8, 2, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'ZAn': [5, 3], 'Zd': [1, 4]}),
    ('mova_mz2_za_h1', 4294909697, 3225812992, 'mova_mz2_za', 'FEAT_SME2', 2, 2, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'ZAn': [7, 1], 'off2': [5, 2], 'Zd': [1, 4]}),
    ('mova_mz2_za_w1', 4294909697, 3230007296, 'mova_mz2_za', 'FEAT_SME2', 4, 2, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'ZAn': [6, 2], 'o1': [5, 1], 'Zd': [1, 4]}),
    ('mova_mz4_za_b1', 4294909827, 3221619712, 'mova_mz4_za', 'FEAT_SME2', 1, 4, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'off2': [5, 2], 'Zd': [2, 3]}),
    ('mova_mz4_za_d1', 4294909699, 3234202624, 'mova_mz4_za', 'FEAT_SME2', 8, 4, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'ZAn': [5, 3], 'Zd': [2, 3]}),
    ('mova_mz4_za_h1', 4294909827, 3225814016, 'mova_mz4_za', 'FEAT_SME2', 2, 4, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'ZAn': [6, 1], 'o1': [5, 1], 'Zd': [2, 3]}),
    ('mova_mz4_za_w1', 4294909827, 3230008320, 'mova_mz4_za', 'FEAT_SME2', 4, 4, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'ZAn': [5, 2], 'Zd': [2, 3]}),
    ('mova_mz_za2_1', 4294942465, 3221620736, 'mova_mz_za2', 'FEAT_SME2', 1, 2, 1, {'Rv': [13, 2], 'off3': [5, 3], 'Zd': [1, 4]}),
    ('mova_mz_za4_1', 4294942467, 3221621760, 'mova_mz_za4', 'FEAT_SME2', 1, 4, 1, {'Rv': [13, 2], 'off3': [5, 3], 'Zd': [2, 3]}),
    ('mova_z_p_rza_b', 4294902272, 3221356544, 'mova_z_p_rza', 'FEAT_SME', 1, 1, 1, {'size': [22, 2], 'Q': [16, 1], 'V': [15, 1], 'Rs': [13, 2], 'Pg': [10, 3], 'off4': [5, 4], 'Zd': [0, 5]}),
    ('mova_z_p_rza_d', 4294902272, 3233939456, 'mova_z_p_rza', 'FEAT_SME', 8, 1, 1, {'size': [22, 2], 'Q': [16, 1], 'V': [15, 1], 'Rs': [13, 2], 'Pg': [10, 3], 'ZAn': [6, 3], 'o1': [5, 1], 'Zd': [0, 5]}),
    ('mova_z_p_rza_h', 4294902272, 3225550848, 'mova_z_p_rza', 'FEAT_SME', 2, 1, 1, {'size': [22, 2], 'Q': [16, 1], 'V': [15, 1], 'Rs': [13, 2], 'Pg': [10, 3], 'ZAn': [8, 1], 'off3': [5, 3], 'Zd': [0, 5]}),
    ('mova_z_p_rza_q', 4294902272, 3234004992, 'mova_z_p_rza', 'FEAT_SME', 16, 1, 1, {'size': [22, 2], 'Q': [16, 1], 'V': [15, 1], 'Rs': [13, 2], 'Pg': [10, 3], 'ZAn': [5, 4], 'Zd': [0, 5]}),
    ('mova_z_p_rza_w', 4294902272, 3229745152, 'mova_z_p_rza', 'FEAT_SME', 4, 1, 1, {'size': [22, 2], 'Q': [16, 1], 'V': [15, 1], 'Rs': [13, 2], 'Pg': [10, 3], 'ZAn': [7, 2], 'off2': [5, 2], 'Zd': [0, 5]}),
    ('mova_za2_z_b1', 4294908984, 3221487616, 'mova_za2_z', 'FEAT_SME2', 1, 2, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'Zn': [6, 4], 'off3': [0, 3]}),
    ('mova_za2_z_d1', 4294908984, 3234070528, 'mova_za2_z', 'FEAT_SME2', 8, 2, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'Zn': [6, 4], 'ZAd': [0, 3]}),
    ('mova_za2_z_h1', 4294908984, 3225681920, 'mova_za2_z', 'FEAT_SME2', 2, 2, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'Zn': [6, 4], 'ZAd': [2, 1], 'off2': [0, 2]}),
    ('mova_za2_z_w1', 4294908984, 3229876224, 'mova_za2_z', 'FEAT_SME2', 4, 2, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'Zn': [6, 4], 'ZAd': [1, 2], 'o1': [0, 1]}),
    ('mova_za4_z_b1', 4294909052, 3221488640, 'mova_za4_z', 'FEAT_SME2', 1, 4, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'Zn': [7, 3], 'off2': [0, 2]}),
    ('mova_za4_z_d1', 4294909048, 3234071552, 'mova_za4_z', 'FEAT_SME2', 8, 4, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'Zn': [7, 3], 'ZAd': [0, 3]}),
    ('mova_za4_z_h1', 4294909052, 3225682944, 'mova_za4_z', 'FEAT_SME2', 2, 4, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'Zn': [7, 3], 'ZAd': [1, 1], 'o1': [0, 1]}),
    ('mova_za4_z_w1', 4294909052, 3229877248, 'mova_za4_z', 'FEAT_SME2', 4, 4, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'Zn': [7, 3], 'ZAd': [0, 2]}),
    ('mova_za_mz2_1', 4294941752, 3221489664, 'mova_za_mz2', 'FEAT_SME2', 1, 2, 1, {'Rv': [13, 2], 'Zn': [6, 4], 'off3': [0, 3]}),
    ('mova_za_mz4_1', 4294941816, 3221490688, 'mova_za_mz4', 'FEAT_SME2', 1, 4, 1, {'Rv': [13, 2], 'Zn': [7, 3], 'off3': [0, 3]}),
    ('mova_za_p_rz_b', 4294901776, 3221225472, 'mova_za_p_rz', 'FEAT_SME', 1, 1, 1, {'size': [22, 2], 'Q': [16, 1], 'V': [15, 1], 'Rs': [13, 2], 'Pg': [10, 3], 'Zn': [5, 5], 'off4': [0, 4]}),
    ('mova_za_p_rz_d', 4294901776, 3233808384, 'mova_za_p_rz', 'FEAT_SME', 8, 1, 1, {'size': [22, 2], 'Q': [16, 1], 'V': [15, 1], 'Rs': [13, 2], 'Pg': [10, 3], 'Zn': [5, 5], 'ZAd': [1, 3], 'o1': [0, 1]}),
    ('mova_za_p_rz_h', 4294901776, 3225419776, 'mova_za_p_rz', 'FEAT_SME', 2, 1, 1, {'size': [22, 2], 'Q': [16, 1], 'V': [15, 1], 'Rs': [13, 2], 'Pg': [10, 3], 'Zn': [5, 5], 'ZAd': [3, 1], 'off3': [0, 3]}),
    ('mova_za_p_rz_q', 4294901776, 3233873920, 'mova_za_p_rz', 'FEAT_SME', 16, 1, 1, {'size': [22, 2], 'Q': [16, 1], 'V': [15, 1], 'Rs': [13, 2], 'Pg': [10, 3], 'Zn': [5, 5], 'ZAd': [0, 4]}),
    ('mova_za_p_rz_w', 4294901776, 3229614080, 'mova_za_p_rz', 'FEAT_SME', 4, 1, 1, {'size': [22, 2], 'Q': [16, 1], 'V': [15, 1], 'Rs': [13, 2], 'Pg': [10, 3], 'Zn': [5, 5], 'ZAd': [2, 2], 'off2': [0, 2]}),
    ('movaz_mz2_za_b1', 4294909697, 3221619200, 'movaz_mz2_za', 'FEAT_SME2p1', 1, 2, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'off3': [5, 3], 'Zd': [1, 4]}),
    ('movaz_mz2_za_d1', 4294909697, 3234202112, 'movaz_mz2_za', 'FEAT_SME2p1', 8, 2, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'ZAn': [5, 3], 'Zd': [1, 4]}),
    ('movaz_mz2_za_h1', 4294909697, 3225813504, 'movaz_mz2_za', 'FEAT_SME2p1', 2, 2, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'ZAn': [7, 1], 'off2': [5, 2], 'Zd': [1, 4]}),
    ('movaz_mz2_za_w1', 4294909697, 3230007808, 'movaz_mz2_za', 'FEAT_SME2p1', 4, 2, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'ZAn': [6, 2], 'o1': [5, 1], 'Zd': [1, 4]}),
    ('movaz_mz4_za_b1', 4294909827, 3221620224, 'movaz_mz4_za', 'FEAT_SME2p1', 1, 4, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'off2': [5, 2], 'Zd': [2, 3]}),
    ('movaz_mz4_za_d1', 4294909699, 3234203136, 'movaz_mz4_za', 'FEAT_SME2p1', 8, 4, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'ZAn': [5, 3], 'Zd': [2, 3]}),
    ('movaz_mz4_za_h1', 4294909827, 3225814528, 'movaz_mz4_za', 'FEAT_SME2p1', 2, 4, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'ZAn': [6, 1], 'o1': [5, 1], 'Zd': [2, 3]}),
    ('movaz_mz4_za_w1', 4294909827, 3230008832, 'movaz_mz4_za', 'FEAT_SME2p1', 4, 4, 1, {'size': [22, 2], 'V': [15, 1], 'Rs': [13, 2], 'ZAn': [5, 2], 'Zd': [2, 3]}),
    ('movaz_mz_za2_1', 4294942465, 3221621248, 'movaz_mz_za2', 'FEAT_SME2p1', 1, 2, 1, {'Rv': [13, 2], 'off3': [5, 3], 'Zd': [1, 4]}),
    ('movaz_mz_za4_1', 4294942467, 3221622272, 'movaz_mz_za4', 'FEAT_SME2p1', 1, 4, 1, {'Rv': [13, 2], 'off3': [5, 3], 'Zd': [2, 3]}),
    ('movaz_z_rza_b', 4294909440, 3221357056, 'movaz_z_rza', 'FEAT_SME2p1', 1, 1, 1, {'size': [22, 2], 'Q': [16, 1], 'V': [15, 1], 'Rs': [13, 2], 'off4': [5, 4], 'Zd': [0, 5]}),
    ('movaz_z_rza_d', 4294909440, 3233939968, 'movaz_z_rza', 'FEAT_SME2p1', 8, 1, 1, {'size': [22, 2], 'Q': [16, 1], 'V': [15, 1], 'Rs': [13, 2], 'ZAn': [6, 3], 'o1': [5, 1], 'Zd': [0, 5]}),
    ('movaz_z_rza_h', 4294909440, 3225551360, 'movaz_z_rza', 'FEAT_SME2p1', 2, 1, 1, {'size': [22, 2], 'Q': [16, 1], 'V': [15, 1], 'Rs': [13, 2], 'ZAn': [8, 1], 'off3': [5, 3], 'Zd': [0, 5]}),
    ('movaz_z_rza_q', 4294909440, 3234005504, 'movaz_z_rza', 'FEAT_SME2p1', 16, 1, 1, {'size': [22, 2], 'Q': [16, 1], 'V': [15, 1], 'Rs': [13, 2], 'ZAn': [5, 4], 'Zd': [0, 5]}),
    ('movaz_z_rza_w', 4294909440, 3229745664, 'movaz_z_rza', 'FEAT_SME2p1', 4, 1, 1, {'size': [22, 2], 'Q': [16, 1], 'V': [15, 1], 'Rs': [13, 2], 'ZAn': [7, 2], 'off2': [5, 2], 'Zd': [0, 5]}),
    ('movt_r_zt_', 4294938592, 3226207200, 'movt_r_zt', 'FEAT_SME2', 1, 1, 1, {'off3': [12, 3], 'opc': [5, 7], 'Rt': [0, 5]}),
    ('movt_zt_r_', 4294938592, 3226338272, 'movt_zt_r', 'FEAT_SME2', 1, 1, 1, {'off3': [12, 3], 'opc': [5, 7], 'Rt': [0, 5]}),
    ('zero_za1_ri_2', 4294942712, 3222011904, 'zero_za1_ri', 'FEAT_SME2p1', 1, 1, 2, {'opc': [15, 3], 'Rv': [13, 2], 'off3': [0, 3]}),
    ('zero_za1_ri_4', 4294942712, 3222142976, 'zero_za1_ri', 'FEAT_SME2p1', 1, 1, 4, {'opc': [15, 3], 'Rv': [13, 2], 'off3': [0, 3]}),
    ('zero_za2_ri_1', 4294942712, 3222044672, 'zero_za2_ri', 'FEAT_SME2p1', 1, 2, 1, {'opc': [15, 3], 'Rv': [13, 2], 'off3': [0, 3]}),
    ('zero_za2_ri_2', 4294942716, 3222077440, 'zero_za2_ri', 'FEAT_SME2p1', 1, 2, 2, {'opc': [15, 3], 'Rv': [13, 2], 'off2': [0, 2]}),
    ('zero_za2_ri_4', 4294942716, 3222110208, 'zero_za2_ri', 'FEAT_SME2p1', 1, 2, 4, {'opc': [15, 3], 'Rv': [13, 2], 'off2': [0, 2]}),
    ('zero_za4_ri_1', 4294942716, 3222175744, 'zero_za4_ri', 'FEAT_SME2p1', 1, 4, 1, {'opc': [15, 3], 'Rv': [13, 2], 'off2': [0, 2]}),
    ('zero_za4_ri_2', 4294942718, 3222208512, 'zero_za4_ri', 'FEAT_SME2p1', 1, 4, 2, {'opc': [15, 3], 'Rv': [13, 2], 'o1': [0, 1]}),
    ('zero_za4_ri_4', 4294942718, 3222241280, 'zero_za4_ri', 'FEAT_SME2p1', 1, 4, 4, {'opc': [15, 3], 'Rv': [13, 2], 'o1': [0, 1]}),
    ('zero_za_i_', 4294967040, 3221749760, 'zero_za_i', 'FEAT_SME', 8, 1, 1, {'imm8': [0, 8]}),
    ('zero_zt_i_', 4294967295, 3225944065, 'zero_zt_i', 'FEAT_SME2', 1, 1, 1, {'opc': [0, 4]}),
)
CANONICAL_FORMS = tuple(row[0] for row in FORM_DATA)

class Direction(Enum):
    TO_ZA = 'to_za'
    FROM_ZA = 'from_za'

class ArchitecturalFault(ValueError):
    """Explicit modeled decode/mode trap, with no successful-looking result."""

@dataclass(frozen=True)
class Operation:
    canonical_id: str
    source: str
    feature: str
    element_bytes: int
    count: int
    groups: int
    index: int = 0
    offset: int = 0
    vector: int = 0
    tile: int = 0
    vertical: bool = False
    predicate: int | None = None
    direction: Direction = Direction.FROM_ZA
    zero_source: bool = False
    shape: str = 'tile'

    @property
    def requires_streaming(self):
        return self.shape not in ('zero_tiles', 'zero_table', 'table_gpr')

    @property
    def requires_halted(self):
        return self.shape == 'table_gpr'


def decode(word):
    rows = [row for row in FORM_DATA if word & row[1] == row[2]]
    if not rows:
        return None
    if len(rows) != 1:
        raise AssertionError('Overlapping canonical movement forms')
    canonical, _, _, source, feature, size, count, groups, fields = rows[0]
    def field(*names):
        for name in names:
            if name in fields:
                shift, width = fields[name]
                return (word >> shift) & ((1 << width) - 1)
        return 0
    shape = 'tile'
    direction = Direction.FROM_ZA
    if source == 'zero_za_i':
        shape = 'zero_tiles'
    elif source == 'zero_zt_i':
        shape = 'zero_table'
    elif source.startswith('zero_za'):
        shape = 'zero_vectors'
    elif source.startswith('movt_'):
        shape = 'table_gpr'
        direction = Direction.TO_ZA if source == 'movt_zt_r' else Direction.FROM_ZA
    elif '_mz_za' in source:
        shape = 'vectors'
    elif '_za_mz' in source:
        shape = 'vectors'
        direction = Direction.TO_ZA
    elif source.startswith('mova_za'):
        direction = Direction.TO_ZA
    index = field('Rs', 'Rv') + (TILE_INDEX_BASE if shape == 'tile' else VECTOR_INDEX_BASE)
    offset = field('off4', 'off3', 'off2', 'o1', 'imm8')
    if shape in ('tile', 'zero_vectors'):
        offset *= count
    vector = field('Zd', 'Zn', 'Rt') * (count if shape in ('tile', 'vectors') else 1)
    return Operation(canonical, source, feature, size, count, groups, index, offset,
                     vector, field('ZAn', 'ZAd'), bool(field('V')),
                     field('Pg') if 'Pg' in fields else None, direction,
                     source.startswith('movaz'), shape)


class State:
    """Complete modeled GPR/control/Z/P/ZA/ZT storage, including inactive bytes."""
    def __init__(self, svl_bytes, *, streaming=True, za_enabled=True, zt0_enabled=True,
                 halted=False, max_svl_bytes=MAX_VECTOR_BYTES,
                 zero_z_upper=False, zero_za_upper=False):
        if (type(svl_bytes) is not int or not MIN_VECTOR_BYTES <= svl_bytes <= max_svl_bytes
                or svl_bytes & (svl_bytes - 1) or max_svl_bytes > MAX_VECTOR_BYTES
                or max_svl_bytes & (max_svl_bytes - 1)):
            raise ValueError('Invalid SME vector length')
        self.svl_bytes = svl_bytes
        self.max_svl_bytes = max_svl_bytes
        self.streaming = streaming
        self.za_enabled = za_enabled
        self.zt0_enabled = zt0_enabled
        self.halted = halted
        self.zero_z_upper = zero_z_upper
        self.zero_za_upper = zero_za_upper
        self.features = {'FEAT_SME', 'FEAT_SME2', 'FEAT_SME2p1'}
        self.x = [0] * (VECTOR_REGISTER_COUNT - 1)
        self.sp = self.nzcv = self.fpcr = self.fpsr = 0
        self.z = [bytearray(MAX_VECTOR_BYTES) for _ in range(VECTOR_REGISTER_COUNT)]
        self.p = [bytearray(MAX_VECTOR_BYTES // BITS_PER_BYTE)
                  for _ in range(PREDICATE_REGISTER_COUNT)]
        self.za = bytearray(MAX_VECTOR_BYTES * MAX_VECTOR_BYTES)
        self.zt0 = bytearray(ZT0_BYTES)

    def read_w(self, register):
        return self.x[register] & W_MASK

    def read_x(self, register):
        return 0 if register == VECTOR_REGISTER_COUNT - 1 else self.x[register] & GPR_MASK

    def write_x(self, register, value):
        if register != VECTOR_REGISTER_COUNT - 1:
            self.x[register] = value & GPR_MASK

    def vector(self, index):
        if not 0 <= index < self.svl_bytes:
            raise AssertionError('ZA physical vector out of range')
        start = index * MAX_VECTOR_BYTES
        return bytes(self.za[start:start + self.svl_bytes])

    def write_vector(self, index, value):
        if len(value) != self.svl_bytes or not 0 <= index < self.svl_bytes:
            raise AssertionError('Invalid ZA physical vector write')
        start = index * MAX_VECTOR_BYTES
        self.za[start:start + self.svl_bytes] = value
        if self.zero_za_upper:
            self.za[start + self.svl_bytes:start + MAX_VECTOR_BYTES] = bytes(MAX_VECTOR_BYTES - self.svl_bytes)

    def write_z(self, register, value):
        if len(value) != self.svl_bytes:
            raise AssertionError('Invalid Z vector write')
        self.z[register][:self.svl_bytes] = value
        if self.zero_z_upper:
            self.z[register][self.svl_bytes:] = bytes(MAX_VECTOR_BYTES - self.svl_bytes)

    def slice(self, tile, size, vertical, index):
        dimension = self.svl_bytes // size
        if not 0 <= tile < size or not 0 <= index < dimension:
            raise AssertionError('Invalid ZA tile slice')
        if not vertical:
            return self.vector(tile + index * size)
        return b''.join(self.vector(tile + row * size)[index * size:(index + 1) * size]
                        for row in range(dimension))

    def write_slice(self, tile, size, vertical, index, value):
        dimension = self.svl_bytes // size
        if (len(value) != self.svl_bytes or not 0 <= tile < size
                or not 0 <= index < dimension):
            raise AssertionError('Invalid ZA tile slice write')
        if not vertical:
            self.write_vector(tile + index * size, value)
            return
        for row in range(dimension):
            physical = tile + row * size
            contents = bytearray(self.vector(physical))
            contents[index * size:(index + 1) * size] = value[row * size:(row + 1) * size]
            self.write_vector(physical, contents)

    def active(self, predicate, lane, size):
        bit = lane * size
        return bool(self.p[predicate][bit // BITS_PER_BYTE] & (1 << (bit % BITS_PER_BYTE)))


def execute(state, operation):
    """Apply one decoded operation; mode/decode rejection leaves all state intact."""
    op = operation
    if op.feature not in state.features:
        raise ArchitecturalFault('Decode_UNDEF: missing ' + op.feature)
    if op.requires_halted and not state.halted:
        raise ArchitecturalFault('Decode_UNDEF: MOVT requires halted debug state')
    if op.shape == 'tile' and op.count == 4 and op.element_bytes == BITS_PER_BYTE:
        if state.max_svl_bytes < DOUBLE_QUAD_MINIMUM_BYTES:
            raise ArchitecturalFault('Decode_UNDEF: maximum implemented SVL below 256 bits')
    if op.requires_streaming and not state.streaming:
        raise ArchitecturalFault('SMEAccessTrap: inactive streaming mode')
    if not state.za_enabled:
        raise ArchitecturalFault('SMEAccessTrap: inactive ZA')
    if op.shape in ('zero_table', 'table_gpr') and not state.zt0_enabled:
        raise ArchitecturalFault('SMEAccessTrap: inaccessible ZT0')
    if op.shape == 'tile' and op.count == 4 and op.element_bytes == BITS_PER_BYTE:
        if state.svl_bytes < DOUBLE_QUAD_MINIMUM_BYTES:
            raise ArchitecturalFault('Decode_UNDEF: current SVL below 256 bits')
    width = state.svl_bytes
    zero = bytes(width)
    if op.shape == 'zero_tiles':
        for row in range(width):
            if op.offset & (1 << (row % BITS_PER_BYTE)):
                state.write_vector(row, zero)
    elif op.shape == 'zero_table':
        state.zt0[:] = bytes(ZT0_BYTES)
    elif op.shape == 'table_gpr':
        start = op.offset * BITS_PER_BYTE
        if op.direction is Direction.TO_ZA:
            state.zt0[start:start + BITS_PER_BYTE] = state.read_x(op.vector).to_bytes(BITS_PER_BYTE, 'little')
        else:
            state.write_x(op.vector, int.from_bytes(state.zt0[start:start + BITS_PER_BYTE], 'little'))
    elif op.shape in ('vectors', 'zero_vectors'):
        groups = op.count if op.shape == 'vectors' else op.groups
        stride = width // groups
        row = (state.read_w(op.index) + op.offset) % stride
        if op.shape == 'zero_vectors':
            row -= row % op.count
        for group in range(groups):
            selected = row + group * stride
            if op.shape == 'zero_vectors':
                for delta in range(op.count):
                    state.write_vector(selected + delta, zero)
            elif op.direction is Direction.TO_ZA:
                state.write_vector(selected, bytes(state.z[op.vector + group][:width]))
            else:
                result = state.vector(selected)
                if op.zero_source:
                    state.write_vector(selected, zero)
                state.write_z(op.vector + group, result)
    else:
        dimension = width // op.element_bytes
        index = state.read_w(op.index)
        row = (index - index % op.count + op.offset) % dimension
        for delta in range(op.count):
            selected = row + delta
            if op.direction is Direction.TO_ZA:
                incoming = bytes(state.z[op.vector + delta][:width])
                current = state.slice(op.tile, op.element_bytes, op.vertical, selected)
            else:
                incoming = state.slice(op.tile, op.element_bytes, op.vertical, selected)
                current = bytes(state.z[op.vector + delta][:width])
            if op.predicate is not None:
                result = bytearray(current)
                for lane in range(dimension):
                    if state.active(op.predicate, lane, op.element_bytes):
                        start = lane * op.element_bytes
                        result[start:start + op.element_bytes] = incoming[start:start + op.element_bytes]
            else:
                result = incoming
            if op.direction is Direction.TO_ZA:
                state.write_slice(op.tile, op.element_bytes, op.vertical, selected, result)
            else:
                if op.zero_source:
                    state.write_slice(op.tile, op.element_bytes, op.vertical, selected, zero)
                state.write_z(op.vector + delta, result)


def expected(operation, initial, ram=None):
    """Recompute one full scalable snapshot, preserving unowned raw state bytes."""
    from dataclasses import replace
    import struct
    import scalable_frame as frame

    if not isinstance(initial, frame.Snapshot):
        raise TypeError('SME movement input must be a scalable Snapshot')
    op = decode(operation['word'])
    if op is None or op.canonical_id != operation['canonical_id']:
        raise ValueError('SME movement encoding and canonical identity differ')
    needed = frame.Component.PRIMARY | frame.Component.SVCR
    if op.shape in ('tile', 'vectors'):
        needed |= frame.Component.Z | frame.Component.ZA
    if op.predicate is not None:
        needed |= frame.Component.P
    if op.shape in ('zero_tiles', 'zero_vectors'):
        needed |= frame.Component.ZA
    if op.shape in ('zero_table', 'table_gpr'):
        needed |= frame.Component.ZT0
    if initial.valid & needed != needed:
        raise ValueError('SME movement input lacks required architectural validity')
    svcr = initial.control('svcr')
    state = State(initial.svl_bytes, streaming=bool(svcr & frame.SVCR_SM),
                  za_enabled=bool(svcr & frame.SVCR_ZA),
                  halted=operation.get('halted', False))
    state.x[:] = struct.unpack_from('<31Q', initial.primary)
    state.sp, = struct.unpack_from('<Q', initial.primary, 31 * BITS_PER_BYTE)
    state.nzcv, = struct.unpack_from('<I', initial.primary, frame.PRIMARY_NZCV_OFFSET)
    state.fpcr, state.fpsr = struct.unpack_from('<II', initial.primary, frame.PRIMARY_FPCR_OFFSET)
    for register, value in enumerate(initial.z):
        state.z[register][:initial.svl_bytes] = value
    for register, value in enumerate(initial.p):
        state.p[register][:initial.svl_bytes // BITS_PER_BYTE] = value
    for row in range(initial.svl_bytes):
        start = row * initial.svl_bytes
        state.za[row * MAX_VECTOR_BYTES:row * MAX_VECTOR_BYTES + initial.svl_bytes] = initial.za[start:start + initial.svl_bytes]
    state.zt0[:] = initial.zt0
    execute(state, op)
    primary = bytearray(initial.primary)
    struct.pack_into('<31Q', primary, 0, *state.x)
    z = tuple(bytes(value[:initial.svl_bytes]) for value in state.z)
    if op.shape in ('tile', 'vectors') and op.direction is Direction.FROM_ZA:
        for register in range(op.vector, op.vector + op.count):
            start = frame.PRIMARY_VECTOR_OFFSET + register * frame.FIXED_VECTOR_BYTES
            primary[start:start + frame.FIXED_VECTOR_BYTES] = z[register][:frame.FIXED_VECTOR_BYTES]
    # Invalid diagnostic Z storage must never repair unrelated primary V bytes.
    result = replace(initial, primary=bytes(primary), z=z,
                     za=b''.join(state.vector(row) for row in range(initial.svl_bytes)),
                     zt0=bytes(state.zt0), provenance=frame.Provenance.MODEL)
    return result, ram, None


def scalable_cases(svl_bytes):
    """All normal movement forms, alias endpoints, merge masks and wrapped W indices.

    Debug-only MOVT and four-register doubleword transfers at SVL128 retain
    explicit decoder/profile requirements and separate rejection evidence.
    """
    from dataclasses import replace
    import struct
    import scalable_frame as frame

    frame.require_sme_length(svl_bytes)
    required = (frame.Component.PRIMARY | frame.Component.Z | frame.Component.P
                | frame.Component.ZA | frame.Component.ZT0 | frame.Component.SVCR
                | frame.Component.TPIDR2)
    case_index = 0
    for row in FORM_DATA:
        for variant, free in enumerate((0, ~row[1] & W_MASK)):
            word = row[2] | free
            op = decode(word)
            if op.requires_halted or (op.shape == 'tile' and op.count == 4
                                     and op.element_bytes == BITS_PER_BYTE
                                     and svl_bytes < DOUBLE_QUAD_MINIMUM_BYTES):
                continue
            operation = {'word': word, 'canonical_id': op.canonical_id,
                         'family': 'sme_movement'}
            initial = frame.seeded_snapshot(svl_bytes, word.to_bytes(4, 'little'),
                                            case_index=case_index, function_index=case_index)
            primary = bytearray(initial.primary)
            selector = (svl_bytes + 1, GPR_MASK)[variant]
            for register in range(VECTOR_INDEX_BASE, TILE_INDEX_BASE + 4):
                struct.pack_into('<Q', primary, register * BITS_PER_BYTE, selector)
            initial = replace(initial, primary=bytes(primary))
            result, _, _ = expected(operation, initial)
            yield {'operation': operation, 'initial': initial, 'expected': result,
                   'required': required}
            case_index += 1
