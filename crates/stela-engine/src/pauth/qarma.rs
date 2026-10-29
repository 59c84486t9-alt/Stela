//! QARMA5-64, the cipher of every PAC (Arm `ComputePAC`, `ComputePACQARMA`
//! with five rounds each way and the involutory middle).
//!
//! The state's cell `i` is bits `4i+3:4i`; its rows are the four 16-bit
//! lanes and its columns the cells' places in a row. MixColumns (QARMA's
//! involutory `M = circ(0, ρ, ρ², ρ)`) gives row `r` rows `r+1` and `r+3`
//! with each cell rotated left one bit, plus row `r+2` rotated two. The
//! tweak schedule depends only on the modifier, so both halves use the six
//! tweaks the forward half computes.
//!
//! Two implementations give one result: [`portable`] on whole 64-bit words
//! (row rotations, shifted cell groups and the bitsliced S-box), and, on
//! x86-64 with SSSE3, [`nibbles`], which holds one cell per byte so PSHUFB
//! performs each S-box, cell shuffle and cell rotation as a single lookup.
//! [`compute`] selects by CPUID once.

const CELL_MASK: u64 = 0x1111_1111_1111_1111;
/// QARMA's τ (MIDORI's cell shuffle): output cell `i` is input cell
/// `SHUFFLE[i]`.
const SHUFFLE: [u8; 16] = [13, 6, 11, 0, 7, 12, 1, 10, 8, 3, 14, 5, 2, 9, 4, 15];
const INV_SHUFFLE: [u8; 16] = [3, 6, 12, 9, 14, 11, 1, 4, 8, 13, 7, 2, 5, 0, 10, 15];
/// The tweak's cell shuffle `h`, and the cells whose LFSR `ω` then steps.
const TWEAK_SHUFFLE: [u8; 16] = [4, 5, 6, 7, 11, 2, 3, 8, 12, 13, 14, 15, 0, 1, 10, 9];
const TWEAK_ROTATED: u16 = 0xd894;
/// The S-box σ₂ (PRINCE's), cell value to cell value.
const SBOX: [u8; 16] = [11, 6, 8, 15, 12, 0, 9, 14, 3, 7, 4, 5, 13, 2, 1, 10];
const ROUND_CONSTANTS: [u64; 5] = [
    0,
    0x1319_8a2e_0370_7344,
    0xa409_3822_299f_31d0,
    0x082e_fa98_ec4e_6c89,
    0x4528_21e6_38d0_1377,
];
/// α, which the backward rounds add with their constants.
const ALPHA: u64 = 0xc0ac_29b7_c97c_50dd;
const ROUNDS: usize = ROUND_CONSTANTS.len();

/// `ComputePACQARMA(data, modifier, key)`: the key's high word is w0, its
/// low word k0.
pub(super) fn compute(data: u64, modifier: u64, key: &[u64; 2]) -> u64 {
    #[cfg(target_arch = "x86_64")]
    if nibbles::available() {
        // SAFETY: CPUID reports SSSE3.
        return unsafe { nibbles::compute(data, modifier, key) };
    }
    portable::compute(data, modifier, key)
}

/// w1 = o(w0): w0 rotated right one bit, its top bit XORed with bit 0.
const fn reflected(key_high: u64) -> u64 {
    key_high.rotate_right(1) ^ (key_high >> 63)
}

/// ω, the tweak cells' LFSR: one step right, the new top bit b0 ^ b1.
const fn lfsr(cell: u8) -> u8 {
    (cell >> 1) | (((cell ^ (cell >> 1)) & 1) << 3)
}

/// A cell rotated left `bits`.
const fn rotate_cell(cell: u8, bits: u32) -> u8 {
    ((cell << bits) | (cell >> (4 - bits))) & 15
}

const fn inverse(order: &[u8; 16]) -> [u8; 16] {
    let mut out = [0; 16];
    let mut index = 0;
    while index < 16 {
        out[order[index] as usize] = index as u8;
        index += 1;
    }
    out
}

const INV_SBOX: [u8; 16] = inverse(&SBOX);
const _: () = {
    let check = inverse(&SHUFFLE);
    let mut index = 0;
    while index < 16 {
        assert!(check[index] == INV_SHUFFLE[index]);
        index += 1;
    }
};

pub(super) mod portable {
    use super::*;

    /// A cell permutation's source cells that move the same distance, and
    /// that distance in cells (positive towards the top).
    #[derive(Clone, Copy)]
    struct Shift {
        mask: u64,
        cells: i32,
    }

    /// The distinct distances of `order`'s moves.
    const fn shift_count(order: &[u8; 16]) -> usize {
        let mut seen = [false; 31];
        let mut count = 0;
        let mut index = 0;
        while index < 16 {
            let distance = (index as i32 - order[index] as i32 + 15) as usize;
            if !seen[distance] {
                seen[distance] = true;
                count += 1;
            }
            index += 1;
        }
        count
    }

    const fn shifts<const N: usize>(order: &[u8; 16]) -> [Shift; N] {
        let mut out = [Shift { mask: 0, cells: 0 }; N];
        let mut used = 0;
        let mut index = 0;
        while index < 16 {
            let cells = index as i32 - order[index] as i32;
            let mut group = 0;
            while group < used && out[group].cells != cells {
                group += 1;
            }
            if group == used {
                out[used].cells = cells;
                used += 1;
            }
            out[group].mask |= 0xf << (4 * order[index] as u32);
            index += 1;
        }
        out
    }

    const SHUFFLE_SHIFTS: [Shift; shift_count(&SHUFFLE)] = shifts(&SHUFFLE);
    const INV_SHUFFLE_SHIFTS: [Shift; shift_count(&INV_SHUFFLE)] = shifts(&INV_SHUFFLE);
    const TWEAK_SHIFTS: [Shift; shift_count(&TWEAK_SHUFFLE)] = shifts(&TWEAK_SHUFFLE);

    /// The cells set in `cells` as a nibble mask.
    const fn cell_mask(cells: u16) -> u64 {
        let mut mask = 0;
        let mut index = 0;
        while index < 16 {
            if cells & (1 << index) != 0 {
                mask |= 0xf << (4 * index);
            }
            index += 1;
        }
        mask
    }
    const TWEAK_ROTATED_MASK: u64 = cell_mask(TWEAK_ROTATED);

    #[inline(always)]
    fn permute(value: u64, shifts: &[Shift]) -> u64 {
        shifts.iter().fold(0, |out, shift| {
            let moved = value & shift.mask;
            out | if shift.cells >= 0 {
                moved << (4 * shift.cells)
            } else {
                moved >> (-4 * shift.cells)
            }
        })
    }

    /// Every cell rotated left `bits` (1 or 2).
    #[inline(always)]
    fn rotate_cells(value: u64, bits: u32) -> u64 {
        let wrapped = CELL_MASK * ((1 << bits) - 1);
        ((value << bits) & !wrapped) | ((value >> (4 - bits)) & wrapped)
    }

    /// MixColumns: row r is ρ(row r+1) ^ ρ²(row r+2) ^ ρ(row r+3).
    #[inline(always)]
    fn mix(value: u64) -> u64 {
        rotate_cells(value.rotate_right(16) ^ value.rotate_right(48), 1)
            ^ rotate_cells(value.rotate_right(32), 2)
    }

    /// Sixteen S-box lookups in parallel bitplanes: the algebraic normal
    /// form of σ₂ (and of its inverse).
    #[inline(always)]
    pub(in super::super) fn substitute(value: u64, inverse: bool) -> u64 {
        let m = CELL_MASK;
        let a = value & m;
        let b = (value >> 1) & m;
        let c = (value >> 2) & m;
        let d = (value >> 3) & m;
        let ab = a & b;
        let ac = a & c;
        let ad = a & d;
        let bc = b & c;
        let bd = b & d;
        let cd = c & d;
        let abc = ab & c;
        let abd = ab & d;
        let acd = ac & d;
        let bcd = bc & d;
        let planes = if inverse {
            [
                m ^ a ^ c ^ bc ^ abc ^ d ^ ad ^ bd ^ abd ^ cd ^ bcd,
                a ^ ab ^ c ^ ac ^ bc ^ abc ^ d ^ ad ^ acd,
                m ^ ab ^ c ^ abc ^ d ^ ad ^ bd ^ abd ^ acd ^ bcd,
                a ^ b ^ ab ^ c ^ ac ^ ad ^ cd ^ bcd,
            ]
        } else {
            [
                m ^ a ^ b ^ c ^ ac ^ abc ^ ad ^ abd ^ cd ^ bcd,
                m ^ b ^ ab ^ c ^ bc ^ abd ^ acd,
                a ^ c ^ bc ^ bd ^ abd ^ bcd,
                m ^ a ^ ab ^ d ^ ad ^ abd ^ cd ^ acd ^ bcd,
            ]
        };
        planes[0] | (planes[1] << 1) | (planes[2] << 2) | (planes[3] << 3)
    }

    /// The next tweak: `h`, then `ω` on the rotated cells.
    #[inline(always)]
    fn tweak(value: u64) -> u64 {
        let shuffled = permute(value, &TWEAK_SHIFTS);
        let stepped =
            ((shuffled >> 1) & (CELL_MASK * 7)) | (((shuffled ^ (shuffled >> 1)) & CELL_MASK) << 3);
        (shuffled & !TWEAK_ROTATED_MASK) | (stepped & TWEAK_ROTATED_MASK)
    }

    pub(in super::super) fn compute(data: u64, modifier: u64, key: &[u64; 2]) -> u64 {
        let [k0, w0] = *key;
        let w1 = reflected(w0);
        let mut tweaks = [modifier; ROUNDS + 1];
        for round in 1..=ROUNDS {
            tweaks[round] = tweak(tweaks[round - 1]);
        }
        let middle = tweaks[ROUNDS];
        let mut state = data ^ w0;
        for (round, constant) in ROUND_CONSTANTS.into_iter().enumerate() {
            state ^= k0 ^ tweaks[round] ^ constant;
            if round != 0 {
                state = mix(permute(state, &SHUFFLE_SHIFTS));
            }
            state = substitute(state, false);
        }
        state ^= w1 ^ middle;
        state = substitute(mix(permute(state, &SHUFFLE_SHIFTS)), false);
        state = mix(permute(state, &SHUFFLE_SHIFTS)) ^ k0;
        state = substitute(permute(state, &INV_SHUFFLE_SHIFTS), true);
        state = permute(mix(state), &INV_SHUFFLE_SHIFTS) ^ w0 ^ middle;
        for round in (0..ROUNDS).rev() {
            state = substitute(state, true);
            if round != 0 {
                state = permute(mix(state), &INV_SHUFFLE_SHIFTS);
            }
            state ^= ROUND_CONSTANTS[round] ^ k0 ^ tweaks[round] ^ ALPHA;
        }
        state ^ w1
    }
}

/// One cell per byte, for PSHUFB (SSSE3), in assembly: the bare-metal engine
/// is built for a soft-float target, whose Rust code may not use SSE, while
/// the processor runs SSE code (native blocks) all the same. The routine
/// follows the SysV ABI and touches only XMM0-XMM15, RAX, RCX, R8, its
/// arguments and [`TABLES`].
#[cfg(target_arch = "x86_64")]
pub(super) mod nibbles {
    use super::*;
    use core::mem::offset_of;
    use core::sync::atomic::{AtomicU8, Ordering};

    /// CPUID.1:ECX.SSSE3.
    const CPUID_SSSE3: u32 = 1 << 9;
    const UNKNOWN: u8 = 0;
    const ABSENT: u8 = 1;
    const PRESENT: u8 = 2;
    static SSSE3: AtomicU8 = AtomicU8::new(UNKNOWN);

    pub(in super::super) fn available() -> bool {
        match SSSE3.load(Ordering::Relaxed) {
            UNKNOWN => {
                let present = core::arch::x86_64::__cpuid(1).ecx & CPUID_SSSE3 != 0;
                SSSE3.store(if present { PRESENT } else { ABSENT }, Ordering::Relaxed);
                present
            }
            state => state == PRESENT,
        }
    }

    /// `value`'s cells, one per byte, as a constant.
    const fn spread_constant(value: u64) -> [u8; 16] {
        let mut out = [0; 16];
        let mut index = 0;
        while index < 16 {
            out[index] = ((value >> (4 * index)) & 15) as u8;
            index += 1;
        }
        out
    }

    /// A PSHUFB table of a cell function: byte `i` is cell `i`'s image,
    /// LFSR steps (`rotation` 0) or rotations left by `rotation` bits.
    const fn cell_table(rotation: u32) -> [u8; 16] {
        let mut out = [0; 16];
        let mut index = 0;
        while index < 16 {
            out[index] = if rotation == 0 {
                lfsr(index as u8)
            } else {
                rotate_cell(index as u8, rotation)
            };
            index += 1;
        }
        out
    }

    /// PSHUFB indices that read, for output cell `i`, the cell `rows` rows
    /// below `order`'s source of cell `i` (`after` true), or `order`'s
    /// source of the cell `rows` rows below `i` (`after` false).
    const fn row_shuffle(order: &[u8; 16], rows: usize, after: bool) -> [u8; 16] {
        let mut out = [0; 16];
        let mut index = 0;
        while index < 16 {
            out[index] = if after {
                ((order[index] as usize + 4 * rows) % 16) as u8
            } else {
                order[(index + 4 * rows) % 16]
            };
            index += 1;
        }
        out
    }

    const fn rotated_cells(cells: u16) -> [u8; 16] {
        let mut out = [0; 16];
        let mut index = 0;
        while index < 16 {
            out[index] = if cells & (1 << index) != 0 { 0xff } else { 0 };
            index += 1;
        }
        out
    }

    const fn constants(alpha: u64) -> [[u8; 16]; ROUNDS] {
        let mut out = [[0; 16]; ROUNDS];
        let mut round = 0;
        while round < ROUNDS {
            out[round] = spread_constant(ROUND_CONSTANTS[round] ^ alpha);
            round += 1;
        }
        out
    }

    /// The routine's 16-byte operands, aligned for SSE memory operands.
    #[repr(C, align(16))]
    pub(super) struct Tables {
        low_cells: [u8; 16],
        /// `pmaddubsw` weights joining a byte pair as low + 16 * high.
        pairs: [u8; 16],
        sbox: [u8; 16],
        inverse_sbox: [u8; 16],
        rotate_one: [u8; 16],
        rotate_two: [u8; 16],
        lfsr: [u8; 16],
        tweak_shuffle: [u8; 16],
        tweak_rotated: [u8; 16],
        inverse_shuffle: [u8; 16],
        /// mix(permute(x, SHUFFLE)): the shuffle into rows 1, 2 and 3 on.
        forward: [[u8; 16]; 3],
        /// permute(mix(x), INV_SHUFFLE): rows 1, 2 and 3 on, then the shuffle.
        backward: [[u8; 16]; 3],
        constants: [[u8; 16]; ROUNDS],
        /// The backward rounds' constants with α.
        alpha_constants: [[u8; 16]; ROUNDS],
    }

    pub(super) static TABLES: Tables = Tables {
        low_cells: [0x0f; 16],
        pairs: [1, 16, 1, 16, 1, 16, 1, 16, 1, 16, 1, 16, 1, 16, 1, 16],
        sbox: SBOX,
        inverse_sbox: INV_SBOX,
        rotate_one: cell_table(1),
        rotate_two: cell_table(2),
        lfsr: cell_table(0),
        tweak_shuffle: TWEAK_SHUFFLE,
        tweak_rotated: rotated_cells(TWEAK_ROTATED),
        inverse_shuffle: INV_SHUFFLE,
        forward: [
            row_shuffle(&SHUFFLE, 1, false),
            row_shuffle(&SHUFFLE, 2, false),
            row_shuffle(&SHUFFLE, 3, false),
        ],
        backward: [
            row_shuffle(&INV_SHUFFLE, 1, true),
            row_shuffle(&INV_SHUFFLE, 2, true),
            row_shuffle(&INV_SHUFFLE, 3, true),
        ],
        constants: constants(0),
        alpha_constants: constants(ALPHA),
    };

    /// `ComputePACQARMA(data, modifier, key)` with PSHUFB.
    ///
    /// # Safety
    ///
    /// The processor implements SSSE3 ([`available`]) and `key` is readable.
    // RAX holds TABLES. XMM0-XMM5 are the tweaks T0..T5, XMM6 the state,
    // XMM8 k0, XMM9 w0, XMM10 w1 and XMM7, XMM11-XMM13 temporaries.
    #[unsafe(naked)]
    unsafe extern "sysv64" fn qarma5_ssse3(data: u64, modifier: u64, key: *const [u64; 2]) -> u64 {
        core::arch::naked_asm!(
            // dst = the cells of gpr, one per byte; clobbers tmp.
            ".macro qarma_spread dst, gpr, tmp",
            "movq \\dst, \\gpr",
            "movdqa \\tmp, \\dst",
            "psrlw \\tmp, 4",
            "pand \\dst, xmmword ptr [rax + {low_cells}]",
            "pand \\tmp, xmmword ptr [rax + {low_cells}]",
            "punpcklbw \\dst, \\tmp",
            ".endm",
            // dst = h then ω of src; clobbers xmm7.
            ".macro qarma_tweak dst, src",
            "movdqa \\dst, \\src",
            "pshufb \\dst, xmmword ptr [rax + {tweak_shuffle}]",
            "movdqa xmm7, xmmword ptr [rax + {lfsr}]",
            "pshufb xmm7, \\dst",
            "pxor xmm7, \\dst",
            "pand xmm7, xmmword ptr [rax + {tweak_rotated}]",
            "pxor \\dst, xmm7",
            ".endm",
            // xmm6 = ρ(rows 1 and 3) ^ ρ²(row 2), each read through the three
            // shuffles at rows; clobbers xmm11-xmm13.
            ".macro qarma_linear rows",
            "movdqa xmm11, xmm6",
            "pshufb xmm11, xmmword ptr [rax + \\rows]",
            "movdqa xmm12, xmm6",
            "pshufb xmm12, xmmword ptr [rax + \\rows + 32]",
            "pxor xmm11, xmm12",
            "movdqa xmm12, xmmword ptr [rax + {rotate_one}]",
            "pshufb xmm12, xmm11",
            "pshufb xmm6, xmmword ptr [rax + \\rows + 16]",
            "movdqa xmm13, xmmword ptr [rax + {rotate_two}]",
            "pshufb xmm13, xmm6",
            "movdqa xmm6, xmm12",
            "pxor xmm6, xmm13",
            ".endm",
            // xmm6 = the table's image of every cell; clobbers xmm7.
            ".macro qarma_substitute table",
            "movdqa xmm7, xmmword ptr [rax + \\table]",
            "pshufb xmm7, xmm6",
            "movdqa xmm6, xmm7",
            ".endm",
            // xmm6 ^= k0 ^ the tweak ^ the round constant at offset.
            ".macro qarma_add_round tweak, constant",
            "pxor xmm6, xmm8",
            "pxor xmm6, \\tweak",
            "pxor xmm6, xmmword ptr [rax + \\constant]",
            ".endm",
            "lea rax, [rip + {tables}]",
            "mov rcx, qword ptr [rdx + 8]",
            "qarma_spread xmm9, rcx, xmm7",
            // w1 = w0 rotated right one bit, its top bit XORed with bit 0.
            "mov r8, rcx",
            "ror rcx, 1",
            "shr r8, 63",
            "xor rcx, r8",
            "qarma_spread xmm10, rcx, xmm7",
            "mov rcx, qword ptr [rdx]",
            "qarma_spread xmm8, rcx, xmm7",
            "qarma_spread xmm0, rsi, xmm7",
            "qarma_tweak xmm1, xmm0",
            "qarma_tweak xmm2, xmm1",
            "qarma_tweak xmm3, xmm2",
            "qarma_tweak xmm4, xmm3",
            "qarma_tweak xmm5, xmm4",
            "qarma_spread xmm6, rdi, xmm7",
            "pxor xmm6, xmm9",
            "qarma_add_round xmm0, {constants}",
            "qarma_substitute {sbox}",
            ".irp round, 1, 2, 3, 4",
            "qarma_add_round xmm\\round, {constants} + 16 * \\round",
            "qarma_linear {forward}",
            "qarma_substitute {sbox}",
            ".endr",
            "pxor xmm6, xmm10",
            "pxor xmm6, xmm5",
            "qarma_linear {forward}",
            "qarma_substitute {sbox}",
            "qarma_linear {forward}",
            "pxor xmm6, xmm8",
            "pshufb xmm6, xmmword ptr [rax + {inverse_shuffle}]",
            "qarma_substitute {inverse_sbox}",
            "qarma_linear {backward}",
            "pxor xmm6, xmm9",
            "pxor xmm6, xmm5",
            ".irp round, 4, 3, 2, 1",
            "qarma_substitute {inverse_sbox}",
            "qarma_linear {backward}",
            "qarma_add_round xmm\\round, {alpha_constants} + 16 * \\round",
            ".endr",
            "qarma_substitute {inverse_sbox}",
            "qarma_add_round xmm0, {alpha_constants}",
            "pxor xmm6, xmm10",
            // Each byte pair as low + 16 * high, then the words as bytes.
            "pmaddubsw xmm6, xmmword ptr [rax + {pairs}]",
            "packuswb xmm6, xmm6",
            "movq rax, xmm6",
            "ret",
            ".purgem qarma_spread",
            ".purgem qarma_tweak",
            ".purgem qarma_linear",
            ".purgem qarma_substitute",
            ".purgem qarma_add_round",
            tables = sym TABLES,
            low_cells = const offset_of!(Tables, low_cells),
            pairs = const offset_of!(Tables, pairs),
            sbox = const offset_of!(Tables, sbox),
            inverse_sbox = const offset_of!(Tables, inverse_sbox),
            rotate_one = const offset_of!(Tables, rotate_one),
            rotate_two = const offset_of!(Tables, rotate_two),
            lfsr = const offset_of!(Tables, lfsr),
            tweak_shuffle = const offset_of!(Tables, tweak_shuffle),
            tweak_rotated = const offset_of!(Tables, tweak_rotated),
            inverse_shuffle = const offset_of!(Tables, inverse_shuffle),
            forward = const offset_of!(Tables, forward),
            backward = const offset_of!(Tables, backward),
            constants = const offset_of!(Tables, constants),
            alpha_constants = const offset_of!(Tables, alpha_constants),
        )
    }

    /// # Safety
    ///
    /// The processor implements SSSE3 ([`available`]).
    pub(in super::super) unsafe fn compute(data: u64, modifier: u64, key: &[u64; 2]) -> u64 {
        // SAFETY: the caller checked SSSE3; the routine reads only `key` and
        // TABLES and clobbers only registers the ABI lets a call clobber.
        unsafe { qarma5_ssse3(data, modifier, key) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cipher cell by cell, as Arm's pseudocode states it: the reference
    /// both implementations are compared with.
    mod reference {
        use super::super::*;

        fn cell(value: u64, index: usize) -> u64 {
            (value >> (index * 4)) & 15
        }
        fn substitute(value: u64, table: &[u8; 16]) -> u64 {
            (0..16).fold(0, |out, index| {
                out | u64::from(table[cell(value, index) as usize]) << (index * 4)
            })
        }
        pub(super) fn permute(value: u64, order: &[u8; 16]) -> u64 {
            order.iter().enumerate().fold(0, |out, (index, source)| {
                out | (cell(value, usize::from(*source)) << (index * 4))
            })
        }
        fn rotate(value: u64, count: u32) -> u64 {
            u64::from(rotate_cell(value as u8, count))
        }
        pub(super) fn mix(value: u64) -> u64 {
            let mut out = 0;
            for column in 0..4 {
                let [a, b, c, d] = core::array::from_fn(|row| cell(value, column + row * 4));
                let rows = [
                    rotate(d, 1) ^ rotate(c, 2) ^ rotate(b, 1),
                    rotate(d, 2) ^ rotate(c, 1) ^ rotate(a, 1),
                    rotate(d, 1) ^ rotate(b, 1) ^ rotate(a, 2),
                    rotate(c, 1) ^ rotate(b, 2) ^ rotate(a, 1),
                ];
                for (row, value) in rows.into_iter().enumerate() {
                    out |= value << ((column + row * 4) * 4);
                }
            }
            out
        }
        fn tweak_rotation(value: u64, inverse: bool) -> u64 {
            if inverse {
                ((value << 1) & 15) | ((value ^ (value >> 3)) & 1)
            } else {
                u64::from(lfsr(value as u8))
            }
        }
        pub(super) fn tweak(value: u64, inverse: bool) -> u64 {
            let mut out = 0;
            for (destination, source) in TWEAK_SHUFFLE.into_iter().enumerate() {
                let (input, output) = if inverse {
                    (destination, usize::from(source))
                } else {
                    (usize::from(source), destination)
                };
                let mut nibble = cell(value, input);
                if TWEAK_ROTATED & (1 << destination) != 0 {
                    nibble = tweak_rotation(nibble, inverse);
                }
                out |= nibble << (output * 4);
            }
            out
        }
        pub(super) fn qarma5(data: u64, modifier: u64, key: &[u64; 2]) -> u64 {
            let [key_low, key_high] = *key;
            let reflected_key = reflected(key_high);
            let mut state = data ^ key_high;
            let mut running = modifier;
            for (round, constant) in ROUND_CONSTANTS.into_iter().enumerate() {
                state ^= key_low ^ running ^ constant;
                if round != 0 {
                    state = mix(permute(state, &SHUFFLE));
                }
                state = substitute(state, &SBOX);
                running = tweak(running, false);
            }
            state ^= reflected_key ^ running;
            state = substitute(mix(permute(state, &SHUFFLE)), &SBOX);
            state = mix(permute(state, &SHUFFLE)) ^ key_low;
            state = substitute(permute(state, &INV_SHUFFLE), &INV_SBOX);
            state = permute(mix(state), &INV_SHUFFLE) ^ key_high ^ running;
            for (round, constant) in ROUND_CONSTANTS.into_iter().rev().enumerate() {
                state = substitute(state, &INV_SBOX);
                if round != 4 {
                    state = permute(mix(state), &INV_SHUFFLE);
                }
                running = tweak(running, true);
                state ^= constant ^ key_low ^ running ^ ALPHA;
            }
            state ^ reflected_key
        }
    }

    /// xorshift64*, for reproducible operands.
    fn operands(count: usize) -> impl Iterator<Item = [u64; 4]> {
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            seed ^= seed >> 12;
            seed ^= seed << 25;
            seed ^= seed >> 27;
            seed.wrapping_mul(0x2545_f491_4f6c_dd1d)
        };
        (0..count).map(move |_| [next(), next(), next(), next()])
    }

    #[test]
    fn the_s_box_bitplanes_mix_and_tweaks_match_the_cell_reference() {
        for (nibble, expected) in SBOX.into_iter().enumerate() {
            let repeated = (nibble as u64) * CELL_MASK;
            let expected = u64::from(expected) * CELL_MASK;
            assert_eq!(portable::substitute(repeated, false), expected);
            assert_eq!(portable::substitute(expected, true), repeated);
        }
        for value in [0, 1, u64::MAX, 0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210] {
            let permuted = reference::permute(value, &SHUFFLE);
            assert_eq!(reference::permute(permuted, &INV_SHUFFLE), value);
            assert_eq!(
                reference::mix(reference::mix(value)),
                value,
                "M is involutory"
            );
            assert_eq!(
                reference::tweak(reference::tweak(value, false), true),
                value
            );
            assert_eq!(
                reference::tweak(reference::tweak(value, true), false),
                value
            );
        }
    }

    #[test]
    fn both_implementations_match_the_cell_reference() {
        for [data, modifier, low, high] in operands(4096) {
            let key = [low, high];
            let expected = reference::qarma5(data, modifier, &key);
            assert_eq!(portable::compute(data, modifier, &key), expected);
            #[cfg(target_arch = "x86_64")]
            if nibbles::available() {
                // SAFETY: CPUID reports SSSE3.
                assert_eq!(unsafe { nibbles::compute(data, modifier, &key) }, expected);
            }
            assert_eq!(compute(data, modifier, &key), expected);
        }
    }

    /// Times each implementation on the host: `cargo test --release -p
    /// stela-runtime --lib qarma::tests::timing -- --ignored --nocapture`.
    #[cfg(feature = "std")]
    #[test]
    #[ignore = "manual: opt-in"]
    fn timing() {
        extern crate std;
        use std::{hint::black_box, println, time::Instant};
        const CALLS: u64 = 2_000_000;
        let time = |name: &str, function: &dyn Fn(u64, u64, &[u64; 2]) -> u64| {
            let key = [0x1122_3344_5566_7788, 0x99aa_bbcc_ddee_ff00];
            let mut chain = 0x4000_u64;
            let start = Instant::now();
            for modifier in 0..CALLS {
                chain = function(black_box(chain), modifier, &key);
            }
            let nanoseconds = start.elapsed().as_nanos() as f64 / CALLS as f64;
            println!("{name}: {nanoseconds:.1} ns/call ({chain:#x})");
        };
        time("reference", &|d, m, k| reference::qarma5(d, m, k));
        time("portable", &|d, m, k| portable::compute(d, m, k));
        #[cfg(target_arch = "x86_64")]
        if nibbles::available() {
            // SAFETY: CPUID reports SSSE3.
            time("ssse3", &|d, m, k| unsafe { nibbles::compute(d, m, k) });
        }
    }
}
