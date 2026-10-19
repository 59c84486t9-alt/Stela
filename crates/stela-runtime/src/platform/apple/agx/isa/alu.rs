//! Arithmetic: immediates and special registers, integer add/multiply,
//! conversions, shifts and bitfields, bitwise truth tables, floating-point
//! arithmetic and unary functions, and compare-and-select.
//!
//! Semantics (Public unless marked): applegpu's `exec_thread` definitions for
//! `iadd`/`imadd` (extension, the shift of the second or third source,
//! saturation), the bitfield family (`bfi`, `bfeil`, `extr`, `shlhi`,
//! `shrhi`, `asr`, `asrh`, the five-bit mask with 0 meaning 32 bits), the
//! bitwise truth table indexed by `a + 2b`, `ffs` as the highest set bit
//! (-1 for zero), and the float rules: f32 sources and results flush
//! denormals, f16 ones do not, and every add, multiply and fused
//! multiply-add is rounded once (computed in f64 rounded to odd, then to the
//! destination). Mesa's lowering confirms the operand roles (`fsqrt` is
//! `x * rsqrts(x)`, `fsin` is `sinr` then `sinc` then a multiply, `fmin` is
//! `fcsel` with the NaN-losing `fltn`).

use super::decode::{Instr, Operand, Value};
use super::float::{f64_to_f32_ftz, f64_to_half, round_to_odd_fma};
use super::generated::{Imm, Mod, Op};
use super::machine::{Error, SimdGroup, Step, lanes, sign_extend};
use super::math;

/// `mfsr` register numbers (`AGX2.xml` enum `sr`).
mod sr {
    pub const THREADGROUP_IN_GRID: u32 = 0;
    pub const THREADS_PER_THREADGROUP: u32 = 4;
    pub const DISPATCH_THREADS_PER_THREADGROUP: u32 = 8;
    pub const THREADGROUP_WIDTH: u32 = 12;
    pub const THREADGROUP_HEIGHT: u32 = 13;
    pub const SAMPLES_LOG2: u32 = 14;
    pub const CORE_INDEX: u32 = 20;
    pub const VM_SLOT: u32 = 21;
    pub const THREAD_IN_THREADGROUP: u32 = 48;
    pub const THREAD_INDEX_IN_THREADGROUP: u32 = 51;
    pub const THREAD_INDEX_IN_SIMDGROUP: u32 = 52;
    pub const SIMDGROUP_INDEX_IN_THREADGROUP: u32 = 53;
    pub const ACTIVE_THREAD_INDEX_IN_QUADGROUP: u32 = 56;
    pub const TOTAL_ACTIVE_THREADS_IN_QUADGROUP: u32 = 57;
    pub const ACTIVE_THREAD_INDEX_IN_SIMDGROUP: u32 = 58;
    pub const TOTAL_ACTIVE_THREADS_IN_SIMDGROUP: u32 = 59;
    pub const INTERNAL_COVERAGE_MASK: u32 = 60;
    pub const BACKFACING: u32 = 62;
    pub const IS_ACTIVE_THREAD: u32 = 63;
    pub const THREAD_IN_GRID: u32 = 80;
    pub const INPUT_SAMPLE_MASK: u32 = 124;
}

/// `convert` rounding (`AGX2.xml` enum `round`).
const ROUND_TO_ZERO: u32 = 0;

/// The bit positions of a `bitop` truth table in the instruction's exact
/// bits: entries 0 and 1 at 26 and 27, 2 and 3 at 38 and 39.
const TRUTH_TABLE_BITS: [u32; 4] = [26, 27, 38, 39];

/// The bitfield mask field: 0 is all 32 bits.
fn bitfield_mask(m: i64) -> u64 {
    if m == 0 { 0xffff_ffff } else { (1u64 << m) - 1 }
}

/// Saturate to a destination width (applegpu `ISaturatableInstructionDesc`).
fn saturate_int(value: i128, bits: u32, signed: bool) -> i128 {
    let (minimum, maximum) = if signed {
        (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1)
    } else {
        (0, (1i128 << bits) - 1)
    };
    value.clamp(minimum, maximum)
}

/// The size an operand occupies, for saturation's width checks.
pub(super) fn size(operand: &Operand) -> u32 {
    match operand.value {
        Value::Reg(_) | Value::Uniform(_) => u32::from(operand.size),
        _ => 16,
    }
}

/// An integer comparison (`icond`): bits 1:0 equal, less, greater; bit 2
/// signed; bit 3 inverts.
pub(super) fn icompare(cond: u32, a: u64, a_bits: u32, b: u64, b_bits: u32) -> bool {
    let signed = cond & 4 != 0;
    let widen = |value: u64, bits: u32| -> i128 {
        if signed {
            i128::from(sign_extend(value, bits))
        } else {
            i128::from(value & mask(bits))
        }
    };
    let (a, b) = (widen(a, a_bits), widen(b, b_bits));
    let result = match cond & 3 {
        0 => a == b,
        1 => a < b,
        _ => a > b,
    };
    result != (cond & 8 != 0)
}

/// A float comparison (`fcond`): bits 2:0 select equal, less, greater, the
/// NaN-losing less and greater (`fltn`, `fgtn`, as `fmin`/`fmax` use them:
/// true when only the second operand is NaN), greater-equal and
/// less-equal; bit 3 inverts.
pub(super) fn fcompare(cond: u32, a: f64, b: f64) -> bool {
    let result = match cond & 7 {
        0 => a == b,
        1 => a < b,
        2 => a > b,
        3 => !a.is_nan() && (b.is_nan() || a < b),
        5 => a >= b,
        6 => a <= b,
        _ => !a.is_nan() && (b.is_nan() || a > b),
    };
    result != (cond & 8 != 0)
}

pub(super) fn mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

impl SimdGroup {
    pub(super) fn alu(&mut self, instr: &Instr) -> Result<Step, Error> {
        let active = self.active();
        for lane in lanes(active) {
            self.alu_lane(instr, lane, active)?;
        }
        Ok(Step::Next)
    }

    fn alu_lane(&mut self, instr: &Instr, lane: usize, active: u32) -> Result<(), Error> {
        use Op::*;
        let dest = instr.dest();
        let saturate = instr.flag(Mod::Saturate);
        match instr.op() {
            Ldimm16 | Ldimm32 => {
                let value = instr.immediate(Imm::Imm).unwrap_or(0) as u64;
                self.put(lane, &dest, 0, value)
            }
            Mfsr => {
                let value = self.special(lane, instr.modifier(Mod::Sr).unwrap_or(0), active)?;
                self.put(lane, &dest, 0, u64::from(value))
            }
            Iadd | Isub => {
                let (a_op, b_op) = (instr.source(0), instr.source(1));
                let a = self.int(lane, &a_op)?;
                let mut b = self.int(lane, &b_op)?;
                if instr.op() == Isub {
                    b = -b;
                }
                let shift = instr.modifier(Mod::Shift).unwrap_or(0);
                b <<= shift;
                let result = a + b;
                let saturating = saturate
                    && shift == 0
                    && size(&a_op) <= 32
                    && size(&b_op) <= 32
                    && dest.size <= 32;
                self.put_int(lane, &dest, result, saturating, a_op.sx || b_op.sx)
            }
            Imul | Imadd | Imsub => {
                let (a_op, b_op) = (instr.source(0), instr.source(1));
                let a = self.int(lane, &a_op)?;
                let b = self.int(lane, &b_op)?;
                let (mut c, c_op) = if instr.op() == Imul {
                    (0, Operand::default())
                } else {
                    let c_op = instr.source(2);
                    (self.int(lane, &c_op)?, c_op)
                };
                if instr.op() == Imsub {
                    c = -c;
                }
                let shift = instr.modifier(Mod::Shift).unwrap_or(0);
                c <<= shift;
                let result = a.wrapping_mul(b) + c;
                let saturating = saturate && shift == 0 && size(&c_op) <= 32 && dest.size <= 32;
                self.put_int(
                    lane,
                    &dest,
                    result,
                    saturating,
                    a_op.sx || b_op.sx || c_op.sx,
                )
            }
            U8ToF | S8ToF | U16ToF | S16ToF | U32ToF | S32ToF => {
                let source = instr.source(0);
                let bits = self.bits(lane, &source, 0)?;
                let value = match instr.op() {
                    U8ToF => bits & 0xff,
                    S8ToF => sign_extend(bits, 8) as u64,
                    U16ToF => bits & 0xffff,
                    S16ToF => sign_extend(bits, 16) as u64,
                    U32ToF => bits & 0xffff_ffff,
                    _ => sign_extend(bits, 32) as u64,
                };
                let signed = matches!(instr.op(), S8ToF | S16ToF | S32ToF);
                let exact = if signed {
                    value as i64 as f64
                } else {
                    value as f64
                };
                let rtz = instr.modifier(Mod::Round) == Some(ROUND_TO_ZERO);
                self.put_rounded(lane, &dest, exact, rtz)
            }
            FToU16 | FToS16 | FToU32 | FToS32 => {
                let value = self.float(lane, &instr.source(0))?;
                let rtz = instr.modifier(Mod::Round) == Some(ROUND_TO_ZERO);
                let integral = if rtz {
                    math::trunc(value)
                } else {
                    super::float::round_even(value)
                };
                // Out-of-range values saturate and NaN converts to 0
                // (Inferred: the Metal conversion rules).
                let (minimum, maximum) = match instr.op() {
                    FToU16 => (0.0, 65_535.0),
                    FToS16 => (-32_768.0, 32_767.0),
                    FToU32 => (0.0, 4_294_967_295.0),
                    _ => (-2_147_483_648.0, 2_147_483_647.0),
                };
                let result = if integral.is_nan() {
                    0
                } else {
                    integral.clamp(minimum, maximum) as i64
                };
                self.put(lane, &dest, 0, result as u64)
            }
            Shl | Shr | Bfi | Bfeil | Extr | Shlhi | Shrhi | Asr | Asrh => {
                let (a_op, b_op, c_op) = match instr.op() {
                    // The binary shifts leave the first source empty.
                    Shl | Shr => (Operand::default(), instr.source(0), instr.source(1)),
                    _ => (instr.source(0), instr.source(1), instr.source(2)),
                };
                let a = self.bits(lane, &a_op, 0)? & mask(size(&a_op));
                let b = self.bits(lane, &b_op, 0)? & mask(size(&b_op));
                let c = self.bits(lane, &c_op, 0)?;
                let m = bitfield_mask(instr.immediate(Imm::Bitmask).unwrap_or(0));
                let result = match instr.op() {
                    Shl | Bfi => {
                        let s = c & 0x7f;
                        let shifted = |v: u64| if s >= 64 { 0 } else { v << s };
                        (a & !shifted(m)) | shifted(b & m)
                    }
                    Shr | Bfeil => {
                        let s = c & 0x7f;
                        (a & !m) | (if s >= 64 { 0 } else { b >> s } & m)
                    }
                    Extr => {
                        let s = (c & 0x7f) as u32;
                        let joined = (u128::from(b) << 32) | u128::from(a);
                        ((joined >> s) as u64) & m
                    }
                    Shlhi => {
                        let s = (c & 0x7f) as u32;
                        let shifted_mask = u128::from(m) << s.saturating_sub(32);
                        let value = (u128::from(b) << s) >> 32;
                        ((value & shifted_mask) | (u128::from(a) & !shifted_mask)) as u64
                    }
                    Shrhi => {
                        let s = (c & 0x7f) as u32;
                        let shifted_mask = (u128::from(m) << 32) >> s.min(32);
                        let value = (u128::from(b) << 32) >> s;
                        ((value & shifted_mask) | (u128::from(a) & !shifted_mask)) as u64
                    }
                    Asr => {
                        let s = (b & 0x7f) as u32;
                        (i128::from(sign_extend(a, size(&a_op))) >> s.min(127)) as u64
                    }
                    _ => {
                        let s = (b & 0x7f) as u32;
                        ((i128::from(sign_extend(a, size(&a_op))) << 32) >> s.min(127)) as u64
                    }
                };
                self.put(lane, &dest, 0, result)
            }
            NotA | Mov | Not | MovA | Zero | And | Andn1 | Andn2 | Xor | Or | Nor | Xnor | Orn1
            | Orn2 | Nand | One => {
                let table = TRUTH_TABLE_BITS
                    .iter()
                    .enumerate()
                    .fold(0u32, |t, (i, &bit)| {
                        t | ((instr.spec.exact >> bit) as u32 & 1) << i
                    });
                let a = self.bits(lane, &instr.source(0), 0)?;
                let b = match instr.sources().get(1) {
                    Some(b) => self.bits(lane, b, 0)?,
                    None => 0,
                };
                let mut result = 0u64;
                for bit in 0..u32::from(dest.size) {
                    let k = (a >> bit & 1) + 2 * (b >> bit & 1);
                    result |= u64::from(table >> k & 1) << bit;
                }
                self.put(lane, &dest, 0, result)
            }
            Bitrev | Popcnt | Ffs => {
                let source = instr.source(0);
                let bits = size(&source);
                let value = self.bits(lane, &source, 0)? & mask(bits);
                let result = match instr.op() {
                    Bitrev => value.reverse_bits() >> (64 - u32::from(dest.size)),
                    Popcnt => u64::from(value.count_ones()),
                    _ if value == 0 => u64::MAX,
                    _ => u64::from(63 - value.leading_zeros()),
                };
                self.put(lane, &dest, 0, result)
            }
            Intl => {
                let a = self.bits(lane, &instr.source(0), 0)?;
                let b = self.bits(lane, &instr.source(1), 0)?;
                let mut result = 0u64;
                for bit in 0..u32::from(dest.size) / 2 {
                    result |= (a >> bit & 1) << (2 * bit) | (b >> bit & 1) << (2 * bit + 1);
                }
                self.put(lane, &dest, 0, result)
            }
            Fadd | Fmul | Ffma | Hadd | Hmul | Hfma => {
                let a = self.float(lane, &instr.source(0))?;
                let b = self.float(lane, &instr.source(1))?;
                let mut result = match instr.op() {
                    Fadd | Hadd => round_to_odd_fma(a, 1.0, b),
                    Fmul | Hmul => round_to_odd_fma(a, b, 0.0),
                    _ => round_to_odd_fma(a, b, self.float(lane, &instr.source(2))?),
                };
                if saturate {
                    result = math::saturate(result);
                }
                self.put_float(lane, &dest, result)
            }
            Floor | Ceil | Trunc | Rint | Rcp | Rsqrt | Rsqrts | Log2 | Exp2 | Sinr | Sinc => {
                let x = self.float(lane, &instr.source(0))?;
                let mut result = match instr.op() {
                    Floor => math::floor(x),
                    Ceil => math::ceil(x),
                    Trunc => math::trunc(x),
                    Rint => super::float::round_even(x),
                    Rcp => 1.0 / x,
                    Rsqrt => math::rsqrt(x),
                    Rsqrts => math::rsqrt_special(x),
                    Log2 => math::log2(x),
                    Exp2 => math::exp2(x),
                    Sinr => math::sin_quadrant(x),
                    _ => math::sinc_quarter_turn(x),
                };
                if saturate {
                    result = math::saturate(result);
                }
                self.put_float(lane, &dest, result)
            }
            Icsel | Fcsel => {
                let cond = instr.modifier(Mod::Condition).unwrap_or(0);
                let (a_op, b_op) = (instr.source(0), instr.source(1));
                let take = if instr.op() == Icsel {
                    let a = self.bits(lane, &a_op, 0)?;
                    let b = self.bits(lane, &b_op, 0)?;
                    icompare(cond, a, size(&a_op), b, size(&b_op))
                } else {
                    fcompare(cond, self.float(lane, &a_op)?, self.float(lane, &b_op)?)
                };
                let chosen = instr.source(if take { 2 } else { 3 });
                let value = self.bits(lane, &chosen, 0)?;
                self.put(lane, &dest, 0, value)
            }
            other => unreachable!("{other:?} is not an ALU instruction"),
        }
    }

    /// Write an integer result, saturated when asked.
    fn put_int(
        &mut self,
        lane: usize,
        dest: &Operand,
        value: i128,
        saturating: bool,
        signed: bool,
    ) -> Result<(), Error> {
        let value = if saturating {
            saturate_int(value, u32::from(dest.size), signed)
        } else {
            value
        };
        self.put(lane, dest, 0, value as u64)
    }

    /// Write an exact value rounded to the destination's float size, to
    /// nearest even or toward zero.
    fn put_rounded(
        &mut self,
        lane: usize,
        dest: &Operand,
        exact: f64,
        rtz: bool,
    ) -> Result<(), Error> {
        let bits = match dest.size {
            16 => {
                let mut half = f64_to_half(exact);
                if rtz && f64::from(super::float::half_to_f32(half)).abs() > exact.abs() {
                    half -= 1;
                }
                u64::from(half)
            }
            32 => {
                let mut single = f64_to_f32_ftz(exact).to_bits();
                if rtz && f64::from(f32::from_bits(single)).abs() > exact.abs() {
                    single -= 1;
                }
                u64::from(single)
            }
            _ => return Err(Error::Refused("a 64-bit float conversion")),
        };
        self.put(lane, dest, 0, bits)
    }

    /// A special register's value for `lane`.
    fn special(&self, lane: usize, register: u32, active: u32) -> Result<u32, Error> {
        let s = &self.specials;
        let missing = Error::Refused("a special register this stage does not provide");
        let axis = |base: u32| (register - base) as usize;
        let quad = active >> (lane & !3) & 0xf;
        Ok(match register {
            sr::THREADGROUP_IN_GRID..=2 => s.threadgroup_in_grid.ok_or(missing)?[axis(0)],
            sr::THREADS_PER_THREADGROUP..=6 => {
                s.threads_per_threadgroup.ok_or(missing)?[axis(sr::THREADS_PER_THREADGROUP)]
            }
            sr::DISPATCH_THREADS_PER_THREADGROUP..=10 => s
                .dispatch_threads_per_threadgroup
                .ok_or(missing)?[axis(sr::DISPATCH_THREADS_PER_THREADGROUP)],
            sr::THREADGROUP_WIDTH => s.threadgroup_size.ok_or(missing)?[0],
            sr::THREADGROUP_HEIGHT => s.threadgroup_size.ok_or(missing)?[1],
            sr::SAMPLES_LOG2 => s.samples_log2.ok_or(missing)?,
            sr::CORE_INDEX => s.core_index.ok_or(missing)?,
            sr::VM_SLOT => s.vm_slot.ok_or(missing)?,
            sr::THREAD_IN_THREADGROUP..=50 => {
                s.thread_in_threadgroup.ok_or(missing)?[lane][axis(sr::THREAD_IN_THREADGROUP)]
            }
            sr::THREAD_INDEX_IN_THREADGROUP => s.thread_index_in_threadgroup.ok_or(missing)?[lane],
            sr::THREAD_INDEX_IN_SIMDGROUP => lane as u32,
            sr::SIMDGROUP_INDEX_IN_THREADGROUP => {
                s.simdgroup_index_in_threadgroup.ok_or(missing)?
            }
            sr::ACTIVE_THREAD_INDEX_IN_QUADGROUP => (quad & ((1 << (lane & 3)) - 1)).count_ones(),
            sr::TOTAL_ACTIVE_THREADS_IN_QUADGROUP => quad.count_ones(),
            sr::ACTIVE_THREAD_INDEX_IN_SIMDGROUP => {
                (active & ((1u64 << lane) - 1) as u32).count_ones()
            }
            sr::TOTAL_ACTIVE_THREADS_IN_SIMDGROUP => active.count_ones(),
            sr::INTERNAL_COVERAGE_MASK => s.internal_coverage_mask.ok_or(missing)?[lane],
            sr::BACKFACING => s.backfacing.ok_or(missing)?[lane],
            // Zero for a helper thread (Mesa: "compare to zero to check if a
            // helper").
            sr::IS_ACTIVE_THREAD => u32::from(self.helpers >> lane & 1 == 0),
            sr::THREAD_IN_GRID..=82 => {
                s.thread_in_grid.ok_or(missing)?[lane][axis(sr::THREAD_IN_GRID)]
            }
            sr::INPUT_SAMPLE_MASK => s.input_sample_mask.ok_or(missing)?[lane],
            _ => {
                return Err(Error::Refused(
                    "the helper-program special registers are not modeled",
                ));
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::float::half_to_f32;
    use super::super::machine::tests::{finish, setup};
    use super::*;

    /// Run `text` on one thread with `init` applied, returning the group.
    fn run(text: &str, init: impl FnOnce(&mut SimdGroup)) -> SimdGroup {
        let (mut memory, mut group) = setup(&alloc::format!("{text}\nstop"), 1);
        init(&mut group);
        finish(&mut group, &mut memory).unwrap();
        group
    }

    fn f32_reg(group: &SimdGroup, half: usize) -> f32 {
        f32::from_bits(group.reg32(0, half))
    }

    #[test]
    fn immediates_and_moves() {
        let group = run("ldimm r1, 305419896\nldimm r2l, 48879\nmov r3, r1", |_| {});
        assert_eq!(group.reg32(0, 2), 0x1234_5678);
        assert_eq!(group.half(0, 4), 0xbeef);
        assert_eq!(group.reg32(0, 6), 0x1234_5678);
    }

    #[test]
    fn integer_add_extends_shifts_and_saturates() {
        let group = run(
            "iadd r2, r8l.sx, 1\n\
             iadd r3, r8l, 1\n\
             iadd r4, r1, r1, lsl 2\n\
             isub r5, r1, 7\n\
             iadd r6, r1.sx, r1.sx, sat\n\
             iadd r7, r1, r1, sat",
            |g| {
                g.set_half(0, 16, 0xffff);
                g.set_reg32(0, 2, 0x7fff_fff0);
            },
        );
        // A 16-bit -1 sign-extended, and the same bits zero-extended.
        assert_eq!(group.reg32(0, 4), 0);
        assert_eq!(group.reg32(0, 6), 0x1_0000);
        // r1 + (r1 << 2), wrapped to 32 bits.
        assert_eq!(group.reg32(0, 8), 0x7fff_ffb0);
        assert_eq!(group.reg32(0, 10), 0x7fff_ffe9);
        // Signed saturation clamps; the unsigned sum fits.
        assert_eq!(group.reg32(0, 12), 0x7fff_ffff);
        assert_eq!(group.reg32(0, 14), 0xffff_ffe0);
    }

    #[test]
    fn sixty_four_bit_adds_and_multiplies() {
        let group = run("iadd dr2, dr20, dr20\nimadd r6, r20.sx, r21.sx, 3", |g| {
            g.set_reg32(0, 40, 0xffff_ffff);
            g.set_reg32(0, 42, 0x1);
        });
        assert_eq!(
            u64::from(group.reg32(0, 4)) | u64::from(group.reg32(0, 6)) << 32,
            0x3_ffff_fffe
        );
        // r20 * r21 + 3 with r20 = -1 and r21 = 1 sign-extended.
        assert_eq!(group.reg32(0, 12), 2);
    }

    #[test]
    fn conversions_round_and_saturate() {
        let group = run(
            "u32_to_f r2, r20, rte\n\
             s16_to_f r3l, r1l, rtz\n\
             f_to_s32 r4, r5, rtz\n\
             f_to_u16 r6l, r5, rte",
            |g| {
                g.set_reg32(0, 40, 0x0100_0001);
                g.set_half(0, 2, 0x8000);
                g.set_reg32(0, 10, (-2.5f32).to_bits());
            },
        );
        // 2^24 + 1 rounds to even (2^24).
        assert_eq!(f32_reg(&group, 4), 16_777_216.0);
        assert_eq!(half_to_f32(group.half(0, 6)), -32768.0);
        assert_eq!(group.reg32(0, 8) as i32, -2);
        assert_eq!(group.half(0, 12), 0);
    }

    #[test]
    fn bitfields_follow_applegpu() {
        let group = run(
            "bfi r2, r20, r1, 8, 8\n\
             bfeil r3, 0, r1, 4, 4\n\
             extr r4, r20, r1, 16, 0\n\
             asr r5, r6, 4, 0, 0\n\
             shl r7, r1, 4\n\
             shr r8, r1, 4",
            |g| {
                g.set_reg32(0, 40, 0xaaaa_aaaa);
                g.set_reg32(0, 2, 0x1234_5678);
                g.set_reg32(0, 12, 0x8000_0000);
            },
        );
        assert_eq!(group.reg32(0, 4), 0xaaaa_78aa);
        assert_eq!(group.reg32(0, 6), 0x7);
        assert_eq!(group.reg32(0, 8), 0x5678_aaaa);
        assert_eq!(group.reg32(0, 10), 0xf800_0000);
        assert_eq!(group.reg32(0, 14), 0x2345_6780);
        assert_eq!(group.reg32(0, 16), 0x0123_4567);
    }

    #[test]
    fn truth_tables_and_bit_counts() {
        let group = run(
            "and r2, r20, r1\nandn1 r3, r20, r1\nxor r4, r20, r1\nnot r5, r20\n\
             popcnt r6, r1\nbitrev r7, r1\nffs r8, r1\nffs r9, 0\nintl r10, r11l, r12l",
            |g| {
                g.set_reg32(0, 40, 0xff00_ff00);
                g.set_reg32(0, 2, 0x0ff0_0ff0);
                g.set_half(0, 22, 0xffff);
            },
        );
        assert_eq!(group.reg32(0, 4), 0x0f00_0f00);
        // andn1 is (not a) and b.
        assert_eq!(group.reg32(0, 6), 0x00f0_00f0);
        assert_eq!(group.reg32(0, 8), 0xf0f0_f0f0);
        assert_eq!(group.reg32(0, 10), 0x00ff_00ff);
        assert_eq!(group.reg32(0, 12), 16);
        assert_eq!(group.reg32(0, 14), 0x0ff0_0ff0u32.reverse_bits());
        assert_eq!(group.reg32(0, 16), 27);
        assert_eq!(group.reg32(0, 18), u32::MAX);
        assert_eq!(group.reg32(0, 20), 0x5555_5555);
    }

    #[test]
    fn float_arithmetic_rounds_once_and_flushes_f32() {
        let group = run(
            "ffma r2, r20, r20, r1\n\
             fadd r3, r4, r4\n\
             fmul r5l, r20, 0.5\n\
             hadd r6l, r7h, r7h\n\
             fadd r8, r20.neg, 0.0, sat",
            |g| {
                // (1 + 2^-23)^2 - (1 + 2^-22) = 2^-46: one rounding keeps it.
                g.set_reg32(0, 40, (1.0f32 + f32::EPSILON).to_bits());
                g.set_reg32(0, 2, (-(1.0f32 + 2.0 * f32::EPSILON)).to_bits());
                // A subnormal f32 input flushes: 2 * 0 = 0.
                g.set_reg32(0, 8, 1);
                g.set_half(0, 15, 0x0001);
            },
        );
        assert_eq!(f32_reg(&group, 4), f32::EPSILON * f32::EPSILON);
        assert_eq!(group.reg32(0, 6), 0);
        // A 16-bit destination of an f32 multiply rounds to half.
        assert_eq!(half_to_f32(group.half(0, 10)), 0.5);
        // f16 subnormals survive: 2^-24 + 2^-24.
        assert_eq!(group.half(0, 12), 0x0002);
        assert_eq!(f32_reg(&group, 16), 0.0);
    }

    #[test]
    fn unary_functions() {
        let group = run(
            "floor r2, r20\nceil r3, r20\nrint r4, r1\nrcp r5, r20\nrsqrt r6, r10\nlog2 r7, r10\n\
             exp2 r8, r20\ntrunc r9, r20.neg",
            |g| {
                g.set_reg32(0, 40, 2.5f32.to_bits());
                g.set_reg32(0, 2, 3.5f32.to_bits());
                g.set_reg32(0, 20, 16.0f32.to_bits());
            },
        );
        assert_eq!(f32_reg(&group, 4), 2.0);
        assert_eq!(f32_reg(&group, 6), 3.0);
        assert_eq!(f32_reg(&group, 8), 4.0);
        assert_eq!(f32_reg(&group, 10), 0.4);
        assert_eq!(f32_reg(&group, 12), 0.25);
        assert_eq!(f32_reg(&group, 14), 4.0);
        assert!((f32_reg(&group, 16) - 5.656_854).abs() < 1e-6);
        assert_eq!(f32_reg(&group, 18), -2.0);
    }

    #[test]
    fn sine_is_sinr_then_sinc_then_a_multiply() {
        // Mesa's fsin_agx over quadrants: sin(q * pi / 2) for q in [0, 4).
        for q in [0.0f32, 0.5, 1.0, 1.5, 2.5, 3.0, 3.75] {
            let group = run("sinr r1, r20\nsinc r2, r1\nfmul r3, r2, r1", |g| {
                g.set_reg32(0, 40, q.to_bits());
            });
            let expected = (f64::from(q) * core::f64::consts::FRAC_PI_2).sin() as f32;
            assert!((f32_reg(&group, 6) - expected).abs() < 2e-7, "{q}");
        }
    }

    #[test]
    fn compare_select_conditions() {
        let group = run(
            "csel r2, r20, r1, 1, 2, slt\n\
             csel r3, r20, r1, 1, 2, ult\n\
             csel r4, r5, r6, r5, r6, fltn\n\
             csel r7, r6, r5, r6, r5, fltn",
            |g| {
                g.set_reg32(0, 40, (-1i32) as u32);
                g.set_reg32(0, 2, 1);
                g.set_reg32(0, 10, f32::NAN.to_bits());
                g.set_reg32(0, 12, 3.0f32.to_bits());
            },
        );
        assert_eq!(group.reg32(0, 4), 1);
        assert_eq!(group.reg32(0, 6), 2);
        // fmin(NaN, 3) and fmin(3, NaN) are both 3: NaN loses.
        assert_eq!(f32_reg(&group, 8), 3.0);
        assert_eq!(f32_reg(&group, 14), 3.0);
    }

    #[test]
    fn special_registers_come_from_the_stage_or_refuse() {
        let (mut memory, mut group) = setup(
            "mov r1, thread_index_in_simdgroup\nmov r2, total_active_threads_in_simdgroup\nstop",
            3,
        );
        finish(&mut group, &mut memory).unwrap();
        assert_eq!(group.reg32(2, 2), 2);
        assert_eq!(group.reg32(1, 4), 3);
        let (mut memory, mut group) = setup("mov r1, threadgroup_in_grid_x\nstop", 1);
        assert!(finish(&mut group, &mut memory).is_err());
    }
}
