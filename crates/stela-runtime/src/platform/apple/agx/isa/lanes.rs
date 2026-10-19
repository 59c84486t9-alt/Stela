//! Cross-thread operations: quad derivatives, ballots, shuffles and the
//! quad/SIMD-group reductions and prefix scans.
//!
//! Semantics (Public: `AGX2.xml`, Mesa `agx_compile.c`,
//! `agx_nir_lower_subgroups.c`, `agx_lower_divergent_shuffle.c`; Inferred
//! where marked):
//! - Quads are lanes `4q .. 4q + 3` laid out `x = lane & 1`, `y = lane >> 1 &
//!   1`. `dfdx`/`dfdy` are the fine differences within the quad, read from
//!   every present thread (helpers included), rounded once to the
//!   destination.
//! - `ballot` writes the mask of active threads whose comparison holds to
//!   every active thread; the bare `ballot` form is `ballot 1, 0, ine` (its
//!   fixed fields decode as that `icmp_ballot`). The quad form gives each
//!   thread its own quad's four bits in the low bits (Inferred placement).
//! - `shuffle` reads the value register of another lane: the index itself
//!   (`none`), lane ^ index, lane - index (`up`) or lane + index (`down`),
//!   within the quad for the quad form. Out-of-range `up`/`down` lanes keep
//!   their own value unless `rotate` wraps them (Inferred: Metal's
//!   `simd_shuffle_up/down` and `_rotate_` definitions). The hardware
//!   accumulates register indices across the whole quad, so an inactive
//!   thread's index can change an active thread's result (Mesa); a shuffle
//!   whose inactive quad threads hold an index other than zero or the
//!   active threads' common index has no defined result and refuses.
//! - `quad`/`simd` reduce over the active threads of the quad or group in
//!   lane order, or form the exclusive prefix (`prefix`) up to each thread,
//!   and write every active thread. Float folds round each step to the
//!   destination (Inferred order); `fmin`/`fmax` lose NaNs.

use super::alu::{fcompare, icompare, size};
use super::decode::{Instr, Operand};
use super::generated::{Mod, Op};
use super::machine::{Error, SIMD_WIDTH, SimdGroup, Step, lanes, sign_extend};

/// Lanes per quad.
const QUAD: usize = 4;
/// The shuffle quad modifier's "quad" value (`AGX2.xml` enum `quad`).
const QUAD_SCOPE: u32 = 0;
/// `ine`, the condition of the bare `ballot` form.
const NOT_EQUAL: u32 = 8;

/// `shuffle_op` values.
mod shuffle {
    pub const XOR: u32 = 1;
    pub const UP: u32 = 2;
    pub const DOWN: u32 = 3;
}

/// `subop` values.
mod subop {
    pub const AND: u32 = 0;
    pub const FADD: u32 = 1;
    pub const OR: u32 = 2;
    pub const FMUL: u32 = 3;
    pub const XOR: u32 = 4;
    pub const FMIN: u32 = 5;
    pub const FMAX: u32 = 7;
    pub const IADD: u32 = 16;
    pub const SMIN: u32 = 20;
    pub const SMAX: u32 = 22;
    pub const UMIN: u32 = 28;
    pub const UMAX: u32 = 30;
}

/// The quad of `lane` as a lane mask.
fn quad_mask(lane: usize) -> u32 {
    0xf << (lane & !(QUAD - 1))
}

/// `fcond` less-than and greater-than that lose NaNs.
const NAN_LOSING_LESS: u32 = 3;
const NAN_LOSING_GREATER: u32 = 7;

impl SimdGroup {
    pub(super) fn lanes(&mut self, instr: &Instr) -> Result<Step, Error> {
        let active = self.active();
        match instr.op() {
            Op::Dfdx | Op::Dfdy => self.derivative(instr, active)?,
            Op::Ballot | Op::IcmpBallot | Op::FcmpBallot => self.ballot(instr, active)?,
            Op::Shuffle => self.shuffle(instr, active)?,
            Op::Quad | Op::Simd => self.reduce(instr, active)?,
            other => unreachable!("{other:?} is not a cross-thread instruction"),
        }
        Ok(Step::Next)
    }

    fn derivative(&mut self, instr: &Instr, active: u32) -> Result<(), Error> {
        let (dest, source) = (instr.dest(), instr.source(0));
        let axis = if instr.op() == Op::Dfdx { 1 } else { 2 };
        let mut results = [0.0f64; SIMD_WIDTH];
        for lane in lanes(active) {
            let (low, high) = (lane & !axis, lane | axis);
            if self.present >> high & 1 == 0 || self.present >> low & 1 == 0 {
                return Err(Error::Refused(
                    "a derivative over a quad with a missing thread",
                ));
            }
            results[lane] = self.float(high, &source)? - self.float(low, &source)?;
        }
        for lane in lanes(active) {
            self.put_float(lane, &dest, results[lane])?;
        }
        Ok(())
    }

    fn ballot(&mut self, instr: &Instr, active: u32) -> Result<(), Error> {
        let dest = instr.dest();
        let mut taken = 0u32;
        for lane in lanes(active) {
            let holds = match instr.op() {
                Op::Ballot => true,
                Op::IcmpBallot => {
                    let cond = instr.modifier(Mod::Condition).unwrap_or(NOT_EQUAL);
                    let (a, b) = (instr.source(0), instr.source(1));
                    icompare(
                        cond,
                        self.bits(lane, &a, 0)?,
                        size(&a),
                        self.bits(lane, &b, 0)?,
                        size(&b),
                    )
                }
                _ => {
                    let cond = instr.modifier(Mod::Condition).unwrap_or(0);
                    fcompare(
                        cond,
                        self.float(lane, &instr.source(0))?,
                        self.float(lane, &instr.source(1))?,
                    )
                }
            };
            taken |= u32::from(holds) << lane;
        }
        let quad = instr.modifier(Mod::Quad) == Some(QUAD_SCOPE);
        for lane in lanes(active) {
            let value = if quad {
                taken >> (lane & !(QUAD - 1)) & 0xf
            } else {
                taken
            };
            self.put(lane, &dest, 0, u64::from(value))?;
        }
        Ok(())
    }

    fn shuffle(&mut self, instr: &Instr, active: u32) -> Result<(), Error> {
        let (dest, value, index) = (instr.dest(), instr.source(0), instr.source(1));
        let quad = instr.modifier(Mod::Quad) == Some(QUAD_SCOPE);
        let rotate = instr.flag(Mod::Rotate);
        let operation = instr.modifier(Mod::Op).unwrap_or(0);
        let width = if quad { QUAD } else { SIMD_WIDTH };
        self.check_shuffle_indices(&index, active)?;
        let mut results = [0u64; SIMD_WIDTH];
        for lane in lanes(active) {
            let i = self.bits(lane, &index, 0)? as usize;
            let base = if quad { lane & !(QUAD - 1) } else { 0 };
            let own = (lane - base) as i64;
            let i = i as i64;
            let target = match operation {
                shuffle::XOR => own ^ i,
                shuffle::UP => own - i,
                shuffle::DOWN => own + i,
                _ => i,
            };
            let outside = !(0..width as i64).contains(&target);
            let shifting = matches!(operation, shuffle::UP | shuffle::DOWN);
            let source_lane = if outside && shifting && !rotate {
                lane
            } else {
                base + target.rem_euclid(width as i64) as usize
            };
            results[lane] = self.bits(source_lane, &value, 0)?;
        }
        for lane in lanes(active) {
            self.put(lane, &dest, 0, results[lane])?;
        }
        Ok(())
    }

    /// Refuse a register-indexed shuffle that inactive threads would make
    /// undefined.
    fn check_shuffle_indices(&self, index: &Operand, active: u32) -> Result<(), Error> {
        if !matches!(index.value, super::decode::Value::Reg(_)) {
            return Ok(());
        }
        for quad in (0..SIMD_WIDTH).step_by(QUAD) {
            let mask = quad_mask(quad) & self.present;
            let mut common = None;
            let mut uniform = true;
            for lane in lanes(mask & active) {
                let i = self.bits(lane, index, 0)?;
                uniform &= common.is_none_or(|c| c == i);
                common = Some(i);
            }
            for lane in lanes(mask & !active) {
                let i = self.bits(lane, index, 0)?;
                if i != 0 && !(uniform && common == Some(i)) {
                    return Err(Error::Refused(
                        "a shuffle index in an inactive thread of the quad (undefined)",
                    ));
                }
            }
        }
        Ok(())
    }

    fn reduce(&mut self, instr: &Instr, active: u32) -> Result<(), Error> {
        let (dest, source) = (instr.dest(), instr.source(0));
        let operation = instr.modifier(Mod::Op).unwrap_or(0);
        let prefix = instr.flag(Mod::Prefix);
        let quad = instr.op() == Op::Quad;
        let float = matches!(
            operation,
            subop::FADD | subop::FMUL | subop::FMIN | subop::FMAX
        );
        let bits = u32::from(dest.size);
        let mut values = [0u64; SIMD_WIDTH];
        for lane in lanes(active) {
            values[lane] = self.bits(lane, &source, 0)?;
        }
        let mut results = [0u64; SIMD_WIDTH];
        for lane in lanes(active) {
            let scope = if quad { quad_mask(lane) } else { u32::MAX };
            let below = if prefix {
                (1u64 << lane) as u32 - 1
            } else {
                u32::MAX
            };
            let contributors = active & scope & below;
            results[lane] = if float {
                let mut accumulator = self.float_identity(operation, &dest)?;
                for other in lanes(contributors) {
                    let x = self.float(other, &source)?;
                    accumulator = self.float_step(operation, accumulator, x, &dest);
                }
                self.float_bits(&dest, accumulator)?
            } else {
                let mut accumulator = integer_identity(operation, bits)?;
                for other in lanes(contributors) {
                    accumulator = integer_step(operation, accumulator, values[other], bits);
                }
                accumulator
            };
        }
        for lane in lanes(active) {
            self.put(lane, &dest, 0, results[lane])?;
        }
        Ok(())
    }

    fn float_identity(&self, operation: u32, _dest: &Operand) -> Result<f64, Error> {
        Ok(match operation {
            subop::FADD => -0.0,
            subop::FMUL => 1.0,
            subop::FMIN => f64::INFINITY,
            _ => f64::NEG_INFINITY,
        })
    }

    /// One fold step, rounded to the destination's precision.
    fn float_step(&self, operation: u32, a: f64, b: f64, dest: &Operand) -> f64 {
        let exact = match operation {
            subop::FADD => a + b,
            subop::FMUL => a * b,
            subop::FMIN => {
                if fcompare(NAN_LOSING_LESS, a, b) || b.is_nan() {
                    a
                } else {
                    b
                }
            }
            _ => {
                if fcompare(NAN_LOSING_GREATER, a, b) || b.is_nan() {
                    a
                } else {
                    b
                }
            }
        };
        round_to(dest, exact)
    }

    fn float_bits(&self, dest: &Operand, value: f64) -> Result<u64, Error> {
        match dest.size {
            16 => Ok(u64::from(super::float::f64_to_half(value))),
            32 => Ok(u64::from(super::float::f64_to_f32_ftz(value).to_bits())),
            _ => Err(Error::Refused("a 64-bit float reduction")),
        }
    }
}

/// `value` rounded to the destination's float size and widened back.
fn round_to(dest: &Operand, value: f64) -> f64 {
    if dest.size == 16 {
        f64::from(super::float::half_to_f32(super::float::f64_to_half(value)))
    } else {
        f64::from(super::float::f64_to_f32_ftz(value))
    }
}

fn integer_identity(operation: u32, bits: u32) -> Result<u64, Error> {
    let all = super::alu::mask(bits);
    Ok(match operation {
        subop::AND | subop::UMIN => all,
        subop::OR | subop::XOR | subop::IADD | subop::UMAX => 0,
        subop::SMIN => all >> 1,
        subop::SMAX => (all >> 1) + 1,
        _ => {
            return Err(Error::Refused(
                "a reduction operation the enumeration lacks",
            ));
        }
    })
}

fn integer_step(operation: u32, a: u64, b: u64, bits: u32) -> u64 {
    let all = super::alu::mask(bits);
    let (a, b) = (a & all, b & all);
    let signed = |x: u64| sign_extend(x, bits);
    let result = match operation {
        subop::AND => a & b,
        subop::OR => a | b,
        subop::XOR => a ^ b,
        subop::IADD => a.wrapping_add(b),
        subop::SMIN => {
            if signed(a) <= signed(b) {
                a
            } else {
                b
            }
        }
        subop::SMAX => {
            if signed(a) >= signed(b) {
                a
            } else {
                b
            }
        }
        subop::UMIN => a.min(b),
        _ => a.max(b),
    };
    result & all
}

#[cfg(test)]
mod tests {
    use super::super::machine::ExecError;
    use super::super::machine::tests::{finish, setup};
    use super::*;

    fn lanes_of(threads: usize, text: &str, init: impl Fn(&mut SimdGroup, usize)) -> SimdGroup {
        let (mut memory, mut group) = setup(&alloc::format!("{text}\nstop"), threads);
        for lane in 0..threads {
            init(&mut group, lane);
        }
        finish(&mut group, &mut memory).unwrap();
        group
    }

    #[test]
    fn derivatives_difference_the_quad() {
        // f(x, y) = 3x + 5y over one quad.
        let group = lanes_of(4, "dfdx r4, r2\ndfdy r6, r2", |group, lane| {
            let value = 3.0 * (lane & 1) as f32 + 5.0 * (lane >> 1) as f32;
            group.set_reg32(lane, 4, value.to_bits());
        });
        for lane in 0..4 {
            assert_eq!(f32::from_bits(group.reg32(lane, 8)), 3.0);
            assert_eq!(f32::from_bits(group.reg32(lane, 12)), 5.0);
        }
    }

    #[test]
    fn ballots_collect_active_comparisons() {
        let group = lanes_of(8, "ballot r4, r2l, 0, ieq\nballot r6", |group, lane| {
            group.set_half(lane, 4, (lane % 3) as u16);
        });
        assert_eq!(group.reg32(0, 8), 0b0100_1001);
        assert_eq!(group.reg32(7, 12), 0xff);
    }

    #[test]
    fn reductions_and_prefixes() {
        let group = lanes_of(
            4,
            "simd r4, r2, iadd\nsimd r6, r2, prefix, iadd",
            |group, lane| {
                group.set_reg32(lane, 4, lane as u32 + 1);
            },
        );
        for lane in 0..4 {
            assert_eq!(group.reg32(lane, 8), 10);
            let exclusive: u32 = (1..=lane as u32).sum();
            assert_eq!(group.reg32(lane, 12), exclusive);
        }
    }

    #[test]
    fn shuffles_read_other_lanes() {
        let group = lanes_of(
            4,
            "shuffle r4, r2, 3\nshuffle r6, r2, 1, xor",
            |group, lane| {
                group.set_reg32(lane, 4, 10 + lane as u32);
            },
        );
        for lane in 0..4 {
            assert_eq!(group.reg32(lane, 8), 13);
            assert_eq!(group.reg32(lane, 12), 10 + (lane as u32 ^ 1));
        }
    }

    #[test]
    fn divergent_inactive_shuffle_indices_refuse() {
        let (mut memory, mut group) = setup("shuffle r4, r2, r3l\nstop", 4);
        group.set_half(1, 0, 1);
        group.set_half(1, 6, 2);
        assert!(matches!(
            finish(&mut group, &mut memory),
            Err(ExecError::Refused {
                op: Op::Shuffle,
                ..
            })
        ));
    }
}
