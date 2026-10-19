//! A decoder and x86-host interpreter for a bounded, bit-exact subset of the
//! AGX G14G (Apple G14, "AGX2") shader ISA, the instruction set the userspace
//! `AGXMetalG14G` driver compiles Metal shaders into at run time.
//!
//! The encodings are Mesa's machine-readable ISA description
//! `src/asahi/isa/AGX2.xml` (pinned `a2b6d5096ebee791427214cba47282788ef4e048`),
//! and the decoder is checked against that tree's disassembler test vectors
//! (`isa/test/cases.txt`). Covered:
//!
//! - `stop` (2 bytes, `88 00`).
//! - The F32 binary ops `fadd` (0b101010) and `fmul` (0b011010), 4 or 6
//!   bytes, and `ffma` (0b111010), 6 or 8 bytes. Bit 15 selects the long
//!   form; the short form's missing high bits read as zero. Operand fields
//!   with negative bit positions in the XML count from the end of the long
//!   form: the `fdest1` (`dalu`) field is bits 7:14 and L-4:L-3, `fsrc1`
//!   16:27 and L-6:L-5, `fsrc2` 28:39 and L-8:L-7, `fsrc3` 40:51 and
//!   L-10:L-9, where L is the long form's bit length; `saturate` is bit 6.
//! - A `float` source's three cases: an 8-bit minifloat immediate when bits
//!   6:9 are zero (Mesa `agx_minifloat_decode`), a uniform when bits 8:9 are
//!   `01` (index bits 0:5, 12:13, 6; `size32` bit 7), else a register (index
//!   bits 0:5, 12:13; cache hint 6:7; bit 8 zero; `size32` bit 9); `abs` is
//!   bit 10 and `neg` bit 11 in every case. A `dalu` destination is `cache`
//!   (bit 0), `size32` (bit 1) and the register (bits 2:9).
//!
//! Semantics (Public: Dougall Johnson's applegpu notes; Mesa's NIR lowering):
//! registers and uniforms are files of 16-bit lanes and a 32-bit operand is
//! an even-aligned lane pair. A 16-bit operand of an F32 op is an IEEE half
//! converted exactly to f32, and a 16-bit destination receives the result
//! rounded to half (nearest even). `abs` applies before `neg`. `ffma` rounds
//! once. `saturate` clamps to [0, 1] with NaN becoming 0 (NIR `fsat`, which
//! the compiler maps onto it). Cache hints change no result.
//!
//! Every other opcode and encoding decodes to [`Decoded::Unsupported`] and
//! the interpreter refuses it. The memory/PBE and control-flow encodings and
//! the integer ops are not yet decoded (see docs/research/agx.md §5).

use alloc::vec::Vec;

/// A 16-bit-lane index into the register or uniform file.
pub type Reg = u16;

/// Opcode of a decoded floating-point ALU operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloatOp {
    Add,
    Mul,
    /// `a * b + c`, rounded once.
    Fma,
}

/// Where a source operand's value comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    Register(Reg),
    Uniform(Reg),
    /// An 8-bit minifloat immediate.
    Immediate(u8),
}

/// A `float` source with its modifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Src {
    pub operand: Operand,
    /// 32-bit lane pair, else one 16-bit lane. Immediates ignore it.
    pub size32: bool,
    pub abs: bool,
    pub neg: bool,
}

impl Src {
    /// A 32-bit register source without modifiers.
    pub const fn reg32(reg: Reg) -> Self {
        Src {
            operand: Operand::Register(reg),
            size32: true,
            abs: false,
            neg: false,
        }
    }

    /// A 32-bit uniform source without modifiers.
    pub const fn uniform32(reg: Reg) -> Self {
        Src {
            operand: Operand::Uniform(reg),
            size32: true,
            abs: false,
            neg: false,
        }
    }

    pub const fn negated(self) -> Self {
        Src { neg: true, ..self }
    }
}

/// A register destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dest {
    pub reg: Reg,
    pub size32: bool,
}

impl Dest {
    pub const fn reg32(reg: Reg) -> Self {
        Dest { reg, size32: true }
    }
}

/// A decoded floating-point ALU instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloatAlu {
    pub op: FloatOp,
    pub dest: Dest,
    /// Two sources for `fadd`/`fmul`, three for `ffma` (the third unused
    /// otherwise).
    pub srcs: [Src; 3],
    pub saturate: bool,
}

/// A decoded instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decoded {
    Stop,
    Float {
        alu: FloatAlu,
        len: usize,
    },
    /// A form this subset does not decode; decoding cannot continue.
    Unsupported,
}

/// `stop`'s 16 bits (XML `0000000010001000`, bytes `88 00`).
const STOP: u16 = 0x0088;
const STOP_BYTES: usize = 2;
const OPCODE_BITS: u32 = 6;
const OP_FADD: u64 = 0b101010;
const OP_FMUL: u64 = 0b011010;
const OP_FFMA: u64 = 0b111010;
const SATURATE_BIT: u32 = 6;
const LENGTH_BIT: u32 = 15;

/// A `float` field's low part (12 bits) and high part (2 bits).
const FLOAT_LOW_BITS: u32 = 12;
const FLOAT_HIGH_BITS: u32 = 2;
/// The `dalu` field's low part (8 bits at 7:14) and high part (2 bits).
const DEST_LOW: u32 = 7;
const DEST_LOW_BITS: u32 = 8;

/// The short and long byte lengths of an opcode, and its source count.
fn shape(opcode: u64) -> Option<(FloatOp, usize, usize, usize)> {
    match opcode {
        OP_FADD => Some((FloatOp::Add, 4, 6, 2)),
        OP_FMUL => Some((FloatOp::Mul, 4, 6, 2)),
        OP_FFMA => Some((FloatOp::Fma, 6, 8, 3)),
        _ => None,
    }
}

const fn opcode(op: FloatOp) -> u64 {
    match op {
        FloatOp::Add => OP_FADD,
        FloatOp::Mul => OP_FMUL,
        FloatOp::Fma => OP_FFMA,
    }
}

fn field(word: u64, lo: u32, bits: u32) -> u64 {
    (word >> lo) & ((1 << bits) - 1)
}

fn set(word: &mut u64, lo: u32, value: u64, bits: u32) {
    *word |= (value & ((1 << bits) - 1)) << lo;
}

/// Bit positions of a source's low and high parts in an instruction whose
/// long form is `long_bits` wide: `fsrc1..3` at 16/28/40 and L-6/L-8/L-10.
fn src_positions(index: usize, long_bits: u32) -> (u32, u32) {
    let index = index as u32;
    (16 + 12 * index, long_bits - 6 - 2 * index)
}

fn dest_high(long_bits: u32) -> u32 {
    long_bits - 4
}

fn decode_src(f: u64) -> Option<Src> {
    let abs = (f >> 10) & 1 != 0;
    let neg = (f >> 11) & 1 != 0;
    let index = (f & 0x3f) | ((f >> 12) & 3) << 6;
    let (operand, size32) = if (f >> 6) & 0xf == 0 {
        (Operand::Immediate(index as u8), true)
    } else if (f >> 8) & 3 == 0b01 {
        let uniform = index | ((f >> 6) & 1) << 8;
        (Operand::Uniform(uniform as Reg), (f >> 7) & 1 != 0)
    } else if (f >> 8) & 1 == 0 {
        (Operand::Register(index as Reg), (f >> 9) & 1 != 0)
    } else {
        return None;
    };
    Some(Src {
        operand,
        size32,
        abs,
        neg,
    })
}

fn encode_src(src: Src) -> Option<u64> {
    let modifiers = u64::from(src.abs) << 10 | u64::from(src.neg) << 11;
    let split = |index: u64| (index & 0x3f) | ((index >> 6) & 3) << 12;
    Some(
        modifiers
            | match src.operand {
                Operand::Immediate(value) => split(u64::from(value)),
                Operand::Uniform(reg) if reg < 1 << 9 => {
                    split(u64::from(reg))
                        | (u64::from(reg) >> 8) << 6
                        | 0b01 << 8
                        | u64::from(src.size32) << 7
                }
                // The register case needs bits 6:9 nonzero: the size32 bit
                // or a cache hint. A 16-bit register is written with hint 1.
                Operand::Register(reg) if reg < 1 << 8 => {
                    split(u64::from(reg)) | if src.size32 { 1 << 9 } else { 1 << 6 }
                }
                _ => return None,
            },
    )
}

/// Decode the instruction at the start of `code`.
pub fn decode(code: &[u8]) -> Decoded {
    if code.len() >= STOP_BYTES && u16::from_le_bytes([code[0], code[1]]) == STOP {
        return Decoded::Stop;
    }
    let Some(&first) = code.first() else {
        return Decoded::Unsupported;
    };
    let Some((op, short, long, sources)) = shape(u64::from(first) & ((1 << OPCODE_BITS) - 1))
    else {
        return Decoded::Unsupported;
    };
    if code.len() < 2 {
        return Decoded::Unsupported;
    }
    let len = if code[1] >> (LENGTH_BIT - 8) & 1 != 0 {
        long
    } else {
        short
    };
    if code.len() < len {
        return Decoded::Unsupported;
    }
    let mut bytes = [0u8; 8];
    bytes[..len].copy_from_slice(&code[..len]);
    let word = u64::from_le_bytes(bytes);
    let long_bits = long as u32 * 8;
    let mut srcs = [Src::reg32(0); 3];
    for (index, slot) in srcs.iter_mut().enumerate().take(sources) {
        let (lo, hi) = src_positions(index, long_bits);
        let f = field(word, lo, FLOAT_LOW_BITS) | field(word, hi, FLOAT_HIGH_BITS) << 12;
        match decode_src(f) {
            Some(src) => *slot = src,
            None => return Decoded::Unsupported,
        }
    }
    let dalu = field(word, DEST_LOW, DEST_LOW_BITS) | field(word, dest_high(long_bits), 2) << 8;
    Decoded::Float {
        alu: FloatAlu {
            op,
            dest: Dest {
                reg: (dalu >> 2) as Reg,
                size32: (dalu >> 1) & 1 != 0,
            },
            srcs,
            saturate: (word >> SATURATE_BIT) & 1 != 0,
        },
        len,
    }
}

/// Assemble a floating-point ALU instruction in its long form (the
/// harness's assembler and the decoder's round-trip oracle). `None` when an
/// index does not fit its field.
pub fn encode(alu: &FloatAlu) -> Option<Vec<u8>> {
    let (_, _, long, sources) = shape(opcode(alu.op))?;
    if alu.dest.reg >= 1 << 8 {
        return None;
    }
    let long_bits = long as u32 * 8;
    let mut word = 0u64;
    set(&mut word, 0, opcode(alu.op), OPCODE_BITS);
    set(&mut word, SATURATE_BIT, u64::from(alu.saturate), 1);
    set(&mut word, LENGTH_BIT, 1, 1);
    let dalu = u64::from(alu.dest.reg) << 2 | u64::from(alu.dest.size32) << 1;
    set(&mut word, DEST_LOW, dalu, DEST_LOW_BITS);
    set(&mut word, dest_high(long_bits), dalu >> 8, 2);
    for (index, src) in alu.srcs.iter().enumerate().take(sources) {
        let f = encode_src(*src)?;
        let (lo, hi) = src_positions(index, long_bits);
        set(&mut word, lo, f, FLOAT_LOW_BITS);
        set(&mut word, hi, f >> 12, FLOAT_HIGH_BITS);
    }
    Some(word.to_le_bytes()[..long].to_vec())
}

/// Assemble a `stop`.
pub fn encode_stop() -> [u8; 2] {
    STOP.to_le_bytes()
}

/// Mesa `agx_minifloat_decode`: sign, 3 exponent and 4 mantissa bits.
pub fn minifloat(value: u8) -> f32 {
    let sign = if value & 0x80 != 0 { -1.0 } else { 1.0 };
    let exponent = i32::from((value >> 4) & 7);
    let mantissa = f32::from(value & 0xf);
    let (significand, scale) = if exponent != 0 {
        (mantissa + 16.0, exponent - 7)
    } else {
        (mantissa, -6)
    };
    sign * significand * pow2(scale)
}

fn pow2(exponent: i32) -> f32 {
    f32::from_bits(((127 + exponent) as u32) << 23)
}

/// An IEEE half as f32 (exact).
pub fn half_to_f32(half: u16) -> f32 {
    let sign = u32::from(half >> 15) << 31;
    let exponent = u32::from((half >> 10) & 0x1f);
    let mantissa = u32::from(half & 0x3ff);
    let bits = match (exponent, mantissa) {
        (0, 0) => sign,
        (0, _) => {
            // Subnormal: normalize.
            let shift = mantissa.leading_zeros() - 21;
            let mantissa = (mantissa << shift) & 0x3ff;
            sign | (127 - 15 + 1 - shift) << 23 | mantissa << 13
        }
        (0x1f, 0) => sign | 0xff << 23,
        (0x1f, _) => sign | 0xff << 23 | mantissa << 13 | 1 << 22,
        _ => sign | (exponent + 127 - 15) << 23 | mantissa << 13,
    };
    f32::from_bits(bits)
}

/// f32 rounded to an IEEE half, nearest even.
pub fn f32_to_half(value: f32) -> u16 {
    let bits = value.to_bits();
    let sign = ((bits >> 16) & 0x8000) as u16;
    let exponent = ((bits >> 23) & 0xff) as i32;
    let mantissa = bits & 0x7f_ffff;
    if exponent == 0xff {
        return sign | 0x7c00 | if mantissa != 0 { 0x200 } else { 0 };
    }
    let unbiased = exponent - 127;
    if unbiased > 15 {
        return sign | 0x7c00;
    }
    // The significand with its implicit bit, and how far to shift it right
    // to land on the half's mantissa (subnormals shift further).
    let (significand, shift) = if exponent == 0 {
        (mantissa, 126 - 14 + 13)
    } else if unbiased >= -14 {
        (mantissa | 1 << 23, 13)
    } else {
        (mantissa | 1 << 23, 13 + (-14 - unbiased) as u32)
    };
    if shift > 24 {
        return sign;
    }
    let kept = significand >> shift;
    let rest = significand & ((1 << shift) - 1);
    let half_way = 1 << (shift - 1);
    let rounded = kept + u32::from(rest > half_way || (rest == half_way && kept & 1 != 0));
    let magnitude = if unbiased >= -14 {
        // Normal: the exponent field adds; a mantissa carry bumps it.
        (((unbiased + 15) as u32) << 10) + (rounded - (1 << 10))
    } else {
        rounded
    };
    sign | magnitude as u16
}

/// `a * b + c` rounded once to f32: the f64 product is exact, the f64 sum is
/// made round-to-odd, and rounding that to f32 is then correct.
pub fn fused_multiply_add(a: f32, b: f32, c: f32) -> f32 {
    let product = f64::from(a) * f64::from(b);
    let addend = f64::from(c);
    let sum = product + addend;
    if !sum.is_finite() || !product.is_finite() {
        return sum as f32;
    }
    // Two-sum: the exact error of `sum`.
    let virtual_addend = sum - product;
    let virtual_product = sum - virtual_addend;
    let error = (product - virtual_product) + (addend - virtual_addend);
    let bits = sum.to_bits();
    if error != 0.0 && bits & 1 == 0 {
        let toward_zero = (error > 0.0) != (sum > 0.0) && sum != 0.0;
        let odd = if toward_zero { bits - 1 } else { bits + 1 };
        return f64::from_bits(odd) as f32;
    }
    sum as f32
}

/// A shader's register and uniform files of 16-bit lanes.
#[derive(Debug, Clone)]
pub struct Registers {
    lanes: Vec<u16>,
    uniforms: Vec<u16>,
}

impl Registers {
    /// `lanes` registers and `uniforms` uniform lanes, zeroed.
    pub fn new(lanes: usize, uniforms: usize) -> Self {
        Registers {
            lanes: alloc::vec![0; lanes],
            uniforms: alloc::vec![0; uniforms],
        }
    }

    pub fn read_f32(&self, reg: Reg) -> f32 {
        pair(&self.lanes, reg).unwrap_or(f32::NAN)
    }

    pub fn write_f32(&mut self, reg: Reg, value: f32) {
        let r = reg as usize;
        let bits = value.to_bits();
        self.lanes[r] = bits as u16;
        self.lanes[r + 1] = (bits >> 16) as u16;
    }

    pub fn write_uniform_f32(&mut self, reg: Reg, value: f32) {
        let r = reg as usize;
        let bits = value.to_bits();
        self.uniforms[r] = bits as u16;
        self.uniforms[r + 1] = (bits >> 16) as u16;
    }

    pub fn lane(&self, reg: Reg) -> u16 {
        self.lanes[reg as usize]
    }

    pub fn set_lane(&mut self, reg: Reg, value: u16) {
        self.lanes[reg as usize] = value;
    }
}

fn pair(file: &[u16], reg: Reg) -> Option<f32> {
    let r = reg as usize;
    let low = *file.get(r)?;
    let high = *file.get(r + 1)?;
    Some(f32::from_bits(u32::from(low) | u32::from(high) << 16))
}

/// Why interpretation stopped before `stop`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunError {
    /// An opcode or operand form this subset does not model.
    Unsupported,
    /// An operand outside the register or uniform file, or a 32-bit operand
    /// on an odd lane.
    BadRegister,
    /// The program ran past its end without a `stop`.
    Overrun,
}

fn read(regs: &Registers, src: Src) -> Result<f32, RunError> {
    let file = |file: &[u16], reg: Reg| -> Result<f32, RunError> {
        if src.size32 {
            if !reg.is_multiple_of(2) {
                return Err(RunError::BadRegister);
            }
            pair(file, reg).ok_or(RunError::BadRegister)
        } else {
            file.get(reg as usize)
                .map(|&half| half_to_f32(half))
                .ok_or(RunError::BadRegister)
        }
    };
    let mut value = match src.operand {
        Operand::Register(reg) => file(&regs.lanes, reg)?,
        Operand::Uniform(reg) => file(&regs.uniforms, reg)?,
        Operand::Immediate(value) => minifloat(value),
    };
    if src.abs {
        value = value.abs();
    }
    if src.neg {
        value = -value;
    }
    Ok(value)
}

fn write(regs: &mut Registers, dest: Dest, value: f32) -> Result<(), RunError> {
    let r = dest.reg as usize;
    if dest.size32 {
        if !r.is_multiple_of(2) || r + 1 >= regs.lanes.len() {
            return Err(RunError::BadRegister);
        }
        regs.write_f32(dest.reg, value);
    } else {
        *regs.lanes.get_mut(r).ok_or(RunError::BadRegister)? = f32_to_half(value);
    }
    Ok(())
}

fn saturate(value: f32) -> f32 {
    if value.is_nan() {
        0.0
    } else {
        value.clamp(0.0, 1.0)
    }
}

/// Run `code` over `regs` until `stop`. Executes the decoded subset on the
/// host; any other form refuses explicitly.
pub fn run(code: &[u8], regs: &mut Registers) -> Result<(), RunError> {
    let mut pc = 0;
    while pc < code.len() {
        match decode(&code[pc..]) {
            Decoded::Stop => return Ok(()),
            Decoded::Float { alu, len } => {
                let a = read(regs, alu.srcs[0])?;
                let b = read(regs, alu.srcs[1])?;
                let mut result = match alu.op {
                    FloatOp::Add => a + b,
                    FloatOp::Mul => a * b,
                    FloatOp::Fma => fused_multiply_add(a, b, read(regs, alu.srcs[2])?),
                };
                if alu.saturate {
                    result = saturate(result);
                }
                write(regs, alu.dest, result)?;
                pc += len;
            }
            Decoded::Unsupported => return Err(RunError::Unsupported),
        }
    }
    Err(RunError::Overrun)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn alu(text: &str) -> (FloatAlu, usize) {
        match decode(&hex(text)) {
            Decoded::Float { alu, len } => (alu, len),
            other => panic!("{text}: {other:?}"),
        }
    }

    fn reg(reg: Reg, size32: bool) -> Src {
        Src {
            operand: Operand::Register(reg),
            size32,
            abs: false,
            neg: false,
        }
    }

    #[test]
    fn decoding_matches_mesas_disassembler_vectors() {
        // `fmul r0, $r1, 0.234375` (4 bytes, cache hint, immediate 0x0f).
        let (fmul, len) = alu("1a0182f2");
        assert_eq!(len, 4);
        assert_eq!(fmul.op, FloatOp::Mul);
        assert_eq!(fmul.dest, Dest::reg32(0));
        assert_eq!(fmul.srcs[0], reg(2, true));
        assert_eq!(fmul.srcs[1].operand, Operand::Immediate(0x0f));
        assert_eq!(minifloat(0x0f), 0.234375);
        // `fmul r4, r11, r9` (6 bytes).
        let (fmul, len) = alu("1a9156222500");
        assert_eq!(len, 6);
        assert_eq!(fmul.dest, Dest::reg32(8));
        assert_eq!(fmul.srcs[..2], [reg(22, true), reg(18, true)]);
        // `fadd r0, r10.neg, r11`.
        let (fadd, _) = alu("2a81546a2500");
        assert_eq!(fadd.srcs[0], reg(20, true).negated());
        assert_eq!(fadd.srcs[1], reg(22, true));
        // `fadd r1l, r0h.abs, -0.0`: 16-bit destination and source.
        let (fadd, _) = alu("2a8441040002");
        assert_eq!(
            fadd.dest,
            Dest {
                reg: 2,
                size32: false
            }
        );
        assert_eq!(
            fadd.srcs[0],
            Src {
                abs: true,
                ..reg(1, false)
            }
        );
        // The immediate's own sign bit gives -0.0.
        assert_eq!(fadd.srcs[1].operand, Operand::Immediate(0x80));
        assert!(!fadd.srcs[1].neg && minifloat(0x80).is_sign_negative());
        // `fadd r11, r8, -0.0, sat`.
        let (fadd, _) = alu("6aad50020002");
        assert!(fadd.saturate);
        assert_eq!(fadd.dest, Dest::reg32(22));
        // `ffma r0, u9h, r0, r10` (8 bytes, 16-bit uniform).
        let (ffma, len) = alu("3a81130124540200");
        assert_eq!((ffma.op, len), (FloatOp::Fma, 8));
        assert_eq!(ffma.srcs[0].operand, Operand::Uniform(19));
        assert!(!ffma.srcs[0].size32);
        assert_eq!(ffma.srcs[1..], [reg(0, true), reg(20, true)]);
        // `ffma r4, r3, u8, u6`.
        let (ffma, _) = alu("3a914602198c0100");
        assert_eq!(ffma.dest, Dest::reg32(8));
        assert_eq!(
            ffma.srcs,
            [reg(6, true), Src::uniform32(16), Src::uniform32(12)]
        );
        assert_eq!(decode(&hex("8800")), Decoded::Stop);
    }

    #[test]
    fn encoding_round_trips_through_decode() {
        let cases = [
            FloatAlu {
                op: FloatOp::Add,
                dest: Dest::reg32(200),
                srcs: [reg(130, true), Src::uniform32(300).negated(), reg(0, true)],
                saturate: true,
            },
            FloatAlu {
                op: FloatOp::Fma,
                dest: Dest {
                    reg: 7,
                    size32: false,
                },
                srcs: [
                    reg(3, false),
                    Src {
                        operand: Operand::Immediate(0xb4),
                        size32: true,
                        abs: true,
                        neg: false,
                    },
                    reg(64, true),
                ],
                saturate: false,
            },
        ];
        for case in cases {
            let bytes = encode(&case).unwrap();
            let Decoded::Float { alu, len } = decode(&bytes) else {
                panic!("{case:?}");
            };
            assert_eq!(len, bytes.len());
            assert_eq!(alu.op, case.op);
            assert_eq!(alu.dest, case.dest);
            let sources = if case.op == FloatOp::Fma { 3 } else { 2 };
            assert_eq!(alu.srcs[..sources], case.srcs[..sources]);
            assert_eq!(alu.saturate, case.saturate);
        }
        // A register past the 8-bit field does not encode.
        let wide = FloatAlu {
            dest: Dest::reg32(256),
            ..cases[0]
        };
        assert_eq!(encode(&wide), None);
    }

    #[test]
    fn unsupported_forms_refuse_rather_than_guess() {
        // An unmodeled opcode.
        assert_eq!(decode(&[0, 0, 0, 0, 0, 0]), Decoded::Unsupported);
        // The register case with bit 8 set and bits 8:9 = 11.
        let mut word = OP_FADD | 1 << LENGTH_BIT;
        set(&mut word, 16, 0x300, FLOAT_LOW_BITS);
        assert_eq!(decode(&word.to_le_bytes()[..6]), Decoded::Unsupported);
        // A truncated long form.
        assert_eq!(decode(&hex("3a81130124")), Decoded::Unsupported);
        let mut regs = Registers::new(4, 0);
        assert_eq!(run(&[0, 0, 0, 0], &mut regs), Err(RunError::Unsupported));
        assert_eq!(run(&[], &mut regs), Err(RunError::Overrun));
    }

    #[test]
    fn the_interpreter_computes_with_uniforms_immediates_and_halves() {
        let program = [
            // r4 = r0 * u0 + 0.234375 (fused).
            FloatAlu {
                op: FloatOp::Fma,
                dest: Dest::reg32(4),
                srcs: [
                    reg(0, true),
                    Src::uniform32(0),
                    Src {
                        operand: Operand::Immediate(0x0f),
                        size32: true,
                        abs: false,
                        neg: false,
                    },
                ],
                saturate: false,
            },
            // r3 (16-bit) = r2h + r4, saturated.
            FloatAlu {
                op: FloatOp::Add,
                dest: Dest {
                    reg: 3,
                    size32: false,
                },
                srcs: [reg(2, false), reg(4, true), reg(0, true)],
                saturate: true,
            },
        ];
        let mut code: Vec<u8> = program.iter().flat_map(|a| encode(a).unwrap()).collect();
        code.extend_from_slice(&encode_stop());
        let mut regs = Registers::new(8, 2);
        regs.write_f32(0, 2.0);
        regs.write_uniform_f32(0, 0.125);
        regs.set_lane(2, f32_to_half(0.25));
        run(&code, &mut regs).unwrap();
        assert_eq!(regs.read_f32(4), 0.484375);
        assert_eq!(half_to_f32(regs.lane(3)), 0.734375);
        // NaN saturates to zero; an odd 32-bit operand refuses.
        regs.write_f32(4, f32::NAN);
        run(&code[8..], &mut regs).unwrap();
        assert_eq!(half_to_f32(regs.lane(3)), 0.0);
        let odd = encode(&FloatAlu {
            op: FloatOp::Mul,
            dest: Dest::reg32(4),
            srcs: [reg(1, true), reg(0, true), reg(0, true)],
            saturate: false,
        })
        .unwrap();
        assert_eq!(run(&odd, &mut regs), Err(RunError::BadRegister));
    }

    #[test]
    fn fused_multiply_add_rounds_once() {
        // (1 + 2^-23)^2 - (1 + 2^-22) = 2^-46, which a rounded product loses.
        let a = 1.0 + f32::EPSILON;
        let c = -(1.0 + 2.0 * f32::EPSILON);
        assert_eq!(fused_multiply_add(a, a, c), f32::EPSILON * f32::EPSILON);
        assert_eq!(a * a + c, 0.0);
        assert_eq!(fused_multiply_add(2.0, 3.0, 1.0), 7.0);
        assert!(fused_multiply_add(f32::INFINITY, 0.0, 1.0).is_nan());
    }

    #[test]
    fn half_conversions_are_exact_and_round_to_nearest_even() {
        for (half, value) in [
            (0x3c00, 1.0),
            (0xc000, -2.0),
            (0x0001, 5.960_464_5e-8),
            (0x03ff, 6.097_555e-5),
            (0x7bff, 65504.0),
            (0x7c00, f32::INFINITY),
        ] {
            assert_eq!(half_to_f32(half), value);
            assert_eq!(f32_to_half(value), half);
        }
        // 1 + 2^-11 is halfway between 1 and 1 + 2^-10: ties to even (1).
        assert_eq!(f32_to_half(1.0 + 2f32.powi(-11)), 0x3c00);
        assert_eq!(f32_to_half(1.0 + 3.0 * 2f32.powi(-11)), 0x3c02);
        assert_eq!(f32_to_half(70000.0), 0x7c00);
        assert!(half_to_f32(f32_to_half(f32::NAN)).is_nan());
        // The largest half subnormal rounds up into the normal range.
        assert_eq!(f32_to_half(6.102e-5), 0x0400);
        assert_eq!(f32_to_half(6.1e-5), 0x03ff);
    }
}
