//! A decoder and x86-host interpreter for a bounded, bit-exact subset of the
//! AGX G14G (Apple G14, "AGX2") shader ISA, the instruction set the userspace
//! `AGXMetalG14G` driver compiles Metal shaders into at run time.
//!
//! The encodings are taken from Mesa's machine-readable ISA description
//! `src/asahi/isa/AGX2.xml` (pinned `a2b6d5096ebee791427214cba47282788ef4e048`)
//! and Dougall Johnson's G13 notes. This module covers the forms whose full
//! operand layout is read directly from that description and round-tripped in
//! tests:
//!
//! - `stop` (2 bytes, `88 00`): end of the program.
//! - the F32 binary ops `fadd`/`fmul` (6-byte register form): opcode at bits
//!   0:5 (`fadd` 0b101010, `fmul` 0b011010), `saturate` at bit 6, the `dalu`
//!   destination at bits 7:14 and 44:45, and two `float` sources at bits
//!   16:27/42:43 and 28:39/40:41. A `float` source's low 6 and high 2 reg
//!   bits give an 8-bit 16-bit-register index, with `size32` (bit 9 of the
//!   field), `abs` (bit 10) and `neg` (bit 11); the `dalu` destination's reg
//!   is bits 2:9 of its field with `size32` at bit 1.
//!
//! Every other opcode, and the immediate/uniform source forms, decode to an
//! explicit [`Decoded::Unsupported`] rather than a guessed instruction; the
//! interpreter refuses them. Registers are 16-bit lanes (the hardware's unit);
//! a 32-bit operand occupies a lane pair. ffma and the 8-byte forms, the
//! memory/PBE and control-flow encodings, and the immediate/uniform operand
//! forms are not yet decoded (see docs/research/agx.md §5).

use alloc::vec::Vec;

/// A 16-bit-register index (the hardware's addressing unit).
pub type Reg = u8;

/// Opcode of a decoded F32 binary operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Mul,
}

/// A source operand in register form, with its float modifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloatSrc {
    pub reg: Reg,
    pub size32: bool,
    pub abs: bool,
    pub neg: bool,
}

/// A destination operand in register form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dest {
    pub reg: Reg,
    pub size32: bool,
}

/// A decoded instruction and its byte length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decoded {
    Stop,
    Binary {
        op: BinOp,
        dest: Dest,
        a: FloatSrc,
        b: FloatSrc,
        saturate: bool,
    },
    /// A form this subset does not decode; `len` bytes were consumed if the
    /// length is known from the first bytes, else 0 (decoding must stop).
    Unsupported {
        len: usize,
    },
}

const STOP: u16 = 0x8800;
const OP_FADD: u64 = 0b101010;
const OP_FMUL: u64 = 0b011010;

/// Extract bits `lo..=hi` (absolute, little-endian bit order) from a 48-bit
/// word.
fn field(word: u64, lo: u32, hi: u32) -> u64 {
    (word >> lo) & ((1 << (hi - lo + 1)) - 1)
}

fn decode_dest(word: u64) -> Dest {
    // dest1 kind dalu: bits 7:14 (low 8) then 44:45 (high 2); the 10-bit dalu
    // field is cache(0), size32(1), reg(2:9).
    let dalu = field(word, 7, 14) | field(word, 44, 45) << 8;
    Dest {
        reg: ((dalu >> 2) & 0xff) as u8,
        size32: (dalu >> 1) & 1 != 0,
    }
}

/// Decode a 14-bit `float` source field into a register operand, or `None`
/// for the immediate/uniform cases this subset does not model.
fn decode_float_src(f: u64) -> Option<FloatSrc> {
    // Immediate case: bits 6:9 are zero. Uniform case: bits 8:9 == 0b01.
    if f & (0xf << 6) == 0 {
        return None; // immediate
    }
    if (f >> 8) & 3 == 0b01 {
        return None; // uniform
    }
    // bit 8 must be zero in the register case.
    if (f >> 8) & 1 != 0 {
        return None;
    }
    let reg = (f & 0x3f) | ((f >> 12) & 3) << 6;
    Some(FloatSrc {
        reg: reg as u8,
        size32: (f >> 9) & 1 != 0,
        abs: (f >> 10) & 1 != 0,
        neg: (f >> 11) & 1 != 0,
    })
}

/// Decode the instruction at the start of `code`. Returns the decoded form;
/// `Unsupported { len: 0 }` means decoding cannot continue.
pub fn decode(code: &[u8]) -> Decoded {
    if code.len() >= 2 && u16::from_le_bytes([code[0], code[1]]) == STOP {
        return Decoded::Stop;
    }
    if code.len() < 6 {
        return Decoded::Unsupported { len: 0 };
    }
    let mut bytes = [0u8; 8];
    bytes[..6].copy_from_slice(&code[..6]);
    let word = u64::from_le_bytes(bytes);
    let opcode = field(word, 0, 5);
    let op = match opcode {
        OP_FADD => BinOp::Add,
        OP_FMUL => BinOp::Mul,
        _ => return Decoded::Unsupported { len: 0 },
    };
    // The length bit (15) selects the 6- or 8-byte form; this subset decodes
    // the 6-byte form only.
    if (word >> 15) & 1 != 0 {
        return Decoded::Unsupported { len: 0 };
    }
    let a = field(word, 16, 27) | field(word, 42, 43) << 12;
    let b = field(word, 28, 39) | field(word, 40, 41) << 12;
    let (Some(a), Some(b)) = (decode_float_src(a), decode_float_src(b)) else {
        return Decoded::Unsupported { len: 6 };
    };
    Decoded::Binary {
        op,
        dest: decode_dest(word),
        a,
        b,
        saturate: (word >> 6) & 1 != 0,
    }
}

fn set(word: &mut u64, lo: u32, value: u64, width: u32) {
    *word |= (value & ((1 << width) - 1)) << lo;
}

fn encode_dest(word: &mut u64, dest: Dest) {
    let dalu = (u64::from(dest.reg) << 2) | u64::from(dest.size32) << 1;
    set(word, 7, dalu & 0xff, 8);
    set(word, 44, dalu >> 8, 2);
}

fn encode_float_src(word: &mut u64, lo_a: u32, lo_b: u32, src: FloatSrc) {
    // Rebuild the 14-bit float field, register case.
    let f = (u64::from(src.reg) & 0x3f)
        | ((u64::from(src.reg) >> 6) & 3) << 12
        | u64::from(src.size32) << 9
        | u64::from(src.abs) << 10
        | u64::from(src.neg) << 11;
    set(word, lo_a, f & 0xfff, 12);
    set(word, lo_b, f >> 12, 2);
}

/// Assemble a 6-byte F32 binary op (the harness's assembler and the decoder's
/// round-trip oracle).
pub fn encode_binary(op: BinOp, dest: Dest, a: FloatSrc, b: FloatSrc, saturate: bool) -> [u8; 6] {
    let mut word = 0u64;
    set(
        &mut word,
        0,
        match op {
            BinOp::Add => OP_FADD,
            BinOp::Mul => OP_FMUL,
        },
        6,
    );
    set(&mut word, 6, u64::from(saturate), 1);
    encode_dest(&mut word, dest);
    encode_float_src(&mut word, 16, 42, a);
    encode_float_src(&mut word, 28, 40, b);
    word.to_le_bytes()[..6].try_into().expect("6 bytes")
}

/// Assemble a `stop`.
pub fn encode_stop() -> [u8; 2] {
    STOP.to_le_bytes()
}

/// A shader register file of 16-bit lanes; a 32-bit value is a lane pair.
#[derive(Debug, Clone)]
pub struct Registers {
    lanes: Vec<u16>,
}

impl Registers {
    /// A file of `lanes` 16-bit registers, zeroed.
    pub fn new(lanes: usize) -> Self {
        Registers {
            lanes: alloc::vec![0; lanes],
        }
    }

    pub fn read_f32(&self, reg: Reg) -> f32 {
        let r = reg as usize;
        f32::from_bits(u32::from(self.lanes[r]) | u32::from(self.lanes[r + 1]) << 16)
    }

    pub fn write_f32(&mut self, reg: Reg, value: f32) {
        let r = reg as usize;
        let bits = value.to_bits();
        self.lanes[r] = bits as u16;
        self.lanes[r + 1] = (bits >> 16) as u16;
    }
}

/// Why interpretation stopped before `stop`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunError {
    /// An opcode or operand form this subset does not model, including a
    /// 16-bit (half) operand of an F32 op.
    Unsupported,
    /// The program ran past its end without a `stop`.
    Overrun,
}

fn source(regs: &Registers, src: FloatSrc) -> Result<f32, RunError> {
    if !src.size32 {
        return Err(RunError::Unsupported);
    }
    let mut v = regs.read_f32(src.reg);
    if src.abs {
        v = v.abs();
    }
    if src.neg {
        v = -v;
    }
    Ok(v)
}

/// Run `code` over `regs` until `stop`. Executes the decoded subset on the
/// host's f32; any other form refuses explicitly.
pub fn run(code: &[u8], regs: &mut Registers) -> Result<(), RunError> {
    let mut pc = 0;
    while pc < code.len() {
        match decode(&code[pc..]) {
            Decoded::Stop => return Ok(()),
            Decoded::Binary {
                op,
                dest,
                a,
                b,
                saturate,
            } => {
                if !dest.size32 {
                    return Err(RunError::Unsupported);
                }
                let (a, b) = (source(regs, a)?, source(regs, b)?);
                let mut result = match op {
                    BinOp::Add => a + b,
                    BinOp::Mul => a * b,
                };
                if saturate {
                    result = result.clamp(0.0, 1.0);
                }
                regs.write_f32(dest.reg, result);
                pc += 6;
            }
            Decoded::Unsupported { .. } => return Err(RunError::Unsupported),
        }
    }
    Err(RunError::Overrun)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(reg: Reg) -> FloatSrc {
        FloatSrc {
            reg,
            size32: true,
            abs: false,
            neg: false,
        }
    }

    fn d(reg: Reg) -> Dest {
        Dest { reg, size32: true }
    }

    #[test]
    fn stop_and_binary_ops_round_trip_through_decode() {
        assert_eq!(decode(&encode_stop()), Decoded::Stop);
        let want = Decoded::Binary {
            op: BinOp::Add,
            dest: d(4),
            a: r(0),
            b: FloatSrc {
                reg: 2,
                size32: true,
                abs: true,
                neg: true,
            },
            saturate: true,
        };
        let Decoded::Binary {
            op,
            dest,
            a,
            b,
            saturate,
        } = want
        else {
            unreachable!()
        };
        let bytes = encode_binary(op, dest, a, b, saturate);
        assert_eq!(decode(&bytes), want);
        // Register indices above 63 use the high two bits of the field.
        let hi = encode_binary(BinOp::Mul, d(200), r(130), r(66), false);
        assert_eq!(
            decode(&hi),
            Decoded::Binary {
                op: BinOp::Mul,
                dest: d(200),
                a: r(130),
                b: r(66),
                saturate: false,
            }
        );
    }

    #[test]
    fn unsupported_forms_refuse_rather_than_guess() {
        // An unmodeled opcode (fcsel-ish 0b000000).
        assert_eq!(decode(&[0, 0, 0, 0, 0, 0]), Decoded::Unsupported { len: 0 });
        // The immediate source case (source bits 6:9 zero) is not modeled.
        let mut word = 0u64;
        set(&mut word, 0, OP_FADD, 6);
        let bytes = word.to_le_bytes();
        assert!(matches!(decode(&bytes[..6]), Decoded::Unsupported { .. }));
    }

    #[test]
    fn the_interpreter_computes_a_multiply_add_sequence() {
        // 32-bit registers occupy lane pairs, so they step by two: r8 = r0 *
        // r2; r10 = r8 + r4, saturated to [0,1].
        let mut code = Vec::new();
        code.extend_from_slice(&encode_binary(BinOp::Mul, d(8), r(0), r(2), false));
        code.extend_from_slice(&encode_binary(BinOp::Add, d(10), r(8), r(4), true));
        code.extend_from_slice(&encode_stop());
        let mut regs = Registers::new(16);
        regs.write_f32(0, 0.5);
        regs.write_f32(2, 0.5);
        regs.write_f32(4, 0.1);
        run(&code, &mut regs).unwrap();
        assert_eq!(regs.read_f32(8), 0.25);
        assert!((regs.read_f32(10) - 0.35).abs() < 1e-6);
        // Saturation clamps above 1.0.
        regs.write_f32(4, 2.0);
        run(&code, &mut regs).unwrap();
        assert_eq!(regs.read_f32(10), 1.0);
    }

    #[test]
    fn a_half_destination_refuses() {
        // A 16-bit (half) destination of an F32 op is not modeled.
        let code = encode_binary(
            BinOp::Add,
            Dest {
                reg: 2,
                size32: false,
            },
            r(0),
            r(4),
            false,
        );
        let mut regs = Registers::new(8);
        assert_eq!(run(&code, &mut regs), Err(RunError::Unsupported));
    }
}
