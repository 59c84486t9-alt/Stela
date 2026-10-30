//! Test-only models of host instructions this machine lacks.
//!
//! Native equivalence tests run emitted code on the host. For the features
//! [`host`] adds, a SIGILL handler decodes the faulting instruction, applies
//! its model (Intel SDM Vol. 2) to the interrupted registers in the Linux
//! signal frame and resumes after it. `models_match_the_host_instructions`
//! checks each model against the instruction wherever the host has it,
//! which Intel SDE provides for each Intel extension.
use crate::TargetCpu;
use core::ffi::c_void;
use std::sync::{Once, OnceLock};

/// `ucontext_t.uc_mcontext.gregs`, after `uc_flags`, `uc_link` and the
/// 24-byte `stack_t`.
const GREGS: usize = 40;
/// `REG_RIP` in `gregs`.
const RIP: usize = 16;
/// `uc_mcontext.fpregs`, after the 23 general registers.
const FPREGS: usize = GREGS + 23 * 8;
/// XMM0 in the FXSAVE image `fpregs` points to.
const XMM: usize = 160;
/// `_fpx_sw_bytes.magic1`: the kernel saved an XSAVE image.
const MAGIC1: usize = 464;
const FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
/// `_fpx_sw_bytes.xfeatures`: the state components the image holds.
const XFEATURES: usize = 472;
/// XSAVE header XSTATE_BV: a clear bit means the component is in its initial
/// (zero) state and its bytes are stale.
const XSTATE_BV: usize = 512;
/// MXCSR in the FXSAVE image.
const MXCSR: usize = 24;
/// XSAVE components: the upper halves of YMM0..15, the opmask registers, the
/// upper halves of ZMM0..15, and ZMM16..31.
const AVX: u32 = 2;
const OPMASK: u32 = 5;
const ZMM_HI256: u32 = 6;
const HI16_ZMM: u32 = 7;
const SIGILL: i32 = 4;
const SA_SIGINFO: i32 = 4;
const SIG_DFL: usize = 0;

/// The host's features plus the modeled ones when the host can hold their
/// state (AVX), with the handler installed.
pub fn host() -> TargetCpu {
    let host = TargetCpu::detect();
    if !host.supports(TargetCpu::Avx2) {
        return host;
    }
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        layout();
        let action = SigAction {
            handler: trap as unsafe extern "C" fn(i32, *mut c_void, *mut c_void) as usize,
            mask: [0; 16],
            flags: SA_SIGINFO,
            restorer: 0,
        };
        // SAFETY: a valid action for SIGILL; the handler is async-signal-safe.
        let installed = unsafe { sigaction(SIGILL, &action, core::ptr::null_mut()) };
        assert_eq!(installed, 0);
    });
    let host = host
        .with_avx_vnni_int8()
        .with_avx_vnni_int16()
        .with_sha512();
    // EVEX forms need the host's opmask and ZMM state.
    if host.supports(TargetCpu::Avx512f) {
        host.with_avx512fp16()
    } else {
        host
    }
}

#[repr(C)]
struct SigAction {
    handler: usize,
    mask: [u64; 16],
    flags: i32,
    restorer: usize,
}

unsafe extern "C" {
    fn sigaction(signal: i32, action: *const SigAction, old: *mut SigAction) -> i32;
    fn write(fd: i32, bytes: *const c_void, count: usize) -> isize;
}

/// One XSAVE component's place in the standard-format image (CPUID 0DH).
#[derive(Clone, Copy)]
struct Component {
    bit: u32,
    offset: usize,
    bytes: usize,
}

struct Layout {
    avx: Component,
    opmask: Component,
    zmm_hi256: Component,
    hi16_zmm: Component,
}

fn layout() -> &'static Layout {
    static LAYOUT: OnceLock<Layout> = OnceLock::new();
    LAYOUT.get_or_init(|| {
        let component = |bit| {
            let leaf = core::arch::x86_64::__cpuid_count(0xd, bit);
            Component {
                bit,
                offset: leaf.ebx as usize,
                bytes: leaf.eax as usize,
            }
        };
        Layout {
            avx: component(AVX),
            opmask: component(OPMASK),
            zmm_hi256: component(ZMM_HI256),
            hi16_zmm: component(HI16_ZMM),
        }
    })
}

/// The interrupted vector registers: an XSAVE image in a signal frame.
struct Frame(*mut u8);

impl Frame {
    fn header(&self, at: usize) -> *mut u64 {
        // SAFETY: the kernel's image covers the FXSAVE area and XSAVE header.
        unsafe { self.0.add(at).cast() }
    }
    fn holds(&self, component: Component) -> bool {
        // SAFETY: as above.
        unsafe { *self.header(XFEATURES) & 1 << component.bit != 0 }
    }
    fn live(&self, component: Component) -> bool {
        // SAFETY: as above.
        self.holds(component) && unsafe { *self.header(XSTATE_BV) & 1 << component.bit != 0 }
    }
    /// The parts of ZMM `register`: its byte range, the component holding it
    /// (`None` for the legacy XMM area) and its offset in the image.
    fn parts(
        register: u8,
    ) -> impl Iterator<Item = (core::ops::Range<usize>, Option<Component>, usize)> {
        let layout = layout();
        let r = usize::from(register);
        let parts = if r < 16 {
            [
                Some((0..16, None, XMM + 16 * r)),
                Some((16..32, Some(layout.avx), layout.avx.offset + 16 * r)),
                Some((
                    32..64,
                    Some(layout.zmm_hi256),
                    layout.zmm_hi256.offset + 32 * r,
                )),
            ]
        } else {
            [
                Some((
                    0..64,
                    Some(layout.hi16_zmm),
                    layout.hi16_zmm.offset + 64 * (r - 16),
                )),
                None,
                None,
            ]
        };
        parts.into_iter().flatten()
    }
    fn read(&self, register: u8) -> [u8; 64] {
        let mut value = [0; 64];
        for (range, component, at) in Self::parts(register) {
            if component.is_none_or(|component| self.live(component)) {
                // SAFETY: the part lies inside the image the frame holds.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        self.0.add(at),
                        value[range.clone()].as_mut_ptr(),
                        range.len(),
                    );
                }
            }
        }
        value
    }
    /// Opmask register `k`, zero when the component is in its initial state.
    fn opmask(&self, k: u8) -> u64 {
        let opmask = layout().opmask;
        if !self.live(opmask) {
            return 0;
        }
        // SAFETY: the component lies inside the image.
        unsafe {
            self.0
                .add(opmask.offset + 8 * usize::from(k))
                .cast::<u64>()
                .read_unaligned()
        }
    }
    fn mxcsr(&self) -> *mut u32 {
        // SAFETY: MXCSR lies inside the FXSAVE area.
        unsafe { self.0.add(MXCSR).cast() }
    }
    /// Write all of ZMM `register`; false when a nonzero part has no place in
    /// the image.
    fn write(&mut self, register: u8, value: &[u8; 64]) -> bool {
        for (range, component, at) in Self::parts(register) {
            let part = &value[range];
            if let Some(component) = component {
                let zero = part.iter().all(|&byte| byte == 0);
                if !self.holds(component) {
                    if zero {
                        continue;
                    }
                    return false;
                }
                if !self.live(component) {
                    if zero {
                        continue;
                    }
                    // Its stale bytes become every register's live state.
                    // SAFETY: the component lies inside the image.
                    unsafe {
                        core::ptr::write_bytes(self.0.add(component.offset), 0, component.bytes);
                        *self.header(XSTATE_BV) |= 1 << component.bit;
                    }
                }
            }
            // SAFETY: the part lies inside the image.
            unsafe { core::ptr::copy_nonoverlapping(part.as_ptr(), self.0.add(at), part.len()) };
        }
        true
    }
}

/// A register-only VEX3 or EVEX instruction without an immediate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Instruction {
    evex: bool,
    /// The opcode map: 2 for 0F38 (VEX), 5 or 6 for the FP16 maps (EVEX).
    map: u8,
    opcode: u8,
    /// 0: none, 1: 66, 2: F3, 3: F2.
    pp: u8,
    w: bool,
    /// The vector length in bytes.
    bytes: usize,
    reg: u8,
    vvvv: u8,
    rm: u8,
    /// EVEX.aaa, the writemask register; k0 writes every lane.
    opmask: u8,
    /// EVEX.z: masked lanes clear instead of keeping the destination.
    zeroing: bool,
}

impl Instruction {
    /// C4 or 62, the payload bytes, the opcode and ModRM.
    fn length(evex: bool) -> usize {
        if evex { 6 } else { 5 }
    }
    fn decode(bytes: &[u8]) -> Option<Self> {
        let invert = |byte: u8, bit: u8| (!byte >> bit & 1) << 3;
        match *bytes {
            [0xc4, first, second, opcode, modrm] if first & 0x1f == 2 && modrm >> 6 == 3 => {
                Some(Self {
                    evex: false,
                    map: 2,
                    opcode,
                    pp: second & 3,
                    w: second & 0x80 != 0,
                    bytes: if second & 4 != 0 { 32 } else { 16 },
                    reg: (modrm >> 3 & 7) | invert(first, 7),
                    vvvv: !second >> 3 & 15,
                    rm: (modrm & 7) | invert(first, 5),
                    opmask: 0,
                    zeroing: false,
                })
            }
            // EVEX.b (rounding or broadcast) and L'L = 3 are not modeled.
            [0x62, p0, p1, p2, opcode, modrm]
                if p0 & 8 == 0
                    && p1 & 4 != 0
                    && p2 & 0x10 == 0
                    && p2 >> 5 & 3 != 3
                    && modrm >> 6 == 3 =>
            {
                Some(Self {
                    evex: true,
                    map: p0 & 7,
                    opcode,
                    pp: p1 & 3,
                    w: p1 & 0x80 != 0,
                    bytes: 16 << (p2 >> 5 & 3),
                    reg: (modrm >> 3 & 7) | invert(p0, 7) | invert(p0, 4) << 1,
                    vvvv: (!p1 >> 3 & 15) | invert(p2, 3) << 1,
                    rm: (modrm & 7) | invert(p0, 5) | invert(p0, 6) << 1,
                    opmask: p2 & 7,
                    zeroing: p2 & 0x80 != 0,
                })
            }
            _ => None,
        }
    }
}

fn qwords(value: &[u8; 64]) -> [u64; 4] {
    core::array::from_fn(|i| u64::from_le_bytes(value[8 * i..][..8].try_into().unwrap()))
}
fn from_qwords(qwords: [u64; 4]) -> [u8; 64] {
    let mut value = [0; 64];
    for (i, qword) in qwords.into_iter().enumerate() {
        value[8 * i..][..8].copy_from_slice(&qword.to_le_bytes());
    }
    value
}

/// VPDPWUUD, VPDPWUSD and VPDPWSUD (AVX-VNNI-INT16): each dword of
/// `accumulator` plus the two products of its words of `left` and `right`,
/// wrapping; bytes above the vector length clear.
fn word_dots(
    accumulator: &[u8; 64],
    left: &[u8; 64],
    right: &[u8; 64],
    signed: [bool; 2],
    bytes: usize,
) -> [u8; 64] {
    let word = |value: &[u8; 64], at: usize, signed: bool| {
        let word = u16::from_le_bytes([value[at], value[at + 1]]);
        if signed {
            i64::from(word as i16)
        } else {
            i64::from(word)
        }
    };
    let mut result = [0; 64];
    for lane in (0..bytes).step_by(4) {
        let sum = [lane, lane + 2].into_iter().fold(
            u32::from_le_bytes(accumulator[lane..][..4].try_into().unwrap()),
            |sum, at| {
                sum.wrapping_add((word(left, at, signed[0]) * word(right, at, signed[1])) as u32)
            },
        );
        result[lane..][..4].copy_from_slice(&sum.to_le_bytes());
    }
    result
}

/// VPDPBUUD, VPDPBSUD and VPDPBSSD (AVX-VNNI-INT8): each dword of
/// `accumulator` plus the four products of its bytes of `left` and `right`,
/// wrapping; bytes above the vector length clear.
fn byte_dots(
    accumulator: &[u8; 64],
    left: &[u8; 64],
    right: &[u8; 64],
    signed: [bool; 2],
    bytes: usize,
) -> [u8; 64] {
    let extend = |byte: u8, signed: bool| {
        if signed {
            i32::from(byte as i8)
        } else {
            i32::from(byte)
        }
    };
    let mut result = [0; 64];
    for lane in (0..bytes).step_by(4) {
        let sum = (lane..lane + 4).fold(
            u32::from_le_bytes(accumulator[lane..][..4].try_into().unwrap()),
            |sum, i| {
                sum.wrapping_add((extend(left[i], signed[0]) * extend(right[i], signed[1])) as u32)
            },
        );
        result[lane..][..4].copy_from_slice(&sum.to_le_bytes());
    }
    result
}

fn large_sigma0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}
fn large_sigma1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}
fn small_sigma0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ x >> 7
}
fn small_sigma1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ x >> 6
}

/// VSHA512RNDS2: two rounds on the state C, D, G, H in `state` (qwords 3, 2,
/// 1, 0) and A, B, E, F in `source` with the summed K+W pair `wk`, leaving A,
/// B, E, F there.
fn sha512_rounds(state: [u64; 4], source: [u64; 4], wk: [u64; 4]) -> [u64; 4] {
    let [mut h, mut g, mut d, mut c] = state;
    let [mut f, mut e, mut b, mut a] = source;
    for &k in &wk[..2] {
        let t1 = (e & f ^ !e & g)
            .wrapping_add(large_sigma1(e))
            .wrapping_add(k)
            .wrapping_add(h);
        let t2 = (a & b ^ a & c ^ b & c).wrapping_add(large_sigma0(a));
        (h, g, f, e) = (g, f, e, d.wrapping_add(t1));
        (d, c, b, a) = (c, b, a, t1.wrapping_add(t2));
    }
    [f, e, b, a]
}

/// VSHA512MSG1: each qword of `state` plus the small sigma0 of the next, with
/// `source` qword 0 after qword 3.
fn sha512_message1(state: [u64; 4], source: [u64; 4]) -> [u64; 4] {
    let next = [state[1], state[2], state[3], source[0]];
    core::array::from_fn(|i| state[i].wrapping_add(small_sigma0(next[i])))
}

/// VSHA512MSG2: W16..W19 from `state` and W14, W15 in `source` qwords 2 and
/// 3, each new word feeding the one two after it.
fn sha512_message2(state: [u64; 4], source: [u64; 4]) -> [u64; 4] {
    let mut w = [source[2], source[3], 0, 0, 0, 0];
    for i in 0..4 {
        w[i + 2] = state[i].wrapping_add(small_sigma1(w[i]));
    }
    [w[2], w[3], w[4], w[5]]
}

/// IEEE binary16 arithmetic as the AVX512-FP16 instructions perform it,
/// with MXCSR rounding and status (SDM Vol. 1 4.9 and Vol. 2). The
/// instructions ignore MXCSR.DAZ and FTZ and report no denormal operands
/// (DE), as Intel SDE does.
mod half {
    pub(super) const INVALID: u32 = 1;
    pub(super) const DIVIDE_BY_ZERO: u32 = 4;
    pub(super) const OVERFLOW: u32 = 8;
    pub(super) const UNDERFLOW: u32 = 16;
    pub(super) const INEXACT: u32 = 32;
    const SIGN: u16 = 0x8000;
    const EXPONENT: u16 = 0x7c00;
    const QUIET: u16 = 0x0200;
    /// The QNaN floating-point indefinite.
    const INDEFINITE: u16 = 0xfe00;
    const MAXIMUM: u16 = 0x7bff;

    #[derive(Clone, Copy)]
    pub(super) enum Operation {
        Add,
        Subtract,
        Multiply,
        Divide,
    }

    fn power(exponent: i32) -> f64 {
        f64::from_bits(((exponent + 1023) as u64) << 52)
    }
    fn nan(bits: u16) -> bool {
        bits & EXPONENT == EXPONENT && bits & !(SIGN | EXPONENT) != 0
    }
    fn value(bits: u16) -> f64 {
        let magnitude = bits & !SIGN;
        let value = if magnitude & EXPONENT == EXPONENT {
            f64::INFINITY
        } else if magnitude & EXPONENT == 0 {
            f64::from(magnitude) * power(-24)
        } else {
            f64::from(magnitude & 0x3ff | 0x400) * power(i32::from(magnitude >> 10) - 25)
        };
        if bits & SIGN != 0 { -value } else { value }
    }

    /// Round the nonnegative `scaled` to an integer under MXCSR.RC `rounding`
    /// for a value of sign `negative`.
    fn integer(scaled: f64, rounding: u32, negative: bool) -> f64 {
        let floor = scaled.floor();
        let fraction = scaled - floor;
        let up = match rounding {
            0 => fraction > 0.5 || fraction == 0.5 && floor % 2.0 == 1.0,
            1 => negative && fraction != 0.0,
            2 => !negative && fraction != 0.0,
            _ => false,
        };
        floor + f64::from(u8::from(up))
    }

    /// Round the finite nonzero `exact` to binary16. Quotients of binary16
    /// values are either exact in f64 or farther than 2^-22 relative from
    /// every binary16 value and midpoint, so rounding the f64 quotient
    /// rounds the exact one. Tininess is detected after rounding.
    fn round(exact: f64, rounding: u32) -> (u16, u32) {
        let negative = exact < 0.0;
        let magnitude = exact.abs();
        let exponent = ((magnitude.to_bits() >> 52) as i32) - 1023;
        let unbounded =
            integer(magnitude / power(exponent - 10), rounding, negative) * power(exponent - 10);
        let quantum = power(exponent.max(-14) - 10);
        let rounded = integer(magnitude / quantum, rounding, negative) * quantum;
        let mut status = if rounded == magnitude { 0 } else { INEXACT };
        let sign = if negative { SIGN } else { 0 };
        if rounded > value(MAXIMUM) {
            let infinity = match rounding {
                0 => true,
                1 => negative,
                2 => !negative,
                _ => false,
            };
            let bits = if infinity { EXPONENT } else { MAXIMUM };
            return (sign | bits, OVERFLOW | INEXACT);
        }
        if unbounded < power(-14) && status != 0 {
            status |= UNDERFLOW;
        }
        let bits = if rounded >= power(-14) {
            let exponent = ((rounded.to_bits() >> 52) as i32) - 1023;
            ((exponent + 15) as u16) << 10 | ((rounded / power(exponent - 10)) as u16 - 0x400)
        } else {
            (rounded / power(-24)) as u16
        };
        (sign | bits, status)
    }

    /// One lane: the result bits and the MXCSR status it raises.
    pub(super) fn arithmetic(
        operation: Operation,
        left: u16,
        right: u16,
        rounding: u32,
    ) -> (u16, u32) {
        if nan(left) || nan(right) {
            let signaling = |bits| nan(bits) && bits & QUIET == 0;
            let status = if signaling(left) || signaling(right) {
                INVALID
            } else {
                0
            };
            return (if nan(left) { left } else { right } | QUIET, status);
        }
        let status = 0;
        let (x, y) = (value(left), value(right));
        let invalid = (INDEFINITE, status | INVALID);
        let exact = match operation {
            Operation::Add | Operation::Subtract => {
                let y = if matches!(operation, Operation::Subtract) {
                    -y
                } else {
                    y
                };
                if x.is_infinite() && y.is_infinite() && x != y {
                    return invalid;
                }
                if x + y == 0.0 {
                    // Zeros of one sign keep it; any other exact zero sum is
                    // -0 when rounding down and +0 otherwise (IEEE 754 6.3).
                    let alike =
                        x == 0.0 && y == 0.0 && x.is_sign_negative() == y.is_sign_negative();
                    let negative = if alike {
                        x.is_sign_negative()
                    } else {
                        rounding == 1
                    };
                    return (if negative { SIGN } else { 0 }, status);
                }
                x + y
            }
            Operation::Multiply => {
                if x == 0.0 && y.is_infinite() || x.is_infinite() && y == 0.0 {
                    return invalid;
                }
                x * y
            }
            Operation::Divide => {
                if x == 0.0 && y == 0.0 || x.is_infinite() && y.is_infinite() {
                    return invalid;
                }
                if y == 0.0 && !x.is_infinite() {
                    let sign = (left ^ right) & SIGN;
                    return (sign | EXPONENT, status | DIVIDE_BY_ZERO);
                }
                x / y
            }
        };
        if exact.is_infinite() || exact == 0.0 {
            let sign = if exact.is_sign_negative() { SIGN } else { 0 };
            return (sign | if exact == 0.0 { 0 } else { EXPONENT }, status);
        }
        let (bits, rounded) = round(exact, rounding);
        (bits, status | rounded)
    }
}

/// MXCSR and the opmask registers the instruction reads.
struct Control {
    mxcsr: u32,
    opmask: u64,
}

/// FP16 lanes of `bytes` from `left` and `right` under `instruction`'s
/// writemask, with MXCSR status; `None` when an unmasked exception would
/// trap.
fn half_lanes(
    instruction: Instruction,
    operation: half::Operation,
    destination: &[u8; 64],
    [left, right]: [&[u8; 64]; 2],
    control: &mut Control,
) -> Option<[u8; 64]> {
    let mut result = [0; 64];
    let rounding = control.mxcsr >> 13 & 3;
    let mut status = 0;
    for lane in 0..instruction.bytes / 2 {
        let at = 2 * lane;
        let active = instruction.opmask == 0 || control.opmask >> lane & 1 != 0;
        let bits = if active {
            let word = |value: &[u8; 64]| u16::from_le_bytes([value[at], value[at + 1]]);
            let (bits, raised) = half::arithmetic(operation, word(left), word(right), rounding);
            status |= raised;
            bits
        } else if instruction.zeroing {
            0
        } else {
            u16::from_le_bytes([destination[at], destination[at + 1]])
        };
        result[at..at + 2].copy_from_slice(&bits.to_le_bytes());
    }
    // Masked exceptions only: the status bits whose MXCSR mask is clear trap.
    if status & !(control.mxcsr >> 7) & 0x3f != 0 {
        return None;
    }
    control.mxcsr |= status;
    Some(result)
}

/// The new value of the destination register from its old value and the
/// vvvv and ModRM.rm sources, or `None` when the form is not modeled.
fn apply(
    instruction: Instruction,
    destination: [u8; 64],
    first: [u8; 64],
    second: [u8; 64],
    control: &mut Control,
) -> Option<[u8; 64]> {
    let bytes = instruction.bytes;
    if instruction.evex {
        let operation = match (
            instruction.map,
            instruction.opcode,
            instruction.pp,
            instruction.w,
        ) {
            (5, 0x58, 0, false) => half::Operation::Add,
            (5, 0x5c, 0, false) => half::Operation::Subtract,
            (5, 0x59, 0, false) => half::Operation::Multiply,
            (5, 0x5e, 0, false) => half::Operation::Divide,
            _ => return None,
        };
        return half_lanes(
            instruction,
            operation,
            &destination,
            [&first, &second],
            control,
        );
    }
    let vex = instruction;
    let wide = bytes == 32;
    match (vex.opcode, vex.pp, vex.w) {
        (0x50, pp, false) if pp != 1 => {
            let signed = [pp != 0, pp == 3];
            Some(byte_dots(&destination, &first, &second, signed, bytes))
        }
        (0xd2, pp, false) => {
            // VEX.pp: VPDPWUUD, VPDPWUSD (signed second source), VPDPWSUD.
            let signed = [pp == 2, pp == 1];
            Some(word_dots(&destination, &first, &second, signed, bytes))
        }
        (0xcb, 3, false) if wide => Some(from_qwords(sha512_rounds(
            qwords(&destination),
            qwords(&first),
            [qwords(&second)[0], qwords(&second)[1], 0, 0],
        ))),
        (0xcc, 3, false) if wide && vex.vvvv == 0 => Some(from_qwords(sha512_message1(
            qwords(&destination),
            qwords(&second),
        ))),
        (0xcd, 3, false) if wide && vex.vvvv == 0 => Some(from_qwords(sha512_message2(
            qwords(&destination),
            qwords(&second),
        ))),
        _ => None,
    }
}

unsafe extern "C" fn trap(_: i32, _: *mut c_void, context: *mut c_void) {
    // SAFETY: the kernel passes a ucontext_t whose RIP addresses the
    // instruction that faulted, and fpregs its XSAVE image.
    unsafe {
        let context = context.cast::<u8>();
        let rip = context.add(GREGS + 8 * RIP).cast::<u64>();
        let image = *context.add(FPREGS).cast::<*mut u8>();
        let start = *rip as *const u8;
        // The faulting instruction is mapped; read only its own bytes.
        let length = Instruction::length(start.read() == 0x62);
        let bytes = core::slice::from_raw_parts(start, length);
        let mut frame = Frame(image);
        if !image.is_null() && image.add(MAGIC1).cast::<u32>().read() == FP_XSTATE_MAGIC1 {
            let mut control = Control {
                mxcsr: frame.mxcsr().read(),
                opmask: 0,
            };
            let result = Instruction::decode(bytes).and_then(|instruction| {
                control.opmask = frame.opmask(instruction.opmask);
                let [destination, first, second] =
                    [instruction.reg, instruction.vvvv, instruction.rm].map(|r| frame.read(r));
                Some((
                    instruction,
                    apply(instruction, destination, first, second, &mut control)?,
                ))
            });
            if let Some((instruction, result)) = result
                && frame.write(instruction.reg, &result)
            {
                frame.mxcsr().write(control.mxcsr);
                *rip += length as u64;
                return;
            }
        }
        // Fault again without the handler.
        let message = b"modeled: unmodeled instruction, restoring SIGILL\n";
        write(2, message.as_ptr().cast(), message.len());
        let default = SigAction {
            handler: SIG_DFL,
            mask: [0; 16],
            flags: 0,
            restorer: 0,
        };
        sigaction(SIGILL, &default, core::ptr::null_mut());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        GuestState, context::ExecutionContext, x86_64::asm::vector_extensions::execution::Native,
    };
    use alloc::vec::Vec;

    impl Instruction {
        fn encode(self) -> Vec<u8> {
            let bit = |register: u8, bit: u8| !register >> bit & 1;
            if !self.evex {
                return alloc::vec![
                    0xc4,
                    bit(self.reg, 3) << 7 | 1 << 6 | bit(self.rm, 3) << 5 | self.map,
                    u8::from(self.w) << 7
                        | (!self.vvvv & 15) << 3
                        | u8::from(self.bytes == 32) << 2
                        | self.pp,
                    self.opcode,
                    0xc0 | (self.reg & 7) << 3 | (self.rm & 7),
                ];
            }
            alloc::vec![
                0x62,
                bit(self.reg, 3) << 7
                    | bit(self.rm, 4) << 6
                    | bit(self.rm, 3) << 5
                    | bit(self.reg, 4) << 4
                    | self.map,
                u8::from(self.w) << 7 | (!self.vvvv & 15) << 3 | 4 | self.pp,
                u8::from(self.zeroing) << 7
                    | ((self.bytes / 32) as u8) << 5
                    | bit(self.vvvv, 4) << 3
                    | self.opmask,
                self.opcode,
                0xc0 | (self.reg & 7) << 3 | (self.rm & 7),
            ]
        }
    }

    /// An instruction addressing RDI + `offset` (ModRM 10 reg 111).
    fn at_rdi(prefix: &[u8], reg: u8, offset: usize) -> Vec<u8> {
        let mut bytes = prefix.to_vec();
        bytes.push(0x87 | reg << 3);
        bytes.extend((offset as u32).to_le_bytes());
        bytes
    }

    /// YMM `register` as the test loads it: guest vectors 2r and 2r + 1.
    fn ymm(state: &GuestState, register: usize) -> [u8; 64] {
        let mut value = [0; 64];
        for (i, limb) in state.v.as_flattened()[4 * register..][..4]
            .iter()
            .enumerate()
        {
            value[8 * i..][..8].copy_from_slice(&limb.to_le_bytes());
        }
        value
    }

    /// A binary16 value from every class: normals across the exponent range,
    /// zeros, denormals, infinities and both kinds of NaN.
    fn half(random: u64) -> u16 {
        let sign = (random >> 63) as u16 * 0x8000;
        let fraction = (random >> 20) as u16 & 0x3ff;
        sign | match random % 16 {
            0 => 0,
            1 => fraction.max(1),
            2 => 0x7c00,
            3 => 0x7c00 | fraction.max(1),
            4 => 0x7e00 | fraction,
            5 => 0x3c00,
            6 => 0x0400 | fraction,
            7 => 0x7800 | fraction,
            8 => 0x3800 | fraction,
            _ => ((random >> 32) as u16 & 0x7fff) % 0x7c00,
        }
    }

    #[test]
    fn models_match_the_host_instructions() {
        let host = TargetCpu::detect();
        let int8 = TargetCpu::X86_64_V3.with_avx_vnni_int8();
        let int16 = TargetCpu::X86_64_V3.with_avx_vnni_int16();
        let sha512 = TargetCpu::X86_64_V3.with_sha512();
        let fp16 = TargetCpu::X86_64_V4.with_avx512fp16();
        // YMM1 is the destination, YMM2 the vvvv source (0 when the form has
        // none) and YMM3 the ModRM.rm source.
        let vex = |opcode, pp, bytes, vvvv| Instruction {
            evex: false,
            map: 2,
            opcode,
            pp,
            w: false,
            bytes,
            reg: 1,
            vvvv,
            rm: 3,
            opmask: 0,
            zeroing: false,
        };
        let mut forms = Vec::new();
        for bytes in [16, 32] {
            for pp in [0, 2, 3] {
                forms.push((int8, vex(0x50, pp, bytes, 2)));
            }
            for pp in [0, 1, 2] {
                forms.push((int16, vex(0xd2, pp, bytes, 2)));
            }
            for opcode in [0x58, 0x5c, 0x59, 0x5e] {
                for (opmask, zeroing) in [(0, false), (1, true), (1, false)] {
                    forms.push((
                        fp16,
                        Instruction {
                            evex: true,
                            map: 5,
                            opmask,
                            zeroing,
                            ..vex(opcode, 0, bytes, 2)
                        },
                    ));
                }
            }
        }
        forms.extend([
            (sha512, vex(0xcb, 3, 32, 2)),
            (sha512, vex(0xcc, 3, 32, 0)),
            (sha512, vex(0xcd, 3, 32, 0)),
        ]);
        let vectors = core::mem::offset_of!(GuestState, v);
        let x = |i: usize| core::mem::offset_of!(GuestState, x) + 8 * i;
        let mut random = 0x243f_6a88_85a3_08d3_u64;
        let mut next = move || {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            random
        };
        let mut checked = 0;
        for (target, instruction) in forms {
            if !host.supports(target) {
                continue;
            }
            // X0 holds the MXCSR to run under, X1 receives the resulting one,
            // X2 holds the caller's and X3 the K1 writemask.
            let mut code = at_rdi(&[0x0f, 0xae], 2, x(0));
            if instruction.evex {
                code.extend(at_rdi(&[0xc5, 0xf8, 0x90], 1, x(3)));
            }
            for register in 1..4 {
                let offset = vectors + 32 * usize::from(register);
                code.extend(at_rdi(&[0xc5, 0xfe, 0x6f], register, offset));
            }
            code.extend(instruction.encode());
            code.extend(at_rdi(&[0xc5, 0xfe, 0x7f], 1, vectors + 32));
            code.extend(at_rdi(&[0x0f, 0xae], 3, x(1)));
            code.extend(at_rdi(&[0x0f, 0xae], 2, x(2)));
            code.extend([0xc5, 0xf8, 0x77, 0xc3]); // vzeroupper; ret
            let native = Native::new(&code);
            for sample in 0..256 {
                let mut state = GuestState::default();
                for limb in state.v.as_flattened_mut() {
                    *limb = match sample {
                        0 => 0x8080_8080_8080_8080,
                        1 => u64::MAX,
                        _ if instruction.evex => (0..4).fold(0, |limb, lane| {
                            limb | u64::from(half(next())) << (16 * lane)
                        }),
                        _ => next(),
                    };
                }
                let mut caller = 0u32;
                // SAFETY: STMXCSR writes four bytes to the local.
                unsafe { core::arch::asm!("stmxcsr [{}]", in(reg) &mut caller) };
                let rounding = (sample % 4) << 13;
                state.x[0] = 0x1f80 | rounding;
                state.x[2] = u64::from(caller);
                state.x[3] = next() & 0xffff;
                let first = if instruction.vvvv == 0 {
                    [0; 64]
                } else {
                    ymm(&state, 2)
                };
                let mut control = Control {
                    mxcsr: 0x1f80 | rounding as u32,
                    opmask: state.x[3],
                };
                let model = apply(
                    instruction,
                    ymm(&state, 1),
                    first,
                    ymm(&state, 3),
                    &mut control,
                )
                .unwrap();
                native.run(&mut state, &mut ExecutionContext::default());
                // Intel SDE 10.13.1 raises only IE and ZE for VADDPH, VSUBPH
                // and VMULPH, and adds only PE for VDIVPH (no OE or UE), so
                // the rest of their status rests on IEEE 754 and
                // `half_rounding_status_and_special_values`.
                let emulated = half::INVALID | half::DIVIDE_BY_ZERO;
                let compared = match (instruction.evex, instruction.opcode) {
                    (false, _) => !0,
                    (true, 0x5e) => !0x3f | emulated | half::INEXACT,
                    (true, _) => !0x3f | emulated,
                };
                assert_eq!(
                    (ymm(&state, 1)[..32].to_vec(), state.x[1] as u32 & compared),
                    (model[..32].to_vec(), control.mxcsr & compared),
                    "{instruction:x?} sample={sample}"
                );
                checked += 1;
            }
        }
        std::println!("MODELED_FORMS_CHECKED={checked}");
    }

    #[test]
    fn instruction_fields_round_trip_through_gnu_encodings() {
        // GNU as 2.42.
        for (bytes, map, opcode, pp, width, [reg, vvvv, rm], opmask, zeroing) in [
            (
                &[0xc4, 0xe2, 0x7b, 0x50, 0xd1][..],
                2,
                0x50,
                3,
                16,
                [2, 0, 1],
                0,
                false,
            ),
            (
                &[0xc4, 0x42, 0x2c, 0xd2, 0xcb],
                2,
                0xd2,
                0,
                32,
                [9, 10, 11],
                0,
                false,
            ),
            (
                &[0x62, 0xf5, 0x6c, 0x89, 0x58, 0xcb],
                5,
                0x58,
                0,
                16,
                [1, 2, 3],
                1,
                true,
            ),
            (
                &[0x62, 0xf5, 0x6c, 0x29, 0x59, 0xcb],
                5,
                0x59,
                0,
                32,
                [1, 2, 3],
                1,
                false,
            ),
            (
                &[0x62, 0xa5, 0x6c, 0xa2, 0x5e, 0xcb],
                5,
                0x5e,
                0,
                32,
                [17, 18, 19],
                2,
                true,
            ),
            (
                &[0x62, 0x55, 0x2c, 0x0f, 0x5e, 0xcb],
                5,
                0x5e,
                0,
                16,
                [9, 10, 11],
                7,
                false,
            ),
        ] {
            let instruction = Instruction {
                evex: bytes[0] == 0x62,
                map,
                opcode,
                pp,
                w: false,
                bytes: width,
                reg,
                vvvv,
                rm,
                opmask,
                zeroing,
            };
            assert_eq!(
                Instruction::decode(bytes),
                Some(instruction),
                "{bytes:02x?}"
            );
            assert_eq!(instruction.encode(), bytes);
        }
    }

    #[test]
    fn half_rounding_status_and_special_values() {
        use half::*;
        let add = |left, right, rounding| arithmetic(Operation::Add, left, right, rounding);
        // 1 + 2^-11 is a tie: to even down, toward +infinity up.
        assert_eq!(add(0x3c00, 0x1000, 0), (0x3c00, INEXACT));
        assert_eq!(add(0x3c00, 0x1000, 2), (0x3c01, INEXACT));
        // 65504 + 16 ties to 65536, overflowing to infinity, but is 65504
        // toward zero; 65504 + 32 overflows to 65504 toward zero.
        assert_eq!(add(0x7bff, 0x4c00, 0), (0x7c00, OVERFLOW | INEXACT));
        assert_eq!(add(0x7bff, 0x4c00, 3), (0x7bff, INEXACT));
        assert_eq!(add(0x7bff, 0x5000, 3), (0x7bff, OVERFLOW | INEXACT));
        // x - x is -0 only when rounding down.
        assert_eq!(
            arithmetic(Operation::Subtract, 0x3c00, 0x3c00, 1),
            (0x8000, 0)
        );
        assert_eq!(arithmetic(Operation::Subtract, 0x3c00, 0x3c00, 0), (0, 0));
        // The first NaN operand returns quiet; an SNaN anywhere is invalid.
        assert_eq!(add(0x7d00, 0xfe01, 0), (0x7f00, INVALID));
        assert_eq!(add(0x3c00, 0xfd01, 0), (0xff01, INVALID));
        assert_eq!(
            arithmetic(Operation::Multiply, 0, 0x7c00, 0),
            (0xfe00, INVALID)
        );
        assert_eq!(
            arithmetic(Operation::Divide, 0xbc00, 0, 0),
            (0xfc00, DIVIDE_BY_ZERO)
        );
        // 2^-14 * (1 - 2^-11) has 11 significant bits below 2^-14, so it is
        // tiny after rounding to an unbounded exponent and underflows even
        // where it rounds to 2^-14.
        assert_eq!(
            arithmetic(Operation::Multiply, 0x0400, 0x3bff, 0),
            (0x0400, UNDERFLOW | INEXACT)
        );
        assert_eq!(
            arithmetic(Operation::Multiply, 0x0400, 0x3bff, 3),
            (0x03ff, UNDERFLOW | INEXACT)
        );
        // Denormal operands raise nothing; an exact denormal result does not
        // underflow.
        assert_eq!(add(0x0001, 0x0001, 0), (0x0002, 0));
    }
}
