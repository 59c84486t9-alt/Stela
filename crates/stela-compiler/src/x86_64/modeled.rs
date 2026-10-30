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
/// XSAVE components: the upper halves of YMM0..15, the upper halves of
/// ZMM0..15, and ZMM16..31.
const AVX: u32 = 2;
const ZMM_HI256: u32 = 6;
const HI16_ZMM: u32 = 7;
/// Every modeled form is a register-only VEX3 instruction without an
/// immediate: C4, two payload bytes, the opcode and ModRM.
const LENGTH: usize = 5;
const SIGILL: i32 = 4;
const SA_SIGINFO: i32 = 4;
const SIG_DFL: usize = 0;

/// The host's features plus the modeled ones when the host can hold their
/// state (AVX), with the handler installed.
pub(crate) fn host() -> TargetCpu {
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
    host.with_avx_vnni_int8().with_sha512()
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

/// A register-only VEX3 instruction in map 0F38.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Vex {
    opcode: u8,
    /// 0: none, 1: 66, 2: F3, 3: F2.
    pp: u8,
    w: bool,
    l: bool,
    reg: u8,
    vvvv: u8,
    rm: u8,
}

impl Vex {
    fn decode(bytes: [u8; LENGTH]) -> Option<Self> {
        let [escape, first, second, opcode, modrm] = bytes;
        if escape != 0xc4 || first & 0x1f != 2 || modrm >> 6 != 3 {
            return None;
        }
        Some(Self {
            opcode,
            pp: second & 3,
            w: second & 0x80 != 0,
            l: second & 4 != 0,
            reg: (modrm >> 3 & 7) | (!first >> 7 & 1) << 3,
            vvvv: !second >> 3 & 15,
            rm: (modrm & 7) | (!first >> 5 & 1) << 3,
        })
    }
    fn encode(self) -> [u8; LENGTH] {
        [
            0xc4,
            (!self.reg >> 3 & 1) << 7 | 1 << 6 | (!self.rm >> 3 & 1) << 5 | 2,
            u8::from(self.w) << 7 | (!self.vvvv & 15) << 3 | u8::from(self.l) << 2 | self.pp,
            self.opcode,
            0xc0 | (self.reg & 7) << 3 | (self.rm & 7),
        ]
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

/// The new value of the destination register from its old value and the
/// VEX.vvvv and ModRM.rm sources, or `None` when the form is not modeled.
fn apply(vex: Vex, destination: [u8; 64], first: [u8; 64], second: [u8; 64]) -> Option<[u8; 64]> {
    let bytes = if vex.l { 32 } else { 16 };
    match (vex.opcode, vex.pp, vex.w) {
        (0x50, pp, false) if pp != 1 => {
            let signed = [pp != 0, pp == 3];
            Some(byte_dots(&destination, &first, &second, signed, bytes))
        }
        (0xcb, 3, false) if vex.l => Some(from_qwords(sha512_rounds(
            qwords(&destination),
            qwords(&first),
            [qwords(&second)[0], qwords(&second)[1], 0, 0],
        ))),
        (0xcc, 3, false) if vex.l && vex.vvvv == 0 => Some(from_qwords(sha512_message1(
            qwords(&destination),
            qwords(&second),
        ))),
        (0xcd, 3, false) if vex.l && vex.vvvv == 0 => Some(from_qwords(sha512_message2(
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
        let bytes = core::ptr::read_unaligned(*rip as *const [u8; LENGTH]);
        let mut frame = Frame(image);
        if !image.is_null() && image.add(MAGIC1).cast::<u32>().read() == FP_XSTATE_MAGIC1 {
            let result = Vex::decode(bytes).and_then(|vex| {
                let [destination, first, second] =
                    [vex.reg, vex.vvvv, vex.rm].map(|r| frame.read(r));
                Some((vex, apply(vex, destination, first, second)?))
            });
            if let Some((vex, result)) = result
                && frame.write(vex.reg, &result)
            {
                *rip += LENGTH as u64;
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

mod tests {
    use super::*;
    use crate::{
        GuestState, context::ExecutionContext, x86_64::asm::vector_extensions::execution::Native,
    };
    use alloc::vec::Vec;

    /// VMOVDQU between YMM `register` and the 32 bytes at RDI + `offset`.
    fn move_ymm(store: bool, register: u8, offset: usize) -> Vec<u8> {
        let mut bytes = alloc::vec![
            0xc5,
            0xfe,
            if store { 0x7f } else { 0x6f },
            0x87 | register << 3
        ];
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

    #[test]
    fn models_match_the_host_instructions() {
        let host = TargetCpu::detect();
        let int8 = TargetCpu::X86_64_V3.with_avx_vnni_int8();
        let sha512 = TargetCpu::X86_64_V3.with_sha512();
        // YMM1 is the destination, YMM2 the VEX.vvvv source (0 when the form
        // has none) and YMM3 the ModRM.rm source.
        let form = |opcode, pp, l, vvvv| Vex {
            opcode,
            pp,
            w: false,
            l,
            reg: 1,
            vvvv,
            rm: 3,
        };
        let mut forms = Vec::new();
        for pp in [0, 2, 3] {
            for l in [false, true] {
                forms.push((int8, form(0x50, pp, l, 2)));
            }
        }
        forms.extend([
            (sha512, form(0xcb, 3, true, 2)),
            (sha512, form(0xcc, 3, true, 0)),
            (sha512, form(0xcd, 3, true, 0)),
        ]);
        let base = core::mem::offset_of!(GuestState, v);
        let mut random = 0x243f_6a88_85a3_08d3_u64;
        let mut checked = 0;
        for (target, vex) in forms {
            if !host.supports(target) {
                continue;
            }
            let mut code = Vec::new();
            for register in 1..4 {
                code.extend(move_ymm(false, register, base + 32 * usize::from(register)));
            }
            code.extend(vex.encode());
            code.extend(move_ymm(true, 1, base + 32));
            code.extend([0xc5, 0xf8, 0x77, 0xc3]); // vzeroupper; ret
            let native = Native::new(&code);
            for sample in 0..64 {
                let mut state = GuestState::default();
                for limb in state.v.as_flattened_mut() {
                    random ^= random << 13;
                    random ^= random >> 7;
                    random ^= random << 17;
                    *limb = match sample {
                        0 => 0x8080_8080_8080_8080,
                        1 => u64::MAX,
                        _ => random,
                    };
                }
                let first = if vex.vvvv == 0 {
                    [0; 64]
                } else {
                    ymm(&state, 2)
                };
                let model = apply(vex, ymm(&state, 1), first, ymm(&state, 3)).unwrap();
                native.run(&mut state, &mut ExecutionContext::default());
                assert_eq!(
                    ymm(&state, 1)[..32],
                    model[..32],
                    "{vex:x?} sample={sample}"
                );
                checked += 1;
            }
        }
        std::println!("MODELED_FORMS_CHECKED={checked}");
    }

    #[test]
    fn vex_fields_round_trip_through_their_encoding() {
        for (reg, vvvv, rm) in [(0, 0, 0), (1, 2, 3), (15, 9, 8), (8, 15, 15)] {
            for (pp, l) in [(0, false), (3, true), (2, false)] {
                let vex = Vex {
                    opcode: 0x50,
                    pp,
                    w: false,
                    l,
                    reg,
                    vvvv,
                    rm,
                };
                assert_eq!(Vex::decode(vex.encode()), Some(vex));
            }
        }
        // vpdpbssd xmm2, xmm0, xmm1 as the byte-dot lowering emits it.
        assert_eq!(
            Vex::decode([0xc4, 0xe2, 0x7b, 0x50, 0xd1]),
            Some(Vex {
                opcode: 0x50,
                pp: 3,
                w: false,
                l: false,
                reg: 2,
                vvvv: 0,
                rm: 1
            })
        );
    }
}
