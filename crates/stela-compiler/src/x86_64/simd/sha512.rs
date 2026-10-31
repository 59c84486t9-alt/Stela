//! SHA512: the SHA512 extension's rounds and message steps, else scalar
//! large sigmas and packed small sigmas.
use super::{Host, commit, packed, read_vector, shuffle, vector_offset};
use crate::x86_64::asm::{Alu, Code, Gpr, Map, Pp, Rm, ShiftOp, Size, Vex};
use crate::x86_64::simd::encode::guest;
use crate::{
    TargetCpu,
    aarch64::simd::sha512::{Kind, Operand},
    x86_64::isa::ShiftOpcode as Shift,
};

const QWORD_BITS: u8 = 64;
const QWORD_BYTES: u32 = 8;
const LOW: u32 = 0;
const HIGH: u32 = 1;
const SWAP_QWORDS: u8 = 0x4e;
const OLD_DESTINATION_XMM: u8 = 0;
const SECOND_SOURCE_XMM: u8 = 1;
const SIGMA_INPUT_XMM: u8 = 2;
const SIGMA_OUTPUT_XMM: u8 = 3;
const ROTATE_SCRATCH_XMM: u8 = 4;
const SECOND_ROTATE_XMM: u8 = 5;
const SMALL_SIGMA0_ROTATIONS: [u8; 2] = [1, 8];
const SMALL_SIGMA0_SHIFT: u8 = 7;
const SMALL_SIGMA1_ROTATIONS: [u8; 2] = [19, 61];
const SMALL_SIGMA1_SHIFT: u8 = 6;
const LARGE_SIGMA0_ROTATIONS: [u8; 3] = [28, 34, 39];
const LARGE_SIGMA1_ROTATIONS: [u8; 3] = [14, 18, 41];

// Only caller-saved registers; RDI remains the GuestState pointer.
const W0: Gpr = Gpr::Rax;
const W1: Gpr = Gpr::Rcx;
const X0: Gpr = Gpr::Rdx;
const X1: Gpr = Gpr::Rsi;
const Y0: Gpr = Gpr::R8;
const Y1: Gpr = Gpr::R9;
const VALUE: Gpr = Gpr::R10;
const SIGMA: Gpr = Gpr::R11;

/// Baseline 64-bit register/register instructions.
#[derive(Clone, Copy)]
enum QwordOpcode {
    Add,
    Or,
    And,
    Xor,
    Move,
}

impl QwordOpcode {
    fn emit(self, code: &mut Code, destination: Gpr, source: Gpr) {
        let mut asm = code.asm();
        let op = match self {
            Self::Add => Alu::Add,
            Self::Or => Alu::Or,
            Self::And => Alu::And,
            Self::Xor => Alu::Xor,
            Self::Move => return asm.mov(Size::Qword, destination, source),
        };
        asm.alu(op, Size::Qword, destination, source);
    }
}

fn state_qword(code: &mut Code, vector: u8, lane: u32, register: Gpr, load: bool) {
    let memory = guest(vector_offset(vector) + lane * QWORD_BYTES);
    if load {
        code.asm().mov_load(Size::Qword, register, memory);
    } else {
        code.asm().mov_store(Size::Qword, memory, register);
    }
}

fn rotate(code: &mut Code, destination: Gpr, amount: u8) {
    code.asm()
        .shift_imm(ShiftOp::Ror, Size::Qword, destination, amount);
}

fn large_sigma(
    code: &mut Code,
    destination: Gpr,
    source: Gpr,
    scratch: [Gpr; 2],
    rotations: [u8; 3],
) {
    // Independent rotates expose parallelism. Callers reuse dead inputs as
    // scratch, avoiding spills and extra CPU features.
    let [first, second] = scratch;
    let [low, middle, high] = rotations;
    QwordOpcode::Move.emit(code, destination, source);
    QwordOpcode::Move.emit(code, first, source);
    QwordOpcode::Move.emit(code, second, source);
    rotate(code, destination, low);
    rotate(code, first, middle);
    rotate(code, second, high);
    QwordOpcode::Xor.emit(code, destination, first);
    QwordOpcode::Xor.emit(code, destination, second);
}

fn choose(code: &mut Code, destination: Gpr, selector: Gpr, yes: Gpr, no: Gpr) {
    QwordOpcode::Move.emit(code, destination, yes);
    QwordOpcode::Xor.emit(code, destination, no);
    QwordOpcode::And.emit(code, destination, selector);
    QwordOpcode::Xor.emit(code, destination, no);
}

fn majority(code: &mut Code, destination: Gpr, scratch: Gpr, x: Gpr, y: Gpr, z: Gpr) {
    QwordOpcode::Move.emit(code, destination, x);
    QwordOpcode::And.emit(code, destination, y);
    QwordOpcode::Move.emit(code, scratch, x);
    QwordOpcode::Or.emit(code, scratch, y);
    QwordOpcode::And.emit(code, scratch, z);
    QwordOpcode::Or.emit(code, destination, scratch);
}

fn hash(code: &mut Code, operand: &Operand, second: bool) {
    let right = operand.right.expect("three-register SHA512 hash form");
    // Stage every needed qword before either destination store, so the high
    // result can be stored before the low one is computed even when all three
    // registers alias.
    for (vector, lane, register) in [
        (operand.destination, LOW, W0),
        (operand.destination, HIGH, W1),
        (operand.left, LOW, X0),
        (right, LOW, Y0),
        (right, HIGH, Y1),
    ] {
        state_qword(code, vector, lane, register, true);
    }
    if second {
        majority(code, VALUE, SIGMA, X0, Y1, Y0);
        // X0 is dead after majority; X1 is unused by the guest H2 form.
        large_sigma(code, SIGMA, Y0, [X0, X1], LARGE_SIGMA0_ROTATIONS);
    } else {
        state_qword(code, operand.left, HIGH, X1, true);
        choose(code, VALUE, Y1, X0, X1);
        // Use the old W1 before sigma so that its register and the dead X1 can
        // hold independent rotations.
        QwordOpcode::Add.emit(code, VALUE, W1);
        large_sigma(code, SIGMA, Y1, [X1, W1], LARGE_SIGMA1_ROTATIONS);
    }
    QwordOpcode::Add.emit(code, VALUE, SIGMA);
    if second {
        QwordOpcode::Add.emit(code, VALUE, W1);
    }
    state_qword(code, operand.destination, HIGH, VALUE, false);

    if second {
        large_sigma(code, SIGMA, VALUE, [X0, X1], LARGE_SIGMA0_ROTATIONS);
        // W1 and X0 are dead inputs. VALUE stays the sigma source until sigma
        // completes, then becomes the first majority operand.
        majority(code, W1, X0, VALUE, Y0, Y1);
        QwordOpcode::Add.emit(code, W1, SIGMA);
        QwordOpcode::Add.emit(code, W1, W0);
        state_qword(code, operand.destination, LOW, W1, false);
    } else {
        QwordOpcode::Add.emit(code, VALUE, Y0);
        choose(code, SIGMA, VALUE, Y1, X0);
        // Y0 is dead after forming VALUE, and X1 was consumed by the first Ch.
        large_sigma(code, W1, VALUE, [X1, Y0], LARGE_SIGMA1_ROTATIONS);
        QwordOpcode::Add.emit(code, SIGMA, W1);
        QwordOpcode::Add.emit(code, SIGMA, W0);
        state_qword(code, operand.destination, LOW, SIGMA, false);
    }
}

fn packed_rotate(code: &mut Code, destination: u8, scratch: u8, source: u8, amount: u8) {
    packed(code, Host::MoveAligned, destination, source);
    Shift::RightQword.emit(code, destination, amount);
    packed(code, Host::MoveAligned, scratch, source);
    Shift::LeftQword.emit(code, scratch, QWORD_BITS - amount);
    packed(code, Host::Or, destination, scratch);
}

fn small_sigma(code: &mut Code, rotations: [u8; 2], shift: u8) {
    // XMM2 holds both independent sigma inputs. XMM0/1 keep old W/Y.
    packed_rotate(
        code,
        SIGMA_OUTPUT_XMM,
        ROTATE_SCRATCH_XMM,
        SIGMA_INPUT_XMM,
        rotations[0],
    );
    packed_rotate(
        code,
        SECOND_ROTATE_XMM,
        ROTATE_SCRATCH_XMM,
        SIGMA_INPUT_XMM,
        rotations[1],
    );
    packed(code, Host::Xor, SIGMA_OUTPUT_XMM, SECOND_ROTATE_XMM);
    Shift::RightQword.emit(code, SIGMA_INPUT_XMM, shift);
    packed(code, Host::Xor, SIGMA_OUTPUT_XMM, SIGMA_INPUT_XMM);
}

/// The SHA512 extension's instructions and the AVX2 lane moves that place
/// their operands, on XMM/YMM registers 0..15 (Intel SDM Vol. 2).
#[derive(Clone, Copy)]
enum Avx {
    /// VPXOR: zero a register with itself.
    Xor,
    AddQword,
    SubtractQword,
    /// VPSHUFD with its control byte.
    ShuffleDword(u8),
    /// VPBLENDD: dword i from the second source where control bit i is set,
    /// else from the first.
    BlendDword(u8),
    /// VPALIGNR: the first source above the second, shifted right by bytes.
    AlignBytes(u8),
    /// VMOVQ: the low qword, the rest cleared.
    MoveQword,
    /// VINSERTI128: the first source with the second as its high lane.
    InsertHigh,
    /// VPERMQ: each result qword picks a source qword by two control bits.
    PermuteQwords(u8),
    /// VSHA512RNDS2: two rounds on state C, D, G, H (qwords 3, 2, 1, 0) and
    /// A, B, E, F in the first source, with K+W from the second's two low
    /// qwords; A, B, E, F of the result replace C, D, G, H.
    Rounds,
    /// VSHA512MSG1: each qword plus the small sigma0 of the next, with the
    /// source's qword 0 after qword 3.
    Message1,
    /// VSHA512MSG2: each qword plus the small sigma1 of the word two before
    /// it: the source's qwords 2 and 3, then the new qwords 0 and 1.
    Message2,
}

impl Avx {
    /// `destination` from `first` (VEX.vvvv; unused forms ignore it) and
    /// `second` (ModRM.rm).
    fn emit(self, code: &mut Code, destination: u8, first: u8, second: u8) {
        let (map, pp, w, l, opcode, immediate) = match self {
            Self::Xor => (Map::M0f, Pp::P66, false, false, 0xef, None),
            Self::AddQword => (Map::M0f, Pp::P66, false, false, 0xd4, None),
            Self::SubtractQword => (Map::M0f, Pp::P66, false, false, 0xfb, None),
            Self::ShuffleDword(control) => (Map::M0f, Pp::P66, false, false, 0x70, Some(control)),
            Self::MoveQword => (Map::M0f, Pp::Pf3, false, false, 0x7e, None),
            Self::BlendDword(control) => (Map::M0f3a, Pp::P66, false, false, 0x02, Some(control)),
            Self::AlignBytes(bytes) => (Map::M0f3a, Pp::P66, false, false, 0x0f, Some(bytes)),
            Self::InsertHigh => (Map::M0f3a, Pp::P66, false, true, 0x38, Some(1)),
            Self::PermuteQwords(control) => (Map::M0f3a, Pp::P66, true, true, 0x00, Some(control)),
            Self::Rounds => (Map::M0f38, Pp::Pf2, false, true, 0xcb, None),
            Self::Message1 => (Map::M0f38, Pp::Pf2, false, true, 0xcc, None),
            Self::Message2 => (Map::M0f38, Pp::Pf2, false, true, 0xcd, None),
        };
        let first = match self {
            Self::ShuffleDword(_)
            | Self::MoveQword
            | Self::PermuteQwords(_)
            | Self::Message1
            | Self::Message2 => 0,
            _ => first,
        };
        let mut asm = code.asm();
        asm.vex(
            Vex { map, pp, w, l },
            opcode,
            destination,
            first,
            Rm::Xmm(second),
        );
        if let Some(immediate) = immediate {
            asm.data(&[immediate]);
        }
    }
}

/// The SHA512 extension with AVX2 for its lane moves. The DIT profile keeps
/// the scalar recipe.
fn extension_supported(target: TargetCpu) -> bool {
    target.supports(TargetCpu::Sha512.with_avx2()) && !target.data_independent_timing()
}

// Extension recipe registers. Every guest operand is read before the store,
// so all aliases are safe.
const X: u8 = 0;
const Y: u8 = 1;
const W: u8 = 2;
const ZERO: u8 = 3;
const STATE: u8 = 4;
const SOURCE: u8 = 5;
/// VPERMQ controls moving qwords 1, 2 and 3, 2 to qwords 0, 1.
const QWORDS_1_2: u8 = 0x09;
const QWORDS_3_2: u8 = 0x0b;
/// VPBLENDD controls taking the high or low qword from the second source.
const HIGH_QWORD: u8 = 0x0c;
const LOW_QWORD: u8 = 0x03;

/// SHA512H and SHA512H2 as two VSHA512RNDS2 rounds whose inputs make each
/// Arm step one round, with X = Vn, Y = Vm and W = Vd.
///
/// SHA512H: T = Ch(e, f, g) + Sigma1(e) + W.hi with e = Y.hi, f = X.lo and
/// g = X.hi, then Ch(t, e, f) + Sigma1(t) + W.lo with t = T + Y.lo. With A, B,
/// C and H zero, round one's T1 is T and its new A is T (Maj and Sigma0 of
/// zeros vanish); D = Y.lo makes the new E t. Round two's H is g, so its K+W
/// is W.lo - g, and its D is the old C, zero: the new E is the low result and
/// the new B the high one.
///
/// SHA512H2: Maj(X.lo, Y.hi, Y.lo) + Sigma0(Y.lo) + W.hi, then Maj(u, Y.lo,
/// Y.hi) + Sigma0(u) + W.lo with u the first. With A = Y.lo, B = Y.hi, C =
/// X.lo and E to H zero, round one's T1 is W.hi and its new A is u. D = -W.hi
/// clears the new E, so round two's T1 is W.lo and its new A the low result.
fn extension_hash(code: &mut Code, operand: &Operand, second: bool) {
    let right = operand.right.expect("three-register SHA512 hash form");
    read_vector(code, operand.left, X);
    read_vector(code, right, Y);
    read_vector(code, operand.destination, W);
    Avx::Xor.emit(code, ZERO, ZERO, ZERO);
    if second {
        Avx::ShuffleDword(SWAP_QWORDS).emit(code, Y, 0, Y);
        Avx::InsertHigh.emit(code, SOURCE, ZERO, Y); // [0, 0, Y.hi, Y.lo]
        Avx::SubtractQword.emit(code, STATE, ZERO, W);
        Avx::AlignBytes(QWORD_BYTES as u8).emit(code, STATE, X, STATE); // [-W.hi, X.lo]
        Avx::InsertHigh.emit(code, STATE, ZERO, STATE); // [0, 0, -W.hi, X.lo]
        Avx::ShuffleDword(SWAP_QWORDS).emit(code, W, 0, W); // [W.hi, W.lo]
    } else {
        Avx::BlendDword(HIGH_QWORD).emit(code, SOURCE, X, Y); // [X.lo, Y.hi, 0, 0]
        Avx::BlendDword(LOW_QWORD).emit(code, STATE, X, ZERO); // [0, X.hi]
        Avx::ShuffleDword(SWAP_QWORDS).emit(code, W, 0, W);
        Avx::SubtractQword.emit(code, W, W, STATE); // [W.hi, W.lo - X.hi]
        Avx::MoveQword.emit(code, Y, 0, Y);
        Avx::InsertHigh.emit(code, STATE, STATE, Y); // [0, X.hi, Y.lo, 0]
    }
    Avx::Rounds.emit(code, STATE, SOURCE, W);
    let result = if second { QWORDS_3_2 } else { QWORDS_1_2 };
    Avx::PermuteQwords(result).emit(code, STATE, 0, STATE);
    code.asm().vzeroupper();
    commit(code, operand.destination, STATE);
}

/// SHA512SU0 is VSHA512MSG1's low lane over [Vd, Vn]; SHA512SU1 is
/// VSHA512MSG2's low lane over Vd + Vm with Vn as its words two before.
fn extension_schedule(code: &mut Code, operand: &Operand) {
    read_vector(code, operand.destination, W);
    read_vector(code, operand.left, X);
    match operand.right {
        None => {
            Avx::InsertHigh.emit(code, W, W, X);
            Avx::Message1.emit(code, W, 0, X);
        }
        Some(right) => {
            read_vector(code, right, Y);
            Avx::AddQword.emit(code, W, W, Y);
            Avx::InsertHigh.emit(code, X, X, X);
            Avx::Message2.emit(code, W, 0, X);
        }
    }
    code.asm().vzeroupper();
    commit(code, operand.destination, W);
}

pub(super) fn emit(code: &mut Code, operand: &Operand, target: TargetCpu) {
    if extension_supported(target) {
        match operand.kind {
            Kind::Hash | Kind::Hash2 => extension_hash(code, operand, operand.kind == Kind::Hash2),
            Kind::Schedule0 | Kind::Schedule1 => extension_schedule(code, operand),
        }
        return;
    }
    match operand.kind {
        Kind::Hash | Kind::Hash2 => hash(code, operand, operand.kind == Kind::Hash2),
        Kind::Schedule0 => {
            read_vector(code, operand.destination, OLD_DESTINATION_XMM);
            read_vector(code, operand.left, SECOND_SOURCE_XMM);
            shuffle(code, SIGMA_INPUT_XMM, OLD_DESTINATION_XMM, SWAP_QWORDS);
            packed(
                code,
                Host::UnpackLowQword,
                SIGMA_INPUT_XMM,
                SECOND_SOURCE_XMM,
            ); // [old W1, old X0]
            small_sigma(code, SMALL_SIGMA0_ROTATIONS, SMALL_SIGMA0_SHIFT);
            packed(code, Host::AddQword, OLD_DESTINATION_XMM, SIGMA_OUTPUT_XMM);
            commit(code, operand.destination, OLD_DESTINATION_XMM);
        }
        Kind::Schedule1 => {
            read_vector(code, operand.destination, OLD_DESTINATION_XMM);
            read_vector(
                code,
                operand.right.expect("three-register SHA512SU1 form"),
                SECOND_SOURCE_XMM,
            );
            read_vector(code, operand.left, SIGMA_INPUT_XMM);
            small_sigma(code, SMALL_SIGMA1_ROTATIONS, SMALL_SIGMA1_SHIFT);
            packed(code, Host::AddQword, OLD_DESTINATION_XMM, SECOND_SOURCE_XMM);
            packed(code, Host::AddQword, OLD_DESTINATION_XMM, SIGMA_OUTPUT_XMM);
            commit(code, operand.destination, OLD_DESTINATION_XMM);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        GuestState, context::ExecutionContext, x86_64::asm::vector_extensions::execution::Native,
    };

    // Literal Arm pseudocode for each instruction (Arm ARM C7.2), with
    // W = Vd, X = Vn and Y = Vm as [low, high].
    fn reference(kind: Kind, w: [u64; 2], x: [u64; 2], y: [u64; 2]) -> [u64; 2] {
        let large0 = |v: u64| v.rotate_right(28) ^ v.rotate_right(34) ^ v.rotate_right(39);
        let large1 = |v: u64| v.rotate_right(14) ^ v.rotate_right(18) ^ v.rotate_right(41);
        let small0 = |v: u64| v.rotate_right(1) ^ v.rotate_right(8) ^ v >> 7;
        let small1 = |v: u64| v.rotate_right(19) ^ v.rotate_right(61) ^ v >> 6;
        match kind {
            Kind::Hash => {
                let high = (y[1] & x[0] ^ !y[1] & x[1])
                    .wrapping_add(large1(y[1]))
                    .wrapping_add(w[1]);
                let t = high.wrapping_add(y[0]);
                let low = (t & y[1] ^ !t & x[0])
                    .wrapping_add(large1(t))
                    .wrapping_add(w[0]);
                [low, high]
            }
            Kind::Hash2 => {
                let high = (x[0] & y[1] | (x[0] | y[1]) & y[0])
                    .wrapping_add(large0(y[0]))
                    .wrapping_add(w[1]);
                let low = (high & y[0] | (high | y[0]) & y[1])
                    .wrapping_add(large0(high))
                    .wrapping_add(w[0]);
                [low, high]
            }
            Kind::Schedule0 => [
                w[0].wrapping_add(small0(w[1])),
                w[1].wrapping_add(small0(x[0])),
            ],
            Kind::Schedule1 => {
                core::array::from_fn(|i| w[i].wrapping_add(small1(x[i])).wrapping_add(y[i]))
            }
        }
    }

    #[test]
    fn both_recipes_match_the_arm_pseudocode_under_all_alias_partitions() {
        let host = crate::x86_64::modeled::host();
        let mut cases = 0;
        let mut random = 0x6a09_e667_f3bc_c908_u64;
        for target in [TargetCpu::X86_64_V2, TargetCpu::X86_64_V3.with_sha512()] {
            if !host.supports(target) {
                continue;
            }
            // The five equality partitions of three roles, plus V31 as data.
            for destination in [0, 31] {
                for left in [destination, 1] {
                    for right in [destination, left, 2] {
                        for kind in [Kind::Hash, Kind::Hash2, Kind::Schedule0, Kind::Schedule1] {
                            let operand = Operand {
                                kind,
                                destination,
                                left,
                                right: (kind != Kind::Schedule0).then_some(right),
                            };
                            let mut code = Code::new();
                            emit(&mut code, &operand, target);
                            code.asm().ret();
                            let native = Native::new(&code);
                            for sample in 0..64 {
                                let mut state = GuestState {
                                    nzcv: 0xa000_0000,
                                    fpsr: 0x0800_001f,
                                    fpcr: 0x1234,
                                    ..GuestState::default()
                                };
                                for limb in state.v.as_flattened_mut() {
                                    random ^= random << 13;
                                    random ^= random >> 7;
                                    random ^= random << 17;
                                    *limb = match sample {
                                        0 => 0,
                                        1 => u64::MAX,
                                        2 => 0x8000_0000_0000_0001,
                                        _ => random,
                                    };
                                }
                                state.x =
                                    core::array::from_fn(|i| random.wrapping_mul(i as u64 + 1));
                                let mut expected = state.clone();
                                expected.v[usize::from(destination)] = reference(
                                    kind,
                                    state.v[usize::from(destination)],
                                    state.v[usize::from(left)],
                                    state.v[usize::from(right)],
                                );
                                native.run(&mut state, &mut ExecutionContext::default());
                                assert_eq!(
                                    state, expected,
                                    "{target:?} {operand:?} sample={sample}"
                                );
                                cases += 1;
                            }
                        }
                    }
                }
            }
        }
        std::println!("SHA512_NATIVE_CASES={cases}");
    }

    #[test]
    fn extension_recipes_match_gnu_encodings() {
        let mut code = Code::new();
        Avx::Rounds.emit(&mut code, 1, 2, 3);
        Avx::Message1.emit(&mut code, 1, 7, 3);
        Avx::Message2.emit(&mut code, 1, 7, 3);
        Avx::InsertHigh.emit(&mut code, 1, 2, 3);
        Avx::PermuteQwords(0x0b).emit(&mut code, 1, 7, 2);
        Avx::AlignBytes(8).emit(&mut code, 1, 2, 3);
        Avx::BlendDword(0x0c).emit(&mut code, 1, 2, 3);
        Avx::SubtractQword.emit(&mut code, 1, 2, 3);
        Avx::AddQword.emit(&mut code, 1, 2, 3);
        Avx::ShuffleDword(0x4e).emit(&mut code, 1, 7, 2);
        Avx::Xor.emit(&mut code, 1, 1, 1);
        Avx::MoveQword.emit(&mut code, 1, 7, 2);
        // GNU as 2.42.
        assert_eq!(
            code,
            [
                &[0xc4, 0xe2, 0x6f, 0xcb, 0xcb][..], // vsha512rnds2 ymm1,ymm2,xmm3
                &[0xc4, 0xe2, 0x7f, 0xcc, 0xcb],     // vsha512msg1 ymm1,xmm3
                &[0xc4, 0xe2, 0x7f, 0xcd, 0xcb],     // vsha512msg2 ymm1,ymm3
                &[0xc4, 0xe3, 0x6d, 0x38, 0xcb, 0x01], // vinserti128 ymm1,ymm2,xmm3,1
                &[0xc4, 0xe3, 0xfd, 0x00, 0xca, 0x0b], // vpermq ymm1,ymm2,0xb
                &[0xc4, 0xe3, 0x69, 0x0f, 0xcb, 0x08], // vpalignr xmm1,xmm2,xmm3,8
                &[0xc4, 0xe3, 0x69, 0x02, 0xcb, 0x0c], // vpblendd xmm1,xmm2,xmm3,0xc
                &[0xc5, 0xe9, 0xfb, 0xcb],           // vpsubq xmm1,xmm2,xmm3
                &[0xc5, 0xe9, 0xd4, 0xcb],           // vpaddq xmm1,xmm2,xmm3
                &[0xc5, 0xf9, 0x70, 0xca, 0x4e],     // vpshufd xmm1,xmm2,0x4e
                &[0xc5, 0xf1, 0xef, 0xc9],           // vpxor xmm1,xmm1,xmm1
                &[0xc5, 0xfa, 0x7e, 0xca],           // vmovq xmm1,xmm2
            ]
            .concat()
        );
    }

    #[test]
    fn scoped_qword_encodings_keep_rex_operand_roles_and_state_base() {
        let mut code = Code::new();
        QwordOpcode::Move.emit(&mut code, Gpr::R10, Gpr::Rdx);
        QwordOpcode::And.emit(&mut code, Gpr::R10, Gpr::R9);
        rotate(&mut code, Gpr::R11, 23);
        state_qword(&mut code, 31, HIGH, Gpr::R9, true);
        state_qword(&mut code, 31, LOW, Gpr::R10, false);
        let high = (vector_offset(31) + QWORD_BYTES).to_le_bytes();
        let low = vector_offset(31).to_le_bytes();
        assert_eq!(
            code,
            [
                &[0x49, 0x89, 0xd2][..], // mov r10,rdx
                &[0x4d, 0x21, 0xca],     // and r10,r9
                &[0x49, 0xc1, 0xcb, 23], // ror r11,23
                &[0x4c, 0x8b, 0x8f],
                &high,
                &[0x4c, 0x89, 0x97],
                &low,
            ]
            .concat()
        );
    }
}
