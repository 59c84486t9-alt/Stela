//! Three-operand recipe steps: the VEX.128 form of a catalog opcode where
//! the target has usable AVX state, otherwise the SSE form after a copy. VEX
//! saves the MOVDQA that a destructive SSE operation needs to keep a source.
//! None of these touches EFLAGS, MXCSR or memory.
use super::{Host, packed};
use crate::TargetCpu;
use crate::x86_64::asm::{Code, Gpr, Map, Pp, Rm, Vex};
use crate::x86_64::isa::{ShiftOpcode as Shift, SimdOpcode};

/// Whether recipes use VEX three-operand forms on `target`: AVX2 hosts
/// (whose probe includes OS-enabled AVX state). The DIT profile keeps its
/// reviewed SSE recipes.
pub(super) fn vex(target: TargetCpu) -> bool {
    target.supports(TargetCpu::Avx2) && !target.data_independent_timing()
}

/// The VEX prefix fields and opcode byte of a legacy `66 0F [38|3A] op`
/// encoding.
fn vex_form(opcode: SimdOpcode) -> (Map, u8) {
    match *opcode.encoding() {
        [0x66, 0x0f, 0x38, byte] => (Map::M0f38, byte),
        [0x66, 0x0f, 0x3a, byte] => (Map::M0f3a, byte),
        [0x66, 0x0f, byte] => (Map::M0f, byte),
        _ => unreachable!("{} has no 66-prefixed VEX.128 form", opcode.mnemonic()),
    }
}

const fn vex128(map: Map) -> Vex {
    Vex {
        map,
        pp: Pp::P66,
        w: false,
        l: false,
    }
}

/// `destination = left op right`. Without VEX, `destination` must not be
/// `right` unless it is also `left`.
pub(super) fn three(
    code: &mut Code,
    opcode: SimdOpcode,
    destination: u8,
    left: u8,
    right: u8,
    target: TargetCpu,
) {
    if vex(target) {
        let (map, byte) = vex_form(opcode);
        code.asm()
            .vex(vex128(map), byte, destination, left, Rm::Xmm(right));
        return;
    }
    assert!(
        destination == left || destination != right,
        "a destructive form would overwrite its right source"
    );
    if destination != left {
        packed(code, Host::MoveAligned, destination, left);
    }
    opcode.register(code, destination, right, target);
}

/// `destination = source` shifted by `amount` (VPSLL/VPSRL/VPSRA by
/// immediate: VEX.vvvv names the destination).
pub(super) fn shift(
    code: &mut Code,
    opcode: Shift,
    destination: u8,
    source: u8,
    amount: u8,
    target: TargetCpu,
) {
    if vex(target) {
        let mut asm = code.asm();
        asm.vex(
            vex128(Map::M0f),
            opcode.opcode(),
            opcode.group(),
            destination,
            Rm::Xmm(source),
        );
        asm.data(&[amount]);
        return;
    }
    if destination != source {
        packed(code, Host::MoveAligned, destination, source);
    }
    opcode.emit(code, destination, amount);
}

/// Whether [`dot_words`] accumulates on `target`: AVX-VNNI, or AVX-512 VNNI
/// with VL. The DIT profile keeps its reviewed recipe.
pub(super) fn dot_words_supported(target: TargetCpu) -> bool {
    (target.supports(TargetCpu::AvxVnni)
        || target.supports(TargetCpu::Avx512f.with_avx512vl().with_avx512vnni()))
        && !target.data_independent_timing()
}

/// VPDPWSSD: each dword of `sum` plus the two signed word products of the
/// matching dwords of `left` and `right`, wrapping (no saturation).
pub(super) fn dot_words(code: &mut Code, sum: u8, left: u8, right: u8, target: TargetCpu) {
    assert!(dot_words_supported(target), "VPDPWSSD needs VNNI");
    const VPDPWSSD: u8 = 0x52;
    if target.supports(TargetCpu::AvxVnni) {
        code.asm()
            .vex(vex128(Map::M0f38), VPDPWSSD, sum, left, Rm::Xmm(right));
    } else {
        code.asm().evex(
            crate::x86_64::asm::Evex {
                map: Map::M0f38,
                pp: Pp::P66,
                w: false,
                length: 0,
                mask: 0,
                zeroing: false,
                broadcast: false,
                scale: 16,
            },
            VPDPWSSD,
            sum,
            left,
            Rm::Xmm(right),
        );
    }
}

/// VPBROADCASTW: word 0 of `source` in every word of `destination` (AVX2).
pub(super) fn broadcast_word(code: &mut Code, destination: u8, source: u8) {
    broadcast(code, 2, destination, Rm::Xmm(source));
}

/// VPBROADCASTB/W/D/Q (AVX2): the low `lane`-byte element of `source`, a
/// register or memory, in every lane of `destination`. A memory source
/// reads exactly `lane` bytes.
pub(super) fn broadcast(code: &mut Code, lane: u8, destination: u8, source: Rm) {
    let opcode = match lane {
        1 => 0x78,
        2 => 0x79,
        4 => 0x58,
        8 => 0x59,
        _ => unreachable!("lane of 1, 2, 4 or 8 bytes"),
    };
    code.asm()
        .vex(vex128(Map::M0f38), opcode, destination, 0, source);
}
/// Whether ZF after [`test_zero`] says every bit of the register is zero:
/// PTEST, SSE4.1.
pub(super) fn test_zero_supported(target: TargetCpu) -> bool {
    target.supports(TargetCpu::Sse41)
}

/// PTEST `xmm`, `xmm` (VPTEST with VEX): ZF = `xmm` is zero. Writes EFLAGS.
pub(super) fn test_zero(code: &mut Code, xmm: u8, target: TargetCpu) {
    const PTEST: u8 = 0x17;
    if vex(target) {
        code.asm()
            .vex(vex128(Map::M0f38), PTEST, xmm, 0, Rm::Xmm(xmm));
    } else {
        assert!(test_zero_supported(target), "PTEST needs SSE4.1");
        code.asm()
            .sse(Some(0x66), &[0x0f, 0x38, PTEST], xmm, Rm::Xmm(xmm));
    }
}

/// Whether [`broadcast_general`] runs on `target`: AVX-512 F with VL. The DIT
/// profile keeps its reviewed constant loads.
pub(super) fn broadcast_general_supported(target: TargetCpu) -> bool {
    target.supports(TargetCpu::Avx512f.with_avx512vl()) && !target.data_independent_timing()
}

/// EVEX VPBROADCASTD/Q xmm, r32/r64: the low dword (or qword) of `source`
/// in every lane of `destination`.
pub(super) fn broadcast_general(code: &mut Code, destination: u8, source: Gpr, qword: bool) {
    const VPBROADCAST_GPR: u8 = 0x7c;
    code.asm().evex(
        crate::x86_64::asm::Evex {
            map: Map::M0f38,
            pp: Pp::P66,
            w: qword,
            length: 0,
            mask: 0,
            zeroing: false,
            broadcast: false,
            scale: 1,
        },
        VPBROADCAST_GPR,
        destination,
        0,
        Rm::Reg(source),
    );
}
