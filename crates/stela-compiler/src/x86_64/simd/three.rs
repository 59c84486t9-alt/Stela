//! Three-operand recipe steps: the VEX.128 form of a catalog opcode where
//! the target has usable AVX state, otherwise the SSE form after a copy. VEX
//! saves the MOVDQA that a destructive SSE operation needs to keep a source.
//! None of these touches EFLAGS, MXCSR or memory.
use super::{Host, packed};
use crate::TargetCpu;
use crate::x86_64::asm::{Code, Map, Pp, Rm, Vex};
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
    const VPBROADCASTW: u8 = 0x79;
    code.asm().vex(
        vex128(Map::M0f38),
        VPBROADCASTW,
        destination,
        0,
        Rm::Xmm(source),
    );
}
