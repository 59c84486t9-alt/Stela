//! Shared ZA state-bank access for the extended native ABI.
//!
//! R15 holds the validated ExecutionContext. The caller owns ZA availability,
//! row/column selection, modulo arithmetic and bounds. These helpers expose no
//! guest RAM access and never reinterpret ZA tiles or physical-vector aliases.

use super::isa::SimdOpcode as Host;
use crate::{
    TargetCpu,
    context::{EXECUTION_CONTEXT_SCALABLE_OFFSET, SCALABLE_ZA_OFFSET},
};

const XMM_REGISTER_COUNT: u8 = 8;
const REX_R8_BASE: u8 = 0x41;
const MODRM_DISP32_R8: u8 = 0x80;
const REGISTER_SHIFT: u8 = 3;
const MOV_R8_CONTEXT_DISP8: &[u8] = &[0x4d, 0x8b, 0x47];
const MOV_R8_R8_DISP8: &[u8] = &[0x4d, 0x8b, 0x40];

/// Load the ZA bank base into R8. Every other GPR/XMM and host flag survives.
/// The runtime must have validated a live scalable view and ZA allocation.
pub(crate) fn load_za_pointer_r8(code: &mut Vec<u8>) {
    // Versioned pointer fields fit a positive signed disp8.
    debug_assert!(EXECUTION_CONTEXT_SCALABLE_OFFSET <= i8::MAX as u32);
    debug_assert!(SCALABLE_ZA_OFFSET <= i8::MAX as u32);
    code.extend(MOV_R8_CONTEXT_DISP8);
    code.push(EXECUTION_CONTEXT_SCALABLE_OFFSET as u8);
    code.extend(MOV_R8_R8_DISP8);
    code.push(SCALABLE_ZA_OFFSET as u8);
}

fn chunk_memory(
    code: &mut Vec<u8>,
    opcode: Host,
    register: u8,
    displacement: u32,
    target: TargetCpu,
) {
    assert!(register < XMM_REGISTER_COUNT, "ZA helper requires XMM0..7");
    assert!(
        displacement <= i32::MAX as u32,
        "ZA displacement must be positive disp32"
    );
    assert!(target.supports(opcode.requires()));
    // MOVDQU's mandatory F3 prefix precedes REX.B for the R8 memory base.
    let encoding = opcode.encoding();
    code.push(encoding[0]);
    code.push(REX_R8_BASE);
    code.extend(&encoding[1..]);
    code.push(MODRM_DISP32_R8 | (register << REGISTER_SHIFT));
    code.extend(displacement.to_le_bytes());
}

/// Read exactly 16 unaligned bytes at R8+displacement into the chosen XMM.
/// Preserves R8, every other GPR/XMM and host flags. The caller may first add a
/// validated dynamic row offset to R8; displacement is relative to that base.
pub(crate) fn load_za_chunk_at_r8(
    code: &mut Vec<u8>,
    destination: u8,
    displacement: u32,
    target: TargetCpu,
) {
    chunk_memory(code, Host::LoadUnaligned, destination, displacement, target);
}

/// Write exactly 16 unaligned bytes from the chosen XMM at R8+displacement.
/// Preserves every GPR/XMM and host flags. The caller stages aliased sources
/// before invoking stores when an instruction requires simultaneous results.
pub(crate) fn store_za_chunk_at_r8(
    code: &mut Vec<u8>,
    source: u8,
    displacement: u32,
    target: TargetCpu,
) {
    chunk_memory(code, Host::StoreUnaligned, source, displacement, target);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_chase_uses_the_shared_context_contract() {
        let mut code = Vec::new();
        load_za_pointer_r8(&mut code);
        assert_eq!(code, [0x4d, 0x8b, 0x47, 16, 0x4d, 0x8b, 0x40, 56]);
    }

    #[test]
    fn rex_base_follows_mandatory_simd_prefix() {
        for register in 0..XMM_REGISTER_COUNT {
            let mut load = Vec::new();
            load_za_chunk_at_r8(&mut load, register, 0x1234, TargetCpu::Baseline);
            assert_eq!(load[..5], [0xf3, 0x41, 0x0f, 0x6f, 0x80 | register << 3]);
            assert_eq!(load[5..], 0x1234u32.to_le_bytes());
            let mut store = Vec::new();
            store_za_chunk_at_r8(&mut store, register, 0x5678, TargetCpu::Baseline);
            assert_eq!(store[..5], [0xf3, 0x41, 0x0f, 0x7f, 0x80 | register << 3]);
            assert_eq!(store[5..], 0x5678u32.to_le_bytes());
        }
    }
}
