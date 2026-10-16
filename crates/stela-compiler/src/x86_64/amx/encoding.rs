//! The VEX and EVEX forms the AMX kernels use (Intel SDM Vol. 2, sections 2.3
//! and 2.7). Operands are named registers and base+displacement memory; no
//! index registers are needed.

/// General-purpose register numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gpr {
    Rax = 0,
    Rdx = 2,
    Rsp = 4,
    Rsi = 6,
    Rdi = 7,
}

/// `[base + displacement]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Memory {
    pub base: Gpr,
    pub displacement: i32,
}

pub(crate) const fn at(base: Gpr, displacement: i32) -> Memory {
    Memory { base, displacement }
}

/// Opcode maps.
#[derive(Clone, Copy)]
pub(crate) enum Map {
    Primary = 1,
    Escape38 = 2,
    Escape3a = 3,
}

/// Implied mandatory prefixes.
#[derive(Clone, Copy)]
pub(crate) enum Prefix {
    None = 0,
    OperandSize = 1,
}

/// The register-or-memory operand.
#[derive(Clone, Copy)]
pub(crate) enum Operand {
    Register(u8),
    Memory(Memory),
}

/// ModRM, SIB and displacement for `reg` and `rm`. `scale` is the EVEX
/// disp8*N factor (1 for VEX and legacy encodings). RBP is never a base, so
/// mod 00 always means no displacement.
fn modrm(code: &mut alloc::vec::Vec<u8>, reg: u8, rm: Operand, scale: i32) {
    match rm {
        Operand::Register(register) => code.push(0xc0 | ((reg & 7) << 3) | (register & 7)),
        Operand::Memory(Memory { base, displacement }) => {
            let base = base as u8;
            let short = (displacement % scale == 0)
                .then_some(displacement / scale)
                .and_then(|value| i8::try_from(value).ok());
            let mode = match (displacement, short) {
                (0, _) => 0,
                (_, Some(_)) => 1,
                _ => 2,
            };
            code.push((mode << 6) | ((reg & 7) << 3) | (base & 7));
            if base & 7 == Gpr::Rsp as u8 {
                // SIB: no index, base RSP.
                code.push(0x24);
            }
            match (mode, short) {
                (1, Some(value)) => code.push(value as u8),
                (2, _) => code.extend(displacement.to_le_bytes()),
                _ => {}
            }
        }
    }
}

/// Three-byte VEX: C4, RXB.mmmmm, W.vvvv.L.pp, opcode, ModRM.
#[allow(clippy::too_many_arguments)]
pub(crate) fn vex(
    code: &mut alloc::vec::Vec<u8>,
    map: Map,
    prefix: Prefix,
    wide: bool,
    long: bool,
    opcode: u8,
    reg: u8,
    source: u8,
    rm: Operand,
) {
    let rm_high = match rm {
        Operand::Register(register) => register >> 3,
        Operand::Memory(memory) => memory.base as u8 >> 3,
    };
    debug_assert!(reg < 16 && source < 16);
    code.push(0xc4);
    code.push(((!reg >> 3) & 1) << 7 | 1 << 6 | ((!rm_high) & 1) << 5 | map as u8);
    code.push(u8::from(wide) << 7 | ((!source) & 15) << 3 | u8::from(long) << 2 | prefix as u8);
    code.push(opcode);
    modrm(code, reg, rm, 1);
}

/// EVEX.512: 62, P0 (R X B R' 0 0 mm), P1 (W vvvv 1 pp), P2 (z L'L b V' aaa).
#[allow(clippy::too_many_arguments)]
pub(crate) fn evex(
    code: &mut alloc::vec::Vec<u8>,
    map: Map,
    prefix: Prefix,
    wide: bool,
    opcode: u8,
    reg: u8,
    source: u8,
    rm: Operand,
    broadcast: bool,
    mask: u8,
) {
    let (rm_high, scale) = match rm {
        Operand::Register(register) => (register >> 3, 1),
        Operand::Memory(memory) => (
            memory.base as u8 >> 3,
            if broadcast {
                if wide { 8 } else { 4 }
            } else {
                64
            },
        ),
    };
    debug_assert!(reg < 32 && source < 32 && mask < 8);
    debug_assert!(matches!(rm, Operand::Memory(_)) || !broadcast);
    let rm_extended = match rm {
        // EVEX.X extends a register rm to 16..31.
        Operand::Register(register) => (register >> 4) & 1,
        Operand::Memory(_) => 0,
    };
    code.push(0x62);
    code.push(
        ((!reg >> 3) & 1) << 7
            | ((!rm_extended) & 1) << 6
            | ((!rm_high) & 1) << 5
            | ((!reg >> 4) & 1) << 4
            | map as u8,
    );
    code.push(u8::from(wide) << 7 | ((!source) & 15) << 3 | 1 << 2 | prefix as u8);
    // L'L = 10 selects 512 bits.
    code.push(2 << 5 | u8::from(broadcast) << 4 | ((!source >> 4) & 1) << 3 | mask);
    code.push(opcode);
    modrm(code, reg, rm, scale);
}

/// A legacy-encoded `opcode /digit` with a memory operand, such as LDMXCSR.
pub(crate) fn legacy_memory(
    code: &mut alloc::vec::Vec<u8>,
    opcode: &[u8],
    digit: u8,
    memory: Memory,
) {
    code.extend(opcode);
    modrm(code, digit, Operand::Memory(memory), 1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn memory_forms_use_sib_for_rsp_and_compress_evex_displacements() {
        let mut code = Vec::new();
        // ldmxcsr [rsp]; stmxcsr [rsp+4]
        legacy_memory(&mut code, &[0x0f, 0xae], 2, at(Gpr::Rsp, 0));
        legacy_memory(&mut code, &[0x0f, 0xae], 3, at(Gpr::Rsp, 4));
        assert_eq!(code, [0x0f, 0xae, 0x14, 0x24, 0x0f, 0xae, 0x5c, 0x24, 0x04]);
    }
}
