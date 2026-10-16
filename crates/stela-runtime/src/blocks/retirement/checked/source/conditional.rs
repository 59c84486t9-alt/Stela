//! Validate a reached conditional carrier against ORIGINAL source and actual
//! post-prefix state. The terminal branch changes neither its tested GPR nor
//! NZCV, so the same state determines its architectural predicate after return.
use stela_compiler::{
    GuestAddress, GuestState, Lifter,
    aarch64::{Decoder, Operation, Register, Width, flags::condition_holds},
    block::{BlockAnalysis, ExitKind, SuccessorKind},
};

/// None denotes a source without a conditional terminal. This function grants
/// no entry, PE, retirement, source generation, memory or replay authority.
pub(super) fn validate(
    analysis: &BlockAnalysis,
    source: &[u8],
    entry: GuestAddress,
    registers: &GuestState,
    kind: ExitKind,
    next: GuestAddress,
) -> anyhow::Result<Option<()>> {
    // The block parser owns special terminal encodings such as BL. Its
    // rechecked immutable analysis must identify a conditional source before
    // the ordinary instruction decoder is called. Decode errors on an actual
    // conditional source remain errors, never a generic fallback.
    let has_target = analysis
        .static_successors
        .iter()
        .any(|edge| edge.kind == SuccessorKind::ConditionalTarget);
    let has_fallthrough = analysis
        .static_successors
        .iter()
        .any(|edge| edge.kind == SuccessorKind::ConditionalFallthrough);
    if !has_target && !has_fallthrough {
        return Ok(None);
    }
    anyhow::ensure!(
        has_target && has_fallthrough && analysis.dynamic_edge.is_none(),
        "conditional source analysis classes differ"
    );
    let pc = analysis
        .terminator_pc
        .ok_or_else(|| anyhow::anyhow!("conditional source terminal absent"))?;
    let offset = usize::try_from(
        pc.0.checked_sub(entry.0)
            .ok_or_else(|| anyhow::anyhow!("conditional terminal precedes source"))?,
    )?;
    let bytes = source
        .get(
            offset
                ..offset
                    .checked_add(size_of::<u32>())
                    .ok_or_else(|| anyhow::anyhow!("conditional terminal extent overflow"))?,
        )
        .ok_or_else(|| anyhow::anyhow!("conditional terminal source absent"))?;
    let word = u32::from_le_bytes(bytes.try_into()?);
    let instruction = Decoder
        .lift(pc, word)
        .map_err(|error| anyhow::anyhow!("conditional terminal decode: {error:?}"))?;
    let (target, taken) = match instruction.operation {
        Operation::BranchCondition { target, condition } => {
            anyhow::ensure!(condition < 16, "conditional source condition differs");
            (target, condition_holds(condition, registers.nzcv))
        }
        Operation::BranchZero {
            target,
            source,
            width,
            nonzero,
        } => {
            let value = read_register(registers, source)?;
            let is_nonzero = match width {
                Width::W32 => value as u32 != 0,
                Width::X64 => value != 0,
            };
            (target, is_nonzero == nonzero)
        }
        Operation::BranchBit {
            target,
            source,
            bit,
            nonzero,
        } => {
            anyhow::ensure!(bit < u64::BITS as u8, "conditional source bit differs");
            let set = read_register(registers, source)? & (1u64 << bit) != 0;
            (target, set == nonzero)
        }
        _ => anyhow::bail!("conditional analysis claims a nonconditional source"),
    };
    let (expected_pc, expected_kind, expected_edge) = if taken {
        (target, ExitKind::Direct, SuccessorKind::ConditionalTarget)
    } else {
        (
            GuestAddress(
                pc.0.checked_add(size_of::<u32>() as u64)
                    .ok_or_else(|| anyhow::anyhow!("conditional continuation overflow"))?,
            ),
            ExitKind::Fallthrough,
            SuccessorKind::ConditionalFallthrough,
        )
    };
    anyhow::ensure!(
        analysis
            .static_successors
            .iter()
            .any(|edge| edge.target == expected_pc && edge.kind == expected_edge),
        "conditional source analysis edge differs"
    );
    anyhow::ensure!(
        kind == expected_kind && next == expected_pc,
        "conditional carrier contradicts actual predicate or source successor"
    );
    Ok(Some(()))
}

fn read_register(registers: &GuestState, register: Register) -> anyhow::Result<u64> {
    match register {
        Register::X(index) => registers
            .x
            .get(usize::from(index))
            .copied()
            .ok_or_else(|| anyhow::anyhow!("conditional register outside actual bank")),
        Register::Zero => Ok(0),
        Register::Sp => anyhow::bail!("conditional source cannot test SP"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::{
        aarch64::flags::NZCV_Z,
        block::{BlockProfile, analyze_with_profile},
    };

    const BASE: GuestAddress = GuestAddress(0x1000);

    fn check(word: u32, registers: &GuestState, taken: bool) {
        let source = word.to_le_bytes();
        let analysis = analyze_with_profile(&source, BASE, BlockProfile::Ordinary).unwrap();
        let target = if taken {
            GuestAddress(0x1008)
        } else {
            GuestAddress(0x1004)
        };
        let kind = if taken {
            ExitKind::Direct
        } else {
            ExitKind::Fallthrough
        };
        assert!(
            validate(&analysis, &source, BASE, registers, kind, target)
                .unwrap()
                .is_some()
        );
        let wrong_kind = if taken {
            ExitKind::Fallthrough
        } else {
            ExitKind::Direct
        };
        assert!(validate(&analysis, &source, BASE, registers, wrong_kind, target).is_err());
        assert!(
            validate(
                &analysis,
                &source,
                BASE,
                registers,
                kind,
                GuestAddress(0x1010)
            )
            .is_err()
        );
        let opposite_target = if taken {
            GuestAddress(0x1004)
        } else {
            GuestAddress(0x1008)
        };
        assert!(
            validate(
                &analysis,
                &source,
                BASE,
                registers,
                wrong_kind,
                opposite_target
            )
            .is_err()
        );
    }

    #[test]
    fn conditional_carriers_match_actual_flags_register_width_and_bit() {
        let mut registers = GuestState::default();
        for z in [0, NZCV_Z] {
            registers.nzcv = z;
            check(0x5400_0040, &registers, z != 0); // B.EQ +8
            check(0x5400_0041, &registers, z == 0); // B.NE +8
        }
        for value in [0, 1, 1u64 << 32, 1u64 << 63, u64::MAX] {
            registers.x[3] = value;
            check(0xb400_0043, &registers, value == 0); // CBZ X3,+8
            check(0xb500_0043, &registers, value != 0); // CBNZ X3,+8
            check(0x3400_0043, &registers, value as u32 == 0); // CBZ W3,+8
            check(0x3500_0043, &registers, value as u32 != 0); // CBNZ W3,+8
            check(0x3600_0043, &registers, value & 1 == 0); // TBZ X3,#0,+8
            check(0x3700_0043, &registers, value & 1 != 0); // TBNZ X3,#0,+8
            check(0xb6f8_0043, &registers, value >> 63 == 0); // TBZ X3,#63,+8
            check(0xb7f8_0043, &registers, value >> 63 != 0); // TBNZ X3,#63,+8
        }
        check(0xb400_005f, &registers, true); // CBZ XZR,+8
        check(0xb500_005f, &registers, false); // CBNZ XZR,+8
    }

    #[test]
    fn equal_target_and_fallthrough_keep_source_selected_branch_kind() {
        // B.EQ +4 has the same address for both outcomes. BranchAddr still
        // applies only to the taken branch, so target equality is insufficient.
        const BRANCH_EQUAL_NEXT: u32 = 0x5400_0020;
        let source = BRANCH_EQUAL_NEXT.to_le_bytes();
        let analysis = analyze_with_profile(&source, BASE, BlockProfile::Ordinary).unwrap();
        for (nzcv, kind, wrong) in [
            (NZCV_Z, ExitKind::Direct, ExitKind::Fallthrough),
            (0, ExitKind::Fallthrough, ExitKind::Direct),
        ] {
            let registers = GuestState {
                nzcv,
                ..GuestState::default()
            };
            let next = GuestAddress(BASE.0 + size_of::<u32>() as u64);
            assert!(
                validate(&analysis, &source, BASE, &registers, kind, next)
                    .unwrap()
                    .is_some()
            );
            assert!(validate(&analysis, &source, BASE, &registers, wrong, next).is_err());
        }
    }

    #[test]
    fn true_fallthrough_and_direct_source_are_not_conditional_edges() {
        for word in [
            0xd503_201f_u32,
            0x1400_0002,
            0x9400_0002,
            0xd61f_0060,
            0xd63f_0060,
            0xd65f_03c0,
        ] {
            // NOP; B +8; BL +8; BR X3; BLR X3; RET X30
            let source = word.to_le_bytes();
            let analysis = analyze_with_profile(&source, BASE, BlockProfile::Ordinary).unwrap();
            assert!(
                validate(
                    &analysis,
                    &source,
                    BASE,
                    &GuestState::default(),
                    ExitKind::Fallthrough,
                    GuestAddress(0x1004)
                )
                .unwrap()
                .is_none()
            );
        }
    }
}
