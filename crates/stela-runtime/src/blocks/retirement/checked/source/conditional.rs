//! Validating a reached conditional branch terminal. The branch changes neither
//! its tested register nor NZCV, so the post-prefix state decides it.
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
mod tests;
