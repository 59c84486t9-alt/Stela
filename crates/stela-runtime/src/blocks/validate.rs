//! Checks that a native exit names an instruction in the registered source.
use super::INSTRUCTION_BYTES;
use anyhow::{Context, Result, ensure};
use stela_compiler::{
    GuestAddress,
    block::{
        ClockInstruction, PointerAuthentication, SynchronousTrap, SystemInstruction,
        ThreadRegisterInstruction, decode_clock_instruction, decode_pointer_authentication,
        decode_system_instruction, decode_thread_register_instruction, decode_trap,
    },
};

pub(super) fn validate_clock_exit(
    entry: GuestAddress,
    exit: GuestAddress,
    source_bytes: usize,
    region_base: u64,
    source: &[u8],
) -> Result<ClockInstruction> {
    let word = validate_terminal_word(entry, exit, source_bytes, region_base, source)?;
    decode_clock_instruction(exit, word)?
        .context("clock exit does not identify a reviewed instruction")
}

pub(super) fn validate_pauth_exit(
    entry: GuestAddress,
    exit: GuestAddress,
    source_bytes: usize,
    region_base: u64,
    source: &[u8],
) -> Result<PointerAuthentication> {
    let word = validate_terminal_word(entry, exit, source_bytes, region_base, source)?;
    decode_pointer_authentication(exit, word)?
        .context("PAuth exit does not identify a reviewed instruction")
}

/// Every consumed aligned word is a source-map boundary, checked at preparation.
/// Numerical exits may identify an interior instruction; all operands are decoded
/// again from the registered immutable source, never from artifact descriptors.
pub(super) fn validate_numerical_exit(
    entry: GuestAddress,
    exit: GuestAddress,
    source_bytes: usize,
    region_base: u64,
    source: &[u8],
) -> Result<(
    stela_compiler::aarch64::FloatingPointOperation,
    GuestAddress,
)> {
    let word = validate_interior_word(entry, exit, source_bytes, region_base, source)?;
    let operand = stela_compiler::aarch64::FloatingPointOperation::decode(word)
        .context("numerical exit does not identify arithmetic")?
        .map_err(|()| anyhow::anyhow!("numerical exit identifies reserved arithmetic"))?;
    let next = GuestAddress(
        exit.0
            .checked_add(INSTRUCTION_BYTES as u64)
            .context("numerical continuation address overflow")?,
    );
    Ok((operand, next))
}

pub(super) fn validate_interior_word(
    entry: GuestAddress,
    exit: GuestAddress,
    source_bytes: usize,
    region_base: u64,
    source: &[u8],
) -> Result<u32> {
    ensure!(
        entry.0.is_multiple_of(INSTRUCTION_BYTES as u64)
            && exit.0.is_multiple_of(INSTRUCTION_BYTES as u64)
            && source_bytes >= INSTRUCTION_BYTES
            && source_bytes.is_multiple_of(INSTRUCTION_BYTES),
        "invalid numerical helper block extent/alignment"
    );
    entry
        .0
        .checked_add(u64::try_from(source_bytes)?)
        .context("numerical consumed guest extent overflow")?;
    let prefix = usize::try_from(
        entry
            .0
            .checked_sub(region_base)
            .context("numerical block precedes immutable source")?,
    )?;
    let end = prefix
        .checked_add(source_bytes)
        .context("numerical block extent overflow")?;
    ensure!(
        end <= source.len(),
        "numerical block exceeds immutable source"
    );
    let relative = usize::try_from(
        exit.0
            .checked_sub(entry.0)
            .context("numerical exit precedes consumed block")?,
    )?;
    ensure!(
        relative < source_bytes,
        "numerical exit exceeds consumed block"
    );
    let offset = prefix
        .checked_add(relative)
        .context("numerical source offset overflow")?;
    Ok(u32::from_le_bytes(
        source[offset..offset + INSTRUCTION_BYTES].try_into()?,
    ))
}

/// Native exit metadata must identify the final immutable source instruction;
/// descriptors are decoded again instead of trusting artifact-supplied operands.
pub(super) fn validate_terminal_word(
    entry: GuestAddress,
    exit: GuestAddress,
    source_bytes: usize,
    region_base: u64,
    source: &[u8],
) -> Result<u32> {
    ensure!(
        source_bytes >= INSTRUCTION_BYTES && source_bytes.is_multiple_of(INSTRUCTION_BYTES),
        "invalid native helper block extent"
    );
    let terminal = entry
        .0
        .checked_add(u64::try_from(source_bytes - INSTRUCTION_BYTES)?)
        .context("native helper terminal address overflow")?;
    ensure!(
        exit.0 == terminal,
        "native helper exit differs from consumed terminal instruction"
    );
    let offset = usize::try_from(
        terminal
            .checked_sub(region_base)
            .context("native helper precedes source region")?,
    )?;
    let end = offset
        .checked_add(INSTRUCTION_BYTES)
        .context("native helper source extent overflow")?;
    Ok(u32::from_le_bytes(
        source
            .get(offset..end)
            .context("native helper exceeds immutable source")?
            .try_into()?,
    ))
}

pub(super) fn validate_system_exit(
    entry: GuestAddress,
    exit: GuestAddress,
    source_bytes: usize,
    region_base: u64,
    source: &[u8],
) -> Result<SystemInstruction> {
    let word = validate_terminal_word(entry, exit, source_bytes, region_base, source)?;
    decode_system_instruction(exit, word)?
        .context("native System exit is not an immutable System instruction")
}

pub(super) fn validate_thread_register_exit(
    entry: GuestAddress,
    exit: GuestAddress,
    source_bytes: usize,
    region_base: u64,
    source: &[u8],
) -> Result<ThreadRegisterInstruction> {
    let word = validate_terminal_word(entry, exit, source_bytes, region_base, source)?;
    decode_thread_register_instruction(exit, word)?
        .context("thread-register exit does not identify a reviewed instruction")
}

pub(super) fn validate_trap_exit(
    entry: GuestAddress,
    exit: GuestAddress,
    source_bytes: usize,
    region_base: u64,
    source: &[u8],
) -> Result<SynchronousTrap> {
    let word = validate_terminal_word(entry, exit, source_bytes, region_base, source)?;
    decode_trap(exit, word)?.context("trap exit does not identify a reviewed instruction")
}

pub(super) fn validate_source_map(
    manifest: &crate::Manifest,
    base: GuestAddress,
    source_bytes: usize,
) -> Result<()> {
    let first_native_offset = if manifest.memory_requirements.is_some()
        || manifest.identity.abi == stela_compiler::block::EL1_M0_INTEGER_BLOCK_ABI
    {
        stela_compiler::extended::CONTEXT_WRAPPER_BYTES
    } else {
        0
    };
    crate::artifact::validate_source_map(manifest, base, source_bytes, first_native_offset)?;
    Ok(())
}
