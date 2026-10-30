//! Checks that a native exit names an instruction in the registered source.
use super::INSTRUCTION_BYTES;
use crate::Result;
use stela_compiler::{
    GuestAddress,
    block::{
        ClockInstruction, PointerAuthentication, SynchronousTrap, SystemInstruction,
        ThreadRegisterInstruction, decode_clock_instruction, decode_pointer_authentication,
        decode_system_instruction, decode_thread_register_instruction, decode_trap,
    },
};
use stela_contracts::{refuse, require};

pub(super) fn validate_clock_exit(
    entry: GuestAddress,
    exit: GuestAddress,
    source_bytes: usize,
    region_base: u64,
    source: &[u8],
) -> Result<ClockInstruction> {
    let word = validate_terminal_word(entry, exit, source_bytes, region_base, source)?;
    Ok(decode_clock_instruction(exit, word)?.ok_or_else(|| {
        refuse!(
            "clock exit does not identify a reviewed instruction",
            exit = exit.0
        )
    })?)
}

pub(super) fn validate_pauth_exit(
    entry: GuestAddress,
    exit: GuestAddress,
    source_bytes: usize,
    region_base: u64,
    source: &[u8],
) -> Result<PointerAuthentication> {
    let word = validate_terminal_word(entry, exit, source_bytes, region_base, source)?;
    Ok(decode_pointer_authentication(exit, word)?.ok_or_else(|| {
        refuse!(
            "PAuth exit does not identify a reviewed instruction",
            exit = exit.0
        )
    })?)
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
        .ok_or(refuse!("numerical exit does not identify arithmetic"))?
        .map_err(|stela_compiler::aarch64::Unsupported| {
            refuse!("numerical exit identifies reserved arithmetic")
        })?;
    let next = GuestAddress(
        exit.0
            .checked_add(INSTRUCTION_BYTES as u64)
            .ok_or(refuse!("numerical continuation address overflow"))?,
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
    require!(
        entry.0.is_multiple_of(INSTRUCTION_BYTES as u64)
            && exit.0.is_multiple_of(INSTRUCTION_BYTES as u64)
            && source_bytes >= INSTRUCTION_BYTES
            && source_bytes.is_multiple_of(INSTRUCTION_BYTES),
        "invalid numerical helper block extent or alignment",
        entry = entry.0,
        source_bytes
    );
    entry
        .0
        .checked_add(source_bytes as u64)
        .ok_or_else(|| refuse!("numerical consumed guest extent overflow", entry = entry.0))?;
    let prefix = entry
        .0
        .checked_sub(region_base)
        .ok_or_else(|| refuse!("numerical block precedes immutable source", entry = entry.0))?
        as usize;
    let end = prefix
        .checked_add(source_bytes)
        .ok_or_else(|| refuse!("numerical block extent overflow", entry = entry.0))?;
    require!(
        end <= source.len(),
        "numerical block exceeds immutable source",
        entry = entry.0,
        source_bytes
    );
    let relative = exit
        .0
        .checked_sub(entry.0)
        .ok_or_else(|| refuse!("numerical exit precedes consumed block", exit = exit.0))?
        as usize;
    require!(
        relative < source_bytes,
        "numerical exit exceeds consumed block",
        exit = exit.0
    );
    word(source, prefix + relative)
        .ok_or_else(|| refuse!("numerical exit exceeds immutable source", exit = exit.0).into())
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
    require!(
        source_bytes >= INSTRUCTION_BYTES && source_bytes.is_multiple_of(INSTRUCTION_BYTES),
        "invalid native helper block extent",
        source_bytes
    );
    let terminal = entry
        .0
        .checked_add((source_bytes - INSTRUCTION_BYTES) as u64)
        .ok_or_else(|| refuse!("native helper terminal address overflow", entry = entry.0))?;
    require!(
        exit.0 == terminal,
        "native helper exit differs from consumed terminal instruction",
        exit = exit.0,
        terminal
    );
    let offset = terminal
        .checked_sub(region_base)
        .ok_or_else(|| refuse!("native helper precedes source region", terminal))?;
    word(source, offset as usize)
        .ok_or_else(|| refuse!("native helper exceeds immutable source", terminal).into())
}

/// The instruction word at `offset` in `source`.
fn word(source: &[u8], offset: usize) -> Option<u32> {
    let bytes = source.get(offset..offset.checked_add(INSTRUCTION_BYTES)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

pub(super) fn validate_system_exit(
    entry: GuestAddress,
    exit: GuestAddress,
    source_bytes: usize,
    region_base: u64,
    source: &[u8],
) -> Result<SystemInstruction> {
    let word = validate_terminal_word(entry, exit, source_bytes, region_base, source)?;
    Ok(decode_system_instruction(exit, word)?.ok_or_else(|| {
        refuse!(
            "native System exit is not an immutable System instruction",
            exit = exit.0
        )
    })?)
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
        .ok_or_else(|| {
            refuse!(
                "thread-register exit does not identify a reviewed instruction",
                exit = exit.0
            )
        })
        .map_err(Into::into)
}

pub(super) fn validate_amx_exit(
    entry: GuestAddress,
    exit: GuestAddress,
    source_bytes: usize,
    region_base: u64,
    source: &[u8],
) -> Result<stela_compiler::amx::AmxInstruction> {
    let word = validate_terminal_word(entry, exit, source_bytes, region_base, source)?;
    stela_compiler::amx::decode(exit, word)?
        .ok_or_else(|| {
            refuse!(
                "AMX exit does not identify an AMX instruction",
                exit = exit.0
            )
        })
        .map_err(Into::into)
}

pub(super) fn validate_trap_exit(
    entry: GuestAddress,
    exit: GuestAddress,
    source_bytes: usize,
    region_base: u64,
    source: &[u8],
) -> Result<SynchronousTrap> {
    let word = validate_terminal_word(entry, exit, source_bytes, region_base, source)?;
    Ok(decode_trap(exit, word)?.ok_or_else(|| {
        refuse!(
            "trap exit does not identify a reviewed instruction",
            exit = exit.0
        )
    })?)
}

pub(super) fn validate_source_map(
    manifest: &crate::Manifest,
    base: GuestAddress,
    source_bytes: usize,
) -> Result<()> {
    let first_native_offset = if manifest.memory_requirements.is_some() {
        stela_compiler::scalable_context::CONTEXT_WRAPPER_BYTES
    } else {
        0
    };
    crate::artifact::validate_source_map(manifest, base, source_bytes, first_native_offset)?;
    Ok(())
}
