//! Bounded, declarative Darwin kernel-to-dyld argument arrays.
//!
//! The reviewed XNU/dyld contract is [main Mach header, argc, argv..., NULL,
//! envp..., NULL, apple..., NULL], with apple[0] the executable path. String
//! ordering/padding here is our deterministic layout, not an exact kernel dump.
//! This module neither reads the host environment nor creates a running process.
use crate::memory::OwnedMemory;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use anyhow::{Context as _, Result, ensure};

mod identity;
pub use identity::{Context, MAX_PROCESS_ID, PROFILE_ID, Snapshot};
use serde::{Deserialize, Serialize};

/// Resource bounds for this planner, not Darwin ARG_MAX or a kernel ABI limit.
pub const MAX_ARGUMENT_STRINGS: usize = 4096;
pub const MAX_ARGUMENT_STRING_BYTES: usize = 64 * 1024;
pub const MAX_ARGUMENT_PAYLOAD_BYTES: usize = 1024 * 1024;
pub const MIN_WORKING_STACK_BYTES: u64 = 256;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProcessArguments {
    pub argv: Vec<Vec<u8>>,
    pub environment: Vec<Vec<u8>>,
    /// Extra apple entries; the planner always inserts executable_path first.
    pub apple: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgumentStringKind {
    Argv,
    Environment,
    Apple,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArgumentStringSpan {
    pub kind: ArgumentStringKind,
    pub index: usize,
    pub address: u64,
    /// String bytes excluding the one appended NUL terminator.
    pub bytes: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct KernelArgsPlan {
    pub stack_base: u64,
    pub stack_bytes: u64,
    pub raw_sp: u64,
    pub aligned_sp: u64,
    pub argc: u64,
    pub argc_address: u64,
    pub argv_address: u64,
    pub envp_address: u64,
    pub apple_address: u64,
    pub strings: Vec<ArgumentStringSpan>,
    pub payload_address: u64,
    pub initial_bytes: Vec<u8>,
}

fn add(left: u64, right: u64) -> Result<u64> {
    left.checked_add(right)
        .context("argument address/size overflow")
}

fn sub(left: u64, right: u64) -> Result<u64> {
    left.checked_sub(right)
        .context("argument stack is too small")
}

/// Build only initialized bytes at the top of a supplied guest stack range.
/// main_header is a guest value; executable ownership must be checked by a loader.
pub fn plan_kernel_args(
    stack_base: u64,
    stack_bytes: u64,
    main_header: u64,
    executable_path: &[u8],
    args: &ProcessArguments,
) -> Result<KernelArgsPlan> {
    let stack_end = add(stack_base, stack_bytes)?;
    ensure!(!executable_path.is_empty(), "executable path is empty");
    let count = args
        .argv
        .len()
        .checked_add(args.environment.len())
        .and_then(|n| n.checked_add(args.apple.len()))
        .and_then(|n| n.checked_add(1))
        .context("argument string count overflow")?;
    ensure!(
        count <= MAX_ARGUMENT_STRINGS,
        "argument string count exceeds planner resource limit"
    );
    let strings: Vec<_> = args
        .argv
        .iter()
        .enumerate()
        .map(|(i, s)| (ArgumentStringKind::Argv, i, s.as_slice()))
        .chain(
            args.environment
                .iter()
                .enumerate()
                .map(|(i, s)| (ArgumentStringKind::Environment, i, s.as_slice())),
        )
        .chain(core::iter::once((
            ArgumentStringKind::Apple,
            0,
            executable_path,
        )))
        .chain(
            args.apple
                .iter()
                .enumerate()
                .map(|(i, s)| (ArgumentStringKind::Apple, i + 1, s.as_slice())),
        )
        .collect();
    let mut string_bytes = 0_u64;
    for (_, _, string) in &strings {
        ensure!(
            string.len() <= MAX_ARGUMENT_STRING_BYTES,
            "argument string exceeds planner resource limit"
        );
        ensure!(
            !string.contains(&0),
            "argument string contains embedded NUL"
        );
        string_bytes = add(string_bytes, add(string.len() as u64, 1)?)?;
        ensure!(
            string_bytes <= MAX_ARGUMENT_PAYLOAD_BYTES as u64,
            "argument bytes exceed planner resource limit"
        );
    }
    // argc plus three NULL terminators, excluding the leading Mach header.
    let table_bytes = add(count as u64, 4)?
        .checked_mul(8)
        .context("argument table size overflow")?;
    let string_address = sub(stack_end, string_bytes)?;
    let argc_address = sub(string_address, table_bytes)? & !15;
    let raw_sp = sub(argc_address, 8)?;
    let aligned_sp = raw_sp & !15;
    ensure!(
        sub(aligned_sp, MIN_WORKING_STACK_BYTES)? >= stack_base,
        "argument stack lacks working scratch space"
    );
    let payload_bytes = sub(stack_end, raw_sp)?;
    ensure!(
        payload_bytes <= MAX_ARGUMENT_PAYLOAD_BYTES as u64,
        "argument payload exceeds planner resource limit"
    );
    let mut initial_bytes = vec![0; usize::try_from(payload_bytes)?];
    let mut spans = Vec::with_capacity(count);
    let mut cursor = string_address;
    for (kind, index, string) in strings {
        let offset = usize::try_from(sub(cursor, raw_sp)?)?;
        initial_bytes[offset..offset + string.len()].copy_from_slice(string);
        spans.push(ArgumentStringSpan {
            kind,
            index,
            address: cursor,
            bytes: string.len(),
        });
        cursor = add(cursor, add(string.len() as u64, 1)?)?;
    }
    let argc = args.argv.len() as u64;
    let argv_address = add(argc_address, 8)?;
    let envp_address = add(
        argv_address,
        add(argc, 1)?.checked_mul(8).context("argv size overflow")?,
    )?;
    let apple_address = add(
        envp_address,
        add(args.environment.len() as u64, 1)?
            .checked_mul(8)
            .context("envp size overflow")?,
    )?;
    let mut words = Vec::with_capacity(count + 5);
    words.extend([main_header, argc]);
    for kind in [
        ArgumentStringKind::Argv,
        ArgumentStringKind::Environment,
        ArgumentStringKind::Apple,
    ] {
        words.extend(spans.iter().filter(|s| s.kind == kind).map(|s| s.address));
        words.push(0);
    }
    for (offset, word) in words.iter().enumerate() {
        initial_bytes[offset * 8..offset * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    Ok(KernelArgsPlan {
        stack_base,
        stack_bytes,
        raw_sp,
        aligned_sp,
        argc,
        argc_address,
        argv_address,
        envp_address,
        apple_address,
        strings: spans,
        payload_address: raw_sp,
        initial_bytes,
    })
}

impl KernelArgsPlan {
    /// Install one prevalidated span. Every declared stack byte must be owned RW
    /// memory without guest execute permission. Failure leaves all bytes untouched.
    pub fn install(&self, memory: &mut OwnedMemory) -> Result<()> {
        let end = add(self.stack_base, self.stack_bytes)?;
        ensure!(
            self.stack_bytes > 0
                && self.payload_address >= self.stack_base
                && add(self.payload_address, self.initial_bytes.len() as u64)? <= end,
            "argument payload lies outside declared stack"
        );
        ensure!(
            self.initial_bytes.len() <= MAX_ARGUMENT_PAYLOAD_BYTES,
            "argument payload exceeds planner resource limit"
        );
        let mut cursor = self.stack_base;
        for region in memory.regions() {
            let region_end = add(region.guest_address, region.virtual_bytes)?;
            if region_end <= cursor {
                continue;
            }
            if cursor == end {
                break;
            }
            ensure!(
                region.guest_address <= cursor,
                "argument stack includes unowned memory"
            );
            ensure!(
                region.readable && region.writable && !region.executable,
                "argument stack requires owned readable/writable non-executable memory"
            );
            cursor = region_end.min(end);
        }
        ensure!(cursor == end, "argument stack includes unowned memory");
        memory.write(self.payload_address, &self.initial_bytes)
    }
}

#[cfg(test)]
mod tests;
