//! Source-ordered copyout for serialized owned ordinary guest memory.
//!
//! Public XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea,
//! osfmk/arm64/copyio.c and machine_routines_asm.s BCOPY_IMPL. This explicit
//! lower-VA47 profile has minimum address zero; it does not infer vm_map_min
//! from the first mapping or normalize tagged addresses. Successful copies use
//! OwnedMemory's whole-range fast path. Faults preserve source-defined complete
//! store prefixes; a fault within a partly writable STP declines before effects.
//! Shared participating memory requires its separately owned publication adapter.

use crate::memory::{DIRECT_RAM_USER_END, OwnedMemory};
use anyhow::{Result, bail, ensure};

const MAX_COPYOUT_BYTES: usize = 256;
const STP_PAIR_BYTES: usize = 2 * size_of::<u64>();
const STRB_BYTES: usize = size_of::<u8>();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Completion {
    Copied,
    Fault { completed: usize },
}

/// Copy only into serialized private ordinary memory. The cold fault path plans
/// every reached store before publishing: an unsupported partly writable pair
/// leaves all destination bytes unchanged, including earlier valid pairs.
pub(crate) fn copyout(memory: &mut OwnedMemory, address: u64, bytes: &[u8]) -> Result<Completion> {
    ensure!(memory.is_usable(), "guest address space is unusable");
    ensure!(
        bytes.len() <= MAX_COPYOUT_BYTES,
        "copyout exceeds the bounded source profile"
    );
    if bytes.is_empty() {
        return Ok(Completion::Copied);
    }
    // copy_validate checks the entire user range before the assembly copy.
    // This lower-VA47 profile's minimum is zero, so only overflow/max need tests.
    if address
        .checked_add(bytes.len() as u64)
        .is_none_or(|end| end > DIRECT_RAM_USER_END)
    {
        return Ok(Completion::Fault { completed: 0 });
    }
    if memory.write(address, bytes).is_ok() {
        return Ok(Completion::Copied);
    }

    let pair_bytes = bytes.len() / STP_PAIR_BYTES * STP_PAIR_BYTES;
    let mut completed = 0;
    while completed < pair_bytes {
        let destination = address + completed as u64;
        if memory.validate_write(destination, STP_PAIR_BYTES).is_ok() {
            completed += STP_PAIR_BYTES;
            continue;
        }
        if (0..STP_PAIR_BYTES).any(|offset| {
            memory
                .validate_write(destination + offset as u64, STRB_BYTES)
                .is_ok()
        }) {
            bail!(
                "copyout fault within a partly writable STP requires a reviewed pair-fault profile"
            );
        }
        return publish_prefix(memory, address, bytes, completed);
    }
    while completed < bytes.len() {
        if memory
            .validate_write(address + completed as u64, STRB_BYTES)
            .is_err()
        {
            return publish_prefix(memory, address, bytes, completed);
        }
        completed += STRB_BYTES;
    }
    // The failed initial whole-range check and the identical successful store
    // plan cannot disagree under this serialized owner. Do not fabricate a fault.
    bail!("copyout permissions changed during serialized preflight")
}

fn publish_prefix(
    memory: &mut OwnedMemory,
    address: u64,
    bytes: &[u8],
    completed: usize,
) -> Result<Completion> {
    // Coalescing already validated stores is observationally equivalent here:
    // this profile permits no concurrent execution, device memory or observers.
    memory.write(address, &bytes[..completed])?;
    Ok(Completion::Fault { completed })
}

#[cfg(test)]
mod tests;
