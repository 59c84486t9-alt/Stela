//! Disjoint ranges owned by fixed physical executors. The loader maps one
//! guarded stack and private bounce leaves per core; native arenas and shadow
//! frames are partitioned, never concurrently reclaimed or patched by peers.
use super::topology::MAX_CORES;
use crate::handoff::Region;
mod allocation;
pub(crate) use allocation::{AllocationClaim, ClaimError, TaskAllocations};

pub(crate) use stela_boot_core::native_resources::*;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Resources {
    pub cores: u32,
    /// Owned LOADER_CODE page below 1 MiB, absent for the serial path.
    pub sipi: u64,
    /// Fixed physical stack ranges; virtual guards are not mapped.
    pub stacks: Region,
    /// Separate native invocation frames; never an executor's Rust stack.
    pub invocations: Region,
    /// One BSP work runtime's fixed pool; task roles are admitted later.
    pub tasks: Region,
    /// Private bounce leaf physical addresses, indexed by fixed worker slot.
    pub bounce: [[u64; 2]; MAX_CORES],
}

impl Default for Resources {
    fn default() -> Self {
        Self {
            cores: 1,
            sipi: 0,
            stacks: Region::default(),
            invocations: Region::default(),
            tasks: Region::default(),
            bounce: [[0; 2]; MAX_CORES],
        }
    }
}
