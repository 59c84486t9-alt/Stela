//! Immutable pre-EBS observation layout, separate from firmware operations.
#[cfg(test)]
use crate::boot_native_topology as topology;
#[cfg(not(test))]
use crate::native_smp::topology;
use topology::{Processor, Snapshot};

#[repr(C)]
pub(crate) struct Capture {
    pub magic: u64,
    pub version: u32,
    pub processor_count: u32,
    pub core_count: u32,
    pub enabled_count: u32,
    pub processors: [Processor; topology::MAX_PROCESSORS],
    pub selected: [u32; topology::MAX_CORES],
    pub snapshots: [Snapshot; topology::MAX_CORES],
}
