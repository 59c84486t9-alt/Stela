//! Immutable processor membership shared by board parsers and execution owners.
use alloc::vec::Vec;

/// Supplied participant membership. A physical cluster can mix core types.
/// These indices describe a plan; they grant no executor, lifecycle, reset,
/// memory-retention or hardware-root permission. Engine owners validate them
/// against their participant inventory before settlement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessorTarget {
    Core { pe: usize },
    Cluster { members: Vec<usize> },
}

impl ProcessorTarget {
    pub fn members(&self) -> &[usize] {
        match self {
            Self::Core { pe } => core::slice::from_ref(pe),
            Self::Cluster { members } => members,
        }
    }
}
