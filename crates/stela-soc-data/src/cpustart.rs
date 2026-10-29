//! CPU-start register extent and decoded physical core coordinates.
//! Describing a core grants no release or native-processor lifecycle authority.
const START: u64 = 0x8;

/// The registers' span for `clusters` clusters.
pub fn bytes(clusters: u8) -> u64 {
    START + 4 * u64::from(clusters)
}

/// A core: its cluster and its number in the cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Core {
    pub cluster: u8,
    pub core: u8,
}
