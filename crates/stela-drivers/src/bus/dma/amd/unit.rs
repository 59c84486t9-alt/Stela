//! AMD-Vi remapper discovery and retained unit resources. Read-only inspection
//! grants no DMA authority. The native backend separately requires an actual
//! cold, exclusive platform owner and preserves process-local ownership.
pub mod native;
pub mod registers;
