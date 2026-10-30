//! AMD-Vi remapper discovery and kept unit resources. Read-only inspection
//! grants no DMA permission. The native backend separately requires a
//! cold, exclusive platform owner and preserves process-local ownership.
pub mod native;
pub mod registers;
