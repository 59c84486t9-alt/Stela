//! Memory budgets for allocations made while UEFI still owns boot services.
use core::fmt;
const PAGE: u64 = 4096;
const MIB: u64 = 1024 * 1024;
const MINIMUM: u64 = 16 * MIB;
const MAXIMUM: u64 = 384 * MIB;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InsufficientMemory;
impl fmt::Display for InsufficientMemory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("free firmware RAM cannot supply the boot heap budget")
    }
}
impl core::error::Error for InsufficientMemory {}

/// At most one sixteenth of the currently free conventional RAM, up to the
/// loader's 384 MiB working-set ceiling. Firmware boot-service allocations
/// remain live and are excluded from the supplied free-byte count.
pub fn bootstrap_heap(free: u64) -> Result<u64, InsufficientMemory> {
    let budget = (free / 16).min(MAXIMUM) / PAGE * PAGE;
    if budget < MINIMUM {
        return Err(InsufficientMemory);
    }
    Ok(budget)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pressure_reduces_the_heap_without_consuming_firmware_reserves() {
        assert_eq!(bootstrap_heap(256 * MIB - 1), Err(InsufficientMemory));
        assert_eq!(bootstrap_heap(256 * MIB), Ok(16 * MIB));
        assert_eq!(bootstrap_heap(1024 * MIB), Ok(64 * MIB));
        assert_eq!(bootstrap_heap(8 * 1024 * MIB), Ok(384 * MIB));
        assert_eq!(bootstrap_heap(u64::MAX), Ok(384 * MIB));
        for free in (256 * MIB..1024 * MIB).step_by(9973) {
            let heap = bootstrap_heap(free).unwrap();
            assert!(heap.is_multiple_of(PAGE));
            assert!(heap <= free / 16);
        }
    }
}
