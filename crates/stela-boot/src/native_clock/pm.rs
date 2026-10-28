//! Port I/O adapter for the shared fixed-PM timer contract.
use core::arch::asm;
pub(super) use stela_boot_core::pm_timer::{HZ, NS, ns};
use stela_drivers::platform::work::WorkError;
#[derive(Clone, Copy)]
pub(crate) struct Prepared(stela_boot_core::pm_timer::Prepared);
impl core::ops::Deref for Prepared {
    type Target = stela_boot_core::pm_timer::Prepared;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Prepared {
    pub(crate) fn from_fadt(table: &[u8]) -> Result<Self, WorkError> {
        stela_boot_core::pm_timer::Prepared::from_fadt(table).map(Self)
    }
    /// # Safety
    /// Every real sample gap obeys this caller-established bound.
    pub(crate) unsafe fn qualify_bounded(self, ns: u64) -> Result<Self, WorkError> {
        // SAFETY: forwarded lifetime-wide bound from this adapter's caller.
        unsafe { self.0.qualify_bounded(ns) }.map(Self)
    }
    pub(super) fn admit(self) -> Result<(), WorkError> {
        self.0.admit()
    }
    pub(super) fn delta(self, previous: u32, current: u32) -> Result<u64, WorkError> {
        self.0.delta(previous, current)
    }
    /// # Safety
    /// The retained root owns this FADT's fixed SystemIO resource after EBS.
    unsafe fn raw(self) -> u32 {
        let value: u32;
        // SAFETY: source-qualified fixed timer port; a read has no clear effect.
        unsafe {
            asm!("in eax, dx", in("dx") self.port, out("eax") value, options(nomem, nostack, preserves_flags));
        }
        value & self.mask
    }

    /// The same three-read consistency predicate as Linux acpi_pm_read_verified,
    /// with bounded failure instead of an unbounded IRQ-context retry.
    pub(super) unsafe fn read(self) -> Result<u32, WorkError> {
        for _ in 0..8 {
            // SAFETY: identical retained fixed resource for all three reads.
            let (a, b, c) = unsafe { (self.raw(), self.raw(), self.raw()) };
            if !((a > b && a < c) || (b > c && b < a) || (c > a && c < b)) {
                return Ok(b);
            }
        }
        Err(WorkError::CorruptContext)
    }
}
