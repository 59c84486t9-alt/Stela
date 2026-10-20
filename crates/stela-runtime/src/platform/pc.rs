//! Host PC storage and input that the mount drives itself after
//! ExitBootServices.
//!
//! `stela.efi` records the ACPI MCFG windows, a block of DMA pages below
//! 4 GiB, the MMIO ranges it mapped uncached and a TSC rate in a [`Handoff`]
//! before it leaves boot services. [`storage::probe`] then enumerates PCI
//! through ECAM and brings up every virtio-blk, NVMe and AHCI controller
//! with polled completion, every virtio-input keyboard and pointer
//! ([`input`]) and every virtio-net adapter ([`virtio_net`]);
//! [`storage::open`] selects the one disk and GPT partition that `stela.cfg`
//! names and returns a [`gpt::PartitionDevice`] that cannot reach any other
//! block. [`boot_log`] keeps the mount's output on the machine-state
//! partition, and `stela` reads it back; [`machine_state`] keeps that
//! partition's layout in the tail of the Apple region instead.
use alloc::vec::Vec;
use core::ops::Range;

pub mod acpi;
pub mod ahci;
pub mod block;
pub mod boot_log;
pub mod dma;
pub mod gpt;
pub mod input;
pub mod machine_state;
mod mmio;
pub mod nvme;
pub mod pci;
pub mod power;
pub mod storage;
pub mod virtio;
pub mod virtio_net;
pub mod xhci;

/// What `stela.efi` records for the host storage drivers before it leaves
/// boot services.
#[derive(Clone, Debug)]
pub struct Handoff {
    /// ECAM windows from the ACPI MCFG table.
    pub ecam: Vec<pci::EcamWindow>,
    /// MMIO ranges mapped uncached in Stela's tables: the ECAM windows and
    /// every memory BAR of a storage controller or input device.
    pub mapped: Vec<Range<u64>>,
    /// Identity-mapped, physically contiguous pages for DMA, below 4 GiB.
    pub dma: Range<u64>,
    /// The time-stamp counter rate, measured against the firmware's stall.
    pub clock: Clock,
}

impl Handoff {
    /// Whether `range` lies inside one mapped MMIO range.
    pub fn is_mapped(&self, range: &Range<u64>) -> bool {
        self.mapped
            .iter()
            .any(|mapped| mapped.start <= range.start && range.end <= mapped.end)
    }
}

/// The registers at `offset..offset + bytes` of a memory BAR, after checking
/// that Stela mapped them uncached.
pub(crate) fn registers(
    handoff: &Handoff,
    bar: Option<pci::Bar>,
    offset: u64,
    bytes: u64,
) -> Result<mmio::Mmio, block::BlockError> {
    let bar = bar
        .and_then(|bar| bar.memory())
        .ok_or(block::BlockError::Unsupported("register BAR is not memory"))?;
    let start = bar
        .start
        .checked_add(offset)
        .filter(|start| start.saturating_add(bytes) <= bar.end)
        .ok_or(block::BlockError::Unsupported(
            "registers outside their BAR",
        ))?;
    if !handoff.is_mapped(&(start..start + bytes)) {
        return Err(block::BlockError::Unsupported("registers are not mapped"));
    }
    // SAFETY: mapped uncached by stela.efi and owned by this one driver.
    Ok(unsafe { mmio::Mmio::new(start) })
}

/// Microsecond deadlines from the time-stamp counter.
#[derive(Clone, Copy, Debug)]
pub struct Clock {
    pub ticks_per_microsecond: u64,
}

impl Clock {
    fn ticks() -> u64 {
        // SAFETY: RDTSC has no memory effects; x86-64 always has it.
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    /// Microseconds since an arbitrary origin.
    pub fn now_us(&self) -> u64 {
        Self::ticks() / self.ticks_per_microsecond
    }

    /// A deadline `microseconds` from now.
    pub fn deadline(&self, microseconds: u64) -> Deadline {
        Deadline {
            end: Self::ticks()
                .saturating_add(microseconds.saturating_mul(self.ticks_per_microsecond)),
        }
    }

    /// Spin for at least `microseconds`.
    pub fn delay(&self, microseconds: u64) {
        let deadline = self.deadline(microseconds);
        while !deadline.passed() {
            core::hint::spin_loop();
        }
    }

    /// Poll `ready` until it holds or `microseconds` pass.
    pub fn wait(&self, microseconds: u64, mut ready: impl FnMut() -> bool) -> bool {
        let deadline = self.deadline(microseconds);
        loop {
            if ready() {
                return true;
            }
            if deadline.passed() {
                return ready();
            }
            core::hint::spin_loop();
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Deadline {
    end: u64,
}

impl Deadline {
    pub fn passed(&self) -> bool {
        Clock::ticks() >= self.end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_ranges_must_contain_the_whole_range() {
        let handoff = Handoff {
            ecam: Vec::new(),
            mapped: vec![0x1000..0x3000, 0x8000..0x9000],
            dma: 0..0,
            clock: Clock {
                ticks_per_microsecond: 1,
            },
        };
        assert!(handoff.is_mapped(&(0x1000..0x3000)));
        assert!(handoff.is_mapped(&(0x2000..0x2800)));
        assert!(!handoff.is_mapped(&(0x2000..0x4000)));
        assert!(!handoff.is_mapped(&(0x3000..0x8800)));
    }

    #[test]
    fn a_zero_wait_still_polls_once() {
        let clock = Clock {
            ticks_per_microsecond: 1,
        };
        let mut calls = 0;
        assert!(!clock.wait(0, || {
            calls += 1;
            false
        }));
        assert!(calls >= 1);
    }
}
