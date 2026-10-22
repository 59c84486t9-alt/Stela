//! Stela's host PC drivers, organized by device class. The mount runs
//! them after ExitBootServices, when the firmware's drivers are gone.
//!
//! Each driver backs an emulated Apple device: a host disk becomes the
//! Mac's internal SSD or a USB disk, a host keyboard or pointer the native
//! USB peripheral, a host network adapter the mount's own client or the
//! guest's Ethernet. macOS never sees these drivers; it keeps Apple's stock
//! drivers for the Apple devices. Polling and the reserved DMA region are
//! implementation choices of the current boot drivers, not requirements
//! for this crate. Native C/C++ ports belong behind explicit ABI wrappers;
//! driver requirements determine allocation and interrupt services.
//!
//! `stela.efi` records the ACPI MCFG windows, a block of DMA pages below
//! 4 GiB, the MMIO ranges it mapped uncached and a TSC rate in a [`Handoff`]
//! before it leaves boot services. [`probe::probe`] then enumerates PCI
//! through ECAM ([`bus`]) and brings up every driver, one folder per device
//! class: disks ([`storage`], behind [`block::BlockDevice`]), keyboards and
//! pointers ([`input`]), raw Ethernet links ([`net`]) and the USB devices
//! behind xHCI controllers ([`usb`]), reporting the functions it cannot take.
//!
//! [`firmware`] holds the exact device firmware catalog drivers load from.
//! [`gpu`] inventories display controllers; its feature-gated vendor ports
//! are support libraries that initialize no GPU. [`audio`] drives HD Audio
//! for the mount's audio check only. The Wi-Fi libraries in [`net::wifi`],
//! USB4/Thunderbolt and I²C/SMBus in [`bus`], Type-C in [`usb::typec`] and
//! [`platform`] (ACPICA and work contexts) are not attached by `probe` yet.
#![no_std]
#[macro_use]
extern crate alloc;

use alloc::{sync::Arc, vec::Vec};
use core::{
    ops::Range,
    sync::atomic::{AtomicPtr, Ordering},
};

pub mod audio;
pub mod block;
pub mod bus;
pub mod firmware;
pub mod gpu;
pub mod input;
pub mod net;
pub mod platform;
pub mod probe;
pub mod storage;
pub mod usb;

use block::BlockError;
use bus::{mmio::Mmio, pci};

/// What `stela.efi` records for the host drivers before it leaves boot
/// services.
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
    /// Verified host-device firmware; sharing a handoff never copies image bytes.
    pub firmware: Option<Arc<firmware::Catalog>>,
    /// Owned pre-EBS Intel Bluetooth board-variable observation and diagnostics.
    pub bluetooth_platform: usb::bluetooth::intel::DsbrCapture,
    /// Copied status metadata; raw bytes belong to the permanent firmware catalog.
    pub wifi_platform: net::wifi::intel::platform::Observations,
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
) -> Result<Mmio, BlockError> {
    let bar = bar
        .and_then(|bar| bar.memory())
        .ok_or(BlockError::Unsupported("register BAR is not memory"))?;
    let start = bar
        .start
        .checked_add(offset)
        .filter(|start| start.saturating_add(bytes) <= bar.end)
        .ok_or(BlockError::Unsupported("registers outside their BAR"))?;
    if !handoff.is_mapped(&(start..start + bytes)) {
        return Err(BlockError::Unsupported("registers are not mapped"));
    }
    // SAFETY: mapped uncached by stela.efi and owned by this one driver.
    Ok(unsafe { Mmio::new(start) })
}

/// What runs while a driver waits: the mount's boot screen moves its
/// marker. A `fn()` pointer, null when none is set.
static WAITING: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Call `hook` while any driver waits, often and briefly; it must not
/// drive a device.
pub fn on_wait(hook: fn()) {
    WAITING.store(hook as *mut (), Ordering::Relaxed);
}

/// What runs as a driver starts on a device, with the device named: the
/// mount's boot screen shows it, so a device that never answers is named
/// there. A `fn(&str)` pointer, null when none is set.
static WORKING: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Call `hook` with a device's name as a driver starts on it; it must not
/// drive a device.
pub fn on_work(hook: fn(&str)) {
    WORKING.store(hook as *mut (), Ordering::Relaxed);
}

pub(crate) fn working(device: &str) {
    let hook = WORKING.load(Ordering::Relaxed);
    if !hook.is_null() {
        // SAFETY: `on_work` stored a `fn(&str)`, the pointer's only source.
        let hook: fn(&str) = unsafe { core::mem::transmute(hook) };
        hook(device);
    }
}

pub(crate) fn waiting() {
    let hook = WAITING.load(Ordering::Relaxed);
    if !hook.is_null() {
        // SAFETY: `on_wait` stored a `fn()`, the pointer's only source.
        let hook: fn() = unsafe { core::mem::transmute(hook) };
        hook();
    }
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

    /// Microseconds since an arbitrary origin. A zero rate, which test clocks
    /// use to expire every wait at once, reads as the origin.
    pub fn now_us(&self) -> u64 {
        Self::ticks()
            .checked_div(self.ticks_per_microsecond)
            .unwrap_or(0)
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
            waiting();
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
            waiting();
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
            firmware: None,
            bluetooth_platform: Default::default(),
            wifi_platform: Default::default(),
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
    fn cloning_a_driver_handoff_shares_the_immutable_firmware_catalog() {
        let catalog = Arc::new(firmware::Catalog::from_handoff(vec![]).unwrap());
        let handoff = Handoff {
            ecam: Vec::new(),
            mapped: Vec::new(),
            dma: 0..0,
            clock: Clock {
                ticks_per_microsecond: 1,
            },
            firmware: Some(catalog.clone()),
            bluetooth_platform: Default::default(),
            wifi_platform: Default::default(),
        };
        let cloned = handoff.clone();
        assert!(Arc::ptr_eq(cloned.firmware.as_ref().unwrap(), &catalog));
        drop(handoff);
        assert_eq!(cloned.firmware.as_ref().unwrap().inventory(), (0, 0));
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
