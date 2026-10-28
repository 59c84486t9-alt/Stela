// SPDX-License-Identifier: GPL-2.0-only
//! ACP6.3 dedicated Pink Sardine direct-PDM driver (AMD1022:15e2 revision63).
//! Adapted from Linux sound/soc/amd/ps/{pci-ps,ps-common,ps-pdm-dma}.c and
//! acp63.h at a804c5742bff224d4cb4d25dd383554d598be32b. See THIRD_PARTY.md.
//! Copyright (C) 2022, 2023, 2025 Advanced Micro Devices, Inc.
//!
//! This is the selector-zero dedicated PDM path, not the separately selected
//! generic LEGACY/I2S/SOF/SoundWire drivers or ACP70/71/72 hardware. It retains
//! an actual whole-function PCI D0/board/firmware epoch, qualified requester DMA,
//! real ACPI child evidence and SoundWire exclusion. No CLKMUX access exists:
//! ACP63 uses the actual ZSC DSP control boundary during init/retirement.
use super::acp_pdm::{self, DmaConfig, Profile};
pub use super::acp_pdm::{
    CAPTURE_FORMAT, CapturePeriod, Error, Identity, Phase, Position, Registers, State,
};
pub use super::acp6x::Ownership;
use crate::bus::{dma::mapping::DmaDomain, i2c::Timer};
use alloc::sync::Arc;
pub mod pci;
pub(super) mod registers;
use registers::*;

#[doc(hidden)]
pub struct PinkSardine;
impl Profile for PinkSardine {
    const POWER_CONTROL: usize = POWER_CONTROL;
    const POWER_STATUS: usize = POWER_STATUS;
    const CLOCK: Option<usize> = None;
    const ZSC_CONTROL: Option<usize> = Some(ZSC_CONTROL);
    const PRESERVE_INITIAL_IRQ_CONTROL: bool = false;
    const CLEAR_IRQ_CONTROL_ON_DISABLE: bool = true;
    const IRQ_ENABLE: usize = IRQ_ENABLE;
    const IRQ_CONTROL: usize = IRQ_CONTROL;
    const IRQ_STATUS: usize = IRQ_STATUS;
    const SRAM_TABLE: u32 = SRAM_TABLE;
    const ERROR_ENABLE: u32 = ERROR_IRQ;
    const REQUIRE_DRAIN: bool = true;
    const PERIOD_DELIVERY: bool = true;
    fn supported(identity: Identity) -> bool {
        identity.vendor == 0x1022 && identity.device == 0x15e2 && identity.revision == 0x63
    }
    fn class_allowed(class: [u8; 3]) -> bool {
        class == [4, 0x80, 0]
    }
    fn pin_mode<R: Registers>(registers: &mut R) -> Result<Option<u32>, Error> {
        let mode = registers.read32(PIN_CONFIG);
        if mode == u32::MAX {
            return Err(Error::RegisterUnavailable(PIN_CONFIG));
        }
        Ok(Some(mode))
    }
    fn validate_pin(mode: Option<u32>, _: Identity) -> Result<(), Error> {
        let mode = mode.unwrap();
        if !matches!(mode, 4..=8 | 10..=14) {
            return Err(Error::UnsupportedPinMode(mode));
        }
        Ok(())
    }
}

/// The actual child at _ADR2 of this exact PCI function's ACPI companion.
/// A matching string/ID from another namespace or a fabricated child is no grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmicChild {
    pub address: u64,
    pub audio_device_type: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WovObservation {
    Value(u64),
    /// ACPI was actually evaluated; missing method or genuine evaluation
    /// failure uses the pinned source's default-on policy AFTER child discovery.
    EvaluatedFailure,
    /// No working native evaluation service/evidence: never default-on.
    Unavailable,
}

/// Actual same-function SoundWire enumeration and whole-function arbitration.
/// A pin-mode value by itself supplies neither absence nor idle ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SoundWireOwnership {
    EnumeratedAbsent,
    /// The real controller/firmware/worker owner has quiesced every SoundWire
    /// engine and retained exclusive exclusion throughout this PDM ownership.
    QuiescedExclusive,
    ActiveOrUnknown,
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub ownership: Ownership,
    /// Actual result of snd_amd_acp_find_config for this function: only zero
    /// selects the dedicated ps PCI driver, not LEGACY8/DMIC16 or SOF flags.
    pub acp_config: Option<u32>,
    pub child: Option<DmicChild>,
    pub wov: WovObservation,
    pub soundwire: SoundWireOwnership,
    pub dma_address_bits: u8,
    pub gain: u8,
}

impl Config {
    /// The direct-PDM claim conditions shared by ACP6.3 and ACP7.x: exclusive
    /// direct ownership with selector zero and SoundWire quiet, the DMIC child
    /// (address 2, audio device type 2) and a nonzero evaluated `_WOV`.
    pub(super) fn direct(&self) -> Result<DmaConfig, Error> {
        if self.ownership != Ownership::ExclusiveDirect
            || self.acp_config != Some(0)
            || self.soundwire == SoundWireOwnership::ActiveOrUnknown
        {
            return Err(Error::Ownership);
        }
        if self.child
            != Some(DmicChild {
                address: 2,
                audio_device_type: 2,
            })
            || matches!(
                self.wov,
                WovObservation::Value(0) | WovObservation::Unavailable
            )
        {
            return Err(Error::MicrophoneAbsent);
        }
        Ok(DmaConfig {
            dma_address_bits: self.dma_address_bits,
            gain: self.gain,
        })
    }
}

pub type Controller<R, T> = acp_pdm::Controller<R, T, PinkSardine>;
impl<R: Registers, T: Timer> acp_pdm::Controller<R, T, PinkSardine> {
    /// Claim without hardware effects or inferred firmware/platform resources.
    ///
    /// # Safety
    /// The retained native requester/BAR/domain must name this exact rev63,
    /// class048000 function and actual coherent RAM/root path. The platform owns
    /// actual PCI D0, board power/clocks, firmware/SOF/AML/SMM and other-CPU
    /// exclusion throughout the epoch. Child/_WOV/selector observations must
    /// come from this function's actual evaluated ACPI and source policy.
    /// SoundWire exclusion must be established by its actual controller/worker
    /// owner and same-function inventory, including mixed pin modes; no parallel
    /// SoundWire child can run under this whole-function reset/ATU/IRQ owner.
    /// Contain native INTx/MSI/MSI-X delivery and retain all roots, mappings,
    /// pins and firmware exclusion through failed stop/reset/drain or drop.
    pub unsafe fn claim(
        registers: R,
        timer: T,
        config: Config,
        domain: Arc<dyn DmaDomain>,
    ) -> Result<Self, Error> {
        Self::claim_profile(registers, timer, config.direct()?, domain)
    }
    /// Poll actual source period completion and copy one ordered period while
    /// DMA runs. Coalesced events, consumed position and pre/post-copy overwrite
    /// checks use the source ISR->PCM-pointer/coherent-buffer contract. Discard
    /// the entire destination on failure; it may be partly modified. No active
    /// buffer invalidation, CPU ownership or atomic stereo snapshot is promised.
    pub fn capture_period(
        &mut self,
        destination: &mut [u8],
    ) -> Result<Option<CapturePeriod>, Error> {
        self.read_completed_period(destination)
    }
    /// Source PDM/controller quiet with original PCI D0/board epoch retained.
    /// This dedicated source parks ZSC, without an invented CLKMUX or optional
    /// PGFSM power-off policy borrowed from a different generation's driver.
    pub fn suspend_held_d0(&mut self) -> Result<(), Error> {
        self.suspend_retained(false)
    }
    /// Restore the actual original PCI/domain epoch and PTE/ring into Prepared;
    /// explicit start is source trigger RESUME and begins a new capture epoch.
    pub fn resume_held_d0(&mut self) -> Result<(), Error> {
        self.resume_retained()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::{PcmFormat, acp_pdm::check_dma_range};
    use super::*;
    use crate::bus::dma::{
        mapping::DomainMapping,
        memory::{PageBacking, PageGeometry, PinnedPages},
        pages::DmaPages,
    };
    use crate::bus::dma::{
        mapping::{Direction as DmaDirection, DmaError},
        memory::{CacheAttribute, CpuMapping, MemoryError, PageSource},
    };
    use alloc::{boxed::Box, vec::Vec};
    use core::sync::atomic::Ordering;
    use core::{
        cell::UnsafeCell,
        ops::Range,
        ptr::NonNull,
        sync::atomic::{AtomicU64, AtomicUsize},
    };
    use std::sync::Mutex;

    const IOVA: u64 = 0x1_8000_0000;
    #[repr(align(4096))]
    struct Ram([u8; 32768]);
    struct Backing {
        ram: Box<UnsafeCell<Ram>>,
        physical: Vec<u64>,
        drops: Arc<AtomicUsize>,
    }
    // SAFETY: uniquely owned aligned CPU storage with no exposed safe mutable
    // references; the synchronous device model serializes every access.
    unsafe impl Send for Backing {}
    // SAFETY: same stable UnsafeCell storage, raw volatile access only.
    unsafe impl Sync for Backing {}
    // SAFETY: actual owned CPU RAM, immutable symbolic non-contiguous physical
    // labels used only by the model domain, never dereferenced as CPU addresses.
    unsafe impl PageBacking for Backing {
        fn cpu_base(&self) -> NonNull<u8> {
            // SAFETY: stable retained allocation, UnsafeCell permits DMA writes.
            unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*self.ram.get()).0).cast()) }
        }
        fn physical_pages(&self) -> &[u64] {
            &self.physical
        }
        fn page_shift(&self) -> u8 {
            12
        }
        fn cache_attribute(&self) -> CacheAttribute {
            CacheAttribute::WriteBack
        }
    }
    impl Drop for Backing {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
    struct Source {
        drops: Arc<AtomicUsize>,
        geometry: u8,
    }
    impl PageSource for Source {
        fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
            PageGeometry::base_only(self.geometry)
        }
        fn allocate(
            &self,
            bytes: usize,
            alignment: usize,
            attribute: CacheAttribute,
        ) -> Result<PinnedPages, MemoryError> {
            assert!(bytes <= 32768);
            assert_eq!(alignment, 4096);
            assert_eq!(attribute, CacheAttribute::WriteBack);
            PinnedPages::new(
                Box::new(Backing {
                    ram: Box::new(UnsafeCell::new(Ram([0; 32768]))),
                    physical: (0..bytes / 4096)
                        .map(|page| 0x5000_0000 + page as u64 * 0x3000)
                        .collect(),
                    drops: self.drops.clone(),
                }),
                bytes,
                alignment,
            )
        }
    }
    struct Translation {
        token: DomainMapping,
        cpu: CpuMapping,
        pages: DmaPages,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Retirement {
        ResetAcknowledged,
        GroupDisabled,
        BusMaster(bool),
        PayloadDrained,
    }
    struct Device {
        words: Vec<u32>,
        identity: Identity,
        master: bool,
        count: u64,
        cursor: usize,
        frames: u64,
        translation: Option<Translation>,
        atu_readback: u32,
        atu_reads: usize,
        resets: usize,
        published_reset: Option<usize>,
        retirement: Vec<Retirement>,
        reject_bme_disable: bool,
        maps: usize,
        unmaps: usize,
        cpu_syncs: usize,
        device_syncs: usize,
        device_owns: bool,
        start_never: bool,
        stop_never: bool,
        reset_never: bool,
        power_never: bool,
        unmap_fail: bool,
        sync_fail: bool,
        drain_fail: bool,
        drain_unavailable: bool,
        drains: usize,
        coherent_reads: usize,
        coherence_unavailable: bool,
        advance_on_coherent: Option<(usize, usize)>,
        accesses: Vec<(usize, bool)>,
        defer_payload: bool,
        posted: Vec<(usize, i32)>,
        lost_read: Option<usize>,
        fail_after_write: Option<usize>,
        ignore_write: Option<usize>,
        rollover: bool,
        unstable: bool,
        writes: Vec<(usize, u32)>,
        clock: Arc<AtomicU64>,
        jump_write: Option<(usize, u32, u64)>,
        jump_read: Option<(usize, u32, u64)>,
    }
    impl Device {
        fn new(revision: u8) -> Self {
            let mut words = vec![0; 0x11000 / 4];
            words[0x1028 / 4] = 2;
            words[0x1014 / 4] = 1;
            words[0x1440 / 4] = 4;
            words[0x2c5c / 4] = 0x6000;
            Self {
                words,
                identity: Identity {
                    vendor: 0x1022,
                    device: 0x15e2,
                    revision,
                },
                master: false,
                count: 0,
                cursor: 0,
                frames: 0,
                translation: None,
                atu_readback: 0,
                atu_reads: 0,
                resets: 0,
                published_reset: None,
                retirement: Vec::new(),
                reject_bme_disable: false,
                maps: 0,
                unmaps: 0,
                cpu_syncs: 0,
                device_syncs: 0,
                device_owns: false,
                start_never: false,
                stop_never: false,
                reset_never: false,
                power_never: false,
                unmap_fail: false,
                sync_fail: false,
                drain_fail: false,
                drain_unavailable: false,
                drains: 0,
                coherent_reads: 0,
                coherence_unavailable: false,
                advance_on_coherent: None,
                accesses: Vec::new(),
                defer_payload: false,
                posted: Vec::new(),
                lost_read: None,
                fail_after_write: None,
                ignore_write: None,
                rollover: false,
                unstable: false,
                writes: Vec::new(),
                clock: Arc::new(AtomicU64::new(0)),
                jump_write: None,
                jump_read: None,
            }
        }
        fn read(&mut self, offset: usize) -> u32 {
            self.accesses.push((offset, false));
            assert!(
                !matches!(
                    offset,
                    0x102c | 0x141c | 0x1420 | 0x1424 | 0x1800 | 0x1804 | 0x1808
                ),
                "Renoir/CLKMUX-only read {offset:x}"
            );
            if offset == 0xc40 {
                self.atu_reads += 1;
                return self.atu_readback;
            }
            let value = if self.lost_read == Some(offset) {
                self.lost_read = None;
                u32::MAX
            } else if offset == 0x2c18 {
                if self.unstable {
                    self.count = self.count.wrapping_add(1u64 << 32);
                }
                (self.count >> 32) as u32
            } else if offset == 0x2c1c {
                if self.rollover {
                    self.rollover = false;
                    self.count += 8;
                }
                self.count as u32
            } else {
                self.words[offset / 4]
            };
            if let Some((at, ready, elapsed)) = self.jump_read
                && at == offset
                && ready == value
            {
                self.jump_read = None;
                self.clock.fetch_add(elapsed, Ordering::Relaxed);
            }
            if offset == 0x1000 && value == 0 {
                self.retirement.push(Retirement::ResetAcknowledged);
            }
            if offset == 0xc04 && value == 0 {
                self.retirement.push(Retirement::GroupDisabled);
            }
            value
        }
        fn write(&mut self, offset: usize, value: u32) {
            self.accesses.push((offset, true));
            assert!(
                !matches!(
                    offset,
                    0x102c | 0x141c | 0x1420 | 0x1424 | 0x1800 | 0x1804 | 0x1808
                ),
                "Renoir/CLKMUX-only write {offset:x}"
            );
            self.writes.push((offset, value));
            if self.ignore_write == Some(offset) {
                return;
            }
            match offset {
                0x1024 => {
                    let on = if matches!(self.identity.revision, 0x70..=0x72) {
                        0x1f
                    } else {
                        1
                    };
                    assert_eq!(value, on, "dedicated ACP63 has no source PGFSM-off request");
                    // Request acceptance and eventual completion are separate:
                    // the pinned power-on path must tolerate a valid command
                    // whose PGFSM status never reaches powered-on.
                    if !self.power_never {
                        self.words[0x1028 / 4] = 0;
                    }
                }
                0x1000 => {
                    self.words[offset / 4] = if self.reset_never || value == 1 {
                        0x10001
                    } else {
                        0
                    };
                    if value == 0 && !self.reset_never {
                        self.resets += 1;
                        // Do not clear group1: retirement must explicitly
                        // disable/read back the actual PAGE_BASE enable bit.
                        for register in [0x2c04, 0x2c08] {
                            self.words[register / 4] = 0;
                        }
                        self.cursor = 0;
                        self.count = 0;
                    }
                }
                0xc40 => {
                    assert_eq!(value, 1, "cache invalidation is a write-one command");
                    // Adversarial permitted read behavior, not a physical
                    // self-clear guarantee, ACK or payload-completion model.
                    self.words[offset / 4] = 0;
                }
                0x10004 if value & 0x8000_0000 != 0 => {
                    self.published_reset = Some(self.resets);
                    self.words[offset / 4] = value;
                }
                0x1a0c => self.words[offset / 4] &= !value, // Real W1C semantics.
                0x2c08 => {
                    if value == 1 {
                        assert!(self.master);
                        assert_eq!(self.words[0x1004 / 4], 1);
                        assert_eq!(self.words[0x1014 / 4], 0);
                        assert_eq!(self.words[0x2c60 / 4], 7);
                        assert_eq!(self.words[0x2c04 / 4], 1);
                        assert_eq!(self.words[0x2c28 / 4], 0);
                        assert_eq!(self.words[0x2c2c / 4], 2);
                        assert_ne!(self.words[0x1a04 / 4] & (1 << 29), 0);
                        assert_ne!(self.words[0x1a04 / 4] & (1 << 16), 0);
                        assert_eq!(self.words[0x1a00 / 4], 1);
                        assert!(self.device_owns);
                        self.cursor = 0;
                        // Request may retire while independent active status
                        // stays asserted. Source checks bit1, not exact3.
                        self.words[offset / 4] = if self.start_never { 1 } else { 2 };
                    } else if value == 2 && !self.stop_never {
                        self.words[offset / 4] = 0;
                    }
                }
                0x2c24 => {
                    assert_eq!(self.words[0x2c08 / 4], 0);
                    assert_eq!(self.words[0x2c04 / 4], 0);
                }
                _ => self.words[offset / 4] = value,
            }
            if let Some((at, request, elapsed)) = self.jump_write
                && at == offset
                && request == value
            {
                self.jump_write = None;
                self.clock.fetch_add(elapsed, Ordering::Relaxed);
            }
            if self.fail_after_write == Some(offset) {
                self.fail_after_write = None;
                self.lost_read = Some(offset);
            }
        }
        fn advance(&mut self, frames: usize) {
            if !self.master || self.words[0x2c08 / 4] & 2 == 0 {
                return;
            }
            assert!(self.device_owns);
            assert_eq!(self.words[0xc00 / 4], 2);
            assert_eq!(self.words[0xc04 / 4], 0x8380_0000);
            assert_eq!(self.words[0x2c0c / 4], 0x0400_0000);
            let ring = self.words[0x2c10 / 4] as usize;
            let period = self.words[0x2c20 / 4] as usize;
            for _ in 0..frames {
                for channel in 0..2 {
                    let offset = (self.cursor + channel * 4) % ring;
                    let entry = 0x10000 / 4 + offset / 4096 * 2;
                    let high = self.words[entry + 1];
                    assert_ne!(high & 0x8000_0000, 0);
                    let iova = u64::from(self.words[entry]) | u64::from(high & 0x7fff_ffff) << 32;
                    let translation = self.translation.as_ref().unwrap();
                    assert!(iova >= translation.token.address);
                    let mapped = (iova - translation.token.address) as usize + offset % 4096;
                    assert!(mapped + 4 <= translation.token.bytes);
                    // These physical pages are deliberately not contiguous;
                    // only the attached domain constructs the contiguous IOVA.
                    assert_eq!(
                        translation.pages.physical_pages()[mapped / 4096],
                        0x5000_0000 + (mapped / 4096) as u64 * 0x3000
                    );
                    let pointer = translation.cpu.address(mapped, 4).unwrap();
                    let sample = sample(self.frames, channel);
                    if self.defer_payload {
                        // A real fabric may still hold issued payload after
                        // the ACP counter and engine-stop acknowledgment.
                        self.posted.push((mapped, sample));
                    } else {
                        // SAFETY: this synchronous model owns DMA while active;
                        // actual retained CPU RAM is reached through its domain.
                        unsafe { pointer.as_ptr().cast::<i32>().write_volatile(sample) };
                    }
                }
                self.frames += 1;
                self.count = self.count.wrapping_add(8);
                self.cursor = (self.cursor + 8) % ring;
                if self.cursor.is_multiple_of(period) && !self.defer_payload {
                    // The ordinary model supplies the pinned source completed-
                    // period event only after its actual coherent payload.
                    // A deferred retirement fabric has not delivered that
                    // event; raw progress/stop acknowledgment alone cannot.
                    self.words[0x1a0c / 4] |= 1 << 16;
                }
            }
        }
    }
    fn sample(frame: u64, channel: usize) -> i32 {
        (frame.wrapping_mul(101) as i32)
            ^ if channel == 0 {
                0x1234_5600
            } else {
                -0x2345_6700
            }
    }
    struct Model(Arc<Mutex<Device>>);
    impl Registers for Model {
        fn region_bytes(&self) -> usize {
            0x11000
        }
        fn identity(&mut self) -> Result<Identity, Error> {
            Ok(self.0.lock().unwrap().identity)
        }
        fn set_bus_master(&mut self, enabled: bool) -> Result<(), Error> {
            let mut device = self.0.lock().unwrap();
            if !enabled && device.reject_bme_disable {
                return Err(Error::PciAuthority);
            }
            device.master = enabled;
            device.retirement.push(Retirement::BusMaster(enabled));
            Ok(())
        }
        fn read32(&mut self, offset: usize) -> u32 {
            self.0.lock().unwrap().read(offset)
        }
        fn write32(&mut self, offset: usize, value: u32) {
            self.0.lock().unwrap().write(offset, value)
        }
    }
    struct Domain(Arc<Mutex<Device>>);
    // SAFETY: isolated synchronous model, real owned CPU RAM and symbolic
    // physical/IOVA labels. Device accesses walk actual programmed ACP PTEs
    // through this domain; no identity DMA or production hardware is claimed.
    unsafe impl DmaDomain for Domain {
        unsafe fn map(
            &self,
            pages: &DmaPages,
            direction: DmaDirection,
            limit: u64,
        ) -> Result<DomainMapping, DmaError> {
            assert_eq!(direction, DmaDirection::FromDevice);
            if IOVA + pages.bytes() as u64 - 1 > limit {
                return Err(DmaError::AddressLimit);
            }
            let mut device = self.0.lock().unwrap();
            assert!(device.translation.is_none());
            device.published_reset = None;
            device.maps += 1;
            let token = DomainMapping {
                id: device.maps as u64,
                address: IOVA,
                bytes: pages.bytes(),
            };
            device.translation = Some(Translation {
                token,
                cpu: pages
                    .as_single()
                    .unwrap()
                    .cpu_mapping(CacheAttribute::WriteBack)
                    .unwrap(),
                pages: pages.clone(),
            });
            Ok(token)
        }
        unsafe fn unmap(&self, token: DomainMapping) -> Result<(), DmaError> {
            let mut device = self.0.lock().unwrap();
            assert_eq!(device.words[0x2c08 / 4], 0);
            assert!(!device.master);
            assert_eq!(device.words[0x2c04 / 4], 0);
            assert_eq!(device.words[0xc04 / 4] & 0x8000_0000, 0);
            if let Some(published) = device.published_reset {
                assert!(device.resets > published, "release requires a fresh reset");
                let last = |effect| {
                    device
                        .retirement
                        .iter()
                        .rposition(|e| *e == effect)
                        .unwrap()
                };
                assert!(last(Retirement::ResetAcknowledged) < last(Retirement::GroupDisabled));
                assert!(last(Retirement::GroupDisabled) < last(Retirement::BusMaster(false)));
                assert!(last(Retirement::BusMaster(false)) < last(Retirement::PayloadDrained));
            }
            assert_eq!(device.translation.as_ref().unwrap().token, token);
            assert!(
                device.posted.is_empty(),
                "unmap before actual payload drain"
            );
            if device.unmap_fail {
                return Err(DmaError::InvalidationFailed);
            }
            device.translation = None;
            device.unmaps += 1;
            Ok(())
        }
        unsafe fn sync_for_device(
            &self,
            token: DomainMapping,
            range: Range<usize>,
            direction: DmaDirection,
        ) -> Result<(), DmaError> {
            let mut device = self.0.lock().unwrap();
            assert_eq!(direction, DmaDirection::FromDevice);
            assert_eq!(device.words[0x2c08 / 4], 0);
            assert_eq!(device.translation.as_ref().unwrap().token, token);
            assert!(range.end <= token.bytes);
            if device.sync_fail {
                return Err(DmaError::VisibilityFailed);
            }
            device.device_syncs += 1;
            device.device_owns = true;
            Ok(())
        }
        unsafe fn sync_for_cpu(
            &self,
            token: DomainMapping,
            range: Range<usize>,
            direction: DmaDirection,
        ) -> Result<(), DmaError> {
            let mut device = self.0.lock().unwrap();
            assert_eq!(direction, DmaDirection::FromDevice);
            assert_eq!(device.words[0x2c08 / 4], 0);
            assert_eq!(device.words[0x2c04 / 4], 0);
            assert_eq!(device.translation.as_ref().unwrap().token, token);
            assert!(range.end <= token.bytes);
            if device.sync_fail {
                return Err(DmaError::VisibilityFailed);
            }
            assert!(
                device.posted.is_empty(),
                "CPU handoff before actual payload drain"
            );
            device.cpu_syncs += 1;
            device.device_owns = false;
            Ok(())
        }
        unsafe fn read_coherent_u32(
            &self,
            token: DomainMapping,
            offset: usize,
            direction: DmaDirection,
        ) -> Result<u32, DmaError> {
            let mut device = self.0.lock().unwrap();
            assert_eq!(direction, DmaDirection::FromDevice);
            assert!(offset.is_multiple_of(4));
            assert!(offset + 4 <= token.bytes);
            assert_eq!(device.translation.as_ref().unwrap().token, token);
            assert!(device.device_owns);
            if device.coherence_unavailable {
                return Err(DmaError::CoherenceUnavailable);
            }
            let pointer = device
                .translation
                .as_ref()
                .unwrap()
                .cpu
                .address(offset, 4)
                .unwrap();
            // SAFETY: actual model-owned retained mapping, per-word coherent
            // observation; no CPU writers or ownership transfer are invented.
            let observed = unsafe { pointer.as_ptr().cast::<u32>().read_volatile() };
            device.coherent_reads += 1;
            if let Some((at, frames)) = device.advance_on_coherent
                && at == device.coherent_reads
            {
                device.advance_on_coherent = None;
                // Source-completed producer progress races this individual
                // word observation, including wrap into its oldest period.
                device.advance(frames);
            }
            Ok(u32::from_le(observed))
        }
        unsafe fn drain_posted_writes(&self) -> Result<(), DmaError> {
            let mut device = self.0.lock().unwrap();
            assert_eq!(device.words[0x2c08 / 4], 0);
            assert_eq!(device.words[0x2c04 / 4], 0);
            if device.drain_unavailable {
                return Err(DmaError::DrainUnavailable);
            }
            if device.drain_fail {
                return Err(DmaError::InvalidationFailed);
            }
            device.drains += 1;
            device.retirement.push(Retirement::PayloadDrained);
            let pending = core::mem::take(&mut device.posted);
            for (offset, sample) in pending {
                let translation = device.translation.as_ref().unwrap();
                let pointer = translation.cpu.address(offset, 4).unwrap();
                // SAFETY: this independent fabric completion finishes its
                // queued writes into the exact retained domain mapping.
                unsafe { pointer.as_ptr().cast::<i32>().write_volatile(sample) };
            }
            Ok(())
        }
    }
    struct Time(Arc<AtomicU64>);
    impl Timer for Time {
        fn now_us(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
        fn relax(&self) {
            self.0.fetch_add(10, Ordering::Relaxed);
        }
    }
    fn config() -> Config {
        Config {
            ownership: Ownership::ExclusiveDirect,
            child: Some(DmicChild {
                address: 2,
                audio_device_type: 2,
            }),
            wov: WovObservation::Value(1),
            soundwire: SoundWireOwnership::EnumeratedAbsent,
            acp_config: Some(0),
            dma_address_bits: 40,
            gain: 3,
        }
    }
    fn fixture(revision: u8) -> (Controller<Model, Time>, Arc<Mutex<Device>>, Source) {
        let device = Arc::new(Mutex::new(Device::new(revision)));
        let clock = device.lock().unwrap().clock.clone();
        // SAFETY: this isolated model supplies every source/ownership boundary;
        // the modeled domain is tied to exactly this modeled PCI function.
        let controller = unsafe {
            Controller::claim(
                Model(device.clone()),
                Time(clock),
                config(),
                Arc::new(Domain(device.clone())),
            )
        }
        .unwrap();
        (
            controller,
            device,
            Source {
                drops: Arc::new(AtomicUsize::new(0)),
                geometry: 12,
            },
        )
    }
    fn ready(revision: u8, period: usize) -> (Controller<Model, Time>, Arc<Mutex<Device>>, Source) {
        let (mut controller, device, source) = fixture(revision);
        controller.initialize().unwrap();
        controller
            .prepare_capture(&source, CAPTURE_FORMAT, period)
            .unwrap();
        (controller, device, source)
    }

    #[test]
    fn peer_power_request_validation_is_independent_of_completion() {
        for revision in [0x63, 0x70, 0x71, 0x72] {
            let on = if revision == 0x63 { 1 } else { 0x1f };
            for stalled in [false, true] {
                let mut device = Device::new(revision);
                device.power_never = stalled;
                device.write(0x1024, on);
                assert_eq!(device.words[0x1028 / 4], if stalled { 2 } else { 0 });
                assert_eq!(device.writes, [(0x1024, on)]);
                assert_eq!(device.resets, 0);
                assert!(!device.master);
                assert_eq!(device.maps, 0);
            }
            // A completion fault must never turn a power-off, reserved value,
            // or another generation's request into a permitted command.
            for stalled in [false, true] {
                for request in [0, 2, 3, u32::MAX, if on == 1 { 0x1f } else { 1 }] {
                    let mut device = Device::new(revision);
                    device.power_never = stalled;
                    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        device.write(0x1024, request);
                    }));
                    assert!(refused.is_err());
                    assert_eq!(device.words[0x1028 / 4], 2);
                    assert_eq!(device.resets, 0);
                    assert!(!device.master);
                    assert_eq!(device.maps, 0);
                }
            }
        }
    }

    #[test]
    fn actual_pte_capture_pcm_wraps_stop_restart_and_acknowledged_release() {
        for (revision, period) in [(0x63, 4096), (0x63, 8192), (0x63, 5000)] {
            let (mut controller, device, source) = ready(revision, period);
            let ring = period * 4;
            assert_eq!(controller.buffer_bytes(), Some(ring));
            let capture = controller.capture.as_ref().unwrap();
            // SAFETY: prepared DMA has never started; take actual CPU cache
            // ownership before poisoning, then start must hand it back.
            unsafe { capture.dma.sync_for_cpu(0..capture.cpu.bytes()) }.unwrap();
            for offset in 0..capture.cpu.bytes() {
                // SAFETY: DMA has not started; poison the actual CPU allocation.
                unsafe {
                    capture
                        .cpu
                        .address(offset, 1)
                        .unwrap()
                        .as_ptr()
                        .write_volatile(0xa5)
                };
            }
            assert_eq!(controller.stop(), Err(Error::NotPrepared));
            assert_eq!(controller.state(), State::Prepared);
            controller.start().unwrap();
            assert_eq!(device.lock().unwrap().words[0x2c5c / 4], 0x6018);
            let mut untouched = [0xa5; 16];
            assert_eq!(
                controller.copy_stopped_ring(0, &mut untouched),
                Err(Error::Busy)
            );
            assert_eq!(untouched, [0xa5; 16]);
            // Coalesced period delivery and more than five real ring wraps.
            let frames = ring / 8 * 5 + 17;
            device.lock().unwrap().advance(frames);
            device.lock().unwrap().words[0x1a0c / 4] |= 1 << 7;
            let position = controller.position().unwrap();
            assert_eq!(position.bytes, (frames * 8) as u64);
            assert_eq!(position.ring_offset, 17 * 8);
            assert!(position.period_pending);
            assert_eq!(device.lock().unwrap().words[0x1a0c / 4], 1 << 7); // No unrelated W1C acknowledgement.
            controller.stop().unwrap();
            let mut pcm = vec![0; ring];
            controller.copy_stopped_ring(0, &mut pcm).unwrap();
            for (index, frame) in pcm.as_chunks::<8>().0.iter().enumerate() {
                let latest_frame = if index < 17 {
                    ring / 8 * 5 + index
                } else {
                    ring / 8 * 4 + index
                };
                assert_eq!(&frame[..4], sample(latest_frame as u64, 0).to_le_bytes());
                assert_eq!(&frame[4..], sample(latest_frame as u64, 1).to_le_bytes());
            }
            assert!(source.drops.load(Ordering::Relaxed) == 0);
            controller.start().unwrap();
            device.lock().unwrap().advance(10);
            controller.stop().unwrap();
            assert_eq!(controller.position().unwrap().bytes, 80);
            controller.shutdown().unwrap();
            assert_eq!(controller.state(), State::Shutdown);
            assert_eq!(source.drops.load(Ordering::Relaxed), 1);
            assert_eq!(device.lock().unwrap().unmaps, 1);
            assert!(controller.into_stopped().is_ok());
        }
    }

    #[test]
    fn first_failure_survives_needs_reset_cleanup_errors_and_successful_recovery() {
        let (mut controller, device, source) = ready(0x63, 4096);
        assert_eq!(controller.first_error(), None);
        controller.start().unwrap();
        device.lock().unwrap().words[0x1a0c / 4] |= 1 << 29;
        assert_eq!(controller.position(), Err(Error::DmaFault(1 << 29)));
        assert_eq!(controller.first_error(), Some(Error::DmaFault(1 << 29)));
        assert_eq!(controller.start(), Err(Error::NeedsReset));
        device.lock().unwrap().stop_never = true;
        assert_eq!(controller.shutdown(), Err(Error::Timeout(Phase::DmaStop)));
        assert_eq!(controller.first_error(), Some(Error::DmaFault(1 << 29)));
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        device.lock().unwrap().stop_never = false;
        // Source diagnostics remain observable even after successful cleanup.
        controller.shutdown().unwrap();
        assert_eq!(controller.first_error(), Some(Error::DmaFault(1 << 29)));
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);

        let (mut controller, device, source) = fixture(0x63);
        device.lock().unwrap().power_never = true;
        assert_eq!(controller.initialize(), Err(Error::Timeout(Phase::PowerOn)));
        assert_eq!(controller.state(), State::Faulted);
        assert!(controller.capture.is_none());
        {
            let model = device.lock().unwrap();
            assert_eq!(model.words[0x1028 / 4], 2);
            assert_eq!(model.writes, [(0x1024, 1)]);
            assert_eq!(model.resets, 0);
            assert!(!model.master);
            assert_eq!(model.maps, 0);
        }
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        assert_eq!(
            controller.first_error(),
            Some(Error::Timeout(Phase::PowerOn))
        );
        device.lock().unwrap().power_never = false;
        controller.initialize().unwrap();
        assert_eq!(controller.state(), State::Ready);
        assert_eq!(
            controller.first_error(),
            Some(Error::Timeout(Phase::PowerOn))
        );
        controller
            .prepare_capture(&source, CAPTURE_FORMAT, 4096)
            .unwrap();
        controller.start().unwrap();
        controller.shutdown().unwrap();
        assert_eq!(
            controller.first_error(),
            Some(Error::Timeout(Phase::PowerOn))
        );
    }

    #[test]
    fn continuous_actual_completed_periods_cross_wraps_without_stopping_dma() {
        let (mut controller, device, source) = ready(0x63, 4096);
        controller.start().unwrap();
        let mut pcm = vec![0xa5; 4096];
        assert_eq!(controller.capture_period(&mut pcm).unwrap(), None);
        assert!(pcm.iter().all(|byte| *byte == 0xa5));
        for period in 0..24 {
            device.lock().unwrap().advance(512);
            device.lock().unwrap().accesses.clear();
            assert_eq!(
                controller.capture_period(&mut pcm).unwrap(),
                Some(CapturePeriod {
                    first_frame: period * 512,
                    frames: 512
                })
            );
            let model = device.lock().unwrap();
            assert_eq!(model.words[0x2c08 / 4] & 2, 2);
            assert_eq!(model.words[0x2c04 / 4], 1);
            assert_eq!(model.cpu_syncs, 0);
            assert_eq!(model.words[0x1a0c / 4] & (1 << 16), 0);
            // Actual source ISR acknowledges period before pointer sampling.
            let ack = model
                .accesses
                .iter()
                .position(|entry| *entry == (0x1a0c, true))
                .unwrap();
            let counter = model
                .accesses
                .iter()
                .position(|entry| *entry == (0x2c18, false))
                .unwrap();
            assert!(ack < counter);
            drop(model);
            for frame in 0..512 {
                for channel in 0..2 {
                    let offset = frame * 8 + channel * 4;
                    assert_eq!(
                        i32::from_le_bytes(pcm[offset..offset + 4].try_into().unwrap()),
                        sample(period * 512 + frame as u64, channel)
                    );
                }
            }
        }
        let model = device.lock().unwrap();
        assert_eq!(
            model
                .writes
                .iter()
                .filter(|entry| **entry == (0x2c08, 1))
                .count(),
            1
        );
        assert_eq!(
            model
                .writes
                .iter()
                .filter(|entry| **entry == (0x2c08, 2))
                .count(),
            0
        );
        drop(model);
        controller.shutdown().unwrap();
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn continuous_coalesced_irq_position_ack_and_partial_frame_are_not_fake_periods() {
        let (mut controller, device, _) = ready(0x63, 4096);
        controller.start().unwrap();
        let mut pcm = vec![0xa5; 4096];
        // Counter progress without the source completion event is positioning,
        // never an independent grant to publish newly captured PCM.
        device.lock().unwrap().advance(512);
        device.lock().unwrap().words[0x1a0c / 4] &= !(1 << 16);
        assert_eq!(controller.capture_period(&mut pcm).unwrap(), None);
        assert!(pcm.iter().all(|byte| *byte == 0xa5));
        device.lock().unwrap().advance(1024);
        assert!(controller.position().unwrap().period_pending);
        // External position polling consumed the W1C status, not completed PCM.
        assert_eq!(device.lock().unwrap().words[0x1a0c / 4] & (1 << 16), 0);
        for index in 0..3 {
            assert_eq!(
                controller.capture_period(&mut pcm).unwrap(),
                Some(CapturePeriod {
                    first_frame: index * 512,
                    frames: 512
                })
            );
            for channel in 0..2 {
                assert_eq!(
                    i32::from_le_bytes(pcm[channel * 4..channel * 4 + 4].try_into().unwrap()),
                    sample(index * 512, channel)
                );
            }
        }
        assert_eq!(controller.capture_period(&mut pcm).unwrap(), None);
        device.lock().unwrap().advance(512);
        // The next hardware frame is only partly counted; no partial-frame
        // bytes are included in the completed preceding period.
        device.lock().unwrap().count += 4;
        assert_eq!(
            controller.capture_period(&mut pcm).unwrap(),
            Some(CapturePeriod {
                first_frame: 1536,
                frames: 512
            })
        );
        assert_eq!(controller.capture_period(&mut pcm).unwrap(), None);
        controller.shutdown().unwrap();
    }

    #[test]
    fn continuous_late_or_mid_copy_overwrite_quarantines_without_consuming_bad_period() {
        for mid_copy in [false, true] {
            let (mut controller, device, source) = ready(0x63, 4096);
            controller.start().unwrap();
            let mut pcm = vec![0xa5; 4096];
            if mid_copy {
                device.lock().unwrap().advance(512);
                let next = device.lock().unwrap().coherent_reads + 16;
                device.lock().unwrap().advance_on_coherent = Some((next, 2048));
            } else {
                device.lock().unwrap().advance(2048);
            }
            let expected = Error::CaptureOverrun {
                produced: if mid_copy { 20_480 } else { 16_384 },
                consumed: 0,
            };
            assert_eq!(controller.capture_period(&mut pcm), Err(expected));
            assert_eq!(controller.first_error(), Some(expected));
            assert_eq!(controller.state(), State::Faulted);
            assert_eq!(controller.capture_period(&mut pcm), Err(Error::NeedsReset));
            if !mid_copy {
                assert!(pcm.iter().all(|byte| *byte == 0xa5));
            }
            assert_eq!(device.lock().unwrap().cpu_syncs, 0);
            assert_eq!(source.drops.load(Ordering::Relaxed), 0);
            controller.initialize().unwrap();
            controller
                .prepare_capture(&source, CAPTURE_FORMAT, 4096)
                .unwrap();
            controller.start().unwrap();
            device.lock().unwrap().advance(512);
            assert!(controller.capture_period(&mut pcm).unwrap().is_some());
            controller.shutdown().unwrap();
            assert_eq!(source.drops.load(Ordering::Relaxed), 2);
            assert_eq!(controller.first_error(), Some(expected));
        }
    }

    #[test]
    fn continuous_coherency_is_actual_and_invalid_destinations_have_no_effects() {
        let (mut controller, device, source) = fixture(0x63);
        controller.initialize().unwrap();
        device.lock().unwrap().coherence_unavailable = true;
        assert_eq!(
            controller.prepare_capture(&source, CAPTURE_FORMAT, 4096),
            Err(Error::Dma(DmaError::CoherenceUnavailable))
        );
        assert_eq!(device.lock().unwrap().maps, 1);
        assert_eq!(device.lock().unwrap().unmaps, 1);
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        assert!(
            !device
                .lock()
                .unwrap()
                .writes
                .iter()
                .any(|(offset, _)| *offset >= 0x10000)
        );
        device.lock().unwrap().coherence_unavailable = false;
        controller.initialize().unwrap();
        controller
            .prepare_capture(&source, CAPTURE_FORMAT, 4096)
            .unwrap();
        controller.start().unwrap();
        let before = device.lock().unwrap().accesses.len();
        for bytes in [0, 8, 4092, 4100] {
            assert_eq!(
                controller.capture_period(&mut vec![0xa5; bytes]),
                Err(Error::InvalidBuffer)
            );
        }
        assert_eq!(device.lock().unwrap().accesses.len(), before);
        device.lock().unwrap().advance(512);
        device.lock().unwrap().coherence_unavailable = true;
        assert_eq!(
            controller.capture_period(&mut vec![0xa5; 4096]),
            Err(Error::Dma(DmaError::CoherenceUnavailable))
        );
        assert_eq!(controller.state(), State::Faulted);
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        device.lock().unwrap().coherence_unavailable = false;
        controller.shutdown().unwrap();
        assert_eq!(source.drops.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn missing_actual_payload_completion_service_refuses_before_first_dma_publication() {
        let (mut controller, device, source) = fixture(0x63);
        device.lock().unwrap().drain_unavailable = true;
        assert_eq!(
            controller.initialize(),
            Err(Error::Dma(DmaError::DrainUnavailable))
        );
        assert_eq!(controller.state(), State::Faulted);
        assert_eq!(
            controller.first_error(),
            Some(Error::Dma(DmaError::DrainUnavailable))
        );
        assert_eq!(controller.start(), Err(Error::NeedsReset));
        assert_eq!(device.lock().unwrap().maps, 0);
        assert!(
            !device
                .lock()
                .unwrap()
                .writes
                .iter()
                .any(|(offset, _)| *offset >= 0x10000)
        );
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        device.lock().unwrap().drain_unavailable = false;
        controller.initialize().unwrap();
        controller
            .prepare_capture(&source, CAPTURE_FORMAT, 4096)
            .unwrap();
        controller.start().unwrap();
        controller.shutdown().unwrap();
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        assert_eq!(
            controller.first_error(),
            Some(Error::Dma(DmaError::DrainUnavailable))
        );
    }

    #[test]
    fn posted_payload_requires_actual_domain_completion_before_cpu_or_release() {
        let (mut controller, device, source) = ready(0x63, 4096);
        controller.start().unwrap();
        device.lock().unwrap().defer_payload = true;
        device.lock().unwrap().advance(512);
        // Raw hardware progress precedes independently queued payload, but
        // this fabric has not supplied a source completed-period event.
        assert_eq!(controller.position().unwrap().bytes, 4096);
        assert_eq!(device.lock().unwrap().posted.len(), 1024);
        let mut untouched = vec![0xa5; 4096];
        assert_eq!(controller.capture_period(&mut untouched).unwrap(), None);
        assert!(untouched.iter().all(|byte| *byte == 0xa5));
        device.lock().unwrap().drain_fail = true;
        assert_eq!(
            controller.stop(),
            Err(Error::Dma(DmaError::InvalidationFailed))
        );
        assert_eq!(controller.state(), State::Faulted);
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        assert_eq!(device.lock().unwrap().unmaps, 0);
        assert_eq!(device.lock().unwrap().cpu_syncs, 0);
        assert_eq!(device.lock().unwrap().posted.len(), 1024);
        device.lock().unwrap().drain_fail = false;
        device.lock().unwrap().drain_unavailable = true;
        assert_eq!(
            controller.initialize(),
            Err(Error::Dma(DmaError::DrainUnavailable))
        );
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        assert_eq!(device.lock().unwrap().posted.len(), 1024);
        device.lock().unwrap().drain_unavailable = false;
        controller.initialize().unwrap();
        assert!(device.lock().unwrap().posted.is_empty());
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        assert_eq!(
            controller.first_error(),
            Some(Error::Dma(DmaError::InvalidationFailed))
        );
        controller
            .prepare_capture(&source, CAPTURE_FORMAT, 4096)
            .unwrap();
        controller.start().unwrap();
        device.lock().unwrap().advance(512);
        controller.stop().unwrap();
        let mut pcm = vec![0; 4096];
        let drains = device.lock().unwrap().drains;
        controller.copy_stopped_ring(0, &mut pcm).unwrap();
        assert_eq!(device.lock().unwrap().drains, drains + 1);
        assert_eq!(device.lock().unwrap().cpu_syncs, 1);
        for frame in 0..512 {
            for channel in 0..2 {
                let offset = frame * 8 + channel * 4;
                assert_eq!(
                    i32::from_le_bytes(pcm[offset..offset + 4].try_into().unwrap()),
                    sample((512 + frame) as u64, channel)
                );
            }
        }
        controller.shutdown().unwrap();
        assert_eq!(source.drops.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn format_geometry_and_address_ceiling_refuse_before_dma_publication() {
        let (mut controller, device, mut source) = fixture(0x63);
        controller.initialize().unwrap();
        let before = device.lock().unwrap().writes.len();
        for format in [
            PcmFormat {
                bits: 24,
                ..CAPTURE_FORMAT
            },
            PcmFormat {
                channels: 1,
                ..CAPTURE_FORMAT
            },
            PcmFormat {
                rate: 96_000,
                ..CAPTURE_FORMAT
            },
        ] {
            assert_eq!(
                controller.prepare_capture(&source, format, 4096),
                Err(Error::InvalidFormat)
            );
        }
        for period in [0, 4095, 4097, 8193, usize::MAX] {
            assert_eq!(
                controller.prepare_capture(&source, CAPTURE_FORMAT, period),
                Err(Error::InvalidBuffer)
            );
        }
        assert_eq!(device.lock().unwrap().writes.len(), before);
        source.geometry = 13;
        assert_eq!(
            controller.prepare_capture(&source, CAPTURE_FORMAT, 4096),
            Err(Error::InvalidBuffer)
        );
        assert_eq!(device.lock().unwrap().maps, 0);
        for (base, bytes, bits) in [
            (0, 4096, 40),
            (4097, 4096, 40),
            (1u64 << 40, 4096, 40),
            ((1u64 << 63) - 4096, 8192, 63),
        ] {
            assert_eq!(
                check_dma_range(base, bytes, bytes, bits),
                Err(Error::DmaAddress)
            );
        }
        assert_eq!(check_dma_range((1u64 << 63) - 4096, 4096, 4096, 63), Ok(()));
        controller.shutdown().unwrap();
    }

    #[test]
    fn independent_counter_rollover_and_wrap_are_not_torn_or_truncated() {
        let (mut controller, device, _) = ready(0x63, 4096);
        device.lock().unwrap().count = u64::MAX - 15;
        controller.start().unwrap();
        device.lock().unwrap().advance(4);
        assert_eq!(controller.position().unwrap().bytes, 32);
        controller.stop().unwrap();
        device.lock().unwrap().count = 0xffff_fff8;
        controller.start().unwrap();
        device.lock().unwrap().rollover = true;
        assert_eq!(controller.position().unwrap().bytes, 8);
        device.lock().unwrap().unstable = true;
        assert_eq!(controller.position(), Err(Error::CounterUnstable));
        assert_eq!(controller.state(), State::Faulted);
        device.lock().unwrap().unstable = false;
        controller.shutdown().unwrap();
    }

    #[test]
    fn late_start_acknowledgement_stop_reset_and_unmap_failures_retain_exact_owners() {
        for fault in [0, 1, 2, 3] {
            let (mut controller, device, source) = ready(0x63, 4096);
            if fault == 0 {
                device.lock().unwrap().fail_after_write = Some(0x2c08);
            }
            if fault == 1 {
                device.lock().unwrap().start_never = true;
            }
            let start = controller.start();
            if fault <= 1 {
                assert!(start.is_err());
                assert_eq!(controller.state(), State::Faulted);
                assert_eq!(controller.start(), Err(Error::NeedsReset));
            } else {
                start.unwrap();
            }
            if fault == 2 {
                device.lock().unwrap().stop_never = true;
            }
            if fault == 3 {
                device.lock().unwrap().reset_never = true;
            }
            if fault >= 2 {
                assert!(controller.shutdown().is_err());
            }
            assert_eq!(source.drops.load(Ordering::Relaxed), 0);
            assert!(controller.capture.is_some());
            {
                let mut model = device.lock().unwrap();
                model.start_never = false;
                model.stop_never = false;
                model.reset_never = false;
                model.unmap_fail = true;
            }
            assert_eq!(
                controller.shutdown(),
                Err(Error::Dma(DmaError::InvalidationFailed))
            );
            assert_eq!(source.drops.load(Ordering::Relaxed), 0);
            assert!(controller.capture.is_some());
            device.lock().unwrap().unmap_fail = false;
            controller.shutdown().unwrap();
            assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn live_map_error_enable_zsc_and_identity_loss_quarantine_old_pcm_and_shutdown_is_safe() {
        for fault in 0..9 {
            let (mut controller, device, source) = ready(0x63, 4096);
            controller.start().unwrap();
            {
                let mut model = device.lock().unwrap();
                match fault {
                    0 => model.words[0x10004 / 4] ^= 1,
                    1 => model.words[0x1a04 / 4] &= !(1 << 29),
                    2 => model.words[0x1014 / 4] = 1,
                    3 => model.identity.device ^= 1,
                    4 => model.words[0x1a0c / 4] |= 1 << 29,
                    5 => model.words[0x2c28 / 4] = 1,
                    6 => model.words[0x2c2c / 4] = 3,
                    7 => model.words[0x2c60 / 4] = 0,
                    _ => model.words[0x2c5c / 4] ^= 1 << 3,
                }
            }
            assert!(controller.position().is_err());
            assert_eq!(controller.state(), State::Faulted);
            assert_eq!(controller.start(), Err(Error::NeedsReset));
            assert_eq!(source.drops.load(Ordering::Relaxed), 0);
            if fault == 3 {
                let writes = device.lock().unwrap().writes.len();
                assert_eq!(controller.shutdown(), Err(Error::AuthorityChanged));
                assert_eq!(device.lock().unwrap().writes.len(), writes);
                device.lock().unwrap().identity.device ^= 1;
            }
            controller.shutdown().unwrap();
            assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn partial_pte_write_unpublished_visibility_failure_and_reset_reconfiguration() {
        for late in [false, true] {
            let (mut controller, device, source) = fixture(0x63);
            controller.initialize().unwrap();
            if late {
                device.lock().unwrap().fail_after_write = Some(0x10004);
            } else {
                device.lock().unwrap().sync_fail = true;
            }
            assert!(
                controller
                    .prepare_capture(&source, CAPTURE_FORMAT, 8192)
                    .is_err()
            );
            assert_eq!(controller.state(), State::Faulted);
            assert_eq!(source.drops.load(Ordering::Relaxed), usize::from(!late));
            assert_eq!(controller.capture.is_some(), late);
            device.lock().unwrap().sync_fail = false;
            controller.initialize().unwrap();
            controller
                .prepare_capture(&source, CAPTURE_FORMAT, 4096)
                .unwrap();
            assert_eq!(device.lock().unwrap().words[0x10000 / 4], IOVA as u32);
            assert_eq!(
                device.lock().unwrap().words[0x10004 / 4],
                (IOVA >> 32) as u32 | 0x8000_0000
            );
            assert_eq!(device.lock().unwrap().words[(0x10000 + 7 * 8 + 4) / 4], 0);
            controller.start().unwrap();
            device.lock().unwrap().advance(20);
            controller.shutdown().unwrap();
            assert_eq!(source.drops.load(Ordering::Relaxed), 2);
        }
    }

    #[test]
    fn power_zsc_and_actual_iova_limit_failures_do_not_publish_dma() {
        let (mut controller, device, source) = fixture(0x63);
        device.lock().unwrap().power_never = true;
        assert_eq!(controller.initialize(), Err(Error::Timeout(Phase::PowerOn)));
        assert_eq!(controller.state(), State::Faulted);
        assert!(controller.capture.is_none());
        {
            let model = device.lock().unwrap();
            assert_eq!(model.words[0x1028 / 4], 2);
            assert_eq!(model.writes, [(0x1024, 1)]);
            assert_eq!(model.resets, 0);
            assert!(!model.master);
            assert_eq!(model.maps, 0);
        }
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        assert_eq!(device.lock().unwrap().maps, 0);
        device.lock().unwrap().power_never = false;
        device.lock().unwrap().ignore_write = Some(0x1014);
        assert_eq!(
            controller.initialize(),
            Err(Error::RegisterRejected(ZSC_CONTROL))
        );
        device.lock().unwrap().ignore_write = None;
        controller.initialize().unwrap();
        // Narrow the platform ceiling before allocating anything. The real
        // model domain refuses its high IOVA; no PA fallback is permitted.
        controller.config.dma_address_bits = 32;
        assert_eq!(
            controller.prepare_capture(&source, CAPTURE_FORMAT, 4096),
            Err(Error::Dma(DmaError::AddressLimit))
        );
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        assert_eq!(device.lock().unwrap().maps, 0);
        assert!(controller.capture.is_none());
        assert!(
            !device
                .lock()
                .unwrap()
                .writes
                .iter()
                .any(|(offset, _)| *offset == 0x10000)
        );
        controller.shutdown().unwrap();
    }

    #[test]
    fn successful_but_late_power_and_reset_accesses_do_not_advance_initialization() {
        // Both a successful request effect and its successful ready read must
        // fit the phase budget. The clock advances inside that actual access.
        for write in [false, true] {
            for (offset, request, ready, phase) in [
                (0x1024, 1, 0, Phase::PowerOn),
                (0x1000, 1, 0x10001, Phase::ResetAssert),
                (0x1000, 0, 0, Phase::ResetClear),
            ] {
                let (mut controller, device, source) = fixture(0x63);
                {
                    let mut model = device.lock().unwrap();
                    if write {
                        model.jump_write = Some((offset, request, 501));
                    } else {
                        model.jump_read = Some((
                            if phase == Phase::PowerOn {
                                0x1028
                            } else {
                                offset
                            },
                            ready,
                            501,
                        ));
                    }
                }
                assert_eq!(controller.initialize(), Err(Error::Timeout(phase)));
                assert_eq!(controller.state(), State::Faulted);
                assert_eq!(device.lock().unwrap().maps, 0);
                assert!(
                    !device
                        .lock()
                        .unwrap()
                        .writes
                        .iter()
                        .any(|(at, _)| *at == 0x1014)
                );
                if phase == Phase::PowerOn {
                    assert!(
                        !device
                            .lock()
                            .unwrap()
                            .writes
                            .iter()
                            .any(|(at, _)| *at == 0x1004)
                    );
                }
                controller.initialize().unwrap();
                controller
                    .prepare_capture(&source, CAPTURE_FORMAT, 4096)
                    .unwrap();
                controller.start().unwrap();
                device.lock().unwrap().advance(16);
                controller.shutdown().unwrap();
                assert_eq!(source.drops.load(Ordering::Relaxed), 1);
            }
        }
        // An already-on first read is still a physical phase access.
        let (mut controller, device, _) = fixture(0x63);
        {
            let mut model = device.lock().unwrap();
            model.words[0x1028 / 4] = 0;
            model.jump_read = Some((0x1028, 0, 501));
        }
        assert_eq!(controller.initialize(), Err(Error::Timeout(Phase::PowerOn)));
        assert!(device.lock().unwrap().writes.is_empty());
        controller.shutdown().unwrap();
    }

    #[test]
    fn successful_but_late_dma_and_reset_completion_retains_pins_until_fresh_recovery() {
        for write in [false, true] {
            for phase in [
                Phase::DmaStart,
                Phase::DmaStop,
                Phase::ResetAssert,
                Phase::ResetClear,
            ] {
                let (mut controller, device, source) = ready(0x63, 4096);
                if phase != Phase::DmaStart {
                    controller.start().unwrap();
                    device.lock().unwrap().advance(32);
                }
                let (offset, request, ready, budget) = match phase {
                    Phase::DmaStart => (0x2c08, 1, 2, 100_001),
                    Phase::DmaStop => (0x2c08, 2, 0, 100_001),
                    Phase::ResetAssert => (0x1000, 1, 0x10001, 501),
                    Phase::ResetClear => (0x1000, 0, 0, 501),
                    _ => unreachable!(),
                };
                {
                    let mut model = device.lock().unwrap();
                    if write {
                        model.jump_write = Some((offset, request, budget));
                    } else {
                        model.jump_read = Some((offset, ready, budget));
                    }
                }
                let result = match phase {
                    Phase::DmaStart => controller.start(),
                    Phase::DmaStop => controller.stop(),
                    _ => controller.shutdown(),
                };
                assert_eq!(result, Err(Error::Timeout(phase)));
                assert_eq!(controller.state(), State::Faulted);
                assert_eq!(controller.start(), Err(Error::NeedsReset));
                assert_eq!(source.drops.load(Ordering::Relaxed), 0);
                assert_eq!(device.lock().unwrap().unmaps, 0);
                assert!(controller.capture.is_some());
                if phase == Phase::DmaStop {
                    // A late actual stop must not silently advance to PDM/FIFO
                    // quiet or unmap within the failed operation.
                    assert_eq!(device.lock().unwrap().words[0x2c04 / 4], 1);
                }
                controller.shutdown().unwrap();
                assert_eq!(source.drops.load(Ordering::Relaxed), 1);
            }
        }
        // A successful late PDM clock effect cannot enable BME or submit DMA.
        let (mut controller, device, source) = ready(0x63, 4096);
        device.lock().unwrap().jump_write = Some((0x2c60, 7, 100_001));
        assert_eq!(controller.start(), Err(Error::Timeout(Phase::DmaStart)));
        assert!(!device.lock().unwrap().master);
        assert!(
            !device
                .lock()
                .unwrap()
                .writes
                .iter()
                .any(|(at, value)| *at == 0x2c08 && *value == 1)
        );
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        controller.shutdown().unwrap();
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn native_read_failure_has_priority_over_clock_expiry_after_that_access() {
        let (mut controller, device, source) = ready(0x63, 4096);
        {
            let mut model = device.lock().unwrap();
            model.fail_after_write = Some(0x2c08);
            model.jump_read = Some((0x2c08, u32::MAX, 100_001));
        }
        assert_eq!(
            controller.start(),
            Err(Error::RegisterUnavailable(DMA_ENABLE))
        );
        assert_eq!(controller.state(), State::Faulted);
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        controller.shutdown().unwrap();
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn active_drop_quarantines_real_domain_and_nonidentity_ram_pins() {
        let (mut controller, device, source) = ready(0x63, 4096);
        controller.start().unwrap();
        let domain_count = Arc::strong_count(&controller.domain);
        assert_eq!(domain_count, 2);
        drop(controller);
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        assert!(device.lock().unwrap().translation.is_some());
        // No fake reset/unmap is supplied for this deliberately quarantined DMA.
        device.lock().unwrap().advance(64);
        assert_eq!(device.lock().unwrap().unmaps, 0);
    }
    #[test]
    fn dedicated_source_child_wov_selector_soundwire_and_pin_admission_are_exact() {
        for cfg in [
            Config {
                ownership: Ownership::Unknown,
                ..config()
            },
            Config {
                ownership: Ownership::FirmwareDsp,
                ..config()
            },
            Config {
                acp_config: None,
                ..config()
            },
            Config {
                acp_config: Some(8),
                ..config()
            },
            Config {
                acp_config: Some(16),
                ..config()
            },
            Config {
                acp_config: Some(2),
                ..config()
            },
            Config {
                child: None,
                ..config()
            },
            Config {
                child: Some(DmicChild {
                    address: 3,
                    audio_device_type: 2,
                }),
                ..config()
            },
            Config {
                child: Some(DmicChild {
                    address: 2,
                    audio_device_type: 3,
                }),
                ..config()
            },
            Config {
                wov: WovObservation::Value(0),
                ..config()
            },
            Config {
                wov: WovObservation::Unavailable,
                ..config()
            },
            Config {
                soundwire: SoundWireOwnership::ActiveOrUnknown,
                ..config()
            },
            Config {
                gain: 4,
                ..config()
            },
            Config {
                dma_address_bits: 64,
                ..config()
            },
        ] {
            let device = Arc::new(Mutex::new(Device::new(0x63)));
            let clock = device.lock().unwrap().clock.clone();
            // SAFETY: isolated actual model owners; invalid platform evidence
            // must refuse without publishing or touching any hardware register.
            assert!(
                unsafe {
                    Controller::claim(
                        Model(device.clone()),
                        Time(clock),
                        cfg,
                        Arc::new(Domain(device.clone())),
                    )
                }
                .is_err()
            );
            assert!(device.lock().unwrap().writes.is_empty());
            assert_eq!(device.lock().unwrap().maps, 0);
        }
        for wov in [WovObservation::Value(7), WovObservation::EvaluatedFailure] {
            let device = Arc::new(Mutex::new(Device::new(0x63)));
            let clock = device.lock().unwrap().clock.clone();
            // SAFETY: this model's actually discovered child/firmware/whole
            // function owner supplies the source-default _WOV failure policy.
            let mut controller = unsafe {
                Controller::claim(
                    Model(device.clone()),
                    Time(clock),
                    Config {
                        wov,
                        soundwire: SoundWireOwnership::QuiescedExclusive,
                        ..config()
                    },
                    Arc::new(Domain(device.clone())),
                )
            }
            .unwrap();
            controller.initialize().unwrap();
            controller.shutdown().unwrap();
        }
        for revision in [0, 1, 0x50, 0x60, 0x62, 0x6f, 0x70, 0x71, 0x72] {
            assert!(!PinkSardine::supported(Identity {
                vendor: 0x1022,
                device: 0x15e2,
                revision
            }));
        }
        for mode in 0..=16 {
            let (mut controller, device, _) = fixture(0x63);
            device.lock().unwrap().words[0x1440 / 4] = mode;
            let result = controller.initialize();
            if matches!(mode, 4..=8 | 10..=14) {
                result.unwrap();
            } else {
                assert_eq!(result, Err(Error::UnsupportedPinMode(mode)));
            }
            controller.shutdown().unwrap();
        }
    }

    #[test]
    fn actual_acp63_irq_zsc_policy_and_retained_resume_do_not_alias_a_clock_mux() {
        let (mut controller, device, source) = fixture(0x63);
        device.lock().unwrap().words[0x1a04 / 4] = 1 << 7;
        device.lock().unwrap().words[0x1a0c / 4] = 1 << 9;
        controller.initialize().unwrap();
        {
            let model = device.lock().unwrap();
            assert_eq!(model.words[0x1a04 / 4], 1 << 29);
            assert_eq!(model.words[0x1014 / 4], 0);
            assert_eq!(model.words[0x1a0c / 4], 1 << 9);
            let gate = model
                .accesses
                .iter()
                .position(|entry| *entry == (0x1a00, true))
                .unwrap();
            let control = model
                .accesses
                .iter()
                .position(|entry| *entry == (0x1a04, true))
                .unwrap();
            let zsc = model
                .accesses
                .iter()
                .position(|entry| *entry == (0x1014, true))
                .unwrap();
            let pin = model
                .accesses
                .iter()
                .position(|entry| *entry == (0x1440, false))
                .unwrap();
            assert!(gate < control && control < zsc && zsc < pin);
        }
        controller
            .prepare_capture(&source, CAPTURE_FORMAT, 4096)
            .unwrap();
        let address = controller.capture.as_ref().unwrap().dma.address().unwrap();
        let cpu = controller
            .capture
            .as_ref()
            .unwrap()
            .cpu
            .address(0, 4)
            .unwrap();
        controller.start().unwrap();
        device.lock().unwrap().advance(512);
        let mut pcm = vec![0xa5; 4096];
        assert!(controller.capture_period(&mut pcm).unwrap().is_some());
        device.lock().unwrap().writes.clear();
        controller.suspend_held_d0().unwrap();
        {
            let model = device.lock().unwrap();
            let status = model
                .writes
                .iter()
                .position(|entry| *entry == (0x1a0c, u32::MAX))
                .unwrap();
            let control = model
                .writes
                .iter()
                .position(|entry| *entry == (0x1a04, 0))
                .unwrap();
            let gate = model
                .writes
                .iter()
                .position(|entry| *entry == (0x1a00, 0))
                .unwrap();
            let reset = model
                .writes
                .iter()
                .position(|entry| *entry == (0x1000, 1))
                .unwrap();
            let quiet = model
                .writes
                .iter()
                .position(|entry| *entry == (0x1004, 0))
                .unwrap();
            let zsc = model
                .writes
                .iter()
                .position(|entry| *entry == (0x1014, 1))
                .unwrap();
            assert!(
                status < control && control < gate && gate < reset && reset < quiet && quiet < zsc
            );
            assert_eq!(model.maps, 1);
            assert_eq!(model.unmaps, 0);
        }
        assert_eq!(controller.state(), State::Suspended);
        assert_eq!(controller.capture_period(&mut pcm), Err(Error::Suspended));
        controller.resume_held_d0().unwrap();
        assert_eq!(controller.state(), State::Prepared);
        assert_eq!(
            controller.capture.as_ref().unwrap().dma.address().unwrap(),
            address
        );
        assert_eq!(
            controller
                .capture
                .as_ref()
                .unwrap()
                .cpu
                .address(0, 4)
                .unwrap(),
            cpu
        );
        assert!(controller.capture.as_ref().unwrap().published);
        controller.start().unwrap();
        assert_eq!(controller.capture_period(&mut pcm).unwrap(), None);
        device.lock().unwrap().advance(512);
        assert_eq!(
            controller.capture_period(&mut pcm).unwrap(),
            Some(CapturePeriod {
                first_frame: 0,
                frames: 512
            })
        );
        assert_eq!(
            i32::from_le_bytes(pcm[0..4].try_into().unwrap()),
            sample(512, 0)
        );
        controller.suspend_held_d0().unwrap();
        let starts = device
            .lock()
            .unwrap()
            .writes
            .iter()
            .filter(|entry| **entry == (0x2c08, 1))
            .count();
        controller.shutdown().unwrap();
        assert_eq!(
            device
                .lock()
                .unwrap()
                .writes
                .iter()
                .filter(|entry| **entry == (0x2c08, 1))
                .count(),
            starts
        );
        assert_eq!(device.lock().unwrap().words[0x1014 / 4], 1);
        assert_eq!(device.lock().unwrap().maps, 1);
        assert_eq!(device.lock().unwrap().unmaps, 1);
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        assert!(controller.into_stopped().is_ok());
    }

    #[test]
    fn acp63_failed_suspend_or_restore_retains_the_original_published_epoch() {
        for restore in [false, true] {
            for fault in 0..4 {
                let (mut controller, device, source) = ready(0x63, 4096);
                controller.start().unwrap();
                if restore {
                    controller.suspend_held_d0().unwrap();
                }
                let address = controller.capture.as_ref().unwrap().dma.address().unwrap();
                let expected = {
                    let mut model = device.lock().unwrap();
                    if restore {
                        match fault {
                            0 => {
                                model.identity.device ^= 1;
                                Error::AuthorityChanged
                            }
                            1 => {
                                model.fail_after_write = Some(0x10004);
                                Error::RegisterUnavailable(0x10004)
                            }
                            2 => {
                                model.coherence_unavailable = true;
                                Error::Dma(DmaError::CoherenceUnavailable)
                            }
                            _ => {
                                model.ignore_write = Some(0x1014);
                                Error::RegisterRejected(ZSC_CONTROL)
                            }
                        }
                    } else {
                        match fault {
                            0 => {
                                model.stop_never = true;
                                Error::Timeout(Phase::DmaStop)
                            }
                            1 => {
                                model.reset_never = true;
                                Error::Timeout(Phase::ResetClear)
                            }
                            2 => {
                                model.drain_fail = true;
                                Error::Dma(DmaError::InvalidationFailed)
                            }
                            _ => {
                                model.ignore_write = Some(0x1014);
                                Error::RegisterRejected(ZSC_CONTROL)
                            }
                        }
                    }
                };
                let before = device.lock().unwrap().writes.len();
                let result = if restore {
                    controller.resume_held_d0()
                } else {
                    controller.suspend_held_d0()
                };
                assert_eq!(result, Err(expected));
                if restore && fault == 0 {
                    assert_eq!(device.lock().unwrap().writes.len(), before);
                }
                assert_eq!(controller.state(), State::Faulted);
                assert_eq!(controller.first_error(), Some(expected));
                assert_eq!(
                    controller.capture.as_ref().unwrap().dma.address().unwrap(),
                    address
                );
                assert!(controller.capture.as_ref().unwrap().published);
                assert_eq!(source.drops.load(Ordering::Relaxed), 0);
                assert_eq!(device.lock().unwrap().unmaps, 0);
                {
                    let mut model = device.lock().unwrap();
                    if restore && fault == 0 {
                        model.identity.device ^= 1;
                    }
                    model.coherence_unavailable = false;
                    model.stop_never = false;
                    model.reset_never = false;
                    model.drain_fail = false;
                    model.ignore_write = None;
                }
                controller.initialize().unwrap();
                assert_eq!(source.drops.load(Ordering::Relaxed), 1);
                assert_eq!(controller.first_error(), Some(expected));
                controller.shutdown().unwrap();
            }
        }
    }

    #[test]
    fn live_acp63_pin_and_zsc_loss_are_actual_authority_failures() {
        for (offset, value) in [(0x1440, 5), (0x1014, 1)] {
            let (mut controller, device, source) = ready(0x63, 4096);
            controller.start().unwrap();
            device.lock().unwrap().words[offset / 4] = value;
            assert_eq!(controller.position(), Err(Error::AuthorityChanged));
            assert_eq!(controller.first_error(), Some(Error::AuthorityChanged));
            assert_eq!(source.drops.load(Ordering::Relaxed), 0);
            controller.shutdown().unwrap();
            assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        }
    }

    // ACP70 uses the same independently modeled PS PDM PTE/ring engine, while
    // these checks assert its distinct power/ZSC/PME and retirement behavior.
    // Authored SOURCE ONLY; execution is assigned to the parent gate owner.
    fn fixture70(
        revision: u8,
    ) -> (
        crate::audio::acp70::Controller<Model, Time>,
        Arc<Mutex<Device>>,
        Source,
    ) {
        let device = Arc::new(Mutex::new(Device::new(revision)));
        let clock = device.lock().unwrap().clock.clone();
        // SAFETY: actual isolated model's exclusive firmware/child/controller
        // epoch and domain supply the same authority as the ACP63 fixture.
        let controller = unsafe {
            crate::audio::acp70::Controller::claim(
                Model(device.clone()),
                Time(clock),
                config(),
                Arc::new(Domain(device.clone())),
            )
        }
        .unwrap();
        (
            controller,
            device,
            Source {
                drops: Arc::new(AtomicUsize::new(0)),
                geometry: 12,
            },
        )
    }
    #[test]
    fn acp70_three_revisions_have_distinct_power_order_and_real_continuous_pcm_pm() {
        for revision in 0x70..=0x72 {
            let (mut controller, device, source) = fixture70(revision);
            // Low bits 1 mean transition on ACP63, but ACP70 must issue 0x1f.
            device.lock().unwrap().words[0x1028 / 4] = 1;
            controller.initialize().unwrap();
            {
                let model = device.lock().unwrap();
                let writes = &model.writes;
                let index = |entry| writes.iter().position(|actual| *actual == entry).unwrap();
                assert!(index((0x1024, 0x1f)) < index((0x1004, 1)));
                assert!(index((0x1000, 0)) < index((0x1014, 0)));
                assert!(index((0x1014, 0)) < index((0x1a00, 1)));
                assert!(index((0x1a04, 1 << 29)) < index((0x1400, 1)));
                assert!(!writes.iter().any(|(offset, _)| *offset == 0x1a08));
            }
            controller
                .prepare_capture(&source, CAPTURE_FORMAT, 4096)
                .unwrap();
            let address = controller.capture.as_ref().unwrap().dma.address().unwrap();
            controller.start().unwrap();
            let mut pcm = vec![0xa5; 4096];
            for period in 0..10 {
                device.lock().unwrap().advance(512);
                assert_eq!(
                    controller.capture_period(&mut pcm).unwrap(),
                    Some(CapturePeriod {
                        first_frame: period * 512,
                        frames: 512,
                    })
                );
                for frame in 0..512 {
                    for channel in 0..2 {
                        let offset = frame * 8 + channel * 4;
                        assert_eq!(
                            i32::from_le_bytes(pcm[offset..offset + 4].try_into().unwrap()),
                            sample(period * 512 + frame as u64, channel)
                        );
                    }
                }
            }
            device.lock().unwrap().writes.clear();
            controller.suspend_held_d0().unwrap();
            {
                let model = device.lock().unwrap();
                assert_eq!(model.words[0x1004 / 4], 1);
                assert_eq!(model.words[0x1014 / 4], 1);
                assert!(!model.writes.iter().any(|(offset, _)| *offset == 0x1004));
                assert_eq!(model.unmaps, 0);
            }
            controller.resume_held_d0().unwrap();
            assert_eq!(controller.state(), State::Prepared);
            assert_eq!(
                controller.capture.as_ref().unwrap().dma.address().unwrap(),
                address
            );
            controller.start().unwrap();
            device.lock().unwrap().advance(512);
            assert_eq!(
                controller
                    .capture_period(&mut pcm)
                    .unwrap()
                    .unwrap()
                    .first_frame,
                0
            );
            assert_eq!(
                i32::from_le_bytes(pcm[..4].try_into().unwrap()),
                sample(5120, 0)
            );
            controller.shutdown().unwrap();
            assert_eq!(device.lock().unwrap().words[0x1004 / 4], 1);
            assert_eq!(device.lock().unwrap().words[0x1014 / 4], 1);
            assert_eq!(device.lock().unwrap().maps, 1);
            assert_eq!(device.lock().unwrap().unmaps, 1);
            assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        }
    }
    #[test]
    fn acp70_actual_soundwire_enable_and_wake_refuse_before_whole_function_effects() {
        for offset in [0x3000, 0x3004, 0x3c00, 0x3c04, 0x1458, 0x1460] {
            let (mut controller, device, _) = fixture70(0x70);
            device.lock().unwrap().words[offset / 4] = 1;
            assert_eq!(controller.initialize(), Err(Error::Ownership));
            assert!(device.lock().unwrap().writes.is_empty());
            device.lock().unwrap().words[offset / 4] = 0;
            controller.initialize().unwrap();
            controller.shutdown().unwrap();
        }
        for offset in [0x3000, 0x3004, 0x3c00, 0x3c04, 0x1458, 0x1460] {
            let (mut controller, device, _) = fixture70(0x71);
            device.lock().unwrap().lost_read = Some(offset);
            assert_eq!(
                controller.initialize(),
                Err(Error::RegisterUnavailable(offset))
            );
            assert!(device.lock().unwrap().writes.is_empty());
            controller.shutdown().unwrap();
        }
    }
    #[test]
    fn acp70_pgfsm_upper_bits_are_not_an_on_grant_and_budget_is_two_milliseconds() {
        for status in [0x1, 0x2, 0x80, 0x100] {
            let (mut controller, device, _) = fixture70(0x72);
            {
                let mut model = device.lock().unwrap();
                model.words[0x1028 / 4] = status;
                if status != 0x100 {
                    // Exercise a successful request whose native effect costs
                    // more than ACP63's 500us but remains within ACP70's 2ms.
                    model.jump_write = Some((0x1024, 0x1f, 1500));
                }
            }
            if status == 0x100 {
                // ACP70 requests only when low eight bits are nonzero, then
                // waits for the entire status to clear; upper bits cannot pass.
                assert_eq!(controller.initialize(), Err(Error::Timeout(Phase::PowerOn)));
                assert!(device.lock().unwrap().writes.is_empty());
                device.lock().unwrap().words[0x1028 / 4] = 0;
            } else {
                controller.initialize().unwrap();
            }
            controller.shutdown().unwrap();
        }
        for write in [false, true] {
            let (mut controller, device, _) = fixture70(0x70);
            {
                let mut model = device.lock().unwrap();
                if write {
                    model.jump_write = Some((0x1024, 0x1f, 2001));
                } else {
                    model.jump_read = Some((0x1028, 0, 2001));
                }
            }
            assert_eq!(controller.initialize(), Err(Error::Timeout(Phase::PowerOn)));
            assert!(
                !device
                    .lock()
                    .unwrap()
                    .writes
                    .iter()
                    .any(|(offset, _)| *offset == 0x1004)
            );
            controller.shutdown().unwrap();
        }
    }
    #[test]
    fn acp70_exact_generation_and_pin_modes_do_not_admit_acp7x_or_sdw_only() {
        use crate::audio::acp70::Ps70;
        for revision in 0..=255 {
            assert_eq!(
                Ps70::supported(Identity {
                    vendor: 0x1022,
                    device: 0x15e2,
                    revision
                }),
                matches!(revision, 0x70..=0x72)
            );
        }
        for mode in 0..=21 {
            let (mut controller, device, _) = fixture70(0x70);
            device.lock().unwrap().words[0x1440 / 4] = mode;
            let result = controller.initialize();
            if matches!(mode, 4..=8 | 10..=14 | 17..=20) {
                result.unwrap();
            } else {
                assert_eq!(result, Err(Error::UnsupportedPinMode(mode)));
            }
            controller.shutdown().unwrap();
        }
    }
    #[test]
    fn acp70_live_wake_or_pme_loss_and_failed_restore_preserve_published_dma() {
        for offset in [0x1458, 0x1460, 0x1400] {
            let (mut controller, device, source) = fixture70(0x72);
            controller.initialize().unwrap();
            controller
                .prepare_capture(&source, CAPTURE_FORMAT, 4096)
                .unwrap();
            controller.start().unwrap();
            device.lock().unwrap().words[offset / 4] ^= 1;
            assert_eq!(
                controller.position(),
                Err(if offset == 0x1400 {
                    Error::AuthorityChanged
                } else {
                    Error::Ownership
                })
            );
            assert_eq!(controller.state(), State::Faulted);
            assert_eq!(source.drops.load(Ordering::Relaxed), 0);
            device.lock().unwrap().words[offset / 4] ^= 1;
            controller.shutdown().unwrap();
            assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        }
        for restore in [false, true] {
            let (mut controller, device, source) = fixture70(0x71);
            controller.initialize().unwrap();
            controller
                .prepare_capture(&source, CAPTURE_FORMAT, 4096)
                .unwrap();
            controller.start().unwrap();
            let address = controller.capture.as_ref().unwrap().dma.address().unwrap();
            if restore {
                controller.suspend_held_d0().unwrap();
            }
            device.lock().unwrap().ignore_write = Some(0x1014);
            assert_eq!(
                if restore {
                    controller.resume_held_d0()
                } else {
                    controller.suspend_held_d0()
                },
                Err(Error::RegisterRejected(0x1014))
            );
            assert_eq!(
                controller.capture.as_ref().unwrap().dma.address().unwrap(),
                address
            );
            assert_eq!(device.lock().unwrap().unmaps, 0);
            assert_eq!(source.drops.load(Ordering::Relaxed), 0);
            device.lock().unwrap().ignore_write = None;
            controller.shutdown().unwrap();
            assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        }
    }
    // Source-only ATU regressions for each actual PS profile. All UNRUN.
    fn check_ps_cache_lifecycle<P: Profile>(
        (mut controller, device, source): (
            acp_pdm::Controller<Model, Time, P>,
            Arc<Mutex<Device>>,
            Source,
        ),
        readback: u32,
    ) {
        use super::super::acp_pdm::trace_assertions::assert_ring_invalidation;
        device.lock().unwrap().atu_readback = readback;
        controller.initialize().unwrap();
        assert!(
            !device
                .lock()
                .unwrap()
                .writes
                .iter()
                .any(|(at, _)| *at == 0xc40)
        );
        let first = device.lock().unwrap().writes.len();
        controller
            .prepare_capture(&source, CAPTURE_FORMAT, 4096)
            .unwrap();
        assert_ring_invalidation(
            &device.lock().unwrap().writes[first..],
            IOVA,
            0x0380_0000,
            4096,
            false,
        );
        controller.start().unwrap();
        assert_ring_invalidation(
            &device.lock().unwrap().writes[first..],
            IOVA,
            0x0380_0000,
            4096,
            true,
        );
        device.lock().unwrap().advance(512);
        assert!(controller.position().unwrap().period_pending);
        controller.stop().unwrap();
        let reset = device.lock().unwrap().resets;
        let replacement = device.lock().unwrap().writes.len();
        controller
            .prepare_capture(&source, CAPTURE_FORMAT, 8192)
            .unwrap();
        assert_ring_invalidation(
            &device.lock().unwrap().writes[replacement..],
            IOVA,
            0x0380_0000,
            8192,
            false,
        );
        assert!(device.lock().unwrap().resets > reset);
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        assert_eq!(device.lock().unwrap().unmaps, 1);
        let capture = controller.capture.as_ref().unwrap();
        let address = capture.dma.address().unwrap();
        let cpu = capture.cpu.address(0, 4).unwrap();
        controller.start().unwrap();
        assert_ring_invalidation(
            &device.lock().unwrap().writes[replacement..],
            IOVA,
            0x0380_0000,
            8192,
            true,
        );
        device.lock().unwrap().advance(1024);
        controller.suspend_retained(false).unwrap();
        assert_eq!(controller.state(), State::Suspended);
        {
            let model = device.lock().unwrap();
            assert_eq!(model.words[0xc04 / 4], 0);
            assert!(!model.master);
            assert_eq!(model.unmaps, 1);
        }
        let restored = device.lock().unwrap().writes.len();
        controller.resume_retained().unwrap();
        assert_ring_invalidation(
            &device.lock().unwrap().writes[restored..],
            IOVA,
            0x0380_0000,
            8192,
            false,
        );
        assert_eq!(controller.state(), State::Prepared);
        let capture = controller.capture.as_ref().unwrap();
        assert_eq!(capture.dma.address().unwrap(), address);
        assert_eq!(capture.cpu.address(0, 4).unwrap(), cpu);
        controller.start().unwrap();
        assert_ring_invalidation(
            &device.lock().unwrap().writes[restored..],
            IOVA,
            0x0380_0000,
            8192,
            true,
        );
        device.lock().unwrap().advance(1024);
        assert!(controller.position().unwrap().period_pending);
        controller.shutdown().unwrap();
        let model = device.lock().unwrap();
        assert_eq!(model.atu_reads, 0);
        assert_eq!(
            model
                .writes
                .iter()
                .copied()
                .filter(|(at, _)| *at == 0xc40)
                .collect::<Vec<_>>(),
            [(0xc40, 1), (0xc40, 1), (0xc40, 1)],
            "one command per initial/replacement/resume publication, none for stop/suspend/shutdown"
        );
        assert_eq!(model.maps, 2);
        assert_eq!(model.unmaps, 2);
        assert_eq!(source.drops.load(Ordering::Relaxed), 2);
    }
    #[test]
    fn ps_atu_cache_command_is_write_only_and_ordered_for_all_actual_profiles() {
        for readback in [0, 1, 0x1234_5678, u32::MAX] {
            check_ps_cache_lifecycle(fixture(0x63), readback);
            for revision in 0x70..=0x72 {
                check_ps_cache_lifecycle(fixture70(revision), readback);
            }
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum RetirePath {
        Replace,
        Suspend,
        Resume,
        Shutdown,
    }
    fn check_ps_retirement_failure<P: Profile>(
        (mut controller, device, source): (
            acp_pdm::Controller<Model, Time, P>,
            Arc<Mutex<Device>>,
            Source,
        ),
        path: RetirePath,
        fault: usize,
    ) {
        controller.initialize().unwrap();
        controller
            .prepare_capture(&source, CAPTURE_FORMAT, 4096)
            .unwrap();
        controller.start().unwrap();
        device.lock().unwrap().advance(32);
        if matches!(path, RetirePath::Replace) {
            controller.stop().unwrap();
        }
        if matches!(path, RetirePath::Resume) {
            controller.suspend_retained(false).unwrap();
        }
        let capture = controller.capture.as_ref().unwrap();
        let address = capture.dma.address().unwrap();
        let cpu = capture.cpu.address(0, 4).unwrap();
        let expected = {
            let mut model = device.lock().unwrap();
            match fault {
                0 => {
                    // A stale group can survive reset; an ignored write must
                    // fail even when entering from retained suspension.
                    model.words[0xc04 / 4] = 0x8380_0000;
                    model.ignore_write = Some(0xc04);
                    Error::RegisterRejected(0xc04)
                }
                1 => {
                    model.fail_after_write = Some(0xc04);
                    Error::RegisterUnavailable(0xc04)
                }
                2 => {
                    model.reject_bme_disable = true;
                    Error::PciAuthority
                }
                3 => {
                    model.reset_never = true;
                    Error::Timeout(Phase::ResetClear)
                }
                4 => {
                    model.drain_fail = true;
                    Error::Dma(DmaError::InvalidationFailed)
                }
                _ => {
                    model.drain_unavailable = true;
                    Error::Dma(DmaError::DrainUnavailable)
                }
            }
        };
        let result = match path {
            RetirePath::Replace => controller.prepare_capture(&source, CAPTURE_FORMAT, 8192),
            RetirePath::Suspend => controller.suspend_retained(false),
            RetirePath::Resume => controller.resume_retained(),
            RetirePath::Shutdown => controller.shutdown(),
        };
        assert_eq!(result, Err(expected), "{path:?}, fault {fault}");
        assert_eq!(controller.first_error(), Some(expected));
        assert_eq!(controller.state(), State::Faulted);
        let capture = controller.capture.as_ref().unwrap();
        assert_eq!(capture.dma.address().unwrap(), address);
        assert_eq!(capture.cpu.address(0, 4).unwrap(), cpu);
        assert!(capture.published);
        {
            let mut model = device.lock().unwrap();
            assert_eq!(model.translation.as_ref().unwrap().token.address, address);
            assert_eq!(model.maps, 1);
            assert_eq!(model.unmaps, 0);
            assert_eq!(model.atu_reads, 0);
            assert_eq!(
                model.writes.iter().filter(|(at, _)| *at == 0xc40).count(),
                1
            );
            if fault == 2 && !matches!(path, RetirePath::Replace | RetirePath::Resume) {
                assert!(
                    model.master,
                    "failed BME containment cannot clear ownership by assumption"
                );
            }
            model.ignore_write = None;
            model.reject_bme_disable = false;
            model.reset_never = false;
            model.drain_fail = false;
            model.drain_unavailable = false;
        }
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        controller.shutdown().unwrap();
        assert_eq!(controller.first_error(), Some(expected));
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
        assert_eq!(device.lock().unwrap().unmaps, 1);
    }
    #[test]
    fn ps_actual_reset_group_bme_and_domain_failures_retain_exact_published_owners() {
        for path in [
            RetirePath::Replace,
            RetirePath::Suspend,
            RetirePath::Resume,
            RetirePath::Shutdown,
        ] {
            for fault in 0..6 {
                check_ps_retirement_failure(fixture(0x63), path, fault);
                for revision in 0x70..=0x72 {
                    check_ps_retirement_failure(fixture70(revision), path, fault);
                }
            }
        }
    }

    fn check_ps_posted_payload<P: Profile>(
        (mut controller, device, source): (
            acp_pdm::Controller<Model, Time, P>,
            Arc<Mutex<Device>>,
            Source,
        ),
    ) {
        controller.initialize().unwrap();
        controller
            .prepare_capture(&source, CAPTURE_FORMAT, 4096)
            .unwrap();
        controller.start().unwrap();
        {
            let mut model = device.lock().unwrap();
            model.defer_payload = true;
            model.advance(512);
            let drains = model.drains;
            model.write(0xc40, 1);
            assert_eq!(model.posted.len(), 1024);
            assert_eq!(
                model.drains, drains,
                "cache command cannot complete posted payload"
            );
            model.drain_fail = true;
        }
        assert_eq!(
            controller.stop(),
            Err(Error::Dma(DmaError::InvalidationFailed))
        );
        assert_eq!(
            controller.shutdown(),
            Err(Error::Dma(DmaError::InvalidationFailed))
        );
        assert_eq!(device.lock().unwrap().posted.len(), 1024);
        assert_eq!(device.lock().unwrap().cpu_syncs, 0);
        assert_eq!(device.lock().unwrap().unmaps, 0);
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        {
            let mut model = device.lock().unwrap();
            model.drain_fail = false;
            model.drain_unavailable = true;
        }
        assert_eq!(
            controller.initialize(),
            Err(Error::Dma(DmaError::DrainUnavailable))
        );
        assert_eq!(device.lock().unwrap().posted.len(), 1024);
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        device.lock().unwrap().drain_unavailable = false;
        controller.shutdown().unwrap();
        assert!(device.lock().unwrap().posted.is_empty());
        assert_eq!(device.lock().unwrap().unmaps, 1);
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn ps_cache_request_never_drains_payload_or_authorizes_faulted_release() {
        check_ps_posted_payload(fixture(0x63));
        for revision in 0x70..=0x72 {
            check_ps_posted_payload(fixture70(revision));
        }
    }

    fn check_ps_partial_publication<P: Profile>(
        (mut controller, device, source): (
            acp_pdm::Controller<Model, Time, P>,
            Arc<Mutex<Device>>,
            Source,
        ),
        resume: bool,
    ) {
        controller.initialize().unwrap();
        if resume {
            controller
                .prepare_capture(&source, CAPTURE_FORMAT, 4096)
                .unwrap();
            controller.start().unwrap();
            controller.suspend_retained(false).unwrap();
        }
        device.lock().unwrap().fail_after_write = Some(0x10004);
        let result = if resume {
            controller.resume_retained()
        } else {
            controller.prepare_capture(&source, CAPTURE_FORMAT, 4096)
        };
        assert_eq!(result, Err(Error::RegisterUnavailable(0x10004)));
        assert!(controller.capture.as_ref().unwrap().published);
        {
            let model = device.lock().unwrap();
            assert_eq!(model.unmaps, 0);
            assert_eq!(
                model.writes.iter().filter(|(at, _)| *at == 0xc40).count(),
                usize::from(resume),
                "partial PTE programming cannot issue the end-of-ring invalidate request"
            );
        }
        assert_eq!(source.drops.load(Ordering::Relaxed), 0);
        controller.shutdown().unwrap();
        assert_eq!(device.lock().unwrap().unmaps, 1);
        assert_eq!(source.drops.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn ps_partial_setup_and_resume_publication_never_invalidate_or_release_early() {
        for resume in [false, true] {
            check_ps_partial_publication(fixture(0x63), resume);
            for revision in 0x70..=0x72 {
                check_ps_partial_publication(fixture70(revision), resume);
            }
        }
    }

    #[test]
    #[ignore = "requires unchanged Linux trace in STELA_ACP70_ORACLE"]
    fn acp70_unchanged_linux_power_and_init_oracle() {
        use std::fmt::Write;
        let path = std::env::var("STELA_ACP70_ORACLE").unwrap();
        let original = std::fs::read_to_string(path).unwrap();
        let mut actual =
            std::string::String::from("linux a804c5742bff224d4cb4d25dd383554d598be32b\n");
        for status in [0, 1, 2, 0x80, 0x100] {
            let (mut controller, device, _) = fixture70(0x70);
            device.lock().unwrap().words[0x1028 / 4] = status;
            writeln!(actual, "case {status:08x}").unwrap();
            let result = controller.initialize();
            {
                let model = device.lock().unwrap();
                for (offset, value) in &model.writes {
                    // These are the original source's init registers. Native
                    // ATU/BME/drain containment additionally precedes DMA, but
                    // never substitutes for a source effect in this trace.
                    if matches!(
                        *offset,
                        0x1024 | 0x1004 | 0x1000 | 0x1014 | 0x1a00 | 0x1a04 | 0x1400
                    ) {
                        writeln!(actual, "w {offset:04x} {value:08x}").unwrap();
                    }
                }
            }
            let code = if result.is_ok() {
                0
            } else {
                assert_eq!(result, Err(Error::Timeout(Phase::PowerOn)));
                -110
            };
            writeln!(actual, "result {code}").unwrap();
            if status == 0x100 {
                device.lock().unwrap().words[0x1028 / 4] = 0;
            }
            controller.shutdown().unwrap();
        }
        assert_eq!(actual, original);
    }
}
