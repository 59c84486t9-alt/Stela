// SPDX-License-Identifier: GPL-2.0-only
//! Native ACP6x Yellow Carp direct PDM capture. Register sequencing adapts AMD
//! Linux sound/soc/amd/yc/{pci-acp6x.c,acp6x-pdm-dma.c,acp6x-mach.c,acp6x.h}
//! at a804c5742bff224d4cb4d25dd383554d598be32b. See THIRD_PARTY.md.
//! Copyright (C) 2021 Advanced Micro Devices, Inc. All rights reserved.
//!
//! This is the held-D0 direct path, not SOF firmware/IPC, ACP3x/5x, I2S or an
//! Apple audio frontend. Only 48kHz stereo signed 32-bit little-endian capture
//! is admitted. The caller supplies actual evaluated ACPI presence evidence;
//! DMI-only machine selection and system/runtime suspend remain separate.
//! DMA uses actual retained native RAM and an attached device domain. After an error or drop, mappings,
//! power and exclusive ownership must remain pinned until acknowledged reset
//! or shutdown. No destructor attempts device access or frees active DMA.
use super::acp_pdm::{self, DmaConfig, Profile};
pub use super::acp_pdm::{CAPTURE_FORMAT, Error, Identity, Phase, Position, Registers, State};
use crate::bus::{dma::mapping::DmaDomain, i2c::Timer};
use alloc::sync::Arc;
pub mod pci;
mod registers;
use registers::*;

#[doc(hidden)]
pub struct YellowCarp;
impl Profile for YellowCarp {
    const POWER_CONTROL: usize = POWER_CONTROL;
    const POWER_STATUS: usize = POWER_STATUS;
    const CLOCK: usize = CLOCK;
    const IRQ_ENABLE: usize = IRQ_ENABLE;
    const IRQ_CONTROL: usize = IRQ_CONTROL;
    const IRQ_STATUS: usize = IRQ_STATUS;
    const SRAM_TABLE: u32 = SRAM_TABLE;
    const ERROR_ENABLE: u32 = 0;
    const REQUIRE_DRAIN: bool = false;
    const PERIOD_DELIVERY: bool = false;
    fn supported(identity: Identity) -> bool {
        identity.supported()
    }
    fn class_allowed(_: [u8; 3]) -> bool {
        true
    }
    fn pin_mode<R: Registers>(registers: &mut R) -> Result<Option<u32>, Error> {
        let mode = registers.read32(PIN_CONFIG);
        if mode == u32::MAX {
            return Err(Error::RegisterUnavailable(PIN_CONFIG));
        }
        Ok(Some(mode))
    }
    fn validate_pin(mode: Option<u32>, identity: Identity) -> Result<(), Error> {
        let mode = mode.unwrap();
        if !matches!(mode, 4..=8 | 10..=14) || (identity.revision == 0x62 && mode >= 10) {
            return Err(Error::UnsupportedPinMode(mode));
        }
        Ok(())
    }
}
pub type Controller<R, T> = acp_pdm::Controller<R, T, YellowCarp>;

impl Identity {
    fn supported(self) -> bool {
        self.vendor == 0x1022
            && self.device == 0x15e2
            && matches!(self.revision, 0x60 | 0x6f | 0x62)
    }
}

/// Actual firmware observations for this function, not an ID-derived guess.
/// Pinned machine policy refuses `_WOV=0` even for its DMI overrides. This
/// bounded path requires successful nonzero `_WOV` and `AcpDmicConnected=1`;
/// the upstream positive DMI fallback is intentionally not implemented here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmicPresence {
    pub wov: Option<u64>,
    pub acp_dmic_connected: Option<u64>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ownership {
    ExclusiveDirect,
    FirmwareDsp,
    Unknown,
}
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub ownership: Ownership,
    pub presence: DmicPresence,
    /// Actual platform/IOMMU reachability ceiling. Bit63 is PTE validity, so
    /// the hardware encoding can represent at most 63 address bits.
    pub dma_address_bits: u8,
    /// Source WOV gain encoding 0..=3, applied preserving other MISC bits.
    pub gain: u8,
}

impl<R: Registers, T: Timer> acp_pdm::Controller<R, T, YellowCarp> {
    /// Claim without writing hardware. Initialization errors retain this owner.
    ///
    /// # Safety
    /// The platform must arbitrate the whole function away from firmware, SOF,
    /// AML/SMM and other CPUs and hold it in PCI D0 with coherent DMA/IOMMU
    /// reachability. Presence must come from this function's evaluated ACPI.
    /// `domain` is the actual isolated domain attached to this PCI requester.
    /// Registers and DMA RAM stay mapped while retained, including after errors
    /// or drop; release ownership only after acknowledged shutdown/reset.
    /// Native PCI interrupt delivery must be contained (the supplied adapter
    /// requires INTx disabled and MSI/MSI-X disabled). This backend polls W1C
    /// status rather than registering an interrupt handler.
    pub unsafe fn claim(
        registers: R,
        timer: T,
        config: Config,
        domain: Arc<dyn DmaDomain>,
    ) -> Result<Self, Error> {
        if config.ownership != Ownership::ExclusiveDirect {
            return Err(Error::Ownership);
        }
        if !config.presence.wov.is_some_and(|value| value != 0)
            || config.presence.acp_dmic_connected != Some(1)
        {
            return Err(Error::MicrophoneAbsent);
        }
        Self::claim_profile(
            registers,
            timer,
            DmaConfig {
                dma_address_bits: config.dma_address_bits,
                gain: config.gain,
            },
            domain,
        )
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
    struct Device {
        words: Vec<u32>,
        identity: Identity,
        master: bool,
        count: u64,
        cursor: usize,
        frames: u64,
        translation: Option<Translation>,
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
            value
        }
        fn write(&mut self, offset: usize, value: u32) {
            self.writes.push((offset, value));
            if self.ignore_write == Some(offset) {
                return;
            }
            match offset {
                0x1024 => {
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
                        for register in [0x2c04, 0x2c08, 0xc40, 0x1a04] {
                            self.words[register / 4] = 0;
                        }
                        self.cursor = 0;
                        self.count = 0;
                    }
                }
                0x1a0c => self.words[offset / 4] &= !value, // Real W1C semantics.
                0x2c08 => {
                    if value == 1 {
                        assert!(self.master);
                        assert_eq!(self.words[0x1004 / 4], 1);
                        assert_eq!(self.words[0x102c / 4], 3);
                        assert_eq!(self.words[0x2c60 / 4], 7);
                        assert_eq!(self.words[0x2c04 / 4], 1);
                        assert_eq!(self.words[0x2c28 / 4], 0);
                        assert_eq!(self.words[0x2c2c / 4], 2);
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
            assert_eq!(self.words[0xc40 / 4], 1);
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
                    // SAFETY: this synchronous model owns DMA while active;
                    // actual retained CPU RAM is reached through its domain.
                    unsafe { pointer.as_ptr().cast::<i32>().write_volatile(sample) };
                }
                self.frames += 1;
                self.count = self.count.wrapping_add(8);
                self.cursor = (self.cursor + 8) % ring;
                if self.cursor.is_multiple_of(period) {
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
            self.0.lock().unwrap().master = enabled;
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
            assert_eq!(device.words[0xc40 / 4], 0);
            assert_eq!(device.translation.as_ref().unwrap().token, token);
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
            device.cpu_syncs += 1;
            device.device_owns = false;
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
            presence: DmicPresence {
                wov: Some(1),
                acp_dmic_connected: Some(1),
            },
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
    fn actual_pte_capture_pcm_wraps_stop_restart_and_acknowledged_release() {
        for (revision, period) in [(0x60, 4096), (0x6f, 8192), (0x62, 5000)] {
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
    fn source_presence_ownership_exact_identity_and_pin_mode_are_not_inferred() {
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
                presence: DmicPresence {
                    wov: None,
                    acp_dmic_connected: Some(1),
                },
                ..config()
            },
            Config {
                presence: DmicPresence {
                    wov: Some(0),
                    acp_dmic_connected: Some(1),
                },
                ..config()
            },
            Config {
                presence: DmicPresence {
                    wov: Some(1),
                    acp_dmic_connected: None,
                },
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
            let device = Arc::new(Mutex::new(Device::new(0x60)));
            // SAFETY: same isolated model as fixture; deliberately invalid grant.
            assert!(
                unsafe {
                    Controller::claim(
                        Model(device.clone()),
                        Time(Arc::new(AtomicU64::new(0))),
                        cfg,
                        Arc::new(Domain(device.clone())),
                    )
                }
                .is_err()
            );
            assert!(device.lock().unwrap().writes.is_empty());
        }
        for revision in [0, 1, 0x50, 0x63, 0x70] {
            let identity = Identity {
                vendor: 0x1022,
                device: 0x15e2,
                revision,
            };
            assert!(!identity.supported());
        }
        for (revision, mode) in [
            (0x60, 0),
            (0x60, 3),
            (0x60, 9),
            (0x60, 15),
            (0x60, 16),
            (0x62, 10),
            (0x62, 14),
        ] {
            let (mut controller, device, _) = fixture(revision);
            device.lock().unwrap().words[0x1440 / 4] = mode;
            assert_eq!(
                controller.initialize(),
                Err(Error::UnsupportedPinMode(mode))
            );
            assert_eq!(controller.state(), State::Faulted);
            controller.shutdown().unwrap();
        }
        // Source allows modes10..14 on non-RPL revisions only.
        let (mut controller, device, _) = fixture(0x60);
        device.lock().unwrap().words[0x1440 / 4] = 10;
        controller.initialize().unwrap();
        controller.shutdown().unwrap();
    }

    #[test]
    fn format_geometry_and_address_ceiling_refuse_before_dma_publication() {
        let (mut controller, device, mut source) = fixture(0x60);
        controller.initialize().unwrap();
        let before = device.lock().unwrap().writes.len();
        for format in [
            PcmFormat {
                bits: 16,
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
        let (mut controller, device, _) = ready(0x60, 4096);
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
            let (mut controller, device, source) = ready(0x60, 4096);
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
    fn live_map_pin_clock_and_identity_loss_quarantine_old_pcm_and_shutdown_is_safe() {
        for fault in 0..9 {
            let (mut controller, device, source) = ready(0x60, 4096);
            controller.start().unwrap();
            {
                let mut model = device.lock().unwrap();
                match fault {
                    0 => model.words[0x10004 / 4] ^= 1,
                    1 => model.words[0x1440 / 4] = 5,
                    2 => model.words[0x102c / 4] = 0,
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
            let (mut controller, device, source) = fixture(0x60);
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
    fn power_clock_and_actual_iova_limit_failures_do_not_publish_dma() {
        let (mut controller, device, source) = fixture(0x60);
        device.lock().unwrap().power_never = true;
        assert_eq!(controller.initialize(), Err(Error::Timeout(Phase::PowerOn)));
        assert_eq!(device.lock().unwrap().maps, 0);
        device.lock().unwrap().power_never = false;
        device.lock().unwrap().ignore_write = Some(0x102c);
        assert_eq!(controller.initialize(), Err(Error::RegisterRejected(CLOCK)));
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
                let (mut controller, device, source) = fixture(0x60);
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
                        .any(|(at, _)| *at == 0x102c)
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
        let (mut controller, device, _) = fixture(0x60);
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
                let (mut controller, device, source) = ready(0x60, 4096);
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
        let (mut controller, device, source) = ready(0x60, 4096);
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
        let (mut controller, device, source) = ready(0x60, 4096);
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
        let (mut controller, device, source) = ready(0x60, 4096);
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
}
