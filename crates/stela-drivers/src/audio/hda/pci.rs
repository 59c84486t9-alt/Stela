// SPDX-License-Identifier: GPL-2.0-only
//! Bounded conventional HDA PCI attachment. Quirks and exact controller IDs adapt
//! Linux sound/hda/controllers/intel.c, include/linux/pci_ids.h, capability
//! layouts in include/uapi/linux/pci_regs.h, and PCI D0 transition sequencing
//! from drivers/pci/pci.c at
//! a804c5742bff224d4cb4d25dd383554d598be32b.
//!
//! Copyright(c) 2004 Intel Corporation
//! Copyright (c) 2004 Takashi Iwai <tiwai@suse.de>
//!                     PeiSen Hou <pshou@realtek.com.tw>
//! Copyright 1993 -- 1997 Drew Eckhardt, Frederic Potter, David Mosberger-Tang
//! Copyright 1997 -- 2000 Martin Mares <mj@ucw.cz>
//!
//! Platform ACPI power resources, firmware/AML/SMM arbitration and coherent DMA
//! mappings remain prerequisites. DSP/GPU controllers require additional owners
//! and are deliberately absent from this attachment table.
use super::{Config, CorbReset, MmioRegisters, PositionPolicy, ProbePolicy};
use crate::bus::{
    i2c::Timer,
    pci::{Bar, ConfigSpace, Function},
};

pub const CLASS: [u8; 3] = [0x04, 0x03, 0x00];
const INTEL: u16 = 0x8086;
const ATI: u16 = 0x1002;
const AMD: u16 = 0x1022;
const PCI_ID: u16 = 0;
const PCI_COMMAND: u16 = 4;
const PCI_STATUS: u16 = 6;
const PCI_CLASS: u16 = 8;
const PCI_HEADER: u16 = 0x0e;
const PCI_BAR0: u16 = 0x10;
const PCI_CAPABILITIES: u16 = 0x34;
const PCI_SUBSYSTEM: u16 = 0x2c;
const COMMAND_MEMORY: u16 = 1 << 1;
const COMMAND_MASTER: u16 = 1 << 2;
const COMMAND_INTX_DISABLE: u16 = 1 << 10;
const STATUS_CAPABILITIES: u16 = 1 << 4;
const CAP_PM: u8 = 1;
const CAP_MSI: u8 = 5;
const CAP_MSIX: u8 = 0x11;
const MSI_ADDRESS_64: u16 = 1 << 7;
const MSI_VECTOR_MASK: u16 = 1 << 8;
const PM_STATE: u16 = 3;
const PM_PME_ENABLE: u16 = 1 << 8;
const PM_PME_STATUS: u16 = 1 << 15;
const PM_NO_SOFT_RESET: u16 = 1 << 3;
const TCSEL: u16 = 0x44;
const TCSEL_MASK: u8 = 7;
const ATI_SNOOP_CONTROL: u16 = 0x42;
const ATI_SNOOP_MASK: u8 = 7;
const ATI_SNOOP_ENABLE: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Setup {
    IntelIch,
    AtiAzalia,
}

impl Setup {
    fn control(self) -> (u16, u8, u8) {
        match self {
            Self::IntelIch => (TCSEL, TCSEL_MASK, 0),
            Self::AtiAzalia => (ATI_SNOOP_CONTROL, ATI_SNOOP_MASK, ATI_SNOOP_ENABLE),
        }
    }
}

/// Actual identity selected by the bounded table, never by a failed handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub vendor: u16,
    pub device: u16,
    pub corb_reset: CorbReset,
    /// Explicit platform ceiling, independent of GCAP. ATI uses a conservative
    /// 32-bit policy without companion-SMBus stepping evidence; AMD uses 40 bits.
    pub dma_address_bits: u8,
    pub position_policy: PositionPolicy,
    pub probe_policy: ProbePolicy,
    setup: Setup,
}

/// A platform decision made before touching the PCI function. An identity
/// match alone cannot establish exclusive controller ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ownership {
    ExclusiveLegacy,
    Dsp,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachError {
    UnsupportedController,
    Ownership,
    IdentityChanged,
    SubsystemUnavailable,
    SubsystemExcluded,
    BoardIdentityRequired,
    BoardExcluded,
    InvalidBar,
    InvalidCapabilities,
    UnsupportedPowerManagement,
    PowerTransition,
    ConfigurationRejected,
}

/// Match the enumerated identity only; `prepare` rechecks actual config space.
/// This is a candidate match; actual subsystem/DMI exclusions are checked by
/// prepare before any write. Intel DSP and GPU HDA functions remain separate.
pub fn identify<C: ConfigSpace>(function: &Function<C>) -> Result<Identity, AttachError> {
    identity(function.vendor, function.device, function.class)
}

fn identity(vendor: u16, device: u16, class: [u8; 3]) -> Result<Identity, AttachError> {
    if class != CLASS {
        return Err(AttachError::UnsupportedController);
    }
    let (setup, dma_address_bits) = match (vendor, device) {
        (INTEL, 0x2668 | 0x269a | 0x27d8 | 0x284b | 0x293e | 0x293f | 0x3a3e | 0x3a6e) => {
            (Setup::IntelIch, 64)
        }
        // Linux restricts ATI to 40 bits, and SB600 companion-SMBus revisions
        // before 0x30 additionally require 32 bits. Without companion evidence,
        // retain the supported conservative 32-bit mode on every ATI stepping.
        (ATI, 0x437b | 0x4383) => (Setup::AtiAzalia, 32),
        // Exact AMD hosts use ATI snoop and 40-bit DMA. The later family
        // selects FIFO correction and mandatory bounded discovery below.
        (AMD, 0x780d | 0x157a | 0x1457 | 0x1487 | 0x15e3) => (Setup::AtiAzalia, 40),
        _ => return Err(AttachError::UnsupportedController),
    };
    let (position_policy, probe_policy) =
        if vendor == AMD && matches!(device, 0x1457 | 0x1487 | 0x15e3) {
            (
                PositionPolicy::AmdFifo32,
                ProbePolicy::Retry {
                    attempts: 60,
                    delay_us: 1_000_000,
                },
            )
        } else {
            (PositionPolicy::Link, ProbePolicy::Once)
        };
    Ok(Identity {
        vendor,
        device,
        corb_reset: CorbReset::Handshake,
        dma_address_bits,
        position_policy,
        probe_policy,
        setup,
    })
}

/// Target-machine SMBIOS board strings, when actually available. Missing data
/// stays Unknown; a retail product name or development-host identity is no proof.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BoardIdentity<'a> {
    #[default]
    Unknown,
    Known {
        vendor: &'a str,
        name: &'a str,
    },
}

fn check_subsystem<C: ConfigSpace>(
    config: &C,
    identity: Identity,
    board: BoardIdentity<'_>,
) -> Result<(), AttachError> {
    if identity.vendor != AMD || !matches!(identity.device, 0x1457 | 0x1487 | 0x15e3) {
        return Ok(());
    }
    let subsystem = config.read32(PCI_SUBSYSTEM);
    if subsystem == u32::MAX {
        return Err(AttachError::SubsystemUnavailable);
    }
    let pair = (subsystem as u16, (subsystem >> 16) as u16);
    // Exact unconditional PCI denylist from the pinned driver's driver_denylist.
    if identity.device == 0x1487 && matches!(pair, (0x1043, 0x874f) | (0x1462, 0xcb59 | 0xcb60)) {
        return Err(AttachError::SubsystemExcluded);
    }
    // The donor intentionally conditions this subsystem on two DMI strings:
    // some laptops share the PCI IDs. Keep that condition, including unknowns.
    if identity.device == 0x15e3 && pair == (0x1462, 0xee59) {
        let BoardIdentity::Known { vendor, name } = board else {
            return Err(AttachError::BoardIdentityRequired);
        };
        if vendor.trim().is_empty() || name.trim().is_empty() {
            return Err(AttachError::BoardIdentityRequired);
        }
        // Linux DMI_MATCH uses case-sensitive substring matching.
        if vendor.contains("Micro-Star International Co., Ltd.")
            && name.contains("MAG X870E TOMAHAWK WIFI (MS-7E59)")
        {
            return Err(AttachError::BoardExcluded);
        }
    }
    Ok(())
}

/// Successful PCI preparation. Keep the function and mapping exclusively owned
/// throughout controller lifetime; no automatic detach/restore runs on drop.
#[derive(Debug)]
pub struct Prepared {
    identity: Identity,
    base: u64,
    bytes: u64,
}

impl Prepared {
    pub fn identity(&self) -> Identity {
        self.identity
    }

    pub fn config(&self) -> Config {
        Config {
            corb_reset: self.identity.corb_reset,
            dma_address_bits: self.identity.dma_address_bits,
            position_policy: self.identity.position_policy,
            probe_policy: self.identity.probe_policy,
            ..Config::default()
        }
    }

    pub fn bar_range(&self) -> core::ops::Range<u64> {
        self.base..self.base + self.bytes
    }

    /// # Safety
    /// The prepared BAR range must be identity mapped uncached, exclusively
    /// owned and remain mapped until controller shutdown succeeds. Retain PCI
    /// ownership, power and decode established by `prepare` for that lifetime.
    pub unsafe fn claim_mmio(self) -> Result<MmioRegisters, super::super::Error> {
        unsafe { MmioRegisters::claim(self.base, self.bytes) }
    }
}

#[derive(Default)]
struct Capabilities {
    pm: Option<u16>,
    msi: Option<u16>,
    msix: Option<u16>,
}

fn capabilities<C: ConfigSpace>(
    config: &C,
    vendor_control: u16,
) -> Result<Capabilities, AttachError> {
    let mut found = Capabilities::default();
    if config.read16(PCI_STATUS) & STATUS_CAPABILITIES == 0 {
        return Ok(found);
    }
    let mut occupied = [false; 256];
    // The identity's vendor-control byte cannot alias a standard capability.
    occupied[usize::from(vendor_control)] = true;
    let mut offset = config.read8(PCI_CAPABILITIES);
    while offset != 0 {
        if offset < 0x40 || offset & 3 != 0 {
            return Err(AttachError::InvalidCapabilities);
        }
        let offset16 = u16::from(offset);
        let id = config.read8(offset16);
        let (slot, bytes) = match id {
            CAP_PM => (Some(&mut found.pm), 8),
            CAP_MSI => {
                // Control must fit before reading the length-dependent body.
                if offset16 + 4 > 0x100 {
                    return Err(AttachError::InvalidCapabilities);
                }
                let control = config.read16(offset16 + 2);
                let bytes = match (
                    control & MSI_ADDRESS_64 != 0,
                    control & MSI_VECTOR_MASK != 0,
                ) {
                    (false, false) => 10,
                    (true, false) => 14,
                    (false, true) => 20,
                    (true, true) => 24,
                };
                (Some(&mut found.msi), bytes)
            }
            CAP_MSIX => (Some(&mut found.msix), 12),
            // Unknown bodies are not touched or sized. Reserve their headers
            // so a known body cannot alias them or loop through them later.
            _ => (None, 2),
        };
        let end = usize::from(offset16 + bytes);
        let start = usize::from(offset);
        if end > occupied.len() || occupied[start..end].iter().any(|used| *used) {
            return Err(AttachError::InvalidCapabilities);
        }
        occupied[start..end].fill(true);
        if let Some(slot) = slot {
            if slot.is_some() {
                return Err(AttachError::InvalidCapabilities);
            }
            *slot = Some(offset16);
        }
        offset = config.read8(offset16 + 1);
    }
    Ok(found)
}

fn delay(timer: &impl Timer, us: u64) {
    let start = timer.now_us();
    while timer.now_us().wrapping_sub(start) < us {
        timer.relax();
    }
}

fn bar_matches<C: ConfigSpace>(config: &C, base: u64, wide: bool) -> bool {
    let low = config.read32(PCI_BAR0);
    let expected_type = if wide { 4 } else { 0 };
    if low & 15 != expected_type {
        return false;
    }
    let actual = u64::from(low & !15)
        | if wide {
            u64::from(config.read32(PCI_BAR0 + 4)) << 32
        } else {
            0
        };
    actual == base
}

/// Enter PCI D0, select the identity's conventional coherent DMA behavior,
/// enable memory/mastering, and disable all PCI interrupt delivery.
///
/// `bar0` must be the actual BAR0 sized by the platform while the function is
/// exclusively owned. It must be nonprefetchable memory, at least 0x440 bytes.
/// This function never sizes BARs or guesses addresses. Failure after a config
/// write leaves ownership with the caller, with decoding/mastering disabled
/// where possible; the caller must not free DMA or mapping resources blindly.
///
/// # Safety
/// The platform has made main power/clocks available (including D3cold/ACPI
/// resources), quiesced every prior DMA engine, and established exclusive
/// ownership against firmware, AML, SMM, DSP and other CPUs. `ExclusiveLegacy`
/// certifies that decision; the enum cannot discover it. Configuration space
/// must use native byte/word stores. No-PM-capability functions must already be
/// configuration-ready in D0. The supplied allocator used subsequently
/// must provide coherent, controller-reachable DMA through the actual IOMMU.
/// No later agent may change power, decode, snoop or controller ownership.
pub unsafe fn prepare<C: ConfigSpace>(
    function: &mut Function<C>,
    bar0: Bar,
    timer: &impl Timer,
    ownership: Ownership,
) -> Result<Prepared, AttachError> {
    unsafe { prepare_with_board(function, bar0, timer, ownership, BoardIdentity::Unknown) }
}

/// Prepare with actual target SMBIOS board evidence for conditional exclusions.
/// `prepare` supplies Unknown and refuses ambiguous subsystem identities.
///
/// # Safety
/// All platform/power/ownership/coherent-DMA prerequisites of `prepare` apply.
/// Known board strings must come from this target's actual firmware SMBIOS,
/// never a guessed machine name, the development host, or a PCI-ID inference.
pub unsafe fn prepare_with_board<C: ConfigSpace>(
    function: &mut Function<C>,
    bar0: Bar,
    timer: &impl Timer,
    ownership: Ownership,
    board: BoardIdentity<'_>,
) -> Result<Prepared, AttachError> {
    if ownership != Ownership::ExclusiveLegacy {
        return Err(AttachError::Ownership);
    }
    let selected = identify(function)?;
    let config = function.config();
    let id = config.read32(PCI_ID);
    let class = config.read32(PCI_CLASS);
    let actual = identity(
        id as u16,
        (id >> 16) as u16,
        [(class >> 24) as u8, (class >> 16) as u8, (class >> 8) as u8],
    )?;
    if actual != selected || config.read8(PCI_HEADER) & 0x7f != 0 {
        return Err(AttachError::IdentityChanged);
    }
    check_subsystem(config, actual, board)?;
    let (base, bytes, wide) = match bar0 {
        Bar::Memory {
            address,
            size,
            prefetchable: false,
            wide,
        } if address != 0
            && address & 0x7f == 0
            && size >= 0x440
            && size.is_power_of_two()
            && address & (size - 1) == 0
            && address.checked_add(size).is_some() =>
        {
            (address, size, wide)
        }
        _ => return Err(AttachError::InvalidBar),
    };
    if !bar_matches(config, base, wide) {
        return Err(AttachError::InvalidBar);
    }
    let (vendor_control, vendor_mask, vendor_bits) = selected.setup.control();
    let caps = capabilities(config, vendor_control)?;
    let pmcsr = caps.pm.map(|pm| {
        let version = config.read16(pm + 2) & 7;
        (pm + 4, version, config.read16(pm + 4))
    });
    if let Some((_, version, value)) = pmcsr
        && (!(1..=3).contains(&version) || value == u16::MAX)
    {
        return Err(AttachError::UnsupportedPowerManagement);
    }
    // Save resources before a D3hot exit can reset them. Disable decode/mastering
    // before restoring any BAR; PCI status is never written by command updates.
    let bars: [u32; 6] = core::array::from_fn(|i| config.read32(PCI_BAR0 + i as u16 * 4));
    let command = config.read16(PCI_COMMAND);
    if command == u16::MAX {
        return Err(AttachError::ConfigurationRejected);
    }
    let command = command & !(COMMAND_MEMORY | COMMAND_MASTER);
    config.write16(PCI_COMMAND, command | COMMAND_INTX_DISABLE);
    let result = (|| {
        if config.read16(PCI_COMMAND) & (COMMAND_MEMORY | COMMAND_MASTER) != 0 {
            return Err(AttachError::ConfigurationRejected);
        }
        if let Some((offset, _, value)) = pmcsr {
            let state = value & PM_STATE;
            // PME_Status is W1C: write zero to preserve pending wake evidence.
            config.write16(offset, value & !(PM_STATE | PM_PME_ENABLE | PM_PME_STATUS));
            delay(
                timer,
                match state {
                    3 => 10_000,
                    2 => 200,
                    _ => 0,
                },
            );
            if config.read16(offset) & PM_STATE != 0 {
                return Err(AttachError::PowerTransition);
            }
            if state == 3 && value & PM_NO_SOFT_RESET == 0 {
                config.write16(PCI_COMMAND, command | COMMAND_INTX_DISABLE);
                for (index, value) in bars.iter().enumerate() {
                    config.write32(PCI_BAR0 + index as u16 * 4, *value);
                }
            }
        }
        if !bar_matches(config, base, wide) {
            return Err(AttachError::InvalidBar);
        }
        // The exact identity selects either ICH TCSEL or ATI/AMD snoop.
        // These bytes are not interchangeable; never touch Intel TCSEL on AMD.
        let previous = config.read8(vendor_control);
        if previous == u8::MAX {
            return Err(AttachError::ConfigurationRejected);
        }
        let value = previous & !vendor_mask | vendor_bits;
        config.write8(vendor_control, value);
        if config.read8(vendor_control) != value {
            return Err(AttachError::ConfigurationRejected);
        }
        if let Some(offset) = caps.msi {
            let control = config.read16(offset + 2) & !1;
            config.write16(offset + 2, control);
            if config.read16(offset + 2) & 1 != 0 {
                return Err(AttachError::ConfigurationRejected);
            }
        }
        if let Some(offset) = caps.msix {
            let control = config.read16(offset + 2) & !(1 << 15);
            config.write16(offset + 2, control);
            if config.read16(offset + 2) & (1 << 15) != 0 {
                return Err(AttachError::ConfigurationRejected);
            }
        }
        let enabled = command | COMMAND_MEMORY | COMMAND_MASTER | COMMAND_INTX_DISABLE;
        config.write16(PCI_COMMAND, enabled);
        let readback = config.read16(PCI_COMMAND);
        if readback == u16::MAX
            || readback & (COMMAND_MEMORY | COMMAND_MASTER | COMMAND_INTX_DISABLE)
                != COMMAND_MEMORY | COMMAND_MASTER | COMMAND_INTX_DISABLE
        {
            return Err(AttachError::ConfigurationRejected);
        }
        Ok(Prepared {
            identity: selected,
            base,
            bytes,
        })
    })();
    if result.is_err() {
        config.write16(PCI_COMMAND, command | COMMAND_INTX_DISABLE);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::pci::Address;
    use alloc::{rc::Rc, vec::Vec};
    use core::cell::Cell;

    struct Clock(Rc<Cell<u64>>);
    impl Timer for Clock {
        fn now_us(&self) -> u64 {
            self.0.get()
        }
        fn relax(&self) {
            self.0.set(self.0.get() + 10);
        }
    }

    struct Model {
        words: [u32; 64],
        now: Rc<Cell<u64>>,
        ready_at: u64,
        previous_state: u16,
        reject_power: bool,
        reject_command: bool,
        reject_vendor_control: bool,
        fail_after_enable: bool,
        writes: Vec<(u16, u8, u32, u64)>,
    }
    impl Model {
        fn get16(&self, offset: u16) -> u16 {
            (self.words[usize::from(offset / 4)] >> ((offset & 2) * 8)) as u16
        }
        fn set16(&mut self, offset: u16, value: u16) {
            let shift = (offset & 2) * 8;
            let index = usize::from(offset / 4);
            self.words[index] = self.words[index] & !(0xffff << shift) | u32::from(value) << shift;
        }
    }
    impl ConfigSpace for Model {
        fn read32(&self, offset: u16) -> u32 {
            let value = self.words[usize::from(offset / 4)];
            if offset == PCI_COMMAND
                && self.fail_after_enable
                && self.writes.iter().any(|(off, _, value, _)| {
                    *off == PCI_COMMAND && *value & u32::from(COMMAND_MASTER) != 0
                })
            {
                return u32::MAX;
            }
            if offset == 0x54 && (self.reject_power || self.now.get() < self.ready_at) {
                value & !3 | u32::from(self.previous_state)
            } else {
                value
            }
        }
        fn write32(&mut self, offset: u16, value: u32) {
            // The only dword writes attachment needs are saved BAR restores.
            assert!((PCI_BAR0..PCI_BAR0 + 24).contains(&offset));
            assert!(self.now.get() >= self.ready_at);
            assert_eq!(
                self.get16(PCI_COMMAND) & (COMMAND_MEMORY | COMMAND_MASTER),
                0
            );
            self.writes.push((offset, 4, value, self.now.get()));
            self.words[usize::from(offset / 4)] = value;
        }
        fn write8(&mut self, offset: u16, value: u8) {
            assert!(matches!(offset, TCSEL | ATI_SNOOP_CONTROL));
            assert_eq!(
                self.get16(PCI_COMMAND) & (COMMAND_MEMORY | COMMAND_MASTER),
                0
            );
            self.writes
                .push((offset, 1, u32::from(value), self.now.get()));
            if self.reject_vendor_control {
                return;
            }
            let shift = (offset & 3) * 8;
            let index = usize::from(offset / 4);
            self.words[index] = self.words[index] & !(0xff << shift) | u32::from(value) << shift;
        }
        fn write16(&mut self, offset: u16, value: u16) {
            assert!(matches!(offset, PCI_COMMAND | 0x54 | 0x62 | 0x72));
            self.writes
                .push((offset, 2, u32::from(value), self.now.get()));
            if offset == PCI_COMMAND {
                if self.reject_command {
                    return;
                }
                if value & COMMAND_MASTER != 0 {
                    assert!(self.now.get() >= self.ready_at);
                }
            }
            if offset == 0x54 {
                let old = self.get16(offset);
                self.previous_state = old & PM_STATE;
                self.ready_at = self.now.get()
                    + match self.previous_state {
                        3 => 10_000,
                        2 => 200,
                        _ => 0,
                    };
                if old & PM_STATE == 3 && old & PM_NO_SOFT_RESET == 0 {
                    self.words[4..10].fill(0);
                }
                // Pending PME is W1C, not an ordinary stored bit.
                self.set16(
                    offset,
                    (value & !PM_PME_STATUS) | (old & !value & PM_PME_STATUS),
                );
                return;
            }
            self.set16(offset, value);
        }
    }

    fn fixture(state: u16) -> (Function<Model>, Clock, Bar) {
        let now = Rc::new(Cell::new(0));
        let mut model = Model {
            words: [0; 64],
            now: now.clone(),
            ready_at: 0,
            previous_state: state,
            reject_power: false,
            reject_command: false,
            reject_vendor_control: false,
            fail_after_enable: false,
            writes: Vec::new(),
        };
        model.words[0] = 0x2668_8086;
        model.words[1] = 0xf910_0406; // W1C status, capabilities, decode/master.
        model.words[2] = 0x0403_0001;
        model.words[4] = 0xfebf_0000;
        model.words[5] = 0x1234_0000; // Exercise restoration of every BAR.
        model.words[13] = 0x50;
        model.words[17] = 0x5ac3_a5f7; // TCSEL byte plus adjacent vendor state.
        model.words[20] = 0x0003_6001; // PCI PMv3 -> MSI.
        model.words[21] = u32::from(state | PM_PME_ENABLE | PM_PME_STATUS);
        model.words[24] = 0x0001_7005; // Enabled MSI -> MSI-X.
        model.words[28] = 0x8000_0011; // Enabled MSI-X.
        let function = Function::new(
            Address {
                segment: 0,
                bus: 0,
                device: 27,
                function: 0,
            },
            model,
        )
        .unwrap();
        (
            function,
            Clock(now),
            Bar::Memory {
                address: 0xfebf_0000,
                size: 0x4000,
                prefetchable: false,
                wide: false,
            },
        )
    }

    fn set_identity(function: &mut Function<Model>, vendor: u16, device: u16) {
        function.vendor = vendor;
        function.device = device;
        function.config().words[0] = u32::from(vendor) | (u32::from(device) << 16);
    }

    fn prepare_model(
        function: &mut Function<Model>,
        timer: &Clock,
        bar: Bar,
    ) -> Result<Prepared, AttachError> {
        // SAFETY: the isolated stateful model has no real hardware/firmware owner.
        unsafe { prepare(function, bar, timer, Ownership::ExclusiveLegacy) }
    }

    #[test]
    fn exact_legacy_ids_refuse_modern_dsp_gpu_and_wrong_classes() {
        for device in [
            0x2668, 0x269a, 0x27d8, 0x284b, 0x293e, 0x293f, 0x3a3e, 0x3a6e,
        ] {
            assert_eq!(
                identity(INTEL, device, CLASS).unwrap().corb_reset,
                CorbReset::Handshake
            );
        }
        for (vendor, device, class) in [
            (INTEL, 0xa170, CLASS),
            (INTEL, 0x9dc8, CLASS),
            (INTEL, 0x0a0c, CLASS),
            (INTEL, 0xffff, CLASS),
            (AMD, 0x15e2, CLASS),
            (INTEL, 0x2668, [4, 1, 0]),
        ] {
            assert_eq!(
                identity(vendor, device, class),
                Err(AttachError::UnsupportedController)
            );
        }
    }

    #[test]
    fn d3hot_restores_bars_after_delay_and_preserves_wake_status_and_vendor_bytes() {
        let (mut function, timer, bar) = fixture(3);
        let prepared = prepare_model(&mut function, &timer, bar).unwrap();
        assert_eq!(prepared.bar_range(), 0xfebf_0000..0xfebf_4000);
        assert_eq!(prepared.config().corb_reset, CorbReset::Handshake);
        assert_eq!(prepared.config().dma_address_bits, 64);
        let config = function.config();
        assert_eq!(timer.now_us(), 10_000);
        assert_eq!(config.words[4], 0xfebf_0000);
        assert_eq!(config.words[5], 0x1234_0000);
        assert_eq!(config.words[17], 0x5ac3_a5f0);
        assert_eq!(config.get16(0x54), PM_PME_STATUS);
        assert_eq!(config.get16(PCI_STATUS), 0xf910);
        assert_eq!(config.get16(PCI_COMMAND) & 0x406, 0x406);
        assert_eq!(config.get16(0x62) & 1, 0);
        assert_eq!(config.get16(0x72) & 0x8000, 0);
        assert_eq!(
            config
                .writes
                .iter()
                .filter(|(_, width, _, _)| *width == 4)
                .count(),
            6
        );
        assert_eq!(
            config
                .writes
                .iter()
                .filter(|(off, _, _, _)| *off == TCSEL)
                .count(),
            1
        );
    }

    #[test]
    fn d2_delay_and_d3_no_soft_reset_do_not_rewrite_bars() {
        for (state, delay_us) in [(2, 200), (3 | PM_NO_SOFT_RESET, 10_000), (0, 0)] {
            let (mut function, timer, bar) = fixture(state);
            prepare_model(&mut function, &timer, bar).unwrap();
            assert_eq!(timer.now_us(), delay_us);
            assert!(
                !function
                    .config()
                    .writes
                    .iter()
                    .any(|(_, width, _, _)| *width == 4)
            );
        }
    }

    #[test]
    fn absent_pci_pm_is_configuration_ready_and_wide_bar_is_preserved() {
        let (mut function, timer, _) = fixture(0);
        function.config().words[13] = 0x60; // No PM capability.
        function.config().words[4] = 0x0000_0004;
        function.config().words[5] = 1;
        let bar = Bar::Memory {
            address: 1 << 32,
            size: 0x4000,
            prefetchable: false,
            wide: true,
        };
        assert_eq!(
            prepare_model(&mut function, &timer, bar)
                .unwrap()
                .bar_range(),
            (1 << 32)..(1 << 32) + 0x4000
        );
        assert!(
            !function
                .config()
                .writes
                .iter()
                .any(|(offset, _, _, _)| *offset == 0x54)
        );
    }

    #[test]
    fn ownership_unknown_or_dsp_causes_no_configuration_writes() {
        for ownership in [Ownership::Unknown, Ownership::Dsp] {
            let (mut function, timer, bar) = fixture(0);
            // SAFETY: isolated model; refusal must occur before any mutation.
            assert_eq!(
                unsafe { prepare(&mut function, bar, &timer, ownership) }.unwrap_err(),
                AttachError::Ownership
            );
            assert!(function.config().writes.is_empty());
        }
    }

    #[test]
    fn malformed_capability_lists_and_invalid_bars_refuse_before_mutation() {
        for change in [0, 1, 2, 3, 4, 5] {
            let (mut function, timer, bar) = fixture(0);
            match change {
                0 => function.config().words[13] = 0x51,
                1 => function.config().words[28] |= 0x50 << 8, // Loop.
                2 => function.config().words[28] = 1,          // Second PM.
                3 => function.config().words[20] &= !(7 << 16), // PMv0.
                _ => function.config().words[4] += 0x4000,     // Stale supplied BAR.
            }
            assert!(prepare_model(&mut function, &timer, bar).is_err());
            assert!(function.config().writes.is_empty());
        }
        for bar in [
            Bar::Io {
                port: 0x1000,
                size: 0x1000,
            },
            Bar::Memory {
                address: 0xfebf_0000,
                size: 0x400,
                prefetchable: false,
                wide: false,
            },
            Bar::Memory {
                address: 0xfebf_0000,
                size: 0x4000,
                prefetchable: true,
                wide: false,
            },
            Bar::Memory {
                address: 0xfebf_0000,
                size: 0x4000,
                prefetchable: false,
                wide: true,
            },
        ] {
            let (mut function, timer, _) = fixture(0);
            assert_eq!(
                prepare_model(&mut function, &timer, bar).unwrap_err(),
                AttachError::InvalidBar
            );
            assert!(function.config().writes.is_empty());
        }
    }

    #[test]
    fn overlapping_capability_bodies_and_vendor_tcsel_refuse_before_writes() {
        for variant in 0..5 {
            let (mut function, timer, bar) = fixture(0);
            match variant {
                // PM50's PMCSR becomes an aliased MSI54 header/control pair.
                0 => {
                    function.config().words[20] = 0x0003_5401;
                    function.config().words[21] = 5;
                }
                // Even an unknown header must not occupy the vendor TCSEL byte.
                1 => {
                    function.config().words[13] = 0x44;
                    function.config().words[17] = 0xfe;
                }
                // 32-bit MSI with masks occupies 0x60..0x74, overlapping MSI-X70.
                2 => function.config().words[24] |= u32::from(MSI_VECTOR_MASK) << 16,
                // 64-bit MSI with masks occupies 0x60..0x78, also overlapping70.
                3 => {
                    function.config().words[24] |= u32::from(MSI_VECTOR_MASK | MSI_ADDRESS_64) << 16
                }
                // A known PM body cannot cover a previously encountered unknown header.
                _ => {
                    function.config().words[13] = 0x54;
                    function.config().words[21] = 0x50fe;
                    function.config().words[20] = 0x0003_0001;
                }
            }
            assert_eq!(
                prepare_model(&mut function, &timer, bar).unwrap_err(),
                AttachError::InvalidCapabilities
            );
            assert!(function.config().writes.is_empty());
        }
    }

    #[test]
    fn all_msi_layouts_are_bounded_and_disjoint_when_well_formed() {
        for flags in [
            0,
            MSI_ADDRESS_64,
            MSI_VECTOR_MASK,
            MSI_ADDRESS_64 | MSI_VECTOR_MASK,
        ] {
            let (mut function, timer, bar) = fixture(0);
            function.config().words[24] = (u32::from(flags | 1) << 16) | 5; // MSI ends list.
            prepare_model(&mut function, &timer, bar).unwrap();
        }
    }

    #[test]
    fn config_failure_beginning_after_final_enable_is_rejected_and_cleanup_attempted() {
        let (mut function, timer, bar) = fixture(0);
        function.config().fail_after_enable = true;
        assert_eq!(
            prepare_model(&mut function, &timer, bar).unwrap_err(),
            AttachError::ConfigurationRejected
        );
        let config = function.config();
        assert!(config.writes.iter().any(
            |(off, _, value, _)| *off == PCI_COMMAND && *value & u32::from(COMMAND_MASTER) != 0
        ));
        let (offset, width, value, _) = config.writes.last().unwrap();
        assert_eq!((*offset, *width), (PCI_COMMAND, 2));
        assert_eq!(*value & u32::from(COMMAND_MASTER | COMMAND_MEMORY), 0);
    }

    #[test]
    fn actual_identity_is_checked_against_enumerated_identity_before_writes() {
        let (mut function, timer, bar) = fixture(0);
        function.config().words[0] = 0x27d8_8086; // Still supported, but a different function.
        assert_eq!(
            prepare_model(&mut function, &timer, bar).unwrap_err(),
            AttachError::IdentityChanged
        );
        assert!(function.config().writes.is_empty());
    }

    #[test]
    fn rejected_decode_disable_stops_before_power_or_vendor_writes() {
        let (mut function, timer, bar) = fixture(3);
        function.config().reject_command = true;
        assert_eq!(
            prepare_model(&mut function, &timer, bar).unwrap_err(),
            AttachError::ConfigurationRejected
        );
        assert!(
            function
                .config()
                .writes
                .iter()
                .all(|(offset, width, _, _)| *offset == PCI_COMMAND && *width == 2)
        );
        assert_eq!(timer.now_us(), 0);
    }

    #[test]
    fn power_tcsel_or_command_rejections_fail_and_leave_mastering_disabled() {
        for failure in 0..3 {
            let (mut function, timer, bar) = fixture(3);
            match failure {
                0 => function.config().reject_power = true,
                1 => function.config().reject_vendor_control = true,
                _ => {
                    function.config().set16(PCI_COMMAND, COMMAND_INTX_DISABLE);
                    function.config().reject_command = true;
                }
            }
            let result = prepare_model(&mut function, &timer, bar).unwrap_err();
            assert_eq!(
                result,
                if failure == 0 {
                    AttachError::PowerTransition
                } else {
                    AttachError::ConfigurationRejected
                }
            );
            assert_eq!(
                function.config().get16(PCI_COMMAND) & (COMMAND_MASTER | COMMAND_MEMORY),
                0
            );
        }
    }
    #[test]
    fn legacy_ati_amd_snoop_uses_exact_identity_and_preserves_neighbor_and_tcsel() {
        for (vendor, device, bits) in [
            (ATI, 0x437b, 32),
            (ATI, 0x4383, 32),
            (AMD, 0x780d, 40),
            (AMD, 0x157a, 40),
        ] {
            let (mut function, timer, bar) = fixture(3);
            set_identity(&mut function, vendor, device);
            function.config().words[16] = 0x5aa5_1234; //0x42snoop=a5, adjacent43=5a.
            let prepared = prepare_model(&mut function, &timer, bar).unwrap();
            assert_eq!(prepared.identity().dma_address_bits, bits);
            assert_eq!(prepared.config().dma_address_bits, bits);
            assert_eq!(prepared.config().corb_reset, CorbReset::Handshake);
            let config = function.config();
            assert_eq!(config.words[16], 0x5aa2_1234);
            assert_eq!(config.words[17], 0x5ac3_a5f7); // IntelTCSEL untouched.
            assert!(
                !config
                    .writes
                    .iter()
                    .any(|(offset, _, _, _)| *offset == TCSEL)
            );
            assert!(
                config
                    .writes
                    .iter()
                    .any(|(offset, width, _, time)| *offset == ATI_SNOOP_CONTROL
                        && *width == 1
                        && *time >= 10_000)
            );
        }
    }

    #[test]
    fn newer_amd_ids_select_fifo_retry_snoop_and_explicit_dma_ceiling() {
        for device in [0x1457, 0x1487, 0x15e3] {
            let (mut function, timer, bar) = fixture(3);
            set_identity(&mut function, AMD, device);
            function.config().words[16] = 0x5aa5_1234;
            let prepared = prepare_model(&mut function, &timer, bar).unwrap();
            let policy = prepared.config();
            assert_eq!(policy.corb_reset, CorbReset::Handshake);
            assert_eq!(policy.dma_address_bits, 40);
            assert_eq!(policy.position_policy, PositionPolicy::AmdFifo32);
            assert_eq!(
                policy.probe_policy,
                ProbePolicy::Retry {
                    attempts: 60,
                    delay_us: 1_000_000
                }
            );
            assert_eq!(function.config().words[16], 0x5aa2_1234);
            assert!(
                !function
                    .config()
                    .writes
                    .iter()
                    .any(|(offset, _, _, _)| *offset == TCSEL)
            );
            assert_eq!(function.config().get16(0x54) & 3, 0);
            assert!(timer.now_us() >= 10_000);
        }
        for (vendor, device) in [(INTEL, 0x2668), (ATI, 0x4383), (AMD, 0x157a)] {
            let selected = identity(vendor, device, CLASS).unwrap();
            assert_eq!(selected.position_policy, PositionPolicy::Link);
            assert_eq!(selected.probe_policy, ProbePolicy::Once);
        }
    }

    #[test]
    fn newer_amd_subsystem_exclusions_and_failed_subsystem_reads_refuse_before_writes() {
        for (device, subvendor, subdevice, error) in [
            (0x1487, 0x1043, 0x874f, AttachError::SubsystemExcluded),
            (0x1487, 0x1462, 0xcb59, AttachError::SubsystemExcluded),
            (0x1487, 0x1462, 0xcb60, AttachError::SubsystemExcluded),
            (0x15e3, 0x1462, 0xee59, AttachError::BoardIdentityRequired),
            (0x1457, 0xffff, 0xffff, AttachError::SubsystemUnavailable),
        ] {
            let (mut function, timer, bar) = fixture(0);
            set_identity(&mut function, AMD, device);
            function.config().words[usize::from(PCI_SUBSYSTEM / 4)] = subvendor | (subdevice << 16);
            assert_eq!(
                prepare_model(&mut function, &timer, bar).unwrap_err(),
                error
            );
            assert!(function.config().writes.is_empty());
        }
        // Similar pairs do not inherit another subsystem's exclusion.
        for (device, subvendor, subdevice) in [
            (0x1487, 0x1043, 0x8750),
            (0x1487, 0x1463, 0xcb59),
            (0x15e3, 0x1462, 0xee60),
        ] {
            let (mut function, timer, bar) = fixture(0);
            set_identity(&mut function, AMD, device);
            function.config().words[usize::from(PCI_SUBSYSTEM / 4)] = subvendor | (subdevice << 16);
            prepare_model(&mut function, &timer, bar).unwrap();
        }
    }

    #[test]
    fn conditional_amd_board_exclusion_retains_exact_dmi_condition_and_unknown_evidence() {
        for (vendor, name, expected) in [
            (
                "Micro-Star International Co., Ltd.",
                "MAG X870E TOMAHAWK WIFI (MS-7E59)",
                Some(AttachError::BoardExcluded),
            ),
            (
                "OEM Micro-Star International Co., Ltd. ",
                "prefix MAG X870E TOMAHAWK WIFI (MS-7E59) rev2",
                Some(AttachError::BoardExcluded),
            ),
            (
                "Micro-Star International Co., Ltd.",
                "Different verified laptop board",
                None,
            ),
            (
                "Different verified vendor",
                "MAG X870E TOMAHAWK WIFI (MS-7E59)",
                None,
            ),
            (
                "",
                "MAG X870E TOMAHAWK WIFI (MS-7E59)",
                Some(AttachError::BoardIdentityRequired),
            ),
            (
                "Micro-Star International Co., Ltd.",
                "  ",
                Some(AttachError::BoardIdentityRequired),
            ),
        ] {
            let (mut function, timer, bar) = fixture(0);
            set_identity(&mut function, AMD, 0x15e3);
            function.config().words[usize::from(PCI_SUBSYSTEM / 4)] = 0xee59_1462;
            // SAFETY: modeled target firmware strings, no real platform state.
            let result = unsafe {
                prepare_with_board(
                    &mut function,
                    bar,
                    &timer,
                    Ownership::ExclusiveLegacy,
                    BoardIdentity::Known { vendor, name },
                )
            };
            if let Some(error) = expected {
                assert_eq!(result.unwrap_err(), error);
                assert!(function.config().writes.is_empty());
            } else {
                result.unwrap();
            }
        }
    }

    #[test]
    fn unsupported_amd_dsp_and_gpu_id_families_do_not_inherit_snoop_policy() {
        for (vendor, device) in [
            (AMD, 0x15e2),
            (AMD, 0x1640),
            (AMD, 0xab28),
            (ATI, 0x157a),
            (ATI, 0x0002),
            (0x10de, 0x0be3),
            (INTEL, 0xa170),
        ] {
            let (mut function, timer, bar) = fixture(0);
            set_identity(&mut function, vendor, device);
            assert_eq!(
                prepare_model(&mut function, &timer, bar).unwrap_err(),
                AttachError::UnsupportedController
            );
            assert!(function.config().writes.is_empty());
        }
    }

    #[test]
    fn amd_vendor_control_overlap_and_snoop_rejection_refuse_without_bus_mastering() {
        for variant in 0..3 {
            let (mut function, timer, bar) = fixture(0);
            set_identity(&mut function, AMD, 0x780d);
            match variant {
                0 => {
                    function.config().words[13] = 0x40;
                    function.config().words[16] = 0x0003_0001;
                }
                1 => function.config().reject_vendor_control = true,
                _ => function.config().words[16] = 0x00ff_0000,
            }
            let result = prepare_model(&mut function, &timer, bar).unwrap_err();
            if variant == 0 {
                assert_eq!(result, AttachError::InvalidCapabilities);
                assert!(function.config().writes.is_empty());
            } else {
                assert_eq!(result, AttachError::ConfigurationRejected);
                assert_eq!(
                    function.config().get16(PCI_COMMAND) & (COMMAND_MEMORY | COMMAND_MASTER),
                    0
                );
            }
            assert!(
                !function
                    .config()
                    .writes
                    .iter()
                    .any(|(offset, _, _, _)| *offset == TCSEL)
            );
        }
    }

    #[test]
    fn failed_initial_pci_or_vendor_controls_are_not_used_for_read_modify_write() {
        for vendor_fault in [false, true] {
            let (mut function, timer, bar) = fixture(0);
            if vendor_fault {
                function.config().words[17] |= 0xff;
            } else {
                function.config().set16(PCI_COMMAND, u16::MAX);
            }
            assert_eq!(
                prepare_model(&mut function, &timer, bar).unwrap_err(),
                AttachError::ConfigurationRejected
            );
            if vendor_fault {
                assert!(
                    !function
                        .config()
                        .writes
                        .iter()
                        .any(|(offset, _, _, _)| *offset == TCSEL)
                );
            } else {
                assert!(function.config().writes.is_empty());
            }
        }
    }
}
