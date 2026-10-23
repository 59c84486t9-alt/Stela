// SPDX-License-Identifier: GPL-2.0-only
// Register definitions follow Linux include/uapi/linux/pci_regs.h, copyright
// 1994 Drew Eckhardt and 1997-1999 Martin Mares; stopped PRI/PASID/VF behavior
// follows drivers/pci/ats.c, Copyright (C) 2009 Intel Corporation,
// Yu Zhao <yu.zhao@intel.com>, Copyright (C) 2011 Advanced Micro Devices,
// PRI and PASID additions by Joerg Roedel <joerg.roedel@amd.com>, at commit
// cc9de5d4b5ab6459f5774946aa3195ad51236fa8. See platform/THIRD_PARTY.md.
//! Retained stopped PCI endpoints. A claim grants neither alias isolation nor
//! a remapping-unit takeover. Actual engine/IRQ/work drainage and physical
//! function identity are unsafe producer obligations, not config-bit inferences.
use super::{
    Address, ConfigSpace, Function,
    owned::{ConfigRetention, OwnedConfig},
};
use crate::bus::mmio::owned::{Error as MappingError, Mapping};

const COMMAND: u16 = 4;
const STATUS: u16 = 6;
const BUS_MASTER: u16 = 4;
const INTX_DISABLE: u16 = 1 << 10;
const CAP_LIST: u16 = 1 << 4;
const PM: u16 = 1;
const MSI: u16 = 5;
const PCIX: u16 = 7;
const VENDOR: u16 = 9;
const PCIE: u16 = 0x10;
const MSIX: u16 = 0x11;
const ATS: u16 = 0xf;
const PRI: u16 = 0x13;
const PASID: u16 = 0x1b;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FunctionRole {
    Physical,
    Virtual,
    Unverified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimError {
    Mapping(MappingError),
    AlreadyBound,
    IdentityChanged,
    ReadFailed { offset: u16 },
    Active { offset: u16 },
    MalformedCapability { offset: u16 },
    UnsupportedHeader(u8),
    UnsupportedRole(FunctionRole),
    UnsupportedCapability { id: u16, extended: bool },
    UnsupportedVersion { id: u16, version: u8 },
    UnsupportedPcieType(u8),
}

/// The original configuration owner, with its immutable ECAM BDF and root/
/// resource/reset epoch retained. No mutable config access escapes this claim.
pub struct StoppedRequester {
    function: Function<OwnedConfig>,
    address: Address,
    dma_bound: bool,
}

/// Non-cloneable binding derived from the original validated stopped function.
/// It retains its exact native epoch but supplies no second config writer, new
/// coherency/alias proof, or observation of current endpoint quiescence. The
/// original unsafe stopped/attachment grant persists until explicit retirement.
pub struct RequesterBinding {
    address: Address,
    retention: ConfigRetention,
}
impl RequesterBinding {
    pub fn address(&self) -> Address {
        self.address
    }
    pub fn requester(&self) -> u16 {
        u16::from(self.address.bus) << 8
            | u16::from(self.address.device) << 3
            | u16::from(self.address.function)
    }
    pub fn check_live(&self) -> Result<(), MappingError> {
        self.retention.check_live()
    }
    pub fn matches_mapping(&self, mapping: &Mapping) -> Result<bool, MappingError> {
        self.retention.matches_mapping(mapping)
    }
}

impl StoppedRequester {
    /// # Safety
    /// The actual endpoint's engines, DMA/posted requests, IRQs and workers are
    /// stopped and drained. Payload WB DMA coherency has been independently
    /// qualified for this device and platform. `Physical` must come from the
    /// actual complete PF/VF inventory, never local capability absence. Firmware,
    /// reset, removal and alias/config owners cannot change this retained epoch.
    /// This grants no isolation from aliases and no control over other requesters.
    /// The caller and final release obey process/deferred-context requirements.
    /// Rejection returns the exact original function and mapping owner.
    pub unsafe fn from_stopped_pci(
        mut function: Function<OwnedConfig>,
        role: FunctionRole,
    ) -> Result<Self, (ClaimError, Function<OwnedConfig>)> {
        if role != FunctionRole::Physical {
            return Err((ClaimError::UnsupportedRole(role), function));
        }
        let address = function.config().address();
        if function.address != address {
            return Err((ClaimError::IdentityChanged, function));
        }
        if let Err(error) = validate_stopped(&mut function) {
            return Err((error, function));
        }
        Ok(Self {
            function,
            address,
            dma_bound: false,
        })
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn requester(&self) -> u16 {
        u16::from(self.address.bus) << 8
            | u16::from(self.address.device) << 3
            | u16::from(self.address.function)
    }

    /// Recheck configuration observations without inferring new engine
    /// quiescence or renewing the original producer's epoch grant.
    pub fn check_stopped(&mut self) -> Result<(), ClaimError> {
        if self.function.address != self.address || self.function.config().address() != self.address
        {
            return Err(ClaimError::IdentityChanged);
        }
        validate_stopped(&mut self.function)
    }

    /// Transfer the exact retained owner. Consuming the claim does not end its
    /// mapping lifetime or authorize bus mastering; the recipient owns config.
    pub fn into_function(self) -> Function<OwnedConfig> {
        self.function
    }

    /// Return this exact original stopped owner and retain its actual
    /// mapping/root epoch for one DMA domain. No new function or access path is
    /// manufactured. A private flag forbids a second safe split. Any failure
    /// returns the same original stopped owner.
    /// The sole original owner must not reset, remove or reassign in a way
    /// invalidating the retained resource/routing/coherency/translation epoch.
    /// Only a specifically qualified bounded reset preserving those owners and
    /// ATS/NoSnoop policy is admissible. Reset supplies neither stopped/drained
    /// proof nor remapper completion; retaining a mapping cannot enforce it.
    pub fn into_dma_binding(mut self) -> Result<(Self, RequesterBinding), (ClaimError, Self)> {
        if self.dma_bound {
            return Err((ClaimError::AlreadyBound, self));
        }
        if let Err(error) = self.check_stopped() {
            return Err((error, self));
        }
        let retention = match self.function.config().retain_epoch() {
            Ok(retention) => retention,
            Err(error) => return Err((ClaimError::Mapping(error), self)),
        };
        let binding = RequesterBinding {
            address: self.address,
            retention,
        };
        self.dma_bound = true;
        Ok((self, binding))
    }
}

fn read16<C: ConfigSpace>(config: &C, offset: u16) -> Result<u16, ClaimError> {
    let value = config.read16(offset);
    if value == u16::MAX {
        Err(ClaimError::ReadFailed { offset })
    } else {
        Ok(value)
    }
}

fn inactive<C: ConfigSpace>(config: &C, offset: u16, mask: u16) -> Result<u16, ClaimError> {
    let value = read16(config, offset)?;
    if value & mask != 0 {
        return Err(ClaimError::Active { offset });
    }
    Ok(value)
}

/// Occupancy is in four-byte cells because every capability starts aligned to
/// four. Rounding a partial final cell cannot hide a legal next capability.
struct Extents([u64; 16]);

impl Extents {
    fn reserve(&mut self, offset: u16, bytes: u16, end: u16) -> Result<(), ClaimError> {
        let invalid = || ClaimError::MalformedCapability { offset };
        let last = offset
            .checked_add(bytes)
            .filter(|last| *last <= end)
            .ok_or_else(invalid)?;
        if bytes < 2 || !offset.is_multiple_of(4) {
            return Err(invalid());
        }
        let first = usize::from(offset / 4);
        let limit = usize::from(last.div_ceil(4));
        for slot in first..limit {
            if self.0[slot / 64] & (1 << (slot % 64)) != 0 {
                return Err(invalid());
            }
        }
        for slot in first..limit {
            self.0[slot / 64] |= 1 << (slot % 64);
        }
        Ok(())
    }
}

fn standard<C: ConfigSpace>(config: &C, status: u16) -> Result<(), ClaimError> {
    if status & CAP_LIST == 0 {
        return Ok(());
    }
    let mut offset = u16::from(config.read8(0x34));
    let mut extents = Extents([0; 16]);
    let mut singleton = 0u32;
    while offset != 0 {
        if !(0x40..=0xfc).contains(&offset) || !offset.is_multiple_of(4) {
            return Err(ClaimError::MalformedCapability { offset });
        }
        let header = read16(config, offset)?;
        let id = header & 255;
        let bytes = match id {
            PM => {
                let version = (read16(config, offset + 2)? & 7) as u8;
                if !(1..=3).contains(&version) {
                    return Err(ClaimError::UnsupportedVersion { id, version });
                }
                8
            }
            PCIX => {
                let version = ((read16(config, offset + 2)? >> 12) & 3) as u8;
                match version {
                    0 => 8,
                    1 | 2 => 24,
                    _ => return Err(ClaimError::UnsupportedVersion { id, version }),
                }
            }
            MSI => {
                let flags = inactive(config, offset + 2, 1)?;
                let supported = (flags >> 1) & 7;
                let selected = (flags >> 4) & 7;
                if flags & !0x1ff != 0 || supported > 5 || selected > supported {
                    return Err(ClaimError::MalformedCapability { offset });
                }
                match (flags & 0x80 != 0, flags & 0x100 != 0) {
                    (false, false) => 10,
                    (true, false) => 14,
                    (false, true) => 20,
                    (true, true) => 24,
                }
            }
            MSIX => {
                inactive(config, offset + 2, 1 << 15)?;
                12
            }
            PCIE => {
                let flags = read16(config, offset + 2)?;
                let version = (flags & 15) as u8;
                if !matches!(version, 1 | 2) {
                    return Err(ClaimError::UnsupportedVersion { id, version });
                }
                let kind = ((flags >> 4) & 15) as u8;
                if !matches!(kind, 0 | 1 | 9) || flags & 0x100 != 0 {
                    return Err(ClaimError::UnsupportedPcieType(kind));
                }
                let bytes = match (kind == 9, version) {
                    (true, 1) => 12,
                    (true, _) => 44,
                    (false, 1) => 20,
                    (false, _) => 52,
                };
                // Check the complete extent before reading Device Control.
                if offset.checked_add(bytes).is_none_or(|last| last > 256) {
                    return Err(ClaimError::MalformedCapability { offset });
                }
                inactive(config, offset + 8, 1 << 11)?;
                bytes
            }
            VENDOR => {
                let length = u16::from(config.read8(offset + 2));
                if length < 3 {
                    return Err(ClaimError::MalformedCapability { offset });
                }
                length
            }
            _ => {
                return Err(ClaimError::UnsupportedCapability {
                    id,
                    extended: false,
                });
            }
        };
        extents.reserve(offset, bytes, 256)?;
        if id != VENDOR {
            let bit = 1 << id;
            if singleton & bit != 0 {
                return Err(ClaimError::MalformedCapability { offset });
            }
            singleton |= bit;
        }
        offset = header >> 8;
    }
    Ok(())
}

fn extended<C: ConfigSpace>(config: &C) -> Result<(), ClaimError> {
    let mut offset = 0x100u16;
    let mut extents = Extents([0; 16]);
    let mut singleton = 0u32;
    loop {
        if !(0x100..=0xffc).contains(&offset) || !offset.is_multiple_of(4) {
            return Err(ClaimError::MalformedCapability { offset });
        }
        let header = config.read32(offset);
        if header == u32::MAX {
            return Err(ClaimError::ReadFailed { offset });
        }
        if header == 0 && offset == 0x100 {
            return Ok(());
        }
        let id = header as u16;
        let version = ((header >> 16) & 15) as u8;
        let bytes = match id {
            ATS | PASID => 8,
            PRI => 16,
            0 => return Err(ClaimError::MalformedCapability { offset }),
            _ => return Err(ClaimError::UnsupportedCapability { id, extended: true }),
        };
        if version != 1 {
            return Err(ClaimError::UnsupportedVersion { id, version });
        }
        extents.reserve(offset, bytes, 4096)?;
        let bit = 1 << id;
        if singleton & bit != 0 {
            return Err(ClaimError::MalformedCapability { offset });
        }
        singleton |= bit;
        match id {
            ATS => {
                inactive(config, offset + 6, 1 << 15)?;
            }
            PASID => {
                inactive(config, offset + 6, 1)?;
            }
            PRI => {
                inactive(config, offset + 4, 3)?;
                if read16(config, offset + 6)? & 0x100 == 0 {
                    return Err(ClaimError::Active { offset: offset + 6 });
                }
            }
            _ => unreachable!("recognized translation capability"),
        }
        offset = (header >> 20) as u16;
        if offset == 0 {
            return Ok(());
        }
    }
}

fn validate_stopped<C: ConfigSpace>(function: &mut Function<C>) -> Result<(), ClaimError> {
    let expected = u32::from(function.vendor) | u32::from(function.device) << 16;
    let class = function.class;
    let config = function.config();
    let identity = config.read32(0);
    if identity == u32::MAX {
        return Err(ClaimError::ReadFailed { offset: 0 });
    }
    let actual_class = config.read32(8);
    if actual_class == u32::MAX {
        return Err(ClaimError::ReadFailed { offset: 8 });
    }
    if identity != expected
        || [
            (actual_class >> 24) as u8,
            (actual_class >> 16) as u8,
            (actual_class >> 8) as u8,
        ] != class
    {
        return Err(ClaimError::IdentityChanged);
    }
    let header = config.read8(0x0e);
    if header == u8::MAX {
        return Err(ClaimError::ReadFailed { offset: 0x0e });
    }
    if header & 0x7f != 0 {
        return Err(ClaimError::UnsupportedHeader(header & 0x7f));
    }
    if inactive(config, COMMAND, BUS_MASTER)? & INTX_DISABLE == 0 {
        return Err(ClaimError::Active { offset: COMMAND });
    }
    standard(config, read16(config, STATUS)?)?;
    extended(config)?;
    // A second identity read catches observed removal/reset during traversal.
    // The retained epoch grant, not this observation, excludes concurrent change.
    if config.read32(0) != identity {
        return Err(ClaimError::IdentityChanged);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::owned::tests::{Counters, fixture};
    use super::*;
    use alloc::sync::Arc;
    use core::{cell::Cell, sync::atomic::Ordering};

    const ADDRESS: Address = Address {
        segment: 0xfffe,
        bus: 0xe7,
        device: 29,
        function: 6,
    };

    struct Config {
        words: [u32; 1024],
        last_read: Cell<u16>,
    }
    impl ConfigSpace for Config {
        fn read32(&self, offset: u16) -> u32 {
            self.last_read.set(offset);
            self.words[usize::from(offset / 4)]
        }
        fn write32(&mut self, offset: u16, value: u32) {
            self.words[usize::from(offset / 4)] = value;
        }
    }
    fn configure<C: ConfigSpace>(config: &mut C) {
        config.write32(0, 0x2c02_10de);
        config.write32(8, 0x0300_0000);
        config.write16(COMMAND, INTX_DISABLE);
    }
    fn endpoint() -> Function<Config> {
        let mut config = Config {
            words: [0; 1024],
            last_read: Cell::new(0),
        };
        configure(&mut config);
        Function::new(ADDRESS, config).unwrap()
    }
    fn cap(function: &mut Function<Config>, offset: u16, id: u16, next: u16) {
        function.config().write16(STATUS, CAP_LIST);
        function.config().write8(0x34, offset as u8);
        function.config().write16(offset, id | next << 8);
        if id == PM {
            function.config().write16(offset + 2, 3);
        }
    }
    fn ext(function: &mut Function<Config>, offset: u16, id: u16, version: u32, next: u16) {
        function.config().write32(
            offset,
            u32::from(id) | version << 16 | u32::from(next) << 20,
        );
    }
    fn release(function: Function<OwnedConfig>, counters: &Arc<Counters>) {
        let mut mapping = function.into_config().into_mapping();
        assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
        // SAFETY: fixture has no device, IRQ or workers and no config access
        // remains after consuming the exact original function owner.
        unsafe { mapping.retire() }.unwrap();
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
        assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 1);
        assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn actual_owned_config_binds_full_segment_rid_and_retains_original_epoch() {
        let (mut config, counters) = fixture(ADDRESS);
        configure(&mut config);
        let function = Function::new(ADDRESS, config).unwrap();
        // SAFETY: isolated RAM fixture has no active engine, alias, VF or IRQ;
        // its real registry owners are retained, without native qualification.
        let mut claim =
            match unsafe { StoppedRequester::from_stopped_pci(function, FunctionRole::Physical) } {
                Ok(claim) => claim,
                Err((error, _)) => panic!("valid owned endpoint: {error:?}"),
            };
        assert_eq!(claim.address(), ADDRESS);
        assert_eq!(claim.requester(), 0xe7ee);
        assert_eq!(claim.check_stopped(), Ok(()));
        assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
        assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 0);
        release(claim.into_function(), &counters);
    }

    fn bound_fixture() -> (StoppedRequester, RequesterBinding, Arc<Counters>) {
        let (mut config, counters) = fixture(ADDRESS);
        configure(&mut config);
        let function = Function::new(ADDRESS, config).unwrap();
        // SAFETY: actual isolated registry-owned RAM; no device/IRQ/worker.
        let claim =
            match unsafe { StoppedRequester::from_stopped_pci(function, FunctionRole::Physical) } {
                Ok(claim) => claim,
                Err((error, _)) => panic!("fixture claim: {error:?}"),
            };
        let (function, binding) = match claim.into_dma_binding() {
            Ok(pair) => pair,
            Err((error, _)) => panic!("fixture binding: {error:?}"),
        };
        (function, binding, counters)
    }

    #[test]
    fn binding_retains_exact_original_config_and_native_root_until_explicit_release() {
        let (mut claim, binding, counters) = bound_fixture();
        assert_eq!(claim.check_stopped(), Ok(()));
        let (error, claim) = match claim.into_dma_binding() {
            Err(error) => error,
            Ok(_) => panic!("second safe DMA binding accepted"),
        };
        assert_eq!(error, ClaimError::AlreadyBound);
        let mut function = claim.into_function();
        assert_eq!(binding.address(), ADDRESS);
        assert_eq!(binding.requester(), 0xe7ee);
        assert_eq!(binding.check_live(), Ok(()));
        assert_eq!(function.config().read32(0), 0x2c02_10de);
        let mut mapping = function.into_config().into_mapping();
        assert_eq!(binding.matches_mapping(&mapping), Ok(true));
        // SAFETY: stopped synchronous fixture; Busy must refuse before unmap.
        assert_eq!(unsafe { mapping.retire() }, Err(MappingError::Busy));
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
        let (other, other_counters) = fixture(ADDRESS);
        let mut other = other.into_mapping();
        // Same BDF and even the fixture's same numeric root identity do not
        // reproduce the original retained Authority allocation.
        assert_eq!(binding.matches_mapping(&other), Ok(false));
        drop(binding);
        // SAFETY: explicit fixture release follows the final retained binding.
        unsafe { mapping.retire() }.unwrap();
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
        assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 1);
        // SAFETY: independent original synchronous fixture mapping.
        unsafe { other.retire() }.unwrap();
        assert_eq!(other_counters.unmaps.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn dropping_original_config_permanently_quarantines_the_bound_epoch() {
        let (function, binding, counters) = bound_fixture();
        drop(function);
        assert!(binding.check_live().is_err());
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
        drop(binding);
        assert_eq!(counters.unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
        assert_eq!(counters.platform_drops.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn binding_recheck_refusal_returns_the_unchanged_original_function() {
        let (mut config, counters) = fixture(ADDRESS);
        configure(&mut config);
        let function = Function::new(ADDRESS, config).unwrap();
        // SAFETY: isolated synchronous stopped fixture, as above.
        let mut claim =
            match unsafe { StoppedRequester::from_stopped_pci(function, FunctionRole::Physical) } {
                Ok(claim) => claim,
                Err((error, _)) => panic!("fixture claim: {error:?}"),
            };
        // Private test access models an actual changed hardware observation.
        claim
            .function
            .config()
            .write16(COMMAND, INTX_DISABLE | BUS_MASTER);
        let (error, claim) = match claim.into_dma_binding() {
            Err(error) => error,
            Ok(_) => panic!("active requester accepted"),
        };
        assert_eq!(error, ClaimError::Active { offset: COMMAND });
        let mut function = claim.into_function();
        assert_eq!(function.address, ADDRESS);
        assert_eq!(function.config().read16(COMMAND), INTX_DISABLE | BUS_MASTER);
        function.config().write16(COMMAND, INTX_DISABLE);
        release(function, &counters);
    }

    #[test]
    fn rejected_roles_and_mutable_public_metadata_return_the_original_owner() {
        for role in [FunctionRole::Virtual, FunctionRole::Unverified] {
            let (mut config, counters) = fixture(ADDRESS);
            configure(&mut config);
            let function = Function::new(ADDRESS, config).unwrap();
            // SAFETY: fixture is drained; unsupported role makes no grant.
            let (error, function) =
                match unsafe { StoppedRequester::from_stopped_pci(function, role) } {
                    Err(rejected) => rejected,
                    Ok(_) => panic!("unsupported role admitted"),
                };
            assert_eq!(error, ClaimError::UnsupportedRole(role));
            release(function, &counters);
        }
        let (mut config, counters) = fixture(ADDRESS);
        configure(&mut config);
        let mut function = Function::new(ADDRESS, config).unwrap();
        function.address.bus ^= 1;
        // SAFETY: drained fixture, deliberately mismatched metadata must fail.
        let (error, function) =
            match unsafe { StoppedRequester::from_stopped_pci(function, FunctionRole::Physical) } {
                Err(rejected) => rejected,
                Ok(_) => panic!("forged metadata admitted"),
            };
        assert_eq!(error, ClaimError::IdentityChanged);
        release(function, &counters);
    }

    #[test]
    fn device_identity_interrupt_gating_and_header_are_observed_not_assumed() {
        assert_eq!(validate_stopped(&mut endpoint()), Ok(()));
        for (offset, value, expected) in [
            (0, u32::MAX, ClaimError::ReadFailed { offset: 0 }),
            (0, 0x2c03_10de, ClaimError::IdentityChanged),
            (8, u32::MAX, ClaimError::ReadFailed { offset: 8 }),
            (8, 0x0400_0000, ClaimError::IdentityChanged),
            (4, 0x0404, ClaimError::Active { offset: 4 }),
            (4, 0, ClaimError::Active { offset: 4 }),
            (4, 0xffff, ClaimError::ReadFailed { offset: 4 }),
            (0x100, u32::MAX, ClaimError::ReadFailed { offset: 0x100 }),
        ] {
            let mut function = endpoint();
            function.config().write32(offset, value);
            assert_eq!(validate_stopped(&mut function), Err(expected));
        }
        let mut function = endpoint();
        function.config().write8(0x0e, 1);
        assert_eq!(
            validate_stopped(&mut function),
            Err(ClaimError::UnsupportedHeader(1))
        );
        let mut function = endpoint();
        function.class = [0xff; 3];
        function.config().write32(8, u32::MAX);
        assert_eq!(
            validate_stopped(&mut function),
            Err(ClaimError::ReadFailed { offset: 8 })
        );
    }

    #[test]
    fn msi_layouts_pcie_versions_and_no_snoop_require_complete_extents() {
        for (flags, length) in [(0, 10), (0x80, 14), (0x100, 20), (0x180, 24)] {
            let mut function = endpoint();
            cap(&mut function, 0x40, MSI, 0);
            function.config().write16(0x42, flags);
            assert_eq!(validate_stopped(&mut function), Ok(()));
            function.config().write16(0x42, flags | 1);
            assert_eq!(
                validate_stopped(&mut function),
                Err(ClaimError::Active { offset: 0x42 })
            );
            function.config().write16(0x42, flags);
            let collision = 0x40 + ((length - 1) / 4) * 4;
            function.config().write16(0x40, MSI | collision << 8);
            function.config().write16(collision, PM);
            function.config().write16(collision + 2, 3);
            assert_eq!(
                validate_stopped(&mut function),
                Err(ClaimError::MalformedCapability { offset: collision })
            );
        }
        for (kind, version, bytes) in [(0, 1, 20), (1, 2, 52), (9, 1, 12), (9, 2, 44)] {
            let mut function = endpoint();
            cap(&mut function, 0x40, PCIE, 0);
            function.config().write16(0x42, version | kind << 4);
            assert_eq!(validate_stopped(&mut function), Ok(()));
            function.config().write16(0x48, 1 << 11);
            assert_eq!(
                validate_stopped(&mut function),
                Err(ClaimError::Active { offset: 0x48 })
            );
            // A full layout one DWORD beyond the conventional region is refused
            // before Device Control could be read from unrelated space.
            let offset = 260 - bytes;
            let mut function = endpoint();
            cap(&mut function, offset, PCIE, 0);
            function.config().write16(offset + 2, version | kind << 4);
            assert_eq!(
                validate_stopped(&mut function),
                Err(ClaimError::MalformedCapability { offset })
            );
            assert!(function.config().last_read.get() <= offset);
        }
        let mut function = endpoint();
        cap(&mut function, 0x40, MSIX, 0);
        function.config().write16(0x42, 0x8000);
        assert_eq!(
            validate_stopped(&mut function),
            Err(ClaimError::Active { offset: 0x42 })
        );
    }

    #[test]
    fn linked_zero_cycles_overlaps_unknowns_and_unmasked_pointers_are_refused() {
        for pointer in [0x3f, 0x41, 0xff] {
            let mut function = endpoint();
            function.config().write16(STATUS, CAP_LIST);
            function.config().write8(0x34, pointer);
            assert!(matches!(
                validate_stopped(&mut function),
                Err(ClaimError::MalformedCapability { .. })
            ));
        }
        for (first, second) in [(0x40, 0x44), (0x44, 0x40), (0x40, 0x40)] {
            let mut function = endpoint();
            cap(&mut function, first, PM, second);
            if first != second {
                function.config().write16(second, PM);
                function.config().write16(second + 2, 3);
            }
            assert!(matches!(
                validate_stopped(&mut function),
                Err(ClaimError::MalformedCapability { .. })
            ));
        }
        let mut unknown = endpoint();
        cap(&mut unknown, 0x40, 0x7f, 0);
        assert_eq!(
            validate_stopped(&mut unknown),
            Err(ClaimError::UnsupportedCapability {
                id: 0x7f,
                extended: false
            })
        );
        let mut unknown = endpoint();
        ext(&mut unknown, 0x100, 0x7fff, 1, 0);
        assert_eq!(
            validate_stopped(&mut unknown),
            Err(ClaimError::UnsupportedCapability {
                id: 0x7fff,
                extended: true
            })
        );
        for next in [0x104, 0x101, 0xfff, 0x100, 0x120] {
            let mut function = endpoint();
            ext(&mut function, 0x100, ATS, 1, next);
            assert!(validate_stopped(&mut function).is_err());
        }
    }

    #[test]
    fn pcix_versioned_bodies_cannot_hide_an_overlapping_capability() {
        for version in 0..=2 {
            let mut function = endpoint();
            cap(&mut function, 0x40, PCIX, 0);
            function.config().write16(0x42, version << 12);
            assert_eq!(validate_stopped(&mut function), Ok(()));
        }
        let mut function = endpoint();
        cap(&mut function, 0x40, PCIX, 0);
        function.config().write16(0x42, 3 << 12);
        assert_eq!(
            validate_stopped(&mut function),
            Err(ClaimError::UnsupportedVersion {
                id: PCIX,
                version: 3
            })
        );
        for version in [1, 2] {
            for reverse in [false, true] {
                let mut function = endpoint();
                cap(&mut function, 0x40, PCIX, if reverse { 0 } else { 0x48 });
                function.config().write16(0x42, version << 12);
                function
                    .config()
                    .write16(0x48, MSI | if reverse { 0x40 << 8 } else { 0 });
                if reverse {
                    function.config().write8(0x34, 0x48);
                }
                assert!(matches!(
                    validate_stopped(&mut function),
                    Err(ClaimError::MalformedCapability { .. })
                ));
            }
        }
        for version in 0..=7 {
            let mut function = endpoint();
            cap(&mut function, 0x40, PM, 0);
            function.config().write16(0x42, version);
            let result = validate_stopped(&mut function);
            if (1..=3).contains(&version) {
                assert_eq!(result, Ok(()));
            } else {
                assert_eq!(
                    result,
                    Err(ClaimError::UnsupportedVersion {
                        id: PM,
                        version: version as u8
                    })
                );
            }
        }
    }

    #[test]
    fn translation_features_require_inactive_controls_and_stopped_pri() {
        for (id, control, active) in [(ATS, 6, 0x8000), (PRI, 4, 1), (PRI, 4, 2), (PASID, 6, 1)] {
            let mut function = endpoint();
            ext(&mut function, 0x100, id, 1, 0);
            if id == PRI {
                function.config().write16(0x106, 0x100);
            }
            assert_eq!(validate_stopped(&mut function), Ok(()));
            function.config().write16(0x100 + control, active);
            assert_eq!(
                validate_stopped(&mut function),
                Err(ClaimError::Active {
                    offset: 0x100 + control
                })
            );
            function.config().write16(0x100 + control, u16::MAX);
            assert_eq!(
                validate_stopped(&mut function),
                Err(ClaimError::ReadFailed {
                    offset: 0x100 + control
                })
            );
        }
        let mut function = endpoint();
        ext(&mut function, 0x100, PRI, 1, 0);
        assert_eq!(
            validate_stopped(&mut function),
            Err(ClaimError::Active { offset: 0x106 })
        );
        for (id, bytes) in [(ATS, 8), (PRI, 16), (PASID, 8)] {
            let mut function = endpoint();
            ext(&mut function, 0x100, ATS, 1, 4100 - bytes);
            ext(&mut function, 4100 - bytes, id, 1, 0);
            assert!(matches!(
                validate_stopped(&mut function),
                Err(ClaimError::MalformedCapability { .. })
            ));
            let mut function = endpoint();
            ext(&mut function, 0x100, id, 2, 0);
            assert_eq!(
                validate_stopped(&mut function),
                Err(ClaimError::UnsupportedVersion { id, version: 2 })
            );
        }
    }
}
