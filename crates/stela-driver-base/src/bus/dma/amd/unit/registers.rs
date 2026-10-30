// SPDX-License-Identifier: GPL-2.0-only
// PCI capability encodings follow Linux include/uapi/linux/pci_regs.h at
// cc9de5d4b5ab6459f5774946aa3195ad51236fa8, Copyright 1994 Drew Eckhardt
// and 1997–1999 Martin Mares. AMD register layouts follow AMD 48882 rev 3.11.
//! Read-only, function-grouped AMD-Vi register inspection. Layouts follow AMD
//! 48882 revision 3.11 sections 1.3, 2.3, 3.1–3.4 and 5.2. No register writer,
//! borrowed mapping view, numeric permission or successful completion is exposed.
use crate::bus::{
    dma::amd::ivrs::{HardwareVersion, Ivhd, Ivrs},
    mmio::owned::{CacheAttribute, Error as MappingError, Mapping, Protection},
    pci::{Address, ConfigSpace, Function, owned::OwnedConfig},
};
use alloc::vec::Vec;
use core::{marker::PhantomData, mem::size_of};

mod capability;

const CONFIG_LIMIT: u16 = 256;
const CAP_LIMIT: usize = 48;
const SECURE_DEVICE: u8 = 0x0f;
const IOMMU_TYPE: u32 = 3;
const IOMMU_REVISION: u32 = 1;
const EFR_SUPPORTED: u32 = 1 << 27;
const CAP_EXTENDED: u32 = 1 << 28;
const BASE_ENABLED: u32 = 1;
const BASE_LOW_MASK: u32 = 0xffff_c000;
const RANGE_VALID: u32 = 1 << 7;
const IVINFO_EFR_SUPPORTED: u32 = 1;
const PERFORMANCE_COUNTERS: u64 = 1 << 9;
const SMALL_APERTURE: usize = 16 * 1024;
const COUNTER_APERTURE: usize = 512 * 1024;
const EXTENDED_FEATURES: usize = 0x30;
const EXTENDED_FEATURES_2: usize = 0x1a0;
const DEVICE_TABLE: usize = 0x0000;
const COMMAND_BUFFER: usize = 0x0008;
const EVENT_LOG: usize = 0x0010;
const CONTROL: usize = 0x0018;
const COMMAND_HEAD: usize = 0x2000;
const COMMAND_TAIL: usize = 0x2008;
const EVENT_HEAD: usize = 0x2010;
const EVENT_TAIL: usize = 0x2018;
const STATUS: usize = 0x2020;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Identity,
    Header(u8),
    ReadFailed(u16),
    Capability(u16),
    UnsupportedCapability { offset: u16, id: u8 },
    UnsupportedLayout(u16),
    Firmware,
    MissingInstance(u16),
    Disabled(u16),
    Range(u16),
    Register(usize),
    MappingCount,
    InterruptLayout,
    MappingGeometry,
    MappingPolicy,
    Overlap,
    FeatureReporting(u16),
    OutOfMemory,
    Mapping(MappingError),
}

/// Owners on entry and refusal. Returning these never retires a mapping;
/// the caller still owes its original context and explicit retirement protocol.
pub struct Inputs {
    pub function: Function<OwnedConfig>,
    pub mappings: Vec<Mapping>,
}

/// Raw configuration observations. Deprecated UnitID and register range are
/// evidence only; neither replaces IVRS topology or an alias-group owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Configuration {
    pub capability_offset: u16,
    pub header: u32,
    pub base_low: u32,
    pub base_high: u32,
    pub range: u32,
    pub miscellaneous: u32,
    pub miscellaneous_1: Option<u32>,
}
impl Configuration {
    pub fn base(self) -> u64 {
        u64::from(self.base_high) << 32 | u64::from(self.base_low & BASE_LOW_MASK)
    }
}

/// Firmware policy remains separate from hardware observations. These copied
/// fields preserve the selected block's coordinates; the original IVRS ledger
/// remains authoritative for complete bytes, routing and memory definitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Firmware {
    pub offset: usize,
    pub version: HardwareVersion,
    pub ivrs_info: u32,
    pub flags: u8,
    pub info: u16,
    pub feature_or_attributes: u32,
    pub extended_features: Option<(u64, u64)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Profile {
    pub configuration: Configuration,
    pub firmware: Firmware,
    /// None means the capability makes both registers reserved; they
    /// were not read. Raw hardware values grant no firmware-disabled feature.
    pub hardware_extended_features: Option<(u64, u64)>,
    /// Conservative union of physical and firmware decode requirements.
    pub aperture_bytes: usize,
    mapping: usize,
}

/// A non-atomic series of non-clearing register observations. Engines may
/// advance between reads. Head movement and status never prove completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub device_table: u64,
    pub command_buffer: u64,
    pub event_log: u64,
    pub control: u64,
    pub command_head: u64,
    pub command_tail: u64,
    pub event_head: u64,
    pub event_tail: u64,
    pub status: u64,
}

/// Keeps one original PCI function and every unit mapping. No independent
/// per-capability owner can invalidate another unit's configuration/IRQ epoch.
/// The complete checksum-validated original IVRS bytes remain attached too.
pub struct FunctionInspection {
    inputs: Inputs,
    address: Address,
    profiles: Vec<Profile>,
    firmware: Vec<u8>,
    _process_context: PhantomData<*mut ()>,
}
impl FunctionInspection {
    pub(super) fn native_firmware(&self) -> &[u8] {
        &self.firmware
    }
    // Native ownership remains in this inspection. Only the cold backend may
    // select registers; neither a public pointer nor a writable view escapes.
    pub(super) fn native_read(&self, offset: usize) -> Result<u64, Error> {
        if self.profiles.len() != 1 {
            return Err(Error::MappingCount);
        }
        read_register(&self.inputs.mappings[self.profiles[0].mapping], offset)
    }

    pub(super) fn native_write(&self, offset: usize, value: u64) -> Result<(), Error> {
        if self.profiles.len() != 1 {
            return Err(Error::MappingCount);
        }
        let mapping = &self.inputs.mappings[self.profiles[0].mapping];
        let pointer = mapping
            .address(offset, size_of::<u64>())
            .map_err(Error::Mapping)?;
        if !(pointer.as_ptr() as usize).is_multiple_of(size_of::<u64>()) {
            return Err(Error::MappingGeometry);
        }
        // SAFETY: the native backend's unsafe cold grant keeps this exact
        // exclusive UC/RW unit and checks aligned native write64 accesses.
        // Its closed register selection contains no status W1C writes.
        unsafe { pointer.cast::<u64>().as_ptr().write_volatile(value.to_le()) };
        Ok(())
    }

    /// # Safety
    /// Inputs are the IOMMU function and all its selected physical unit
    /// resources, under their original exclusive configuration/reset/root and
    /// MMIO access epochs. The complete IVRS is the firmware input for
    /// that epoch. Firmware, other native drivers and other CPU access paths
    /// cannot mutate configuration or invalidate these resources. The platform
    /// has checked native aligned read64 accesses to the UC
    /// mappings, including decode validity of their complete physical spans.
    /// The caller keeps the checked process/deferred CPU context through
    /// inspection, snapshots, return and final release. This grants no unit
    /// takeover, engine stop, DMA coherency, IRQ or requester/alias permission.
    /// No hardware state is changed, including on refusal or allocation failure.
    pub unsafe fn inspect(mut inputs: Inputs, ivrs: &Ivrs<'_>) -> Result<Self, (Error, Inputs)> {
        let mut firmware = Vec::new();
        if firmware.try_reserve_exact(ivrs.raw().len()).is_err() {
            return Err((Error::OutOfMemory, inputs));
        }
        firmware.extend_from_slice(ivrs.raw());
        match prepare(&mut inputs, ivrs) {
            Ok(profiles) => Ok(Self {
                address: inputs.function.address,
                inputs,
                profiles,
                firmware,
                _process_context: PhantomData,
            }),
            Err(error) => Err((error, inputs)),
        }
    }

    pub fn address(&self) -> Address {
        self.address
    }
    pub fn profiles(&self) -> &[Profile] {
        &self.profiles
    }
    /// Returns None for an unrepresented capability, never an invented unit.
    pub fn snapshot(&self, capability_offset: u16) -> Result<Option<Snapshot>, Error> {
        let Some(profile) = self
            .profiles
            .iter()
            .find(|p| p.configuration.capability_offset == capability_offset)
        else {
            return Ok(None);
        };
        let mapping = &self.inputs.mappings[profile.mapping];
        Ok(Some(Snapshot {
            device_table: read_register(mapping, DEVICE_TABLE)?,
            command_buffer: read_register(mapping, COMMAND_BUFFER)?,
            event_log: read_register(mapping, EVENT_LOG)?,
            control: read_register(mapping, CONTROL)?,
            command_head: read_register(mapping, COMMAND_HEAD)?,
            command_tail: read_register(mapping, COMMAND_TAIL)?,
            event_head: read_register(mapping, EVENT_HEAD)?,
            event_tail: read_register(mapping, EVENT_TAIL)?,
            status: read_register(mapping, STATUS)?,
        }))
    }
    /// No writes or publications took place. Original mapping retirement and
    /// producer epoch obligations survive this consuming transfer unchanged.
    pub fn into_inputs(self) -> Inputs {
        self.inputs
    }
}

fn read_register(mapping: &Mapping, offset: usize) -> Result<u64, Error> {
    let pointer = mapping
        .address(offset, size_of::<u64>())
        .map_err(Error::Mapping)?;
    if !(pointer.as_ptr() as usize).is_multiple_of(size_of::<u64>()) {
        return Err(Error::MappingGeometry);
    }
    // SAFETY: inspect's producer checks native aligned read64 and
    // keeps the exclusive UC resource/context; callers select known readable
    // non-clearing registers only. Registry access rechecks the original lease.
    let value = u64::from_le(unsafe { pointer.cast::<u64>().as_ptr().read_volatile() });
    if value == u64::MAX {
        Err(Error::Register(offset))
    } else {
        Ok(value)
    }
}

fn prepare(inputs: &mut Inputs, ivrs: &Ivrs<'_>) -> Result<Vec<Profile>, Error> {
    if !matches!(ivrs.revision(), 1 | 2) {
        return Err(Error::Firmware);
    }
    let function = &mut inputs.function;
    let address = function.address;
    let expected_id = u32::from(function.vendor) | u32::from(function.device) << 16;
    let expected_class = function.class;
    let config = function.config();
    let class = config.read32(8);
    if config.address() != address
        || config.read32(0) != expected_id
        || expected_class != [0x08, 0x06, 0]
        || class >> 8 != 0x080600
    {
        return Err(Error::Identity);
    }
    let header = config.read8(0x0e) & 0x7f;
    if header != 0 {
        return Err(Error::Header(header));
    }
    let capabilities = capability::scan(config)?;
    if capabilities.count > 1 && !capabilities.has_msix {
        return Err(Error::InterruptLayout);
    }
    let belongs = |unit: &Ivhd<'_>| {
        unit.id().segment == address.segment
            && unit.id().device_id
                == (u16::from(address.bus) << 8
                    | u16::from(address.device) << 3
                    | u16::from(address.function))
    };
    let count = ivrs.units().filter(belongs).count();
    if count == 0 || count != capabilities.count {
        return Err(Error::Firmware);
    }
    if inputs.mappings.len() != count {
        return Err(Error::MappingCount);
    }
    // Entire provided resource geometry is checked before the first MMIO read.
    for (index, mapping) in inputs.mappings.iter().enumerate() {
        validate_mapping(mapping)?;
        let span = mapping.physical_span().map_err(Error::Mapping)?;
        for previous in &inputs.mappings[..index] {
            let other = previous.physical_span().map_err(Error::Mapping)?;
            if span.start() < other.end() && other.start() < span.end() {
                return Err(Error::Overlap);
            }
        }
    }
    let mut profiles = Vec::new();
    profiles
        .try_reserve_exact(count)
        .map_err(|_| Error::OutOfMemory)?;
    for unit in ivrs.units().filter(belongs) {
        if unit.version() == HardwareVersion::Type40 && ivrs.revision() != 2 {
            return Err(Error::Firmware);
        }
        let configuration = capabilities.entries[..capabilities.count]
            .iter()
            .flatten()
            .find(|cap| cap.capability_offset == unit.capability_offset())
            .copied()
            .ok_or(Error::MissingInstance(unit.capability_offset()))?;
        if configuration.base() != unit.mmio_address() {
            return Err(Error::Firmware);
        }
        let firmware_efr = ivrs.info() & IVINFO_EFR_SUPPORTED != 0;
        let actual_efr = configuration.header & EFR_SUPPORTED != 0;
        let firmware_counters = firmware_counters(unit, firmware_efr)?;
        if (firmware_efr && !actual_efr)
            || (unit.extended_features().is_some() && !firmware_efr)
            || (firmware_counters && !actual_efr)
        {
            return Err(Error::FeatureReporting(configuration.capability_offset));
        }
        let mapping = inputs
            .mappings
            .iter()
            .position(|mapping| {
                mapping
                    .physical_span()
                    .is_ok_and(|span| span.start() == unit.mmio_address())
            })
            .ok_or(Error::MappingGeometry)?;
        if profiles.iter().any(|p: &Profile| p.mapping == mapping) {
            return Err(Error::Overlap);
        }
        let bytes = inputs.mappings[mapping].bytes().map_err(Error::Mapping)?;
        if (firmware_counters && bytes != COUNTER_APERTURE)
            || (!actual_efr && bytes != SMALL_APERTURE)
        {
            return Err(Error::MappingGeometry);
        }
        profiles.push(Profile {
            configuration,
            firmware: Firmware {
                offset: unit.offset(),
                version: unit.version(),
                ivrs_info: ivrs.info(),
                flags: unit.flags(),
                info: unit.info(),
                feature_or_attributes: unit.feature_or_attributes(),
                extended_features: unit.extended_features(),
            },
            hardware_extended_features: None,
            aperture_bytes: if firmware_counters {
                COUNTER_APERTURE
            } else {
                SMALL_APERTURE
            },
            mapping,
        });
    }
    // All config/firmware associations have passed. No reserved register is
    // read when the capability lacks EFRSup, regardless of ACPI claims.
    // A base without its enable bit (QEMU's amd-iommu leaves it clear) is
    // used when its registers answer, as Linux uses the IVHD's base.
    for profile in &profiles {
        if profile.configuration.base_low & BASE_ENABLED == 0 {
            read_register(&inputs.mappings[profile.mapping], CONTROL)
                .map_err(|_| Error::Disabled(profile.configuration.capability_offset))?;
        }
    }
    for profile in &mut profiles {
        let mapping = &inputs.mappings[profile.mapping];
        if profile.configuration.header & EFR_SUPPORTED != 0 {
            let features = read_register(mapping, EXTENDED_FEATURES)?;
            let features_2 = read_register(mapping, EXTENDED_FEATURES_2)?;
            profile.hardware_extended_features = Some((features, features_2));
            if features & PERFORMANCE_COUNTERS != 0 {
                profile.aperture_bytes = COUNTER_APERTURE;
            }
        }
        if mapping.bytes().map_err(Error::Mapping)? != profile.aperture_bytes
            || !profile
                .configuration
                .base()
                .is_multiple_of(profile.aperture_bytes as u64)
        {
            return Err(Error::MappingGeometry);
        }
    }
    Ok(profiles)
}

fn validate_mapping(mapping: &Mapping) -> Result<(), Error> {
    let bytes = mapping.bytes().map_err(Error::Mapping)?;
    let span = mapping.physical_span().map_err(Error::Mapping)?;
    if !matches!(bytes, SMALL_APERTURE | COUNTER_APERTURE)
        || span.bytes() != bytes as u64
        || !span.start().is_multiple_of(bytes as u64)
    {
        return Err(Error::MappingGeometry);
    }
    if mapping.attribute().map_err(Error::Mapping)? != CacheAttribute::Uncached
        || mapping.protection().map_err(Error::Mapping)? != Protection::ReadWrite
    {
        return Err(Error::MappingPolicy);
    }
    let cpu = mapping.address(0, bytes).map_err(Error::Mapping)?.as_ptr() as usize;
    if !cpu.is_multiple_of(size_of::<u64>()) || cpu.checked_add(bytes).is_none() {
        return Err(Error::MappingGeometry);
    }
    Ok(())
}

fn firmware_counters(unit: Ivhd<'_>, firmware_efr: bool) -> Result<bool, Error> {
    if !firmware_efr {
        // Type 10's feature-reporting field is reserved without IVINFO.EFRSup;
        // keep its raw bytes, but never derive geometry from reserved data.
        return Ok(false);
    }
    if let Some((features, _)) = unit.extended_features() {
        return Ok(features & PERFORMANCE_COUNTERS != 0);
    }
    let value = unit.feature_or_attributes();
    let banks = (value >> 17) & 0x3f;
    let counters = (value >> 13) & 0xf;
    match (banks != 0, counters != 0) {
        (false, false) => Ok(false),
        (true, true) => Ok(true),
        _ => Err(Error::FeatureReporting(unit.capability_offset())),
    }
}

#[cfg(test)]
mod tests;
