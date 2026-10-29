//! Admission of the IVRS description of one AMD IOMMU unit.
use super::*;
use crate::bus::dma::amd::{
    device::REQUESTERS,
    ivrs::{DeviceKind, RangePolicy},
};

pub(super) struct Admission {
    pub(super) bits: u8,
    pub(super) segment: u16,
    pub(super) control: u64,
    pub(super) hardware_errors: bool,
    pub(super) policies: Vec<u8>,
    pub(super) coverage: Vec<bool>,
    /// Each requester whose DMA arrives under another ID, with that ID.
    pub(super) aliases: Vec<(u16, u16)>,
}

pub(super) fn admit(
    inspection: &FunctionInspection,
    ivrs: &Ivrs<'_>,
    actual_bits: u8,
) -> Result<Admission, Error> {
    if inspection.native_firmware() != ivrs.raw() {
        return Err(Error::Firmware);
    }
    if inspection.profiles().len() != 1 {
        return Err(Error::Firmware);
    }
    let profile = inspection.profiles()[0];
    let address = inspection.address();
    let rid =
        u16::from(address.bus) << 8 | u16::from(address.device) << 3 | u16::from(address.function);
    // One IVHD per unit; a system with several units has one per function.
    let unit = ivrs
        .units()
        .find(|unit| {
            unit.id().segment == address.segment
                && unit.id().device_id == rid
                && unit.capability_offset() == profile.configuration.capability_offset
        })
        .ok_or(Error::Firmware)?;
    if unit.id().segment != address.segment
        || unit.id().device_id != rid
        || unit.capability_offset() != profile.configuration.capability_offset
        || unit.mmio_address() != profile.configuration.base()
        || unit.offset() != profile.firmware.offset
        || unit.version() != profile.firmware.version
        || unit.flags() != profile.firmware.flags
        || unit.info() != profile.firmware.info
        || unit.feature_or_attributes() != profile.firmware.feature_or_attributes
        || unit.extended_features() != profile.firmware.extended_features
        || ivrs.info() != profile.firmware.ivrs_info
    {
        return Err(Error::Firmware);
    }
    let info = ivrs.info();
    let pa = ((info >> 8) & 127) as u8;
    let va = (info >> 15) & 127;
    let miscellaneous = profile.configuration.miscellaneous;
    let hardware_pa = ((miscellaneous >> 8) & 127) as u8;
    let hardware_va = (miscellaneous >> 15) & 127;
    if info & 1 == 0
        || info & !(3 | (7 << 5) | (127 << 8) | (127 << 15) | (1 << 22)) != 0
        || !(32..=52).contains(&actual_bits)
        || !matches!(pa, 40 | 48 | 52)
        || !matches!(va, 0 | 32 | 40 | 48 | 64)
        || !matches!(hardware_pa, 40 | 48 | 52)
        || !matches!(hardware_va, 32 | 40 | 48 | 64)
        || miscellaneous & 0xff80_0000 != 0
    {
        return Err(Error::Profile);
    }
    let (features, _) = profile.hardware_extended_features.ok_or(Error::Profile)?;
    let (firmware_features, _) = unit.extended_features().ok_or(Error::Profile)?;
    // IA is needed for initial/final complete cache invalidation. HATS3
    // is reserved. SNP changes completion/exclusion ownership and is refused.
    if features & firmware_features & (1 << 6) == 0
        || (features >> 10) & 3 == 3
        || (firmware_features >> 10) & 3 == 3
        || features & (1 << 63) != 0
        || firmware_features & (1 << 63) != 0
    {
        return Err(Error::Profile);
    }
    let mut policies = Vec::new();
    policies
        .try_reserve_exact(REQUESTERS)
        .map_err(|_| Error::Memory(MemoryError::OutOfMemory))?;
    policies.resize(REQUESTERS, 0);
    let mut coverage = Vec::new();
    coverage
        .try_reserve_exact(REQUESTERS)
        .map_err(|_| Error::Memory(MemoryError::OutOfMemory))?;
    coverage.resize(REQUESTERS, false);
    let mut aliases = Vec::new();
    let mut start = None;
    // The device-setting flags (INITPass, EIntPass, NMIPass, SysMgt,
    // Lint0Pass, Lint1Pass) go into each DTE (`entry::Policy`); ATCPermit
    // stays metadata. A later entry overrides an earlier one, as Linux's
    // init_iommu_from_acpi applies them.
    for entry in unit.entries() {
        let (range, alias) = match entry.kind {
            DeviceKind::Padding if entry.raw()[1..].iter().all(|byte| *byte == 0) => continue,
            DeviceKind::NotUsed => continue,
            DeviceKind::Select(id) | DeviceKind::Extended { requester: id, .. } => {
                ((id.device_id, id.device_id, entry.flags()), None)
            }
            DeviceKind::Hid { requester, .. } => (
                (requester.device_id, requester.device_id, entry.flags()),
                None,
            ),
            DeviceKind::Alias { requester, target } => (
                (requester.device_id, requester.device_id, entry.flags()),
                Some(target.device_id),
            ),
            DeviceKind::All if entry.raw()[1..3] == [0, 0] => ((0, u16::MAX, entry.flags()), None),
            DeviceKind::RangeStart { first, policy } => {
                let alias = match policy {
                    RangePolicy::Alias(target) => Some(target.device_id),
                    RangePolicy::Plain | RangePolicy::Extended(_) => None,
                };
                start = Some((first.device_id, entry.flags(), alias));
                continue;
            }
            DeviceKind::RangeEnd(last) => {
                let (first, flags, alias) = start.take().ok_or(Error::Firmware)?;
                if entry.flags() != 0 {
                    return Err(Error::Firmware);
                }
                ((first, last.device_id, flags), alias)
            }
            // IOAPIC and HPET entries name interrupt sources, which matter
            // only to interrupt remapping.
            DeviceKind::Special { .. } => continue,
            _ => return Err(Error::Firmware),
        };
        let (first, last, flags) = range;
        for requester in first..=last {
            coverage[usize::from(requester)] = true;
            policies[usize::from(requester)] = flags;
            aliases.retain(|&(source, _)| source != requester);
            if let Some(target) = alias.filter(|target| *target != requester) {
                // The alias carries the source's settings, as Linux's
                // set_dev_entry_from_acpi gives both.
                coverage[usize::from(target)] = true;
                policies[usize::from(target)] = flags;
                aliases
                    .try_reserve(1)
                    .map_err(|_| Error::Memory(MemoryError::OutOfMemory))?;
                aliases.push((requester, target));
            }
        }
    }
    if start.is_some() || !coverage.iter().any(|value| *value) {
        return Err(Error::Firmware);
    }
    let flags = unit.flags();
    let control = IOMMU_ENABLE
        | EVENT_ENABLE
        | COMMAND_ENABLE
        | COHERENT
        | if flags & 1 != 0 { 1 << 1 } else { 0 }
        | if flags & 2 != 0 { 1 << 8 } else { 0 }
        | if flags & 4 != 0 { 1 << 9 } else { 0 }
        | if flags & 8 != 0 { 1 << 11 } else { 0 };
    Ok(Admission {
        bits: actual_bits.min(pa).min(hardware_pa),
        segment: address.segment,
        control,
        hardware_errors: features & (1 << 8) != 0,
        policies,
        coverage,
        aliases,
    })
}
