//! The stage-1 descriptor walk: reads table descriptors from physical memory
//! level by level, accumulates table permissions, and returns the physical
//! address, attributes and permissions, or the architectural fault or
//! `Unsupported` result.
use super::config::{ADDRESS_MASK, Granule, Mode, RegionConfig, VaRegion};
use super::{
    Access, AccessKind, AttributeOrigin, Attributes, Config, ExceptionLevel, Fault, FaultKind,
    MemoryType, Permissions, PhysicalMemory, PhysicalReadError, Shareability, Translation,
    TranslationError, Unsupported, WalkMetadata,
};

const DESCRIPTOR_BYTES: u64 = 8;
const FINAL_LEVEL: u8 = 3;
const VALID: u64 = 1;
const TABLE_OR_PAGE: u64 = 2;
const ATTRIBUTE_INDEX_SHIFT: u32 = 2;
const ATTRIBUTE_INDEX_MASK: u64 = 7;
const AP_USER: u64 = 1 << 6;
const AP_READ_ONLY: u64 = 1 << 7;
const SHAREABILITY_SHIFT: u32 = 8;
const ACCESS_FLAG: u64 = 1 << 10;
const NOT_GLOBAL: u64 = 1 << 11;
const GUARDED_PAGE: u64 = 1 << 50;
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;
const TABLE_PXN: u64 = 1 << 59;
const TABLE_UXN: u64 = 1 << 60;
const TABLE_NO_USER: u64 = 1 << 61;
const TABLE_READ_ONLY: u64 = 1 << 62;
const NORMAL_WB_RA_WA: u8 = 0xff;

#[derive(Default)]
struct TablePermissions {
    no_user: bool,
    read_only: bool,
    pxn: bool,
    uxn: bool,
}

fn fault(
    access: Access,
    kind: FaultKind,
    level: u8,
    descriptor_address: Option<u64>,
    during_walk: bool,
) -> TranslationError {
    TranslationError::Fault(Fault {
        kind,
        level,
        access,
        virtual_address_valid: true,
        during_walk,
        descriptor_address,
        external_abort_type: None,
    })
}

fn leaf_permissions(config: &Config, descriptor: u64, table: &TablePermissions) -> Permissions {
    let el0_read = descriptor & AP_USER != 0 && !table.no_user;
    let writable = descriptor & AP_READ_ONLY == 0 && !table.read_only;
    let el0_write = el0_read && writable;
    let el1_write = writable;
    Permissions {
        el0_read,
        el0_write,
        el0_execute: descriptor & UXN == 0 && !table.uxn && !(config.wxn && el0_write),
        el1_read: true,
        el1_write,
        // EL0-writable mappings are implicitly privileged execute-never.
        el1_execute: descriptor & PXN == 0
            && !table.pxn
            && !el0_write
            && !(config.wxn && el1_write),
    }
}

fn permitted(access: Access, permissions: Permissions, pan_denied: bool) -> bool {
    match (access.exception_level, access.kind) {
        (ExceptionLevel::El0, AccessKind::Fetch) => permissions.el0_execute,
        (ExceptionLevel::El0, AccessKind::Read) => permissions.el0_read,
        (ExceptionLevel::El0, AccessKind::Write) => permissions.el0_write,
        (ExceptionLevel::El1, AccessKind::Fetch) => permissions.el1_execute,
        (ExceptionLevel::El1, AccessKind::Read) => permissions.el1_read && !pan_denied,
        (ExceptionLevel::El1, AccessKind::Write) => permissions.el1_write && !pan_denied,
    }
}

fn attributes(config: &Config, descriptor: u64, level: u8) -> Result<Attributes, TranslationError> {
    let index = (descriptor >> ATTRIBUTE_INDEX_SHIFT) & ATTRIBUTE_INDEX_MASK;
    let mair = (config.mair >> (index * 8)) as u8;
    if mair != NORMAL_WB_RA_WA {
        return Err(TranslationError::Unsupported(Unsupported::Descriptor {
            level,
            feature: "memory other than Normal inner/outer WB RA WA (MAIR 0xff)",
        }));
    }
    let shareability = match (descriptor >> SHAREABILITY_SHIFT) & 3 {
        0 => Shareability::NonShareable,
        2 => Shareability::Outer,
        3 => Shareability::Inner,
        _ => {
            return Err(TranslationError::Unsupported(Unsupported::Descriptor {
                level,
                feature: "reserved leaf shareability",
            }));
        }
    };
    Ok(Attributes {
        memory_type: MemoryType::NormalWriteBackReadWriteAllocate,
        origin: AttributeOrigin::Walk,
        mair: Some(mair),
        tagged: false,
        xs: false,
        shareability,
        not_global: descriptor & NOT_GLOBAL != 0,
        guarded_page: descriptor & GUARDED_PAGE != 0,
    })
}

pub(super) fn translate(
    config: &Config,
    memory: &(impl PhysicalMemory + ?Sized),
    access: Access,
) -> Result<Translation, TranslationError> {
    if access.uao {
        return Err(TranslationError::Unsupported(Unsupported::Access(
            "UAO and unprivileged-instruction adapter",
        )));
    }
    if matches!(config.mode, Mode::Disabled) {
        return super::disabled::translate(config, access);
    }
    let raw = access.raw_virtual_address;
    let region = VaRegion::from_address(raw);
    let Some(RegionConfig::Tables(table)) = config.region(region) else {
        return Err(fault(access, FaultKind::Translation, 0, None, false));
    };
    if !table.contains(raw, config.address_top(region, access.kind), region) {
        return Err(fault(access, FaultKind::Translation, 0, None, false));
    }
    // Strip only the extension and tag bits; initial tables can have fewer
    // index bits than a full table, including the upper-range 4K/47-bit and
    // 16K/48-bit roots.
    let va = raw & ((1_u64 << table.va_bits) - 1);
    let mut table_base = table.table_base;
    if table_base & !config.pa_mask != 0 {
        return Err(fault(access, FaultKind::AddressSize, 0, None, true));
    }
    let mut table_permissions = TablePermissions::default();
    for level in table.start_level..=FINAL_LEVEL {
        let offset_bits = table.offset_bits(level);
        let index = (va >> offset_bits) & ((1_u64 << table.index_bits()) - 1);
        let descriptor_address = table_base + index * DESCRIPTOR_BYTES;
        let descriptor =
            memory
                .read_descriptor(descriptor_address)
                .map_err(|error| match error {
                    PhysicalReadError::ExternalAbort {
                        external_abort_type,
                    } => {
                        let TranslationError::Fault(mut fault) = fault(
                            access,
                            FaultKind::ExternalAbort,
                            level,
                            Some(descriptor_address),
                            true,
                        ) else {
                            unreachable!("fault constructor returns a fault")
                        };
                        fault.external_abort_type = Some(external_abort_type);
                        TranslationError::Fault(fault)
                    }
                    PhysicalReadError::Platform(reason) => {
                        TranslationError::Unsupported(Unsupported::PhysicalPlatform(reason))
                    }
                })?;
        let is_table_or_page = descriptor & TABLE_OR_PAGE != 0;
        if descriptor & VALID == 0
            || (!is_table_or_page && (level == 0 || table.granule == Granule::KiB16 && level == 1))
            || (level == FINAL_LEVEL && !is_table_or_page)
        {
            return Err(fault(
                access,
                FaultKind::Translation,
                level,
                Some(descriptor_address),
                true,
            ));
        }
        if level < FINAL_LEVEL && is_table_or_page {
            table_base = descriptor & ADDRESS_MASK & !((1 << table.granule.bits()) - 1);
            if table_base & !config.pa_mask != 0 {
                // The fault belongs to the descriptor just read, not the next level.
                return Err(fault(
                    access,
                    FaultKind::AddressSize,
                    level,
                    Some(descriptor_address),
                    true,
                ));
            }
            table_permissions.no_user |= descriptor & TABLE_NO_USER != 0;
            table_permissions.read_only |= descriptor & TABLE_READ_ONLY != 0;
            table_permissions.pxn |= descriptor & TABLE_PXN != 0;
            table_permissions.uxn |= descriptor & TABLE_UXN != 0;
            continue;
        }
        let offset_mask = (1 << offset_bits) - 1;
        // LeafBase aligns the descriptor OA; ignored low and [49:48] bits
        // must not be invented into alignment or address-size faults.
        let physical_address = (descriptor & ADDRESS_MASK & !offset_mask) | (va & offset_mask);
        if physical_address & !config.pa_mask != 0 {
            return Err(fault(
                access,
                FaultKind::AddressSize,
                level,
                Some(descriptor_address),
                false,
            ));
        }
        if descriptor & ACCESS_FLAG == 0 {
            return Err(fault(
                access,
                FaultKind::AccessFlag,
                level,
                Some(descriptor_address),
                false,
            ));
        }
        let attributes = attributes(config, descriptor, level)?;
        let permissions = leaf_permissions(config, descriptor, &table_permissions);
        // EPAN tests unprivileged X before WXN suppression, as the source
        // computes PAN inside direct base permissions before final WXN removal.
        let user_execute_before_wxn = descriptor & UXN == 0 && !table_permissions.uxn;
        let pan_denied = config.pan
            && access.pan
            && (permissions.el0_read || config.epan && user_execute_before_wxn);
        if !permitted(access, permissions, pan_denied) {
            return Err(fault(
                access,
                FaultKind::Permission,
                level,
                Some(descriptor_address),
                false,
            ));
        }
        return Ok(Translation {
            access,
            physical_address,
            contiguous_bytes: (1 << offset_bits) - (va & offset_mask),
            attributes,
            permissions: Some(permissions),
            walk: Some(WalkMetadata {
                region,
                level,
                descriptor_address,
                descriptor,
                asid: config.asid,
            }),
        });
    }
    unreachable!("final descriptor is a leaf or faults")
}
