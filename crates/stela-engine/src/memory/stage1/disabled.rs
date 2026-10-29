//! Translation results with stage 1 disabled.
use super::config::VaRegion;
use super::{
    Access, AccessKind, AttributeOrigin, Attributes, Config, Fault, FaultKind, MemoryType,
    Shareability, Translation, TranslationError, Unsupported,
};

pub(super) fn translate(config: &Config, access: Access) -> Result<Translation, TranslationError> {
    let raw = access.raw_virtual_address;
    let region = VaRegion::from_address(raw);
    let top = config.address_top(region, access.kind);
    let checked = raw & (u64::MAX >> (u64::BITS - 1 - top));
    if checked & !config.pa_max_mask != 0 {
        return Err(TranslationError::Fault(Fault {
            kind: FaultKind::AddressSize,
            level: 0,
            access,
            virtual_address_valid: true,
            during_walk: false,
            descriptor_address: None,
            external_abort_type: None,
        }));
    }
    if access.kind != AccessKind::Fetch && !access.aligned {
        // Source support is location-specific. CPU-global flags cannot certify
        // unaligned Device access or manufacture a guest Alignment fault.
        return Err(TranslationError::Unsupported(Unsupported::Access(
            "unaligned MMU-off Device location witness",
        )));
    }
    let memory_type = if access.kind == AccessKind::Fetch {
        if config.instruction_cache {
            MemoryType::NormalWriteThroughReadAllocate
        } else {
            MemoryType::NormalNonCacheable
        }
    } else {
        MemoryType::DeviceNgnrne
    };
    let physical_address = raw & config.pa_max_mask;
    Ok(Translation {
        access,
        physical_address,
        contiguous_bytes: (config.pa_max_mask - physical_address + 1)
            .min(VaRegion::remaining_bytes(raw)),
        attributes: Attributes {
            memory_type,
            origin: AttributeOrigin::MmuDisabled,
            mair: None,
            tagged: false,
            xs: true,
            shareability: Shareability::Outer,
            not_global: false,
            guarded_page: false,
        },
        permissions: None,
        walk: None,
    })
}
