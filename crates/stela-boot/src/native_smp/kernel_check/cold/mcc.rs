//! Authored controller fixture over the actual registered native RAM owner.
//! Geometry follows the model's direct resource contract; these configuration
//! words are explicit fixture policy, never Apple boot-state measurements.
use alloc::{sync::Arc, vec};
use stela_runtime::{
    machine::apple::memory_resources::{
        LifecycleState,
        amcc::{Layout, LockGroup, Register},
        mcc, ptd,
    },
    machine::{
        apple::{AppleDevices, memory_resources::Prepared},
        soc::{DirectMemoryCache, MemoryController, PtdBank},
    },
    memory::RegisteredSystemRam,
};

const APERTURE: u64 = 0x200000000;
const PUBLICATION: u64 = 0x300000000;
const ENTRIES: usize = 384;
pub(super) const DRAIN: u64 = APERTURE + mcc::DCS_BASE + mcc::DCS_DRAIN;

pub(super) fn devices(ram: Arc<RegisteredSystemRam>) -> Result<AppleDevices, &'static str> {
    let register = |offset, mask, value| Register {
        offset,
        mask,
        value,
    };
    let locks = MemoryController {
        apertures: vec![APERTURE],
        layout: Layout {
            aperture_bytes: 0x200000,
            planes: u32::from(mcc::PLANES),
            stride: mcc::PLANE_STRIDE,
            cache_status: Some(register(0x10000c, 1, 1)),
            dram_base: super::source::BASE,
            group: LockGroup {
                page_size_shift: 14,
                lower_limit: register(0x680, u32::MAX, 0),
                upper_limit: register(0x684, u32::MAX, 0),
                enable: Some(register(0x688, 1, 1)),
                write_disable: None,
                lock: Some(register(0x68c, 1, 1)),
            },
        },
    };
    let descriptor = DirectMemoryCache {
        apertures: locks.apertures.clone(),
        config_data: vec![1],
        alternate_dram_configuration: 0xffff0000,
        ptd: PtdBank {
            physical: PUBLICATION,
            ranges: vec![ptd::Range {
                id: 1,
                start: 0,
                count: 2,
                name: "FIXTURE".into(),
            }],
            interrupts: vec![14],
        },
        ptd_updates: (PUBLICATION + ptd::UPDATE_OFFSET, ENTRIES as u64 * 8),
        ptd_entries: ENTRIES,
    };
    let owner = Prepared::new_local(
        descriptor,
        &locks,
        None,
        mcc::Configuration {
            dram: vec![[0; mcc::CHANNELS as usize]],
            weights: [1; 32],
        },
        LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: true,
        },
    )?
    .0
    .with_registered_ram(ram)?;
    let mut devices = AppleDevices::new();
    devices
        .add_memory_resources(owner)
        .map_err(|_| "cold actual MCC placement refused")?;
    Ok(devices)
}
