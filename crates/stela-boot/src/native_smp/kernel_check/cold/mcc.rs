//! Authored controller fixture over the actual registered native RAM owner.
//! Geometry follows the model's direct resource contract; these configuration
//! words are explicit fixture policy, never Apple boot-state measurements.
use alloc::{sync::Arc, vec};
use stela_engine::memory::RegisteredSystemRam;
use stela_runtime::machine::apple::AppleDevices;
use stela_runtime::machine::apple::memory_resources::LifecycleState;
use stela_runtime::machine::apple::memory_resources::t8112::CHANNEL_STRIDE;
use stela_runtime::machine::apple::memory_resources::t8112::CHANNELS;
use stela_runtime::machine::apple::memory_resources::t8112::ChannelConfiguration;
use stela_runtime::machine::apple::memory_resources::t8112::Prepared;
use stela_runtime::machine::apple::memory_resources::t8112::cache::EmptyResource;
use stela_runtime::machine::apple::memory_resources::t8112::cache::SoftwareImage;
use stela_runtime::machine::apple::memory_resources::t8112::cache::ZeroWayConfiguration;
use stela_runtime::machine::soc::MemoryCache;
use stela_runtime::machine::soc::MemoryController;
use stela_runtime::machine::soc::PtdBank;
use stela_soc_data::amcc::Layout;
use stela_soc_data::amcc::LockGroup;
use stela_soc_data::amcc::Register;

const APERTURE: u64 = 0x200000000;
const PUBLICATION: u64 = 0x300000000;
const ENTRIES: usize = 2048;
const DCS: u64 = APERTURE + 0x1000000;
pub(super) const DRAIN: u64 = DCS + 0xa40;
pub(super) const FLUSH: u64 = APERTURE + 0xf01c2c;

pub(super) fn devices(ram: Arc<RegisteredSystemRam>) -> Result<AppleDevices, &'static str> {
    let register = |offset, mask, value| Register {
        offset,
        mask,
        value,
    };
    let locks = MemoryController {
        apertures: vec![APERTURE],
        layout: Layout {
            aperture_bytes: 0xf40000,
            planes: 4,
            stride: 0x40000,
            cache_status: Some(register(0x424, 1, 1)),
            dram_base: super::source::BASE,
            groups: [
                Some(LockGroup {
                    page_size_shift: 14,
                    lower_limit: register(0x680, u32::MAX, 0),
                    upper_limit: register(0x684, u32::MAX, 0),
                    enable: Some(register(0x688, 1, 1)),
                    write_disable: Some(register(0x7f0, 1, 1)),
                    lock: Some(register(0x68c, 1, 1)),
                }),
                None,
                None,
                None,
            ],
        },
    };
    let descriptor = MemoryCache {
        cache: stela_soc_data::amcc::Cache {
            shared: (0x100000, 0x80000),
            broadcast: 0xf00000,
            bytes: 0,
            ways: 0,
        },
        channels: (DCS, CHANNEL_STRIDE * CHANNELS as u64, CHANNELS),
        ptd: PtdBank {
            physical: PUBLICATION,
            ranges: vec![stela_soc_data::ptd::Range {
                id: 1,
                start: 0,
                count: 256,
                name: "FIXTURE".into(),
            }],
            interrupts: vec![14],
        },
        ptd_updates: (
            PUBLICATION + stela_soc_data::ptd::UPDATE_OFFSET,
            ENTRIES as u64 * 8,
        ),
        ptd_entries: ENTRIES,
    };
    let lifecycle = LifecycleState {
        powered: true,
        clocked: true,
        quiesced: false,
        reset: false,
        retention: true,
    };
    let owner = Prepared::initialized(
        descriptor,
        (0..CHANNELS)
            .map(|_| ChannelConfiguration {
                ec8: 0,
                ed0: 0,
                gating: 0,
                drain_high: 0,
            })
            .collect(),
        lifecycle,
        ram,
    )?;
    let lock_owner = owner.initialize_amcc_locks(locks, [None; 4], lifecycle)?;
    // Authored input deliberately has no outer-cache allocation path. No
    // original command line, capacity, reset image or PMP grant is supplied.
    let cache = EmptyResource::initialized(
        lock_owner,
        ZeroWayConfiguration::ClampZero,
        SoftwareImage::zeroed_control_image(),
    )?;
    let mut devices = AppleDevices::new();
    devices
        .add_t8112_empty_memory_resources(owner, cache)
        .map_err(|_| "cold actual MCC placement refused")?;
    Ok(devices)
}
