use super::*;
use crate::Result;
use stela_contracts::refuse;
const PRIMARY: u64 = 0x2_8800_0000;
const WRAPPER: u64 = 0x2_89c0_0000;
const TRAD: u64 = 0x2_8930_4000;
const UMMS: u64 = 0x2_8930_0000;
const FIRMWARE: u64 = 0x2_8930_c000;
const SHARED: u64 = 0x2_8e3d_0000;

struct Screen;
impl Scanout for Screen {
    fn mode(&self) -> ScanoutMode {
        ScanoutMode {
            width: 1,
            height: 1,
            format: ScanoutFormat::Bgra8888,
        }
    }
    fn present(&mut self, _: &[u8]) -> Result<()> {
        panic!("aperture mounting must not present a frame")
    }
}

fn placement() -> (AppleDevices, Vec<DartId>, Vec<(&'static str, Range)>) {
    let mut devices = AppleDevices::new();
    let mut owners = Vec::new();
    for physical in [TRAD, FIRMWARE] {
        owners.push(
            devices
                .add_dart_group_for_profile(
                    stela_soc_data::dart::Profile::T6000,
                    &[Range {
                        physical,
                        bytes: 0x4000,
                    }],
                    16,
                    None,
                    None,
                )
                .unwrap()[0],
        );
    }
    devices
        .add_dart_smmu(
            owners[0],
            Range {
                physical: UMMS,
                bytes: 0x4000,
            },
        )
        .unwrap();
    devices
        .add_dcpext(
            DcpextNub {
                wrapper: Range {
                    physical: WRAPPER,
                    bytes: 0x6c000,
                },
                interrupts: [873; 4],
                quiesced: false,
                role: "DCPEXT0",
                identity: stela_soc_data::dcp::ExternalIdentity::Numbered(0),
            },
            Box::new(Screen),
            DcpextDma {
                link: (owners[1], 5),
                window: None,
                surface: Some((owners[0], 0)),
            },
            stela_formats::builds::DEFAULT,
        )
        .unwrap();
    let views = [
        (PRIMARY, 0x3000000),
        (0x2_8932_0000, 0x4000),
        (0x2_8934_4000, 0x4000),
        (0x2_8980_0000, 0x800000),
        (SHARED, 0x4000),
    ]
    .into_iter()
    .map(|(physical, bytes)| ("dispext0", Range { physical, bytes }))
    .collect();
    (devices, owners, views)
}

#[test]
fn complete_display_views_preserve_trad_umms_mailbox_and_shared_bank_ownership() {
    let (mut devices, owners, views) = placement();
    let addresses = [
        TRAD,
        TRAD + 0x100,
        UMMS,
        UMMS + 0x100,
        FIRMWARE,
        WRAPPER + 0x8114,
    ];
    let before = addresses.map(|pa| devices.bus.route(pa, Width::Word).unwrap());
    devices
        .add_display_with_darts(&views, "DCPEXT0", &owners)
        .unwrap();
    assert_eq!(
        addresses.map(|pa| devices.bus.route(pa, Width::Word).unwrap()),
        before
    );
    for pa in [
        PRIMARY,
        PRIMARY + 0x2ff_fffc,
        0x2_8932_0000,
        0x2_8934_4000,
        0x2_8980_0000,
        SHARED + 0x3ffc,
    ] {
        let error = devices.read(0, pa, 4, 0).unwrap_err();
        assert!(format!("{error:?}").contains("dispext0"));
    }
    assert!(devices.bus.route(SHARED + 0x4000, Width::Word).is_err());
    assert!(devices.bus.route(PRIMARY + 0x3000000, Width::Word).is_err());
}

#[test]
fn invalid_or_unrelated_owners_refuse_before_any_display_route_is_published() {
    let (mut devices, owners, views) = placement();
    assert!(
        devices
            .add_display_with_darts(&views, "DCPEXT0", &owners[..1])
            .is_err()
    );
    assert!(
        devices
            .add_display_with_darts(&views, "SMC", &owners)
            .is_err()
    );
    let mut invalid = views.clone();
    invalid.push((
        "dispext0",
        Range {
            physical: u64::MAX,
            bytes: 4,
        },
    ));
    assert!(
        devices
            .add_display_with_darts(&invalid, "DCPEXT0", &owners)
            .is_err()
    );
    assert!(devices.bus.route(PRIMARY, Width::Word).is_err());
    devices
        .add_watchdog(
            &[Range {
                physical: PRIMARY + 0x100000,
                bytes: 0x4000,
            }],
            None,
            0,
        )
        .unwrap();
    let old = devices.bus.route(PRIMARY + 0x100000, Width::Word).unwrap();
    let owner_name = devices.bus.device_name(old.0).unwrap();
    let error = devices
        .add_display_with_darts(&views, "DCPEXT0", &owners)
        .unwrap_err();
    assert!(error.to_string().contains(owner_name));
    assert_eq!(devices.bus.route(PRIMARY + 0x100000, Width::Word), Ok(old));
    assert!(devices.bus.route(PRIMARY, Width::Word).is_err());
    assert!(devices.bus.route(SHARED, Width::Word).is_err());
}
use {
    crate::platform::apple::mcc, crate::platform::apple::mcc::Configuration,
    crate::platform::apple::ptd, stela_contracts::bus::Lifecycle,
    stela_contracts::bus::LifecycleState, stela_contracts::bus::MmioError,
    stela_contracts::interrupt::InterruptLatch, stela_soc_data::amcc::Layout,
    stela_soc_data::amcc::LockGroup, stela_soc_data::amcc::Register,
    stela_soc_data::board::DirectMemoryCache, stela_soc_data::board::MemoryController,
    stela_soc_data::board::PtdBank,
};
fn prepared() -> memory_resources::Prepared {
    let reg = |offset, mask, value| Register {
        offset,
        mask,
        value,
    };
    let locks = MemoryController {
        apertures: vec![0x200000000, 0x201000000],
        layout: Layout {
            aperture_bytes: 0x200000,
            planes: 4,
            stride: mcc::PLANE_STRIDE,
            cache_status: Some(reg(0x1c00, 0x1f, 0)),
            dram_base: 0x800000000,
            groups: [
                Some(LockGroup {
                    page_size_shift: 14,
                    lower_limit: reg(0x680, u32::MAX, 0),
                    upper_limit: reg(0x684, u32::MAX, 0),
                    enable: Some(reg(0x688, 1, 1)),
                    write_disable: None,
                    lock: Some(reg(0x68c, 1, 1)),
                }),
                None,
                None,
                None,
            ],
        },
    };
    let descriptor = DirectMemoryCache {
        apertures: locks.apertures.clone(),
        config_data: vec![1],
        alternate_dram_configuration: 0xffff0000,
        ptd: PtdBank {
            physical: 0x28e3c0000,
            ranges: vec![stela_soc_data::ptd::Range {
                id: 1,
                start: 0,
                count: 2,
                name: "DECLARED".into(),
            }],
            interrupts: vec![14],
        },
        ptd_updates: (0x28e3d0000, 0xc00),
        ptd_entries: 384,
    };
    memory_resources::Prepared::new(
        descriptor,
        &locks,
        stela_soc_data::amcc::ctrr_a(Some((0x800004000, 0x4000))),
        Configuration {
            dram: vec![[7; 4]; 2],
            weights: [1; 32],
        },
        LifecycleState {
            powered: true,
            clocked: true,
            reset: false,
            quiesced: false,
            retention: true,
        },
        [None; 16],
    )
    .unwrap()
}

fn mount_prepared(
    devices: &mut AppleDevices,
    owner: memory_resources::Prepared,
) -> (DeviceId, ptd::Ptd) {
    let publication = owner.publication_bank().clone();
    let bindings = owner.bindings();
    let id = devices.bus.install(Box::new(owner), &bindings).unwrap();
    devices.memory_controller = Some(id);
    (id, publication)
}

#[test]
fn display_update_view_uses_prepared_storage_and_preserves_unknown_tail() {
    let (mut devices, owners, views) = placement();
    let (id, publication) = mount_prepared(&mut devices, prepared());
    let addresses = [
        TRAD,
        UMMS,
        FIRMWARE,
        WRAPPER + 0x8114,
        SHARED - 0x10000,
        SHARED,
        SHARED + 0x3ffc,
        SHARED + 0xfffc,
    ];
    let before = addresses.map(|pa| devices.bus.route(pa, Width::Word).unwrap());
    devices
        .add_display_with_darts(&views, "DCPEXT0", &owners)
        .unwrap();
    assert_eq!(
        addresses.map(|pa| devices.bus.route(pa, Width::Word).unwrap()),
        before
    );
    assert_eq!(
        devices.bus.route(SHARED, Width::Double),
        Ok((
            id,
            2 * mcc::APERTURE_BYTES + stela_soc_data::ptd::UPDATE_OFFSET
        ))
    );
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 17, &mut latch);
    for (entry, value) in [(0, 0x1234), (383, 0xdead_beef)] {
        devices
            .bus
            .write(SHARED + entry * 8, Width::Double, value, &mut access)
            .unwrap();
        let consumed = publication
            .consume_entry(entry as u32, &mut access)
            .unwrap();
        assert_eq!(consumed.value, value);
        assert_eq!(consumed.metadata, (17 << 10) | 2);
    }
    let history = publication.requests();
    assert_eq!(history.len(), 2);
    for (pa, width) in [
        (SHARED + 0xc00, Width::Double),
        (SHARED + 0x3ff8, Width::Double),
        (SHARED, Width::Word),
    ] {
        let error = devices.bus.write(pa, width, 7, &mut access).unwrap_err();
        assert!(matches!(
            error,
            MmioError::Unsupported { device: "ptd", .. }
        ));
    }
    assert!(
        devices
            .bus
            .read(SHARED, Width::Double, &mut access)
            .is_err()
    );
    assert_eq!(publication.requests(), history);
    let active = publication.lifecycle_state();
    devices
        .bus
        .device_mut::<memory_resources::Prepared>(id)
        .unwrap()
        .set_lifecycle(
            LifecycleState {
                clocked: false,
                ..active
            },
            &mut access,
        );
    assert!(!publication.lifecycle_state().clocked);
    assert!(
        devices
            .bus
            .write(SHARED, Width::Double, 0x99, &mut access)
            .is_err()
    );
    assert_eq!(publication.requests(), history);
    devices
        .bus
        .device_mut::<memory_resources::Prepared>(id)
        .unwrap()
        .set_lifecycle(active, &mut access);
    devices
        .bus
        .write(SHARED, Width::Double, 0x99, &mut access)
        .unwrap();
    assert_eq!(
        publication.consume_entry(0, &mut access).unwrap().value,
        0x99
    );
    assert_eq!(publication.requests().len(), 3);
}

#[test]
fn display_shared_view_refuses_wrong_offsets_holes_and_unrelated_prepared_identity_atomically() {
    for invalid in 0..5 {
        let (mut devices, owners, views) = placement();
        let owner = prepared();
        let publication = owner.publication_bank().clone();
        let mut bindings = owner.bindings();
        let (pa, bytes, offset) = bindings.pop().unwrap();
        match invalid {
            0 => bindings.push((pa, bytes, offset + 8)),
            1 => {
                bindings.push((pa, 0x10400, offset));
                bindings.push((pa + 0x11000, bytes - 0x11000, offset + 0x11000));
            }
            2 => bindings.push((pa, bytes, offset)),
            3 => bindings.push((
                pa + stela_soc_data::ptd::UPDATE_OFFSET,
                bytes - stela_soc_data::ptd::UPDATE_OFFSET,
                offset + stela_soc_data::ptd::UPDATE_OFFSET,
            )),
            _ => {
                bindings.push((pa, stela_soc_data::ptd::UPDATE_OFFSET, offset + 8));
                bindings.push((
                    pa + stela_soc_data::ptd::UPDATE_OFFSET,
                    bytes - stela_soc_data::ptd::UPDATE_OFFSET,
                    offset + stela_soc_data::ptd::UPDATE_OFFSET,
                ));
            }
        }
        let id = devices.bus.install(Box::new(owner), &bindings).unwrap();
        if invalid != 2 {
            devices.memory_controller = Some(id);
        }
        let before = devices.bus.route(SHARED, Width::Double).unwrap();
        assert!(
            devices
                .add_display_with_darts(&views, "DCPEXT0", &owners)
                .is_err()
        );
        assert_eq!(devices.bus.route(SHARED, Width::Double), Ok(before));
        assert!(devices.bus.route(PRIMARY, Width::Word).is_err());
        assert!(devices.bus.route(0x2_8932_0000, Width::Word).is_err());
        assert!(publication.requests().is_empty());
    }
}

#[test]
fn display_subview_geometry_and_late_conflict_fail_without_partial_publication() {
    for (physical, bytes) in [(SHARED - 8, 0x4008), (SHARED, 0xbf8), (SHARED, 0x10008)] {
        let (mut devices, owners, mut views) = placement();
        mount_prepared(&mut devices, prepared());
        views[4].1 = Range { physical, bytes };
        assert!(
            devices
                .add_display_with_darts(&views, "DCPEXT0", &owners)
                .is_err()
        );
        assert!(devices.bus.route(PRIMARY, Width::Word).is_err());
    }
    let (mut devices, owners, views) = placement();
    let (id, publication) = mount_prepared(&mut devices, prepared());
    devices
        .add_watchdog(
            &[Range {
                physical: 0x2_8932_0000,
                bytes: 0x4000,
            }],
            None,
            0,
        )
        .unwrap();
    let before = devices.bus.route(SHARED, Width::Double).unwrap();
    assert!(
        devices
            .add_display_with_darts(&views, "DCPEXT0", &owners)
            .is_err()
    );
    assert_eq!(before.0, id);
    assert_eq!(devices.bus.route(SHARED, Width::Double), Ok(before));
    assert!(devices.bus.route(PRIMARY, Width::Word).is_err());
    assert!(publication.requests().is_empty());
}
#[test]
fn display_views_strictly_inside_a_larger_window_stay_with_its_owner() {
    let (mut devices, owners, mut views) = placement();
    mount_prepared(&mut devices, prepared());
    const INSIDE: u64 = 0x2_9000_4000;
    views.push((
        "dispext0",
        Range {
            physical: INSIDE,
            bytes: 0x1000,
        },
    ));
    struct Block;
    impl MmioDevice for Block {
        fn name(&self) -> &'static str {
            "block"
        }
        fn read(&mut self, _: u64, _: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
            Ok(0)
        }
        fn write(&mut self, _: u64, _: Width, _: u64, _: &mut Access<'_>) -> Result<(), MmioError> {
            Ok(())
        }
    }
    // A larger block owns the window around one display view.
    devices
        .bus
        .install(Box::new(Block), &[(0x2_9000_0000, 0x10000, 0)])
        .unwrap();
    let before = devices.bus.route(INSIDE, Width::Word).unwrap();
    devices
        .add_display_with_darts(&views, "DCPEXT0", &owners)
        .unwrap();
    assert_eq!(devices.bus.route(INSIDE, Width::Word), Ok(before));
    assert!(devices.bus.route(PRIMARY, Width::Word).is_ok());
}

#[test]
fn refused_ptd_owner_blocks_overlapping_display_publication_before_any_alias() {
    let (mut devices, owners, views) = placement();
    devices
        .add_t6020_memory_resources(memory_resources::t6020::tests::fixture_owner(4))
        .unwrap();
    let before = devices.bus.route(SHARED, Width::Double).unwrap();
    let error = devices
        .add_display_with_darts(&views, "DCPEXT0", &owners)
        .unwrap_err();
    assert_eq!(
        error,
        refuse!("T602x PTD publication has no qualified source owner")
    );
    assert_eq!(devices.bus.route(SHARED, Width::Double), Ok(before));
    assert!(devices.bus.route(PRIMARY, Width::Word).is_err());
    assert!(devices.bus.route(0x2_8932_0000, Width::Word).is_err());
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    assert!(
        devices
            .bus
            .write(SHARED, Width::Double, 1, &mut access)
            .is_err()
    );
}

#[test]
fn unrelated_display_windows_preserve_a_refused_ptd_owners_full_extent() {
    let (mut devices, owners, mut views) = placement();
    views.retain(|(_, range)| range.physical != SHARED);
    devices
        .add_t6020_memory_resources(memory_resources::t6020::tests::fixture_owner(4))
        .unwrap();
    let before = devices.bus.route(SHARED, Width::Double).unwrap();
    devices
        .add_display_with_darts(&views, "DCPEXT0", &owners)
        .unwrap();
    assert_eq!(devices.bus.route(SHARED, Width::Double), Ok(before));
    assert!(devices.bus.route(PRIMARY, Width::Word).is_ok());
}

#[test]
#[ignore = "oracle: STELA_T6000_MCC_DEVICE_TREE"]
fn original_j314s_display_ptd_view_is_the_pmgr_pmp_update_bank() {
    use stela_contracts::adt::Node;
    let input = std::env::var("STELA_T6000_MCC_DEVICE_TREE").expect("explicit original ADT input");
    let bytes = std::fs::read(&input).unwrap();
    assert_eq!(
        stela_formats::sha256(&bytes),
        "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
    );
    let io = Node::root(&bytes).unwrap().child("arm-io").unwrap();
    let display = io.child("dispext0").unwrap().pairs("reg").unwrap();
    assert_eq!(display.len(), 5);
    let (base, bytes) = display[4];
    let physical = io.translate_range(base, bytes).unwrap();
    assert_eq!((physical, bytes), (SHARED, 0x4000));
    let (bank, bank_bytes) = io.child("pmgr").unwrap().pairs("reg").unwrap()[41];
    let bank = io.translate_range(bank, bank_bytes).unwrap();
    assert_eq!(
        (bank, bank_bytes),
        (
            SHARED - stela_soc_data::ptd::UPDATE_OFFSET,
            stela_soc_data::ptd::PTD_BYTES
        )
    );
    let pmp = io.child("pmp").unwrap();
    let index = u32::from_le_bytes(
        pmp.property("ptd-update-reg-index")
            .unwrap()
            .try_into()
            .unwrap(),
    ) as usize;
    let (updates, update_bytes) = pmp.pairs("reg").unwrap()[index];
    let updates = io.translate_range(updates, update_bytes).unwrap();
    assert_eq!(index, 3);
    assert_eq!((updates, update_bytes), (physical, 0xc00));
    let owner = prepared();
    assert_eq!(owner.descriptor().ptd.physical, bank);
    assert_eq!(owner.descriptor().ptd_updates, (updates, update_bytes));
    assert_eq!(
        owner.display_publication_view(physical, bytes),
        Ok((
            physical,
            bytes,
            2 * mcc::APERTURE_BYTES + stela_soc_data::ptd::UPDATE_OFFSET
        ))
    );
}
