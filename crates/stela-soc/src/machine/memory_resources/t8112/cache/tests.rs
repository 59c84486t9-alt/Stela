use super::super::amcc::tests::{frontend, ram, source};
use super::*;
use alloc::boxed::Box;
use {stela_contracts::bus::Bus, stela_contracts::interrupt::InterruptLatch};

const LIVE: LifecycleState = LifecycleState {
    powered: true,
    clocked: true,
    quiesced: false,
    reset: false,
    retention: true,
};
fn resource(image: SoftwareImage) -> EmptyResource {
    let owner = frontend(ram());
    let locks = owner
        .initialize_amcc_locks(source(), [None; 4], LIVE)
        .unwrap();
    EmptyResource::initialized(locks, ZeroWayConfiguration::ClampZero, image).unwrap()
}
fn access(latch: &mut InterruptLatch) -> Access<'_> {
    Access::new(0, 21, latch)
}
fn read(resource: &mut EmptyResource, offset: u64) -> u64 {
    let mut latch = InterruptLatch::new();
    resource
        .read(offset, Width::Word, &mut access(&mut latch))
        .unwrap()
}
fn write(resource: &mut EmptyResource, offset: u64, value: u64) {
    let mut latch = InterruptLatch::new();
    resource
        .write(offset, Width::Word, value, &mut access(&mut latch))
        .unwrap();
}
#[test]
fn perf_counters_hold_their_writes_and_report_counting_nothing_once() {
    let mut cache = resource(SoftwareImage::zeroed_control_image());
    let mut latch = InterruptLatch::new();
    let mut a = access(&mut latch);
    let word = 5 * STRIDE + 0x18288;
    assert!(cache.read(word, Width::Double, &mut a).is_err());
    assert_eq!(cache.read(word, Width::Double, &mut a), Ok(0));
    cache
        .write(word, Width::Double, 0x1100_0000_0000_0021, &mut a)
        .unwrap();
    assert_eq!(
        cache.read(word, Width::Double, &mut a),
        Ok(0x1100_0000_0000_0021)
    );
    assert_eq!(cache.read(0x18288, Width::Double, &mut a), Ok(0));
    for (counter, width) in [(0x25000, Width::Double), (0x152004, Width::Word)] {
        assert_eq!(cache.read(counter, width, &mut a), Ok(0));
    }
    for (enable, width) in [(0x1f004, Width::Word), (BROADCAST + 0xa820, Width::Word)] {
        cache.write(enable, width, 0x21, &mut a).unwrap();
        assert_eq!(cache.read(enable, width, &mut a), Ok(0x21));
    }
    assert!(cache.read(0x18004, Width::Double, &mut a).is_err());
    assert!(cache.read(BROADCAST + 0x400, Width::Word, &mut a).is_err());
}
#[test]
fn empty_composite_consumes_reached_lock_state_and_installs_one_source_union() {
    let owner = frontend(ram());
    let registered = Arc::clone(owner.registered_ram());
    let programmed = [Some((0x800004000, 0x4000)), None, None, None];
    let mut locks = owner
        .initialize_amcc_locks(source(), programmed, LIVE)
        .unwrap();
    let mut latch = InterruptLatch::new();
    let mut a = access(&mut latch);
    for p in 0..4 {
        for word in [0x688, 0x7f0, 0x68c] {
            locks
                .write(p * STRIDE + word, Width::Word, 1, &mut a)
                .unwrap();
        }
    }
    let reached = locks.locked_regions();
    let cache = EmptyResource::initialized(
        locks,
        ZeroWayConfiguration::DisableArgument,
        SoftwareImage::zeroed_control_image(),
    )
    .unwrap();
    assert!(Arc::ptr_eq(cache.registered_ram(), &registered));
    assert_eq!(cache.locked_regions(), reached);
    assert_eq!(cache.locks().locked_regions(), reached);
    assert_eq!(cache.configuration(), ZeroWayConfiguration::DisableArgument);
    assert_eq!(cache.binding(), (0x200000000, 0x1000000, 0));
    assert_eq!(cache.source(), &source());
    let mut bus = Bus::new();
    let memory_bindings = owner.bindings();
    bus.install(Box::new(owner), &memory_bindings).unwrap();
    let binding = cache.binding();
    let id = bus.install(Box::new(cache), &[binding]).unwrap();
    assert_eq!(bus.route(binding.0 + 0x680, Width::Word).unwrap().0, id);
    assert_eq!(
        bus.route(binding.0 + BROADCAST + STATUS, Width::Word)
            .unwrap()
            .0,
        id
    );
    assert_ne!(bus.route(memory_bindings[1].0, Width::Word).unwrap().0, id);
    assert!(
        bus.install(
            Box::new(resource(SoftwareImage::zeroed_control_image())),
            &[binding]
        )
        .is_err()
    );
}
#[test]
fn zero_way_request_enable_and_declared_noncount_words_have_distinct_meaning() {
    let image = SoftwareImage {
        way_status: [0x80000001, 2, 4, 8],
        flush_status: [2, 4, 8, 16],
        ..SoftwareImage::zeroed_control_image()
    };
    let mut cache = resource(image);
    assert_eq!(cache.progress(), Progress::default());
    for p in 0..4 {
        assert_eq!(read(&mut cache, p * STRIDE + STATUS), 1);
    }
    write(&mut cache, BROADCAST + WAY_REQUEST, 0);
    for p in 0..4 {
        assert_eq!(
            read(&mut cache, p * STRIDE + WAY_STATUS),
            u64::from(image.way_status[p as usize])
        );
    }
    write(&mut cache, BROADCAST + STATUS, 0);
    for p in 0..4 {
        assert_eq!(read(&mut cache, p * STRIDE + STATUS), 0);
        assert_eq!(
            read(&mut cache, p * STRIDE + WAY_STATUS) & u64::from(WAY_COUNTS),
            0
        );
    }
    write(&mut cache, BROADCAST + STATUS, 1);
    assert_eq!(cache.progress().way_commands, 1);
    assert_eq!(cache.progress().control_writes, 2);
    assert_eq!(cache.progress().completed_flushes, 0);
    for p in 0..4 {
        assert_eq!(
            read(&mut cache, p * STRIDE + FLUSH),
            u64::from(image.flush_status[p as usize])
        );
    }
    let paused = LifecycleState {
        quiesced: true,
        ..LIVE
    };
    let mut latch = InterruptLatch::new();
    cache.set_lifecycle(paused, &mut access(&mut latch));
    assert!(
        cache
            .read(WAY_STATUS, Width::Word, &mut access(&mut latch))
            .is_err()
    );
    cache.set_lifecycle(LIVE, &mut access(&mut latch));
    assert_eq!(cache.image(), image);
    assert!(
        cache
            .check_lifecycle(LifecycleState {
                retention: false,
                ..LIVE
            })
            .is_err()
    );
    assert!(
        cache
            .check_lifecycle(LifecycleState {
                reset: true,
                ..LIVE
            })
            .is_err()
    );
}
#[test]
fn direct_limits_apply_without_resident_bytes_or_pmp_grants() {
    let mut cache = resource(SoftwareImage::zeroed_control_image());
    for group in 0..32 {
        write(&mut cache, BROADCAST + QUOTAS + 4 * group, group * 4 + 3);
        assert_eq!(read(&mut cache, QUOTAS + 4 * group), group * 4 + 3);
    }
    for dsid in 0..256 {
        assert_eq!(read(&mut cache, OCCUPANCY + 4 * dsid), 0);
    }
    assert_eq!(cache.progress().quota_writes, 32);
    assert_eq!(cache.image().quota_words[31], 127);
    let mut latch = InterruptLatch::new();
    let mut a = access(&mut latch);
    for offset in [
        QUOTAS + 128,
        OCCUPANCY + 1024,
        STRIDE + QUOTAS,
        STRIDE + OCCUPANCY,
        BROADCAST + QUOTAS + 128,
    ] {
        assert!(cache.read(offset, Width::Word, &mut a).is_err());
    }
    assert!(latch.take_aic_inputs().is_empty());
}
#[test]
fn native_and_ap_quota_views_share_full_words_without_truncating_or_shadowing() {
    let mut image = SoftwareImage::zeroed_control_image();
    image.quota_words[3] = 0x4012_0180;
    let mut cache = resource(image);
    let plane = QUOTAS + 3 * 4;
    let broadcast = BROADCAST + plane;
    assert_eq!(read(&mut cache, plane), 0x4012_0180);
    assert_eq!(read(&mut cache, broadcast), 0x4012_0180);
    assert_eq!(cache.progress().quota_writes, 0);
    // The original AP masks low7 in its caller, not in the MMIO read.
    assert_eq!(read(&mut cache, plane) & 0x7f, 0);
    assert_eq!(read(&mut cache, broadcast) & 0x1ff, 384);
    write(&mut cache, broadcast, 0x40fe_01ff);
    assert_eq!(read(&mut cache, plane), 0x40fe_01ff);
    assert_eq!(read(&mut cache, broadcast), 0x40fe_01ff);
    // An AP full32 low7 write replaces the word, including the attributes;
    // a native publisher must keep its own source attribute cache.
    write(&mut cache, broadcast, 17);
    assert_eq!(read(&mut cache, plane), 17);
    assert_eq!(read(&mut cache, broadcast), 17);
    assert_eq!(cache.progress().quota_writes, 2);
    assert_eq!(cache.progress().completed_flushes, 0);
    assert_eq!(read(&mut cache, OCCUPANCY + 3 * 4), 0);
    let before = (cache.image(), cache.progress());
    let mut latch = InterruptLatch::new();
    for value in [1 << 9, 1 << 24, 1 << 29, 1 << 31, 1 << 32] {
        assert!(
            cache
                .write(broadcast, Width::Word, value, &mut access(&mut latch))
                .is_err()
        );
        assert_eq!((cache.image(), cache.progress()), before);
    }
    cache.set_lifecycle(
        LifecycleState {
            quiesced: true,
            ..LIVE
        },
        &mut access(&mut latch),
    );
    assert!(
        cache
            .read(broadcast, Width::Word, &mut access(&mut latch))
            .is_err()
    );
    assert!(
        cache
            .write(broadcast, Width::Word, 31, &mut access(&mut latch))
            .is_err()
    );
    cache.set_lifecycle(LIVE, &mut access(&mut latch));
    assert_eq!(read(&mut cache, plane), 17);
    assert_eq!((cache.image(), cache.progress()), before);
}
#[test]
fn invalid_images_widths_unknown_effects_and_overflow_refuse_before_any_state() {
    for image in [
        SoftwareImage {
            way_status: [1 << 10, 0, 0, 0],
            ..SoftwareImage::zeroed_control_image()
        },
        SoftwareImage {
            way_status: [0, 1 << 5, 0, 0],
            ..SoftwareImage::zeroed_control_image()
        },
        SoftwareImage {
            flush_status: [0, 0, 1, 0],
            ..SoftwareImage::zeroed_control_image()
        },
        SoftwareImage {
            quota_words: [512; 32],
            ..SoftwareImage::zeroed_control_image()
        },
    ] {
        let owner = frontend(ram());
        let locks = owner
            .initialize_amcc_locks(source(), [None; 4], LIVE)
            .unwrap();
        assert!(
            EmptyResource::initialized(locks, ZeroWayConfiguration::ProviderDisabled, image)
                .is_err()
        );
    }
    let mut cache = resource(SoftwareImage::zeroed_control_image());
    let before = (cache.image(), cache.progress(), cache.locked_regions());
    let mut latch = InterruptLatch::new();
    let mut a = access(&mut latch);
    for (offset, value) in [
        (BROADCAST + WAY_REQUEST, 1),
        (BROADCAST + WAY_REQUEST, u64::MAX),
        (BROADCAST + STATUS, 2),
        (BROADCAST + QUOTAS, 512),
        (BROADCAST + FLUSH, 1),
        (WAY_REQUEST, 0),
        (STATUS, 0),
        (OCCUPANCY, 0),
        (QUOTAS, 0),
        (BROADCAST + 0x13ffc + 4, 1),
        (BROADCAST + 0x13ffc + 4, 2),
        (0x10001c, 0),
        (MMIO_BYTES, 0),
        (u64::MAX - 3, 0),
        (0x680, 1 << 32),
    ] {
        assert!(
            cache.write(offset, Width::Word, value, &mut a).is_err(),
            "{offset:x}/{value:x}"
        );
    }
    for width in [Width::Byte, Width::Half, Width::Double] {
        assert!(cache.write(BROADCAST + STATUS, width, 1, &mut a).is_err());
        assert!(cache.read(WAY_STATUS, width, &mut a).is_err());
    }
    assert!(cache.read(WAY_STATUS + 1, Width::Word, &mut a).is_err());
    assert!(cache.read(0x10001c, Width::Word, &mut a).is_err());
    assert_eq!(
        (cache.image(), cache.progress(), cache.locked_regions()),
        before
    );
    cache.progress.control_writes = u64::MAX;
    assert!(
        cache
            .write(BROADCAST + STATUS, Width::Word, 0, &mut a)
            .is_err()
    );
    assert_eq!(cache.image(), before.0);
    cache.progress.quota_writes = u64::MAX;
    assert!(
        cache
            .write(BROADCAST + QUOTAS, Width::Word, 1, &mut a)
            .is_err()
    );
    assert_eq!(cache.image(), before.0);
    assert!(latch.take_aic_inputs().is_empty());
}
#[test]
fn raw_flush_requires_same_live_ram_disabled_controls_and_bounded_empty_effect() {
    let mut cache = resource(SoftwareImage::zeroed_control_image());
    let actual = Arc::clone(cache.registered_ram());
    let foreign = ram();
    let service = actual.try_service().unwrap().unwrap();
    let other = foreign.try_service().unwrap().unwrap();
    assert!(cache.requires_ram_flush(BROADCAST + FLUSH, Width::Word));
    assert!(!cache.requires_ram_flush(FLUSH, Width::Word));
    assert!(!cache.requires_ram_flush(BROADCAST + FLUSH, Width::Double));
    let before = (cache.image(), cache.progress());
    assert!(
        cache
            .prepare_flush(BROADCAST + FLUSH, Width::Word, 1, 1, &other)
            .is_err()
    );
    for (offset, width, value) in [
        (FLUSH, Width::Word, 1),
        (BROADCAST + FLUSH, Width::Half, 1),
        (BROADCAST + FLUSH, Width::Word, 0),
        (BROADCAST + FLUSH, Width::Word, 2),
    ] {
        assert!(
            cache
                .prepare_flush(offset, width, value, 1, &service)
                .is_err()
        );
    }
    assert_eq!((cache.image(), cache.progress()), before);
    write(&mut cache, BROADCAST + STATUS, 0);
    assert!(
        cache
            .prepare_flush(BROADCAST + FLUSH, Width::Word, 1, 1, &service)
            .is_err()
    );
    write(&mut cache, BROADCAST + STATUS, 1);
    // The fixture has no native PE/DMA/client, so its permanent-empty
    // effect can exercise this private consumer under RAM exclusion.
    // Production enters only through the sealed adapter and fences.
    for at in 1..=3 {
        let prepared = cache
            .prepare_flush(BROADCAST + FLUSH, Width::Word, 1, at, &service)
            .unwrap();
        cache.complete_flush(prepared);
    }
    assert_eq!(cache.progress().completed_flushes, 3);
    assert_eq!(
        cache.progress().latest_flush,
        Some(FlushCompletion {
            serial: 3,
            at: 3,
            ram_generation: service.generation()
        })
    );
    for p in 0..4 {
        assert_eq!(read(&mut cache, p * STRIDE + FLUSH), 0);
    }
    cache.progress.completed_flushes = u64::MAX;
    let before = cache.progress();
    assert!(
        cache
            .prepare_flush(BROADCAST + FLUSH, Width::Word, 1, 4, &service)
            .is_err()
    );
    assert_eq!(cache.progress(), before);
    let mut latch = InterruptLatch::new();
    cache.set_lifecycle(
        LifecycleState {
            quiesced: true,
            ..LIVE
        },
        &mut access(&mut latch),
    );
    assert!(
        cache
            .prepare_flush(BROADCAST + FLUSH, Width::Word, 1, 4, &service)
            .is_err()
    );
}
#[test]
#[cfg(feature = "std")]
#[ignore = "oracle: STELA_TEST_PMP_T8112"]
fn original_native_quota_seed_and_publisher_share_the_broadcast_full_word() {
    let code = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
    assert_eq!(
        stela_formats::sha256(&code),
        "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
    );
    for (start, end, hash) in [
        (
            0x426c,
            0x472c,
            "e4971d2db1643fd5fa9412d278d2dbb1ea177f902bba9ec22d4dc41c0fd62a7b",
        ),
        (
            0x4cbc,
            0x4ee8,
            "9d7f54726ce6b42b4f802022a6f3fb0902a2a53cb1f57bdfb028513d67d99ad7",
        ),
        (
            0x33ea8,
            0x33fd0,
            "949295e2f93ed5c1f89e3e2712b07ba2a039d29dcb382a94ba003f35fb258601",
        ),
    ] {
        assert_eq!(stela_formats::sha256(&code[start..end]), hash);
    }
    assert_eq!(
        u64::from_le_bytes(code[0x46360..0x46368].try_into().unwrap()),
        0x200f04000
    );
    // Both the initial seed and later programming use AND W12,#0x1ff.
    for offset in [0x4654, 0x4e60] {
        assert_eq!(
            u32::from_le_bytes(code[offset..offset + 4].try_into().unwrap()),
            0x1200218c
        );
    }
    assert_eq!(0x200f04000 + 0x6000, 0x200000000 + BROADCAST + QUOTAS);
    assert_eq!(QUOTA_FIELDS, 0x40ff_01ff);
}
#[test]
#[cfg(feature = "std")]
#[ignore = "oracle: STELA_TEST_MCC_J473_KERNELCACHE"]
fn original_j473_zero_mode_way_flush_quota_and_occupancy_windows_match() {
    let code = std::fs::read(std::env::var("STELA_TEST_MCC_J473_KERNELCACHE").unwrap()).unwrap();
    assert_eq!(
        stela_formats::sha256(&code),
        "06846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d"
    );
    for (start, end, hash) in [
        (
            0x1c71874,
            0x1c719d8,
            "d9ec1c82e6e0625634c0eaaf040440f9b97f29d869ab71bba1eaef7d0149cd9a",
        ),
        (
            0x2efd354,
            0x2efd5b0,
            "762b24538ec890d4ecf738385a0a8a0ec10237a9be19149b1cb56488f3321da2",
        ),
        (
            0x2efdf14,
            0x2efdfec,
            "a74c2838255731a373c51d85471f79cc689c26013474e6485f9068abcc4d4ff2",
        ),
        (
            0x2efd010,
            0x2efd234,
            "12fb82ea20b708995577b41fa026705b3e3cd9a7bf4230129aa2f18c1a0a0bc8",
        ),
        (
            0x2efd234,
            0x2efd354,
            "cca95cd9acf337b877c05b5c706b00b731b97ec5b1e3439ed5f0ba4679f71233",
        ),
        (
            0x2eff664,
            0x2eff924,
            "1e9ee5dfb705e2f39efb276e714f60b828b25ad45ee6fb68cb7726bc4a1128d8",
        ),
        (
            0x2effa54,
            0x2effb34,
            "e6aa987254d58eda768ef148602596c4e4583aa7cb77c2b9f2aacc679c7529cd",
        ),
    ] {
        assert_eq!(
            stela_formats::sha256(&code[start..end]),
            hash,
            "{start:x}..{end:x}"
        );
    }
    assert_eq!(&code[0x17dba3..0x17dbaf], b"disable-mcc\0");
    assert_eq!(&code[0x17dbaf..0x17dbbc], b"-disable_mcc\0");
    assert_eq!(&code[0x17dc0f..0x17dc21], b"mcc_clampwaycount\0");
    assert_eq!(WAY_COUNTS, (0x1f << 10) | (0x1f << 5));
    assert_eq!(SoftwareImage::zeroed_control_image().way_status, [0; 4]);
}
