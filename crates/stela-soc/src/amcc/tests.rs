use super::*;
use stela_contracts::interrupt::InterruptLatch;

const fn bit_register(offset: u64) -> Register {
    Register {
        offset,
        mask: 1,
        value: 1,
    }
}

fn layout() -> Layout {
    let limit = |offset| Register {
        offset,
        mask: u32::MAX,
        value: 0,
    };
    Layout {
        aperture_bytes: 0xf4_0000,
        planes: 4,
        stride: 0x4_0000,
        cache_status: Some(bit_register(0x424)),
        groups: [
            Some(LockGroup {
                page_size_shift: 14,
                lower_limit: limit(0x680),
                upper_limit: limit(0x684),
                enable: Some(bit_register(0x688)),
                write_disable: Some(bit_register(0x7f0)),
                lock: Some(bit_register(0x68c)),
            }),
            None,
            None,
            None,
        ],
        dram_base: 0x8_0000_0000,
    }
}

const NONE: Programmed = [None; GROUPS];

/// CTRR-A's registers.
fn a(layout: &mut Layout) -> &mut LockGroup {
    layout.groups[0].as_mut().unwrap()
}

/// The M4 Pro and later's map: four groups, each register a word apart
/// from the same register of the next group.
fn interleaved() -> Layout {
    let limit = |offset| Register {
        offset,
        mask: u32::MAX,
        value: 0,
    };
    let group = |index: u64| {
        Some(LockGroup {
            page_size_shift: 14,
            lower_limit: limit(0xaa0 + 4 * index),
            upper_limit: limit(0xab0 + 4 * index),
            enable: Some(bit_register(0xac0 + 4 * index)),
            write_disable: Some(bit_register(0xae0 + 4 * index)),
            lock: Some(bit_register(0xad0 + 4 * index)),
        })
    };
    Layout {
        aperture_bytes: 0x14_0000,
        planes: 4,
        stride: 0x4_0000,
        cache_status: Some(bit_register(0x82c)),
        groups: [group(0), group(1), group(2), group(3)],
        dram_base: 0x100_0000_0000,
    }
}

/// SPTM's `ctrr_lock_sptm` on the M4 and later: CTRR-C and D read
/// iBoot's limits and unlocked controls on every plane, then lock, last
/// plane first; each group's region is locked on its own, and CTRR-A
/// and B, which no component writes, stay unlocked.
#[test]
fn sptm_locks_ctrr_c_and_d_each_over_its_own_region() {
    let base = 0x100_0000_0000;
    let c = (base + 0x400_0000, 0x10_0000);
    let d = (base + 0x800_0000, 0x40_0000);
    let mut amcc = Amcc::new(
        interleaved(),
        2,
        [Some((base + 0x200_0000, 0x4000)), None, Some(c), Some(d)],
        None,
    )
    .unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let at =
        |aperture: u64, plane: u64, offset: u64| aperture * 0x14_0000 + plane * 0x4_0000 + offset;
    for aperture in 0..2 {
        for plane in 0..4 {
            let read = |amcc: &mut Amcc, offset, access: &mut Access<'_>| {
                amcc.read(at(aperture, plane, offset), Width::Word, access)
            };
            assert_eq!(read(&mut amcc, 0xaa8, &mut access), Ok(0x1000));
            assert_eq!(read(&mut amcc, 0xab8, &mut access), Ok(0x103f));
            assert_eq!(read(&mut amcc, 0xaac, &mut access), Ok(0x2000));
            assert_eq!(read(&mut amcc, 0xabc, &mut access), Ok(0x20ff));
            assert_eq!(read(&mut amcc, 0xaa4, &mut access), Ok(0));
            for control in [0xae8, 0xad8, 0xaec, 0xadc] {
                assert_eq!(read(&mut amcc, control, &mut access), Ok(0));
            }
        }
    }
    for group in [2, 3] {
        for aperture in 0..2 {
            for plane in (0..4).rev() {
                for control in [0xac0, 0xae0, 0xad0] {
                    amcc.write(
                        at(aperture, plane, control + 4 * group),
                        Width::Word,
                        1,
                        &mut access,
                    )
                    .unwrap();
                }
            }
        }
    }
    assert_eq!(
        amcc.locked_regions(),
        [
            None,
            None,
            Some((c.0, c.0 + c.1 - 1)),
            Some((d.0, d.0 + d.1 - 1)),
        ]
    );
    // A locked group's limits and controls stay; others still change.
    assert!(amcc.write(0xaa8, Width::Word, 0, &mut access).is_err());
    assert!(amcc.write(0xac8, Width::Word, 0, &mut access).is_err());
    amcc.write(0xaa4, Width::Word, 7, &mut access).unwrap();
    assert_eq!(amcc.read(0xaa4, Width::Word, &mut access), Ok(7));
    // A region programmed into a group the map lacks refuses.
    let mut lacking = interleaved();
    lacking.groups[3] = None;
    assert!(Amcc::new(lacking, 1, [None, None, None, Some(d)], None).is_err());
    lacking.groups[0] = None;
    assert!(Amcc::new(lacking, 1, NONE, None).is_err());
}

#[test]
fn io_access_limits_are_absolute_and_need_no_cache_or_lock_register() {
    let mut description = layout();
    description.aperture_bytes = 0x4000;
    description.planes = 1;
    description.stride = 0;
    description.dram_base = 0;
    description.cache_status = None;
    a(&mut description).lower_limit.offset = 0x220;
    a(&mut description).upper_limit.offset = 0x224;
    a(&mut description).enable = Some(bit_register(0x228));
    a(&mut description).write_disable = None;
    a(&mut description).lock = None;
    let base = 0x100_0200_0000;
    let mut model = Amcc::new(description, 4, ctrr_a(Some((base, 0x8000))), None).unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    assert_eq!(model.locked_regions()[0], None);
    for aperture in 0..4 {
        let origin = aperture * 0x4000;
        assert_eq!(
            model.read(origin + 0x220, Width::Word, &mut access),
            Ok(base >> 14)
        );
        assert_eq!(
            model.read(origin + 0x224, Width::Word, &mut access),
            Ok((base + 0x7fff) >> 14)
        );
        model
            .write(origin + 0x228, Width::Word, 1, &mut access)
            .unwrap();
        assert_eq!(model.read(origin + 0x228, Width::Word, &mut access), Ok(1));
        for absent in [0, 0x22c, 0x424, 0x68c, 0x7f0] {
            assert!(
                model
                    .read(origin + absent, Width::Word, &mut access)
                    .is_err()
            );
            assert!(
                model
                    .write(origin + absent, Width::Word, 1, &mut access)
                    .is_err()
            );
        }
    }
    assert_eq!(model.locked_regions()[0], Some((base, base + 0x7fff)));
    description.planes = 2;
    assert!(Amcc::new(description, 1, NONE, None).is_err());
}

#[test]
fn disabling_dram_broadcasts_and_stops_before_further_guest_ram_execution() {
    let mut sink = InterruptLatch::new();
    let mut a = Access::new(0, 0, &mut sink);
    let mut m = Amcc::new(layout(), 1, NONE, Some(CACHE)).unwrap();
    assert!(m.planes.borrow().iter().all(|p| p.dram_access));
    assert!(
        m.write(CACHE.broadcast + DRAM_ACCESS, Width::Word, 1, &mut a)
            .is_err()
    );
    assert!(a.reset_request().is_none());
    assert!(m.planes.borrow().iter().all(|p| p.dram_access));
    m.write(CACHE.broadcast + DRAM_ACCESS, Width::Word, 0, &mut a)
        .unwrap();
    assert!(m.planes.borrow().iter().all(|p| !p.dram_access));
    let request = a.reset_request().unwrap();
    assert_eq!(request.transition, Transition::Halt);
    assert!(request.reason.contains("DRAM access disabled"));
    assert!(
        m.read(CACHE.broadcast + DRAM_ACCESS, Width::Word, &mut a)
            .is_err()
    );
    assert!(
        m.write(CACHE.broadcast + DRAM_ACCESS, Width::Double, 0, &mut a)
            .is_err()
    );
}

#[test]
fn extended_status_offsets_and_absent_controls_keep_each_plane_independent() {
    let mut description = layout();
    description.aperture_bytes = 0x20_0000;
    description.cache_status = Some(bit_register(0x10_000c));
    a(&mut description).write_disable = None;
    let base = description.dram_base;
    let mut device = Amcc::new(
        description,
        2,
        ctrr_a(Some((base + 0x200_0000, 0x4000))),
        None,
    )
    .unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    for aperture in 0..2 {
        for plane in 0..4 {
            let origin = aperture * description.aperture_bytes + plane * description.stride;
            assert_eq!(
                device.read(origin + 0x10_000c, Width::Word, &mut access),
                Ok(1)
            );
            assert_eq!(
                device.read(origin + 0x680, Width::Word, &mut access),
                Ok(0x800)
            );
            assert!(
                device
                    .read(origin + 0x7f0, Width::Word, &mut access)
                    .is_err()
            );
            assert!(
                device
                    .write(origin + 0x7f0, Width::Word, 1, &mut access)
                    .is_err()
            );
            device
                .write(origin + 0x688, Width::Word, 1, &mut access)
                .unwrap();
            device
                .write(origin + 0x68c, Width::Word, 1, &mut access)
                .unwrap();
            assert!(
                device
                    .write(origin + 0x680, Width::Word, 0, &mut access)
                    .is_err()
            );
        }
    }
    assert_eq!(
        device.locked_regions()[0],
        Some((base + 0x200_0000, base + 0x200_3fff))
    );
    assert!(
        device
            .read(2 * description.aperture_bytes, Width::Word, &mut access)
            .is_err()
    );
    a(&mut description).enable = None;
    let mut absent = Amcc::new(description, 1, NONE, None).unwrap();
    assert!(absent.read(0x688, Width::Word, &mut access).is_err());
    description.cache_status.as_mut().unwrap().offset = 0x20_0000;
    assert!(Amcc::new(description, 1, NONE, None).is_err());
    description.cache_status.as_mut().unwrap().offset =
        a(&mut description).lower_limit.offset + description.stride;
    assert!(Amcc::new(description, 1, NONE, None).is_err());
}

#[test]
fn sptms_lockdown_reads_iboots_limits_and_locks_every_plane() {
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut amcc = Amcc::new(layout(), 1, ctrr_a(Some((0x8_0200_0000, 0x579_0000))), None).unwrap();
    for plane in 0..4u64 {
        let at = |offset: u64| plane * 0x4_0000 + offset;
        assert_eq!(amcc.read(at(0x424), Width::Word, &mut access), Ok(1));
        assert_eq!(amcc.read(at(0x680), Width::Word, &mut access), Ok(0x800));
        assert_eq!(amcc.read(at(0x684), Width::Word, &mut access), Ok(0x1de3));
        assert_eq!(amcc.read(at(0x7f0), Width::Word, &mut access), Ok(0));
        assert_eq!(amcc.read(at(0x68c), Width::Word, &mut access), Ok(0));
    }
    assert_eq!(amcc.locked_regions()[0], None);
    for plane in (0..4u64).rev() {
        for offset in [0x688, 0x7f0, 0x68c] {
            amcc.write(plane * 0x4_0000 + offset, Width::Word, 1, &mut access)
                .unwrap();
        }
    }
    assert_eq!(
        amcc.locked_regions()[0],
        Some((0x8_0200_0000, 0x8_0778_ffff))
    );
    // A repeat completes; a change, other registers and widths stop.
    amcc.write(0x688, Width::Word, 1, &mut access).unwrap();
    amcc.write(0x680, Width::Word, 0x800, &mut access).unwrap();
    assert!(amcc.write(0x680, Width::Word, 0, &mut access).is_err());
    assert!(amcc.write(0x68c, Width::Word, 0, &mut access).is_err());
    assert!(amcc.write(0x424, Width::Word, 1, &mut access).is_err());
    assert!(amcc.read(0x428, Width::Word, &mut access).is_err());
    assert!(amcc.read(0x680, Width::Double, &mut access).is_err());
    assert!(amcc.read(0x10_0000, Width::Word, &mut access).is_err());
}

#[test]
fn programmed_regions_are_whole_pages_above_dram() {
    assert!(Amcc::new(layout(), 1, ctrr_a(Some((0x8_0200_1000, 0x4000))), None).is_err());
    assert!(Amcc::new(layout(), 1, ctrr_a(Some((0x7_0000_0000, 0x4000))), None).is_err());
    let blank = Amcc::new(layout(), 2, NONE, None).unwrap();
    assert_eq!(blank.planes.borrow().len(), 8);
}

const CACHE: Cache = Cache {
    shared: (0x10_0000, 0x8_0000),
    broadcast: 0xf0_0000,
    bytes: 8 << 20,
    ways: 16,
};

/// `mccEnableCacheMode`, `_cacheFlush` and `readCacheSize` as the 26A434
/// J473AP driver runs them.
#[test]
fn the_memory_cache_powers_ways_enables_and_flushes_at_once() {
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut amcc = Amcc::new(layout(), 1, NONE, Some(CACHE)).unwrap();
    let plane = |n: u64, offset: u64| n * 0x4_0000 + offset;
    let mut read = |amcc: &mut Amcc, offset, width| amcc.read(offset, width, &mut access);
    assert_eq!(read(&mut amcc, 0x10_001c, Width::Word), Ok(0x800));
    for n in 0..4 {
        assert_eq!(read(&mut amcc, plane(n, 0x424), Width::Word), Ok(1));
        assert_eq!(read(&mut amcc, plane(n, 0x1c04), Width::Word), Ok(0));
    }
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut write =
        |amcc: &mut Amcc, offset, width, value| amcc.write(offset, width, value, &mut access);
    // Enable: power 16 ways, wait, then clear cache-status.
    write(&mut amcc, 0xf0_1c00, Width::Word, 16).unwrap();
    write(&mut amcc, 0xf0_0424, Width::Word, 0).unwrap();
    assert!(write(&mut amcc, 0xf0_1c00, Width::Word, 17).is_err());
    // Flush: set cache-status and start the flush.
    write(&mut amcc, 0xf0_0424, Width::Word, 1).unwrap();
    write(&mut amcc, 0xf0_1c2c, Width::Word, 1).unwrap();
    // A group quota through the broadcast window, and the shared
    // configuration.
    write(&mut amcc, 0xf0_a010, Width::Word, 0x20).unwrap();
    write(&mut amcc, 0x15_8000, Width::Double, 1 << 55).unwrap();
    assert!(write(&mut amcc, 0x15_9000, Width::Double, 0).is_err());
    assert!(write(&mut amcc, 0x10_001c, Width::Word, 0).is_err());
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut read = |amcc: &mut Amcc, offset, width| amcc.read(offset, width, &mut access);
    for n in 0..4 {
        assert_eq!(
            read(&mut amcc, plane(n, 0x1c04), Width::Word),
            Ok(16 << 10 | 16 << 5)
        );
        assert_eq!(read(&mut amcc, plane(n, 0x1c2c), Width::Word), Ok(0));
        assert_eq!(read(&mut amcc, plane(n, 0x424), Width::Word), Ok(1));
        assert_eq!(read(&mut amcc, plane(n, 0xa010), Width::Word), Ok(0x20));
        assert_eq!(read(&mut amcc, plane(n, 0x2_5000), Width::Double), Ok(0));
    }
    assert_eq!(read(&mut amcc, 0xf0_a010, Width::Word), Ok(0x20));
    assert_eq!(read(&mut amcc, 0x15_8000, Width::Double), Ok(1 << 55));
    // Undescribed registers and widths still refuse.
    assert!(read(&mut amcc, 0x1c04, Width::Double).is_err());
    assert!(read(&mut amcc, 0x1c08, Width::Word).is_err());
    assert!(read(&mut amcc, 0x18_0000, Width::Word).is_err());
}

#[test]
fn a_broadcast_write_reaches_every_plane_or_none() {
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut amcc = Amcc::new(layout(), 1, NONE, Some(CACHE)).unwrap();
    // Plane 3 locks its group; a broadcast change of enable then stops
    // without changing planes 0 to 2.
    for offset in [0x688, 0x68c] {
        amcc.write(3 * 0x4_0000 + offset, Width::Word, 1, &mut access)
            .unwrap();
    }
    assert!(amcc.write(0xf0_0688, Width::Word, 0, &mut access).is_err());
    assert!(amcc.read(0xf0_0688, Width::Word, &mut access).is_err());
    assert_eq!(amcc.read(0x688, Width::Word, &mut access), Ok(0));
    // Blocks that overlap the planes or each other are refused.
    let overlapping = Cache {
        shared: (0xf0_0000, 0x8_0000),
        ..CACHE
    };
    assert!(Amcc::new(layout(), 1, NONE, Some(overlapping)).is_err());
}
#[test]
fn native_cache_geometry_refuses_wrapped_or_zero_plane_spans_before_allocating() {
    assert!(
        Amcc::new(
            Layout {
                stride: u64::MAX,
                ..layout()
            },
            1,
            NONE,
            Some(CACHE)
        )
        .unwrap_err()
        .to_string()
        .contains("geometry wraps")
    );
    assert!(
        Amcc::new(
            Layout {
                stride: 0,
                ..layout()
            },
            1,
            NONE,
            Some(CACHE)
        )
        .is_err()
    );
}
