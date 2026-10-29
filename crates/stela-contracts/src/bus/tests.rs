mod advance;

use super::*;
use crate::interrupt::InterruptLatch;

/// A 16-byte scratch register file, for routing tests only.
struct Scratch([u8; 16]);
impl MmioDevice for Scratch {
    fn name(&self) -> &'static str {
        "scratch"
    }
    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let mut bytes = [0; 8];
        let range = offset as usize..(offset + width.bytes()) as usize;
        bytes[..range.len()].copy_from_slice(&self.0[range]);
        Ok(u64::from_le_bytes(bytes))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let range = offset as usize..(offset + width.bytes()) as usize;
        let len = range.len();
        self.0[range].copy_from_slice(&value.to_le_bytes()[..len]);
        Ok(())
    }
}

#[test]
fn routing_requires_a_nonwrapping_complete_access_without_register_effects() {
    let mut bus = Bus::new();
    let bank = bus.add(Box::new(Scratch([0; 16])));
    bus.map(bank, 0x1000, 16, 0).unwrap();
    assert_eq!(bus.route(0x1008, Width::Double), Ok((bank, 8)));
    for address in [0x1010, u64::MAX - 7] {
        assert_eq!(
            bus.route(address, Width::Double),
            Err(MmioError::Unmapped {
                address,
                width: Width::Double,
            })
        );
    }
}

#[test]
fn install_validates_all_ranges_before_publishing_any_owner() {
    let mut bus = Bus::new();
    let original = bus
        .install(Box::new(Scratch([0; 16])), &[(0x2000, 16, 0)])
        .unwrap();
    for bindings in [
        vec![(0x1000, 16, 0), (0x2008, 16, 16)],
        vec![(0x1000, 16, 0), (0x1008, 16, 16)],
        vec![(0x1000, 16, 0), (u64::MAX - 7, 16, 0)],
        vec![(0x1000, 16, 0), (0x3000, 16, u64::MAX - 7)],
        vec![(0x1000, 16, 0), (0x3000, 0, 0)],
        vec![],
    ] {
        assert!(bus.install(Box::new(Scratch([0; 16])), &bindings).is_err());
        assert_eq!(bus.devices.len(), 1);
        assert_eq!(bus.regions.len(), 1);
        assert!(bus.route(0x1000, Width::Word).is_err());
        assert_eq!(bus.route(0x2000, Width::Word), Ok((original, 0)));
    }
    assert_eq!(
        bus.install(
            Box::new(Scratch([0; 16])),
            &[(0x1000, 16, 0), (0x1008, 16, 16)]
        ),
        Err(MapError::ProposedOverlap)
    );
    let added = bus
        .install(
            Box::new(Scratch([0; 16])),
            &[(0x3000, 8, 8), (0x1000, 8, 0)],
        )
        .unwrap();
    assert_eq!(bus.route(0x3004, Width::Word), Ok((added, 12)));
    assert_eq!(bus.route(0x1000, Width::Word), Ok((added, 0)));
}

#[test]
fn a_later_owner_failure_leaves_the_whole_installation_unpublished() {
    let mut bus = Bus::new();
    let original = bus
        .install(Box::new(Scratch([7; 16])), &[(0x2000, 16, 0)])
        .unwrap();
    for second in [
        vec![(0x2008, 8, 0)],
        vec![(0x1004, 8, 0)],
        vec![(0x3000, 0, 0)],
        vec![(u64::MAX - 3, 8, 0)],
        vec![(0x3000, 8, u64::MAX - 3)],
        vec![],
    ] {
        let result = bus.install_many(
            [Box::new(Scratch([1; 16])), Box::new(Scratch([2; 16]))],
            [&[(0x1000, 8, 0)], &second],
        );
        assert!(result.is_err());
        assert_eq!(bus.devices.len(), 1);
        assert_eq!(bus.regions.len(), 1);
        assert!(bus.route(0x1000, Width::Word).is_err());
        assert!(bus.route(0x3000, Width::Word).is_err());
        assert_eq!(bus.route(0x2000, Width::Word), Ok((original, 0)));
        assert_eq!(bus.device::<Scratch>(original).unwrap().0, [7; 16]);
    }
    assert_eq!(bus.install_many::<0>([], []), Err(MapError::Empty));
    assert!(
        bus.install_many(
            [Box::new(Scratch([1; 16])), Box::new(Scratch([2; 16]))],
            [&[], &[(0x3000, 8, 0)]],
        )
        .is_err()
    );
    assert_eq!(bus.devices.len(), 1);
    assert_eq!(bus.regions.len(), 1);
}

#[test]
fn one_batch_publishes_distinct_owners_and_their_aliases_with_exact_offsets() {
    let mut bus = Bus::new();
    let [first, second] = bus
        .install_many(
            [Box::new(Scratch([1; 16])), Box::new(Scratch([2; 16]))],
            [
                &[(0x3000, 8, 8), (0x1000, 8, 0)],
                &[(0x2000, 8, 0), (0x4000, 8, 0)],
            ],
        )
        .unwrap();
    assert_ne!(first, second);
    assert_eq!(bus.route(0x3004, Width::Word), Ok((first, 12)));
    assert_eq!(bus.route(0x1004, Width::Word), Ok((first, 4)));
    assert_eq!(bus.route(0x2004, Width::Word), Ok((second, 4)));
    assert_eq!(bus.route(0x4004, Width::Word), Ok((second, 4)));
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    bus.write(0x2000, Width::Word, 0x98765432, &mut access)
        .unwrap();
    assert_eq!(bus.read(0x4000, Width::Word, &mut access), Ok(0x98765432));
    assert_eq!(bus.read(0x1000, Width::Word, &mut access), Ok(0x01010101));
}

#[test]
fn a_window_maps_only_the_bytes_smaller_banks_leave() {
    let mut bus = Bus::new();
    let small = bus.add(Box::new(Scratch([0; 16])));
    let window = bus.add(Box::new(Scratch([0; 16])));
    bus.map(small, 0x1400, 0x100, 0).unwrap();
    bus.map(small, 0x1000, 0x10, 0x100).unwrap();
    bus.map_gaps(window, 0x1000, 0x1000, 0).unwrap();
    let route = |bus: &Bus, address| bus.route(address, Width::Word).unwrap();
    assert_eq!(route(&bus, 0x1000), (small, 0x100));
    assert_eq!(route(&bus, 0x1010), (window, 0x10));
    assert_eq!(route(&bus, 0x1404), (small, 0x4));
    assert_eq!(route(&bus, 0x1500), (window, 0x500));
    assert_eq!(route(&bus, 0x1ffc), (window, 0xffc));
    assert!(bus.route(0x2000, Width::Word).is_err());
    // A window that is already wholly owned refuses.
    let other = bus.add(Box::new(Scratch([0; 16])));
    assert!(matches!(
        bus.map_gaps(other, 0x1400, 0x100, 0),
        Err(MapError::Overlap { .. })
    ));
}

#[test]
fn whole_range_preflight_sees_interior_owners_and_publishes_nothing() {
    let mut bus = Bus::new();
    let bank = bus.add(Box::new(Scratch([7; 16])));
    bus.map(bank, 0x1800, 16, 0).unwrap();
    assert_eq!(
        bus.check_free(0x1000, 0x1000),
        Err(MapError::Overlap { existing: bank })
    );
    assert_eq!(
        bus.check_free(0x1801, 1),
        Err(MapError::Overlap { existing: bank })
    );
    assert_eq!(bus.check_free(0x17f0, 16), Ok(()));
    assert_eq!(bus.check_free(0x1810, 16), Ok(()));
    assert_eq!(bus.check_free(0, 0), Err(MapError::Empty));
    assert_eq!(bus.check_free(u64::MAX, 2), Err(MapError::Overflow));
    assert_eq!(bus.regions.len(), 1);
    assert_eq!(bus.devices.len(), 1);
    assert_eq!(bus.device::<Scratch>(bank).unwrap().0, [7; 16]);
    // A successful preflight is not a reservation; actual map follows
    // the same checked overlap path under exclusive mutable Bus access.
    bus.map(bank, 0x1810, 16, 0).unwrap();
    assert_eq!(
        bus.check_free(0x1810, 16),
        Err(MapError::Overlap { existing: bank })
    );
}

#[test]
fn routes_ranges_with_device_offsets_and_refuses_gaps() {
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut bus = Bus::new();
    let scratch = bus.add(Box::new(Scratch([0; 16])));
    bus.map(scratch, 0x2_3b0c_0000, 8, 0).unwrap();
    bus.map(scratch, 0x2_3b0c_8000, 8, 8).unwrap();
    bus.write(0x2_3b0c_8000, Width::Word, 0xdead_beef, &mut access)
        .unwrap();
    assert_eq!(
        bus.read(0x2_3b0c_8000, Width::Half, &mut access),
        Ok(0xbeef)
    );
    bus.write(0x2_3b0c_0004, Width::Word, 0x1234_5678, &mut access)
        .unwrap();
    assert_eq!(
        bus.read(0x2_3b0c_0000, Width::Double, &mut access),
        Ok(0x1234_5678_0000_0000)
    );
    assert_eq!(
        bus.read(0x2_3b0c_0008, Width::Word, &mut access),
        Err(MmioError::Unmapped {
            address: 0x2_3b0c_0008,
            width: Width::Word
        })
    );
    assert_eq!(
        bus.read(0x2_3b0c_0002, Width::Word, &mut access),
        Err(MmioError::Misaligned {
            address: 0x2_3b0c_0002,
            width: Width::Word
        })
    );
    assert_eq!(
        bus.map(scratch, 0x2_3b0c_0004, 8, 0),
        Err(MapError::Overlap { existing: scratch })
    );
    assert!(bus.device_mut::<Scratch>(scratch).is_some());
}
