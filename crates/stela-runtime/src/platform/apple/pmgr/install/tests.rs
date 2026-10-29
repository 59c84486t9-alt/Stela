use super::*;
use alloc::{boxed::Box, collections::BTreeMap, vec};
use core::sync::atomic::{Ordering, fence};
use {
    stela_contracts::bus::Access, stela_contracts::bus::Bus, stela_contracts::bus::Direction,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError,
    stela_contracts::interrupt::InterruptLatch,
};
use {stela_contracts::dma::Memory, stela_contracts::dma::test_support::Ram};

/// Test-only captured configuration bank, without any hardware execution or
/// completion semantics. All SRAM data still traverses the RAM API.
#[derive(Default)]
struct Captured {
    words: BTreeMap<u64, u64>,
    reads: BTreeMap<u64, u32>,
    writes: BTreeMap<u64, u32>,
    fail_after_write: Option<u64>,
    fail_after_read: Option<u64>,
}
impl MmioDevice for Captured {
    fn name(&self) -> &'static str {
        "captured installation test bank"
    }
    fn read(&mut self, offset: u64, _: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        *self.reads.entry(offset).or_default() += 1;
        if self.fail_after_read == Some(offset) {
            return Err(MmioError::Unsupported {
                device: self.name(),
                offset,
                width: Width::Word,
                direction: Direction::Read,
                reason: "after committed read side effect",
            });
        }
        Ok(self.words.get(&offset).copied().unwrap_or(0xa5a55aa5))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        *self.writes.entry(offset).or_default() += 1;
        self.words.insert(offset, value);
        if self.fail_after_write == Some(offset) {
            return Err(MmioError::Unsupported {
                device: self.name(),
                offset,
                width,
                direction: Direction::Write,
                reason: "after committed configuration effect",
            });
        }
        Ok(())
    }
}
fn inputs(kind: ProgramKind, stage: u32) -> Inputs {
    Inputs {
        chip: 0x8112,
        revision: 0x11,
        stage,
        kind,
        // These are explicit synthetic test inputs, not a native snapshot.
        pool: Some(
            NubPool::from_metadata(Metadata {
                first_page: 2,
                pages: 0x2e,
            })
            .unwrap(),
        ),
        history: History {
            setup: [Some(0); 2],
            activation: [Some(0); 2],
        },
    }
}
fn images(kind: ProgramKind) -> Vec<NativeImage> {
    kind.sequences()
        .into_iter()
        .map(|sequence| NativeImage {
            sequence,
            counted_words: 1,
            // Unknown native tag is data here, never silently executed.
            bytes: [0x44u32, 0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect(),
        })
        .collect()
}
fn install(kind: ProgramKind, stage: u32) -> Installation {
    Installation::new(inputs(kind, stage), images(kind)).unwrap()
}
fn bus(installation: &Installation) -> (Bus, stela_contracts::bus::DeviceId) {
    let mut bank = Captured::default();
    bank.words.insert(0x23d050008, 0);
    bank.words.insert(0x23d054008, 0);
    let mut bus = Bus::new();
    let id = bus.add(Box::new(bank));
    let mut words = alloc::collections::BTreeSet::new();
    for step in &installation.steps {
        match step {
            Step::Write(write) if !(NUB_BASE..NUB_LIMIT).contains(&write.address) => {
                words.insert(write.address);
            }
            Step::Modify { address, .. } | Step::Expect { address, .. } => {
                words.insert(*address);
            }
            _ => {}
        }
    }
    for address in words {
        bus.map(id, address, 4, address).unwrap();
    }
    (bus, id)
}
fn route(
    action: Action,
    ram: &mut Ram,
    bus: &mut Bus,
    access: &mut Access<'_>,
) -> Outcome<MmioError> {
    match action {
        Action::DmbSy => {
            // The test has one synchronous RAM/Bus participant. This host
            // fence does not check the multi-PE production adapter.
            fence(Ordering::SeqCst);
            Outcome::Ordered
        }
        Action::Read { address, width } => match bus.read(address, width, access) {
            Ok(value) => Outcome::Read(value),
            Err(error) => Outcome::Uncertain(error),
        },
        Action::Write(write) if (NUB_BASE..NUB_LIMIT).contains(&write.address) => {
            let data = write.value.to_le_bytes();
            assert!(ram.write(write.address, &data[..write.width.bytes() as usize]));
            Outcome::Written
        }
        Action::Write(write) => match bus.write(write.address, write.width, write.value, access) {
            Ok(()) => Outcome::Written,
            Err(error) => Outcome::Uncertain(error),
        },
    }
}
fn drain(
    installation: &mut Installation,
    ram: &mut Ram,
    bus: &mut Bus,
    access: &mut Access<'_>,
) -> Vec<Action> {
    let mut actions = Vec::new();
    while let Some(claim) = installation.begin().unwrap() {
        let action = installation.dispatch(&claim).unwrap();
        let result = route(action, ram, bus, access);
        installation.finish(&claim, result).unwrap();
        actions.push(action);
    }
    actions
}
#[test]
fn all_thirty_bindings_reach_pointer_ram_and_preserve_paired_fields() {
    let mut ram = Ram::new(NUB_BASE, 0x40000);
    ram.bytes.fill(0xcc);
    let mut sink = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut sink);
    let mut seen = alloc::collections::BTreeSet::new();
    for kind in [ProgramKind::EarlyCpu, ProgramKind::EarlyPeripheral] {
        let mut install = install(kind, 5);
        let (mut bus, id) = bus(&install);
        let actions = drain(&mut install, &mut ram, &mut bus, &mut access);
        assert!(install.published());
        assert!(install.blockage().is_none());
        let first_image = actions.iter().position(|action| matches!(action, Action::Write(write) if write.width == Width::Word && (NUB_BASE..NUB_LIMIT).contains(&write.address))).unwrap();
        let mut zero_pointers = 0;
        let mut pointers = 0;
        for (index, action) in actions.iter().enumerate() {
            if let Action::Write(write) = action
                && write.width == Width::Double
            {
                assert!(index < first_image);
                if write.value == 0 {
                    zero_pointers += 1;
                } else {
                    pointers += 1;
                }
            }
        }
        assert_eq!(zero_pointers, install.placements().len());
        assert_eq!(pointers, install.placements().len());
        for placement in install.placements() {
            seen.insert(placement.sequence);
            assert!(placement.code.is_multiple_of(32));
            let mut pointer = [0; 8];
            assert!(ram.read(
                placement.table + u64::from(placement.slot) * 8,
                &mut pointer
            ));
            assert_eq!(u64::from_le_bytes(pointer), placement.code >> 4);
            let mut image = [0; 8];
            assert!(ram.read(placement.code, &mut image));
            assert_eq!(image, [0x44, 0, 0, 0, 0, 0, 0, 0]);
        }
        let bank = bus.device_mut::<Captured>(id).unwrap();
        if !kind.peripheral() {
            // Sequences0/2 share this word, with independently replaced
            // slots3/9 and enable bits8/24. Every unrelated bit survives.
            let expected =
                (0xa5a55aa5u32 & !(0x1f | (0x1f << 16))) | 3 | (9 << 16) | (1 << 8) | (1 << 24);
            assert_eq!(bank.words[&0x23d2d0214], u64::from(expected));
            // Group3 source uses OR, rather than replacing either field.
            assert_eq!(bank.words[&0x23b78d004], 0xa5a55aa5 | (1 << 5));
        }
        assert_eq!(
            bank.words[&GROUP_CONTROL[usize::from(kind.groups()[0])]],
            if kind.peripheral() { 0x30000 } else { 0x5000 }
        );
    }
    assert_eq!(seen, (0..30).collect());
}
#[test]
fn both_families_use_native_binding_bank_without_claiming_hardware_completion() {
    use {crate::platform::apple::power::Power, stela_soc_data::power::Kind};
    let mut bus = Bus::new();
    let offsets = Kind::NubBindings.offsets();
    let model = Power::from_snapshot(
        Kind::NubBindings,
        offsets.iter().map(|offset| {
            (
                *offset,
                if GROUP_CONTROL.contains(offset) {
                    0
                } else {
                    0xa5a55aa5
                },
            )
        }),
    )
    .unwrap();
    let id = bus.add(Box::new(model));
    for offset in offsets {
        bus.map(id, offset, 4, offset).unwrap();
    }
    let metadata = bus.add(Box::new(Captured::default()));
    for address in [0x23d050000, 0x23d050004, 0x23d054000, 0x23d054004] {
        bus.map(metadata, address, 4, address).unwrap();
    }
    let mut ram = Ram::new(NUB_BASE, 0x40000);
    let mut sink = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut sink);
    for kind in [ProgramKind::EarlyCpu, ProgramKind::EarlyPeripheral] {
        let mut installer = install(kind, 5);
        drain(&mut installer, &mut ram, &mut bus, &mut access);
        assert!(installer.published());
        assert_eq!(
            installer.committed_reads(),
            installer.placements().len() as u64 * 2
        );
    }
    let bank = bus.device_mut::<Power>(id).unwrap();
    assert_eq!(bank.pending_configuration().count(), 64);
    assert!(bank.advance(&mut access).is_err());
    // The bank keeps configured fields; it has no trigger->PC or
    // native instruction retirement method that could invent PS effects.
    assert_eq!(
        bank.read(0x23d2d0214, Width::Word, &mut access),
        Ok(0xa5a95ba3)
    );
    assert!(
        bank.write(0x23d2d0214, Width::Word, 0, &mut access)
            .is_err()
    );
    assert_eq!(bank.pending_configuration().count(), 64);
}

#[test]
fn setup_activation_and_dmb_order_follow_stage_guards_without_retirement() {
    for stage in [2, 3, 5, 10, 11] {
        for kind in [
            ProgramKind::EarlyCpu,
            ProgramKind::LateCpu,
            ProgramKind::EarlyPeripheral,
            ProgramKind::LatePeripheral,
        ] {
            let mut install = install(kind, stage);
            let (mut bus, _) = bus(&install);
            let mut ram = Ram::new(NUB_BASE, 0x40000);
            let mut sink = InterruptLatch::new();
            let mut access = Access::new(0, 0, &mut sink);
            let actions = drain(&mut install, &mut ram, &mut bus, &mut access);
            let family = usize::from(kind.peripheral());
            assert_eq!(
                install.history().setup[family],
                Some(u8::from(matches!(stage, 2 | 3)))
            );
            assert_eq!(
                install.history().activation[family],
                Some(u8::from(matches!(stage, 2 | 3 | 10)))
            );
            let activate = if kind.peripheral() {
                0x23d054008
            } else {
                0x23d050008
            };
            let activation = actions.iter().position(
                |action| matches!(action, Action::Write(write) if write.address == activate),
            );
            if matches!(stage, 2 | 3 | 10) {
                let index = activation.unwrap();
                assert_eq!(
                    actions[index - 1],
                    Action::Read {
                        address: activate,
                        width: Width::Word
                    }
                );
                assert_eq!(actions[index + 1], Action::DmbSy);
                assert_eq!(
                    actions[index + 2],
                    Action::Read {
                        address: activate,
                        width: Width::Word
                    }
                );
            } else {
                assert!(activation.is_none());
            }
            if stage == 5 {
                assert!(!actions.contains(&Action::DmbSy));
            }
            if kind == ProgramKind::LateCpu {
                // Shared descriptors still publish group3 despite no such sequence.
                assert_eq!(
                    actions[1],
                    Action::Write(PhysicalWrite {
                        address: 0x23b78d000,
                        width: Width::Word,
                        value: 0x23df05100 >> 8
                    })
                );
            }
        }
    }
}
#[test]
fn latched_rmw_survives_no_effect_write_refusal_and_uncertain_write_is_terminal() {
    let mut install = install(ProgramKind::EarlyCpu, 5);
    let (mut bus, id) = bus(&install);
    let mut ram = Ram::new(NUB_BASE, 0x40000);
    let mut sink = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut sink);
    // Commit group stores and first live RMW read.
    for _ in 0..3 {
        let claim = install.begin().unwrap().unwrap();
        let action = install.dispatch(&claim).unwrap();
        install
            .finish(&claim, route(action, &mut ram, &mut bus, &mut access))
            .unwrap();
    }
    let claim = install.begin().unwrap().unwrap();
    let first = install.dispatch(&claim).unwrap();
    assert_eq!(
        install.finish(&claim, Outcome::NoEffect("target preflight refused")),
        Err(FinishError::NoEffect("target preflight refused"))
    );
    // An external change cannot cause this RMW to be silently reread.
    bus.device_mut::<Captured>(id)
        .unwrap()
        .words
        .insert(0x23d2d0214, 0);
    let retry = install.begin().unwrap().unwrap();
    assert_eq!(retry.action(), first);
    let action = install.dispatch(&retry).unwrap();
    bus.device_mut::<Captured>(id).unwrap().fail_after_write = Some(0x23d2d0214);
    let error = match route(action, &mut ram, &mut bus, &mut access) {
        Outcome::Uncertain(error) => error,
        _ => panic!("real target must retain the write then refuse"),
    };
    assert_eq!(
        install.finish(&retry, Outcome::Uncertain(error)),
        Err(FinishError::Uncertain(error))
    );
    assert_eq!(install.committed_writes(), 2);
    assert_eq!(install.committed_reads(), 1);
    assert_eq!(install.blockage(), Some(Blockage::Uncertain(action)));
    assert!(matches!(install.begin(), Err(Error::Blocked)));
    assert_eq!(install.cancel(&retry), Err(Error::Blocked));
    let bank = bus.device_mut::<Captured>(id).unwrap();
    assert_eq!(bank.reads[&0x23d2d0214], 1);
    assert_eq!(bank.writes[&0x23d2d0214], 1);
    assert!(!install.published());
}
#[test]
fn partial_read_and_barrier_refusal_cannot_replay_committed_stores_or_reads() {
    let mut install = install(ProgramKind::EarlyCpu, 2);
    let (mut bus, id) = bus(&install);
    let mut ram = Ram::new(NUB_BASE, 0x40000);
    let mut sink = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut sink);
    // Reach the first DMB after its setup store has committed.
    loop {
        let claim = install.begin().unwrap().unwrap();
        let action = install.dispatch(&claim).unwrap();
        if action == Action::DmbSy {
            let writes = install.committed_writes();
            assert_eq!(
                install.finish(&claim, Outcome::NoEffect("ordering preflight refused")),
                Err(FinishError::NoEffect("ordering preflight refused"))
            );
            let retry = install.begin().unwrap().unwrap();
            assert_eq!(install.dispatch(&retry), Ok(Action::DmbSy));
            install.finish::<()>(&retry, Outcome::Ordered).unwrap();
            assert_eq!(install.committed_writes(), writes);
            break;
        }
        install
            .finish(&claim, route(action, &mut ram, &mut bus, &mut access))
            .unwrap();
    }
    let next = install.begin().unwrap().unwrap();
    let action = install.dispatch(&next).unwrap();
    let Action::Read { address, .. } = action else {
        panic!("source readback follows DMB");
    };
    bus.device_mut::<Captured>(id).unwrap().fail_after_read = Some(address);
    let outcome = route(action, &mut ram, &mut bus, &mut access);
    assert!(matches!(
        outcome,
        Outcome::Uncertain(MmioError::Unsupported {
            reason: "after committed read side effect",
            ..
        })
    ));
    assert!(matches!(
        install.finish(&next, outcome),
        Err(FinishError::Uncertain(_))
    ));
    assert_eq!(install.blockage(), Some(Blockage::Uncertain(action)));
    assert!(matches!(install.begin(), Err(Error::Blocked)));
    assert_eq!(bus.device_mut::<Captured>(id).unwrap().reads[&address], 1);
    assert!(!install.published());
}

#[test]
fn bad_activation_readback_preserves_images_and_never_sets_completion_history() {
    let mut install = install(ProgramKind::LatePeripheral, 10);
    let (mut bus, id) = bus(&install);
    bus.device_mut::<Captured>(id)
        .unwrap()
        .words
        .insert(0x23d054008, 0x42);
    let mut ram = Ram::new(NUB_BASE, 0x40000);
    let mut sink = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut sink);
    loop {
        let claim = install.begin().unwrap().unwrap();
        let action = install.dispatch(&claim).unwrap();
        let result = install.finish(&claim, route(action, &mut ram, &mut bus, &mut access));
        if matches!(
            action,
            Action::Read {
                address: 0x23d054008,
                ..
            }
        ) {
            assert_eq!(
                result,
                Err(FinishError::Readback {
                    address: 0x23d054008,
                    expected: 0,
                    actual: 0x42
                })
            );
            break;
        }
        result.unwrap();
    }
    assert!(!install.published());
    assert_eq!(install.history().activation[1], Some(0));
    assert!(matches!(install.begin(), Err(Error::Blocked)));
    let bank = bus.device_mut::<Captured>(id).unwrap();
    assert!(!bank.writes.contains_key(&0x23d054008));
    for placement in install.placements() {
        let mut data = [0; 8];
        assert!(ram.read(placement.code, &mut data));
        assert_eq!(data[0], 0x44);
        assert_eq!(
            u64::from_le_bytes(
                ram.bytes
                    [(placement.table - NUB_BASE) as usize + usize::from(placement.slot) * 8..]
                    [..8]
                    .try_into()
                    .unwrap()
            ),
            placement.code >> 4
        );
    }
}
#[test]
fn claims_cancellation_pause_and_wrong_kind_results_preserve_ownership() {
    let mut a = install(ProgramKind::EarlyCpu, 5);
    let mut b = install(ProgramKind::EarlyCpu, 5);
    let old = a.begin().unwrap().unwrap();
    assert!(matches!(a.begin(), Err(Error::InFlight)));
    assert_eq!(
        a.finish::<()>(&old, Outcome::Written),
        Err(FinishError::Ownership(
            Error::NotDispatched,
            Outcome::Written
        ))
    );
    a.cancel(&old).unwrap();
    let new = a.begin().unwrap().unwrap();
    assert_eq!(a.cancel(&old), Err(Error::StaleClaim));
    a.set_suspended(true);
    assert_eq!(a.dispatch(&new), Err(Error::Suspended));
    a.set_suspended(false);
    a.dispatch(&new).unwrap();
    assert_eq!(a.cancel(&new), Err(Error::AlreadyDispatched));
    assert_eq!(a.dispatch(&new), Err(Error::AlreadyDispatched));
    let other = b.begin().unwrap().unwrap();
    assert_eq!(
        b.finish::<()>(&new, Outcome::Written),
        Err(FinishError::Ownership(Error::StaleClaim, Outcome::Written))
    );
    b.cancel(&other).unwrap();
    a.set_suspended(true);
    a.finish::<()>(&new, Outcome::Written).unwrap();
    assert!(matches!(a.begin(), Err(Error::Suspended)));
    a.set_suspended(false);
    let next = a.begin().unwrap().unwrap();
    let action = a.dispatch(&next).unwrap();
    assert_eq!(
        a.finish::<()>(&next, Outcome::Read(0)),
        Err(FinishError::WrongResult(Outcome::Read(0)))
    );
    assert_eq!(a.blockage(), Some(Blockage::WrongResult(action)));
    assert!(matches!(a.begin(), Err(Error::Blocked)));
}
#[test]
fn missing_unknown_duplicate_geometry_and_history_inputs_never_guess() {
    let kind = ProgramKind::EarlyPeripheral;
    let mut input = inputs(kind, 5);
    input.pool = None;
    assert!(matches!(
        Installation::new(input, images(kind)),
        Err(Error::UnknownPool)
    ));
    let mut input = inputs(kind, 2);
    input.history = History::default();
    assert!(matches!(
        Installation::new(input, images(kind)),
        Err(Error::UnknownHistory)
    ));
    let mut input = inputs(kind, 2);
    input.history.setup[1] = Some(1);
    assert!(matches!(
        Installation::new(input, images(kind)),
        Err(Error::AlreadyConfigured)
    ));
    let mut image = images(kind);
    image.remove(0);
    assert!(matches!(
        Installation::new(inputs(kind, 5), image),
        Err(Error::MissingImage(1))
    ));
    let mut image = images(kind);
    image.push(NativeImage {
        sequence: 1,
        counted_words: 0,
        bytes: vec![0; 4],
    });
    assert!(matches!(
        Installation::new(inputs(kind, 5), image),
        Err(Error::DuplicateImage(1))
    ));
    let mut image = images(kind);
    image[0].counted_words = 0;
    assert!(matches!(
        Installation::new(inputs(kind, 5), image),
        Err(Error::ImageGeometry(1))
    ));
    let mut image = images(kind);
    image[0].bytes[4] = 1;
    assert!(matches!(
        Installation::new(inputs(kind, 5), image),
        Err(Error::ImageGeometry(1))
    ));
    let mut input = inputs(kind, 5);
    input.chip = 0x8110;
    assert!(matches!(
        Installation::new(input, images(kind)),
        Err(Error::UnqualifiedChip)
    ));
    let mut input = inputs(kind, 5);
    input.revision = 2;
    assert!(matches!(
        Installation::new(input, images(kind)),
        Err(Error::UnqualifiedRevision)
    ));
    assert_eq!(
        NubPool::from_metadata(Metadata {
            first_page: 0xff,
            pages: 1
        }),
        Err(Error::PoolGeometry)
    );
    let pool = NubPool::from_metadata(Metadata {
        first_page: 2,
        pages: 0x10002e,
    })
    .unwrap();
    // Native W-shift wraps the high bits; it does not widen them.
    assert_eq!(pool.tables(), [0x23df30000, 0x23df30100]);
    assert_eq!(pool.code_start(), 0x23df30200);
}
#[test]
#[cfg(feature = "std")]
#[ignore = "oracle: STELA_TEST_PMGR_LLB"]
fn original_llb_matches_every_installed_group_slot_and_dmb_boundary() {
    use sha2::{Digest, Sha256};
    let bytes =
        std::fs::read(std::env::var("STELA_TEST_PMGR_LLB").expect("pinned original LLB path"))
            .unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        "d6c695d26e5d816a2ecd523c0be20a15307af24c404b1603d74a970b53e75e77"
    );
    let word = |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let quad = |offset: usize| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    assert_eq!(word(0x4ac), 0xd5033fbf); // helper is DMB SY
    assert_eq!(word(0x4b0), 0xd65f03c0);
    let branch = word(0x26634);
    let displacement = ((branch << 6) as i32 >> 4) as isize;
    assert_eq!(0x26634usize.wrapping_add_signed(displacement), 0x4ac);
    for (raw_kind, kind) in [
        (0, ProgramKind::EarlyCpu),
        (1, ProgramKind::EarlyPeripheral),
        (3, ProgramKind::LateCpu),
        (4, ProgramKind::LatePeripheral),
    ] {
        let start = (quad(0x160198 + raw_kind * 8) - 0x1fc050000) as usize;
        let end = (quad(0x160170 + raw_kind * 8) - 0x1fc050000) as usize;
        let descriptors: Vec<_> = (start..end)
            .step_by(64)
            .map(|offset| (word(offset), word(offset + 4), word(offset + 40)))
            .collect();
        // These minimal supplied images are construction fixtures, never
        // evidence that original source bodies emit or execute empty work.
        let images = descriptors
            .iter()
            .map(|(id, _, _)| NativeImage {
                sequence: *id as u8,
                counted_words: 0,
                bytes: vec![0; 4],
            })
            .collect();
        let mut installation = Installation::new(inputs(kind, 5), images).unwrap();
        for (placement, (id, group, slot)) in installation.placements().iter().zip(&descriptors) {
            assert_eq!(
                (
                    u32::from(placement.sequence),
                    u32::from(placement.group),
                    u32::from(placement.slot)
                ),
                (*id, *group, *slot)
            );
        }
        assert_eq!(installation.placements().len(), descriptors.len());
        let group_start = (quad(0x1601e8 + raw_kind * 8) - 0x1fc050000) as usize;
        assert_eq!(word(0x1a30a0 + raw_kind * 4), 2);
        if matches!(kind, ProgramKind::EarlyCpu | ProgramKind::LateCpu) {
            for index in 0..2 {
                let descriptor = group_start + index * 64;
                let table = quad(descriptor + 24);
                let (address, value) = match word(descriptor) {
                    0 => (0x23d2d0200, table & 0x3ff00),
                    3 => (0x23b78d000, (table >> 8) & 0xfffffff),
                    other => panic!("unexpected original CPU group {other}"),
                };
                let claim = installation.begin().unwrap().unwrap();
                assert!(
                    matches!(installation.dispatch(&claim), Ok(Action::Write(write)) if write.address == address && write.width == Width::Word && write.value == value)
                );
                installation.finish::<()>(&claim, Outcome::Written).unwrap();
            }
        }
    }
}
