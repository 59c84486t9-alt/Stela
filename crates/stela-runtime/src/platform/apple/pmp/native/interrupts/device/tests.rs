use super::super::{Completion, Event, Handler, Outcome, Owner, Signals, SoftwareConfiguration};
use super::*;
use alloc::{boxed::Box, vec};
use core::cell::Cell;
use stela_contracts::interrupt::InterruptLatch;

// Authored NEW profile, not a production/reset default.
fn configuration(count: u32) -> Configuration {
    let groups = (count as usize).div_ceil(32);
    let mut masks = vec![u32::MAX; groups];
    if count & 31 != 0 {
        masks[groups - 1] = (1u32 << (count & 31)) - 1;
    }
    Configuration {
        relocation: 0x8000,
        source_count: count,
        control: 0,
        masks,
        targets: vec![1; count as usize],
        software_pending: vec![0; groups],
        arbitration: Arbitration::RefuseAmbiguous,
    }
}
fn read(view: &mut DeviceView, offset: u64, a: &mut Access<'_>) -> u32 {
    Device::read(view, offset, a).unwrap()
}
fn write(view: &mut DeviceView, offset: u64, value: u32, a: &mut Access<'_>) {
    Device::write(view, offset, value, a).unwrap();
}

#[test]
fn explicit_new_geometry_refuses_unknown_fields_and_preserves_source_widths() {
    let mut c = configuration(33);
    c.masks[1] = 2;
    assert!(Controller::new_software(c).is_err());
    c = configuration(33);
    c.targets.pop();
    assert!(Controller::new_software(c).is_err());
    c = configuration(33);
    c.software_pending.clear();
    assert!(Controller::new_software(c).is_err());
    c = configuration(1);
    c.control = 0x10000001;
    assert!(Controller::new_software(c).is_err());
    c = configuration(1);
    c.targets[0] = 0;
    assert!(Controller::new_software(c).is_err());
    c = configuration(1025);
    assert!(Controller::new_software(c).is_err());
    c = configuration(1);
    c.relocation = u64::MAX;
    assert!(Controller::new_software(c).is_err());
    c = configuration(1);
    c.relocation = 1;
    assert!(Controller::new_software(c).is_err());
    let empty = Controller::new_software(configuration(0)).unwrap();
    assert_eq!(empty.snapshot().unwrap().source_count, 0);
    assert!(empty.snapshot().unwrap().inputs.is_empty());
}

#[test]
fn same_storage_views_apply_mask_pairs_and_real_level_claim_without_clearing_input() {
    let controller = Controller::new_software(configuration(65)).unwrap();
    let mut a_view = controller.device();
    let mut b_view = controller.device();
    let mut route = controller.route();
    assert!(
        controller.same_device(&a_view)
            && controller.same_device(&b_view)
            && controller.same_route(&route)
    );
    let owner = Rc::new(Cell::new(false));
    let producer = ProducerIdentity::for_owner(&owner);
    let mut line = controller.bind_source(64, &producer, owner.get()).unwrap();
    let mut latch = InterruptLatch::new();
    let mut a = Access::new(0, 1, &mut latch);
    write(&mut a_view, 0x14, 1, &mut a);
    write(&mut b_view, 0x6608, 1, &mut a);
    assert!(!route.irq_pending(&mut a).unwrap()); // Enabling created no input.
    assert_eq!(read(&mut a_view, 0x6408, &mut a), 0);
    assert_eq!(read(&mut b_view, 0x6608, &mut a), 0);
    owner.set(true);
    line.set_level(&producer, owner.get()).unwrap();
    assert!(Device::irq_pending(&mut a_view, &mut a).unwrap());
    assert_eq!(read(&mut b_view, 0xc000, &mut a), 0x10040);
    assert_eq!(read(&mut a_view, 0x6408, &mut a), 1); // Claim masked source.
    assert!(!route.irq_pending(&mut a).unwrap());
    assert_eq!(
        controller.snapshot().unwrap().inputs[64].last_level,
        Some(true)
    );
    write(&mut a_view, 0x6208, 1, &mut a); // Does not clear electrical level.
    write(&mut b_view, 0x6608, 1, &mut a);
    assert!(route.irq_pending(&mut a).unwrap());
    owner.set(false);
    line.set_level(&producer, owner.get()).unwrap();
    assert!(!route.irq_pending(&mut a).unwrap());
    assert_eq!(read(&mut a_view, 0xc000, &mut a), 0); // Known-empty, no unknown inputs.
    Route::order(&mut route, &mut a).unwrap();
    let snapshot = controller.snapshot().unwrap();
    assert_eq!(snapshot.applied_sequence, snapshot.ordered_sequence);
}

#[test]
fn software_pending_is_owned_mmio_state_orred_with_hardware_and_clear_does_not_deassert() {
    let controller = Controller::new_software(configuration(1)).unwrap();
    let mut view = controller.device();
    let owner = Rc::new(Cell::new(false));
    let producer = ProducerIdentity::for_owner(&owner);
    let mut line = controller.bind_source(0, &producer, false).unwrap();
    let mut latch = InterruptLatch::new();
    let mut a = Access::new(0, 2, &mut latch);
    write(&mut view, 0x14, 1, &mut a);
    write(&mut view, 0x6600, 1, &mut a);
    write(&mut view, 0x6000, 1, &mut a);
    assert_eq!(read(&mut view, 0x6200, &mut a), 1);
    assert!(Device::irq_pending(&mut view, &mut a).unwrap());
    assert_eq!(read(&mut view, 0xc000, &mut a), 0x10000);
    assert_eq!(read(&mut view, 0x6000, &mut a), 1); // Claim is not SW clear.
    owner.set(true);
    line.set_level(&producer, owner.get()).unwrap();
    write(&mut view, 0x6200, 1, &mut a);
    write(&mut view, 0x6600, 1, &mut a);
    assert_eq!(read(&mut view, 0x6000, &mut a), 0);
    assert!(Device::irq_pending(&mut view, &mut a).unwrap());
    owner.set(false);
    line.set_level(&producer, owner.get()).unwrap();
    assert!(!Device::irq_pending(&mut view, &mut a).unwrap());
}

#[test]
fn absent_foreign_abandoned_and_dropped_line_owners_cannot_become_zero_inputs() {
    let controller = Controller::new_software(configuration(2)).unwrap();
    let mut view = controller.device();
    let mut latch = InterruptLatch::new();
    let mut a = Access::new(0, 3, &mut latch);
    let before = controller.snapshot().unwrap();
    assert!(Device::write(&mut view, 0x6600, 1, &mut a).is_err());
    assert_eq!(controller.snapshot().unwrap(), before);
    let actual = Rc::new(Cell::new(false));
    let producer = ProducerIdentity::for_owner(&actual);
    let other = Rc::new(Cell::new(false));
    let foreign = ProducerIdentity::for_owner(&other);
    let mut line = controller.bind_source(0, &producer, false).unwrap();
    assert!(line.set_level(&foreign, true).is_err());
    assert_eq!(
        controller.snapshot().unwrap().inputs[0].last_level,
        Some(false)
    );
    assert!(controller.bind_source(0, &producer, false).is_err());
    write(&mut view, 0x14, 1, &mut a);
    write(&mut view, 0x6600, 1, &mut a);
    drop(actual);
    assert!(Device::irq_pending(&mut view, &mut a).is_err());
    assert!(line.set_level(&producer, false).is_err());
    write(&mut view, 0x6400, 1, &mut a); // A real mask still gates an unknown input.
    assert!(!Device::irq_pending(&mut view, &mut a).unwrap());
    assert!(Device::write(&mut view, 0x6600, 1, &mut a).is_err());
    let mut line2 = controller.bind_source(1, &foreign, true).unwrap();
    write(&mut view, 0x6600, 2, &mut a);
    line2.set_level(&foreign, false).unwrap();
    drop(line2);
    assert!(Device::irq_pending(&mut view, &mut a).is_err());
    assert!(!controller.snapshot().unwrap().inputs[1].line_alive);
    drop(view);
    drop(controller);
    assert!(line.set_level(&producer, true).is_err());
    let abandoned = Controller::new_software(configuration(1)).unwrap();
    let mut wire = abandoned.bind_source(0, &foreign, false).unwrap();
    drop(abandoned);
    assert!(matches!(
        wire.set_level(&foreign, true),
        Err(Error::Refused(
            "native hardware line controller has been abandoned"
        ))
    ));
}

#[test]
fn multiple_inputs_assert_line_but_ambiguous_claim_refuses_atomically() {
    let controller = Controller::new_software(configuration(2)).unwrap();
    let mut view = controller.device();
    let owner0 = Rc::new(Cell::new(true));
    let id0 = ProducerIdentity::for_owner(&owner0);
    let owner1 = Rc::new(Cell::new(true));
    let id1 = ProducerIdentity::for_owner(&owner1);
    let mut line0 = controller.bind_source(0, &id0, true).unwrap();
    let _line1 = controller.bind_source(1, &id1, true).unwrap();
    let mut latch = InterruptLatch::new();
    let mut a = Access::new(0, 4, &mut latch);
    write(&mut view, 0x14, 1, &mut a);
    write(&mut view, 0x6600, 3, &mut a);
    assert!(Device::irq_pending(&mut view, &mut a).unwrap());
    let before = controller.snapshot().unwrap();
    assert!(matches!(
        Device::read(&mut view, 0xc000, &mut a),
        Err(Error::Refused(
            "native IRQ priority among multiple actual pending sources is unqualified"
        ))
    ));
    assert_eq!(controller.snapshot().unwrap(), before);
    owner0.set(false);
    line0.set_level(&id0, owner0.get()).unwrap();
    assert_eq!(read(&mut view, 0xc000, &mut a), 0x10001);
}

#[test]
fn boundary_source_and_bad_width_register_bits_are_checked_before_any_effect() {
    let controller = Controller::new_software(configuration(1024)).unwrap();
    let mut view = controller.device();
    let owner = Rc::new(Cell::new(true));
    let producer = ProducerIdentity::for_owner(&owner);
    let _line = controller.bind_source(1023, &producer, true).unwrap();
    let mut latch = InterruptLatch::new();
    let mut a = Access::new(0, 5, &mut latch);
    write(&mut view, 0x14, 1, &mut a);
    write(&mut view, 0x667c, 1 << 31, &mut a);
    assert_eq!(read(&mut view, 0xc000, &mut a), 0x103ff);
    let before = controller.snapshot().unwrap();
    for offset in [0, 0x10, 0x20000, u64::MAX, 0x6401] {
        assert!(Device::write(&mut view, offset, 1, &mut a).is_err());
    }
    assert!(Device::write(&mut view, 0x2000, 0, &mut a).is_err());
    assert!(Device::write(&mut view, 0x14, 3, &mut a).is_err());
    for width in [Width::Byte, Width::Half, Width::Double] {
        assert!(MmioDevice::read(&mut view, 4, width, &mut a).is_err());
        assert!(MmioDevice::write(&mut view, 0x6400, width, 1, &mut a).is_err());
    }
    assert_eq!(controller.snapshot().unwrap(), before);
    let partial = Controller::new_software(configuration(33)).unwrap();
    let mut p = partial.device();
    let before = partial.snapshot().unwrap();
    assert!(Device::write(&mut p, 0x6404, 2, &mut a).is_err());
    assert_eq!(partial.snapshot().unwrap(), before);
}

#[test]
fn owner_initialization_signal_and_dispatch_use_the_shared_controller_resource() {
    struct Peripheral {
        level: bool,
        line: Option<HardwareLine>,
    }
    fn effect(owner: &Rc<RefCell<Peripheral>>, id: &ProducerIdentity, level: bool) {
        let mut model = owner.borrow_mut();
        model.level = level;
        let actual = model.level;
        model.line.as_mut().unwrap().set_level(id, actual).unwrap();
    }
    struct Callback {
        model: Rc<RefCell<Peripheral>>,
        id: ProducerIdentity,
        calls: Rc<Cell<u32>>,
    }
    impl Handler for Callback {
        fn call(
            &mut self,
            event: Event,
            _: &mut Signals<'_>,
            _: &mut Access<'_>,
        ) -> Completion<()> {
            assert_eq!(event.source, 64);
            self.calls.set(self.calls.get() + 1);
            effect(&self.model, &self.id, false);
            Completion::Retired {
                value: (),
                refusal: None,
            }
        }
    }
    let controller = Controller::new_software(configuration(512)).unwrap();
    let model = Rc::new(RefCell::new(Peripheral {
        level: false,
        line: None,
    }));
    let id = ProducerIdentity::for_owner(&model);
    model.borrow_mut().line = Some(controller.bind_source(64, &id, false).unwrap());
    let calls = Rc::new(Cell::new(0));
    let mut native = Owner::t8112(
        controller.placement(),
        Box::new(controller.device()),
        SoftwareConfiguration::default(),
    )
    .unwrap();
    let mut latch = InterruptLatch::new();
    let mut a = Access::new(0, 6, &mut latch);
    assert_eq!(native.initialize(&mut a), Ok(512));
    native
        .register(
            64,
            Box::new(Callback {
                model: model.clone(),
                id: id.clone(),
                calls: calls.clone(),
            }),
        )
        .unwrap();
    let signal = native.begin_signal(64, true).unwrap();
    assert_eq!(
        native.advance_signal(&signal, &mut a),
        Completion::Retired {
            value: Outcome::Signal { previous: false },
            refusal: None
        }
    );
    assert!(!controller.route().irq_pending(&mut a).unwrap());
    assert!(!model.borrow().level);
    assert_eq!(calls.get(), 0);
    effect(&model, &id, true);
    assert!(controller.route().irq_pending(&mut a).unwrap());
    native.begin_dispatch(false).unwrap();
    assert_eq!(
        native.advance_dispatch(&mut a),
        Completion::Retired {
            value: Outcome::Dispatched {
                source: 64,
                registered: true,
                more: false
            },
            refusal: None
        }
    );
    assert_eq!(calls.get(), 1);
    assert!(!model.borrow().level);
    assert_eq!(controller.snapshot().unwrap().software_pending, vec![0; 16]);
    assert_eq!(controller.snapshot().unwrap().masks[2] & 1, 0); // Reenabled only after callback effect.
}

#[test]
fn driver_keeps_unmask_prefix_until_the_real_producer_is_bound() {
    let controller = Controller::new_software(configuration(65)).unwrap();
    let mut native = Owner::t8112(
        controller.placement(),
        Box::new(controller.device()),
        SoftwareConfiguration::default(),
    )
    .unwrap();
    let mut latch = InterruptLatch::new();
    let mut a = Access::new(0, 7, &mut latch);
    native.initialize(&mut a).unwrap();
    let signal = native.begin_signal(64, true).unwrap();
    assert!(matches!(
        native.advance_signal(&signal, &mut a),
        Completion::Refused("native source requires its actual live peripheral owner and line")
    ));
    assert_eq!(controller.snapshot().unwrap().applied_sequence, 2); // control enable, then target store.
    assert_eq!(controller.snapshot().unwrap().masks[2], 1);
    let actual = Rc::new(Cell::new(false));
    let producer = ProducerIdentity::for_owner(&actual);
    let _line = controller.bind_source(64, &producer, actual.get()).unwrap();
    assert_eq!(
        native.advance_signal(&signal, &mut a),
        Completion::Retired {
            value: Outcome::Signal { previous: false },
            refusal: None
        }
    );
    assert_eq!(controller.snapshot().unwrap().applied_sequence, 3); // Only owed mask clear, no target/read replay.
    assert_eq!(controller.snapshot().unwrap().masks[2], 0);
}

#[test]
#[cfg(feature = "std")]
#[ignore = "oracle: STELA_TEST_PMP_T8112"]
fn original_selected_native_register_offsets_and_event_claim_operands_match() {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
    );
    let w =
        |va: usize| u32::from_le_bytes(bytes[va - 0xfff000..va - 0xfff000 + 4].try_into().unwrap());
    assert_eq!(w(0x10326ac), 0x12002908); // Original count read masks11bits; new profile additionally bounds event encoding.
    assert_eq!(w(0x10262a4), 0x528c000a); // SWset6000.
    assert_eq!(w(0x10261b4), 0x528c4019); // SWclear6200.
    assert_eq!(w(0x1026478), 0x528cc008); // Maskclear6600.
    assert_eq!(w(0x1026480), 0x528c8008); // Maskset6400.
    assert_eq!(w(0x10261e4), 0x92402776); // Event source low10.
    assert_eq!(w(0x10261f4), 0x12100b68); // Type bits70000.
    assert_eq!(w(0x1026248), 0xd538c108); // Native ISR_EL1, no AP AIC/PTD alias.
}
