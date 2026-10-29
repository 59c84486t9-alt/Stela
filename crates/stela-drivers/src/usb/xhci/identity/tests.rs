use super::*;

#[test]
fn device_identity_is_controller_specific_and_refused_before_mmio() {
    let mut first_memory = vec![0u64; 512 * 1024];
    let mut second_memory = vec![0u64; 512 * 1024];
    let (first, first_device, first_hardware, _first_dma) =
        reset::tests::fixture(&mut first_memory, HIGH_SPEED, 32, 3);
    let (second, second_device, second_hardware, _second_dma) =
        reset::tests::fixture(&mut second_memory, HIGH_SPEED, 32, 3);
    assert_eq!(first_device.slot, second_device.slot);
    assert_ne!(first_device.id, second_device.id);
    let first_accesses = first_hardware.borrow().accesses;
    let second_accesses = second_hardware.borrow().accesses;
    assert!(first.borrow_mut().device(second_device.id).is_err());
    assert!(second.borrow_mut().device(first_device.id).is_err());
    assert_eq!(first_hardware.borrow().accesses, first_accesses);
    assert_eq!(second_hardware.borrow().accesses, second_accesses);
}

#[test]
fn quarantined_identity_cannot_read_cached_configuration_or_take_another_claim() {
    let mut memory = vec![0u64; 512 * 1024];
    let (controller, device, hardware, _dma) =
        reset::tests::fixture(&mut memory, HIGH_SPEED, 64, 3);
    controller.borrow_mut().claim_native(device.id).unwrap();
    assert!(controller.borrow_mut().claim_native(device.id).is_err());
    assert!(controller.borrow_mut().claim_forwarding(device.id).is_err());
    controller.borrow_mut().quarantine_slot(device.slot);
    let accesses = hardware.borrow().accesses;
    assert!(controller.borrow_mut().device(device.id).is_err());
    assert_eq!(hardware.borrow().accesses, accesses);
}

fn trapped(controller: &Shared, operation: impl FnOnce()) {
    struct NoAccess;
    impl Registers for NoAccess {
        fn read32(&mut self, _: usize) -> u32 {
            panic!("retired USB Ethernet consumer reached MMIO read")
        }
        fn write32(&mut self, _: usize, _: u32) {
            panic!("retired USB Ethernet consumer reached MMIO write")
        }
    }
    let pending = |c: &Controller| {
        c.pending
            .iter()
            .map(|e| (e.parameter, e.status, e.control))
            .collect::<Vec<_>>()
    };
    let queues = |c: &Controller| {
        c.slots
            .iter()
            .flat_map(|slot| slot.iter())
            .flat_map(|slot| {
                slot.endpoints
                    .iter()
                    .flatten()
                    .map(|ep| (ep.ring.index, ep.ring.cycle, ep.in_flight))
            })
            .collect::<Vec<_>>()
    };
    let mut c = controller.borrow_mut();
    let before_pending = pending(&c);
    let before_cursor = (c.event_index, c.event_cycle);
    let before_queues = queues(&c);
    let registers = core::mem::replace(&mut c.registers, Box::new(NoAccess));
    drop(c);
    operation();
    let mut c = controller.borrow_mut();
    assert_eq!(pending(&c), before_pending);
    assert_eq!((c.event_index, c.event_cycle), before_cursor);
    assert_eq!(queues(&c), before_queues);
    c.registers = registers;
}

fn network_generation_peer(vendor: bool) {
    use crate::bus::dma::RegionAllocator;
    use crate::usb::{
        cdc::tests::generation as cdc_peer, ethernet::tests::generation as vendor_peer,
    };
    for already_pending in [false, true] {
        let mut backing = vec![0u64; 512 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: every modeled DMA buffer remains inside this live allocation.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let configuration = if vendor { 7 } else { 42 };
        let (previous, old_hardware) =
            model::unconfigured_cancellation_controller_with_configurations(
                &mut dma,
                &[vec![9, 2, 9, 0, 0, configuration, 0, 0x80, 50]],
            );
        let (current, new_hardware) = model::cancellation_controller(&mut dma);
        let previous = Rc::new(RefCell::new(previous));
        let current = Rc::new(RefCell::new(current));
        let old_id = previous.borrow().device_id(1).unwrap();
        let fresh_id = current.borrow().device_id(1).unwrap();
        assert_eq!(old_id.hardware_slot(), fresh_id.hardware_slot());
        assert_ne!(old_id, fresh_id);
        let mut mac = vec![26, STRING_DESCRIPTOR];
        for unit in "025354000001".encode_utf16() {
            mac.extend_from_slice(&unit.to_le_bytes());
        }
        old_hardware.borrow_mut().descriptors = vec![(STRING_DESCRIPTOR, 1, mac)];
        old_hardware.borrow_mut().ethernet =
            vendor.then(|| ethernet::rtl815x::tests::Model::new(0x4c00));
        let mut cdc = (!vendor).then(|| cdc_peer::peer(previous.clone(), &mut dma));
        let mut ethernet = vendor.then(|| vendor_peer::peer(previous.clone(), &mut dma));
        if let Some(peer) = &mut cdc {
            old_hardware.borrow_mut().push_event(vec![
                DEVICE_TO_HOST | TYPE_CLASS | RECIPIENT_INTERFACE,
                0,
                1,
                0,
                0,
                0,
                0,
                0,
            ]);
            cdc_peer::queue(peer);
        }
        if let Some(peer) = &mut ethernet {
            vendor_peer::queue(peer);
        }
        assert!(old_hardware.borrow().active[3].is_some());
        if !vendor {
            assert!(old_hardware.borrow().active[5].is_some());
        }
        // Execute Stop/Set Dequeue and matching Disable Slot completion;
        // no invented software retirement or new-generation ID is installed.
        previous
            .borrow_mut()
            .disable_slot(1, reset::Ownership::Retired)
            .unwrap();
        assert!(old_hardware.borrow().active.iter().all(Option::is_none));
        assert_eq!(
            old_hardware.borrow().seen.last(),
            Some(&reset::DISABLE_SLOT)
        );
        assert_eq!(
            previous.borrow().slot_ownership[1],
            reset::Ownership::Retired
        );
        assert_eq!(previous.borrow().dcbaa.read::<u64>(8), 0);
        for dci in [1, 3, 4] {
            assert!(old_hardware.borrow().seen.contains(&STOP_ENDPOINT));
            assert_eq!(old_hardware.borrow().state(dci), ENDPOINT_STOPPED);
        }
        if !vendor {
            assert_eq!(old_hardware.borrow().state(5), ENDPOINT_STOPPED);
        }
        let before = backing.clone();
        trapped(&previous, || {
            if let Some(peer) = &mut cdc {
                cdc_peer::refuse(peer, &previous);
            }
            if let Some(peer) = &mut ethernet {
                vendor_peer::refuse(peer, &previous);
            }
            let mut host = previous.borrow_mut();
            let mut access = DeviceAccess {
                controller: &mut host,
                id: old_id,
            };
            assert_eq!(access.string(LANGUAGE_EN_US, 1), None);
        });
        assert!(backing == before);

        let mut data = dma.allocate(128, 64).unwrap();
        data.bytes_mut().fill(0xa5);
        let fresh = current
            .borrow_mut()
            .device(fresh_id)
            .unwrap()
            .submit_ticket(5, data.physical(), 64)
            .unwrap();
        new_hardware.borrow_mut().push_acl(vec![0x6a; 64]);
        new_hardware.borrow_mut().receive(5);
        if already_pending {
            current.borrow_mut().drain();
        }
        assert_eq!(current.borrow().pending.len(), usize::from(already_pending));
        let before = backing.clone();
        trapped(&current, || {
            if let Some(peer) = &mut cdc {
                cdc_peer::refuse(peer, &current);
            }
            if let Some(peer) = &mut ethernet {
                vendor_peer::refuse(peer, &current);
            }
            let mut host = current.borrow_mut();
            assert!(host.device(old_id).is_err());
            let mut access = DeviceAccess {
                controller: &mut host,
                id: old_id,
            };
            assert_eq!(access.string(LANGUAGE_EN_US, 1), None);
        });
        assert!(backing == before);
        assert_eq!(
            current
                .borrow_mut()
                .device(fresh_id)
                .unwrap()
                .completed_ticket(&fresh),
            Some(Ok(64))
        );
        assert_eq!(&data.bytes()[..64], &[0x6a; 64]);
        assert_eq!(&data.bytes()[64..], &[0xa5; 64]);
        // This exercises kept consumer admission across real retirement
        // and distinct controller generations. Hardware-slot reuse stays
        // disabled and is not established by this fixture.
    }
}

#[test]
fn retained_cdc_generation_refuses_before_mmio_and_preserves_current_completion() {
    network_generation_peer(false);
}

#[test]
fn retained_vendor_ethernet_generation_refuses_before_mmio_and_preserves_current_completion() {
    network_generation_peer(true);
}

fn media_generation_peer(kind: u8) {
    use crate::bus::dma::RegionAllocator;
    use crate::usb::{
        audio::generation_tests as audio_peer,
        bluetooth::{ath3k::generation_tests as ath3k_peer, generation_tests as bluetooth_peer},
    };
    for already_pending in [false, true] {
        let mut backing = vec![0u64; 512 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: all native owners/DMAs remain inside this live allocation.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let configuration = match kind {
            0 => audio_peer::configuration(),
            1 | 3 | 4 => bluetooth_peer::configuration(),
            _ => ath3k_peer::configuration(),
        };
        let (previous, hardware) = model::high_speed_media_controller(&mut dma, &configuration);
        let previous = Rc::new(RefCell::new(previous));
        let old_id = previous.borrow().device_id(1).unwrap();
        let mut audio = (kind == 0).then(|| audio_peer::peer(previous.clone(), &mut dma));
        let mut bluetooth = (kind == 1).then(|| bluetooth_peer::peer(previous.clone(), &mut dma));
        let mut ath3k = (kind == 2).then(|| ath3k_peer::peer(previous.clone(), &mut dma));
        let mut session =
            (kind == 3).then(|| bluetooth_peer::session_peer(previous.clone(), &mut dma));
        let mut cached_hci =
            (kind == 4).then(|| bluetooth_peer::cached_peer(previous.clone(), &mut dma));
        if kind != 2 {
            assert!(hardware.borrow().active.iter().any(Option::is_some));
        }
        previous
            .borrow_mut()
            .disable_slot(1, reset::Ownership::Retired)
            .unwrap();
        assert!(hardware.borrow().active.iter().all(Option::is_none));
        assert_eq!(hardware.borrow().seen.last(), Some(&reset::DISABLE_SLOT));
        assert_eq!(
            previous.borrow().slot_ownership[1],
            reset::Ownership::Retired
        );
        assert_eq!(previous.borrow().dcbaa.read::<u64>(8), 0);
        let before = backing.clone();
        let before_remaining = dma.remaining();
        trapped(&previous, || {
            if let Some(peer) = &mut audio {
                audio_peer::refuse(peer, &previous);
            }
            if let Some(peer) = &mut bluetooth {
                bluetooth_peer::refuse(peer, &previous);
            }
            if let Some(peer) = &mut ath3k {
                ath3k_peer::refuse(peer, &previous);
            }
            if let Some(peer) = &mut session {
                bluetooth_peer::session_refuse(peer, &previous);
            }
            if let Some(peer) = &mut cached_hci {
                bluetooth_peer::cached_refuse(peer, &previous);
            }
        });
        assert_eq!(dma.remaining(), before_remaining);
        assert_eq!(backing, before);

        // A second addressed controller independently mints the same
        // hardware slot number; no old identity or publication fence is reset.
        let (current, current_hardware) = model::cancellation_controller(&mut dma);
        let current = Rc::new(RefCell::new(current));
        let current_id = current.borrow().device_id(1).unwrap();
        assert_eq!(current_id.hardware_slot(), old_id.hardware_slot());
        assert_ne!(current_id, old_id);
        let mut data = dma.allocate(128, 64).unwrap();
        data.bytes_mut().fill(0xa5);
        let ticket = current
            .borrow_mut()
            .device(current_id)
            .unwrap()
            .submit_ticket(5, data.physical(), 64)
            .unwrap();
        current_hardware.borrow_mut().push_acl(vec![0x6a; 64]);
        current_hardware.borrow_mut().receive(5);
        if already_pending {
            current.borrow_mut().drain();
        }
        assert_eq!(current.borrow().pending.len(), usize::from(already_pending));
        let before = backing.clone();
        let before_remaining = dma.remaining();
        trapped(&current, || {
            if let Some(peer) = &mut audio {
                audio_peer::refuse(peer, &current);
            }
            if let Some(peer) = &mut bluetooth {
                bluetooth_peer::refuse(peer, &current);
            }
            if let Some(peer) = &mut ath3k {
                ath3k_peer::refuse(peer, &current);
            }
            if let Some(peer) = &mut session {
                bluetooth_peer::session_refuse(peer, &current);
            }
            if let Some(peer) = &mut cached_hci {
                bluetooth_peer::cached_refuse(peer, &current);
            }
        });
        assert_eq!(dma.remaining(), before_remaining);
        assert_eq!(backing, before);
        assert_eq!(
            current
                .borrow_mut()
                .device(current_id)
                .unwrap()
                .completed_ticket(&ticket),
            Some(Ok(64))
        );
        assert_eq!(&data.bytes()[..64], &[0x6a; 64]);
        assert_eq!(&data.bytes()[64..], &[0xa5; 64]);
        // This verifies native admission across retirement and distinct
        // addressed generations. Published hardware-slot reuse stays closed.
    }
}

#[test]
fn retained_uac2_generation_refuses_before_mmio_and_preserves_current_completion() {
    media_generation_peer(0);
}

#[test]
fn retained_mt7925_media_generation_refuses_before_mmio_and_preserves_current_completion() {
    media_generation_peer(1);
}
#[test]
fn retained_hci_generation_refuses_cached_partial_timeout_and_close_before_mmio_and_preserves_current_completion()
 {
    media_generation_peer(4);
}

#[test]
fn retained_mt7925_session_generation_refuses_cached_state_before_mmio_and_preserves_current_completion()
 {
    media_generation_peer(3);
}

#[test]
fn retained_ath3k_initializer_generation_refuses_before_mmio_and_preserves_current_completion() {
    media_generation_peer(2);
}

pub(in crate::usb::xhci) mod raw;
