//! Stateful F12 packet-register windows and exact input/IRQ effects.
use super::*;

pub(super) fn install_f12(h: &Rc<RefCell<Hardware>>, page: u16) {
    let base = page << 8;
    let mut h = h.borrow_mut();
    h.memory[usize::from(base + 0xe9)..usize::from(base + 0xef)]
        .copy_from_slice(&[0x10, 0x30, 0x40, 0x80, 2, 0x12]);
    for (address, bytes) in [
        (base + 0x10, vec![9]),
        (base + 0x11, vec![2]),
        (base + 0x12, vec![1, 0]),
        (base + 0x13, vec![0]),
        (base + 0x14, vec![4]),
        (base + 0x15, vec![4, 0, 1, 0x10]),
        (base + 0x16, vec![4, 1, 1, 0]),
        (base + 0x17, vec![2]),
        (base + 0x18, vec![4, 0x22]),
        (base + 0x19, vec![16, 3, 2, 1]),
        (base + 0x40, vec![0xff, 0x0f, 0xff, 7]),
        (base + 0x41, vec![0xa0]),
        (
            base + 0x80,
            vec![
                1, 0x23, 1, 0x56, 4, 80, 4, 5, 3, 0xe8, 3, 0xd0, 7, 99, 7, 8, 0xaa, 0xbb,
            ],
        ),
    ] {
        h.windows.insert((address, bytes.len()), bytes);
    }
}

#[test]
fn f12_configures_real_descriptors_control_and_irq_before_contact_publication() {
    let h = hardware();
    install_f12(&h, 1);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    assert_eq!(h.borrow().memory[0x41], 1);
    d.initialize_f12(Some(true)).unwrap();
    assert_eq!(h.borrow().memory[0x41], 5); // F12abs on, relative/unknown F11 off
    assert_eq!(h.borrow().windows[&(0x141, 1)], [0xa4]);
    let capability = d.f12_capabilities().next().unwrap();
    assert_eq!(capability.maximum, Some((4095, 2047)));
    assert_eq!(capability.objects, 2);
    assert_eq!(capability.data.packet_offset(5).unwrap(), Some(16));
    assert_eq!(d.poll_f12().frames.len(), 0);
    h.borrow_mut().memory[0x81] = 4;
    let reads = h.borrow().reads;
    assert_eq!(d.poll_control(), Err(Error::InputConsumerActive));
    assert_eq!(h.borrow().reads, reads);
    let poll = d.poll_f12();
    assert_eq!(poll.error, None);
    assert_eq!(poll.frames.len(), 1);
    assert_eq!(poll.control.unwrap().interrupts, [4]);
    let frame = &poll.frames[0];
    assert_eq!(frame.contacts.len(), 2);
    assert_eq!(
        frame.contacts[0],
        f12::Contact {
            object_index: 0,
            object_type: 1,
            x: 0x123,
            y: 0x456,
            pressure: 80,
            width_x: 4,
            width_y: 5
        }
    );
    assert_eq!(frame.contacts[1].object_type, 3);
    assert_eq!(&frame.raw_packet[16..], &[0xaa, 0xbb]);
    h.borrow_mut().windows.get_mut(&(0x180, 18)).unwrap()[0] = 0;
    h.borrow_mut().memory[0x81] = 4;
    assert_eq!(d.poll_f12().frames[0].contacts[0].object_type, 0);
}

#[test]
fn f12_invalid_descriptor_or_tuning_never_enables_function_interrupt() {
    for invalid in 0..3 {
        let h = hardware();
        install_f12(&h, 1);
        let mut d = control_device(&h);
        d.initialize_control().unwrap();
        match invalid {
            0 => {
                h.borrow_mut().windows.insert((0x110, 1), vec![0]);
            }
            1 => {
                h.borrow_mut().windows.insert((0x119, 4), vec![8, 3, 2, 1]);
            } //2objects require16actualbytes
            _ => {
                h.borrow_mut().windows.insert((0x116, 4), vec![3, 1, 1, 0]);
            } //maxXY subpacket lacks fourthbyte
        }
        assert_eq!(d.initialize_f12(None), Err(Error::RegisterDescriptor));
        assert_eq!(h.borrow().memory[0x41], 1);
        assert_eq!(d.control_state(), ControlState::Uncertain);
        assert_eq!(d.f12_capabilities().count(), 0);
    }
}

#[test]
fn f12_late_second_function_failure_retains_first_complete_frame_and_irq_status() {
    let h = hardware();
    install_f12(&h, 1);
    install_f12(&h, 2);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f12(None).unwrap();
    let read = h.borrow().reads + 4;
    h.borrow_mut().fail_read_number = Some(read);
    h.borrow_mut().memory[0x81] = 0x14;
    let poll = d.poll_f12();
    assert!(matches!(poll.error, Some(Error::I2c(_))));
    assert_eq!(poll.frames.len(), 1);
    assert_eq!(poll.frames[0].function.data, 0x180);
    assert_eq!(poll.control.unwrap().interrupts, [0x14]);
    assert_eq!(d.control_state(), ControlState::Uncertain);
    assert_eq!(d.poll_f12().error, Some(Error::NeedsReset));
}

#[test]
fn f12_dribble_subpacket_selection_and_query_resolution_use_real_register_windows() {
    let h = hardware();
    install_f12(&h, 1);
    h.borrow_mut().windows.insert((0x116, 4), vec![4, 1, 3, 1]);
    h.borrow_mut()
        .windows
        .insert((0x141, 3), vec![0x99, 0xa0, 0x5a]);
    // Query0..29 are present, so the resolution selector is29, not the sum
    // of unrelated control/data byte lengths.
    h.borrow_mut().windows.insert((0x111, 1), vec![5]);
    h.borrow_mut()
        .windows
        .insert((0x112, 5), vec![60, 0xff, 0xff, 0xff, 0x3f]);
    h.borrow_mut()
        .windows
        .insert((0x113, 60), [1, 1].repeat(30));
    h.borrow_mut().windows.insert((0x12d, 1), vec![10]);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f12(Some(true)).unwrap();
    assert_eq!(h.borrow().windows[&(0x141, 3)], [0x99, 0xa4, 0x5a]);
    assert_eq!(
        d.f12_capabilities().next().unwrap().dimensions_mm,
        (Some(409), Some(204))
    );
}

#[test]
fn f12_smbus_multiblock_reports_preserve_all_ten_contacts_and_auxiliary_bytes() {
    let h = hardware();
    install_f12(&h, 1);
    let mut packet = Vec::new();
    for index in 0..10u8 {
        packet.extend_from_slice(&[index, index, 1, index, 2, 90, 6, 7]);
    }
    packet.extend_from_slice(&[0xaa, 0xbb]);
    {
        let mut h = h.borrow_mut();
        h.require_mask = true;
        h.windows.insert((0x118, 2), vec![5, 0x22]);
        h.windows.insert((0x119, 5), vec![80, 0xff, 7, 2, 1]);
        h.windows.remove(&(0x180, 18));
        h.memory[0x180..0x180 + packet.len()].copy_from_slice(&packet);
    }
    let mut d = Device::new(
        smb_transport(&h),
        Attn(h.clone()),
        Time(h.borrow().time.clone()),
        Configuration::default(),
    )
    .unwrap();
    d.initialize_control().unwrap();
    d.initialize_f12(None).unwrap();
    h.borrow_mut().memory[0x81] = 4;
    let poll = d.poll_f12();
    assert_eq!(poll.error, None);
    let frame = &poll.frames[0];
    assert_eq!(frame.raw_packet, packet);
    assert_eq!(frame.contacts.len(), 10);
    assert_eq!(frame.contacts[9].object_type, 9);
    assert_eq!(frame.contacts[9].x, 0x109);
}

#[test]
fn f12_sleep_reinitialization_and_irq_enable_effect_errors_preserve_readiness_boundaries() {
    let h = hardware();
    install_f12(&h, 1);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    d.initialize_f12(None).unwrap();
    d.sleep().unwrap();
    h.borrow_mut().memory[0x81] = 4;
    let reads = h.borrow().reads;
    assert_eq!(d.poll_f12().error, Some(Error::NotActive));
    assert_eq!(h.borrow().reads, reads);
    d.wake().unwrap();
    assert_eq!(d.poll_f12().frames.len(), 1);
    d.stop().unwrap();
    d.initialize_control().unwrap();
    assert_eq!(d.f12_capabilities().count(), 0);
    assert_eq!(h.borrow().memory[0x41], 1);
    h.borrow_mut().fail_after_write = true;
    assert!(matches!(d.initialize_f12(None), Err(Error::I2c(_))));
    assert_eq!(h.borrow().memory[0x41], 5); // effect preceded error
    assert_eq!(d.f12_capabilities().count(), 0);
    assert_eq!(d.control_state(), ControlState::Uncertain);
    assert_eq!(d.poll_f12().error, Some(Error::NeedsReset));
}

#[test]
fn f12_refuses_transport_inaccessible_packets_before_enabling_input_irq() {
    let h = hardware();
    install_f12(&h, 1);
    h.borrow_mut().windows.insert((0x118, 2), vec![6, 0x22]);
    h.borrow_mut()
        .windows
        .insert((0x119, 6), vec![16, 3, 0, 0xff, 0xff, 1]);
    let mut d = control_device(&h);
    d.initialize_control().unwrap();
    assert_eq!(
        d.initialize_f12(None),
        Err(Error::AddressRange {
            address: 0x180,
            length: 65551
        })
    );
    assert_eq!(h.borrow().memory[0x41], 1);
    assert_eq!(d.f12_capabilities().count(), 0);
}
