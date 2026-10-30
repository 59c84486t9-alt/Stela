use super::*;
use crate::usb::xhci::{self, Device};
use crate::usb::xhci::{model::*, *};
use alloc::{collections::VecDeque, rc::Rc};
use core::cell::Cell;
use core::cell::RefCell;

fn device(composite: bool) -> Device {
    let first = if composite { 2 } else { 0 };
    let mut configuration = vec![
        9,
        2,
        48,
        0,
        2,
        1,
        0,
        0x80,
        50,
        9,
        4,
        first,
        0,
        3,
        0xe0,
        1,
        1,
        0,
        7,
        5,
        0x81,
        3,
        16,
        0,
        1,
        7,
        5,
        0x82,
        2,
        64,
        0,
        0,
        7,
        5,
        0x02,
        2,
        64,
        0,
        0,
        9,
        4,
        first + 1,
        0,
        0,
        0xe0,
        1,
        1,
        0,
    ];
    if composite {
        configuration.splice(
            9..9,
            [9, 4, 0, 0, 0, 0xff, 0, 0, 0, 9, 4, 1, 0, 0, 0xff, 0, 0, 0],
        );
        configuration[4] = 4;
    }
    let length = configuration.len() as u16;
    configuration[2..4].copy_from_slice(&length.to_le_bytes());
    Device {
        id: crate::usb::xhci::SlotId::fixture(1),
        vendor_ethernet_revision: None,
        vendor_ethernet_tcr: None,
        slot: 1,
        speed: xhci::FULL_SPEED,
        location: "model USB".into(),
        descriptor: [
            18,
            1,
            0,
            2,
            if composite { 0 } else { 0xe0 },
            if composite { 0 } else { 1 },
            if composite { 0 } else { 1 },
            64,
            0x34,
            0x12,
            0x78,
            0x56,
            0,
            1,
            0,
            0,
            0,
            1,
        ],
        configurations: vec![configuration.clone()],
        configuration,
        manufacturer: None,
        product: None,
        serial: None,
        language: None,
    }
}
fn binding(composite: bool) -> Binding {
    let device = device(composite);
    let interfaces = crate::usb::descriptor::interfaces(&device.configuration);
    Binding::new(
        &device,
        interfaces
            .iter()
            .find(|interface| interface.endpoints.len() == 3)
            .unwrap(),
    )
    .unwrap()
}

#[derive(Default)]
struct Model {
    control: Vec<([u8; 8], Vec<u8>)>,
    sent: Vec<Vec<u8>>,
    events: VecDeque<Result<Vec<u8>, BlockError>>,
    acl: VecDeque<Result<Vec<u8>, BlockError>>,
    clock: u64,
    close_count: Rc<Cell<usize>>,
    close_error: Option<BlockError>,
    control_error: Option<BlockError>,
    write_error: Option<BlockError>,
    receive_count: usize,
}
impl Io for Model {
    fn validate(&self) -> core::result::Result<(), BlockError> {
        Ok(()) // This in-memory model has no physical device-generation owner.
    }
    fn control(&mut self, setup: [u8; 8], packet: &[u8]) -> Result<(), BlockError> {
        self.control.push((setup, packet.to_vec()));
        match self.control_error.take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    fn receive(&mut self, pipe: Pipe) -> Result<Option<Vec<u8>>, BlockError> {
        self.receive_count += 1;
        match pipe {
            Pipe::Event => &mut self.events,
            Pipe::Acl => &mut self.acl,
        }
        .pop_front()
        .transpose()
    }
    fn write_acl(&mut self, packet: &[u8]) -> Result<(), BlockError> {
        self.sent.push(packet.to_vec());
        match self.write_error.take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    fn quiesce_bulk(&mut self) -> Result<(), BlockError> {
        Ok(())
    }
    fn close(&mut self) -> Result<(), BlockError> {
        self.close_count.set(self.close_count.get() + 1);
        match self.close_error.take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    fn now_us(&self) -> u64 {
        self.clock
    }
}

#[test]
fn class_requests_use_device_context_not_sco_interface_count() {
    {
        let mut hci = Hci::from_io(binding(false), Model::default());
        let packet = [3, 0x0c, 0]; // Reset, submitted without inventing its response.
        hci.submit_command(&packet).unwrap();
        assert_eq!(
            hci.io.control,
            vec![([0x20, 0, 0, 0, 0, 0, 3, 0], packet.to_vec())]
        );
        assert!(hci.poll().unwrap().is_empty());
        assert_eq!(hci.state(), State::Open);
        assert_eq!(hci.firmware_status(), FirmwareStatus::Unverified);
        assert_eq!(
            hci.binding().device().configuration,
            device(false).configuration
        );
    }
}

#[test]
fn transmit_validates_full_hci_packets_without_h4_prefix_or_fragmentation() {
    let mut hci = Hci::from_io(binding(false), Model::default());
    for packet in [&[][..], &[3, 0x0c], &[3, 0x0c, 1], &[3, 0x0c, 0, 99]] {
        assert!(matches!(
            hci.submit_command(packet).unwrap_err().kind,
            ErrorKind::InvalidPacket(_)
        ));
    }
    for packet in [&[][..], &[1, 0, 0], &[1, 0, 1, 0], &[1, 0, 0, 0, 9]] {
        assert!(matches!(
            hci.submit_acl(packet).unwrap_err().kind,
            ErrorKind::InvalidPacket(_)
        ));
    }
    let mut oversized = vec![0; MAX_ACL_PAYLOAD + 5];
    oversized[2..4].copy_from_slice(&((MAX_ACL_PAYLOAD + 1) as u16).to_le_bytes());
    assert!(matches!(
        hci.submit_acl(&oversized).unwrap_err().kind,
        ErrorKind::TooLarge { .. }
    ));
    assert!(hci.io.control.is_empty());
    assert!(hci.io.sent.is_empty());
    let acl = [1, 0x20, 3, 0, 0xaa, 0xbb, 0xcc];
    hci.submit_acl(&acl).unwrap();
    assert_eq!(hci.io.sent, vec![acl.to_vec()]);
    assert_eq!(hci.state(), State::Open);
}

#[test]
fn every_header_payload_split_and_coalesced_packet_is_reassembled_per_pipe() {
    let event = [0x0e, 4, 1, 3, 0x0c, 0];
    let acl = [1, 0x20, 3, 0, 9, 8, 7];
    for event_split in 1..event.len() {
        for acl_split in 1..acl.len() {
            let mut model = Model::default();
            model.events.push_back(Ok(event[..event_split].to_vec()));
            let mut events = event[event_split..].to_vec();
            events.extend([0xff, 0]);
            model.events.push_back(Ok(events));
            model.acl.push_back(Ok(acl[..acl_split].to_vec()));
            let mut acls = acl[acl_split..].to_vec();
            acls.extend([2, 0, 0, 0]);
            model.acl.push_back(Ok(acls));
            let mut hci = Hci::from_io(binding(false), model);
            assert!(hci.poll().unwrap().is_empty());
            assert_eq!(
                hci.poll().unwrap(),
                vec![
                    Packet::Event(event.to_vec()),
                    Packet::Event(vec![0xff, 0]),
                    Packet::Acl(acl.to_vec()),
                    Packet::Acl(vec![2, 0, 0, 0])
                ]
            );
        }
    }
}

#[test]
fn partial_packet_has_a_fixed_deadline_and_idle_endpoints_do_not() {
    let mut model = Model::default();
    model.events.push_back(Ok(vec![0x0e]));
    let mut hci = Hci::from_io(binding(false), model);
    assert!(hci.poll().unwrap().is_empty());
    hci.io.clock = PARTIAL_US - 1;
    hci.io.events.push_back(Ok(vec![4])); // Progress must not extend the deadline.
    assert!(hci.poll().unwrap().is_empty());
    hci.io.clock = PARTIAL_US;
    assert_eq!(
        hci.poll().unwrap_err().kind,
        ErrorKind::PartialTimeout(Pipe::Event)
    );
    assert_eq!(hci.io.close_count.get(), 1);
    let mut idle = Hci::from_io(binding(false), Model::default());
    idle.io.clock = u64::MAX;
    assert!(idle.poll().unwrap().is_empty());
    assert_eq!(idle.state(), State::Open);
}

#[test]
fn malformed_events_and_acl_lengths_close_without_partial_delivery() {
    for bytes in [vec![0, 0], vec![0x0e, 2, 1, 3], vec![0x0f, 3, 0, 1, 3]] {
        let mut model = Model::default();
        model.events.push_back(Ok(bytes));
        let mut hci = Hci::from_io(binding(false), model);
        assert!(matches!(
            hci.poll().unwrap_err().kind,
            ErrorKind::InvalidPacket(_)
        ));
        assert_eq!(hci.state(), State::Failed);
        assert_eq!(hci.io.close_count.get(), 1);
    }
    let mut model = Model::default();
    model.acl.push_back(Ok(vec![1, 0, 1, 0x10]));
    let mut hci = Hci::from_io(binding(false), model);
    assert_eq!(
        hci.poll().unwrap_err().kind,
        ErrorKind::TooLarge {
            maximum: MAX_ACL_PAYLOAD + 4,
            actual: MAX_ACL_PAYLOAD + 5
        }
    );
}

#[test]
fn endpoint_stall_disconnect_and_cleanup_failure_are_terminal() {
    for failure in [
        BlockError::Device {
            status: xhci::STALL,
        },
        BlockError::Unsupported("USB Bluetooth device disconnected"),
        BlockError::Timeout,
    ] {
        let mut model = Model::default();
        model.events.push_back(Err(failure.clone()));
        model.close_error = Some(BlockError::Timeout);
        let mut hci = Hci::from_io(binding(false), model);
        let error = hci.poll().unwrap_err();
        assert_eq!(error.kind, ErrorKind::Usb(failure));
        assert_eq!(error.cleanup, Some(BlockError::Timeout));
        let receives = hci.io.receive_count;
        assert_eq!(hci.poll().unwrap_err().kind, ErrorKind::Failed);
        assert_eq!(
            hci.submit_command(&[3, 0x0c, 0]).unwrap_err().kind,
            ErrorKind::Failed
        );
        assert_eq!(hci.io.receive_count, receives);
        assert_eq!(hci.io.close_count.get(), 1);
    }
}

#[test]
fn command_and_acl_usb_failures_never_report_success() {
    let mut model = Model {
        control_error: Some(BlockError::Timeout),
        ..Model::default()
    };
    let mut hci = Hci::from_io(binding(false), model);
    assert_eq!(
        hci.submit_command(&[3, 0x0c, 0]).unwrap_err().kind,
        ErrorKind::Usb(BlockError::Timeout)
    );
    assert_eq!(hci.io.close_count.get(), 1);
    model = Model {
        write_error: Some(BlockError::Device { status: 4 }),
        ..Model::default()
    };
    let mut hci = Hci::from_io(binding(false), model);
    assert_eq!(
        hci.submit_acl(&[1, 0, 0, 0]).unwrap_err().kind,
        ErrorKind::Usb(BlockError::Device { status: 4 })
    );
}

#[test]
fn explicit_close_and_drop_cancel_without_reopening() {
    let count = Rc::new(Cell::new(0));
    {
        let model = Model {
            close_count: count.clone(),
            ..Model::default()
        };
        let mut hci = Hci::from_io(binding(false), model);
        hci.close().unwrap();
        hci.close().unwrap();
        assert_eq!(hci.state(), State::Closed);
        assert_eq!(hci.poll().unwrap_err().kind, ErrorKind::Closed);
    }
    assert_eq!(count.get(), 1);
    {
        let model = Model {
            close_count: count.clone(),
            ..Model::default()
        };
        let _hci = Hci::from_io(binding(false), model);
    }
    assert_eq!(count.get(), 2);
}

#[test]
fn hci_interfaces_need_their_three_endpoints_on_interface_zero() {
    let original = device(false);
    let first = |d: &Device| crate::usb::descriptor::interfaces(&d.configuration)[0].clone();
    assert!(Binding::new(&original, &first(&original)).is_ok());
    // Without its bulk IN endpoint (made a second interrupt IN) the
    // interface has no inbound ACL pipe.
    let mut d = original.clone();
    d.configuration[28] = 3;
    assert_eq!(
        Binding::new(&d, &first(&d)).unwrap_err(),
        "Bluetooth HCI endpoints are missing"
    );
    let mut d = original.clone();
    d.speed = xhci::SUPER_SPEED;
    assert!(Binding::new(&d, &first(&d)).is_err());
    let mut fabricated = first(&original);
    fabricated.number = 4;
    assert!(Binding::new(&original, &fabricated).is_err());
    let sco = &crate::usb::descriptor::interfaces(&original.configuration)[1];
    assert!(Binding::new(&original, sco).is_err());
}

#[test]
fn extra_endpoints_are_ignored_and_other_interfaces_refused_like_btusb() {
    let mut d = device(true);
    d.descriptor[4..7].copy_from_slice(&[0xef, 2, 1]);
    assert_eq!(
        Binding::new(&d, &crate::usb::descriptor::interfaces(&d.configuration)[2]).unwrap_err(),
        "Bluetooth HCI on an interface other than 0"
    );
}

#[test]
fn hci_interface_discovers_its_endpoints_and_commands_go_to_the_device() {
    let mut device = device(false);
    device.configuration[41] = 2;
    device.configuration[20] = 0x87;
    device.configuration[27] = 0x86;
    device.configuration[34] = 0x06;
    device
        .configuration
        .splice(9..9, [9, 4, 1, 0, 0, 0xff, 0, 0, 0]);
    device.configuration[4] = 3;
    let length = device.configuration.len() as u16;
    device.configuration[2..4].copy_from_slice(&length.to_le_bytes());
    let binding = Binding::new(
        &device,
        &crate::usb::descriptor::interfaces(&device.configuration)[1],
    )
    .unwrap();
    assert_eq!(binding.interface(), 0);
    assert_eq!(binding.events.address, 0x87);
    assert_eq!(binding.input.address, 0x86);
    assert_eq!(binding.output.address, 0x06);
    let mut hci = Hci::from_io(binding, Model::default());
    hci.submit_command(&[3, 0x0c, 0]).unwrap();
    assert_eq!(hci.io.control[0].0, [0x20, 0, 0, 0, 0, 0, 3, 0]);
}

#[test]
fn bluetooth_binds_real_xhci_queues_moves_packets_and_stops_on_disconnect() {
    use crate::usb::bluetooth::{FirmwareStatus, Packet, State};
    for scenario in 0..3 {
        let mut backing = vec![0u64; 128 * 1024];
        let start = backing.as_mut_ptr() as u64;
        // SAFETY: this boot-lifetime-style allocation outlives every model DMA.
        let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
        let (controller, model) = unconfigured_cancellation_controller(&mut dma);
        let shared: Shared = Rc::new(RefCell::new(controller));
        let mut device = Device {
            id: shared.borrow().test_device_id(1).unwrap(),
            vendor_ethernet_revision: None,
            vendor_ethernet_tcr: None,
            slot: 1,
            speed: FULL_SPEED,
            location: "modeled physical HCI".into(),
            descriptor: [
                18, 1, 0, 2, 0xe0, 1, 1, 64, 0x34, 0x12, 0x78, 0x56, 0, 1, 0, 0, 0, 1,
            ],
            configurations: Vec::new(),
            configuration: vec![
                9, 2, 48, 0, 2, 1, 0, 0x80, 50, 9, 4, 0, 0, 3, 0xe0, 1, 1, 0, 7, 5, 0x81, 3, 16, 0,
                1, 7, 5, 0x82, 2, 64, 0, 0, 7, 5, 0x02, 2, 64, 0, 0, 9, 4, 1, 0, 0, 0xe0, 1, 1, 0,
            ],
            manufacturer: None,
            product: None,
            serial: None,
            language: None,
        };
        device.configurations = vec![device.configuration.clone()];
        let mut found = Found::default();
        bind(&shared, device, &mut dma, &mut found);
        assert!(found.failures.is_empty(), "{:?}", found.failures);
        assert_eq!(found.bluetooth.len(), 1);
        if scenario == 0 {
            let count = model.borrow().seen.len();
            drop(found);
            assert_eq!(model.borrow().seen.len(), count);
            continue;
        }
        let mut hci = found.bluetooth.pop().unwrap();
        assert_eq!(hci.firmware_status(), FirmwareStatus::Unverified);
        hci.submit_command(&[3, 0x0c, 0]).unwrap();
        assert_eq!(
            model.borrow().setup.last().unwrap(),
            &([0x20, 0, 0, 0, 0, 0, 3, 0], vec![3, 0x0c, 0])
        );
        assert!(hci.poll().unwrap().is_empty());
        model.borrow_mut().push_event(vec![0x0e, 4, 1, 3, 0x0c, 0]);
        model.borrow_mut().push_acl(vec![1, 0x20, 2, 0, 0xab, 0xcd]);
        assert_eq!(
            hci.poll().unwrap(),
            vec![
                Packet::Event(vec![0x0e, 4, 1, 3, 0x0c, 0]),
                Packet::Acl(vec![1, 0x20, 2, 0, 0xab, 0xcd])
            ]
        );
        hci.submit_acl(&[2, 0x20, 1, 0, 0x42]).unwrap();
        assert_eq!(model.borrow().outgoing, vec![vec![2, 0x20, 1, 0, 0x42]]);
        assert!(hci.poll().unwrap().is_empty()); // Leaves both IN TDs active.
        model.borrow_mut().connected = false;
        if scenario == 2 {
            model.borrow_mut().fail = Some((STOP_ENDPOINT, 11));
        }
        let error = hci.poll().unwrap_err();
        assert_eq!(hci.state(), State::Failed);
        if scenario == 1 {
            assert_eq!(error.cleanup, None);
            assert_eq!(model.borrow().state(3), 3);
            assert_eq!(model.borrow().state(5), 3);
            assert!(model.borrow().active[3].is_none());
            assert!(model.borrow().active[5].is_none());
        } else {
            assert_eq!(error.cleanup, Some(BlockError::Device { status: 11 }));
            for dci in [3, 5] {
                assert_eq!(model.borrow().state(dci), 1);
                assert!(model.borrow().active[dci].is_some());
                assert!(shared.borrow().endpoint_poisoned(1, dci));
            }
            assert!(hci.poll().is_err());
        }
        let count = model.borrow().seen.len();
        drop(hci);
        assert_eq!(model.borrow().seen.len(), count); // Drop does not reset another device.
    }
}
