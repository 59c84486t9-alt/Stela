use super::*;
use crate::{
    bus::dma::RegionAllocator,
    usb::bluetooth::{State, mediatek::media::tests::binding},
};
#[test]
fn native_media_buffers_remain_unchanged_after_failed_stop_or_halted_dequeue() {
    for halted in [false, true] {
        let mut backing = vec![0u64; 256 * 1024];
        let base = backing.as_mut_ptr() as u64;
        // SAFETY: synthetic RAM remains exclusive/live through all owners.
        let mut dma = unsafe { RegionAllocator::new(base..base + backing.len() as u64 * 8) };
        let binding = binding();
        let mut native = Native::new(Bindings::new(&binding).unwrap(), &mut dma).unwrap();
        let (controller, ticket) = xhci::model::controller_with_unresolved_ticket(
            &mut dma,
            native.iso_input.physical(),
            512,
            5,
            halted,
        );
        let mut device = binding.device().clone();
        device.id = controller.borrow().test_device_id(device.slot).unwrap();
        let binding = crate::usb::bluetooth::Binding::new(
            &device,
            &xhci::interfaces(&device.configuration)[0],
        )
        .unwrap();
        let mut hci = Hci::attach(controller, &device, binding, &mut dma).unwrap();
        // This is the shared fixture's real submitted interrupt/bulk TD,
        // not an invented completion. The endpoint plan is local test data.
        let mut pair = native.bindings.iso();
        pair.input.address = 0x82;
        pair.output.address = 2;
        native.iso = Some(pair);
        native.iso_receive = Some(ticket);
        native.running = true;
        native.iso_input.bytes_mut()[..512].fill(0xa5);
        hci.io.media = Some(native);
        let before = backing.clone();
        assert!(hci.io.close_media().is_err());
        let native = hci.io.media.as_ref().unwrap();
        assert!(native.retired && native.poisoned);
        assert!(native.iso_receive.is_some());
        assert!(hci.io.resume_media().is_err());
        assert!(hci.io.write_media(Kind::Iso, &[0; 264]).is_err());
        assert_eq!(backing, before);
        // Base close cannot turn the failed media retirement into success.
        assert!(hci.close().is_err());
        assert_eq!(hci.state(), State::Failed);
        // A quarantined owner never reopens for a later power-on.
        assert!(hci.io.reopen_media().is_err());
        assert_eq!(backing, before);
    }
}
#[test]
fn native_quiesce_retires_idle_sco_output_schedule_before_repost_after_long_pause() {
    idle_sco_output_schedule(false);
}
#[test]
fn native_realtek_sco_without_iso_resumes_actual_retired_schedule_after_long_pause() {
    idle_sco_output_schedule(true);
}
fn idle_sco_output_schedule(realtek: bool) {
    let mut backing = vec![0u64; 256 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: exclusive synthetic RAM outlives model, rings and class owner.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let fixture = xhci::model::iso_class_fixture(&mut dma, xhci::HIGH_SPEED);
    let controller = fixture.controller();
    let binding = binding();
    let mut device = binding.device().clone();
    if realtek {
        device.descriptor[8..12].copy_from_slice(&[0xda, 0x0b, 0x71, 0x87]);
    }
    device.id = controller.borrow().test_device_id(device.slot).unwrap();
    let binding =
        crate::usb::bluetooth::Binding::new(&device, &xhci::interfaces(&device.configuration)[0])
            .unwrap();
    let bindings = if realtek {
        Bindings::realtek_sco(&binding)
    } else {
        Bindings::new(&binding)
    }
    .unwrap();
    let mut native = Native::new(bindings, &mut dma).unwrap();
    if realtek {
        assert!(native.running && native.iso.is_none());
    }
    let pair = native
        .bindings
        .sco(media::Voice {
            connections: 1,
            air_mode: media::AirMode::Cvsd,
            voice_setting: 0,
        })
        .unwrap()
        .unwrap();
    controller
        .borrow_mut()
        .configure(1, &pair.endpoints(), None, &mut dma)
        .unwrap();
    let mut hci = Hci::attach(controller.clone(), &device, binding, &mut dma).unwrap();
    native.sco = Some(pair);
    native.running = true;
    let dci = pair.output.dci();
    let length = media::service_bytes(pair.output);
    let ticket = controller
        .borrow_mut()
        .submit_iso(1, dci, native.output[0].dma.physical(), length)
        .unwrap();
    fixture.complete(dci, 1, 0);
    let done = controller
        .borrow_mut()
        .completed_iso(&ticket)
        .unwrap()
        .unwrap();
    assert_eq!(done.status, IsoStatus::Success);
    assert_eq!(done.bytes, length);
    assert!(native.output.iter().all(|b| b.queued.is_none())); // Payload done; schedule still held.
    native.quiesce(&mut hci.io).unwrap();
    assert!(fixture.commands().contains(&(15, dci))); // Stop Endpoint ACK.
    assert!(fixture.commands().contains(&(16, dci))); // Set Dequeue ACK resets Queue.next.
    fixture.set_mfindex(8192); // Old FrameID is outside the scheduling window.
    // Reuse the exact SCO repost operation from Native::resume. This opaque
    // fixture models ISO rings only, not ordinary interrupt/HCI enumeration.
    if realtek {
        native.resume(&mut hci.io).unwrap();
        assert!(native.iso_receive.is_none());
    } else {
        native.post_sco(&mut hci.io).unwrap();
    }
    let fresh = controller
        .borrow_mut()
        .submit_iso(1, dci, native.output[0].dma.physical(), length)
        .unwrap();
    fixture.complete(dci, 1, 0);
    assert_eq!(
        controller
            .borrow_mut()
            .completed_iso(&fresh)
            .unwrap()
            .unwrap()
            .status,
        IsoStatus::Success
    );
    controller.borrow_mut().cancel(1, pair.input.dci()).unwrap();
}
#[test]
fn mt7925_wideband_sco_paces_alternate_6_like_btusb_isoc_tx() {
    let mut backing = vec![0u64; 64 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: exclusive synthetic RAM outlives the class owner.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let mut native = Native::new(Bindings::new(&binding()).unwrap(), &mut dma).unwrap();
    assert!(native.bindings.has_iso());
    let pair = native
        .bindings
        .sco(media::Voice {
            connections: 1,
            air_mode: media::AirMode::Transparent,
            voice_setting: 0,
        })
        .unwrap()
        .unwrap();
    assert_eq!(pair.alternate, 6);
    let service = media::service_bytes(pair.output);
    let paced = |idle| [vec![0; idle], vec![service]].concat();
    assert_eq!(native.sco_lengths(pair, service).unwrap(), paced(6));
    native.alt6_packet_flow = true;
    assert_eq!(native.sco_lengths(pair, service).unwrap(), paced(7));
    // A packet goes in one frame; one larger than a service cannot.
    assert!(native.sco_lengths(pair, service + 1).is_err());
}

#[test]
fn native_realtek_alt6_queues_actual_zero_services_and_payloads_with_bounded_receipts() {
    for speed in [xhci::FULL_SPEED, xhci::HIGH_SPEED] {
        queued_wideband_services(speed);
    }
}
fn queued_wideband_services(speed: u8) {
    let mut backing = vec![0u64; 256 * 1024];
    let start = backing.as_mut_ptr() as u64;
    // SAFETY: exclusive fixture memory outlives every native TD.
    let mut dma = unsafe { RegionAllocator::new(start..start + backing.len() as u64 * 8) };
    let fixture = xhci::model::iso_class_fixture(&mut dma, speed);
    let controller = fixture.controller();
    let mut device = binding().device().clone();
    device.speed = speed;
    device.descriptor[8..12].copy_from_slice(&[0xda, 0x0b, 0x71, 0x87]);
    let mut at = 0;
    let mut alt6 = false;
    while at < device.configuration.len() {
        let len = usize::from(device.configuration[at]);
        if device.configuration[at + 1] == 4 {
            alt6 = device.configuration[at + 2..at + 4] == [1, 6];
        }
        if alt6 && device.configuration[at + 1] == 5 {
            device.configuration[at + 4..at + 7].copy_from_slice(&[
                63,
                0,
                if speed == xhci::FULL_SPEED { 1 } else { 4 },
            ]);
        } else if speed == xhci::FULL_SPEED
            && device.configuration[at + 1] == 5
            && matches!(device.configuration[at + 3] & 3, 2 | 3)
        {
            device.configuration[at + 4..at + 6].copy_from_slice(&64u16.to_le_bytes());
        }
        at += len;
    }
    device.id = controller.borrow().test_device_id(device.slot).unwrap();
    let binding =
        crate::usb::bluetooth::Binding::new(&device, &xhci::interfaces(&device.configuration)[0])
            .unwrap();
    let bindings = Bindings::realtek_sco(&binding).unwrap();
    let pair = bindings.wideband_sco(1, 60).unwrap().unwrap();
    assert_eq!(pair.alternate, 6);
    let mut native = Native::new(bindings, &mut dma).unwrap();
    // Native ring fixture supplies real endpoint contexts, but does not
    // simulate HCI firmware setup or SET_INTERFACE. Those are separate models.
    controller
        .borrow_mut()
        .configure(1, &pair.endpoints(), None, &mut dma)
        .unwrap();
    let mut hci = Hci::attach(controller.clone(), &device, binding, &mut dma).unwrap();
    native.sco = Some(pair);
    let mut packet = vec![0x6a; 63];
    // A generous real TSC budget keeps this DMA/scheduling proof independent
    // of host test-runner latency. Modeled MFINDEX supplies service timing.
    hci.io.clock.ticks_per_microsecond = 1000;
    packet[..3].copy_from_slice(&[1, 0, 60]);
    for sequence in 1..=4 {
        assert_eq!(
            native.queue_sco(&mut hci.io, &packet).unwrap(),
            Some(sequence)
        );
    }
    let geometry: Vec<_> = native
        .output
        .iter()
        .map(|b| b.dma.bytes().to_vec())
        .collect();
    assert_eq!(native.queue_sco(&mut hci.io, &packet).unwrap(), None);
    assert_eq!(native.output_sequence, 5);
    assert!(!native.alt6_packet_flow);
    assert_eq!(
        native
            .output
            .iter()
            .map(|b| b.dma.bytes().to_vec())
            .collect::<Vec<_>>(),
        geometry
    );
    let mut previous = None;
    let mut service_times = Vec::new();
    for (n, queued) in native.queued_output.iter().enumerate() {
        assert_eq!(queued.slots.len(), if n % 2 == 0 { 7 } else { 8 });
        for (i, slot) in queued.slots.iter().enumerate() {
            assert_eq!(
                queued.lengths[i],
                if i + 1 == queued.slots.len() { 63 } else { 0 }
            );
            let xhci::IsoSchedule::AtMicroframe(now) =
                native.output[*slot].queued.as_ref().unwrap().schedule()
            else {
                panic!("fixture requires actual FrameID schedule");
            };
            if let Some(last) = previous {
                assert_eq!(now, (last + 8) % 16384);
            }
            previous = Some(now);
            service_times.push(now);
        }
    }
    assert_eq!(native.poll_sco_output(&mut hci.io).unwrap(), None);
    // Complete the 30 ring TDs. The hardware model reads native TRB
    // lengths: an empty interval cannot masquerade as the 63-byte payload.
    assert_eq!(service_times.len(), 30);
    assert_eq!(service_times[14] - service_times[6], 64); // 8ms between payloads
    assert_eq!(service_times[21] - service_times[14], 56); // 7ms between payloads
    assert_eq!(service_times[29] - service_times[21], 64);
    for now in service_times {
        fixture.service_at(pair.output.dci(), u32::from(now), 1);
    }
    for sequence in 1..=4 {
        assert_eq!(
            native.poll_sco_output(&mut hci.io).unwrap(),
            Some(media::OutputReceipt {
                sequence,
                packet_bytes: 63,
                disposition: media::OutputDisposition::Completed,
            })
        );
    }
    assert!(native.output.iter().all(|b| b.queued.is_none()));
    assert_eq!(native.queue_sco(&mut hci.io, &packet).unwrap(), Some(5));
    assert_eq!(native.queue_sco(&mut hci.io, &packet).unwrap(), Some(6));
    native.quiesce(&mut hci.io).unwrap();
    assert!(fixture.commands().contains(&(15, pair.output.dci())));
    assert!(fixture.commands().contains(&(16, pair.output.dci())));
    for sequence in 5..=6 {
        assert_eq!(
            native.poll_sco_output(&mut hci.io).unwrap(),
            Some(media::OutputReceipt {
                sequence,
                packet_bytes: 63,
                disposition: media::OutputDisposition::RetiredUnconfirmed,
            })
        );
    }
    assert_eq!(native.poll_sco_output(&mut hci.io).unwrap(), None);
    fixture.set_mfindex(8192);
    native.resume(&mut hci.io).unwrap();
    assert_eq!(native.queue_sco(&mut hci.io, &packet).unwrap(), Some(7));
    for _ in 0..7 {
        fixture.complete(pair.output.dci(), 1, 0);
    }
    assert_eq!(
        native
            .poll_sco_output(&mut hci.io)
            .unwrap()
            .unwrap()
            .disposition,
        media::OutputDisposition::Completed
    );
    native.quiesce(&mut hci.io).unwrap();
    native.resume(&mut hci.io).unwrap();
    assert_eq!(native.queue_sco(&mut hci.io, &packet).unwrap(), Some(8));
    let retained: Vec<_> = native
        .output
        .iter()
        .map(|b| b.dma.bytes().to_vec())
        .collect();
    // Deterministically inject an already expired real raw-clock deadline
    // after publication. This does not claim five physical seconds
    // elapsed or change calibration to invent a timeout.
    native.queued_output.front_mut().unwrap().deadline = hci.io.clock.try_deadline(0).unwrap();
    assert!(
        matches!(native.poll_sco_output(&mut hci.io),Err(media::Error::QueuedOutput {sequence:8,cause})
            if matches!(*cause,media::Error::Transport(BlockError::Timeout)))
    );
    assert_eq!(native.queued_output.front().unwrap().sequence, 8);
    assert_eq!(
        native.output.iter().filter(|b| b.queued.is_some()).count(),
        8
    );
    assert_eq!(
        native
            .output
            .iter()
            .map(|b| b.dma.bytes().to_vec())
            .collect::<Vec<_>>(),
        retained
    );
    native.quiesce(&mut hci.io).unwrap(); // retirement, never local timeout credit
    assert_eq!(
        native
            .poll_sco_output(&mut hci.io)
            .unwrap()
            .unwrap()
            .disposition,
        media::OutputDisposition::RetiredUnconfirmed
    );
}
