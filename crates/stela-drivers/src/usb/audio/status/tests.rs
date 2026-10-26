// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual ordinary xHCI interrupt TDs, DMA payloads and command acknowledgements.
use super::*;
use crate::usb::audio::{Plan, UsbAudio};
use crate::usb::xhci::{self, Device};
use alloc::rc::Rc;
use core::cell::RefCell;

mod uac1;

fn configuration() -> Vec<u8> {
    let mut raw = crate::usb::audio::test_configuration();
    let at = raw
        .windows(9)
        .position(|d| d == [9, 4, 0, 0, 0, 1, 1, 0x20, 0])
        .unwrap();
    raw[at + 4] = 1;
    let after = raw
        .windows(9)
        .position(|d| d == [9, 4, 1, 0, 0, 1, 2, 0x20, 0])
        .unwrap();
    let additions = [
        8, 0x24, 11, 11, 1, 10, 3, 0, // readable clock selector
        8, 0x24, 5, 12, 1, 1, 3, 0, // readable signal selector
        7, 0x24, 12, 13, 10, 15, 0, // multiplier numerator/denominator
    ];
    let header = raw
        .windows(9)
        .position(|d| d[0..6] == [9, 0x24, 1, 0, 2, 1])
        .unwrap();
    let old_total = u16::from_le_bytes([raw[header + 6], raw[header + 7]]);
    raw[header + 6..header + 8]
        .copy_from_slice(&(old_total + additions.len() as u16).to_le_bytes());
    raw.splice(
        after..after,
        additions.into_iter().chain([7, 5, 0x81, 3, 12, 0, 4]),
    );
    let length = raw.len() as u16;
    raw[2..4].copy_from_slice(&length.to_le_bytes());
    raw
}
fn peer(dma: &mut dyn DmaAllocator) -> (UsbAudio, Rc<RefCell<xhci::model::CancelModel>>, Shared) {
    peer_with_packet(dma, 12)
}
fn peer_with_packet(
    dma: &mut dyn DmaAllocator,
    packet: u16,
) -> (UsbAudio, Rc<RefCell<xhci::model::CancelModel>>, Shared) {
    let mut raw = configuration();
    let at = raw
        .windows(7)
        .position(|d| d == [7, 5, 0x81, 3, 12, 0, 4])
        .unwrap();
    raw[at + 4..at + 6].copy_from_slice(&packet.to_le_bytes());
    peer_configuration(dma, &raw)
}
fn peer_configuration(
    dma: &mut dyn DmaAllocator,
    raw: &[u8],
) -> (UsbAudio, Rc<RefCell<xhci::model::CancelModel>>, Shared) {
    let (mut controller, model) = xhci::model::status_interrupt_controller(dma, raw);
    controller.set_configuration(1, 1).unwrap();
    let shared = Rc::new(RefCell::new(controller));
    let device = Device {
        id: shared.borrow().test_device_id(1).unwrap(),
        slot: 1,
        speed: xhci::HIGH_SPEED,
        location: "representative standard audio status peer".into(),
        descriptor: [18, 1, 0, 2, 0, 0, 0, 64, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1],
        configurations: vec![raw.to_vec()],
        configuration: raw.to_vec(),
        manufacturer: None,
        product: None,
        serial: None,
        language: None,
        vendor_ethernet_tcr: None,
        vendor_ethernet_revision: None,
    };
    let all = xhci::interfaces(raw);
    let plan = Plan::parse(&all[0], &all, raw, xhci::HIGH_SPEED).unwrap();
    let owner = UsbAudio::attach(shared.clone(), &device, plan, dma).unwrap();
    (owner, model, shared)
}
fn memory() -> Vec<u64> {
    vec![0; 512 * 1024]
}
fn allocator(memory: &mut [u64]) -> RegionAllocator {
    let base = memory.as_mut_ptr() as u64;
    // SAFETY: each caller retains exclusive backing for all controller/owner DMA.
    unsafe { RegionAllocator::new(base..base + memory.len() as u64 * 8) }
}
const FREQUENCY: [u8; 6] = [0, 1, 0, 1, 0, 10];
const VOLUME: [u8; 6] = [0, 2, 1, 2, 0, 2];

#[test]
fn actual_descriptor_dma_completion_rearm_and_bounded_backpressure() {
    let mut backing = memory();
    let mut dma = allocator(&mut backing);
    let (audio, model, _) = peer(&mut dma);
    let old_binding = audio.binding().clone();
    let mut owner = audio.status_notifications(&mut dma).unwrap().unwrap();
    assert!(!owner.configured);
    owner.start().unwrap();
    let allocation = owner.allocator.remaining();
    model.borrow_mut().incoming_events.push_back(Vec::new());
    assert_eq!(owner.poll().unwrap(), 0); // real zero-length terminal packet
    assert!(owner.ticket.is_none() && owner.notices.is_empty());
    assert_eq!(owner.poll().unwrap(), 0); // rearm only after retirement
    for epoch in 0..320 {
        let original = model.borrow().active[3].unwrap();
        for _ in 0..8 {
            assert_eq!(owner.poll().unwrap(), 0); // genuine NAK: unchanged owner
            assert_eq!(model.borrow().active[3], Some(original));
        }
        model
            .borrow_mut()
            .incoming_events
            .push_back([FREQUENCY.as_slice(), VOLUME.as_slice()].concat());
        assert_eq!(owner.poll().unwrap(), 2);
        assert!(owner.ticket.is_none());
        assert!(model.borrow().active[3].is_none());
        for _ in 0..8 {
            assert_eq!(owner.poll().unwrap(), 0);
        }
        let a = owner.next_notice().unwrap().unwrap();
        assert_eq!(
            (a.attribute, a.entity, a.selector, a.channel, a.raw),
            (StatusAttribute::Current, 10, 1, 0, FREQUENCY)
        );
        assert_eq!(owner.poll().unwrap(), 0); // second notice blocks rearm
        assert!(model.borrow().active[3].is_none());
        let b = owner.next_notice().unwrap().unwrap();
        assert_eq!(
            (b.attribute, b.entity, b.selector, b.channel, b.raw),
            (StatusAttribute::Range, 2, 2, 1, VOLUME)
        );
        assert_eq!(owner.next_notice().unwrap(), None);
        assert_eq!(audio.binding(), &old_binding); // notices never retune PCM
        assert_eq!(owner.poll().unwrap(), 0);
        assert!(model.borrow().active[3].is_some());
        assert_eq!(owner.allocator.remaining(), allocation, "epoch {epoch}");
    }
    owner.stop().unwrap();
    assert!(owner.ticket.is_none());
    assert!(!owner.configured);
    assert!(model.borrow().seen.contains(&15)); // actual Stop Endpoint
    assert!(model.borrow().seen.contains(&16)); // actual Set Dequeue
    assert!(model.borrow().seen.contains(&12)); // actual Configure/Drop
}

#[test]
fn actual_hostile_packets_publish_no_valid_prefix_and_rearm_after_retirement() {
    let mut backing = memory();
    let mut dma = allocator(&mut backing);
    let (audio, model, _) = peer(&mut dma);
    let mut owner = audio.status_notifications(&mut dma).unwrap().unwrap();
    owner.start().unwrap();
    let mut hostile = Vec::new();
    for (offset, value) in [
        (0, 1),
        (0, 2),
        (0, 4),
        (1, 0),
        (1, 3),
        (1, 0xff),
        (3, 0),
        (3, 3),
        (4, 1),
        (5, 0),
        (5, 99),
        (2, 1),
    ] {
        let mut raw = FREQUENCY;
        raw[offset] = value;
        hostile.push(raw.to_vec());
    }
    hostile.push(vec![0, 2, 0, 2, 0, 10]); // validity has only CUR
    hostile.push(vec![0, 1, 3, 2, 0, 2]); // feature channel outside cluster
    hostile.push(vec![0, 1, 0, 1, 0, 1]); // terminal controls not retained
    hostile.push(vec![0, 2, 0, 1, 0, 2]); // mute RANGE unsupported
    hostile.push(vec![0, 1, 0, 16, 0, 2]); // unsupported feature selector
    for raw in hostile {
        model
            .borrow_mut()
            .incoming_events
            .push_back([FREQUENCY.as_slice(), raw.as_slice()].concat());
        assert!(owner.poll().is_err());
        assert!(owner.notices.is_empty());
        assert!(owner.ticket.is_none()); // terminal event, not fake cancellation
        assert!(!owner.poisoned);
        assert_eq!(owner.next_notice().unwrap(), None);
        assert_eq!(owner.poll().unwrap(), 0);
    }
    for length in [1, 5, 7, 11] {
        model
            .borrow_mut()
            .incoming_events
            .push_back(vec![0; length]);
        assert_eq!(
            owner.poll(),
            Err(Error::Packet("truncated audio status packet"))
        );
        assert!(owner.notices.is_empty());
        assert_eq!(owner.poll().unwrap(), 0);
    }
    model
        .borrow_mut()
        .incoming_events
        .push_back(FREQUENCY.to_vec());
    assert_eq!(owner.poll().unwrap(), 1);
    assert_eq!(owner.next_notice().unwrap().unwrap().raw, FREQUENCY);
    owner.stop().unwrap();
}

#[test]
fn actual_exclusive_endpoint_claim_and_failed_stop_preserve_live_dma_owner() {
    for command in [15, 16, 12] {
        let mut backing = memory();
        let mut dma = allocator(&mut backing);
        let (audio, model, _) = peer(&mut dma);
        let mut owner = audio.status_notifications(&mut dma).unwrap().unwrap();
        let mut second = audio.status_notifications(&mut dma).unwrap().unwrap();
        owner.start().unwrap();
        let active = model.borrow().active[3];
        assert!(second.start().is_err());
        assert!(!second.configured);
        second.stop().unwrap();
        assert_eq!(model.borrow().active[3], active);
        let geometry = (
            owner.packet.physical(),
            owner._arena.physical(),
            owner.allocator.remaining(),
        );
        model.borrow_mut().fail = Some((command, 5));
        assert!(owner.stop().is_err());
        assert!(owner.poisoned && owner.configured && owner.ticket.is_some());
        if command == 15 {
            assert_eq!(model.borrow().active[3], active);
        }
        assert_eq!(
            (
                owner.packet.physical(),
                owner._arena.physical(),
                owner.allocator.remaining()
            ),
            geometry
        );
        assert_eq!(owner.poll(), Err(Error::Poisoned));
        assert_eq!(owner.next_notice(), Err(Error::Poisoned));
        assert_eq!(owner.start(), Err(Error::Poisoned));
        model.borrow_mut().fail = None;
        assert!(owner.stop().is_err()); // native uncertainty is a permanent epoch fence
        assert!(owner.poisoned && owner.configured && owner.ticket.is_some());
        assert!(second.start().is_err());
        assert!(!second.configured);
        second.stop().unwrap();
    }
}
#[test]
fn actual_configuration_failure_retains_staged_owner_and_native_quarantine() {
    let mut backing = memory();
    let mut dma = allocator(&mut backing);
    let (audio, model, _) = peer(&mut dma);
    let mut owner = audio.status_notifications(&mut dma).unwrap().unwrap();
    model.borrow_mut().fail = Some((12, 5));
    assert!(owner.start().is_err());
    assert!(owner.configured && owner.poisoned);
    assert!(owner.ticket.is_none());
    let retained = (
        owner.packet.physical(),
        owner._arena.physical(),
        owner.allocator.remaining(),
    );
    assert_eq!(owner.poll(), Err(Error::Poisoned));
    model.borrow_mut().fail = None;
    assert!(owner.stop().is_err()); // never pretend an unacknowledged context was dropped
    assert!(owner.configured && owner.poisoned);
    assert_eq!(
        (
            owner.packet.physical(),
            owner._arena.physical(),
            owner.allocator.remaining()
        ),
        retained
    );
}

#[test]
fn actual_stale_identity_refuses_before_cached_dequeue_or_any_mmio() {
    let mut backing = memory();
    let mut dma = allocator(&mut backing);
    let (audio, model, _) = peer(&mut dma);
    let mut owner = audio.status_notifications(&mut dma).unwrap().unwrap();
    owner.start().unwrap();
    model
        .borrow_mut()
        .incoming_events
        .push_back(FREQUENCY.to_vec());
    owner.poll().unwrap();
    let notices = owner.notices.clone();
    let (_, _, foreign) = peer(&mut dma);
    foreign.borrow_mut().forbid_mmio();
    owner.shared = foreign;
    let old = (
        owner.configured,
        owner.poisoned,
        owner.ticket.is_some(),
        owner.allocator.remaining(),
    );
    assert!(owner.next_notice().is_err());
    assert!(owner.poll().is_err());
    assert!(owner.stop().is_err());
    assert!(owner.start().is_err());
    assert_eq!(owner.notices, notices);
    assert_eq!(
        (
            owner.configured,
            owner.poisoned,
            owner.ticket.is_some(),
            owner.allocator.remaining()
        ),
        old
    );
}

#[test]
fn descriptor_selection_refuses_foreign_aliases_and_invalid_status_endpoint_profiles() {
    let raw = configuration();
    let all = xhci::interfaces(&raw);
    let binding = Binding::parse(&all[0], &all, &raw, xhci::FULL_SPEED).unwrap();
    let good = StatusPlan::discover(&binding, &raw).unwrap().unwrap();
    assert_eq!(good.endpoint.address, 0x81);
    let at = raw
        .windows(7)
        .position(|d| d == [7, 5, 0x81, 3, 12, 0, 4])
        .unwrap();
    for (offset, value) in [
        (2, 1),
        (2, 0x80),
        (2, 0x91),
        (3, 2),
        (3, 0x13),
        (4, 0),
        (4, 5),
        (4, 65),
        (5, 8),
        (6, 0),
    ] {
        let mut bad = raw.clone();
        bad[at + offset] = value;
        assert!(StatusPlan::discover(&binding, &bad).is_err());
    }
    let mut alias = raw.clone();
    alias.extend_from_slice(&[9, 4, 3, 0, 1, 3, 0, 0, 0, 7, 5, 0x81, 3, 12, 0, 4]);
    assert!(StatusPlan::discover(&binding, &alias).is_err());
    let mut none = crate::usb::audio::test_configuration();
    assert!(StatusPlan::discover(&binding, &none).unwrap().is_none());
    none[0] = 0; // not admitted by Binding::parse; no native authority minted
    let all = xhci::interfaces(&none);
    assert!(Binding::parse(&xhci::interfaces(&raw)[0], &all, &none, xhci::FULL_SPEED).is_err());
}

#[test]
fn actual_fragmented_packet_dma_alignment_preserves_one_td_boundary() {
    struct Fragmented<'a>(&'a mut RegionAllocator);
    impl DmaAllocator for Fragmented<'_> {
        fn allocate(
            &mut self,
            bytes: usize,
            align: usize,
        ) -> Result<DmaBuffer, crate::block::BlockError> {
            if bytes == MAX_PACKET {
                // Arrange the next free physical byte 64 bytes before a 64 KiB
                // edge; honoring the owner's requested alignment must skip it.
                let anchor = self.0.allocate(1, 65536)?;
                self.0.allocate(65536 - 65, 1)?;
                let buffer = self.0.allocate(bytes, align)?;
                assert!(buffer.physical() >= anchor.physical() + 65536);
                return Ok(buffer);
            }
            self.0.allocate(bytes, align)
        }
    }
    let mut backing = memory();
    let mut dma = allocator(&mut backing);
    let (audio, model, _) = peer_with_packet(&mut dma, MAX_PACKET as u16);
    let mut owner = audio
        .status_notifications(&mut Fragmented(&mut dma))
        .unwrap()
        .unwrap();
    assert!((owner.packet.physical() & 0xffff) + owner.packet.len() as u64 <= 65536);
    owner.start().unwrap();
    model
        .borrow_mut()
        .incoming_events
        .push_back(FREQUENCY.to_vec());
    assert_eq!(owner.poll().unwrap(), 1);
    assert_eq!(owner.next_notice().unwrap().unwrap().raw, FREQUENCY);
    owner.stop().unwrap();
}

#[test]
fn actual_descriptor_advertised_clock_selector_multiplier_and_feature_attributes() {
    let mut backing = memory();
    let mut dma = allocator(&mut backing);
    let (audio, model, _) = peer(&mut dma);
    let mut owner = audio.status_notifications(&mut dma).unwrap().unwrap();
    owner.start().unwrap();
    for raw in [
        [0, 1, 0, 2, 0, 10],
        [0, 2, 0, 1, 0, 10], // validity CUR/frequency RANGE
        [0, 1, 0, 1, 0, 11],
        [0, 1, 0, 1, 0, 12], // clock/signal selector CUR
        [0, 1, 0, 1, 0, 13],
        [0, 1, 0, 2, 0, 13], // multiplier CUR attributes
        [0, 1, 0, 1, 0, 2],
        [0, 1, 2, 2, 0, 2], // feature master mute/channel volume CUR
    ] {
        model.borrow_mut().incoming_events.push_back(raw.to_vec());
        assert_eq!(owner.poll().unwrap(), 1);
        assert_eq!(owner.next_notice().unwrap().unwrap().raw, raw);
        assert_eq!(owner.poll().unwrap(), 0);
    }
    owner.stop().unwrap();
}

#[test]
fn dropping_pending_owner_retains_boot_dma_and_cannot_mint_replacement_authority() {
    let mut backing = memory();
    let mut dma = allocator(&mut backing);
    let (audio, model, _) = peer(&mut dma);
    let mut owner = audio.status_notifications(&mut dma).unwrap().unwrap();
    owner.start().unwrap();
    let original = model.borrow().active[3].unwrap();
    let before_drop = model.borrow().seen.clone();
    drop(owner);
    assert_eq!(model.borrow().active[3], Some(original));
    assert_eq!(model.borrow().seen, before_drop);
    let mut replacement = audio.status_notifications(&mut dma).unwrap().unwrap();
    assert!(replacement.start().is_err());
    assert!(!replacement.configured);
    replacement.stop().unwrap();
    assert_eq!(model.borrow().active[3], Some(original));
    // The allocator's boot-lived original packet remains writable by hardware;
    // dropping a Rust owner did not free or overwrite the submitted allocation.
    model
        .borrow_mut()
        .incoming_events
        .push_back(FREQUENCY.to_vec());
    model.borrow_mut().receive(3);
    assert!(model.borrow().active[3].is_none());
    // SAFETY: original still-live DMA lies in this test's retained backing RAM.
    let delivered = unsafe { core::slice::from_raw_parts(original.1 as *const u8, 6) };
    assert_eq!(delivered, FREQUENCY);
}

#[test]
fn actual_transfer_error_retains_ticket_until_reset_dequeue_and_drop_ack() {
    let mut backing = memory();
    let mut dma = allocator(&mut backing);
    let (audio, model, _) = peer(&mut dma);
    model.borrow_mut().halt_transfer = Some(3);
    let mut owner = audio.status_notifications(&mut dma).unwrap().unwrap();
    owner.start().unwrap();
    let original = model.borrow().active[3].unwrap();
    let packet = owner.packet.bytes().to_vec();
    assert!(matches!(
        owner.poll(),
        Err(Error::Transport(crate::block::BlockError::Device {
            status: 6
        }))
    ));
    assert!(owner.poisoned && owner.configured && owner.ticket.is_some());
    assert_eq!(model.borrow().active[3], Some(original));
    assert_eq!(owner.packet.bytes(), packet);
    assert!(owner.notices.is_empty());
    assert_eq!(owner.next_notice(), Err(Error::Poisoned));
    // Recovery requires actual native Reset Endpoint, Set Dequeue and Drop;
    // no class-local clearing of the native halt/submission fence is allowed.
    owner.stop().unwrap();
    assert!(!owner.configured && !owner.poisoned && owner.ticket.is_none());
    assert!(model.borrow().seen.contains(&14));
    assert!(model.borrow().seen.contains(&16));
    assert!(model.borrow().seen.contains(&12));
    assert_eq!(owner.packet.bytes(), packet);
    assert!(
        model
            .borrow()
            .setup
            .iter()
            .any(|(request, _)| *request == xhci::setup(2, 1, 0, 0x81, 0))
    );
    assert_eq!(model.borrow().halt_transfer, None);
    // Replacement configuration must consume the actual retained dequeue
    // pointer from the acknowledged native ring, without an allocator rewind.
    let producer = model.borrow().dequeues.last().copied().unwrap() & !0xf;
    owner.start().unwrap();
    assert_eq!(model.borrow().active[3].unwrap().0, producer);
    model
        .borrow_mut()
        .incoming_events
        .push_back(FREQUENCY.to_vec());
    assert_eq!(owner.poll().unwrap(), 1);
    assert_eq!(owner.next_notice().unwrap().unwrap().raw, FREQUENCY);
    owner.stop().unwrap();
}

#[test]
fn unsupported_optional_status_profile_preserves_pcm_and_refuses_before_status_allocation() {
    struct NoAllocation;
    impl DmaAllocator for NoAllocation {
        fn allocate(&mut self, _: usize, _: usize) -> Result<DmaBuffer, crate::block::BlockError> {
            panic!("unadmitted status profile allocated DMA")
        }
    }
    let mut backing = memory();
    let mut dma = allocator(&mut backing);
    // Valid USB2 high-bandwidth interrupt descriptor, outside this finite
    // status receiver's single-transaction profile. PCM remains admitted.
    let (audio, model, _) = peer_with_packet(&mut dma, 0x080c);
    assert!(!audio.binding().formats.is_empty());
    let before = model.borrow().seen.clone();
    assert!(matches!(
        audio.status_notifications(&mut NoAllocation),
        Err(Error::Unsupported("audio status endpoint profile"))
    ));
    assert_eq!(model.borrow().seen, before);
    assert!(model.borrow().active[3].is_none());
}

#[test]
fn actual_usb_halt_clear_failure_retains_owner_and_never_acknowledges_drop() {
    let mut backing = memory();
    let mut dma = allocator(&mut backing);
    let (audio, model, _) = peer(&mut dma);
    model.borrow_mut().halt_transfer = Some(3);
    let mut owner = audio.status_notifications(&mut dma).unwrap().unwrap();
    owner.start().unwrap();
    assert!(owner.poll().is_err());
    let geometry = (
        owner.packet.physical(),
        owner._arena.physical(),
        owner.allocator.remaining(),
    );
    let drops = model
        .borrow()
        .seen
        .iter()
        .filter(|&&command| command == 12)
        .count();
    model.borrow_mut().stall_control = Some(1);
    assert!(owner.stop().is_err());
    assert!(owner.poisoned && owner.configured && owner.cancelled && owner.ticket.is_some());
    assert_eq!(model.borrow().halt_transfer, Some(3));
    assert_eq!(
        model
            .borrow()
            .seen
            .iter()
            .filter(|&&command| command == 12)
            .count(),
        drops
    );
    assert_eq!(
        (
            owner.packet.physical(),
            owner._arena.physical(),
            owner.allocator.remaining()
        ),
        geometry
    );
    assert!(
        model
            .borrow()
            .setup
            .iter()
            .any(|(request, _)| *request == xhci::setup(2, 1, 0, 0x81, 0))
    );
    assert_eq!(owner.start(), Err(Error::Poisoned));
    assert_eq!(owner.next_notice(), Err(Error::Poisoned));
    let original_shared = owner.shared.clone();
    let (_, _, foreign) = peer(&mut dma);
    foreign.borrow_mut().forbid_mmio();
    owner.shared = foreign;
    assert!(owner.stop().is_err()); // cached cancellation ACK is not foreign authority
    assert!(owner.cancelled && owner.poisoned && owner.configured && owner.ticket.is_some());
    assert_eq!(
        (
            owner.packet.physical(),
            owner._arena.physical(),
            owner.allocator.remaining()
        ),
        geometry
    );
    owner.shared = original_shared;
    model.borrow_mut().stall_control = None;
    owner.stop().unwrap(); // retry requires genuine EP0 recovery and new clear ACK
    assert!(!owner.poisoned && !owner.configured);
    assert_eq!(model.borrow().halt_transfer, None);
    assert!(
        model
            .borrow()
            .seen
            .iter()
            .filter(|&&command| command == 12)
            .count()
            > drops
    );
}

#[test]
fn actual_unpolled_stall_is_cleared_on_device_before_acknowledged_restart() {
    let mut backing = memory();
    let mut dma = allocator(&mut backing);
    let (audio, model, _) = peer(&mut dma);
    model.borrow_mut().halt_transfer = Some(3);
    let mut owner = audio.status_notifications(&mut dma).unwrap().unwrap();
    owner.start().unwrap();
    assert!(model.borrow().active[3].is_some());
    assert!(owner.ticket.is_some());
    // The host deliberately has not consumed the actual STALL event. Device
    // HALT must still clear through its actual EP0 request, not a cached flag.
    owner.stop().unwrap();
    assert_eq!(model.borrow().halt_transfer, None);
    assert!(
        model
            .borrow()
            .setup
            .iter()
            .any(|(request, _)| *request == xhci::setup(2, 1, 0, 0x81, 0))
    );
    assert!(owner.ticket.is_none() && owner.notices.is_empty());
    let producer = model.borrow().dequeues.last().copied().unwrap() & !0xf;
    owner.start().unwrap();
    assert_eq!(model.borrow().active[3].unwrap().0, producer);
    model
        .borrow_mut()
        .incoming_events
        .push_back(FREQUENCY.to_vec());
    assert_eq!(owner.poll().unwrap(), 1);
    assert_eq!(owner.next_notice().unwrap().unwrap().raw, FREQUENCY);
    owner.stop().unwrap();
}
