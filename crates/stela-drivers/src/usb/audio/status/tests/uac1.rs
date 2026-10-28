// SPDX-License-Identifier: GPL-2.0-or-later
//! UAC1 status words through actual xHCI TD, DMA and cancellation ownership.
extern crate std;
use super::*;

fn configuration(packet: u16) -> Vec<u8> {
    let mut raw = vec![9, 2, 0, 0, 3, 1, 0, 0x80, 50];
    raw.extend_from_slice(&[9, 4, 0, 0, 1, 1, 1, UAC1, 0]);
    let start = raw.len();
    raw.extend_from_slice(&[10, 0x24, 1, 0, 1, 0, 0, 2, 3, 7]);
    raw.extend_from_slice(&[12, 0x24, 2, 1, 1, 1, 0, 2, 3, 0, 0, 0]);
    raw.extend_from_slice(&[10, 0x24, 6, 2, 1, 1, 3, 3, 3, 0]);
    raw.extend_from_slice(&[9, 0x24, 3, 3, 1, 3, 0, 2, 0]);
    raw.extend_from_slice(&[12, 0x24, 2, 4, 1, 2, 0, 2, 3, 0, 0, 0]);
    raw.extend_from_slice(&[9, 0x24, 3, 5, 1, 1, 0, 4, 0]);
    let total = (raw.len() - start) as u16;
    raw[start + 5..start + 7].copy_from_slice(&total.to_le_bytes());
    let [lo, hi] = packet.to_le_bytes();
    raw.extend_from_slice(&[7, 5, 0x81, 3, lo, hi, 4]);
    for (interface, terminal, address, attributes) in [(3, 1, 1, 0x0d), (7, 5, 0x82, 0x05)] {
        raw.extend_from_slice(&[9, 4, interface, 0, 0, 1, 2, UAC1, 0]);
        raw.extend_from_slice(&[9, 4, interface, 1, 1, 1, 2, UAC1, 0]);
        raw.extend_from_slice(&[7, 0x24, 1, terminal, 1, 1, 0]);
        raw.extend_from_slice(&[11, 0x24, 2, 1, 2, 2, 16, 1, 0x80, 0xbb, 0]);
        raw.extend_from_slice(&[9, 5, address, attributes, 0xc0, 0, 4, 0, 0]);
        raw.extend_from_slice(&[7, 0x25, 1, 1, 0, 0, 0]);
    }
    let total = raw.len() as u16;
    raw[2..4].copy_from_slice(&total.to_le_bytes());
    raw
}

fn notice(raw: [u8; 2]) -> StatusEvent {
    StatusEvent::Uac1(Uac1StatusNotice {
        entity: raw[1],
        memory_changed: raw[0] & 0x40 != 0,
        interrupt_pending: raw[0] & 0x80 != 0,
        raw,
    })
}

#[test]
fn actual_uac1_entity_and_memory_words_wrap_rearm_and_apply_backpressure() {
    let mut backing = memory();
    let mut dma = allocator(&mut backing);
    let (audio, model, _) = peer_configuration(&mut dma, &configuration(4));
    let binding = audio.binding().clone();
    let mut owner = audio.status_notifications(&mut dma).unwrap().unwrap();
    owner.start().unwrap();
    let geometry = (owner.packet.physical(), owner.allocator.remaining());
    for _ in 0..320 {
        let pending = model.borrow().active[3];
        assert_eq!(owner.poll().unwrap(), 0); // NAK retains the genuine TD
        assert_eq!(model.borrow().active[3], pending);
        model.borrow_mut().push_event(vec![0x80, 2, 0xc0, 4]);
        assert_eq!(owner.poll().unwrap(), 2);
        assert!(model.borrow().active[3].is_none());
        assert!(owner.next_notice().is_err()); // cannot consume entity as selector/channel
        assert_eq!(owner.poll().unwrap(), 0);
        assert_eq!(owner.next_event().unwrap(), Some(notice([0x80, 2])));
        assert_eq!(owner.poll().unwrap(), 0); // second event still holds back rearm
        assert_eq!(owner.next_event().unwrap(), Some(notice([0xc0, 4])));
        assert_eq!(owner.next_event().unwrap(), None);
        assert_eq!(audio.binding(), &binding); // neither event changes PCM authority
        assert_eq!(owner.poll().unwrap(), 0);
        assert!(model.borrow().active[3].is_some());
        assert_eq!(
            (owner.packet.physical(), owner.allocator.remaining()),
            geometry
        );
    }
    owner.stop().unwrap();
    assert!(owner.ticket.is_none() && !owner.configured);
    assert!(model.borrow().seen.contains(&15));
    assert!(model.borrow().seen.contains(&16));
    assert!(model.borrow().seen.contains(&12));
    owner.start().unwrap();
    model.borrow_mut().push_event(vec![0, 2]);
    assert_eq!(owner.poll().unwrap(), 1); // donor does not gate on IRQ_PENDING
    assert_eq!(owner.next_event().unwrap(), Some(notice([0, 2])));
    owner.stop().unwrap();
}

#[test]
fn actual_uac1_foreign_reserved_unknown_and_truncated_words_publish_no_prefix() {
    let mut backing = memory();
    let mut dma = allocator(&mut backing);
    let (audio, model, _) = peer_configuration(&mut dma, &configuration(4));
    let mut owner = audio.status_notifications(&mut dma).unwrap().unwrap();
    owner.start().unwrap();
    let bad = [
        vec![0x80, 2, 0x81, 3],  // streaming interface origin
        vec![0x80, 2, 0x82, 1],  // streaming endpoint origin
        vec![0x80, 2, 0x90, 2],  // reserved bit 4
        vec![0x80, 2, 0xa0, 2],  // reserved bit 5
        vec![0x80, 2, 0x80, 0],  // interface-wide protocol not retained
        vec![0x80, 2, 0x80, 99], // absent entity
        vec![0x80],
        vec![0x80, 2, 0x80], // do not silently drop a trailing half-word
    ];
    for packet in bad {
        model.borrow_mut().push_event(packet);
        assert!(owner.poll().is_err());
        assert!(owner.notices.is_empty() && owner.ticket.is_none());
        assert!(!owner.poisoned);
        assert_eq!(owner.next_event().unwrap(), None);
        assert_eq!(owner.poll().unwrap(), 0);
    }
    model.borrow_mut().push_event(vec![0x40, 2]);
    assert_eq!(owner.poll().unwrap(), 1);
    assert_eq!(owner.next_event().unwrap(), Some(notice([0x40, 2])));
    owner.stop().unwrap();
}

#[test]
fn uac1_two_byte_endpoint_admission_uses_actual_protocol_and_exclusive_dci() {
    for speed in [xhci::FULL_SPEED, xhci::HIGH_SPEED] {
        let raw = configuration(2);
        let all = xhci::interfaces(&raw);
        let binding = Binding::parse(&all[0], &all, &raw, speed).unwrap();
        let plan = StatusPlan::discover(&binding, &raw).unwrap().unwrap();
        assert_eq!(plan.message_bytes(), 2);
        assert_eq!(plan.endpoint.max_packet, 2);
        let mut wrong = raw.clone();
        wrong[16] = UAC2; // actual AC bInterfaceProtocol disagrees with binding
        assert!(StatusPlan::discover(&binding, &wrong).is_err());
        let mut alias = raw.clone();
        alias.extend_from_slice(&[9, 4, 8, 0, 1, 3, 0, 0, 0, 7, 5, 0x81, 3, 2, 0, 4]);
        assert!(StatusPlan::discover(&binding, &alias).is_err());
        assert!(StatusPlan::discover(&binding, &configuration(1)).is_err());
    }
    let mut backing = memory();
    let mut dma = allocator(&mut backing);
    let (audio, model, _) = peer_configuration(&mut dma, &configuration(2));
    let mut owner = audio.status_notifications(&mut dma).unwrap().unwrap();
    let mut contender = audio.status_notifications(&mut dma).unwrap().unwrap();
    owner.start().unwrap();
    let pending = model.borrow().active[3];
    assert!(contender.start().is_err());
    assert!(!contender.configured);
    contender.stop().unwrap();
    assert_eq!(model.borrow().active[3], pending);
    owner.stop().unwrap();
}

#[test]
fn actual_uac1_stall_usb_clear_failure_retains_dma_until_real_recovery() {
    let mut backing = memory();
    let mut dma = allocator(&mut backing);
    let (audio, model, _) = peer_configuration(&mut dma, &configuration(2));
    let mut owner = audio.status_notifications(&mut dma).unwrap().unwrap();
    // The peer consumes halt injection when the actual start doorbell publishes
    // this TD, before polling observes its terminal STALL event.
    model.borrow_mut().halt_transfer = Some(3);
    owner.start().unwrap();
    let original = model.borrow().active[3].unwrap();
    assert!(matches!(
        owner.poll(),
        Err(Error::Transport(crate::block::BlockError::Device {
            status: 6
        }))
    ));
    assert_eq!(model.borrow().active[3], Some(original));
    assert!(owner.poisoned && owner.ticket.is_some());
    assert_eq!(owner.next_event(), Err(Error::Poisoned));
    let geometry = (
        owner.packet.physical(),
        owner._arena.physical(),
        owner.allocator.remaining(),
    );
    model.borrow_mut().stall_control = Some(1);
    let drops = model.borrow().seen.iter().filter(|&&c| c == 12).count();
    assert!(owner.stop().is_err());
    assert!(owner.cancelled && owner.configured && owner.poisoned);
    assert_eq!(
        model.borrow().seen.iter().filter(|&&c| c == 12).count(),
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
    model.borrow_mut().stall_control = None;
    owner.stop().unwrap();
    assert!(!owner.poisoned && !owner.configured);
    assert_eq!(model.borrow().halt_transfer, None);
    assert!(model.borrow().seen.contains(&14));
    owner.start().unwrap();
    model.borrow_mut().push_event(vec![0x80, 2]);
    assert_eq!(owner.poll().unwrap(), 1);
    assert_eq!(owner.next_event().unwrap(), Some(notice([0x80, 2])));
    owner.stop().unwrap();
}

#[test]
fn actual_uac1_cached_event_refuses_retired_device_before_any_mmio() {
    let mut backing = memory();
    let mut dma = allocator(&mut backing);
    let (audio, model, _) = peer_configuration(&mut dma, &configuration(2));
    let mut owner = audio.status_notifications(&mut dma).unwrap().unwrap();
    owner.start().unwrap();
    model.borrow_mut().push_event(vec![0x80, 2]);
    assert_eq!(owner.poll().unwrap(), 1);
    let queued = owner.notices.clone();
    let (_, _, foreign) = peer_configuration(&mut dma, &configuration(2));
    foreign.borrow_mut().forbid_mmio();
    owner.shared = foreign;
    assert!(owner.next_event().is_err());
    assert!(owner.next_notice().is_err());
    assert!(owner.poll().is_err());
    assert!(owner.stop().is_err());
    assert_eq!(owner.notices, queued);
}

#[test]
#[ignore = "requires unchanged-source Linux USB audio status oracle trace"]
fn uac1_unchanged_linux_irq_callback_oracle() {
    use sha2::{Digest, Sha256};
    let path = std::env::var("STELA_USB_AUDIO_STATUS_ORACLE")
        .expect("set STELA_USB_AUDIO_STATUS_ORACLE to source oracle trace.txt");
    let trace = std::fs::read_to_string(path).unwrap();
    assert_eq!(
        alloc::format!("{:x}", Sha256::digest(trace.as_bytes())),
        "260f6feea2211f7be7d97c0ffa9e267955c0d36108a6db20d021658a97f4f1f9"
    );
    let mut lines = trace.lines();
    assert_eq!(
        lines.next(),
        Some("linux cc9de5d4b5ab6459f5774946aa3195ad51236fa8")
    );
    let raw = configuration(4);
    let all = xhci::interfaces(&raw);
    let binding = Binding::parse(&all[0], &all, &raw, xhci::HIGH_SPEED).unwrap();
    let plan = StatusPlan::discover(&binding, &raw).unwrap().unwrap();
    let mut words = 0;
    let mut admitted = 0;
    let mut errors = 0;
    let mut lengths = 0;
    for line in lines {
        let columns: Vec<_> = line.split_whitespace().collect();
        let numbers: Vec<i32> = columns[1..].iter().map(|n| n.parse().unwrap()).collect();
        match columns[0] {
            "word" => {
                assert_eq!(numbers.len(), 6);
                let [status, entity, controls, memories, queued, unit] = numbers[..] else {
                    unreachable!()
                };
                assert_eq!(queued, 1);
                let event = plan.event(&[status as u8, entity as u8]);
                if status & 0x3f == 0 && binding.graph.entity(entity as u8).is_ok() {
                    let StatusEvent::Uac1(observed) = event.unwrap() else {
                        panic!("UAC1 protocol")
                    };
                    assert_eq!(unit, entity);
                    assert_eq!(controls + memories, 1);
                    assert_eq!(observed.memory_changed, memories == 1);
                    assert_eq!(observed.raw, [status as u8, entity as u8]);
                    admitted += 1;
                } else {
                    // Linux ignores reserved bits and looks up unknown IDs in
                    // later callbacks. Stela refuses both at its retained graph
                    // boundary, without publishing any valid packet prefix.
                    assert!(event.is_err());
                }
                words += 1;
            }
            "error" => {
                assert_eq!(numbers.len(), 4);
                let [error, controls, memories, queued] = numbers[..] else {
                    unreachable!()
                };
                assert_eq!(controls, i32::from(error == 0));
                assert_eq!(memories, 0);
                assert_eq!(queued, i32::from(![-2, -104, -108].contains(&error)));
                errors += 1;
            }
            "length" => {
                assert_eq!(numbers.len(), 4);
                let [length, controls, memories, queued] = numbers[..] else {
                    unreachable!()
                };
                assert_eq!((controls, memories, queued), (length / 2, 0, 1));
                // The donor discards a trailing half-word. Native whole-packet
                // refusal is deliberately stronger and tested through actual DMA.
                lengths += 1;
            }
            kind => panic!("unknown source oracle record {kind}"),
        }
    }
    assert_eq!((words, admitted, errors, lengths), (2048, 20, 7, 9));
}
