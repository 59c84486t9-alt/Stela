// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual descriptor-qualified native EP0 and interrupt DMA observations.
use super::*;
use crate::{
    block::BlockError,
    bus::dma::{DmaAllocator, RegionAllocator},
    usb::{
        audio::{Plan, UsbAudio},
        xhci::{Device, Shared},
    },
};
use alloc::{rc::Rc, vec};
use core::cell::RefCell;

fn configuration(access: u8) -> Vec<u8> {
    let mut raw = crate::usb::audio::test_configuration();
    let output = raw
        .windows(12)
        .position(|d| d[..9] == [12, 0x24, 3, 3, 1, 3, 0, 2, 10])
        .unwrap();
    raw[output + 9] = access << 2;
    let input = raw
        .windows(17)
        .position(|d| d[..8] == [17, 0x24, 2, 4, 1, 2, 0, 10])
        .unwrap();
    raw[input + 14] = access << 2;
    let control = raw
        .windows(9)
        .position(|d| d == [9, 4, 0, 0, 0, 1, 1, 0x20, 0])
        .unwrap();
    raw[control + 4] = 1;
    let after = raw
        .windows(9)
        .position(|d| d == [9, 4, 1, 0, 0, 1, 2, 0x20, 0])
        .unwrap();
    raw.splice(after..after, [7, 5, 0x81, 3, 12, 0, 4]);
    let total = raw.len() as u16;
    raw[2..4].copy_from_slice(&total.to_le_bytes());
    raw
}
fn peer(
    dma: &mut dyn DmaAllocator,
    access: u8,
) -> (UsbAudio, Rc<RefCell<xhci::model::CancelModel>>, Shared) {
    let raw = configuration(access);
    let (mut controller, model) = xhci::model::status_interrupt_controller(dma, &raw);
    controller.set_configuration(1, 1).unwrap();
    let shared = Rc::new(RefCell::new(controller));
    let device = Device {
        id: shared.borrow().test_device_id(1).unwrap(),
        slot: 1,
        speed: xhci::HIGH_SPEED,
        location: "descriptor-qualified UAC2 native connector peer".into(),
        descriptor: [18, 1, 0, 2, 0, 0, 0, 64, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1],
        configurations: vec![raw.clone()],
        configuration: raw.clone(),
        manufacturer: None,
        product: None,
        serial: None,
        language: None,
        vendor_ethernet_tcr: None,
        vendor_ethernet_revision: None,
    };
    let all = xhci::interfaces(&raw);
    let plan = Plan::parse(&all[0], &all, &raw, xhci::HIGH_SPEED).unwrap();
    let owner = UsbAudio::attach(shared.clone(), &device, plan, dma).unwrap();
    (owner, model, shared)
}
fn allocator(memory: &mut [u64]) -> RegionAllocator {
    let start = memory.as_mut_ptr() as u64;
    // SAFETY: exclusive backing outlives all controller and audio DMA owners.
    unsafe { RegionAllocator::new(start..start + memory.len() as u64 * 8) }
}

#[test]
fn actual_native_terminal_queries_preserve_raw_connected_channels_with_pcm_owned() {
    let mut backing = vec![0u64; 512 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut audio, model, _) = peer(&mut dma, 1);
    // PCM must consume genuine device validity, RANGE, current-frequency and
    // validity replies before the native isochronous queue can be owned. The
    // connector peer has no implicit clock responses or synthetic startup.
    model.borrow_mut().control_replies.extend([
        (xhci::setup(0xa1, 1, 0x0200, 0x0a00, 1), vec![1]),
        (xhci::setup(0xa1, 2, 0x0100, 0x0a00, 2), vec![1, 0]),
        (
            xhci::setup(0xa1, 2, 0x0100, 0x0a00, 14),
            vec![1, 0, 0x80, 0xbb, 0, 0, 0x80, 0xbb, 0, 0, 0, 0, 0, 0],
        ),
        (
            xhci::setup(0xa1, 1, 0x0100, 0x0a00, 4),
            vec![0x80, 0xbb, 0, 0],
        ),
        (xhci::setup(0xa1, 1, 0x0200, 0x0a00, 1), vec![1]),
    ]);
    audio
        .start_playback(0, 48_000, &[0x55; 12288], false)
        .unwrap();
    assert!(model.borrow().control_replies.is_empty());
    assert!(audio.progress().queued_playback > 0);
    for terminal in [3, 4] {
        for raw in [
            [0, 0, 0, 0, 0, 0],
            [2, 3, 0, 0, 0, 7],
            [5, 0x35, 0, 0, 0x80, 9],
        ] {
            let request = xhci::setup(0xa1, 1, 0x0200, u16::from(terminal) << 8, 6);
            model
                .borrow_mut()
                .control_replies
                .push_back((request, raw.to_vec()));
            let observed = audio.connector_status(terminal).unwrap();
            assert_eq!(observed.terminal, terminal);
            assert_eq!(
                observed.terminal_type,
                if terminal == 3 { 0x301 } else { 0x201 }
            );
            assert_eq!(observed.raw, raw);
            assert_eq!(observed.channels, raw[0]);
            assert_eq!(
                observed.channel_config,
                u32::from_le_bytes(raw[1..5].try_into().unwrap())
            );
            assert_eq!(observed.channel_names, raw[5]);
            assert_eq!(observed.connected(), raw[0] != 0);
            assert!(model.borrow().control_replies.is_empty());
            assert!(audio.progress().queued_playback > 0);
        }
    }
    audio.shutdown().unwrap();
}

#[test]
fn absent_reserved_or_foreign_connector_access_does_not_submit_a_control() {
    for access in [0, 2] {
        let mut backing = vec![0u64; 512 * 1024];
        let mut dma = allocator(&mut backing);
        let (mut audio, model, _) = peer(&mut dma, access);
        let before = model.borrow().setup.len();
        assert!(audio.connector_status(3).is_err());
        assert!(audio.connector_status(4).is_err());
        assert!(audio.connector_status(2).is_err());
        assert!(audio.connector_status(255).is_err());
        assert_eq!(model.borrow().setup.len(), before);
        audio.shutdown().unwrap();
    }
}

#[test]
fn actual_short_or_stalled_connector_query_never_fabricates_connected_state() {
    for stalled in [false, true] {
        let mut backing = vec![0u64; 512 * 1024];
        let mut dma = allocator(&mut backing);
        let (mut audio, model, _) = peer(&mut dma, 3);
        if stalled {
            model.borrow_mut().stall_control = Some(1);
            assert_eq!(
                audio.connector_status(3),
                Err(Error::Transport(BlockError::Device { status: 6 }))
            );
            // The first failed request actually halted EP0 and the engine
            // acknowledged Reset Endpoint + Set Dequeue before returning it.
            assert!(model.borrow().seen.contains(&14));
            assert!(model.borrow().seen.contains(&16));
            model.borrow_mut().stall_control = None;
        } else {
            model
                .borrow_mut()
                .control_replies
                .push_back((xhci::setup(0xa1, 1, 0x0200, 0x0300, 6), vec![2, 3, 0, 0, 0]));
            assert_eq!(audio.connector_status(3), Err(Error::ControlLength));
        }
        // A later actual complete observation can succeed after the native
        // EP0 engine's genuine acknowledged recovery; the failed read cached
        // no connected/disconnected replacement and changed no terminal state.
        model
            .borrow_mut()
            .control_replies
            .push_back((xhci::setup(0xa1, 1, 0x0200, 0x0300, 6), vec![0; 6]));
        assert!(!audio.connector_status(3).unwrap().connected());
        audio.shutdown().unwrap();
    }
}

#[test]
fn actual_connector_interrupt_invalidates_but_never_replaces_a_status_query() {
    let mut backing = vec![0u64; 512 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut audio, model, _) = peer(&mut dma, 1);
    let mut status = audio.status_notifications(&mut dma).unwrap().unwrap();
    status.start().unwrap();
    for terminal in [3, 4] {
        let raw = [0, 1, 0, 2, 0, terminal];
        model.borrow_mut().push_event(raw.to_vec());
        assert_eq!(status.poll().unwrap(), 1);
        let notice = status.next_notice().unwrap().unwrap();
        assert_eq!(notice.raw, raw);
        model.borrow_mut().control_replies.push_back((
            xhci::setup(0xa1, 1, 0x0200, u16::from(terminal) << 8, 6),
            vec![2, 3, 0, 0, 0, 0],
        ));
        assert_eq!(audio.connector_status(terminal).unwrap().channels, 2);
        assert_eq!(status.poll().unwrap(), 0);
    }
    for raw in [
        [0, 2, 0, 2, 0, 3],
        [0, 1, 1, 2, 0, 3],
        [0, 1, 0, 1, 0, 3],
        [0, 1, 0, 2, 0, 1],
    ] {
        model.borrow_mut().push_event(raw.to_vec());
        assert!(status.poll().is_err());
        assert!(status.next_notice().unwrap().is_none());
        assert_eq!(status.poll().unwrap(), 0);
    }
    status.stop().unwrap();
    audio.shutdown().unwrap();
}

#[test]
#[ignore = "oracle: STELA_USB_AUDIO_CONNECTOR_ORACLE"]
fn native_connectors_match_original_linux_complete_control_observations() {
    extern crate std;
    use sha2::{Digest, Sha256};
    let trace = std::fs::read_to_string(
        std::env::var("STELA_USB_AUDIO_CONNECTOR_ORACLE")
            .expect("set STELA_USB_AUDIO_CONNECTOR_ORACLE to source trace.txt"),
    )
    .unwrap();
    assert_eq!(
        alloc::format!("{:x}", Sha256::digest(trace.as_bytes())),
        "ed984665251a0a564350fec62e33debf2dc3359493e7a8f7d10c0e7d2a139a65"
    );
    let mut lines = trace.lines();
    assert_eq!(
        lines.next(),
        Some("linux cc9de5d4b5ab6459f5774946aa3195ad51236fa8")
    );
    let mut backing = vec![0u64; 512 * 1024];
    let mut dma = allocator(&mut backing);
    let (mut audio, model, _) = peer(&mut dma, 1);
    let (mut records, mut actual) = (0, 0);
    for line in lines {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields[0], "C");
        let fields: Vec<i32> = fields[1..].iter().map(|v| v.parse().unwrap()).collect();
        let [
            interface,
            terminal,
            channels,
            reply,
            speaker,
            result,
            connected,
            request,
            kind,
            value,
            index,
            bytes,
        ] = fields[..]
        else {
            panic!("original connector row")
        };
        records += 1;
        if interface != 0 || reply != 6 || speaker != 0 {
            continue;
        }
        assert_eq!(result, 6);
        let request = xhci::setup(
            kind as u8,
            request as u8,
            value as u16,
            index as u16,
            bytes as u16,
        );
        let raw = vec![channels as u8, 0, 0, 0, 0, 0];
        model
            .borrow_mut()
            .control_replies
            .push_back((request, raw.clone()));
        let observed = audio.connector_status(terminal as u8).unwrap();
        assert_eq!(observed.connected(), connected != 0);
        assert_eq!(observed.channels, channels as u8);
        assert_eq!(observed.raw.as_slice(), raw);
        assert_eq!(model.borrow().setup.last(), Some(&(request, raw)));
        actual += 1;
    }
    assert_eq!((records, actual), (6144, 512));
    audio.shutdown().unwrap();
}
