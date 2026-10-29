use crate::bus::thunderbolt::ring::{self, Direction, model::*};

use core::sync::atomic::Ordering;

extern crate std;
use super::*;
fn message(code: u8, index: u8, count: u8, flags: u8, info: u16, words: usize) -> Message {
    let mut data = vec![0; words];
    data[0] = u32::from(code)
        | (u32::from(flags) << 8)
        | (u32::from(index) << 16)
        | (u32::from(count) << 24);
    if words > 1 {
        data[1] = u32::from(info) << 16;
    }
    let mut wire = Vec::new();
    for word in data {
        wire.extend_from_slice(&word.to_be_bytes());
    }
    wire.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    Message::decode(PacketType::IcmResponse, 15, &wire).unwrap()
}
#[test]
fn icm_preserves_unverified_trailer_unknown_event_and_sof() {
    let mut raw = message(0xfe, 0xff, 0, 0xa4, 0xffff, 2);
    raw.kind = PacketType::IcmEvent;
    let decoded = Message::decode(raw.kind, raw.sof, &raw.raw_wire).unwrap();
    assert_eq!(raw, decoded);
    assert_eq!(decoded.unverified_trailer, [0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(decoded.sof, 15);
    for length in 0..=260 {
        let result = Message::decode(PacketType::IcmResponse, 0, &vec![0; length]);
        assert_eq!(
            result.is_ok(),
            (8..=256).contains(&length) && length % 4 == 0
        );
    }
    assert_eq!(
        Message::decode(PacketType::Read, 0, &[0; 8]),
        Err(Error::WrongType)
    );
}
#[test]
fn icm_assembly_requires_all_fragments_and_is_single_use() {
    for count in 1..=MAX_PACKETS {
        let mut assembly = Assembly::new(3, 2, count).unwrap();
        for index in (0..count).rev() {
            let packet = message(3, index as u8, count as u8, 0, index as u16, 2);
            let result = assembly.receive(packet.clone()).unwrap();
            if index != 0 {
                assert!(result.is_none());
                assert!(assembly.receive(packet).unwrap().is_none());
            } else {
                let complete = result.unwrap();
                assert_eq!(complete.len(), count);
                for (i, packet) in complete.iter().enumerate() {
                    assert_eq!(usize::from(packet.packet_id), i);
                }
                assert_eq!(assembly.receive(packet), Err(Error::Stopped));
            }
        }
    }
}
#[test]
fn icm_assembly_refuses_conflicts_and_malformed_responses() {
    let mut assembly = Assembly::new(3, 2, 2).unwrap();
    assert_eq!(
        assembly.receive(message(4, 0, 2, 0, 0, 2)),
        Err(Error::WrongCode)
    );
    assert_eq!(
        assembly.receive(message(3, 0, 1, 0, 0, 2)),
        Err(Error::PacketCount)
    );
    assert_eq!(
        assembly.receive(message(3, 2, 2, 0, 0, 2)),
        Err(Error::PacketIndex)
    );
    assert_eq!(
        assembly.receive(message(3, 0, 2, 0, 0, 1)),
        Err(Error::Length)
    );
    assert_eq!(
        assembly.receive(message(3, 0, 2, 1, 0, 2)),
        Err(Error::FirmwareError(1))
    );
    assert!(
        assembly
            .receive(message(3, 0, 2, 0, 0, 2))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        assembly.receive(message(3, 0, 2, 0, 1, 2)),
        Err(Error::DuplicateConflict)
    );
    assert!(Assembly::new(3, 0, 1).is_err());
    assert!(Assembly::new(3, 64, 1).is_err());
    assert!(Assembly::new(3, 2, 0).is_err());
    assert!(Assembly::new(3, 2, 15).is_err());
}
#[test]
fn icm_protocol_parameters_preserve_unsupported_and_unknown_values() {
    let alpine = DriverReady::parse(Family::Alpine, message(3, 0, 1, 64, 15, 2)).unwrap();
    assert_eq!(alpine.security, Some(Security::Unknown(15)));
    assert_eq!(alpine.boot_acl_slots, None);
    assert_eq!(alpine.protocol_version, None);
    assert!(alpine.runtime_pm);
    let info = (1 << 13) | (31 << 7) | 7;
    let alpine = DriverReady::parse(Family::Alpine, message(3, 0, 1, 0, info, 2)).unwrap();
    assert_eq!(alpine.boot_acl_slots, Some(31));
    for family in [Family::Titan, Family::Maple] {
        let parsed = DriverReady::parse(family, message(3, 0, 1, 0, 0xffff, 4)).unwrap();
        assert_eq!(parsed.security, Some(Security::Unknown(7)));
        assert_eq!(parsed.protocol_version, Some(7));
        assert_eq!(parsed.boot_acl_slots, Some(63));
        assert!(!parsed.runtime_pm);
    }
    let ice = DriverReady::parse(Family::IceLake, message(3, 0, 1, 0, 0xffff, 4)).unwrap();
    assert_eq!(ice.security, None);
    assert_eq!(ice.boot_acl_slots, None);
    assert!(ice.runtime_pm);
    assert_eq!(
        DriverReady::parse(Family::Titan, message(3, 0, 1, 1, 0, 4)),
        Err(Error::FirmwareError(1))
    );
}
#[test]
#[ignore = "oracle: STELA_THUNDERBOLT_ICM_ORACLE"]
fn unchanged_linux_icm_driver_ready_and_command_wire_agree() {
    use std::{env, fs};
    let trace =
        fs::read_to_string(env::var("STELA_THUNDERBOLT_ICM_ORACLE").expect("set ICM trace"))
            .unwrap();
    let mut count = 0;
    for line in trace.lines() {
        let f: Vec<_> = line.split_ascii_whitespace().collect();
        assert_eq!(f[0], "I");
        let n = |i: usize| f[i].parse::<u64>().unwrap();
        let family = match n(1) {
            0 => Family::Alpine,
            1 => Family::Titan,
            2 => Family::IceLake,
            3 => Family::Maple,
            _ => panic!("family"),
        };
        let parsed = DriverReady::parse(
            family,
            message(3, 0, 1, n(3) as u8, n(2) as u16, family.words()),
        )
        .unwrap();
        assert_eq!(
            parsed.security,
            if n(4) == 99 {
                None
            } else {
                Some(Security::from_raw(n(4) as u8))
            }
        );
        assert_eq!(
            parsed.protocol_version,
            if n(5) == 99 { None } else { Some(n(5) as u8) }
        );
        assert_eq!(
            parsed.boot_acl_slots,
            if n(6) == 999 { None } else { Some(n(6) as u8) }
        );
        assert_eq!(parsed.runtime_pm, n(7) != 0);
        assert_eq!(family.timeout_ms(), n(8));
        assert_eq!(
            n(9),
            if matches!(family, Family::Titan | Family::Maple) {
                10
            } else {
                3
            }
        );
        let command = config::encode(PacketType::IcmCommand, &[3]).unwrap();
        assert_eq!(n(10), command.kind as u64);
        assert_eq!(n(11), command.kind as u64);
        assert_eq!(n(12), command.bytes.len() as u64);
        let wire: Vec<u8> = f[13]
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u8::from_str_radix(core::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(command.bytes, wire);
        count += 1;
    }
    assert_eq!(count, 4096);
}

#[test]
fn icm_actual_dma_driver_ready_and_raw_notification_wrap_rings() {
    use super::super::icm::{Event, Security};
    let (_source, domain, model, mut host) = icm(0x15e8);
    host.start(0).unwrap();
    let mut rx = 0;
    for index in 0..25 {
        let request = host.driver_ready(index * 2).unwrap();
        let txindex = index as usize % 10;
        let wire = domain.data(model.frame_address(Direction::Tx, txindex), 8);
        assert_eq!(wire, incoming(PacketType::IcmCommand, &[3]).bytes);
        let descriptor = domain.read32(model.descriptor_address(Direction::Tx, txindex) + 8);
        assert_eq!((descriptor >> 12) & 0xf, 11);
        assert_eq!((descriptor >> 16) & 0xf, 11);
        model.finish(Direction::Tx, txindex, &[], None);
        if index == 0 {
            let mut event = incoming(PacketType::IcmEvent, &[0x00fe_40fe, 0xdeadbeef]);
            let len = event.bytes.len();
            event.bytes[len - 4..].copy_from_slice(&[1, 2, 3, 4]);
            model.finish(
                Direction::Rx,
                rx,
                &event.bytes,
                Some((2 << 20) | (15 << 16) | (10 << 12) | (len as u32)),
            );
            match host.poll(1).unwrap().unwrap() {
                Event::Notification(m) => {
                    assert_eq!(m.code, 0xfe);
                    assert_eq!(m.sof, 15);
                    assert_eq!(m.unverified_trailer, [1, 2, 3, 4]);
                }
                other => panic!("{other:?}"),
            }
            rx = (rx + 1) % 10;
            assert_eq!(host.driver_ready(1), Err(super::super::icm::Error::Busy));
        }
        let reply = incoming(
            PacketType::IcmResponse,
            &[0x01004003, 0x00920000, 0x12345678, 0xabcdef01],
        );
        finish_rx(&model, rx, &reply);
        rx = (rx + 1) % 10;
        match host.poll(index * 2 + 1).unwrap().unwrap() {
            Event::DriverReady {
                request: id,
                parameters,
            } => {
                assert_eq!(id, request);
                assert_eq!(parameters.security, Some(Security::Secure));
                assert_eq!(parameters.protocol_version, Some(1));
                assert_eq!(parameters.boot_acl_slots, Some(1));
                assert!(parameters.runtime_pm);
            }
            other => panic!("{other:?}"),
        }
    }
    icm_release(&mut host);
}

#[test]
fn icm_timeout_never_reuses_ambiguous_firmware_code() {
    use super::super::icm::Error;
    for (device, timeout) in [
        (0x1575, 5000),
        (0x15e8, 250),
        (0x1134, 250),
        (0x8a0d, 20000),
    ] {
        let (_source, _domain, model, mut host) = icm(device);
        host.start(100).unwrap();
        let id = host.driver_ready(100).unwrap();
        assert!(host.poll(100 + timeout - 1).unwrap().is_none());
        assert_eq!(
            host.poll(100 + timeout),
            Err(Error::Timeout { request: id })
        );
        assert_eq!(host.driver_ready(101 + timeout), Err(Error::Poisoned));
        let writes = model.state.lock().unwrap().writes.len();
        assert_eq!(host.poll(102 + timeout), Err(Error::Poisoned));
        assert_eq!(model.state.lock().unwrap().writes.len(), writes);
        icm_release(&mut host);
    }
}

#[test]
fn icm_firmware_error_and_epoch_observation_loss_poison() {
    use super::super::icm::Error;
    for loss in [false, true] {
        let (_source, _domain, model, mut host) = icm(0x9a1b);
        host.start(0).unwrap();
        host.driver_ready(0).unwrap();
        finish_rx(
            &model,
            0,
            &incoming(PacketType::IcmResponse, &[0x01000103, 0, 0, 0]),
        );
        if loss {
            model.state.lock().unwrap().values[0x39944 / 4] = 0;
        }
        assert_eq!(
            host.poll(1),
            Err(if loss {
                Error::FirmwareNotAuthenticated
            } else {
                Error::FirmwareError(1)
            })
        );
        assert_eq!(host.driver_ready(2), Err(Error::Poisoned));
        icm_release(&mut host);
    }
}

#[test]
fn icm_prerequisites_refuse_before_any_ring_programming() {
    use super::super::icm::{Error, Host};
    for (device, command, status, mode, expected) in [
        (0xdead, 6, 0x80000001, 3, Error::Unsupported),
        (0x1575, 2, 0x80000001, 3, Error::PciState),
        (0x1575, 6, 0x80000000, 3, Error::FirmwareNotRunning),
        (0x15e8, 6, 1, 3, Error::FirmwareNotAuthenticated),
        (0x1134, 6, 0x80000001, 0, Error::SafeMode),
        (0x1575, 6, 0x80000001, 2, Error::WrongMode(2)),
        (0x9a1b, 6, 1, 0, Error::FirmwareNotAuthenticated),
    ] {
        let source = Source::new();
        let domain = Arc::new(Domain::new());
        let model = Arc::new(Model::new(domain.clone()));
        model.state.lock().unwrap().values[0x39944 / 4] = status;
        model.state.lock().unwrap().values[0x3990c / 4] = mode << 8;
        // SAFETY: negative synthetic prerequisites cannot authorize any DMA.
        let result = unsafe {
            Host::new(
                &IcmPci { device, command },
                model.clone(),
                &source,
                domain,
                u64::MAX,
            )
        };
        assert!(matches!(result,Err(error) if error==expected));
        assert!(model.state.lock().unwrap().writes.is_empty());
    }
    let (_source, _domain, model, mut host) = icm(0x8a0d);
    model.state.lock().unwrap().values[0x39944 / 4] = 0;
    host.start(0).unwrap();
    icm_release(&mut host);
}

#[test]
fn icm_malformed_frame_keeps_request_pending_until_real_reply() {
    use super::super::icm::{Error, Event};
    let (_source, _domain, model, mut host) = icm(0x1575);
    host.start(0).unwrap();
    let id = host.driver_ready(0).unwrap();
    for (index, words, error) in [
        (0, vec![0x01000004, 0], Error::WrongCode),
        (1, vec![0x02000003, 0], Error::PacketCount),
        (2, vec![0x01000003], Error::Length),
    ] {
        finish_rx(&model, index, &incoming(PacketType::IcmResponse, &words));
        assert_eq!(
            host.poll(1 + index as u64),
            Ok(Some(Event::Discarded(error)))
        );
        assert_eq!(host.driver_ready(1 + index as u64), Err(Error::Busy));
    }
    finish_rx(
        &model,
        3,
        &incoming(PacketType::IcmResponse, &[0x01000003, 0]),
    );
    assert!(matches!(host.poll(4),Ok(Some(Event::DriverReady{request,..})) if request==id));
    icm_release(&mut host);
}

#[test]
fn icm_tx_backpressure_never_publishes_a_ghost_request_and_release_retries() {
    use super::super::icm::{Error, Event};
    let (_source, domain, model, mut host) = icm(0x15e8);
    host.start(0).unwrap();
    // Firmware has replied but the modeled TX descriptor consumer is stalled.
    for i in 0..9 {
        let id = host.driver_ready(i * 2).unwrap();
        finish_rx(
            &model,
            i as usize,
            &incoming(PacketType::IcmResponse, &[0x01000003, 0, 0, 0]),
        );
        assert!(matches!(host.poll(i*2+1),Ok(Some(Event::DriverReady{request,..})) if request==id));
    }
    let writes = model.state.lock().unwrap().writes.len();
    assert_eq!(host.driver_ready(20), Err(Error::Ring(ring::Error::Full)));
    assert_eq!(model.state.lock().unwrap().writes.len(), writes);
    model.finish(Direction::Tx, 0, &[], None);
    assert_eq!(host.poll(21), Ok(None));
    assert_eq!(host.driver_ready(22), Ok(10));
    host.disable().unwrap();
    domain.fail_unmap_at.store(12, Ordering::Relaxed);
    // SAFETY: final synthetic device/IRQ/work drain is complete, including
    // the active request. Failed invalidation keeps its mapping for retry.
    assert!(unsafe { host.release() }.is_err());
    assert!(!domain.state.lock().unwrap().maps.is_empty());
    // SAFETY: the same exact drained reservation remains held.
    unsafe { host.release() }.unwrap();
    assert!(domain.state.lock().unwrap().maps.is_empty());
}
