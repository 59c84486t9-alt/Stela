use super::*;
use crate::Result;
use crate::platform::apple::sep::endpoint::Service;
use stela_contracts::refuse;

fn shm(address: u64, pages: u16) -> Frame {
    Frame {
        service: message::BOOT,
        tag: 0,
        opcode: pages as u8,
        parameter: (pages >> 8) as u8,
        data: (address >> 12) as u32,
    }
}

fn control(tag: u8, opcode: u8, parameter: u8, data: u32) -> Frame {
    Frame {
        service: message::CONTROL,
        tag,
        opcode,
        parameter,
        data,
    }
}

fn counter() -> impl FnMut(&mut [u8]) -> Result<()> {
    let mut next = 0u8;
    move |bytes: &mut [u8]| {
        for byte in bytes {
            next = next.wrapping_add(1);
            *byte = next;
        }
        Ok(())
    }
}

/// Service 9, taking one or two pages each way.
fn catalog() -> Catalog {
    Catalog::new(alloc::vec![Service {
        id: 9,
        name: u32::from_be_bytes(*b"test"),
        capacities: [1, 2, 1, 2],
    }])
    .unwrap()
}

fn store() -> Nonces<Box<dyn Backend>> {
    let roots = super::super::keys::Roots::provisioned([1; 32], [2; 32], 0xa5a5_0002).unwrap();
    let backend: Box<dyn Backend> = Box::new(super::super::store::Volatile::default());
    Nonces::provision(&roots, backend).unwrap()
}

fn active(security: Option<SecurityMode>) -> SepOs {
    let mut os = SepOs::new(security).with_catalog(catalog());
    map_shared(&mut os, shm(0x1234_4000, 0x20)).unwrap();
    os
}

fn reply(os: &mut SepOs, frame: Frame) -> Result<Vec<Frame>> {
    let mut outbox = Vec::new();
    os.receive(frame, &mut counter(), &mut outbox)?;
    Ok(outbox
        .into_iter()
        .map(|m| Frame::from_mailbox(m).unwrap())
        .collect())
}

fn map_shared(os: &mut SepOs, frame: Frame) -> Result<Vec<Frame>> {
    let region = Region::from_message(frame.mailbox())?;
    assert!(reply(os, frame)?.is_empty());
    let mut ram = stela_contracts::dma::test_support::Ram::new(region.address, 0x4000);
    ram.bytes[..4].copy_from_slice(&u32::from_be_bytes(*b"null").to_le_bytes());
    dma(os, &mut ram)
}

#[test]
fn mapping_shared_memory_reports_os_active_exactly_once() {
    let mut os = SepOs::new(None);
    assert!(!os.os_active_sent());
    let first = map_shared(&mut os, shm(0x1234_4000, 0x20)).unwrap();
    assert_eq!(
        os.region(),
        Some(Region {
            address: 0x1234_4000,
            bytes: 0x20 << 12,
        })
    );
    assert_eq!(first, [control::notification(control::OS_ACTIVE, 0)]);
    assert!(os.os_active_sent());
    // A cataloged service is advertised after OS active, name first.
    let mut os = SepOs::new(None).with_catalog(catalog());
    let first = map_shared(&mut os, shm(0x1234_4000, 0x20)).unwrap();
    assert_eq!(first[0], control::notification(control::OS_ACTIVE, 0));
    assert_eq!(first[1..], catalog().advertisements()[..]);
    assert_eq!((first[1].opcode, first[2].opcode), (0, 1));
    // A second shared-memory frame (wake remap) does not re-announce.
    assert!(
        map_shared(&mut os, shm(0x2000_0000, 0x10))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn tagged_control_requests_are_answered_with_their_tag_and_status() {
    let mode = SecurityMode {
        production: true,
        secure: true,
    };
    let mut os = active(Some(mode));
    let nop = control(3, control::NOP, 0, 0);
    assert_eq!(
        reply(&mut os, nop).unwrap(),
        [control::reply(nop, Status::Success, 0)]
    );
    let mode_request = control(4, control::SECURITY_MODE, 0, 0);
    assert_eq!(reply(&mut os, mode_request).unwrap()[0].data, 0b11);
    let entropy = control(5, control::ENTROPY, 0, 0);
    assert_eq!(
        reply(&mut os, entropy).unwrap(),
        [control::reply(entropy, Status::Success, 0x0403_0201)]
    );
    // OOL registration: length, then page address, owned by service 9.
    reply(&mut os, control(6, control::SET_OOL_IN_LENGTH, 9, 0x4000)).unwrap();
    reply(
        &mut os,
        control(7, control::SET_OOL_IN_ADDRESS, 9, 0x8_0000),
    )
    .unwrap();
    assert!(os.buffers(9).is_some());
    assert!(os.buffers(10).is_none());
    // Unadvertised owners and lengths outside the pages refuse.
    assert!(reply(&mut os, control(8, control::SET_OOL_IN_LENGTH, 10, 0x4000)).is_err());
    assert!(reply(&mut os, control(8, control::SET_OOL_OUT_LENGTH, 9, 0xc000)).is_err());
    assert!(reply(&mut os, control(8, control::SET_OOL_OUT_LENGTH, 9, 0x8000)).is_ok());
    // An unknown security mode refuses rather than guess one.
    let mut unknown = active(None);
    assert!(reply(&mut unknown, mode_request).is_err());
}

#[test]
fn sleep_nap_and_wake_follow_the_ap_power_sequence() {
    let mut os = active(None);
    reply(&mut os, control(1, control::SLEEP, 2, 0)).unwrap();
    assert_eq!(os.power(), Power::Asleep(2));
    // Asleep, only a wake is serviced.
    assert!(reply(&mut os, control(2, control::NOP, 0, 0)).is_err());
    reply(&mut os, control(3, control::WAKE, 0, 0)).unwrap();
    assert_eq!(os.power(), Power::Awake);
    assert!(reply(&mut os, control(4, control::WAKE, 0, 0)).is_err());
    // AP nap: no reply; the nap wake word is answered by NAP_AWAKE.
    assert!(
        reply(&mut os, control(0, control::NAP, 0, 0))
            .unwrap()
            .is_empty()
    );
    assert_eq!(os.power(), Power::Napping);
    assert_eq!(
        reply(&mut os, control(0, control::WAKE_FROM_NAP, 0, 0)).unwrap(),
        [control::notification(control::NAP_AWAKE, 0)]
    );
    assert!(reply(&mut os, control(0, control::WAKE_FROM_NAP, 0, 0)).is_err());
    assert!(
        reply(&mut os, control(0, control::AP_SLEEP_READY, 0, 0))
            .unwrap()
            .is_empty()
    );
    assert!(os.ap_sleep_ready());
}

struct Identity;
impl stela_contracts::dma::Iommu for Identity {
    fn page(&self) -> u64 {
        0x4000
    }
    fn translate(
        &mut self,
        _: &mut dyn stela_contracts::dma::Memory,
        _: usize,
        iova: u64,
        _: u64,
        _: bool,
        _: &mut stela_contracts::bus::Access<'_>,
    ) -> Result<u64, DmaError> {
        Ok(iova)
    }
}

/// One DMA step: its result and every frame it produced, which a failed
/// step may also have.
fn dma_step(
    os: &mut SepOs,
    ram: &mut stela_contracts::dma::test_support::Ram,
) -> (Result<()>, Vec<Frame>) {
    let mut latch = stela_contracts::interrupt::InterruptLatch::new();
    let mut access = stela_contracts::bus::Access::new(0, 0, &mut latch);
    let mut port = Port {
        iommu: &mut Identity,
        stream: 0,
        memory: ram,
        access: &mut access,
    };
    let mut outbox = Vec::new();
    let result = os.dma(
        &mut port,
        &mut |bytes: &mut [u8]| {
            bytes.fill(0x5a);
            Ok(())
        },
        &mut outbox,
    );
    let frames = outbox
        .into_iter()
        .map(|m| Frame::from_mailbox(m).unwrap())
        .collect();
    (result, frames)
}

fn dma(os: &mut SepOs, ram: &mut stela_contracts::dma::test_support::Ram) -> Result<Vec<Frame>> {
    let (result, frames) = dma_step(os, ram);
    result.map(|()| frames)
}

/// Register `service`'s OOL buffers: `input` bytes at 0x10_0000 and
/// `output` bytes right after.
fn register(os: &mut SepOs, service: u8, input: u32, output: u32) {
    for (tag, opcode, data) in [
        (1, control::SET_OOL_IN_LENGTH, input),
        (2, control::SET_OOL_IN_ADDRESS, 0x100),
        (3, control::SET_OOL_OUT_LENGTH, output),
        (4, control::SET_OOL_OUT_ADDRESS, 0x100 + (input >> 12)),
    ] {
        reply(os, control(tag, opcode, service, data)).unwrap();
    }
}

#[test]
fn xart_requests_are_answered_after_their_ool_input_is_read() {
    let mut os = SepOs::new(None).with_services(store(), false).unwrap();
    let advertised = map_shared(&mut os, shm(0x1234_4000, 0x20)).unwrap();
    // OS active, then name and capacities for each of xarm, xars, sks
    // and pnon.
    assert_eq!(advertised.len(), 9);
    assert_eq!(advertised[1].data, xart::MASTER);
    assert_eq!(advertised[3].data, xart::SLAVE);
    let request = xart::XartMessage {
        service: xart::SLAVE_ID,
        tag: 4,
        op: 8,
        length: 16,
        flags: 0,
        slot: 0,
        reserved: 0,
    }
    .frame();
    // Without registered buffers the request is queued, then refuses.
    assert!(reply(&mut os, request).unwrap().is_empty());
    assert!(os.dma_pending());
    let mut ram = stela_contracts::dma::test_support::Ram::new(0x10_0000, 0x10000);
    assert!(dma(&mut os, &mut ram).is_err());
    // The AP registers one 0x8000-byte buffer each way, then sends.
    for (tag, opcode, data) in [
        (1, control::SET_OOL_IN_LENGTH, 0x8000),
        (2, control::SET_OOL_IN_ADDRESS, 0x100),
        (3, control::SET_OOL_OUT_LENGTH, 0x8000),
        (4, control::SET_OOL_OUT_ADDRESS, 0x108),
    ] {
        reply(&mut os, control(tag, opcode, xart::SLAVE_ID, data)).unwrap();
    }
    ram.bytes[..16].copy_from_slice(&[0x5a; 16]);
    assert!(reply(&mut os, request).unwrap().is_empty());
    let answer = dma(&mut os, &mut ram).unwrap();
    assert_eq!(
        answer,
        [xart::XartMessage {
            op: 0,
            length: 0,
            ..xart::XartMessage::from_frame(request)
        }
        .frame()]
    );
    assert_eq!(os.xart().unwrap().os_uuid(), Some(&[0x5a; 16][..]));
    assert!(!os.dma_pending());
    // The nonce comes from the store; the Erase Install announcement
    // erases it.
    let nonce = |op| {
        xart::XartMessage {
            op,
            length: 0,
            ..xart::XartMessage::from_frame(request)
        }
        .frame()
    };
    reply(&mut os, nonce(0x0f)).unwrap();
    assert_eq!(
        xart::XartMessage::from_frame(dma(&mut os, &mut ram).unwrap()[0]).length,
        20
    );
    assert_eq!(ram.bytes[0x8000..0x8014], [0x5a; 20]);
    assert_eq!(
        reply(&mut os, control(5, control::ERASE_INSTALL, 0, 0)).unwrap(),
        [control::reply(
            control(5, control::ERASE_INSTALL, 0, 0),
            Status::Success,
            0
        )]
    );
    reply(&mut os, nonce(0x10)).unwrap();
    assert!(dma(&mut os, &mut ram).is_err());
    // An unrecovered operation refuses with no reply.
    reply(&mut os, nonce(18)).unwrap();
    assert!(dma(&mut os, &mut ram).is_err());
}

#[test]
fn one_failed_request_does_not_discard_other_transactions_or_their_replies() {
    let mut os = SepOs::new(None).with_services(store(), false).unwrap();
    map_shared(&mut os, shm(0x4000, 4)).unwrap();
    for (tag, opcode, data) in [
        (1, control::SET_OOL_IN_LENGTH, 0x8000),
        (2, control::SET_OOL_IN_ADDRESS, 0x100),
    ] {
        reply(&mut os, control(tag, opcode, xart::SLAVE_ID, data)).unwrap();
    }
    let request = |tag, op, length| {
        xart::XartMessage {
            service: xart::SLAVE_ID,
            tag,
            op,
            length,
            flags: 0,
            slot: 0,
            reserved: 0,
        }
        .frame()
    };
    for frame in [request(1, 8, 16), request(2, 18, 0), request(3, 8, 16)] {
        reply(&mut os, frame).unwrap();
    }
    assert!(reply(&mut os, request(1, 8, 16)).is_err());
    assert!(
        reply(
            &mut os,
            control(3, control::SET_OOL_IN_LENGTH, xart::SLAVE_ID, 0x8000)
        )
        .is_err()
    );
    assert!(reply(&mut os, control(3, control::SLEEP, 0, 0)).is_err());
    assert_eq!(os.power(), Power::Awake);
    assert!(reply(&mut os, shm(0x8000, 4)).is_err());
    let mut ram = stela_contracts::dma::test_support::Ram::new(0x10_0000, 0x8000);
    ram.bytes[..16].fill(0x5a);
    let first = dma(&mut os, &mut ram).unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].tag, 1);
    assert!(os.dma_pending());
    assert_eq!(
        dma(&mut os, &mut ram),
        Err(refuse!(
            "xART commit-hash types other than the manifest hash are not recovered"
        ))
    );
    assert!(os.dma_pending());
    let third = dma(&mut os, &mut ram).unwrap();
    assert_eq!(third.len(), 1);
    assert_eq!(third[0].tag, 3);
    assert!(!os.dma_pending());
    assert_eq!(os.xart().unwrap().os_uuid(), Some(&[0x5a; 16][..]));
}

#[test]
fn an_xart_refusal_is_answered_enotsup_from_the_dma_step() {
    let mut os = SepOs::new(None).with_services(store(), false).unwrap();
    map_shared(&mut os, shm(0x1234_4000, 0x20)).unwrap();
    let commit_hash = xart::XartMessage {
        service: xart::SLAVE_ID,
        tag: 9,
        op: 18,
        length: 0,
        flags: 0,
        slot: 0,
        reserved: 0,
    }
    .frame();
    reply(&mut os, commit_hash).unwrap();
    let mut ram = stela_contracts::dma::test_support::Ram::new(0x10_0000, 0x1000);
    assert_eq!(
        dma_step(&mut os, &mut ram),
        (
            Err(refuse!(
                "xART commit-hash types other than the manifest hash are not recovered"
            )),
            alloc::vec![xart::unsupported(commit_hash)]
        )
    );
}

#[test]
fn remap_validates_before_replacing_the_active_layout() {
    let mut os = active(None);
    let previous = os.layout().unwrap().clone();
    assert!(reply(&mut os, shm(0x8000, 4)).unwrap().is_empty());
    assert_eq!(os.region(), Some(previous.region));
    assert!(reply(&mut os, control(1, control::NOP, 0, 0)).is_err());
    let mut ram = stela_contracts::dma::test_support::Ram::new(0x8000, 0x4000);
    // A zero-filled directory has no null terminator and must not
    // replace the known layout, even after OS-active was published.
    assert!(dma(&mut os, &mut ram).is_err());
    assert_eq!(os.layout(), Some(&previous));
    assert!(os.dma_pending());
    ram.bytes[..4].copy_from_slice(&u32::from_be_bytes(*b"null").to_le_bytes());
    assert!(dma(&mut os, &mut ram).unwrap().is_empty());
    assert_eq!(os.region().unwrap().address, 0x8000);
    assert!(!os.dma_pending());
    assert_eq!(
        reply(&mut os, control(1, control::NOP, 0, 0))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn the_keystore_startup_is_answered_through_its_ool_buffers() {
    let mut os = SepOs::new(None).with_services(store(), false).unwrap();
    map_shared(&mut os, shm(0x1234_4000, 0x20)).unwrap();
    register(&mut os, keystore::ID, 0x8000, 0x8000);
    let request = keystore::tests::message(1, 0, 1, &[]);
    let frame = Frame {
        service: keystore::ID,
        tag: keystore::GET_CAPABILITIES,
        opcode: 3,
        parameter: 0,
        data: (request.len() as u32) << 16,
    };
    let mut ram = stela_contracts::dma::test_support::Ram::new(0x10_0000, 0x10000);
    ram.bytes[..request.len()].copy_from_slice(&request);
    assert!(reply(&mut os, frame).unwrap().is_empty());
    let answer = dma(&mut os, &mut ram).unwrap();
    assert_eq!(
        answer,
        [Frame {
            tag: keystore::GET_CAPABILITIES | keystore::REPLY,
            data: 92 << 16,
            ..frame
        }]
    );
    // The negotiated version, 2, follows the header and result.
    assert_eq!(ram.bytes[0x8000 + 80..0x8000 + 88], 2u64.to_le_bytes());
    assert!(os.keystore().unwrap().environment().is_none());
}

#[test]
fn system_identity_uses_the_machine_store_and_registered_dma_buffers() {
    let mut os = SepOs::new(None).with_services(store(), false).unwrap();
    map_shared(&mut os, shm(0x1234_4000, 0x20)).unwrap();
    register(&mut os, keystore::ID, 0x8000, 0x8000);
    let request = keystore::tests::system_request(2, keystore::tests::SIK_QUERY);
    let frame = Frame {
        service: keystore::ID,
        tag: 0x22,
        opcode: 17,
        parameter: 0,
        data: (request.len() as u32) << 16,
    };
    let mut ram = stela_contracts::dma::test_support::Ram::new(0x10_0000, 0x10000);
    ram.bytes[..request.len()].copy_from_slice(&request);
    assert!(reply(&mut os, frame).unwrap().is_empty());
    assert_eq!(
        dma(&mut os, &mut ram).unwrap(),
        [Frame {
            tag: 0x22 | keystore::REPLY,
            data: 160 << 16,
            ..frame
        }]
    );
    // v2 header + variant, then blob length, SEC1 point and pad4.
    assert_eq!(ram.bytes[0x8000 + 88..0x8000 + 92], 65u32.to_le_bytes());
    p256::PublicKey::from_sec1_bytes(&ram.bytes[0x8000 + 92..0x8000 + 157]).unwrap();
    assert_eq!(&ram.bytes[0x8000 + 157..0x8000 + 160], &[0; 3]);
}

#[test]
fn unsupported_system_key_metadata_drains_without_raw_observation() {
    let mut os = SepOs::new(None).with_services(store(), false).unwrap();
    map_shared(&mut os, shm(0x1234_4000, 0x20)).unwrap();
    register(&mut os, keystore::ID, 0x8000, 0x8000);
    let request = keystore::tests::system_request_with_operation(2, 7, keystore::tests::SIK_QUERY);
    let frame = Frame {
        service: keystore::ID,
        tag: 0x22,
        opcode: 17,
        parameter: 0,
        data: (request.len() as u32) << 16,
    };
    let mut ram = stela_contracts::dma::test_support::Ram::new(0x10_0000, 0x10000);
    ram.bytes[..request.len()].copy_from_slice(&request);
    assert!(reply(&mut os, frame).unwrap().is_empty());
    let (result, outbox) = dma_step(&mut os, &mut ram);
    assert!(result.is_err());
    assert_eq!(outbox, [keystore::failure(frame)]);
    assert!(os.observe.is_none());
    let lines = os.observations();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("operation=Some(7)"));
    assert!(lines[0].contains("parameter_operation=oskgp"));
    assert!(!lines[0].contains("input="));
    assert!(os.observations().is_empty());
}

#[test]
fn recovery_policy_nonce_commands_use_the_registered_buffers_and_shared_store() {
    let mut os = SepOs::new(None).with_services(store(), false).unwrap();
    map_shared(&mut os, shm(0x1234_4000, 0x20)).unwrap();
    register(&mut os, boot_policy::ID, 0x1c000, 0x14000);
    let mut ram = stela_contracts::dma::test_support::Ram::new(0x10_0000, 0x30000);
    let mut proposed = Vec::new();
    for (command, length, expected) in [
        (8u32, 0x124, 32),
        (13, 32, 80),
        (9, 0x124, 32),
        (16, 32, 80),
    ] {
        ram.bytes[..0x124].fill(0);
        ram.bytes[..4].copy_from_slice(b"hcPB");
        ram.bytes[4..8].copy_from_slice(&command.to_le_bytes());
        let request = Frame {
            service: boot_policy::ID,
            tag: 2,
            opcode: 0,
            parameter: 0,
            data: length,
        };
        assert!(reply(&mut os, request).unwrap().is_empty());
        assert_eq!(
            dma(&mut os, &mut ram).unwrap(),
            [Frame {
                data: expected,
                ..request
            }]
        );
        assert_eq!(&ram.bytes[0x1c000..0x1c004], b"hrPB");
        assert_eq!(&ram.bytes[0x1c004..0x1c008], &[0; 4]);
        if command == 13 {
            proposed = ram.bytes[0x1c020..0x1c050].to_vec();
        }
        if command == 16 {
            assert_eq!(ram.bytes[0x1c020..0x1c050], proposed);
        }
    }
    assert!(
        os.services
            .as_mut()
            .unwrap()
            .xart
            .policy_store_mut()
            .unwrap()
            .policy_nonce(super::super::store::PolicyNonce::Recovery)
            .unwrap()
            .is_some()
    );
    // Shutdown ownership applies to BootPolicy too; no late nonce work
    // can bypass xART's frozen state through the shared backend.
    let services = os.services.as_mut().unwrap();
    let mut unused = UnusedPayload;
    services
        .xart
        .request(
            xart::XartMessage {
                service: xart::SLAVE_ID,
                tag: 1,
                op: 13,
                length: 0,
                flags: 0,
                slot: 0,
                reserved: 0,
            }
            .frame(),
            &mut unused,
            &mut counter(),
        )
        .unwrap();
    assert!(services.xart.policy_store_mut().is_err());
    ram.bytes[..0x124].fill(0);
    ram.bytes[..4].copy_from_slice(b"hcPB");
    ram.bytes[4..8].copy_from_slice(&8u32.to_le_bytes());
    let request = Frame {
        service: boot_policy::ID,
        tag: 2,
        opcode: 0,
        parameter: 0,
        data: 0x124,
    };
    reply(&mut os, request).unwrap();
    let (result, outbox) = dma_step(&mut os, &mut ram);
    assert!(result.is_err());
    assert_eq!(
        outbox,
        [Frame {
            data: 32,
            ..request
        }]
    );
    assert_eq!(
        &ram.bytes[0x1c004..0x1c008],
        &boot_policy::NOT_SUPPORTED.to_le_bytes()
    );
}

struct UnusedPayload;
impl Payload for UnusedPayload {
    fn input(&mut self, _: &mut [u8]) -> Result<()> {
        panic!("no input expected")
    }
    fn output(&mut self, _: &[u8]) -> Result<()> {
        panic!("no output expected")
    }
}

#[test]
fn services_are_advertised_and_journaled() {
    let mut os = SepOs::new(None).with_services(store(), true).unwrap();
    let advertised = map_shared(&mut os, shm(0x1234_4000, 0x20)).unwrap();
    // OS active, then xarm, xars, sks, pnon and the observed scrd.
    assert_eq!(advertised.len(), 1 + 2 * 5);
    let names: Vec<u32> = advertised[1..]
        .iter()
        .filter(|f| f.opcode == 0)
        .map(|f| f.data)
        .collect();
    assert!(names.contains(&u32::from_be_bytes(*b"sks\0")));
    assert!(names.contains(&u32::from_be_bytes(*b"pnon")));
    assert!(names.contains(&u32::from_be_bytes(*b"scrd")));
    // BootPolicy's buffers, then its current-OS-type command.
    register(&mut os, boot_policy::ID, 0x1c000, 0x14000);
    let request = Frame {
        service: boot_policy::ID,
        tag: 2,
        opcode: 0,
        parameter: 0,
        data: 32,
    };
    let mut ram = stela_contracts::dma::test_support::Ram::new(0x10_0000, 0x30000);
    ram.bytes[..4].copy_from_slice(b"hcPB");
    ram.bytes[4] = 0x3e;
    // Recorded, then answered with the not-supported reply header.
    assert!(reply(&mut os, request).unwrap().is_empty());
    let (result, answer) = dma_step(&mut os, &mut ram);
    assert!(result.is_err());
    assert_eq!(answer, [request]);
    assert_eq!(ram.bytes[0x1c000..0x1c004], *b"hrPB");
    assert_eq!(ram.bytes[0x1c004..0x1c008], 255u32.to_le_bytes());
    let lines = os.observations();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].starts_with("pnon tag=2 op=0"), "{}", lines[0]);
    assert!(lines[0].contains("686350423e000000"), "{}", lines[0]);
    // Draining empties the journal.
    assert!(os.observations().is_empty());
}

#[test]
fn refusals_are_answered_but_never_an_observed_scrd_request() {
    use super::observe;
    let mut os = SepOs::new(None).with_services(store(), true).unwrap();
    map_shared(&mut os, shm(0x1234_4000, 0x20)).unwrap();
    let request = |service, tag| Frame {
        service,
        tag,
        opcode: 0,
        parameter: 0,
        data: 8,
    };
    for frame in [
        request(keystore::ID, 1),
        request(observe::CREDENTIALS_ID, 2),
    ] {
        assert!(reply(&mut os, frame).unwrap().is_empty());
    }
    let mut ram = stela_contracts::dma::test_support::Ram::new(0x10_0000, 0x1000);
    // Each DMA step consumes one request. The keystore refusal is
    // answered with its failure status; scrd is not answered at all.
    let (result, answer) = dma_step(&mut os, &mut ram);
    assert!(result.is_err());
    assert_eq!(answer, [keystore::failure(request(keystore::ID, 1))]);
    assert!(os.dma_pending());
    assert!(dma(&mut os, &mut ram).unwrap().is_empty());
    assert!(!os.dma_pending());
    let lines = os.observations();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("sks tag=1 op=0"), "{}", lines[0]);
    assert!(lines[0].ends_with("input=unregistered"), "{}", lines[0]);
    assert!(lines[1].starts_with("scrd tag=2 op=0"), "{}", lines[1]);
}

#[test]
fn unmodeled_inbound_traffic_refuses_without_faking_a_reply() {
    // Control before shared memory is mapped refuses.
    let mut os = SepOs::new(None);
    assert!(reply(&mut os, control(1, control::NOP, 0, 0)).is_err());
    let mut os = active(None);
    for frame in [
        control(1, control::SELF_TEST, 0, 0),
        control(1, control::TTY_IN, 0x41, 0),
        control(1, 26, 0, 0),
        control(1, control::ERASE_INSTALL, 0, 0),
        control(1, control::SEPOS_PANIC, 0, 0),
        control(0, control::NAP_OK, 0, 0),
        control(1, 0x40, 0, 0),
        Frame {
            service: message::DISCOVERY,
            ..control(1, 0, 0, 0)
        },
        Frame {
            service: message::ROM,
            ..control(1, 0, 0, 0)
        },
        Frame {
            service: 0x12,
            ..control(1, 0, 0, 0)
        },
    ] {
        assert!(reply(&mut os, frame).is_err(), "{frame:?}");
    }
    // A malformed shared-memory frame (zero length) is refused.
    assert!(reply(&mut SepOs::new(None), shm(0x1000, 0)).is_err());
}
