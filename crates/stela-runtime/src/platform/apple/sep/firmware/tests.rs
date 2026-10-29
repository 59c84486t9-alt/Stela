use super::super::observe;
use super::*;
use {
    stela_contracts::bus::Access, stela_contracts::dma::Iommu, stela_contracts::dma::Memory,
    stela_contracts::dma::test_support::Ram, stela_contracts::interrupt::InterruptLatch,
};

struct Identity {
    fault: bool,
}
impl Iommu for Identity {
    fn page(&self) -> u64 {
        0x4000
    }
    fn translate(
        &mut self,
        _: &mut dyn Memory,
        _: usize,
        iova: u64,
        _: u64,
        _: bool,
        _: &mut Access<'_>,
    ) -> Result<u64, DmaError> {
        if self.fault {
            Err(DmaError::Fault(7))
        } else {
            Ok(iova)
        }
    }
}

fn entropy() -> Box<dyn Entropy> {
    Box::new(|b: &mut [u8]| {
        b.fill(0xa5);
        Ok(())
    })
}

fn deliver(fw: &mut SepFirmware, image: &[u8], fault: bool) -> Result<Vec<Message>, &'static str> {
    const ADDRESS: u64 = 0x4000;
    let mut ram = Ram::new(ADDRESS, 0x8000);
    ram.bytes[..image.len()].copy_from_slice(image);
    // BootTz0 first: SEPROM requires it before an image load.
    let mut outbox = Vec::new();
    fw.receive(
        Frame {
            service: message::ROM,
            tag: IMAGE_TAG,
            opcode: 5,
            parameter: FIRMWARE_SEPI,
            data: 0,
        }
        .mailbox(),
        &mut outbox,
    )?;
    outbox.clear();
    // Opcode 6 delivers the IOVA and marks the image pending.
    fw.receive(
        Frame {
            service: message::ROM,
            tag: IMAGE_TAG,
            opcode: 6,
            parameter: FIRMWARE_SEPI,
            data: (ADDRESS >> 12) as u32,
        }
        .mailbox(),
        &mut outbox,
    )?;
    assert!(outbox.is_empty(), "opcode 6 does not ack until DMA accepts");
    assert!(fw.dma_pending());
    dma(fw, &mut ram, fault)
}

/// Run the firmware's queued DMA over `ram` through an identity DART
/// (faulting when `fault`), returning the messages it produced.
fn dma(fw: &mut SepFirmware, ram: &mut Ram, fault: bool) -> Result<Vec<Message>, &'static str> {
    let mut iommu = Identity { fault };
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut port = Port {
        iommu: &mut iommu,
        stream: 0,
        memory: ram,
        access: &mut access,
    };
    let mut produced = Vec::new();
    let result = fw.dma(&mut port, &mut produced);
    if result.is_err() {
        assert!(
            produced.is_empty(),
            "a failed DMA step publishes no replies"
        );
    }
    result?;
    Ok(produced)
}

fn booted(fw: &mut SepFirmware) {
    let mut outbox = Vec::new();
    fw.start(&mut outbox).unwrap();
}

fn map_shared(fw: &mut SepFirmware) -> Vec<Message> {
    let mut outbox = Vec::new();
    fw.receive(
        Frame {
            service: message::BOOT,
            tag: 0,
            opcode: 0x20,
            parameter: 0,
            data: 0x5_0000,
        }
        .mailbox(),
        &mut outbox,
    )
    .unwrap();
    assert!(outbox.is_empty());
    assert!(!fw.booted());
    let mut ram = Ram::new(0x5000_0000, 0x4000);
    ram.bytes[..4].copy_from_slice(&u32::from_be_bytes(*b"null").to_le_bytes());
    dma(fw, &mut ram, false).unwrap()
}

#[test]
fn stela_policy_accepts_a_bare_sepi_and_reaches_os_active() {
    let mut fw = SepFirmware::new(
        entropy(),
        None,
        0xa5a5_0004,
        false,
        state::Location::Volatile,
    );
    booted(&mut fw);
    let image = stela_formats::img4::test_support::im4p(b"sepi", b"stela-sepos");
    let acks = deliver(&mut fw, &image, false).unwrap();
    assert_eq!(acks.len(), 1);
    assert_eq!(Frame::from_mailbox(acks[0]).unwrap().opcode, IMAGE_ACCEPTED);
    assert!(fw.evidence().is_some());
    assert!(fw.evidence().unwrap().manifest.is_none());
    assert!(!fw.dma_pending());
    // The AP maps shared memory; sepOS then reports OS active.
    let outbox = map_shared(&mut fw);
    assert!(fw.booted());
    assert_eq!(Frame::from_mailbox(outbox[0]).unwrap().opcode, 21);
}

#[test]
fn refused_service_requests_get_their_failure_answer_from_the_dma_step() {
    for (tag, reason) in [
        (0x7f, "SEP keystore command is not implemented"),
        (
            0x01,
            "SEP service request before its OOL buffers are registered",
        ),
    ] {
        let mut fw = SepFirmware::new(
            entropy(),
            None,
            0xa5a5_0004,
            false,
            state::Location::Volatile,
        );
        booted(&mut fw);
        deliver(
            &mut fw,
            &stela_formats::img4::test_support::im4p(b"sepi", b"x"),
            false,
        )
        .unwrap();
        map_shared(&mut fw);
        // Unknown commands refuse before DMA; recognized keybag codecs must
        // validate their buffers before refusing unresolved semantics.
        let request = Frame {
            service: keystore::ID,
            tag,
            opcode: 7,
            parameter: 0,
            data: 0x80 << 16,
        };
        let mut ram = Ram::new(0x4000, 0x4000);
        let mut outbox = Vec::new();
        fw.receive(request.mailbox(), &mut outbox).unwrap();
        let mut produced = Vec::new();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut port = Port {
            iommu: &mut Identity { fault: false },
            stream: 0,
            memory: &mut ram,
            access: &mut access,
        };
        assert_eq!(fw.dma(&mut port, &mut produced), Err(reason));
        assert_eq!(produced, [keystore::failure(request).mailbox()]);
    }
}

#[test]
fn a_signed_container_records_signature_evidence() {
    let mut fw = SepFirmware::new(
        entropy(),
        None,
        0xa5a5_0004,
        false,
        state::Location::Volatile,
    );
    booted(&mut fw);
    let (payload, manifest) = signature::tests::inputs();
    let image = stela_formats::img4::compose(&payload, &manifest);
    let acks = deliver(&mut fw, &image, false).unwrap();
    assert_eq!(acks.len(), 1);
    assert!(fw.evidence().unwrap().manifest.is_some());
}

#[test]
fn malformed_payloads_and_dma_faults_refuse_without_a_boot_ack() {
    let rsep = stela_formats::img4::test_support::im4p(b"rsep", b"x");
    let sepi = stela_formats::img4::test_support::im4p(b"sepi", b"x");
    for (image, fault, refusal) in [
        (
            b"\x30\x06\x16\x04IM4P".as_slice(),
            false,
            "SEP firmware payload type is malformed",
        ),
        (
            rsep.as_slice(),
            false,
            "SEP firmware payload type differs from the ROM request",
        ),
        (sepi.as_slice(), true, "SEP firmware DMA fault in dart-sep"),
    ] {
        let mut fw = SepFirmware::new(
            entropy(),
            None,
            0xa5a5_0004,
            false,
            state::Location::Volatile,
        );
        booted(&mut fw);
        assert_eq!(deliver(&mut fw, image, fault), Err(refusal));
        assert!(fw.evidence().is_none());
        assert!(!fw.booted());
    }
}

#[test]
fn state_open_failure_preserves_the_rom_request_without_an_acceptance() {
    use alloc::rc::Rc;
    use core::cell::Cell;
    let failing = Rc::new(Cell::new(true));
    let source = failing.clone();
    let mut fw = SepFirmware::new(
        Box::new(move |bytes: &mut [u8]| {
            if source.get() {
                return Err("entropy unavailable");
            }
            bytes.fill(0xa5);
            Ok(())
        }),
        None,
        0xa5a5_0004,
        false,
        state::Location::Volatile,
    );
    booted(&mut fw);
    let image = stela_formats::img4::test_support::im4p(b"sepi", b"native SEP fixture");
    assert_eq!(deliver(&mut fw, &image, false), Err("entropy unavailable"));
    assert!(fw.dma_pending());
    assert!(fw.evidence().is_none());
    assert!(fw.state.is_some());
    assert!(!fw.booted());
    failing.set(false);
    let mut ram = Ram::new(0x4000, 0x8000);
    ram.bytes[..image.len()].copy_from_slice(&image);
    let reply = dma(&mut fw, &mut ram, false).unwrap();
    assert_eq!(reply.len(), 1);
    assert_eq!(
        Frame::from_mailbox(reply[0]).unwrap().opcode,
        IMAGE_ACCEPTED
    );
    assert!(!fw.dma_pending());
    assert!(fw.evidence().is_some());
    assert!(fw.state.is_none());
}

#[test]
fn shared_directory_faults_do_not_announce_os_active_or_services() {
    let mut fw = SepFirmware::new(
        entropy(),
        None,
        0xa5a5_0004,
        false,
        state::Location::Volatile,
    );
    booted(&mut fw);
    deliver(
        &mut fw,
        &stela_formats::img4::test_support::im4p(b"sepi", b"native SEP fixture"),
        false,
    )
    .unwrap();
    let frame = Frame {
        service: message::BOOT,
        tag: 0,
        opcode: 4,
        parameter: 0,
        data: 4,
    };
    let mut outbox = Vec::new();
    fw.receive(frame.mailbox(), &mut outbox).unwrap();
    assert!(outbox.is_empty());
    assert!(!fw.booted());
    assert!(fw.dma_pending());
    let mut ram = Ram::new(0x4000, 0x4000);
    ram.bytes[..4].copy_from_slice(&u32::from_be_bytes(*b"null").to_le_bytes());
    assert!(dma(&mut fw, &mut ram, true).is_err());
    assert!(!fw.booted());
    assert!(fw.dma_pending());
    let before = ram.bytes.clone();
    let replies = dma(&mut fw, &mut ram, false).unwrap();
    assert_eq!(ram.bytes, before);
    assert!(fw.booted());
    assert_eq!(
        Frame::from_mailbox(replies[0]).unwrap().opcode,
        control::OS_ACTIVE
    );
    // OS active, then the xART pair, sks and pnon, name and capacities.
    assert_eq!(replies.len(), 9);
    assert!(!fw.dma_pending());
}

#[test]
fn error_replies_follow_each_phase_protocol_and_refuse_without_one() {
    let mut fw = SepFirmware::new(
        entropy(),
        None,
        0xa5a5_0004,
        false,
        state::Location::Volatile,
    );
    booted(&mut fw);
    let request = |service, tag, opcode| {
        Frame {
            service,
            tag,
            opcode,
            parameter: 7,
            data: 9,
        }
        .mailbox()
    };
    let reply = |fw: &mut SepFirmware, message| {
        fw.error_reply(message, "unimplemented")
            .map(|replies| Frame::from_mailbox(replies[0]).unwrap())
    };
    let rom = reply(&mut fw, request(message::ROM, 2, 0x30)).unwrap();
    assert_eq!((rom.tag, rom.opcode, rom.data), (2, ROM_FAILURE, 0x30));
    assert_eq!(reply(&mut fw, request(boot_policy::ID, 2, 0)), None);

    let image = stela_formats::img4::test_support::im4p(b"sepi", b"stela-sepos");
    deliver(&mut fw, &image, false).unwrap();
    map_shared(&mut fw);
    assert!(fw.booted());
    let policy = reply(&mut fw, request(boot_policy::ID, 2, 0)).unwrap();
    assert_eq!(
        (policy.service, policy.tag, policy.opcode, policy.data),
        (boot_policy::ID, 2, boot_policy::TRANSPORT_FAILURE, 0)
    );
    let xart = reply(&mut fw, request(xart::SLAVE_ID, 5, 6)).unwrap();
    assert_eq!((xart.tag, xart.opcode, xart.data), (5, 45, 0));
    assert_eq!(reply(&mut fw, request(xart::SLAVE_ID, 0, 6)), None);
    let keys = reply(&mut fw, request(keystore::ID, 0x4d, 6)).unwrap();
    assert_eq!(
        (keys.tag, keys.opcode, keys.parameter, keys.data),
        (0x4d | keystore::REPLY, 6, keystore::FAILURE, 0)
    );
    assert_eq!(reply(&mut fw, request(keystore::ID, 0xcd, 6)), None);
    assert_eq!(reply(&mut fw, request(observe::CREDENTIALS_ID, 3, 4)), None);
    let control = reply(&mut fw, request(message::CONTROL, 1, 99)).unwrap();
    assert_eq!(
        control,
        control::reply(
            Frame::from_mailbox(request(message::CONTROL, 1, 99)).unwrap(),
            control::Status::DeviceError,
            0
        )
    );
    assert_eq!(reply(&mut fw, request(message::CONTROL, 0, 99)), None);
    assert_eq!(reply(&mut fw, request(message::ROM, 2, 0x30)), None);
}
