//! The emulated SEP coprocessor behind the common ASC mailbox: a SEPROM phase
//! and, once a firmware container is accepted, an active sepOS phase.
//!
//! Stela cannot run Apple's sepOS (it is encrypted to Apple's SEP GID). Stela
//! IS the SEP: it boots its own native implementation under its own explicit,
//! TSS-free trust policy. On opcode 6 the SEPROM phase takes a bounded, owned
//! DMA snapshot of the delivered container through dart-sep, measures it,
//! records any supplied manifest's signature as evidence, then accepts it and
//! replies 106 (`_bootAction` 0x2d72d68). This records measured evidence; it
//! does not claim Apple's signature was checked by Apple keys. A malformed
//! container, a payload type that disagrees with the request, or a DMA fault
//! refuses without a boot acknowledgement. docs/research/sep.md owns the
//! contract and the trust-policy boundary.
use super::super::asc::{Firmware, Message};
use super::{
    Entropy, SecurityMode, control,
    image::{self, signature},
    message::{self, Frame},
    observe,
    os::SepOs,
    rom::Rom,
    state, xart,
};
use crate::platform::dma::{DmaError, Port};
use alloc::{boxed::Box, vec::Vec};

/// `_bootAction` 0x2d72d68 accepts opcode 106 ("SEP accepted IMG4") and moves
/// the AP BootStatus to 101. SEPROM replies with it once Stela's policy
/// accepts the container; requests here use tag 1 and the AP ignores the tag.
const IMAGE_ACCEPTED: u8 = 106;
const IMAGE_TAG: u8 = 1;
/// SEPROM's failure report: opcode 199 with the failed command in the data
/// word. `_bootAction` 0x2d72ca8 tolerates only data 0x1e (the iBIC capture
/// a platform lacks) and panics on any other.
const ROM_FAILURE: u8 = 199;
/// A graceful `pnon` reply's status: BootPolicy's `handleSEPMessage`
/// 0x329d940 takes any nonzero opcode byte as the command's failure. The
/// value is Stela's; sepOS's status codes are not recovered.
const BOOT_POLICY_FAILURE: u8 = 1;
const FIRMWARE_SEPI: u8 = 0;

/// What Stela measured and recorded about the delivered firmware. Evidence,
/// never an Apple-verified-boot token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub measurement: image::Measurement,
    /// Signature evidence, only when the container carried a manifest. A bare
    /// encrypted IPSW `sepi` carries none; acceptance is Stela's own policy.
    pub manifest: Option<signature::Evidence>,
    pub firmware_type: u8,
}

enum Phase {
    Rom,
    Active(Box<SepOs>),
}

pub struct SepFirmware {
    rom: Rom,
    phase: Phase,
    evidence: Option<Evidence>,
    security: Option<SecurityMode>,
    /// The machine's `/chosen` `unique-chip-id`, bound into the key hierarchy.
    ecid: u64,
    /// Observe (`--sep-observe`): advertise and log `sks`/`pnon`/`scrd`.
    observe: bool,
    /// Strict mode, which sepOS applies to observed requests
    /// ([`SepOs::set_strict`]).
    strict: bool,
    /// Where sepOS finds its state, until it activates.
    state: Option<state::Location>,
}

impl SepFirmware {
    pub fn new(
        entropy: Box<dyn Entropy>,
        security: Option<SecurityMode>,
        ecid: u64,
        observe: bool,
        state: state::Location,
    ) -> Self {
        Self {
            rom: Rom::new(entropy),
            phase: Phase::Rom,
            evidence: None,
            security,
            ecid,
            observe,
            strict: true,
            state: Some(state),
        }
    }

    /// Strict mode for sepOS's observed requests ([`SepOs::set_strict`]),
    /// now and once it activates.
    pub fn set_strict(&mut self, strict: bool) {
        self.strict = strict;
        if let Phase::Active(os) = &mut self.phase {
            os.set_strict(strict);
        }
    }

    /// The firmware Stela measured and accepted, if any.
    pub fn evidence(&self) -> Option<&Evidence> {
        self.evidence.as_ref()
    }

    /// Whether sepOS has reported its OS active (the kernel then publishes
    /// `sepBootedOnce`). `sep-booted` itself is the AP's own property, set by
    /// `AppleSEPManager::_bootSEP` once the ROM handshake (opcode 6 accept)
    /// succeeds.
    pub fn booted(&self) -> bool {
        matches!(&self.phase, Phase::Active(os) if os.os_active_sent())
    }

    /// Drain the observed `sks`/`pnon`/`scrd` traffic as log lines, if
    /// `--sep-observe` and sepOS is active.
    pub fn drain_observations(&mut self) -> alloc::vec::Vec<alloc::string::String> {
        match &mut self.phase {
            Phase::Active(os) => os.observations(),
            Phase::Rom => alloc::vec::Vec::new(),
        }
    }

    /// Measure the container, bind its payload type to the request, and record
    /// any manifest signature as evidence. Structural or type errors refuse.
    fn measure(&self, snapshot: &image::Snapshot, parameter: u8) -> Result<Evidence, &'static str> {
        let parts = crate::img4::parse(snapshot.bytes())
            .map_err(|_| "SEP firmware Image4 structure is malformed")?;
        let kind = crate::img4::payload_type(parts.payload)
            .map_err(|_| "SEP firmware payload type is malformed")?;
        let expected = if parameter == FIRMWARE_SEPI {
            *b"sepi"
        } else {
            *b"rsep"
        };
        if kind != expected {
            return Err("SEP firmware payload type differs from the ROM request");
        }
        let manifest = parts
            .manifest
            .map(|m| signature::inspect(parts.payload, m))
            .transpose()?;
        Ok(Evidence {
            measurement: snapshot.measurement.clone(),
            manifest,
            firmware_type: parameter,
        })
    }
}

fn dma_refusal(error: DmaError) -> &'static str {
    match error {
        DmaError::Unsupported(reason) => reason,
        DmaError::Fault(_) => "SEP firmware DMA fault in dart-sep",
        DmaError::Memory => "SEP firmware DMA is outside guest RAM",
    }
}

impl Firmware for SepFirmware {
    fn check_reset(&self) -> Result<(), &'static str> {
        Err("SEP physical reset and nonretained security-state restoration are not qualified")
    }
    fn start(&mut self, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
        self.rom.start(outbox)
    }

    fn receive(&mut self, message: Message, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
        if let Phase::Active(os) = &mut self.phase {
            os.receive(Frame::from_mailbox(message)?, self.rom.entropy(), outbox)
        } else {
            self.rom.receive(message, outbox)
        }
    }

    /// SEPROM answers a command it lacks with its failure report; sepOS
    /// answers a tagged control request with kIOReturnDeviceError's status,
    /// a tagged `xars` operation with `ENOTSUP` and a `pnon` command with a
    /// failure status. `sks`, `scrd`, the master instance and notifications
    /// have no recovered error reply and stay refused.
    fn error_reply(&mut self, message: Message, _reason: &'static str) -> Option<Vec<Message>> {
        let frame = Frame::from_mailbox(message).ok()?;
        let reply = match (&self.phase, frame.service) {
            (Phase::Rom, message::ROM) => Frame {
                service: message::ROM,
                tag: frame.tag,
                opcode: ROM_FAILURE,
                parameter: 0,
                data: u32::from(frame.opcode),
            },
            (Phase::Active(_), message::CONTROL) if frame.tag != 0 => {
                control::reply(frame, control::Status::DeviceError, 0)
            }
            (Phase::Active(_), xart::SLAVE_ID) if frame.tag != 0 => xart::unsupported(frame),
            (Phase::Active(_), observe::BOOT_POLICY_ID) => Frame {
                opcode: BOOT_POLICY_FAILURE,
                parameter: 0,
                data: 0,
                ..frame
            },
            _ => return None,
        };
        Some(alloc::vec![reply.mailbox()])
    }

    fn dma_pending(&self) -> bool {
        match &self.phase {
            Phase::Rom => self.rom.image_request().is_some(),
            Phase::Active(os) => os.dma_pending(),
        }
    }

    fn dma(
        &mut self,
        port: &mut Port<'_, '_>,
        outbox: &mut Vec<Message>,
    ) -> Result<(), &'static str> {
        if let Phase::Active(os) = &mut self.phase {
            return os.dma(port, self.rom.entropy(), outbox);
        }
        let Some(request) = self.rom.image_request() else {
            return Ok(());
        };
        let snapshot =
            image::snapshot(port, request.address, image::MAX_IMAGE_BYTES).map_err(dma_refusal)?;
        let evidence = self.measure(&snapshot, request.parameter)?;
        // State open/provision and catalog construction can fail. Keep the
        // ROM request and state location until all activation prerequisites
        // succeed, so neither an acknowledgement nor an accepted identity
        // escapes for a partially activated SEP.
        let location = self.state.as_ref().ok_or("sepOS activated twice")?.clone();
        let (store, _) = state::open(location, self.ecid, self.rom.entropy())?;
        let mut os = SepOs::new(self.security).with_services(store, self.observe)?;
        os.set_strict(self.strict);
        // Stela is the SEP: under its own explicit, TSS-free trust policy it
        // accepts the delivered container (evidence recorded above) and brings
        // up its native sepOS. No Apple key or signing service is consulted.
        self.phase = Phase::Active(Box::new(os));
        self.evidence = Some(evidence);
        self.state = None;
        self.rom.accept_image();
        outbox.push(
            Frame {
                service: message::ROM,
                tag: IMAGE_TAG,
                opcode: IMAGE_ACCEPTED,
                parameter: 0,
                data: 0,
            }
            .mailbox(),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{
        apple::{bus::Access, interrupt::InterruptLatch},
        dma::{Iommu, Memory, tests::Ram},
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

    fn deliver(
        fw: &mut SepFirmware,
        image: &[u8],
        fault: bool,
    ) -> Result<Vec<Message>, &'static str> {
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
        let image = crate::img4::tests::im4p(b"sepi", b"stela-sepos");
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
    fn strict_mode_reaches_sepos_before_and_after_it_activates() {
        // An observed sks request, queued then run through the DMA step.
        let observed = |fw: &mut SepFirmware| {
            let mut outbox = Vec::new();
            let request = Frame {
                service: observe::KEYSTORE_ID,
                tag: 1,
                opcode: 0,
                parameter: 0,
                data: 0,
            };
            fw.receive(request.mailbox(), &mut outbox).unwrap();
            assert!(outbox.is_empty());
            dma(fw, &mut Ram::new(0x4000, 0x4000), false)
        };
        let mut fw = SepFirmware::new(
            entropy(),
            None,
            0xa5a5_0004,
            true,
            state::Location::Volatile,
        );
        booted(&mut fw);
        fw.set_strict(false);
        let image = crate::img4::tests::im4p(b"sepi", b"stela-sepos");
        deliver(&mut fw, &image, false).unwrap();
        map_shared(&mut fw);
        // Graceful from before activation: recorded, unanswered, no stop.
        assert_eq!(observed(&mut fw), Ok(Vec::new()));
        fw.set_strict(true);
        assert_eq!(
            observed(&mut fw),
            Err(observe::refusal(observe::KEYSTORE_ID))
        );
        assert_eq!(fw.drain_observations().len(), 2);
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
        let image = crate::img4::compose(&payload, &manifest);
        let acks = deliver(&mut fw, &image, false).unwrap();
        assert_eq!(acks.len(), 1);
        assert!(fw.evidence().unwrap().manifest.is_some());
    }

    #[test]
    fn malformed_payloads_and_dma_faults_refuse_without_a_boot_ack() {
        let rsep = crate::img4::tests::im4p(b"rsep", b"x");
        let sepi = crate::img4::tests::im4p(b"sepi", b"x");
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
        let image = crate::img4::tests::im4p(b"sepi", b"native SEP fixture");
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
            &crate::img4::tests::im4p(b"sepi", b"native SEP fixture"),
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
        assert_eq!(replies.len(), 5);
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
        assert_eq!(reply(&mut fw, request(observe::BOOT_POLICY_ID, 3, 4)), None);

        let image = crate::img4::tests::im4p(b"sepi", b"stela-sepos");
        deliver(&mut fw, &image, false).unwrap();
        map_shared(&mut fw);
        assert!(fw.booted());
        let policy = reply(&mut fw, request(observe::BOOT_POLICY_ID, 3, 4)).unwrap();
        assert_eq!(
            (policy.service, policy.tag, policy.opcode, policy.data),
            (observe::BOOT_POLICY_ID, 3, BOOT_POLICY_FAILURE, 0)
        );
        let xart = reply(&mut fw, request(xart::SLAVE_ID, 5, 6)).unwrap();
        assert_eq!((xart.tag, xart.opcode, xart.data), (5, 45, 0));
        assert_eq!(reply(&mut fw, request(xart::SLAVE_ID, 0, 6)), None);
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
        assert_eq!(reply(&mut fw, request(observe::KEYSTORE_ID, 3, 4)), None);
        assert_eq!(reply(&mut fw, request(message::ROM, 2, 0x30)), None);
    }
}
