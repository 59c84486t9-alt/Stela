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
    Entropy, SecurityMode,
    image::{self, signature},
    message::{self, Frame},
    os::SepOs,
    rom::Rom,
    state,
};
use crate::platform::dma::{DmaError, Port};
use alloc::{boxed::Box, vec::Vec};

/// `_bootAction` 0x2d72d68 accepts opcode 106 ("SEP accepted IMG4") and moves
/// the AP BootStatus to 101. SEPROM replies with it once Stela's policy
/// accepts the container; requests here use tag 1 and the AP ignores the tag.
const IMAGE_ACCEPTED: u8 = 106;
const IMAGE_TAG: u8 = 1;
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
    /// Where sepOS finds its state, until it activates.
    state: Option<state::Location>,
}

impl SepFirmware {
    pub fn new(
        entropy: Box<dyn Entropy>,
        security: Option<SecurityMode>,
        state: state::Location,
    ) -> Self {
        Self {
            rom: Rom::new(entropy),
            phase: Phase::Rom,
            evidence: None,
            security,
            state: Some(state),
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

    /// Measure the container, bind its payload type to the request, and record
    /// any manifest signature as evidence. Structural or type errors refuse.
    fn measure(&mut self, snapshot: &image::Snapshot, parameter: u8) -> Result<(), &'static str> {
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
        self.evidence = Some(Evidence {
            measurement: snapshot.measurement.clone(),
            manifest,
            firmware_type: parameter,
        });
        Ok(())
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
        self.measure(&snapshot, request.parameter)?;
        // Stela is the SEP: under its own explicit, TSS-free trust policy it
        // accepts the delivered container (evidence recorded above) and brings
        // up its native sepOS. No Apple key or signing service is consulted.
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
        let location = self.state.take().ok_or("sepOS activated twice")?;
        let (store, _) = state::open(location, self.rom.entropy())?;
        self.phase = Phase::Active(Box::new(SepOs::new(self.security).with_services(store)?));
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
        let mut iommu = Identity { fault };
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut port = Port {
            iommu: &mut iommu,
            stream: 0,
            memory: &mut ram,
            access: &mut access,
        };
        let mut produced = Vec::new();
        fw.dma(&mut port, &mut produced)?;
        Ok(produced)
    }

    fn booted(fw: &mut SepFirmware) {
        let mut outbox = Vec::new();
        fw.start(&mut outbox).unwrap();
    }

    #[test]
    fn stela_policy_accepts_a_bare_sepi_and_reaches_os_active() {
        let mut fw = SepFirmware::new(entropy(), None, state::Location::Volatile);
        booted(&mut fw);
        let image = crate::img4::tests::im4p(b"sepi", b"stela-sepos");
        let acks = deliver(&mut fw, &image, false).unwrap();
        assert_eq!(acks.len(), 1);
        assert_eq!(Frame::from_mailbox(acks[0]).unwrap().opcode, IMAGE_ACCEPTED);
        assert!(fw.evidence().is_some());
        assert!(fw.evidence().unwrap().manifest.is_none());
        assert!(!fw.dma_pending());
        // The AP maps shared memory; sepOS then reports OS active.
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
        assert!(fw.booted());
        assert_eq!(Frame::from_mailbox(outbox[0]).unwrap().opcode, 21);
    }

    #[test]
    fn a_signed_container_records_signature_evidence() {
        let mut fw = SepFirmware::new(entropy(), None, state::Location::Volatile);
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
            let mut fw = SepFirmware::new(entropy(), None, state::Location::Volatile);
            booted(&mut fw);
            assert_eq!(deliver(&mut fw, image, fault), Err(refusal));
            assert!(fw.evidence().is_none());
            assert!(!fw.booted());
        }
    }
}
