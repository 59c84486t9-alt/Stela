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
    Entropy, SecurityMode, boot_policy, control,
    image::{self, signature},
    keystore,
    message::{self, Frame},
    os::SepOs,
    rom::Rom,
    state, xart,
};
use alloc::{boxed::Box, vec::Vec};
use {stela_contracts::dma::DmaError, stela_contracts::dma::Port};

/// `_bootAction` 0x2d72d68 accepts opcode 106 ("SEP accepted IMG4") and moves
/// the AP BootStatus to 101. SEPROM replies with it once Stela's policy
/// accepts the container; requests here use tag 1 and the AP ignores the tag.
const IMAGE_ACCEPTED: u8 = 106;
const IMAGE_TAG: u8 = 1;
/// SEPROM's failure report: opcode 199 with the failed command in the data
/// word. `_bootAction` 0x2d72ca8 tolerates only data 0x1e (the iBIC capture
/// a platform lacks) and panics on any other.
const ROM_FAILURE: u8 = 199;
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
    /// Observe (`--sep-observe`): journal `sks`/`pnon`/`scrd`, advertise
    /// `scrd`.
    observe: bool,
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
            state: Some(state),
        }
    }

    /// The firmware Stela measured and accepted, if any.
    #[cfg(test)]
    pub fn evidence(&self) -> Option<&Evidence> {
        self.evidence.as_ref()
    }

    /// Whether sepOS has reported its OS active (the kernel then publishes
    /// `sepBootedOnce`). `sep-booted` itself is the AP's own property, set by
    /// `AppleSEPManager::_bootSEP` once the ROM handshake (opcode 6 accept)
    /// succeeds.
    #[cfg(test)]
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
        let parts = stela_formats::img4::parse(snapshot.bytes())
            .map_err(|_| "SEP firmware Image4 structure is malformed")?;
        let kind = stela_formats::img4::payload_type(parts.payload)
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
            .transpose()
            .map_err(|error| error.reason())?;
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
    /// an `xars` operation with `ENOTSUP`, a keystore request with its
    /// failure status and a BootPolicy command with a transport failure.
    /// These refusals precede any OOL transfer, so none carries reply
    /// bytes. `scrd`, the master instance and notifications have no error
    /// reply and stay refused.
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
            (Phase::Active(_), keystore::ID) if frame.tag & keystore::REPLY == 0 => {
                keystore::failure(frame)
            }
            (Phase::Active(_), boot_policy::ID) => boot_policy::transport_failure(frame),
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
        let os = SepOs::new(self.security).with_services(store, self.observe)?;
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
mod tests;
