//! SEP's native AP-facing protocol, carried by the common ASC wrapper.
//!
//! The J473AP DT uses `iop-sep,ascwrap-v4` and `iop-nub,sep`, not RTBuddy.
//! `AppleSEPManager::_sendMessageGated` (kernel file 0x2d6ac90) puts the
//! service ID in its payload; ASC endpoint zero carries it unchanged.
//! docs/research/sep.md owns the recovered contract and remaining gates.
//!
//! Only the ROM command prefix is executable today. Image4 signature evidence
//! is checked without conferring trust. Boot authentication,
//! shared-memory/TXM, sepOS services and persistence are explicit refusals.
//! No production compatible is admitted in `machine::soc::models` yet.
pub mod endpoint;
pub mod image;
pub mod keys;
pub mod message;
pub mod ool;
pub mod rom;
pub mod shared;
pub mod store;

use super::{
    asc::{Asc, Lines},
    bus::{Access, Direction, MmioDevice, MmioError, Width, refuse},
};
use crate::platform::dma::Port;
use alloc::boxed::Box;

const NAME: &str = "sep";
const SEND_COMMIT: u64 = 0x8808;
/// Device-relative base used to keep the separate DT aperture distinct from
/// ASC offsets. Its registers have no recovered model and always refuse.
pub const AUXILIARY_OFFSET: u64 = 1 << 32;

/// A cryptographic entropy source. Failure is an error, never zero filling.
/// Implementations must supply independent unpredictable bytes in production;
/// only unit tests use deterministic sources.
pub trait Entropy {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), &'static str>;
}

impl<F: FnMut(&mut [u8]) -> Result<(), &'static str>> Entropy for F {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), &'static str> {
        self(bytes)
    }
}

pub struct Sep {
    mailbox: Asc,
}

impl Sep {
    /// Stela's boot stage leaves SEPROM running, waiting for AP commands.
    /// This is an explicit boot-chain choice; it is not an unsolicited RTKit
    /// HELLO or a claim that sepOS already booted.
    pub fn new(entropy: Box<dyn Entropy>, lines: Lines) -> Result<Self, &'static str> {
        Ok(Self {
            mailbox: Asc::new(Box::new(rom::Rom::new(entropy)), true, lines)?,
        })
    }

    pub fn pending(&self) -> bool {
        self.mailbox
            .firmware::<rom::Rom>()
            .expect("SEP owns SEPROM")
            .image_request()
            .is_some()
    }

    /// Snapshot the delivered container through dart-sep, check the manifest's
    /// signature and payload binding when supplied, then refuse at the trust/
    /// native-service boundary. Signature evidence alone never boots SEP.
    pub fn transfer(&mut self, port: &mut Port<'_, '_>) -> Result<(), MmioError> {
        let Some(request) = self
            .mailbox
            .firmware::<rom::Rom>()
            .expect("SEP owns SEPROM")
            .image_request()
        else {
            return Ok(());
        };
        let snapshot =
            image::snapshot(port, request.address, image::MAX_IMAGE_BYTES).map_err(|error| {
                let reason = match error {
                    crate::platform::dma::DmaError::Unsupported(reason) => reason,
                    crate::platform::dma::DmaError::Fault(_) => {
                        "SEP firmware DMA fault in dart-sep"
                    }
                    crate::platform::dma::DmaError::Memory => {
                        "SEP firmware DMA is outside guest RAM"
                    }
                };
                refuse(NAME, SEND_COMMIT, Width::Double, Direction::Write, reason)
            })?;
        let inspect = || -> Result<(), &'static str> {
            let parts = crate::img4::parse(snapshot.bytes())
                .map_err(|_| "SEP firmware Image4 structure is malformed")?;
            let kind = crate::img4::payload_type(parts.payload)
                .map_err(|_| "SEP firmware payload type is malformed")?;
            let expected = if request.parameter == 0 {
                *b"sepi"
            } else {
                *b"rsep"
            };
            if kind != expected {
                return Err("SEP firmware payload type differs from the ROM request");
            }
            let manifest = parts
                .manifest
                .ok_or("SEP bare IM4P has no manifest to authenticate")?;
            image::signature::inspect(parts.payload, manifest)?;
            Err(
                "SEP signature evidence verified; trust constraints and native sepOS services are not modeled",
            )
        };
        Err(refuse(
            NAME,
            SEND_COMMIT,
            Width::Double,
            Direction::Write,
            inspect().expect_err("signature evidence cannot admit native sepOS"),
        ))
    }
}

fn named(error: MmioError) -> MmioError {
    match error {
        MmioError::Unsupported {
            offset,
            width,
            direction,
            reason,
            ..
        } => refuse(NAME, offset, width, direction, reason),
        error => error,
    }
}

impl MmioDevice for Sep {
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(
        &mut self,
        offset: u64,
        width: Width,
        access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
        if offset >= AUXILIARY_OFFSET {
            return Err(refuse(
                NAME,
                offset,
                width,
                Direction::Read,
                "SEP auxiliary register bank is not modeled",
            ));
        }
        self.mailbox.read(offset, width, access).map_err(named)
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        if offset >= AUXILIARY_OFFSET {
            return Err(refuse(
                NAME,
                offset,
                width,
                Direction::Write,
                "SEP auxiliary register bank is not modeled",
            ));
        }
        self.mailbox
            .write(offset, width, value, access)
            .map_err(named)
    }
}

#[cfg(test)]
mod tests {
    use super::message::{Frame, ROM};
    use super::*;
    use crate::platform::apple::interrupt::{AicInput, InterruptLatch, Wire};

    #[test]
    fn rom_response_uses_the_common_mailbox_and_level_interrupts() {
        let irqs = [
            AicInput::new(0, 0x115),
            AicInput::new(0, 0x114),
            AicInput::new(0, 0x117),
            AicInput::new(0, 0x116),
        ];
        let mut sep = Sep::new(
            Box::new(|_: &mut [u8]| Err("unused entropy")),
            Lines::from_interrupts(irqs),
        )
        .unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        assert_eq!(sep.read(0x44, Width::Word, &mut access), Ok(1 << 4));
        sep.write(0x8114, Width::Word, 1, &mut access).unwrap();
        let frame = Frame {
            service: ROM,
            tag: 1,
            opcode: 2,
            parameter: 0,
            data: 0,
        };
        sep.write(0x8800, Width::Double, frame.mailbox().payload, &mut access)
            .unwrap();
        sep.write(0x8808, Width::Double, 0, &mut access).unwrap();
        assert!(latch.is_asserted(Wire::Aic(irqs[2])));
        let mut access = Access::new(0, 0, &mut latch);
        assert_eq!(
            sep.read(0x8830, Width::Double, &mut access),
            Ok(0x0000_0001_00d2_01ff)
        );
        // ASC snapshots the pre-pop count in the received status word.
        assert_eq!(sep.read(0x8838, Width::Double, &mut access), Ok(1 << 52));
        assert!(!latch.is_asserted(Wire::Aic(irqs[2])));
        let mut access = Access::new(0, 0, &mut latch);
        assert!(matches!(
            sep.read(0x10000, Width::Word, &mut access),
            Err(MmioError::Unsupported { device: "sep", .. })
        ));
    }
}
