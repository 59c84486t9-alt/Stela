//! SEP's native AP-facing protocol, carried by the common ASC wrapper.
//!
//! The J473AP DT uses `iop-sep,ascwrap-v4` and `iop-nub,sep`, not RTBuddy.
//! `AppleSEPManager::_sendMessageGated` (kernel file 0x2d6ac90) puts the
//! service ID in its payload; ASC endpoint zero carries it unchanged.
//! docs/research/sep.md owns the recovered contract and remaining gates.
//!
//! The emulated SEP boots: SEPROM accepts the delivered container under
//! Stela's own explicit, TSS-free trust policy (recording measured evidence),
//! then the native sepOS phase maps shared memory and notifies the control
//! endpoint that the OS is active and answers its control requests. Of the
//! application services only the xART pair is advertised (`xart`); its
//! anti-replay operations, and the other services (sks, pnon, scrd, ...),
//! refuse rather than fake replies. See `firmware`/`os`/`control` and
//! docs/research/sep.md.
pub mod control;
pub mod endpoint;
pub mod firmware;
pub mod image;
pub mod inline_key;
pub mod keys;
pub mod message;
pub mod observe;
pub mod ool;
pub mod os;
pub mod policy;
pub mod rom;
pub mod shared;
pub mod state;
pub mod store;
pub mod xart;

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

/// The SEP's effective production status and security mode. The SEP shares
/// the AP's fuses, so Stela's SEP reports what the boot chain set for the AP
/// (`/chosen` `effective-production-status-ap`, `effective-security-mode-ap`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityMode {
    pub production: bool,
    pub secure: bool,
}

pub struct Sep {
    mailbox: Asc,
}

impl Sep {
    /// Stela's boot stage leaves SEPROM running, waiting for AP commands.
    /// This is an explicit boot-chain choice; it is not an unsolicited RTKit
    /// HELLO or a claim that sepOS already booted.
    pub fn new(
        entropy: Box<dyn Entropy>,
        lines: Lines,
        security: Option<SecurityMode>,
        ecid: u64,
        observe: bool,
        state: state::Location,
    ) -> Result<Self, &'static str> {
        Ok(Self {
            mailbox: Asc::new(
                Box::new(firmware::SepFirmware::new(
                    entropy, security, ecid, observe, state,
                )),
                true,
                lines,
            )?,
        })
    }

    /// Drain the `sks`/`pnon`/`scrd` traffic observed this run (`--sep-observe`).
    pub fn observations(&mut self) -> alloc::vec::Vec<alloc::string::String> {
        self.mailbox
            .firmware_mut::<firmware::SepFirmware>()
            .expect("SEP owns its firmware engine")
            .drain_observations()
    }

    pub fn pending(&self) -> bool {
        self.mailbox.dma_pending()
    }

    /// Graceful mode for the SEP's unimplemented requests ([`Asc::set_graceful`]).
    pub fn set_graceful(&mut self, graceful: bool) {
        self.mailbox.set_graceful(graceful);
    }

    /// The requests graceful mode answered for the first time since the last call.
    pub fn take_unsupported(&mut self) -> alloc::vec::Vec<alloc::string::String> {
        self.mailbox.take_unsupported()
    }

    /// Firmware Stela measured and accepted under its own trust policy, if any.
    pub fn evidence(&self) -> Option<&firmware::Evidence> {
        self.mailbox
            .firmware::<firmware::SepFirmware>()
            .expect("SEP owns its firmware engine")
            .evidence()
    }

    /// Whether sepOS has reported OS active (the kernel then publishes
    /// `sepBootedOnce`).
    pub fn booted(&self) -> bool {
        self.mailbox
            .firmware::<firmware::SepFirmware>()
            .expect("SEP owns its firmware engine")
            .booted()
    }

    /// Run the SEP coprocessor's queued bus-master work through dart-sep: the
    /// opcode-6 container snapshot, measured and accepted under Stela's own
    /// trust policy before SEPROM replies 106. A DMA fault or a container the
    /// policy rejects refuses here, with no boot acknowledgement.
    pub fn transfer(&mut self, port: &mut Port<'_, '_>) -> Result<(), MmioError> {
        self.mailbox
            .service_dma(port)
            .map_err(|reason| refuse(NAME, SEND_COMMIT, Width::Double, Direction::Write, reason))
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
            None,
            0xa5a5_0005,
            false,
            state::Location::Volatile,
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
