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
//! endpoint that the OS is active and answers its control requests. It
//! advertises the xART pair (`xart`), the keystore (`keystore`) and
//! BootPolicy (`boot_policy`) services; each answers the requests whose
//! contract is recovered and refuses the rest rather than fake a reply, and
//! the other services (scrd, ...) are not advertised. See
//! `firmware`/`os`/`control` and docs/research/sep.md.
pub mod boot_policy;
pub mod control;
mod der;
pub mod endpoint;
pub mod firmware;
pub mod image;
pub mod keys;
pub mod keystore;
pub mod message;
pub mod observe;
pub mod ool;
pub mod os;
pub mod policy;
pub mod rom;
pub mod shared;
pub mod state;
pub mod store;
pub mod transaction;
pub mod xart;

use alloc::boxed::Box;
use stela_contracts::dma::Port;
use {
    super::asc::Asc, super::asc::Lines, stela_contracts::bus::Access,
    stela_contracts::bus::Direction, stela_contracts::bus::Lifecycle,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError, stela_contracts::bus::Width,
    stela_contracts::bus::refuse,
};

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

    /// Explicit Stela entry policy: the native ROM is already running and
    /// both actual ASC mailboxes are enabled. Original early firmware polls
    /// and sends without enabling them first. This is not an observation of
    /// Apple's BootROM cold state, an authenticated sepOS, or a ready-bit shim.
    /// Entropy, identity, security qualification and persistence remain the
    /// caller's actual inputs, exactly as for `new`.
    #[cfg(test)]
    pub fn booted_rom(
        entropy: Box<dyn Entropy>,
        lines: Lines,
        security: Option<SecurityMode>,
        ecid: u64,
        observe: bool,
        state: state::Location,
    ) -> Result<Self, &'static str> {
        Ok(Self {
            mailbox: Asc::booted(
                Box::new(firmware::SepFirmware::new(
                    entropy, security, ecid, observe, state,
                )),
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

    /// The requests answered with an error reply for the first time since
    /// the last call.
    pub fn take_unmodeled(&mut self) -> alloc::vec::Vec<alloc::string::String> {
        self.mailbox.take_unmodeled()
    }

    /// Firmware Stela measured and accepted under its own trust policy, if any.
    #[cfg(test)]
    pub fn evidence(&self) -> Option<&firmware::Evidence> {
        self.mailbox
            .firmware::<firmware::SepFirmware>()
            .expect("SEP owns its firmware engine")
            .evidence()
    }

    /// Whether sepOS has reported OS active (the kernel then publishes
    /// `sepBootedOnce`).
    #[cfg(test)]
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
    fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
        // Same actual mailbox/firmware owner checks every proposed edge.
        // In particular, delegation does not qualify SEP security-state loss.
        self.mailbox.lifecycle()
    }
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
    fn advance(&mut self, access: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
        self.mailbox.advance(access).map_err(named)
    }
}

#[cfg(test)]
mod tests {
    use super::message::{Frame, ROM};
    use super::*;
    use {
        stela_contracts::interrupt::AicInput, stela_contracts::interrupt::InterruptLatch,
        stela_contracts::interrupt::Wire,
    };

    const PHYSICAL: u64 = 0x396400000;
    const ACTIVE: super::super::bus::LifecycleState = super::super::bus::LifecycleState {
        powered: true,
        clocked: true,
        quiesced: false,
        reset: false,
        retention: true,
    };
    struct Mounted {
        bus: super::super::bus::Bus,
        device: super::super::bus::DeviceId,
        latch: InterruptLatch,
        irqs: [AicInput; 4],
    }
    impl Mounted {
        fn new(entropy: Box<dyn Entropy>) -> Self {
            let irqs = [0x222, 0x221, 0x224, 0x223].map(|irq| AicInput::new(0, irq));
            let sep = Sep::booted_rom(
                entropy,
                Lines::from_interrupts(irqs),
                None,
                0x5354454c41544553,
                false,
                state::Location::Volatile,
            )
            .unwrap();
            let mut bus = super::super::bus::Bus::new();
            let device = bus.add(Box::new(sep));
            bus.map(device, PHYSICAL, 0x6c000, 0).unwrap();
            Self {
                bus,
                device,
                latch: InterruptLatch::new(),
                irqs,
            }
        }
        fn read(&mut self, offset: u64, width: Width) -> Result<u64, MmioError> {
            self.bus.read(
                PHYSICAL + offset,
                width,
                &mut Access::new(0, 1, &mut self.latch),
            )
        }
        fn write(&mut self, offset: u64, width: Width, value: u64) -> Result<(), MmioError> {
            self.bus.write(
                PHYSICAL + offset,
                width,
                value,
                &mut Access::new(0, 1, &mut self.latch),
            )
        }
        fn set(&mut self, state: super::super::bus::LifecycleState) {
            let lifecycle = self.bus.lifecycle(self.device).expect("actual SEP owner");
            lifecycle.check_lifecycle(state).unwrap();
            lifecycle.set_lifecycle(state, &mut Access::new(0, 1, &mut self.latch));
        }
        fn advance(&mut self) {
            assert_eq!(
                self.bus.advance(&mut Access::new(0, 1, &mut self.latch)),
                Ok(None)
            );
        }
    }
    fn random_request() -> u64 {
        Frame {
            service: ROM,
            tag: 0,
            opcode: 16,
            parameter: 0,
            data: 0,
        }
        .mailbox()
        .payload
    }

    #[test]
    fn actual_mounted_rom_random_requires_entropy_and_full_mailbox_commit_before_reply() {
        use std::{cell::Cell, rc::Rc};
        let calls = Rc::new(Cell::new(0));
        let observed = calls.clone();
        let mut mounted = Mounted::new(Box::new(move |bytes: &mut [u8]| {
            assert_eq!(bytes.len(), 4);
            let call = observed.get();
            observed.set(call + 1);
            bytes.copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
            if call == 0 {
                Err("injected real entropy-source failure")
            } else {
                Ok(())
            }
        }));
        assert_eq!(mounted.read(0x44, Width::Word), Ok(1 << 4));
        assert_eq!(mounted.read(0x8114, Width::Word), Ok(1 | 1 << 17));
        mounted
            .write(0x8800, Width::Double, random_request())
            .unwrap();
        assert_eq!(calls.get(), 0, "staged first word cannot consume entropy");
        assert!(mounted.write(0x8808, Width::Double, 1 << 8).is_err());
        assert_eq!(
            calls.get(),
            0,
            "unqualified raw extension cannot be dropped"
        );
        // An entropy failure gets SEPROM's failure reply, reported once.
        mounted.write(0x8808, Width::Double, 0).unwrap();
        assert_eq!(calls.get(), 1);
        assert!(mounted.latch.is_asserted(Wire::Aic(mounted.irqs[2])));
        let failure = mounted.read(0x8830, Width::Double).unwrap();
        assert_eq!(Frame::from_payload(failure).opcode, 199);
        mounted.read(0x8838, Width::Double).unwrap();
        let sep = mounted.bus.device_mut::<Sep>(mounted.device).unwrap();
        assert_eq!(sep.take_unmodeled().len(), 1);
        // A new request then succeeds.
        mounted
            .write(0x8800, Width::Double, random_request())
            .unwrap();
        mounted.write(0x8808, Width::Double, 0).unwrap();
        assert_eq!(calls.get(), 2);
        assert!(mounted.latch.is_asserted(Wire::Aic(mounted.irqs[2])));
        let reply = 0x78563412_007400ff;
        assert_eq!(mounted.read(0x8830, Width::Double), Ok(reply));
        assert_eq!(mounted.read(0x8830, Width::Double), Ok(reply));
        assert_eq!(mounted.read(0x8838, Width::Double), Ok(1 << 52));
        assert!(!mounted.latch.is_asserted(Wire::Aic(mounted.irqs[2])));
        assert!(mounted.read(0x8838, Width::Double).is_err());
        assert!(mounted.write(0x8808, Width::Double, 0).is_err());
        assert_eq!(calls.get(), 2, "consumed transaction cannot be replayed");
        let sep = mounted.bus.device_mut::<Sep>(mounted.device).unwrap();
        assert!(sep.evidence().is_none());
        assert!(!sep.booted());
    }

    #[test]
    fn actual_mounted_sep_retains_staged_and_committed_work_across_checked_gates() {
        use std::{cell::Cell, rc::Rc};
        let calls = Rc::new(Cell::new(0));
        let observed = calls.clone();
        let mut mounted = Mounted::new(Box::new(move |bytes: &mut [u8]| {
            observed.set(observed.get() + 1);
            bytes.copy_from_slice(&[1, 2, 3, 4]);
            Ok(())
        }));
        mounted
            .write(0x8800, Width::Double, random_request())
            .unwrap();
        for paused in [
            super::super::bus::LifecycleState {
                clocked: false,
                ..ACTIVE
            },
            super::super::bus::LifecycleState {
                powered: false,
                ..ACTIVE
            },
            super::super::bus::LifecycleState {
                quiesced: true,
                ..ACTIVE
            },
        ] {
            mounted.set(paused);
            mounted.advance();
            assert!(mounted.write(0x8808, Width::Double, 0).is_err());
            assert_eq!(calls.get(), 0);
            mounted.set(ACTIVE);
        }
        mounted.write(0x8808, Width::Double, 0).unwrap();
        assert_eq!(calls.get(), 1);
        let reset = super::super::bus::LifecycleState {
            reset: true,
            ..ACTIVE
        };
        assert_eq!(
            mounted
                .bus
                .lifecycle(mounted.device)
                .unwrap()
                .check_lifecycle(reset),
            Err("ASC reset or power loss with owned mailbox messages")
        );
        mounted.set(super::super::bus::LifecycleState {
            powered: false,
            ..ACTIVE
        });
        assert!(mounted.read(0x8830, Width::Double).is_err());
        assert!(
            mounted.latch.is_asserted(Wire::Aic(mounted.irqs[2])),
            "owned IRQ level survives retained rail pause"
        );
        mounted.set(ACTIVE);
        assert_eq!(mounted.read(0x8830, Width::Double), Ok(0x04030201_007400ff));
        mounted.read(0x8838, Width::Double).unwrap();
        let lifecycle = mounted.bus.lifecycle(mounted.device).unwrap();
        assert_eq!(
            lifecycle.check_lifecycle(reset),
            Err("SEP physical reset and nonretained security-state restoration are not qualified")
        );
        assert_eq!(
            lifecycle.check_lifecycle(super::super::bus::LifecycleState {
                powered: false,
                retention: false,
                ..ACTIVE
            }),
            Err("SEP physical reset and nonretained security-state restoration are not qualified")
        );
        assert_eq!(mounted.read(0x44, Width::Word), Ok(1 << 4));
        assert!(
            mounted.read(0x10000, Width::Word).is_err(),
            "unknown bank cannot become a zero image"
        );
        mounted
            .write(
                0x8800,
                Width::Double,
                Frame {
                    service: ROM,
                    tag: 0,
                    opcode: 37,
                    parameter: 0,
                    data: 0,
                }
                .mailbox()
                .payload,
            )
            .unwrap();
        // An unqualified security opcode gets SEPROM's failure reply, never
        // an ACK.
        mounted.write(0x8808, Width::Double, 0).unwrap();
        let failure = mounted.read(0x8830, Width::Double).unwrap();
        assert_eq!(Frame::from_payload(failure).opcode, 199);
    }

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
            Ok(0x0000_0001_0066_01ff)
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
