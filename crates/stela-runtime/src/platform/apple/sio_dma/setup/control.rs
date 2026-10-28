//! Native ownership of the recovered wrapper/ICU tunable SET_PARAM requests.
//! This is a setup component, not a complete SIO firmware or version handshake.
use super::{Effect, EffectResult, FinishError, Request, TunableProgram};
use crate::platform::apple::sio_dma::Error;
use stela_contracts::dma::Port;

/// A physical map range qualified by the actual owner. Geometry alone does
/// not qualify its registers; requests still use checked machine MMIO.
#[derive(Debug, Clone, Copy)]
pub struct PhysicalRange {
    pub base: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct Buffer {
    address: u64,
    bytes: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Table,
    Effects,
    Reply,
}

struct Pending {
    request: u64,
    bank: usize,
    generation: u64,
    phase: Phase,
    program: Option<TunableProgram>,
}

/// The controller generation qualifies a program-local effect ticket. A stale
/// result from a previous SET_PARAM cannot retire an identical new operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlEffect {
    generation: u64,
    effect: Effect,
}
impl ControlEffect {
    pub fn request(self) -> Request {
        self.effect.request()
    }
}

/// Wrapper parameters0x1e/0x1f and ICU parameters0x20/0x21, respectively.
/// Only one request/reply is owned here at a time. Unsupported setup families
/// remain explicit; this component never invents a complete SIO handshake.
pub struct TunableControl {
    ranges: [PhysicalRange; 2],
    buffers: [Buffer; 2],
    generation: u64,
    pending: Option<Pending>,
}
impl TunableControl {
    pub fn new(wrapper: PhysicalRange, icu: PhysicalRange) -> Result<Self, Error> {
        for range in [wrapper, icu] {
            if range.base.checked_add(range.bytes).is_none() {
                return Err(Error::Unsupported("SIO setup physical range overflows"));
            }
        }
        Ok(Self {
            ranges: [wrapper, icu],
            buffers: [Buffer::default(); 2],
            generation: 0,
            pending: None,
        })
    }

    /// Own a global SET_PARAM without prematurely sending an ACK. Original
    /// VA0x12ac/0x1330 stores each address/length once while nonzero; applying
    /// tunables waits until both exist. A zero field remains unset, as there.
    pub fn receive(&mut self, request: u64) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(Error::Unsupported(
                "SIO setup request or reply is still owned",
            ));
        }
        if request as u8 != 0 || (request >> 16) as u8 != 3 {
            return Err(Error::Unsupported("SIO setup command is not qualified"));
        }
        let parameter = (request >> 24) as u8;
        let (bank, address) = match parameter {
            0x1e => (0, true),
            0x1f => (0, false),
            0x20 => (1, true),
            0x21 => (1, false),
            _ => {
                return Err(Error::Unsupported(
                    "SIO setup parameter family is not qualified",
                ));
            }
        };
        let data = (request >> 32) as u32;
        let mut buffer = self.buffers[bank];
        if address {
            if buffer.address != 0 {
                return Err(Error::Unsupported(
                    "SIO setup buffer address is already owned",
                ));
            }
            buffer.address = u64::from(data) << 12;
        } else {
            if buffer.bytes != 0 {
                return Err(Error::Unsupported("SIO setup buffer size is already owned"));
            }
            if data > super::MAX_TABLE_BYTES || !data.is_multiple_of(super::ROW_BYTES as u32) {
                return Err(Error::Unsupported(
                    "SIO tunable table length is not qualified",
                ));
            }
            buffer.bytes = data;
        }
        let generation = self.generation.checked_add(1).ok_or(Error::Unsupported(
            "SIO setup request generation is exhausted",
        ))?;
        self.buffers[bank] = buffer;
        self.generation = generation;
        self.pending = Some(Pending {
            request,
            bank,
            generation,
            phase: if buffer.address != 0 && buffer.bytes != 0 {
                Phase::Table
            } else {
                Phase::Reply
            },
            program: None,
        });
        Ok(())
    }

    pub fn dma_pending(&self) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|pending| pending.phase == Phase::Table)
    }

    /// Acquire RAM through the actual IOMMU stream before exposing a physical
    /// effect. A fault keeps the request/fields for retry and emits no ACK.
    pub fn dma(&mut self, port: &mut Port<'_, '_>) -> Result<(), Error> {
        let Some(pending) = self
            .pending
            .as_mut()
            .filter(|pending| pending.phase == Phase::Table)
        else {
            return Ok(());
        };
        let buffer = self.buffers[pending.bank];
        let range = self.ranges[pending.bank];
        let program =
            TunableProgram::load(port, buffer.address, buffer.bytes, range.base, range.bytes)?;
        pending.phase = if program.complete() {
            Phase::Reply
        } else {
            Phase::Effects
        };
        pending.program = Some(program);
        Ok(())
    }

    /// Claim outside the machine's mutable bus borrow. While claimed, nested
    /// service cannot claim it again; suspension must prevent new claims.
    pub fn begin_effect(&mut self) -> Result<Option<ControlEffect>, Error> {
        let Some(pending) = self
            .pending
            .as_mut()
            .filter(|pending| pending.phase == Phase::Effects)
        else {
            return Ok(None);
        };
        Ok(pending
            .program
            .as_mut()
            .expect("effect phase owns program")
            .begin_effect()?
            .map(|effect| ControlEffect {
                generation: pending.generation,
                effect,
            }))
    }

    pub fn finish_effect<E>(
        &mut self,
        expected: ControlEffect,
        result: Result<EffectResult, E>,
    ) -> Result<(), FinishError<E>> {
        let Some(pending) = self.pending.as_mut().filter(|pending| {
            pending.phase == Phase::Effects && pending.generation == expected.generation
        }) else {
            return Err(FinishError::Ownership(
                "SIO setup result has no matching request generation",
            ));
        };
        let program = pending.program.as_mut().expect("effect phase owns program");
        program.finish_effect(expected.effect, result)?;
        if program.complete() {
            pending.phase = Phase::Reply;
        }
        Ok(())
    }

    /// Peek the committed ACK; the transport must commit delivery before
    /// releasing it. Original VA0x45b8/0x45d4 returns request kind3 in high32,
    /// not a fabricated zero status. Request parameter is absent from ACK.
    pub fn reply(&self) -> Option<u64> {
        self.pending
            .as_ref()
            .filter(|pending| pending.phase == Phase::Reply)
            .map(|pending| pending.request & 0xffff | 0x65 << 16 | 3 << 32)
    }

    pub fn acknowledge_reply(&mut self, expected: u64) -> Result<(), Error> {
        if self.reply() != Some(expected) {
            return Err(Error::Unsupported(
                "SIO setup ACK delivery has no matching owner",
            ));
        }
        self.pending = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{boxed::Box, vec};
    use {
        crate::platform::apple::gpio::Gpio, stela_contracts::bus::Access,
        stela_contracts::bus::Bus, stela_contracts::bus::MmioError, stela_contracts::bus::Width,
        stela_contracts::dma::Physical, stela_contracts::dma::test_support::Ram,
        stela_contracts::interrupt::AicInput, stela_contracts::interrupt::InterruptLatch,
    };

    const TABLE: u64 = 0x8000;
    const BASE: u64 = 0x238300000;

    fn command(tag: u8, parameter: u8, data: u32) -> u64 {
        u64::from(tag) << 8 | 3 << 16 | u64::from(parameter) << 24 | u64::from(data) << 32
    }
    fn control() -> TunableControl {
        let range = PhysicalRange {
            base: BASE,
            bytes: 8,
        };
        TunableControl::new(range, range).unwrap()
    }
    fn address(control: &mut TunableControl, parameter: u8) {
        control
            .receive(command(7, parameter, (TABLE >> 12) as u32))
            .unwrap();
        let reply = control.reply().unwrap();
        assert_eq!(reply, 7 << 8 | 0x65 << 16 | 3 << 32);
        assert!(!control.dma_pending());
        assert!(control.begin_effect().unwrap().is_none());
        assert!(control.acknowledge_reply(reply ^ 1).is_err());
        control.acknowledge_reply(reply).unwrap();
    }
    fn memory() -> Ram {
        let mut memory = Ram::new(TABLE, 24);
        memory.bytes[4..8].copy_from_slice(&4u32.to_le_bytes());
        memory.bytes[8..16].copy_from_slice(&1u64.to_le_bytes());
        memory
    }
    fn dma(control: &mut TunableControl, memory: &mut Ram) -> Result<(), Error> {
        let mut physical = Physical;
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut port = Port {
            iommu: &mut physical,
            memory,
            stream: 2,
            access: &mut access,
        };
        control.dma(&mut port)
    }
    fn route(
        control: &mut TunableControl,
        bus: &mut Bus,
        access: &mut Access<'_>,
    ) -> Result<ControlEffect, FinishError<MmioError>> {
        let effect = control.begin_effect().unwrap().unwrap();
        let result = match effect.request() {
            Request::Read { address, width } => {
                bus.read(address, width, access).map(EffectResult::Read)
            }
            Request::Write {
                address,
                width,
                value,
            } => bus
                .write(address, width, value, access)
                .map(|()| EffectResult::Written),
        };
        control.finish_effect(effect, result)?;
        Ok(effect)
    }

    #[test]
    fn set_param_ack_waits_for_dma_and_actual_mounted_physical_effects() {
        let mut control = control();
        let mut memory = memory();
        address(&mut control, 0x1e);
        control.receive(command(0x91, 0x1f, 24)).unwrap();
        assert!(control.dma_pending());
        assert_eq!(control.reply(), None);
        assert!(control.receive(command(8, 0x20, 8)).is_err());
        assert!(control.begin_effect().unwrap().is_none());
        dma(&mut control, &mut memory).unwrap();
        assert!(!control.dma_pending());
        assert_eq!(control.reply(), None);
        let mut bus = Bus::new();
        let id = bus.add(Box::new(
            Gpio::new(2, vec![AicInput::new(0, 30)], &[0], vec![]).unwrap(),
        ));
        bus.map(id, BASE, 8, 0).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let stale_read = route(&mut control, &mut bus, &mut access).unwrap();
        assert_eq!(control.reply(), None);
        assert_eq!(bus.device::<Gpio>(id).unwrap().output(0), Some(true));
        route(&mut control, &mut bus, &mut access).unwrap();
        assert_eq!(bus.device::<Gpio>(id).unwrap().output(0), Some(false));
        assert_eq!(control.reply(), Some(0x91 << 8 | 0x65 << 16 | 3 << 32));
        assert!(control.begin_effect().unwrap().is_none());
        assert!(control.receive(command(8, 0x20, 8)).is_err());
        let reply = control.reply().unwrap();
        control.acknowledge_reply(reply).unwrap();
        assert!(control.receive(command(1, 0x1f, 24)).is_err());
        // The ICU program uses the same physical address; a ticket from the
        // prior wrapper request must not retire its identical read operation.
        address(&mut control, 0x20);
        control.receive(command(0x92, 0x21, 24)).unwrap();
        dma(&mut control, &mut memory).unwrap();
        let current = control.begin_effect().unwrap().unwrap();
        assert_eq!(stale_read.request(), current.request());
        assert_ne!(stale_read, current);
        assert!(
            control
                .finish_effect::<()>(stale_read, Ok(EffectResult::Read(2)))
                .is_err()
        );
        assert!(control.begin_effect().is_err());
        control
            .finish_effect::<()>(current, Ok(EffectResult::Read(2)))
            .unwrap();
        assert_eq!(control.reply(), Some(0x92 << 8 | 0x65 << 16 | 3 << 32));
    }

    #[test]
    fn dma_and_routed_refusals_retain_request_without_a_success_ack() {
        let mut control = control();
        address(&mut control, 0x1e);
        control.receive(command(11, 0x1f, 24)).unwrap();
        let mut too_short = Ram::new(TABLE, 12);
        assert!(matches!(
            dma(&mut control, &mut too_short),
            Err(Error::Dma(_))
        ));
        assert!(control.dma_pending());
        assert_eq!(control.reply(), None);
        dma(&mut control, &mut memory()).unwrap();
        let mut bus = Bus::new();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        assert_eq!(
            route(&mut control, &mut bus, &mut access),
            Err(FinishError::Access(MmioError::Unmapped {
                address: BASE,
                width: Width::Word
            }))
        );
        assert_eq!(control.reply(), None);
        let effect = control.begin_effect().unwrap().unwrap();
        assert!(control.begin_effect().is_err());
        control
            .finish_effect::<()>(effect, Ok(EffectResult::Read(3)))
            .unwrap();
        let write = control.begin_effect().unwrap().unwrap();
        let original_error =
            alloc::string::String::from("actual routed dynamic refusal, not substituted");
        assert_eq!(
            control.finish_effect(write, Err(original_error.clone())),
            Err(FinishError::Access(original_error))
        );
        assert_eq!(control.reply(), None);
        let retry = control.begin_effect().unwrap().unwrap();
        assert_eq!(
            retry.request(),
            Request::Write {
                address: BASE,
                width: Width::Word,
                value: 2
            }
        );
        control
            .finish_effect::<()>(retry, Ok(EffectResult::Written))
            .unwrap();
        assert!(control.reply().is_some());
    }

    #[test]
    fn unset_fields_and_unknown_setup_never_claim_a_complete_firmware() {
        let mut control = control();
        // Unknown families and GET_PARAM/version are explicit. This native
        // tunable component cannot publish complete SIO firmware support.
        for request in [
            2 << 16,
            command(1, 0x22, 8),
            command(1, 0x1f, 23),
            command(1, 0x1e, 8) | 1,
        ] {
            assert!(control.receive(request).is_err());
            assert_eq!(control.reply(), None);
        }
        for parameter in [0x1e, 0x1e, 0x1f, 0x1f] {
            control.receive(command(1, parameter, 0)).unwrap();
            assert!(!control.dma_pending());
            let reply = control.reply().unwrap();
            control.acknowledge_reply(reply).unwrap();
        }
        // Size before address is stored, then address triggers the real DMA.
        control.receive(command(2, 0x1f, 24)).unwrap();
        let reply = control.reply().unwrap();
        control.acknowledge_reply(reply).unwrap();
        control.receive(command(3, 0x1e, 8)).unwrap();
        assert!(control.dma_pending());
        assert_eq!(control.reply(), None);
        assert!(
            TunableControl::new(
                PhysicalRange {
                    base: u64::MAX,
                    bytes: 1
                },
                PhysicalRange { base: 0, bytes: 0 }
            )
            .is_err()
        );
    }
}
