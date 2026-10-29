//! Native coprocessor interrupt owner, distinct from AP AIC and PTD transport.
//!
//! Original26A434 T8112 PMP SHA256
//! b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c:
//! constructor10066f0..10067b8, selected vtable1035608, initialize1026008,
//! dispatch1026194, signal1026280/10263f8, registry10262b4/1026328.
//! Fresh static evidence: memory/native-interrupts-r1. Firmware is never
//! executed. Required device/line/callback owners have no defaults.
mod auxiliary;
pub mod device;
mod owner;

use super::platform::owner::Completion;
pub use auxiliary::{AuxiliaryHandler, AuxiliaryReset, AuxiliaryTarget};
pub use owner::{Event, Handler, Owner, Registration, Signal, Signals, Snapshot};
use stela_contracts::Refusal;
use stela_contracts::refuse;
use {
    stela_contracts::bus::Access, stela_contracts::bus::MmioDevice,
    stela_contracts::bus::MmioError, stela_contracts::bus::Width,
};

pub const SPECIAL: u32 = 0x0800_0000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// No effect retired. A missing required owner must return this variant.
    Refused(Refusal),
    /// MMIO may have retired; the owner permanently prevents access replay.
    Uncertain(MmioError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement {
    pub address: u64,
    pub bytes: u64,
    pub relocation: u64,
}
impl Placement {
    ///1044650 is relocatable:1006714..28 adds actual1079fb0. Zero is allowed
    /// only when it is the declared runtime relocation, never a default.
    pub fn t8112(relocation: u64) -> Result<Self, Error> {
        let address = 0x23b0c0000u64
            .checked_add(relocation)
            .ok_or(Error::Refused(refuse!(
                "native interrupt mapping relocation overflow"
            )))?;
        address.checked_add(0x20000).ok_or(Error::Refused(refuse!(
            "native interrupt aperture overflow"
        )))?;
        Ok(Self {
            address,
            bytes: 0x20000,
            relocation,
        })
    }
}

/// Source software configuration or an observation of it, not
/// controller reset/enable state. The original global BSS image has zero bytes
/// at P28/P8c; runtime overrides require their producers. Only bit0 is
/// interpreted. Snapshot-enabled lifecycle paths require real saved words.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SoftwareConfiguration {
    pub routing_flags: u8,
    pub save_flags: u8,
}

/// Required native device, ordering and CPU IRQ route. Numeric aperture
/// matching alone does not check an independently copied register bank.
/// Refused must be effect-free; every ambiguous MMIO error is Uncertain.
pub trait Device {
    fn placement(&self) -> Placement;
    fn read(&mut self, offset: u64, access: &mut Access<'_>) -> Result<u32, Error>;
    fn write(&mut self, offset: u64, value: u32, access: &mut Access<'_>) -> Result<(), Error>;
    fn order(&mut self, access: &mut Access<'_>) -> Result<(), Error>;
    /// Native ISR_EL1 bit7 route after one dispatched event. Never an
    /// expected mask, AP IRQ, queued request or guessed cache-counter event.
    fn irq_pending(&mut self, access: &mut Access<'_>) -> Result<bool, Error>;
}
pub trait Route {
    fn order(&mut self, access: &mut Access<'_>) -> Result<(), Error>;
    fn irq_pending(&mut self, access: &mut Access<'_>) -> Result<bool, Error>;
}

/// Adapter keeping MMIO and native line/order owners. `new` stores a
/// declared placement; it grants no mapped-borrow capability. Root must
/// check the same bus-owned view and native route when composing the owner.
/// Bounds checks below establish only the declared aperture, never identity.
pub struct Mapped<M, R> {
    placement: Placement,
    device: M,
    route: R,
}
impl<M, R> Mapped<M, R> {
    pub fn new(placement: Placement, device: M, route: R) -> Self {
        Self {
            placement,
            device,
            route,
        }
    }
}
impl<M: MmioDevice, R: Route> Device for Mapped<M, R> {
    fn placement(&self) -> Placement {
        self.placement
    }
    fn read(&mut self, offset: u64, access: &mut Access<'_>) -> Result<u32, Error> {
        if offset & 3 != 0
            || offset
                .checked_add(4)
                .is_none_or(|end| end > self.placement.bytes)
        {
            return Err(Error::Refused(refuse!(
                "native interrupt word read exceeds declared mapped aperture"
            )));
        }
        self.device
            .read(offset, Width::Word, access)
            .map(|v| v as u32)
            .map_err(Error::Uncertain)
    }
    fn write(&mut self, offset: u64, value: u32, access: &mut Access<'_>) -> Result<(), Error> {
        if offset & 3 != 0
            || offset
                .checked_add(4)
                .is_none_or(|end| end > self.placement.bytes)
        {
            return Err(Error::Refused(refuse!(
                "native interrupt word write exceeds declared mapped aperture"
            )));
        }
        self.device
            .write(offset, Width::Word, u64::from(value), access)
            .map_err(Error::Uncertain)
    }
    fn order(&mut self, access: &mut Access<'_>) -> Result<(), Error> {
        self.route.order(access)
    }
    fn irq_pending(&mut self, access: &mut Access<'_>) -> Result<bool, Error> {
        self.route.irq_pending(access)
    }
}

/// Retired source return or event outcome; none denotes native command
/// ACK, a device event producer, controller readiness or whole boot admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Signal {
        previous: bool,
    },
    Dispatched {
        source: u32,
        registered: bool,
        more: bool,
    },
    OtherEvent {
        word: u32,
    },
    Special {
        registered: bool,
    },
}
pub(super) fn refused(error: Error) -> Completion<Outcome> {
    Completion::Refused(match error {
        Error::Refused(reason) => reason,
        Error::Uncertain(_) => {
            refuse!("native interrupt device retirement uncertain; replay refused")
        }
    })
}

#[cfg(test)]
mod tests;
