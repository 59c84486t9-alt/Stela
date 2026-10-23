//! Native coprocessor interrupt owner, distinct from AP AIC and PTD transport.
//!
//! Original26A434 T8112 PMP SHA256
//! b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c:
//! constructor10066f0..10067b8, selected vtable1035608, initialize1026008,
//! dispatch1026194, signal1026280/10263f8, registry10262b4/1026328.
//! Exact fresh static evidence: memory/native-interrupts-r1. Firmware is never
//! executed. Required actual device/line/callback owners have no defaults.
mod auxiliary;
mod owner;
#[cfg(test)]
mod tests;

use super::platform::owner::Completion;
use crate::platform::apple::bus::{Access, MmioDevice, MmioError, Width};
pub use auxiliary::{AuxiliaryHandler, AuxiliaryTarget};
pub use owner::{Event, Handler, Owner, Registration, Signal, Signals, Snapshot};

pub const SPECIAL: u32 = 0x0800_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No effect retired. A missing required owner must return this variant.
    Refused(&'static str),
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
    /// only when it is the actual declared runtime relocation, never a default.
    pub fn t8112(relocation: u64) -> Result<Self, Error> {
        let address = 0x23b0c0000u64
            .checked_add(relocation)
            .ok_or(Error::Refused(
                "native interrupt mapping relocation overflow",
            ))?;
        address
            .checked_add(0x20000)
            .ok_or(Error::Refused("native interrupt aperture overflow"))?;
        Ok(Self {
            address,
            bytes: 0x20000,
            relocation,
        })
    }
}

/// Actual source software configuration or a retained observation of it, not
/// controller reset/enable state. The original global BSS image has zero bytes
/// at P28/P8c; runtime overrides require their actual producers. Only bit0 is
/// interpreted. Snapshot-enabled lifecycle paths require real saved words.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SoftwareConfiguration {
    pub routing_flags: u8,
    pub save_flags: u8,
}

/// Required actual native device, ordering and CPU IRQ route. Numeric aperture
/// matching alone does not qualify an independently copied register bank.
/// Refused must be effect-free; every ambiguous MMIO error is Uncertain.
pub trait Device {
    fn placement(&self) -> Placement;
    fn read(&mut self, offset: u64, access: &mut Access<'_>) -> Result<u32, Error>;
    fn write(&mut self, offset: u64, value: u32, access: &mut Access<'_>) -> Result<(), Error>;
    fn order(&mut self, access: &mut Access<'_>) -> Result<(), Error>;
    /// Actual native ISR_EL1 bit7 route after one dispatched event. Never an
    /// expected mask, AP IRQ, queued request or guessed cache-counter event.
    fn irq_pending(&mut self, access: &mut Access<'_>) -> Result<bool, Error>;
}
pub trait Route {
    fn order(&mut self, access: &mut Access<'_>) -> Result<(), Error>;
    fn irq_pending(&mut self, access: &mut Access<'_>) -> Result<bool, Error>;
}

/// Adapter retaining actual MMIO and native line/order owners. The caller must
/// supply an identity-preserving mapped view, not a second independent bus owner.
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
        self.device
            .read(offset, Width::Word, access)
            .map(|v| v as u32)
            .map_err(Error::Uncertain)
    }
    fn write(&mut self, offset: u64, value: u32, access: &mut Access<'_>) -> Result<(), Error> {
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

/// Actual retired source return or event outcome; none denotes native command
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
        Error::Uncertain(_) => "native interrupt device retirement uncertain; replay refused",
    })
}
