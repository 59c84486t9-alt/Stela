//! Actual101d02c callback, registered by101cfcc..101cff0 with context
//! {same platform owner, slot}. Its disable precedes the source P300 byte store.
use super::super::platform::{Descriptor, ingestion::control::Configuration, owner::Completion};
use super::{Error, Event, Handler, Signals};
use crate::platform::apple::bus::Access;

/// Mandatory handle to the same actual platform/control software allocation.
/// Root must validate its instance and slot against the registration producer.
/// It stores1 at P300+40*slot byte0 only after this real IRQ callback's disable
/// has retired; it must not reset timers, synthesize a capture or acknowledge PMP.
pub trait AuxiliaryTarget {
    fn reset_slot(&mut self, event: Event, slot: usize, access: &mut Access<'_>) -> Completion<()>;
}

pub struct AuxiliaryHandler<T> {
    target: T,
    slot: usize,
    source: u32,
    pending: Option<(u64, u8)>,
}
impl<T: AuxiliaryTarget> AuxiliaryHandler<T> {
    /// Factory only: this does not register a handler or manufacture the
    /// nonzero member-flag condition that actually reaches101cfcc.
    pub fn t8112(descriptor: &Descriptor, slot: usize, target: T) -> Result<Self, Error> {
        let configuration = Configuration::t8112(descriptor).map_err(|_| {
            Error::Refused("auxiliary IRQ handler requires qualified source configuration")
        })?;
        let row = configuration
            .rows()
            .get(slot)
            .filter(|r| !r.members.is_empty())
            .ok_or(Error::Refused(
                "auxiliary IRQ handler has no configured member/slot producer",
            ))?;
        Ok(Self {
            target,
            slot,
            source: row.words[1],
            pending: None,
        })
    }
    pub fn source(&self) -> u32 {
        self.source
    }
    pub fn slot(&self) -> usize {
        self.slot
    }
}
impl<T: AuxiliaryTarget> Handler for AuxiliaryHandler<T> {
    fn call(
        &mut self,
        event: Event,
        signals: &mut Signals<'_>,
        access: &mut Access<'_>,
    ) -> Completion<()> {
        if event.source != self.source || event.word.is_none() {
            return Completion::Refused(
                "auxiliary IRQ callback received another source/context route",
            );
        }
        if let Some((generation, stage)) = self.pending {
            if event.generation < generation || (event.generation != generation && stage != 2) {
                return Completion::Refused("auxiliary IRQ callback retains another actual event");
            }
            if event.generation != generation {
                self.pending = Some((event.generation, 0));
            }
        } else {
            self.pending = Some((event.generation, 0));
        }
        if self.pending.unwrap().1 == 0 {
            if let Err(error) = signals.set(0, self.source, false, access) {
                return Completion::Refused(match error {
                    Error::Refused(reason) => reason,
                    Error::Uncertain(_) => "auxiliary IRQ disable retirement is uncertain",
                });
            }
            self.pending = Some((event.generation, 1));
        }
        if self.pending.unwrap().1 == 1 {
            match self.target.reset_slot(event, self.slot, access) {
                Completion::Retired { refusal, .. } => {
                    self.pending = Some((event.generation, 2));
                    return Completion::Retired { value: (), refusal };
                }
                other => return other,
            }
        }
        Completion::Retired {
            value: (),
            refusal: None,
        }
    }
}
