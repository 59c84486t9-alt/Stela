//! Actual101d02c callback, registered by101cfcc..101cff0 with context
//! {same platform owner, slot}. Its disable precedes the source P300 byte store.
use super::super::platform::{
    Descriptor,
    ingestion::control::{AuxiliaryBinding, Configuration},
    owner::Completion,
};
use super::{Error, Event, Handler, Signals};
use alloc::rc::Rc;
use core::cell::Cell;
use stela_contracts::bus::Access;

/// Opaque live callback receipt, minted only from the actual Signals context
/// after the same source disable and actual registration retired. Event data
/// alone cannot construct one or mutate a control allocation.
#[derive(Clone)]
pub struct AuxiliaryReset {
    binding: AuxiliaryBinding,
    event: Event,
    native: Rc<()>,
    live: Rc<Cell<u64>>,
}
impl AuxiliaryReset {
    pub(super) fn retired(
        binding: AuxiliaryBinding,
        event: Event,
        native: Rc<()>,
        live: Rc<Cell<u64>>,
    ) -> Self {
        Self {
            binding,
            event,
            native,
            live,
        }
    }
    pub fn event(&self) -> Event {
        self.event
    }
    pub fn slot(&self) -> usize {
        self.binding.slot()
    }
    pub(in crate::platform::apple::pmp::native) fn validate(
        &self,
        binding: &AuxiliaryBinding,
    ) -> Result<(), &'static str> {
        if !self.binding.same(binding)
            || !binding.registered()
            || self.live.get() != self.event.generation
        {
            return Err("auxiliary reset receipt is foreign, unregistered or no longer live");
        }
        Ok(())
    }
    pub(in crate::platform::apple::pmp::native) fn after(
        &self,
        previous: &Self,
    ) -> Result<bool, &'static str> {
        if !Rc::ptr_eq(&self.native, &previous.native)
            || self.event.generation < previous.event.generation
        {
            return Err("auxiliary reset native owner is foreign or event is stale");
        }
        Ok(self.event.generation != previous.event.generation)
    }
}

/// Mandatory handle to the same actual platform/control software allocation.
/// Root must validate its instance and slot against the registration producer.
/// It stores1 at P300+40*slot byte0 only after this real IRQ callback's disable
/// has retired; it must not reset timers, synthesize a capture or acknowledge PMP.
pub trait AuxiliaryTarget {
    fn reset_slot(&mut self, reset: &AuxiliaryReset, access: &mut Access<'_>) -> Completion<()>;
}

pub struct AuxiliaryHandler<T> {
    target: T,
    slot: usize,
    source: u32,
    binding: AuxiliaryBinding,
    pending: Option<(u64, u8)>,
}
impl<T: AuxiliaryTarget> AuxiliaryHandler<T> {
    /// Factory only: this does not register a handler or manufacture the
    /// nonzero member-flag condition that actually reaches101cfcc.
    pub fn t8112(
        descriptor: &Descriptor,
        slot: usize,
        binding: AuxiliaryBinding,
        target: T,
    ) -> Result<Self, Error> {
        let configuration = Configuration::t8112(descriptor).map_err(|_| {
            Error::Refused("auxiliary IRQ handler requires qualified source configuration")
        })?;
        let row = configuration.rows().get(slot).ok_or(Error::Refused(
            "auxiliary IRQ handler slot exceeds complete source geometry",
        ))?;
        if binding.slot() != slot || binding.source() != row.words[1] {
            return Err(Error::Refused(
                "auxiliary IRQ handler binding differs from configured same-owner slot",
            ));
        }
        Ok(Self {
            target,
            slot,
            source: row.words[1],
            binding,
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
        if !self.binding.registered() {
            return Completion::Refused("auxiliary IRQ registration producer has not retired");
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
            let reset = match signals.reset_receipt(&self.binding, event) {
                Ok(reset) => reset,
                Err(Error::Refused(reason)) => return Completion::Refused(reason),
                Err(Error::Uncertain(_)) => {
                    return Completion::Refused("auxiliary IRQ reset has uncertain actual owner");
                }
            };
            match self.target.reset_slot(&reset, access) {
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
