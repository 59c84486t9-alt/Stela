//! The actual SGX sink for the original fixed TA parameter phase. Stored
//! native values have no reset readback; only source stores make them known.
//! No trigger or backend invocation is provided by this configuration phase.

use super::FirmwareWork;
use crate::platform::apple::agx::{
    channel::Kind,
    work_decode::{
        Submission,
        resources::{Lease, Outcome},
        ta::{self, Word},
    },
};
use crate::platform::dma::Port;
use alloc::vec::Vec;

#[derive(Debug)]
struct Run {
    submission: Submission,
    lease: Lease,
    next: usize,
    words: Vec<Word>,
}
#[derive(Debug, Default)]
pub(super) struct Registers {
    run: Option<Run>,
    // An absent word remains unknown. This is native configuration, not a
    // RAM substitute or readable register image.
    stored: Vec<(Word, u64)>,
    #[cfg(test)]
    pub(super) writes: usize,
}
impl Registers {
    pub(super) fn active(&self) -> bool {
        self.run.is_some()
    }
    #[cfg(test)]
    pub(super) fn value(&self, word: Word) -> Option<u64> {
        self.stored
            .iter()
            .find(|(stored, _)| *stored == word)
            .map(|(_, value)| *value)
    }
}

pub struct ParameterAccess<'a, 'p, 'm> {
    owner: &'a FirmwareWork,
    port: &'a mut Port<'p, 'm>,
}
impl FirmwareWork {
    pub fn ta_parameter_access<'a, 'p, 'm>(
        &'a self,
        port: &'a mut Port<'p, 'm>,
    ) -> ParameterAccess<'a, 'p, 'm> {
        ParameterAccess { owner: self, port }
    }
    /// The outer source owner settles resources/TVB before cancelling native
    /// ownership. This does not revert any committed configuration stores.
    pub fn cancel_ta_parameters(
        &self,
        submission: &Submission,
        lease: Lease,
        settlement: &Outcome,
    ) -> Result<(), &'static str> {
        self.available()?;
        if !matches!(settlement, Outcome::Aborted) {
            return Err("GFX TA cancellation requires settled resource abort ownership");
        }
        let mut native = self.power.native.borrow_mut();
        let run = native
            .work
            .ta
            .run
            .as_ref()
            .ok_or("GFX TA cancellation has no native owner")?;
        if run.submission != *submission || run.lease != lease {
            return Err("GFX TA cancellation differs from its accepted native owner");
        }
        native.work.ta.run = None;
        Ok(())
    }
}
impl ta::Access for ParameterAccess<'_, '_, '_> {
    fn policy(&self) -> crate::platform::apple::agx::work_decode::resources::Policy {
        self.owner.policy
    }
    fn memory(&mut self) -> &mut dyn crate::platform::apple::agx::ring::Shared {
        self.port
    }
    fn begin(&mut self, submission: &Submission, lease: Lease) -> Result<(), &'static str> {
        self.owner.available()?;
        if submission.command.kind != Kind::Ta
            || lease.pipe != 0
            || lease.slot >= 6
            || submission.context >= 64
        {
            return Err("GFX TA native parameters require their accepted geometry lease/context");
        }
        let mut native = self.owner.power.native.borrow_mut();
        if native.work.run.is_some() {
            return Err("GFX native parameter bank still belongs to accepted CL work");
        }
        let registers = &mut native.work.ta;
        if let Some(run) = &registers.run {
            return if run.submission == *submission && run.lease == lease {
                Ok(())
            } else {
                Err("GFX TA native parameters still belong to another command")
            };
        }
        registers.run = Some(Run {
            submission: submission.clone(),
            lease,
            next: 0,
            words: ta::words(self.owner.policy),
        });
        Ok(())
    }
    fn write_native(&mut self, word: Word, value: u64) -> Result<(), &'static str> {
        let (offset, width) = word.range();
        self.owner.target_word(self.port, offset, width, true)?;
        let mut native = self.owner.power.native.borrow_mut();
        let registers = &mut native.work.ta;
        let run = registers
            .run
            .as_mut()
            .ok_or("GFX TA native parameter store has no accepted owner")?;
        if run.words.get(run.next) != Some(&word)
            || (width == 4 && value > u64::from(u32::MAX))
            || (offset == 0x11000 && value != 0x100)
        {
            return Err("GFX TA native parameter store differs from its source order/width");
        }
        if let Some((_, stored)) = registers
            .stored
            .iter_mut()
            .find(|(known, _)| *known == word)
        {
            *stored = value;
        } else {
            registers.stored.push((word, value));
        }
        run.next += 1;
        #[cfg(test)]
        {
            registers.writes += 1;
        }
        if offset == 0x11000 {
            native.work.setup = value;
        }
        Ok(())
    }
}
