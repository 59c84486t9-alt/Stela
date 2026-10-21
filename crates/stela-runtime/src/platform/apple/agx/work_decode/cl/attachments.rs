//! Linear transfer from the completed CL parameter phase to its original
//! fixed attachment acquisition. The pool and its held result remain owned
//! through fault/retry and cancellation; no native trigger occurs here.

use super::Parameters;
use crate::platform::apple::agx::work_decode::resources::{self, Outcome, Pool};
use alloc::boxed::Box;

/// The actual composed SGX/cache handle additionally qualifies the source
/// program's submission, lease and native parameter phase before pool work.
pub trait Access: resources::Access {
    fn check_owner(&self, parameters: &Parameters) -> Result<(), &'static str>;
}

#[derive(Debug)]
pub struct Attachments {
    parameters: Box<Parameters>,
    pool: Box<Pool>,
    started: bool,
    cancel: bool,
    outcome: Option<Outcome>,
}
impl Attachments {
    pub fn new(
        parameters: Parameters,
        pool: Pool,
    ) -> Result<Self, (Box<Parameters>, Box<Pool>, &'static str)> {
        let refusal = if !parameters.completed() {
            Some("GFX CL attachment acquisition precedes complete native parameters")
        } else if pool.policy() != parameters.policy {
            Some("GFX CL attachment pool belongs to another fixed family")
        } else if pool.pending() {
            Some("GFX CL attachment pool already owns another transition")
        } else {
            None
        };
        if let Some(reason) = refusal {
            return Err((Box::new(parameters), Box::new(pool), reason));
        }
        Ok(Self {
            parameters: Box::new(parameters),
            pool: Box::new(pool),
            started: false,
            cancel: false,
            outcome: None,
        })
    }
    pub fn result(&self) -> Option<&Outcome> {
        self.outcome.as_ref()
    }
    pub fn abort(&mut self) -> Result<(), &'static str> {
        if self.started {
            self.pool.abort_pending_acquire()?;
        }
        self.cancel = true;
        self.outcome = None;
        Ok(())
    }
    pub fn advance(&mut self, access: &mut dyn Access) -> Result<(), &'static str> {
        if self.outcome.is_some() {
            return Ok(());
        }
        access.check_owner(&self.parameters)?;
        access.check_available()?;
        if !self.started {
            self.pool.acquire(
                access.memory(),
                self.parameters.lease,
                self.parameters.submission.context,
                &self.parameters.attachments,
            )?;
            self.started = true;
            if self.cancel {
                self.pool.abort_pending_acquire()?;
            }
        }
        self.outcome = Some(
            self.pool
                .advance(access)?
                .ok_or("GFX CL attachment acquisition lost its owned pool transition")?
                .clone(),
        );
        Ok(())
    }
    /// A finished acquisition still holds its pool result until this linear
    /// transfer. Canceling that held result settles real release first.
    pub fn finish(mut self) -> Result<(Parameters, Pool, Outcome), (Self, &'static str)> {
        if self.outcome.is_none() {
            return Err((
                self,
                "GFX CL attachment phase still owns unfinished effects",
            ));
        }
        let result = match self.pool.finish() {
            Ok(result) => result,
            Err(reason) => return Err((self, reason)),
        };
        Ok((*self.parameters, *self.pool, result))
    }
}
