//! Original fixed TA/3D attachment acquisition after native parameters.
//! This phase owns its accepted setup and physical resource pool through
//! fault/retry/cancellation. It does not run the following native callback,
//! configure TVB, start a GPU engine, or retire the work command.

use super::resources::{self, Attachment, Lease, Outcome, Policy, Pool};
use super::{Frame, Submission, ta, three_d};
use alloc::{boxed::Box, vec::Vec};

#[derive(Debug)]
pub enum Parameters {
    Ta(ta::Parameters),
    ThreeD(three_d::Parameters),
}
impl Parameters {
    pub(crate) fn identity(&self) -> (&Submission, &Frame, Lease, Policy) {
        match self {
            Self::Ta(parameters) => parameters.identity(),
            Self::ThreeD(parameters) => parameters.identity(),
        }
    }
    fn completed(&self) -> bool {
        match self {
            Self::Ta(parameters) => parameters.completed(),
            Self::ThreeD(parameters) => parameters.completed(),
        }
    }
}

/// The actual SGX/cache adapter checks the exact complete native owner
/// before any pool comparison, native write or shared-memory tail.
pub trait Access: resources::Access {
    fn check_owner(&self, parameters: &Parameters) -> Result<(), &'static str>;
}

#[derive(Debug)]
pub struct Attachments {
    parameters: Box<Parameters>,
    pool: Box<Pool>,
    rows: Vec<Attachment>,
    started: bool,
    cancel: bool,
    outcome: Option<Outcome>,
}
impl Attachments {
    pub fn new(
        parameters: Parameters,
        pool: Pool,
    ) -> Result<Self, (Box<Parameters>, Box<Pool>, &'static str)> {
        let (submission, frame, _, policy) = parameters.identity();
        let rows = if !parameters.completed() {
            Err("GFX render attachment acquisition precedes complete native parameters")
        } else if pool.policy() != policy {
            Err("GFX render attachment pool belongs to another fixed family")
        } else if pool.pending() {
            Err("GFX render attachment pool already owns another transition")
        } else {
            Attachment::read_setup(submission.encoding, frame)
        };
        let rows = match rows {
            Ok(rows) => rows,
            Err(reason) => return Err((Box::new(parameters), Box::new(pool), reason)),
        };
        Ok(Self {
            parameters: Box::new(parameters),
            pool: Box::new(pool),
            rows,
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
            let (submission, _, lease, _) = self.parameters.identity();
            self.pool
                .acquire(access.memory(), lease, submission.context, &self.rows)?;
            self.started = true;
            if self.cancel {
                self.pool.abort_pending_acquire()?;
            }
        }
        self.outcome = Some(
            self.pool
                .advance(access)?
                .ok_or("GFX render attachments lost their owned resource transition")?
                .clone(),
        );
        Ok(())
    }
    pub fn finish(mut self) -> Result<(Parameters, Pool, Outcome), (Self, &'static str)> {
        if self.outcome.is_none() {
            return Err((self, "GFX render attachments still own unfinished effects"));
        }
        let result = match self.pool.finish() {
            Ok(result) => result,
            Err(reason) => return Err((self, reason)),
        };
        Ok((*self.parameters, *self.pool, result))
    }
}
