//! Admission closure and GPU idle acknowledgement for the native owner.
use super::Device;
use crate::metal::{
    error::{Error, Result},
    shader::Compiler,
    vulkan::backend::Backend,
};

/// GPU progress after admission closes. None of these states acknowledges
/// PCI removal, reset, gate disconnection or DMA-domain invalidation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuiesceStatus {
    /// Previously accepted work still needs to finish. Unsatisfied event
    /// dependencies may keep this state pending indefinitely.
    Pending { completed: u64, submitted: u64 },
    /// The backend acknowledged GPU idleness. Objects and imported memory
    /// remain owned until their owners release them and consume retirement.
    GpuIdle,
    /// Completion or backend idleness could not be established. Keep the
    /// native owner, its code, objects and imports alive.
    Unproven(Error),
}

impl<B: Backend, C: Compiler> Device<B, C> {
    /// Permanently closes imports and command submission. Previously
    /// accepted work may continue through `poll` or `quiesce_step`.
    pub fn begin_quiesce(&mut self) {
        self.quiesce.get_or_insert(QuiesceStatus::Pending {
            completed: self.completed,
            submitted: self.submitted,
        });
    }

    pub fn is_quiescing(&self) -> bool {
        self.quiesce.is_some()
    }

    /// Whether the backend acknowledged idleness after admission closed.
    pub fn is_quiesced(&self) -> bool {
        matches!(self.quiesce, Some(QuiesceStatus::GpuIdle))
    }

    pub(crate) fn ensure_admission(&self) -> Result<()> {
        if self.lost {
            Err(Error::DeviceLost)
        } else if self.is_quiescing() {
            Err(Error::Invalid("the device is quiescing"))
        } else {
            Ok(())
        }
    }

    /// Makes one progress query, without waiting for pending timeline or
    /// event values. Once tracked work finishes, asks the backend to
    /// acknowledge idleness; that backend operation may block. Failure is
    /// sticky and never manufactures a completion serial or retirement token.
    pub fn quiesce_step(&mut self) -> QuiesceStatus {
        self.begin_quiesce();
        let status = match self.quiesce {
            Some(QuiesceStatus::Unproven(error)) => return QuiesceStatus::Unproven(error),
            _ if self.lost => QuiesceStatus::Unproven(Error::DeviceLost),
            Some(QuiesceStatus::GpuIdle) => return QuiesceStatus::GpuIdle,
            _ => match self.poll() {
                Err(error) => QuiesceStatus::Unproven(error),
                Ok(completed) if completed < self.submitted => QuiesceStatus::Pending {
                    completed,
                    submitted: self.submitted,
                },
                Ok(_) => match self.backend.acknowledge_idle() {
                    Ok(()) => QuiesceStatus::GpuIdle,
                    Err(error) => QuiesceStatus::Unproven(error),
                },
            },
        };
        if matches!(status, QuiesceStatus::Unproven(_)) {
            self.mark_lost();
        }
        self.quiesce = Some(status);
        status
    }
}

#[cfg(test)]
mod tests;
