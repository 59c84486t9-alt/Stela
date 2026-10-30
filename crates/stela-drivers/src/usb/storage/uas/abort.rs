//! Opt-in, serialized ABORT TASK for an outstanding timed-out CDB.
//! No task-set, LUN-reset or general asynchronous management service is implied.
// SPDX-License-Identifier: GPL-2.0-only
use super::*;

const TASK_MGMT_IU: u8 = 5;
const ABORT_TASK: u8 = 1;
const FUNCTION_COMPLETE: u8 = 0;
const TASK_IU_BYTES: usize = 16;

/// A nonzero tag admitted by this attachment's configured stream limit.
/// The management tag is selected while its original task remains held.
#[derive(Clone, Copy)]
struct TaskTag(u16);
impl TaskTag {
    fn distinct(original: u16, maximum: u16) -> Result<(Self, Self), BlockError> {
        if original == 0 || original > maximum || maximum < 2 {
            return Err(BlockError::Unsupported(
                "UAS abort needs a distinct task tag",
            ));
        }
        let fresh = if original == maximum { 1 } else { original + 1 };
        Ok((Self(original), Self(fresh)))
    }
}

/// Device acknowledgment and host DMA retirement are separate observations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AbortTaskOutcome {
    /// No matching FUNCTION COMPLETE response was consumed. This includes
    /// refused preconditions, transport failure and malformed/negative replies.
    NotAcknowledged(BlockError),
    /// The real matching Response IU acknowledged ABORT TASK. `retirement`
    /// independently reports the stop/dequeue/drain of original host data TDs.
    /// Even `Ok(())` does not complete the original CDB or permit tag reuse.
    Acknowledged { retirement: Result<(), BlockError> },
}

/// The original CDB result and, only on timeout, the bounded recovery result.
#[derive(Debug)]
pub struct AbortCommandResult {
    pub command: Result<Vec<u8>, BlockError>,
    pub abort: Option<AbortTaskOutcome>,
}
impl Host {
    /// Execute one ordinary CDB, attempting ABORT TASK only if its deadline
    /// expires. The original command still returns `Timeout`; no data is
    /// published from an aborted command. A recovery attempt permanently fences
    /// this class owner and keeps all allocations. Fully acknowledged native
    /// retirement permits the existing whole-device reset/rebind; uncertainty
    /// also quarantines the native slot and requires controller-level recovery.
    ///
    /// Recovery requires the original Command TD completion and a
    /// successful native stop/dequeue/drain of its status request before either
    /// IU buffer is rewritten. SuperSpeed uses a distinct allocated
    /// status stream; HS uses its ordinary status FIFO. An older READY/Sense IU
    /// arriving there is an explicit failed recovery, never silently discarded.
    /// `timeout_us` must be nonzero and at most the ordinary command deadline.
    pub fn command_with_abort_timeout(
        &mut self,
        lun: [u8; 8],
        cdb: &[u8],
        data: Data<'_>,
        timeout_us: u64,
    ) -> AbortCommandResult {
        let mut abort = None;
        let command = (|| {
            if timeout_us == 0 || timeout_us > TIMEOUT_US {
                return Err(BlockError::Unsupported("UAS abort command deadline"));
            }
            if !self.flags.permits(cdb) {
                return Err(BlockError::Unsupported(
                    "CDB requires an unsupported enclosure operation",
                ));
            }
            let length = match &data {
                Data::None => 0,
                Data::In(length) => *length,
                Data::Out(bytes) => bytes.len(),
            };
            if length > self.flags.max_transfer_bytes() {
                return Err(BlockError::Unsupported("UAS enclosure transfer limit"));
            }
            self.engine
                .command_inner(lun, cdb, data, Some(timeout_us), &mut abort)
        })();
        if abort.is_some()
            && !matches!(
                &abort,
                Some(AbortTaskOutcome::Acknowledged { retirement: Ok(()) })
            )
        {
            // Uncertain native contributors cannot use the ordinary class
            // rebind contract. Keep the whole slot quarantined for its owner.
            self.quarantine();
        }
        AbortCommandResult { command, abort }
    }
}
impl<I: Io> Engine<I> {
    pub(super) fn abort_task(&mut self, lun: [u8; 8]) -> AbortTaskOutcome {
        if let Err(error) = self.abort_response(lun) {
            return AbortTaskOutcome::NotAcknowledged(error);
        }
        // A device task response cannot retire the xHC's outstanding data TD.
        // Clear each receipt only after native cancellation ACK/drain.
        let retirement = (|| {
            for pipe in [Pipe::Input, Pipe::Output] {
                if self.pending[pipe.index()].is_some() {
                    self.io.cancel(pipe)?;
                    self.pending[pipe.index()] = None;
                }
            }
            self.io.ready()?;
            Ok(())
        })();
        AbortTaskOutcome::Acknowledged { retirement }
    }
    fn abort_response(&mut self, lun: [u8; 8]) -> Result<(), BlockError> {
        // Validate the original attachment before any buffer access or effect.
        self.io.ready()?;
        if !self.buffers_present()
            || self.pending[Pipe::Command.index()].is_some()
            || !self.touched[Pipe::Command.index()]
            || self.pending[Pipe::Status.index()].is_none()
        {
            return Err(BlockError::Unsupported(
                "UAS abort requires completed command and pending status",
            ));
        }
        let maximum = self.io.streams().unwrap_or(u16::MAX);
        let (original, tag) = TaskTag::distinct(self.tag, maximum)?;
        let command = self.command.bytes();
        if command[0] != COMMAND_IU
            || command[2..4] != original.0.to_be_bytes()
            || command[8..16] != lun
        {
            return Err(BlockError::Unsupported("UAS abort original task identity"));
        }
        // The original status TD may still own this allocation. Acknowledged
        // cancellation includes every stream dequeue and late-event drain.
        self.io.cancel(Pipe::Status)?;
        self.pending[Pipe::Status.index()] = None;
        self.touched[Pipe::Status.index()] = false;
        let iu = task_iu(tag, original, lun);
        self.command.bytes_mut()[..TASK_IU_BYTES].copy_from_slice(&iu);
        self.status.bytes_mut().fill(0);
        self.tag = tag.0;
        self.post(Pipe::Status, self.status.physical(), IU_BUFFER_BYTES)?;
        self.post(Pipe::Command, self.command.physical(), TASK_IU_BYTES)?;
        let started = self.io.now();
        loop {
            // Do not consume the device response before the TMF's own command
            // TD has completed. No original data completion is polled.
            if let Some(ticket) = &self.pending[Pipe::Command.index()]
                && let Some(completion) = self.io.completed(ticket)
            {
                let count = completion?;
                if count != TASK_IU_BYTES {
                    return Err(PROTOCOL_ERROR);
                }
                self.pending[Pipe::Command.index()] = None;
            }
            if self.pending[Pipe::Command.index()].is_none()
                && let Some(ticket) = &self.pending[Pipe::Status.index()]
                && let Some(completion) = self.io.completed(ticket)
            {
                let count = completion?;
                let response = self.status.bytes().get(..count).ok_or(PROTOCOL_ERROR)?;
                // A Response IU has no LUN field. Its fresh tag identifies the
                // one TMF keeping the original task tag and exact LUN.
                if response.len() != 8
                    || response[0] != RESPONSE_IU
                    || response[1] != 0
                    || response[2..4] != tag.0.to_be_bytes()
                    || response[4..7] != [0; 3]
                    || response[7] != FUNCTION_COMPLETE
                {
                    return Err(PROTOCOL_ERROR);
                }
                self.pending[Pipe::Status.index()] = None;
                return Ok(());
            }
            if self.io.now().wrapping_sub(started) >= TIMEOUT_US {
                return Err(BlockError::Timeout);
            }
            self.io.pause();
        }
    }
}
fn task_iu(tag: TaskTag, original: TaskTag, lun: [u8; 8]) -> [u8; TASK_IU_BYTES] {
    let mut bytes = [0; TASK_IU_BYTES];
    bytes[0] = TASK_MGMT_IU;
    bytes[2..4].copy_from_slice(&tag.0.to_be_bytes());
    bytes[4] = ABORT_TASK;
    bytes[6..8].copy_from_slice(&original.0.to_be_bytes());
    bytes[8..16].copy_from_slice(&lun);
    bytes
}

#[cfg(test)]
mod tests;
