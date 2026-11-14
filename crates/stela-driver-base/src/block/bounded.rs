//! Reads that wait for their device only within a bound, for a caller whose
//! processor answers no one while it waits.

use super::*;
use alloc::rc::Rc;
use core::cell::Cell;

/// The bound a [`Bounded`] device's reads wait within, shared with whoever
/// sets it, and whether the last read ran out of it.
#[derive(Clone, Default)]
pub struct ReadBound(Rc<BoundState>);

#[derive(Default)]
struct BoundState {
    /// Time-stamp counter ticks a read waits at most; `None` waits.
    ticks: Cell<Option<u64>>,
    blocked: Cell<bool>,
}

impl ReadBound {
    /// Have every later read wait at most `ticks` of the time-stamp counter.
    pub fn set(&self, ticks: u64) {
        self.0.ticks.set(Some(ticks));
    }

    /// Whether the last failed read only ran out of its bound: the same
    /// read later takes what the device did meanwhile. Asking clears it.
    pub fn blocked(&self) -> bool {
        self.0.blocked.replace(false)
    }
}

/// Reads started and results kept at most, each for one read a caller asks
/// again for after its bound passed.
const KEPT: usize = 8;

/// A device whose reads, once [`ReadBound::set`] bounds them, go to the
/// device as queued commands and wait for them only within the bound. A
/// read whose command is not done by then fails with
/// [`BlockError::Timeout`], marks the bound blocked and leaves its command
/// running: the same read asked again takes its result. A storage stick
/// that holds one write for seconds then holds no caller for longer than
/// the bound, as a network source bounded for its caller holds none. A
/// device without queued commands, and every read before a bound is set,
/// is read directly. Every other call goes to the device unchanged.
pub struct Bounded {
    device: Box<dyn BlockDevice>,
    bound: ReadBound,
    /// The reads started for bounded reads: first block, bytes, request.
    running: Vec<(u64, usize, Submission)>,
    /// Their results no read has taken yet, oldest first.
    done: VecDeque<(u64, usize, Finished)>,
}

impl Bounded {
    pub fn new(device: Box<dyn BlockDevice>) -> Self {
        Self {
            device,
            bound: ReadBound::default(),
            running: Vec::new(),
            done: VecDeque::new(),
        }
    }

    /// The bound this device's reads wait within.
    pub fn bound(&self) -> ReadBound {
        self.bound.clone()
    }

    fn keep(&mut self, lba: u64, bytes: usize, finished: Finished) {
        if self.done.len() == KEPT {
            self.done.pop_front();
        }
        self.done.push_back((lba, bytes, finished));
    }

    /// Collect the started reads the device has done.
    fn collect(&mut self) {
        let mut index = 0;
        while index < self.running.len() {
            let Some(finished) = self.running[index].2.poll(&mut *self.device) else {
                index += 1;
                continue;
            };
            let (lba, bytes, _) = self.running.swap_remove(index);
            self.keep(lba, bytes, finished);
        }
    }

    /// The bounded read of `buffer` at `lba`, waiting `limit` ticks at most.
    fn read_within(&mut self, lba: u64, buffer: &mut [u8], limit: u64) -> Result<(), BlockError> {
        self.device.identity().check(lba, buffer.len())?;
        let bytes = buffer.len();
        let started = crate::Clock::ticks();
        loop {
            self.collect();
            if let Some(at) = self
                .done
                .iter()
                .position(|(first, length, _)| (*first, *length) == (lba, bytes))
            {
                let (.., finished) = self.done.remove(at).expect("found above");
                let data = finished?.ok_or(BlockError::Protocol("a read returned no data"))?;
                if data.len() != bytes {
                    return Err(BlockError::Protocol("a read returned the wrong length"));
                }
                buffer.copy_from_slice(&data);
                return Ok(());
            }
            let running = self
                .running
                .iter()
                .any(|(first, length, _)| (*first, *length) == (lba, bytes));
            if !running && self.running.len() < KEPT && self.device.room() {
                let request = Request::Read { lba, bytes };
                let mut submission = Submission::new(request, self.device.identity())?;
                match submission.poll(&mut *self.device) {
                    Some(finished) => self.keep(lba, bytes, finished),
                    None => self.running.push((lba, bytes, submission)),
                }
                continue;
            }
            if crate::Clock::ticks().wrapping_sub(started) >= limit {
                self.bound.0.blocked.set(true);
                return Err(BlockError::Timeout);
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }
}

impl BlockDevice for Bounded {
    fn identity(&self) -> &Identity {
        self.device.identity()
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        match self.bound.0.ticks.get() {
            Some(limit) if self.device.depth() > 0 => self.read_within(lba, buffer, limit),
            _ => self.device.read(lba, buffer),
        }
    }

    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.device.write(lba, data)
    }

    fn flush_cache(&mut self) -> Result<(), BlockError> {
        self.device.flush_cache()
    }

    fn write_fua(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.device.write_fua(lba, data)
    }

    fn discard(&mut self, lba: u64, blocks: u64) -> Result<(), BlockError> {
        self.device.discard(lba, blocks)
    }

    fn write_zeroes(&mut self, lba: u64, blocks: u64, unmap: bool) -> Result<(), BlockError> {
        self.device.write_zeroes(lba, blocks, unmap)
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        self.device.flush()
    }

    fn shutdown(&mut self, power_off: bool) -> Result<(), BlockError> {
        self.device.shutdown(power_off)
    }

    /// A command run where it is asked waits for the device, as before.
    fn execute(&mut self, command: Command) -> Finished {
        self.device.execute(command)
    }

    fn depth(&self) -> usize {
        self.device.depth()
    }

    fn room(&self) -> bool {
        self.device.room()
    }

    fn start(&mut self, command: Command) -> Result<u32, BlockError> {
        self.device.start(command)
    }

    fn start_more(&mut self, command: Command) -> Result<u32, BlockError> {
        self.device.start_more(command)
    }

    fn commit(&mut self) {
        self.device.commit();
    }

    fn finish(&mut self, tag: u32) -> Option<Finished> {
        self.device.finish(tag)
    }

    fn reaps_together(&self) -> bool {
        self.device.reaps_together()
    }

    fn finished(&mut self, tag: u32) -> Option<Finished> {
        self.device.finished(tag)
    }

    fn posted(&self) -> bool {
        self.device.posted()
    }

    fn signals(&self) -> bool {
        self.device.signals()
    }
}
