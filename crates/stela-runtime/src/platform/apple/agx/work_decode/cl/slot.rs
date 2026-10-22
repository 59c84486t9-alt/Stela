//! Original fixed CL setup's post-trigger slot publication and its
//! bilateral finalize identity. G14G 0x17024..0x17038 and G13X
//! 0x134e8..0x134fc publish queue -> state0 -> state+c=1, in that order.

use super::Access;
use crate::platform::apple::agx::{
    channel::{Kind, Record},
    ring,
    work_decode::{Encoding, Frame, Submission, resources::Lease},
};

#[derive(Debug)]
struct Write {
    address: u64,
    bytes: alloc::vec::Vec<u8>,
}
impl Write {
    fn new(address: u64, bytes: &[u8]) -> Result<Self, &'static str> {
        ring::scalar_range(address, bytes.len() as u64)?;
        Ok(Self {
            address,
            bytes: bytes.to_vec(),
        })
    }
}

/// Identity is copied from one complete accepted setup, never rediscovered
/// from mutable AP slot contents during a later DMA retry.
#[derive(Debug)]
pub struct SetupTail {
    submission: Submission,
    lease: Lease,
    state: u64,
    queue: u64,
    writes: [Write; 3],
    next: usize,
}
impl SetupTail {
    pub fn new(submission: &Submission, frame: &Frame, lease: Lease) -> Result<Self, &'static str> {
        if submission.command.kind != Kind::Cl
            || submission.encoding != Encoding::Fixed
            || frame.record != Record::SetupCl
            || frame.bytes().len() as u64 != Encoding::Fixed.record_bytes(Record::SetupCl)
        {
            return Err("GFX CL slot publication requires its complete fixed setup");
        }
        if lease.pipe != 2
            || lease.slot >= 6
            || submission.context >= 64
            || frame.u32(0x24)? != submission.context
        {
            return Err("GFX CL slot publication has another context or execution lease");
        }
        let state = frame.u64(0x14)?;
        let queue = frame.u64(0x1c)?;
        let slot = state
            .checked_add(u64::from(lease.slot) * 0x20)
            .ok_or("GFX CL shared slot wraps")?;
        slot.checked_add(0x1f)
            .ok_or("GFX CL shared slot extent wraps")?;
        let writes = [
            Write::new(slot + 0x10, &queue.to_le_bytes())?,
            Write::new(slot, &0u32.to_le_bytes())?,
            Write::new(slot + 0xc, &1u32.to_le_bytes())?,
        ];
        Ok(Self {
            submission: submission.clone(),
            lease,
            state,
            queue,
            writes,
            next: 0,
        })
    }
    pub fn completed(&self) -> bool {
        self.next == self.writes.len()
    }
    pub fn advance(&mut self, access: &mut dyn Access) -> Result<(), &'static str> {
        if self.completed() {
            return Ok(());
        }
        access.check_available()?;
        // A native trigger can have a terminal GPU error. Its accepted
        // post-trigger slot publication still occurs; no successful
        // finalize, stamp or retirement follows from this predicate.
        access.check_submitted(&self.submission, self.lease)?;
        while let Some(write) = self.writes.get(self.next) {
            access.memory().write(write.address, &write.bytes)?;
            self.next += 1;
        }
        Ok(())
    }
    /// Bind the distinct even finalize record to this setup's slot, queue,
    /// context and accepted firmware stamp. This validates identity only;
    /// native completion, abort, release and all finalize effects remain
    /// with the enclosing source consumer.
    pub fn bind_finalize(&self, frame: &Frame) -> Result<FinalizeBinding, &'static str> {
        if !self.completed() {
            return Err("GFX CL finalize precedes its complete post-trigger slot publication");
        }
        if frame.record != Record::StartCl
            || frame.bytes().len() as u64 != Encoding::Fixed.record_bytes(Record::StartCl)
            || frame.u64(4)? != self.state
            || frame.u64(0xc)? != self.queue
            || frame.u32(0x14)? != self.submission.context
            || frame.u64(0x2c)? != self.submission.stamp.firmware
            || frame.u32(0x34)? != self.submission.stamp.value
        {
            return Err("GFX CL finalize does not identify its accepted setup/queue/stamp");
        }
        Ok(FinalizeBinding {
            submission: self.submission.clone(),
            lease: self.lease,
            slot: self.writes[1].address,
            frame: frame.clone(),
        })
    }
}

#[derive(Debug)]
pub struct FinalizeBinding {
    pub submission: Submission,
    pub lease: Lease,
    pub slot: u64,
    pub frame: Frame,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::agx::{
        channel::{Command, Stamp},
        ring::{Shared, tests::Flat},
        sgx::work::Register,
        work_decode::{cl::tests::input, resources::Policy},
    };
    use alloc::vec::Vec;
    struct Memory {
        flat: Flat,
        writes: Vec<(u64, Vec<u8>)>,
        fail: Option<usize>,
    }
    impl Shared for Memory {
        fn read(&mut self, va: u64, out: &mut [u8]) -> Result<(), &'static str> {
            self.flat.read(va, out)
        }
        fn write(&mut self, va: u64, bytes: &[u8]) -> Result<(), &'static str> {
            if self.fail == Some(self.writes.len()) {
                self.fail = None;
                return Err("slot DMA");
            }
            self.flat.write(va, bytes)?;
            self.writes.push((va, bytes.to_vec()));
            Ok(())
        }
        fn gpu_read(
            &mut self,
            _: usize,
            _: u64,
            _: &mut [u8],
        ) -> Result<(), crate::platform::dma::DmaError> {
            panic!("slot publication cannot execute GPU work")
        }
        fn gpu_write(
            &mut self,
            _: usize,
            _: u64,
            _: &[u8],
        ) -> Result<(), crate::platform::dma::DmaError> {
            panic!("slot publication cannot execute GPU work")
        }
    }
    struct Native {
        memory: Memory,
        accepted: bool,
        available: bool,
    }
    impl Access for Native {
        fn policy(&self) -> Policy {
            Policy::G14G
        }
        fn memory(&mut self) -> &mut dyn Shared {
            &mut self.memory
        }
        fn check_available(&self) -> Result<(), &'static str> {
            if self.available {
                Ok(())
            } else {
                Err("retained gate")
            }
        }
        fn begin(
            &mut self,
            _: &Submission,
            _: &Frame,
            _: Lease,
            _: &crate::platform::apple::agx::work_decode::ownership::Identity,
        ) -> Result<(), &'static str> {
            panic!("slot publication cannot begin a new native execution")
        }
        fn check_submitted(&self, _: &Submission, _: Lease) -> Result<(), &'static str> {
            if self.accepted {
                Ok(())
            } else {
                Err("not submitted")
            }
        }
        fn read_native(&mut self, _: Register) -> Result<u64, &'static str> {
            panic!("slot publication cannot read native registers")
        }
        fn write_native(&mut self, _: Register, _: u64) -> Result<(), &'static str> {
            panic!("slot publication cannot submit native work")
        }
    }
    fn native() -> Native {
        Native {
            memory: Memory {
                flat: Flat::new(0x1000, 0x10000),
                writes: Vec::new(),
                fail: None,
            },
            accepted: true,
            available: true,
        }
    }
    fn setup(state: u64) -> (Submission, Frame, Lease) {
        let (submission, mut frame, lease) = input();
        frame.data[0x14..0x1c].copy_from_slice(&state.to_le_bytes());
        frame.data[0x1c..0x24].copy_from_slice(&0x9000u64.to_le_bytes());
        (submission, frame, lease)
    }
    fn finalize(submission: &Submission, state: u64) -> Frame {
        let mut bytes = alloc::vec![0;Record::StartCl.bytes() as usize];
        bytes[..4].copy_from_slice(&12u32.to_le_bytes());
        bytes[4..0xc].copy_from_slice(&state.to_le_bytes());
        bytes[0xc..0x14].copy_from_slice(&0x9000u64.to_le_bytes());
        bytes[0x14..0x18].copy_from_slice(&submission.context.to_le_bytes());
        bytes[0x2c..0x34].copy_from_slice(&submission.stamp.firmware.to_le_bytes());
        bytes[0x34..0x38].copy_from_slice(&submission.stamp.value.to_le_bytes());
        Frame {
            va: 0x6000,
            record: Record::StartCl,
            data: bytes,
        }
    }
    #[test]
    fn every_post_trigger_slot_write_is_retained_and_no_retry_executes_gpu_work() {
        let (submission, frame, lease) = setup(0x2000);
        let slot = 0x2000 + u64::from(lease.slot) * 32;
        let expected = alloc::vec![
            (slot + 0x10, 0x9000u64.to_le_bytes().to_vec()),
            (slot, 0u32.to_le_bytes().to_vec()),
            (slot + 0xc, 1u32.to_le_bytes().to_vec())
        ];
        for fault in 0..3 {
            let mut tail = SetupTail::new(&submission, &frame, lease).unwrap();
            let mut native = native();
            native.memory.fail = Some(fault);
            assert_eq!(tail.advance(&mut native), Err("slot DMA"));
            assert_eq!(native.memory.writes, expected[..fault]);
            native.available = false;
            assert_eq!(tail.advance(&mut native), Err("retained gate"));
            assert_eq!(native.memory.writes.len(), fault);
            native.available = true;
            tail.advance(&mut native).unwrap();
            assert_eq!(native.memory.writes, expected);
            assert!(tail.completed());
            tail.advance(&mut native).unwrap();
            assert_eq!(native.memory.writes, expected);
            let binding = tail.bind_finalize(&finalize(&submission, 0x2000)).unwrap();
            assert_eq!(binding.slot, slot);
            assert_eq!(binding.lease, lease);
            assert_eq!(binding.submission, submission);
        }
    }
    #[test]
    fn trigger_and_bilateral_identity_are_required_before_any_finalization() {
        let (submission, frame, lease) = setup(0x2000);
        let mut tail = SetupTail::new(&submission, &frame, lease).unwrap();
        let mut native = native();
        native.accepted = false;
        assert_eq!(tail.advance(&mut native), Err("not submitted"));
        assert!(native.memory.writes.is_empty());
        assert!(tail.bind_finalize(&finalize(&submission, 0x2000)).is_err());
        native.accepted = true;
        tail.advance(&mut native).unwrap();
        for (at, bytes) in [(4, 8), (0xc, 8), (0x14, 4), (0x2c, 8), (0x34, 4)] {
            let mut other = finalize(&submission, 0x2000);
            other.data[at..at + bytes].fill(0xff);
            assert!(tail.bind_finalize(&other).is_err());
        }
        assert_eq!(native.memory.writes.len(), 3);
    }
    #[test]
    fn slot_extents_and_indivisible_publications_are_checked_before_effects() {
        for base in [u64::MAX - 0x5f, 0x3f8c] {
            let (submission, frame, lease) = setup(base);
            assert!(SetupTail::new(&submission, &frame, lease).is_err());
        }
        let (mut submission, frame, lease) = setup(0x2000);
        submission.command = Command {
            va: 1,
            kind: Kind::Ta,
        };
        submission.stamp = Stamp {
            driver: 0,
            firmware: 0,
            value: 0,
            index: 0,
        };
        assert!(SetupTail::new(&submission, &frame, lease).is_err());
    }
}
