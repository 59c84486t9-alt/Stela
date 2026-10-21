//! Source-ordered fixed CL parameter programming, before resource acquire.
//!
//! G14G firmware 0x160ac..0x16198 interleaves native writes with reads of
//! the AP parameter block. G13X 0x13380..0x13508 omits +0x38 and inserts
//! its two legacy writes. A later RAM/native fault must not hoist a read,
//! repeat a completed RMW or redirect a captured native store.

pub mod slot;

use super::{
    Encoding, Frame, Submission,
    resources::{Lease, Policy},
};
use crate::platform::apple::agx::{
    channel::{Kind, Record},
    ring::Shared,
    sgx::work::Register,
};
use alloc::vec::Vec;

/// The concrete SGX owner supplies native operations; these never pass
/// through Shared's RAM-only write interface. Failed native operations
/// commit no effects. begin is idempotent for the same submission/lease.
pub trait Access {
    fn policy(&self) -> Policy;
    fn memory(&mut self) -> &mut dyn Shared;
    fn check_available(&self) -> Result<(), &'static str>;
    fn begin(&mut self, submission: &Submission, lease: Lease) -> Result<(), &'static str>;
    fn check_submitted(&self, _: &Submission, _: Lease) -> Result<(), &'static str> {
        Err("GFX CL native trigger ownership is not available")
    }
    fn read_native(&mut self, register: Register) -> Result<u64, &'static str>;
    fn write_native(&mut self, register: Register, value: u64) -> Result<(), &'static str>;
}

#[derive(Debug)]
enum Value {
    Literal(u64),
    Control,
    CaptureMask { bit: u64, enabled: bool },
    Mask,
    Parameter(u64),
}
#[derive(Debug)]
struct Action {
    register: Option<Register>,
    value: Value,
}

/// One accepted setup's native parameter phase. Completion here authorizes
/// only the following resource-acquire phase, never a SKU record retirement,
/// GPU trigger, stamp or event. The parent setup retains this owner.
#[derive(Debug)]
pub struct Parameters {
    policy: Policy,
    submission: Submission,
    lease: Lease,
    actions: Vec<Action>,
    next: usize,
    held: Option<u64>,
    mask: Option<u64>,
}
impl Parameters {
    pub fn new(
        submission: &Submission,
        frame: &Frame,
        lease: Lease,
        policy: Policy,
    ) -> Result<Self, &'static str> {
        if submission.encoding != Encoding::Fixed
            || submission.command.kind != Kind::Cl
            || frame.record != Record::SetupCl
            || frame.bytes().len() as u64 != Encoding::Fixed.record_bytes(Record::SetupCl)
        {
            return Err("GFX CL native parameters require the complete fixed setup record");
        }
        if lease.pipe != 2 || lease.slot >= 6 || submission.context >= 64 {
            return Err("GFX CL parameter phase has an invalid execution lease/context");
        }
        let context = frame.u32(0x24)?;
        if context != submission.context {
            return Err("GFX CL setup context differs from its accepted command");
        }
        let parameters = frame.u64(0xc)?;
        parameters
            .checked_add(0x67)
            .ok_or("GFX CL source parameter block wraps")?;
        let mut actions = alloc::vec![
            Action {
                register: Some(Register::Control),
                value: Value::Control
            },
            Action {
                register: Some(Register::Context),
                value: Value::Literal(u64::from(context << 8 | (frame.u32(0x2c)? & 0x3f)))
            },
        ];
        // G13X reads the old mask before committing LegacySetup at
        // 0x133dc / 0x133f4; retain that read even if this write fails.
        actions.push(Action {
            register: None,
            value: Value::CaptureMask {
                bit: 1 << context,
                enabled: frame.u32(0x28)? != 0,
            },
        });
        if policy == Policy::G13X {
            actions.push(Action {
                register: Some(Register::LegacySetup),
                value: Value::Literal(0x100),
            });
        }
        actions.push(Action {
            register: Some(Register::ContextMask),
            value: Value::Mask,
        });
        if policy == Policy::G13X {
            actions.push(Action {
                register: Some(Register::LegacyMask),
                value: Value::Mask,
            });
        }
        for index in 0..13 {
            if policy == Policy::G13X && index == 7 {
                continue;
            }
            actions.push(Action {
                register: Some(Register::Parameter(index)),
                value: Value::Parameter(parameters + u64::from(index) * 8),
            });
            if index == if policy == Policy::G13X { 6 } else { 7 } {
                actions.push(Action {
                    register: Some(Register::Setup),
                    value: Value::Literal(0x100),
                });
            }
        }
        Ok(Self {
            policy,
            submission: submission.clone(),
            lease,
            actions,
            next: 0,
            held: None,
            mask: None,
        })
    }
    pub fn completed(&self) -> bool {
        self.next == self.actions.len()
    }
    pub fn advance(&mut self, access: &mut dyn Access) -> Result<(), &'static str> {
        if self.completed() {
            return Ok(());
        }
        if access.policy() != self.policy {
            return Err("GFX CL parameter program belongs to another native family");
        }
        access.check_available()?;
        access.begin(&self.submission, self.lease)?;
        while let Some(action) = self.actions.get(self.next) {
            if self.held.is_none() {
                let value = match action.value {
                    Value::Literal(value) => value,
                    Value::Control => access.read_native(Register::Control)? | 1,
                    Value::CaptureMask { bit, enabled } => {
                        let value = access.read_native(Register::ContextMask)?;
                        if enabled { value | bit } else { value & !bit }
                    }
                    Value::Mask => self
                        .mask
                        .ok_or("GFX CL legacy mirror precedes its retained context-mask write")?,
                    Value::Parameter(va) => access.memory().read_u64(va)?,
                };
                self.held = Some(value);
            }
            let value = self.held.unwrap();
            if let Some(register) = action.register {
                access.write_native(register, value)?;
            } else {
                self.mask = Some(value);
            }
            self.next += 1;
            self.held = None;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::agx::{
        channel::{Command, Stamp},
        ring::tests::Flat,
    };

    struct ParameterMemory {
        inner: Flat,
        reads: usize,
        fail: Option<usize>,
    }
    impl ParameterMemory {
        fn put_u64(&mut self, address: u64, value: u64) {
            self.inner.put_u64(address, value);
        }
    }
    impl Shared for ParameterMemory {
        fn read(&mut self, va: u64, bytes: &mut [u8]) -> Result<(), &'static str> {
            if self.fail == Some(self.reads) {
                self.fail = None;
                return Err("parameter read");
            }
            self.reads += 1;
            self.inner.read(va, bytes)
        }
        fn write(&mut self, va: u64, bytes: &[u8]) -> Result<(), &'static str> {
            self.inner.write(va, bytes)
        }
        fn gpu_read(
            &mut self,
            context: usize,
            va: u64,
            bytes: &mut [u8],
        ) -> Result<(), crate::platform::dma::DmaError> {
            self.inner.gpu_read(context, va, bytes)
        }
        fn gpu_write(
            &mut self,
            context: usize,
            va: u64,
            bytes: &[u8],
        ) -> Result<(), crate::platform::dma::DmaError> {
            self.inner.gpu_write(context, va, bytes)
        }
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Trace {
        Read(Register),
        Write(Register),
    }
    struct Native {
        policy: Policy,
        memory: ParameterMemory,
        trace: Vec<Trace>,
        writes: Vec<(Register, u64)>,
        reads: Vec<Register>,
        fail_write: Option<usize>,
        fail_read: Option<usize>,
        inhibited: bool,
    }
    impl Access for Native {
        fn policy(&self) -> Policy {
            self.policy
        }
        fn memory(&mut self) -> &mut dyn Shared {
            &mut self.memory
        }
        fn check_available(&self) -> Result<(), &'static str> {
            if self.inhibited { Err("gate") } else { Ok(()) }
        }
        fn begin(&mut self, _: &Submission, _: Lease) -> Result<(), &'static str> {
            Ok(())
        }
        fn read_native(&mut self, register: Register) -> Result<u64, &'static str> {
            if self.fail_read == Some(self.reads.len()) {
                self.fail_read = None;
                return Err("native read");
            }
            self.reads.push(register);
            self.trace.push(Trace::Read(register));
            Ok(match register {
                Register::Control => 0x40,
                Register::ContextMask => 1 << 9,
                _ => unreachable!(),
            })
        }
        fn write_native(&mut self, register: Register, value: u64) -> Result<(), &'static str> {
            if self.fail_write == Some(self.writes.len()) {
                self.fail_write = None;
                return Err("native write");
            }
            self.writes.push((register, value));
            self.trace.push(Trace::Write(register));
            Ok(())
        }
    }
    pub(super) fn input() -> (Submission, Frame, Lease) {
        let submission = Submission {
            command: Command {
                va: 0x3000,
                kind: Kind::Cl,
            },
            encoding: Encoding::Fixed,
            counter: 1,
            context: 5,
            stamp: Stamp {
                driver: 0x4000,
                firmware: 0x4004,
                value: 0x100,
                index: 3,
            },
            stream: 0x5000,
            stream_bytes: 0x200,
        };
        let mut data = alloc::vec![0; Record::SetupCl.bytes() as usize];
        data[..4].copy_from_slice(&11u32.to_le_bytes());
        data[0xc..0x14].copy_from_slice(&0x2000u64.to_le_bytes());
        data[0x24..0x28].copy_from_slice(&5u32.to_le_bytes());
        data[0x28..0x2c].copy_from_slice(&1u32.to_le_bytes());
        data[0x2c..0x30].copy_from_slice(&0xf2u32.to_le_bytes());
        (
            submission,
            Frame {
                va: 0x5000,
                record: Record::SetupCl,
                data,
            },
            Lease { pipe: 2, slot: 3 },
        )
    }
    fn native(policy: Policy) -> Native {
        let mut memory = Flat::new(0x1000, 0x4000);
        for i in 0..13 {
            memory.put_u64(0x2000 + i * 8, 0x100 + i);
        }
        Native {
            policy,
            memory: ParameterMemory {
                inner: memory,
                reads: 0,
                fail: None,
            },
            trace: Vec::new(),
            writes: Vec::new(),
            reads: Vec::new(),
            fail_write: None,
            fail_read: None,
            inhibited: false,
        }
    }
    #[test]
    fn each_native_store_fault_preserves_source_order_and_the_captured_read() {
        for policy in [Policy::G13G, Policy::G13X, Policy::G14G] {
            let (submission, frame, lease) = input();
            let mut expected = native(policy);
            let mut program = Parameters::new(&submission, &frame, lease, policy).unwrap();
            program.advance(&mut expected).unwrap();
            assert!(program.completed());
            for fault in 0..expected.writes.len() {
                let mut owner = Parameters::new(&submission, &frame, lease, policy).unwrap();
                let mut access = native(policy);
                access.fail_write = Some(fault);
                assert_eq!(owner.advance(&mut access), Err("native write"));
                assert_eq!(access.writes, expected.writes[..fault]);
                let reads = access.reads.clone();
                if let Register::Parameter(index) = expected.writes[fault].0 {
                    access
                        .memory
                        .put_u64(0x2000 + u64::from(index) * 8, u64::MAX);
                }
                access.inhibited = true;
                assert_eq!(owner.advance(&mut access), Err("gate"));
                assert_eq!(access.writes.len(), fault);
                access.inhibited = false;
                owner.advance(&mut access).unwrap();
                assert_eq!(access.writes, expected.writes);
                assert_eq!(&access.reads[..reads.len()], &reads);
                let done = (access.writes.clone(), access.reads.clone());
                owner.advance(&mut access).unwrap();
                assert_eq!((access.writes, access.reads), done);
            }
            assert_eq!(expected.writes[0], (Register::Control, 0x41));
            assert_eq!(expected.writes[1], (Register::Context, 0x532));
        }
    }
    #[test]
    fn native_read_faults_do_not_repeat_prior_stores_or_skip_the_failed_rmw() {
        let policy = Policy::G14G;
        for fault in 0..2 {
            let (submission, frame, lease) = input();
            let mut owner = Parameters::new(&submission, &frame, lease, Policy::G14G).unwrap();
            let mut access = native(policy);
            access.fail_read = Some(fault);
            assert_eq!(owner.advance(&mut access), Err("native read"));
            assert_eq!(access.writes.len(), if fault == 0 { 0 } else { 2 });
            owner.advance(&mut access).unwrap();
            assert_eq!(
                access.reads,
                alloc::vec![Register::Control, Register::ContextMask]
            );
            assert_eq!(
                access
                    .writes
                    .iter()
                    .filter(|(r, _)| *r == Register::Control)
                    .count(),
                1
            );
            assert_eq!(
                access
                    .writes
                    .iter()
                    .filter(|(r, _)| *r == Register::ContextMask)
                    .count(),
                1
            );
        }
    }
    #[test]
    fn source_parameter_read_faults_retain_every_prior_native_store() {
        for policy in [Policy::G13G, Policy::G13X, Policy::G14G] {
            let (submission, frame, lease) = input();
            let indices: Vec<u8> = (0..13)
                .filter(|index| policy != Policy::G13X || *index != 7)
                .collect();
            for fault in 0..indices.len() {
                let mut owner = Parameters::new(&submission, &frame, lease, policy).unwrap();
                let mut access = native(policy);
                access.memory.fail = Some(fault);
                assert_eq!(owner.advance(&mut access), Err("parameter read"));
                let prefix = access.writes.clone();
                for index in 0..13 {
                    access.memory.put_u64(0x2000 + index * 8, 0x900 + index);
                }
                owner.advance(&mut access).unwrap();
                assert_eq!(&access.writes[..prefix.len()], &prefix);
                assert_eq!(access.memory.reads, indices.len());
                for (position, index) in indices.iter().copied().enumerate() {
                    let values: Vec<_> = access
                        .writes
                        .iter()
                        .filter(|(r, _)| *r == Register::Parameter(index))
                        .collect();
                    assert_eq!(values.len(), 1);
                    assert_eq!(
                        values[0].1,
                        if position < fault {
                            0x100 + u64::from(index)
                        } else {
                            0x900 + u64::from(index)
                        }
                    );
                }
            }
        }
    }
    #[test]
    fn legacy_setup_store_follows_the_captured_context_mask_read() {
        let policy = Policy::G13X;
        let (submission, frame, lease) = input();
        let mut owner = Parameters::new(&submission, &frame, lease, Policy::G13X).unwrap();
        let mut access = native(policy);
        access.fail_write = Some(2);
        assert_eq!(owner.advance(&mut access), Err("native write"));
        assert_eq!(
            access.trace,
            alloc::vec![
                Trace::Read(Register::Control),
                Trace::Write(Register::Control),
                Trace::Write(Register::Context),
                Trace::Read(Register::ContextMask)
            ]
        );
        owner.advance(&mut access).unwrap();
        assert_eq!(
            &access.trace[..7],
            &[
                Trace::Read(Register::Control),
                Trace::Write(Register::Control),
                Trace::Write(Register::Context),
                Trace::Read(Register::ContextMask),
                Trace::Write(Register::LegacySetup),
                Trace::Write(Register::ContextMask),
                Trace::Write(Register::LegacyMask)
            ]
        );
        assert_eq!(access.reads.len(), 2);
    }

    #[test]
    fn foreign_native_family_refuses_before_memory_or_native_effects() {
        let (submission, frame, lease) = input();
        let mut owner = Parameters::new(&submission, &frame, lease, Policy::G13X).unwrap();
        let mut access = native(Policy::G14G);
        assert!(
            owner
                .advance(&mut access)
                .unwrap_err()
                .contains("another native family")
        );
        assert!(access.trace.is_empty());
        assert_eq!(access.memory.reads, 0);
    }

    #[test]
    fn source_identity_and_complete_parameter_extent_precede_native_ownership() {
        let (submission, mut frame, lease) = input();
        frame.data[0xc..0x14].copy_from_slice(&(u64::MAX - 0x66).to_le_bytes());
        assert!(Parameters::new(&submission, &frame, lease, Policy::G14G).is_err());
        let (_, mut frame, _) = input();
        frame.data[0x24..0x28].copy_from_slice(&6u32.to_le_bytes());
        assert!(Parameters::new(&submission, &frame, lease, Policy::G14G).is_err());
        frame.data.truncate(0x100);
        assert!(Parameters::new(&submission, &frame, lease, Policy::G14G).is_err());
    }
}
