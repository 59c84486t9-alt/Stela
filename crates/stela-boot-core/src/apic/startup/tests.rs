//! Independent RAM controller peer; never native CPU/cache/history evidence.
extern crate std;
use super::*;
use alloc::{rc::Rc, vec::Vec};
use core::cell::RefCell;
use std::panic::{AssertUnwindSafe, catch_unwind};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Error {
    Context,
    Apply(u8),
    Readback,
}
struct Bank {
    profile: Profile,
    words: [u32; 128],
    deadline: u64,
    operations: Vec<Operation>,
    drops: usize,
    fail: Option<u8>,
    panic: Option<u8>,
    bad_readback: bool,
    corrupt_value: bool,
    context: bool,
}
struct Model(Rc<RefCell<Bank>>);
impl Drop for Model {
    fn drop(&mut self) {
        self.0.borrow_mut().drops += 1;
    }
}
fn slot(r: Register) -> usize {
    match r {
        Register::Id => 0,
        Register::Version => 1,
        Register::Svr => 2,
        Register::Tpr => 3,
        Register::Divide => 4,
        Register::Initial => 5,
        Register::Current => 6,
        Register::Lvt(n) => 8 + usize::from(n),
        Register::Isr(n) => 32 + usize::from(n),
        Register::Irr(n) => 40 + usize::from(n),
        Register::Tmr(n) => 48 + usize::from(n),
    }
}
fn bank(mode: Mode, deadline: bool) -> Rc<RefCell<Bank>> {
    let mut words = [0; 128];
    words[slot(Register::Id)] = match mode {
        Mode::Xapic => 3 << 24,
        Mode::X2apic => 3,
    };
    words[slot(Register::Version)] = (1 << 24) | (6 << 16) | 0x14;
    words[slot(Register::Svr)] = (1 << 12) | 0x23; // disabled; keep policy bit12.
    words[slot(Register::Lvt(0))] = if deadline {
        (2 << 17) | 0x75
    } else {
        (1 << 17) | 0x75
    };
    words[slot(Register::Lvt(3))] = (4 << 8) | (1 << 16); // kept LINT data.
    words[slot(Register::Lvt(4))] = (4 << 8) | 0x21;
    words[slot(Register::Initial)] = 100;
    words[slot(Register::Current)] = if deadline { 0 } else { 64 };
    words[slot(Register::Irr(2))] = 1 << (0x75 % 32); // old pending NOT drained.
    Rc::new(RefCell::new(Bank {
        profile: Profile { mode, deadline },
        words,
        deadline: if deadline { 900 } else { 0 },
        operations: Vec::new(),
        drops: 0,
        fail: None,
        panic: None,
        bad_readback: false,
        corrupt_value: false,
        context: true,
    }))
}
// SAFETY: one affine synchronous RAM peer owns the modeled bank. It never
// represents hardware, firmware exclusion, physical mappings or IRQ history.
unsafe impl OriginalController for Model {
    type Error = Error;
    fn check(&self) -> Result<Profile, Error> {
        let b = self.0.borrow();
        if !b.context {
            return Err(Error::Context);
        }
        Ok(b.profile)
    }
    fn read(&self, r: Register) -> Result<u32, Error> {
        let b = self.0.borrow();
        if b.bad_readback && !b.operations.is_empty() {
            return Err(Error::Readback);
        }
        let value = b.words[slot(r)];
        Ok(if b.corrupt_value && !b.operations.is_empty() {
            value ^ 1
        } else {
            value
        })
    }
    fn read_deadline(&self) -> Result<u64, Error> {
        Ok(self.0.borrow().deadline)
    }
    fn apply(&mut self, op: Operation) -> Result<(), Error> {
        let mut b = self.0.borrow_mut();
        b.operations.push(op);
        let n = b.operations.len() as u8;
        match op {
            Operation::MaskOriginalTimer(v) => b.words[slot(Register::Lvt(0))] = v,
            Operation::OrderDeadline => {}
            Operation::DisarmDeadline => b.deadline = 0,
            Operation::StopCount => {
                b.words[slot(Register::Initial)] = 0;
                b.words[slot(Register::Current)] = 0;
            }
            Operation::ConfigureSvr(v) => b.words[slot(Register::Svr)] = v,
            Operation::ConfigureTimer => b.words[slot(Register::Lvt(0))] = (1 << 16) | 64,
            Operation::ConfigureDivide => b.words[slot(Register::Divide)] = 11,
        }
        if b.panic == Some(n) {
            panic!("after real RAM peer effect");
        }
        if b.fail == Some(n) {
            return Err(Error::Apply(n));
        }
        Ok(())
    }
}
#[test]
fn actual_control_moves_once_preserves_policy_lints_and_old_pending() {
    for mode in [Mode::Xapic, Mode::X2apic] {
        let b = bank(mode, false);
        let before = b.borrow().words;
        let configured = Startup::new(Model(b.clone()))
            .configure()
            .unwrap_or_else(|_| panic!("model"));
        assert_eq!(configured.original().timer_vector(), 0x75);
        assert_eq!(
            configured.original().pending_observation()[2],
            1 << (0x75 % 32)
        );
        assert_eq!(b.borrow().words[slot(Register::Svr)], (1 << 12) | 0x1ff);
        for r in [
            Register::Lvt(3),
            Register::Lvt(4),
            Register::Tpr,
            Register::Irr(2),
        ] {
            assert_eq!(b.borrow().words[slot(r)], before[slot(r)]);
        }
        let (same, old) = configured.into_control();
        assert!(Rc::ptr_eq(&same.0, &b));
        assert_eq!(old.timer_lvt(), (1 << 17) | 0x75);
        drop(same);
        assert_eq!(b.borrow().drops, 1);
    }
}
#[test]
fn actual_deadline_disarm_precedes_mode_change_and_count_stop() {
    for mode in [Mode::Xapic, Mode::X2apic] {
        let b = bank(mode, true);
        let configured = Startup::new(Model(b.clone()))
            .configure()
            .unwrap_or_else(|_| panic!("model"));
        let operations = &b.borrow().operations;
        let disarm = operations
            .iter()
            .position(|o| *o == Operation::DisarmDeadline)
            .unwrap();
        let change = operations
            .iter()
            .position(|o| *o == Operation::ConfigureTimer)
            .unwrap();
        let stop = operations
            .iter()
            .position(|o| *o == Operation::StopCount)
            .unwrap();
        assert!(disarm < change && change < stop);
        assert_eq!(
            operations.contains(&Operation::OrderDeadline),
            mode == Mode::Xapic
        );
        if mode == Mode::Xapic {
            assert_eq!(operations[disarm - 1], Operation::OrderDeadline);
        }
        assert_eq!(b.borrow().deadline, 0);
        drop(configured); // abandoned success retains actual old/current owner.
        assert_eq!(b.borrow().drops, 0);
    }
}
#[test]
fn active_service_wrong_context_or_unenumerated_deadline_refuses_before_write() {
    for case in 0..5 {
        let b = bank(Mode::Xapic, true);
        match case {
            0 => b.borrow_mut().words[slot(Register::Isr(7))] = 1,
            1 => b.borrow_mut().context = false,
            2 => b.borrow_mut().profile.deadline = false,
            3 => b.borrow_mut().words[slot(Register::Tpr)] = 1,
            _ => b.borrow_mut().words[slot(Register::Svr)] |= 1 << 9,
        }
        let failure = match Startup::new(Model(b.clone())).configure() {
            Err(f) => f,
            Ok(_) => panic!("refusal"),
        };
        assert_eq!(failure.effect(), Effect::NotWritten);
        assert_eq!(failure.failure(), FaultState::Empty); // no Busy/pending relatch.
        assert!(b.borrow().operations.is_empty());
        let expected = failure.error;
        let retained = &**failure.graph as *const Graph<Model>;
        drop(failure);
        // SAFETY: the exact failed graph is retained by its ManuallyDrop Box;
        // dropping the carrier cannot free it or its original RAM controller.
        let graph = unsafe { &*retained };
        assert_eq!(graph.outcome, Some(expected));
        assert_eq!(graph.fault.observe(), FaultState::Empty);
        assert_eq!(b.borrow().drops, 0);
    }
}
#[test]
fn every_partial_effect_error_preserves_exact_prefix_without_cleanup() {
    for n in 1..=7 {
        let b = bank(Mode::Xapic, true);
        b.borrow_mut().fail = Some(n);
        let failure = match Startup::new(Model(b.clone())).configure() {
            Err(f) => f,
            Ok(_) => panic!("cut"),
        };
        assert_eq!(failure.error.cause, Cause::Source(Error::Apply(n)));
        assert!(matches!(failure.effect(), Effect::MayHaveWritten { ordinal, .. } if ordinal == n));
        assert_eq!(failure.failure(), FaultState::Ready(failure.error));
        assert_eq!(b.borrow().operations.len(), n as usize);
        drop(failure);
        assert_eq!(b.borrow().operations.len(), n as usize);
        assert_eq!(b.borrow().drops, 0);
    }
}
#[test]
fn readback_denial_and_unwind_never_release_or_retry_actual_owner() {
    let b = bank(Mode::Xapic, false);
    b.borrow_mut().bad_readback = true;
    let f = match Startup::new(Model(b.clone())).configure() {
        Err(f) => f,
        Ok(_) => panic!("readback"),
    };
    assert_eq!(f.error.cause, Cause::Source(Error::Readback));
    assert_eq!(b.borrow().operations.len(), 1);
    drop(f);
    assert_eq!(b.borrow().drops, 0);
    for n in 1..=7 {
        let b = bank(Mode::Xapic, true);
        b.borrow_mut().panic = Some(n);
        let startup = Startup::new(Model(b.clone()));
        let retained = &**startup.graph as *const Graph<Model>;
        assert!(catch_unwind(AssertUnwindSafe(|| startup.configure())).is_err());
        // SAFETY: Startup retains its exact ManuallyDrop<Box<Graph>> on unwind;
        // the independent peer above cannot free/reconstruct this allocation.
        let graph = unsafe { &*retained };
        assert!(matches!(graph.fault.observe(), FaultState::Ready(Failure {
            cause: Cause::Interrupted,
            effect: Effect::MayHaveWritten { ordinal, .. },
        }) if ordinal == n));
        assert_eq!(b.borrow().operations.len(), n as usize);
        assert_eq!(b.borrow().drops, 0);
    }
}

#[test]
fn forgotten_unpublished_control_has_no_effect_or_owner_release() {
    let b = bank(Mode::Xapic, false);
    core::mem::forget(Startup::new(Model(b.clone())));
    assert!(b.borrow().operations.is_empty());
    assert_eq!(b.borrow().drops, 0);
}

mod collisions;
