//! Model the post-return capture/publication boundary without CPL0 admission.
//! Real source preparation and linear dispatch/recovery are used; this Host
//! double supplies a simulated raw internal fault, never native CPU authority.
use super::super::terminal::FailureCapture;
use super::*;
use crate::machine::{
    FaultCause, InstallError, NativeCode, NativeFault, NativeFaultOrigin, Regime, Stop,
};
use stela_compiler::block::{HostGprSnapshot, HostSpillSnapshot};
struct ModelHost {
    code: Vec<Vec<u8>>,
    calls: usize,
}
impl Host for ModelHost {
    fn native_worker(&self) -> Option<publication::WorkerId> {
        Some(publication::WorkerId(17))
    }
    fn read_ram(&mut self, _: u64, _: &mut [u8]) -> bool {
        panic!("no raw RAM")
    }
    fn write_ram(&mut self, _: u64, _: &[u8]) -> bool {
        panic!("no raw RAM")
    }
    fn install(&mut self, code: &[u8]) -> Result<NativeCode, InstallError> {
        self.code.push(code.to_vec());
        Ok(NativeCode(self.code.len()))
    }
    fn patch(&mut self, _: NativeCode, _: &[u8]) {
        panic!("no patches")
    }
    fn discard_code(&mut self) {
        panic!("no discard")
    }
    unsafe fn execute(&mut self, code: NativeCode, state: &mut GuestState) -> NativeExit {
        assert!(code.0 != 0 && code.0 <= self.code.len());
        self.calls += 1;
        state.x[0] = 0xdead; // Partial host frame: explicitly not rolled back.
        NativeExit::Fault(fault())
    }
    fn set_regime(&mut self, _: &Regime) {}
    fn invalidate_translations(&mut self) {}
    fn counter(&mut self) -> u64 {
        0
    }
    fn arm_timer(&mut self, _: Option<u64>) {}
    fn wait_for_interrupt(&mut self) {
        panic!("no waiting")
    }
}
fn fault() -> NativeFault {
    NativeFault {
        origin: NativeFaultOrigin::Exception,
        offset: 0,
        address: 0x1234,
        write: false,
        cause: FaultCause::InvalidOpcode,
        trap: 6,
        error_code: 0,
        registers: HostGprSnapshot::legacy([99; 16]),
        spills: HostSpillSnapshot::new(),
    }
}
struct FailedFrame<'a>(NativeRun<'a>);
impl publication::sealed::NativeFrame for FailedFrame<'_> {}
impl<'a> publication::NativeFrame for FailedFrame<'a> {
    type Returned = ReturnedRun<'a>;
    fn execute(self, host: &mut dyn Host) -> ReturnedRun<'a> {
        let code = host.install(&self.0.artifact.code).unwrap();
        // SAFETY: ModelHost is a test double, retaining its Vec code ID and
        // touching only this actual borrowed GuestState; no emitted native code.
        let NativeExit::Fault(fault) = (unsafe { host.execute(code, self.0.state) }) else {
            panic!("model fault")
        };
        self.0.memory.machine.record(FailureCapture {
            pe: self.0.artifact.identity.pe,
            pc: *self.0.pc,
            retired: *self.0.retired,
            code,
            fault,
        });
        let observation = Observation {
            identity: Arc::clone(&self.0.artifact.identity),
            artifact_cache: self.0.memory.artifacts.stats(),
            native: Some(NativeExit::Fault(fault)),
            memory_fault: None,
            source_failure: None,
            status: Err(MemoryStatus::Domain),
            settled_pc: *self.0.pc,
            retired: 0,
            epoch_retired: 0,
            executed_bodies: 1,
            epoch_end: NativeEpochEnd::Failure,
            physical_processor: None,
            settlement: None,
        };
        ReturnedRun {
            run: self.0,
            observation: Some(observation),
        }
    }
}
#[test]
fn ignored_recovered_fault_observation_cannot_readmit_the_actual_frame() {
    let (mut machine, _ram) = super::artifact_tests::fixture();
    let binding = publication::WorkerBinding {
        pe: 0,
        worker: publication::WorkerId(17),
    };
    let (mut inventory, mut owners) = publication::WorkerPublications::new(&[binding]).unwrap();
    let mut host = ModelHost {
        code: Vec::new(),
        calls: 0,
    };
    inventory
        .accept_initial(owners[0].publish_initial(&mut host).unwrap())
        .unwrap();
    let boundary = (machine.cpu.pc, machine.cpu.retired);
    // SAFETY: one actual exclusively borrowed canonical frame, no other workers
    // or writers; the test wrapper models only terminal recovery, no native lane.
    let run = unsafe { machine.shared_native_run(binding) }.unwrap();
    let loan = inventory
        .dispatch(0, FailedFrame(run))
        .unwrap_or_else(|_| panic!("dispatch"));
    let returned = owners[0]
        .execute(loan, &mut host)
        .unwrap_or_else(|_| panic!("return"));
    let observation = recover(&mut inventory, returned).unwrap_or_else(|_| panic!("recover"));
    assert_eq!(observation.status, Err(MemoryStatus::Domain));
    drop(observation); // Deliberately skip scheduler validate/settlement.
    assert_eq!(machine.cpu.state.x[0], 0xdead, "no false rollback claim");
    assert_eq!((machine.cpu.pc, machine.cpu.retired), boundary);
    assert!(
        machine.native_failure.is_none(),
        "dispatcher diagnostic still lazy"
    );
    // SAFETY: identical owned frame; quarantine must reject before execution.
    assert!(matches!(
        unsafe { machine.shared_native_run(binding) },
        Err(MemoryStatus::Domain)
    ));
    let stop = machine.run(1);
    assert!(
        matches!(&stop,Stop::NativeFailure(failure) if matches!(failure.reason,
        super::super::super::NativeFailureReason::CanonicalDomain{pe:0,..}))
    );
    assert_eq!(machine.native_failure_capture(), Some(&fault()));
    assert_eq!(machine.run(1), stop);
    assert_eq!(host.calls, 1);
    assert_eq!((machine.cpu.pc, machine.cpu.retired), boundary);
}
#[test]
fn shared_execution_domain_preserves_first_evidence_across_peer_handles() {
    let (machine, _ram) = super::artifact_tests::fixture();
    let actual = Arc::clone(&machine.cpu.canonical_memory.as_ref().unwrap().machine);
    assert!(Arc::ptr_eq(&actual, &machine.native_memory_identity));
    let first = FailureCapture {
        pe: 0,
        pc: 0x4000,
        retired: 7,
        code: NativeCode(1),
        fault: fault(),
    };
    actual.record(first);
    let peer = Arc::clone(&actual);
    std::thread::spawn(move || {
        assert!(peer.quarantined());
        peer.record(FailureCapture {
            pe: 1,
            pc: 0x8000,
            retired: 99,
            code: NativeCode(2),
            ..first
        });
        assert_eq!(peer.failure(), Some(first));
    })
    .join()
    .unwrap();
    assert_eq!(machine.native_memory_identity.failure(), Some(first));
}

#[test]
fn already_prepared_frame_refuses_before_any_host_admission_after_peer_quarantine() {
    let (mut machine, _ram) = super::artifact_tests::fixture();
    let binding = publication::WorkerBinding {
        pe: 0,
        worker: publication::WorkerId(17),
    };
    let domain = Arc::clone(&machine.native_memory_identity);
    let (mut inventory, mut owners) = publication::WorkerPublications::new(&[binding]).unwrap();
    let mut host = ModelHost {
        code: Vec::new(),
        calls: 0,
    };
    inventory
        .accept_initial(owners[0].publish_initial(&mut host).unwrap())
        .unwrap();
    let boundary = (machine.cpu.pc, machine.cpu.retired);
    // SAFETY: exclusive actual frame and canonical source; dispatch/recovery
    // below use the real linear protocol. No native permission is manufactured.
    let run = unsafe { machine.shared_native_run(binding) }.unwrap();
    // Model another holder of this same domain publishing a raw failure after
    // preparation but before entry. This record grants rejection only; this is
    // a publication-boundary model, not evidence of two executing physical PEs.
    let first = FailureCapture {
        pe: 1,
        pc: 0x8000,
        retired: 23,
        code: NativeCode(1),
        fault: fault(),
    };
    domain.record(first);
    let loan = dispatch(&mut inventory, run).unwrap_or_else(|_| panic!("dispatch"));
    let returned = owners[0]
        .execute(loan, &mut host)
        .unwrap_or_else(|_| panic!("return"));
    let observation = recover(&mut inventory, returned).unwrap_or_else(|_| panic!("recover"));
    assert_eq!(observation.status, Err(MemoryStatus::Domain));
    assert_eq!(observation.native, None);
    drop(observation);
    assert_eq!(host.calls, 0);
    assert!(host.code.is_empty(), "quarantine precedes install/entry");
    assert_eq!((machine.cpu.pc, machine.cpu.retired), boundary);
    assert!(
        matches!(machine.run(1), Stop::NativeFailure(failure) if matches!(failure.reason,
        super::super::super::NativeFailureReason::CanonicalDomain { pe: 1, retired_before: 23 }))
    );
    assert_eq!(domain.failure(), Some(first));
}
