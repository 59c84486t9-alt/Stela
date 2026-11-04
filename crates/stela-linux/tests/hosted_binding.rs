//! Original bare C scope on the checked hosted task adapter.
#![cfg(all(
    feature = "hosted-runtime",
    target_os = "linux",
    target_arch = "x86_64"
))]

use std::{
    cell::Cell,
    ffi::c_void,
    pin::Pin,
    ptr,
    rc::Rc,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use stela_driver_base::platform::work::{
    Kind, WorkError,
    kernel_domain::{HostedExecution, HostedExecutor, HostedQueue, HostedRuntime, HostedWake},
};
use stela_linux::task::HostedTaskBinding;

unsafe extern "C" {
    fn stela_linux_enter(owner: *const stela_linux::owner::RawOwner);
    fn stela_linux_exit();
    fn stela_linux_current() -> *mut c_void;
    fn sched_set_fifo(task: *mut c_void);
    fn schedule();
    static stela_linux_bare: stela_linux::owner::RawOwner;
}
struct Fixture<'a> {
    runtime: Pin<&'a HostedRuntime<4>>,
    binding: Rc<HostedTaskBinding<4>>,
    wake: Cell<Option<HostedWake>>,
    phase: Cell<u8>,
    fifo: Cell<bool>,
    live_ns: Cell<Option<u64>>,
}
unsafe extern "C" fn body(context: *mut c_void) {
    // SAFETY: the sole producer keeps this fixture through both task steps.
    let fixture = unsafe { &*context.cast::<Fixture<'_>>() };
    // SAFETY: this bound task owns the live bare scope on the sole thread.
    unsafe { stela_linux_enter(&raw const stela_linux_bare) };
    if fixture.fifo.get() {
        // SAFETY: this source task is current on its original hosted stack.
        unsafe { sched_set_fifo(stela_linux_current()) };
        let start = fixture.binding.measured_execution_ns().unwrap();
        let wall = Instant::now();
        thread::sleep(Duration::from_millis(20));
        let awake = fixture.binding.measured_execution_ns().unwrap();
        assert!(wall.elapsed().as_nanos() > u128::from(awake - start) + 10_000_000);
        fixture.live_ns.set(Some(awake));
    }
    fixture.phase.set(1);
    // SAFETY: exact live source scope on this executing bound stack.
    unsafe { schedule() };
    if let Some(before) = fixture.live_ns.get() {
        let resumed = fixture.binding.measured_execution_ns().unwrap();
        assert!(resumed >= before);
        fixture.live_ns.set(Some(resumed));
    }
    fixture.phase.set(2);
    // SAFETY: resumed the same source lease and holds no outstanding user.
    unsafe { stela_linux_exit() };
}
unsafe extern "C" fn run(context: *mut c_void) {
    // SAFETY: the sole producer keeps this fixture through both task steps.
    let fixture = unsafe { &*context.cast::<Fixture<'_>>() };
    fixture
        .wake
        .set(Some(fixture.binding.bind_current().unwrap()));
    // SAFETY: no unwind or escaped scope; both steps keep the fixture.
    unsafe { fixture.binding.run_scoped(body, context) }.unwrap();
}
unsafe extern "C" fn reuse(context: *mut c_void) {
    // SAFETY: same retained fixture and binding through its newer assignment.
    let fixture = unsafe { &*context.cast::<Fixture<'_>>() };
    fixture
        .wake
        .set(Some(fixture.runtime.current_wake().unwrap()));
    // SAFETY: the runtime restored the original source binding on this stack.
    unsafe { fixture.binding.run_scoped(body, context) }.unwrap();
}

#[test]
fn original_bare_scopes_yield_and_resume_on_separate_hosted_stacks() {
    let queue = HostedQueue::<4>::new(HostedExecution::new(), Arc::new(())).unwrap();
    let stack = stela_linux::task::stack_requirement().unwrap();
    // SAFETY: these callbacks are bounded and do not change shadow stacks.
    let executor = unsafe { HostedExecutor::new_with_stacks(queue.clone(), stack, 2) }.unwrap();
    let runtime = executor.runtime();
    let fixture = || Fixture {
        runtime,
        // SAFETY: sole C owner thread and retained executor until explicit release.
        binding: unsafe { HostedTaskBinding::new_bare(runtime) }.unwrap(),
        wake: Cell::new(None),
        phase: Cell::new(0),
        fifo: Cell::new(false),
        live_ns: Cell::new(None),
    };
    let fixtures = [fixture(), fixture()];
    let tickets = fixtures.each_ref().map(|fixture| {
        // SAFETY: both original fixtures stay alive through every callback.
        unsafe { queue.execute(Kind::General, run, ptr::from_ref(fixture).cast_mut().cast()) }
            .unwrap()
    });
    for expected in [[1, 0], [1, 1], [2, 1], [2, 2]] {
        assert!(runtime.step().unwrap());
        assert_eq!(
            fixtures.each_ref().map(|fixture| fixture.phase.get()),
            expected
        );
        assert_eq!(
            tickets.map(|ticket| queue.completed(ticket).unwrap()),
            expected.map(|phase| phase == 2)
        );
    }
    let first = &fixtures[0];
    let old_wake = first.wake.take().unwrap();
    runtime.enable_ranked_scheduling().unwrap();
    first.fifo.set(true);
    for fixture in &fixtures {
        fixture.phase.set(0);
    }
    // The original dispatcher returns to the first General stack after the
    // second General callback and the empty Notify lane.
    // SAFETY: the same original binding and fixture stay live through reuse.
    let tickets = fixtures.each_ref().map(|fixture| {
        // SAFETY: each original binding and fixture stay live through reuse.
        unsafe {
            queue.execute(
                Kind::General,
                reuse,
                ptr::from_ref(fixture).cast_mut().cast(),
            )
        }
        .unwrap()
    });
    assert!(runtime.step().unwrap());
    assert_eq!(
        fixtures.each_ref().map(|fixture| fixture.phase.get()),
        [1, 0]
    );
    let stopped = first.binding.measured_execution_ns().unwrap();
    assert!(stopped >= first.live_ns.get().unwrap());
    assert_eq!(first.binding.measured_execution_ns(), Ok(stopped));
    assert_eq!(runtime.execution_ns(&old_wake), Err(WorkError::Closed));
    for expected in [[2, 0], [2, 1], [2, 2]] {
        assert!(runtime.step().unwrap());
        assert_eq!(
            fixtures.each_ref().map(|fixture| fixture.phase.get()),
            expected
        );
        assert_eq!(
            tickets.map(|ticket| queue.completed(ticket).unwrap()),
            expected.map(|phase| phase == 2)
        );
    }
    assert!(first.live_ns.get().unwrap() >= stopped);
    assert_eq!(
        first.binding.measured_execution_ns(),
        Err(WorkError::Closed)
    );
    // SAFETY: the source scope joined. The earlier assignment is still the
    // wrong detach handle even though the physical stack and C task are same.
    let detached = unsafe { runtime.detach_binding(&old_wake) };
    assert!(matches!(detached, Err(WorkError::InvalidTicket)));
    for fixture in fixtures {
        // SAFETY: callbacks completed and no source producer remains.
        let binding = unsafe { runtime.detach_binding(&fixture.wake.take().unwrap()) }.unwrap();
        drop(binding);
        // SAFETY: taskless dispatcher after the original source detached.
        assert!(unsafe { fixture.binding.release_quiescent() }.is_ok());
    }
    queue.close().unwrap();
    runtime.retire().unwrap();
    // SAFETY: all producers stopped and the executor retired.
    unsafe { queue.retire() }.unwrap();
}
