//! Original bare C scope on the checked hosted task adapter.
#![cfg(all(
    feature = "hosted-runtime",
    target_os = "linux",
    target_arch = "x86_64"
))]

use std::{cell::Cell, ffi::c_void, ptr, rc::Rc, sync::Arc};
use stela_driver_base::platform::work::{
    Kind,
    kernel_domain::{HostedExecution, HostedExecutor, HostedQueue, HostedWake},
};
use stela_linux::task::HostedTaskBinding;

unsafe extern "C" {
    fn stela_linux_enter(owner: *const stela_linux::owner::RawOwner);
    fn stela_linux_exit();
    fn schedule();
    static stela_linux_bare: stela_linux::owner::RawOwner;
}
struct Fixture {
    binding: Rc<HostedTaskBinding<4>>,
    wake: Cell<Option<HostedWake>>,
    phase: Cell<u8>,
}
unsafe extern "C" fn body(context: *mut c_void) {
    // SAFETY: the sole producer keeps this fixture through both task steps.
    let fixture = unsafe { &*context.cast::<Fixture>() };
    // SAFETY: this bound task owns the live bare scope on the sole thread.
    unsafe { stela_linux_enter(&raw const stela_linux_bare) };
    fixture.phase.set(1);
    // SAFETY: exact live source scope on this executing bound stack.
    unsafe { schedule() };
    fixture.phase.set(2);
    // SAFETY: resumed the same source lease and holds no outstanding user.
    unsafe { stela_linux_exit() };
}
unsafe extern "C" fn run(context: *mut c_void) {
    // SAFETY: the sole producer keeps this fixture through both task steps.
    let fixture = unsafe { &*context.cast::<Fixture>() };
    fixture
        .wake
        .set(Some(fixture.binding.bind_current().unwrap()));
    // SAFETY: no unwind or escaped scope; both steps keep the fixture.
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
        // SAFETY: sole C owner thread and retained executor until explicit release.
        binding: unsafe { HostedTaskBinding::new_bare(runtime) }.unwrap(),
        wake: Cell::new(None),
        phase: Cell::new(0),
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
