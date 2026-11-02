//! Owned probe body, invoked only by the genuine original-kthread producer.
use super::*;
use core::marker::PhantomPinned;
struct Job<P: KernelThreadPlatform + 'static, const N: usize> {
    kernel: Arc<KernelOwner<P, N>>,
    result: Arc<Cell<Option<i32>>>,
    _pin: PhantomPinned,
}
pub(super) fn new<P: KernelThreadPlatform + 'static, const N: usize>(
    kernel: Arc<KernelOwner<P, N>>,
    result: Arc<Cell<Option<i32>>>,
) -> Pin<Box<dyn ManagedJob>> {
    Box::pin(Job {
        kernel,
        result,
        _pin: PhantomPinned,
    })
}
// SAFETY: CPU-local owned pinned job contains no independently owned C source
// refs. It keeps actual canonical code/platform/root and result allocation
// until full JoinedJob, including suspended original probe/work/timer frames.
// Source PID1 owns actual child exit/reaper/RCU/native disposal before join.
unsafe impl<P: KernelThreadPlatform + 'static, const N: usize> ManagedJob for Job<P, N> {
    fn run(self: Pin<&mut Self>) {
        let job = self.as_ref().get_ref();
        // SAFETY: the real original kthread is already entered on this exact
        // canonical owner/current. Never acquire a nested owner or keep native
        // metadata/process loans over the original source waits/probe joins.
        let code = unsafe { stela_linux_srcu_bootstrap(job.kernel.raw()) };
        job.result.set(Some(code));
    }
}
