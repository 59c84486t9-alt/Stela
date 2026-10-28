//! Queue admission, ticket identity and hosted continuation fixtures.
extern crate std;
use super::*;
use std::thread;
struct CpuModel {
    thread: thread::ThreadId,
    flags: AtomicU64,
    irq: AtomicBool,
    time: AtomicU64,
}
impl CpuModel {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            thread: thread::current().id(),
            flags: AtomicU64::new(0x202),
            irq: AtomicBool::new(false),
            time: AtomicU64::new(0),
        })
    }
}
// SAFETY: explicit hosted exclusion/flags model only. It never installs a
// native provider or attests privileged CLI/IRQ behavior; QEMU tests bind
// those separately. Real x86 continuations use actual OS-owned VM stacks.
unsafe impl Cpu for CpuModel {
    fn check_cpu(&self) -> Result<(), WorkError> {
        if thread::current().id() == self.thread {
            Ok(())
        } else {
            Err(WorkError::WrongCpu)
        }
    }
    fn in_interrupt(&self) -> bool {
        self.irq.load(Ordering::Acquire)
    }
    fn save_disable(&self) -> Result<u64, WorkError> {
        self.check_cpu()?;
        Ok(self.flags.swap(2, Ordering::AcqRel))
    }
    unsafe fn restore(&self, flags: u64) {
        self.flags.store(flags, Ordering::Release);
    }
    fn ticks(&self) -> u64 {
        self.time.fetch_add(1, Ordering::Relaxed)
    }
    fn fatal(&self, e: WorkError) -> ! {
        panic!("fatal context {e:?}")
    }
}
struct Owner(Arc<AtomicU64>);
impl Drop for Owner {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
unsafe extern "C" fn noop(_: *mut c_void) {}
#[test]
fn admission_is_bounded_noninline_closed_and_restores_nested_flags() {
    let cpu = CpuModel::new();
    let drops = Arc::new(AtomicU64::new(0));
    let queue = unsafe { Queue::<2>::new(cpu.clone(), Arc::new(Owner(drops.clone()))) }.unwrap();
    cpu.irq.store(true, Ordering::Release);
    let a = unsafe { queue.execute(Kind::Notify, noop, core::ptr::null_mut()) }.unwrap();
    let b = unsafe { queue.execute(Kind::General, noop, core::ptr::null_mut()) }.unwrap();
    assert_eq!(
        unsafe { queue.execute(Kind::General, noop, core::ptr::null_mut()) },
        Err(WorkError::Full)
    );
    assert_eq!(cpu.flags.load(Ordering::Acquire), 0x202);
    cpu.flags.store(2, Ordering::Release);
    queue.close().unwrap();
    assert_eq!(cpu.flags.load(Ordering::Acquire), 2);
    assert!(!queue.completed(a).unwrap());
    assert!(!queue.completed(b).unwrap());
    assert_eq!(
        unsafe { queue.execute(Kind::General, noop, core::ptr::null_mut()) },
        Err(WorkError::Closed)
    );
    cpu.irq.store(false, Ordering::Release);
    assert_eq!(unsafe { queue.retire() }, Err(WorkError::Pending));
    let foreign = queue.clone();
    assert_eq!(
        thread::spawn(move || foreign.close()).join().unwrap(),
        Err(WorkError::WrongCpu)
    );
    let count = quarantined_owners();
    drop(queue);
    assert!(quarantined_owners() >= count.saturating_add(1));
    assert_eq!(drops.load(Ordering::Relaxed), 0);
}
#[test]
fn queue_ids_tickets_and_sequence_exhaustion_do_not_alias_or_wrap() {
    let cpu = CpuModel::new();
    let owner: RetainedOwner = Arc::new(());
    let a = unsafe { Queue::<2>::new(cpu.clone(), owner.clone()) }.unwrap();
    let b = unsafe { Queue::<2>::new(cpu, owner) }.unwrap();
    let ticket = unsafe { a.execute(Kind::General, noop, core::ptr::null_mut()) }.unwrap();
    assert_eq!(b.completed(ticket), Err(WorkError::InvalidTicket));
    {
        let mut g = b.lock().unwrap();
        g.state().next = u64::MAX;
    }
    assert_eq!(
        unsafe { b.execute(Kind::General, noop, core::ptr::null_mut()) },
        Err(WorkError::Exhausted)
    );
    assert!(b.lock().unwrap().state().jobs.iter().all(Option::is_none));
    b.close().unwrap();
    unsafe { b.retire() }.unwrap();
    drop((a, b));
}

// Guard-paged stacks come from the host's POSIX mmap.
#[cfg(all(target_arch = "x86_64", unix))]
mod switched;
