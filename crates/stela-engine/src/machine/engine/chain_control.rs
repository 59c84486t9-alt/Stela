//! Stable chaining storage with one local writer and atomic interruption epochs.
use alloc::sync::Arc;
use core::{
    cell::{Cell, UnsafeCell},
    marker::PhantomData,
    sync::atomic::{AtomicU64, Ordering},
};
use stela_compiler::x86_64::chain::ChainControl;

/// By its hub inbox even when no Machine owns the PE. The hub exposes
/// only the interruption epoch; all other fields belong to its admitted Machine.
#[repr(C, align(64))]
pub(super) struct Storage {
    control: UnsafeCell<ChainControl>,
}
// SAFETY: shared storage exposes only an aligned atomic epoch. Other fields
// are accessed only through the unique Owner admitted by the inbox.
unsafe impl Send for Storage {}
// SAFETY: the same single-writer/atomic-epoch contract applies to shared access.
unsafe impl Sync for Storage {}
impl Storage {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            control: UnsafeCell::new(ChainControl::default()),
        })
    }
    fn budget(&self) -> &AtomicU64 {
        // SAFETY: the live allocation has ChainControl's aligned u64 budget.
        // Rust never reads/writes this field non-atomically after publication;
        // native chaining uses its aligned architectural accesses at this ABI.
        unsafe { AtomicU64::from_ptr(core::ptr::addr_of_mut!((*self.control.get()).budget)) }
    }
    pub(super) fn interrupt_epoch(&self) -> &AtomicU64 {
        // SAFETY: the control has a naturally aligned epoch field.
        // Every Rust access is atomic; native thunks perform aligned loads.
        unsafe {
            AtomicU64::from_ptr(core::ptr::addr_of_mut!(
                (*self.control.get()).interrupt_epoch
            ))
        }
    }
    pub(super) fn notify(&self) {
        // Publish every source write before making the corresponding epoch
        // visible. Exhaustion stays permanently interrupted rather than wraps.
        let _ = self
            .interrupt_epoch()
            .try_update(Ordering::Release, Ordering::Relaxed, |epoch| {
                Some(epoch.saturating_add(1))
            });
    }
}

/// The sole local-control writer. It can move between threads with its Machine,
/// but cannot be shared; a hub keeps Storage without granting this role.
pub(super) struct Owner {
    storage: Arc<Storage>,
    _single_writer: PhantomData<Cell<()>>,
    _attachment: Option<Arc<super::parallel::Attached>>,
}
impl Default for Owner {
    fn default() -> Self {
        Self {
            storage: Storage::new(),
            _single_writer: PhantomData,
            _attachment: None,
        }
    }
}
impl Owner {
    /// # Safety
    /// The caller holds the unique live attachment claim for this storage,
    /// until this Owner can no longer access it. No old native code or other
    /// writer may run through its previous owner's installed chain thunks.
    pub(super) unsafe fn from_claimed(
        storage: Arc<Storage>,
        attachment: Arc<super::parallel::Attached>,
    ) -> Self {
        Self {
            storage,
            _single_writer: PhantomData,
            _attachment: Some(attachment),
        }
    }
    pub(super) fn budget(&self) -> &AtomicU64 {
        self.storage.budget()
    }
    pub(super) fn address(&self) -> u64 {
        self.storage.control.get() as u64
    }

    /// Reset every local field, keeping the inbox's monotonic notification epoch.
    pub(super) fn initialize(&mut self, table: u64, contexts: [u64; 2]) {
        let control = self.storage.control.get();
        // SAFETY: this Owner is the sole local writer, with no native call
        // in progress. Disjoint raw writes never borrow the shared epoch.
        unsafe {
            core::ptr::addr_of_mut!((*control).retired).write(0);
            core::ptr::addr_of_mut!((*control).block).write(0);
            core::ptr::addr_of_mut!((*control).contexts).write(contexts);
            core::ptr::addr_of_mut!((*control).table).write(table);
            core::ptr::addr_of_mut!((*control).hits).write(0);
            core::ptr::addr_of_mut!((*control).linked).write(0);
            core::ptr::addr_of_mut!((*control).observed_interrupt_epoch).write(0);
        }
        self.budget().store(0, Ordering::Relaxed);
    }
    /// Acknowledge only the Acquire snapshot taken before a successful drain.
    /// MAX is never acknowledged, so exhausted notification state stays sticky.
    pub(super) fn acknowledge_interrupt(&mut self, epoch: u64) {
        // SAFETY: only the unique owner writes the observed field outside its
        // synchronous native invocation; notifiers touch the separate epoch.
        unsafe {
            core::ptr::addr_of_mut!((*self.storage.control.get()).observed_interrupt_epoch)
                .write(epoch.min(u64::MAX - 1));
        }
    }
    pub(super) fn set_table(&mut self, table: u64) {
        // SAFETY: the sole owner writes this non-budget field outside native execution.
        unsafe { core::ptr::addr_of_mut!((*self.storage.control.get()).table).write(table) };
    }
    pub(super) fn contexts(&self) -> [u64; 2] {
        // SAFETY: only this Owner or its synchronous native call can write contexts.
        unsafe { core::ptr::addr_of!((*self.storage.control.get()).contexts).read() }
    }
    pub(super) fn set_contexts(&mut self, contexts: [u64; 2]) {
        // SAFETY: the sole owner writes this non-budget field outside native execution.
        unsafe { core::ptr::addr_of_mut!((*self.storage.control.get()).contexts).write(contexts) };
    }
    pub(super) fn begin(&mut self, block: usize, budget: u64) {
        let control = self.storage.control.get();
        // SAFETY: the sole owner prepares these disjoint fields before its
        // synchronous native call; remote writers touch only the epoch.
        unsafe {
            core::ptr::addr_of_mut!((*control).retired).write(0);
            core::ptr::addr_of_mut!((*control).block).write(block as u64);
            core::ptr::addr_of_mut!((*control).hits).write(0);
            core::ptr::addr_of_mut!((*control).linked).write(0);
        }
        self.budget().store(budget, Ordering::Relaxed);
    }
    pub(super) fn completed(&self) -> (u64, u64, u64, u64) {
        let control = self.storage.control.get();
        // SAFETY: the synchronous native call has returned; no other owner
        // touches these fields, including while a peer posts an interruption.
        unsafe {
            (
                core::ptr::addr_of!((*control).block).read(),
                core::ptr::addr_of!((*control).retired).read(),
                core::ptr::addr_of!((*control).hits).read(),
                core::ptr::addr_of!((*control).linked).read(),
            )
        }
    }
    #[cfg(test)]
    pub(super) fn weak_storage(&self) -> alloc::sync::Weak<Storage> {
        Arc::downgrade(&self.storage)
    }
    #[cfg(test)]
    pub(super) fn snapshot(&self) -> ChainControl {
        let (block, retired, hits, linked) = self.completed();
        let control = self.storage.control.get();
        ChainControl {
            budget: self.budget().load(Ordering::Relaxed),
            block,
            retired,
            hits,
            linked,
            contexts: self.contexts(),
            // SAFETY: the sole owner observes a non-budget field outside entry.
            table: unsafe { core::ptr::addr_of!((*control).table).read() },
            interrupt_epoch: self.storage.interrupt_epoch().load(Ordering::Acquire),
            // SAFETY: only the unique owner writes the observed epoch.
            observed_interrupt_epoch: unsafe {
                core::ptr::addr_of!((*control).observed_interrupt_epoch).read()
            },
        }
    }
}
