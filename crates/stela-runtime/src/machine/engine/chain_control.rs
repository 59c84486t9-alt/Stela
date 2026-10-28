//! Stable chaining storage with one local writer and an atomic remote budget.
use alloc::sync::Arc;
use core::{
    cell::{Cell, UnsafeCell},
    marker::PhantomData,
    sync::atomic::{AtomicU64, Ordering},
};
use stela_compiler::x86_64::chain::ChainControl;

/// Retained by its hub inbox even when no Machine owns the PE. The hub exposes
/// only the budget; all other fields belong to its one admitted Machine.
pub(super) struct Storage {
    control: UnsafeCell<ChainControl>,
}
// SAFETY: shared storage exposes only an aligned atomic budget. Non-budget
// fields are accessed only through the unique Owner admitted by the inbox.
unsafe impl Send for Storage {}
// SAFETY: the same single-writer/atomic-budget contract applies to shared access.
unsafe impl Sync for Storage {}
impl Storage {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            control: UnsafeCell::new(ChainControl::default()),
        })
    }
    pub(super) fn budget(&self) -> &AtomicU64 {
        // SAFETY: the live allocation has ChainControl's aligned u64 budget.
        // Rust never reads/writes this field non-atomically after publication;
        // native chaining uses its aligned architectural accesses at this ABI.
        unsafe { AtomicU64::from_ptr(core::ptr::addr_of_mut!((*self.control.get()).budget)) }
    }
}

/// The sole non-budget writer. It can move between threads with its Machine,
/// but cannot be shared; a hub retains Storage without granting this role.
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

    /// Reset every non-budget field before entry by a new admitted owner.
    pub(super) fn initialize(&mut self, table: u64, contexts: [u64; 2]) {
        let control = self.storage.control.get();
        // SAFETY: this Owner is the sole non-budget writer, with no native
        // invocation in progress. Field-specific raw writes never create a
        // shared mutable reference covering the remotely accessed budget.
        unsafe {
            core::ptr::addr_of_mut!((*control).retired).write(0);
            core::ptr::addr_of_mut!((*control).block).write(0);
            core::ptr::addr_of_mut!((*control).contexts).write(contexts);
            core::ptr::addr_of_mut!((*control).table).write(table);
            core::ptr::addr_of_mut!((*control).hits).write(0);
            core::ptr::addr_of_mut!((*control).linked).write(0);
        }
        self.budget().store(0, Ordering::Relaxed);
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
        // synchronous native call; remote writers touch only the budget.
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
        // touches these fields, including while a peer spends the budget.
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
        }
    }
}
