//! State owned by this physical host processor for its executor lifetime.
//! GS is private to Stela at CPL0, including translated execution and faults.
use super::State;
use core::{
    arch::asm,
    cell::UnsafeCell,
    marker::PhantomData,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

const GS_BASE: u32 = 0xc000_0101;

#[repr(C, align(64))]
pub(crate) struct Local {
    this: *mut Local,
    /// Native assembly and the local recovery path share this one slot.
    recovery_rsp: UnsafeCell<u64>,
    handler: extern "sysv64" fn(&mut super::super::interrupts::Frame),
    state: UnsafeCell<Option<State>>,
    interrupted: AtomicBool,
    doorbells: AtomicU64,
    worker: UnsafeCell<Option<stela_runtime::machine::engine::publication::WorkerId>>,
}

impl Local {
    pub(crate) const fn new() -> Self {
        Self {
            this: core::ptr::null_mut(),
            recovery_rsp: UnsafeCell::new(0),
            handler: super::super::interrupts::interrupt,
            state: UnsafeCell::new(None),
            interrupted: AtomicBool::new(false),
            doorbells: AtomicU64::new(0),
            worker: UnsafeCell::new(None),
        }
    }
}

/// A CPU-local state allocation. It cannot migrate or be shared with another
/// host processor. The owner must outlive every local native call and handler.
#[must_use = "retain the physical native host owner through every call and handler"]
pub(crate) struct Owner {
    local: NonNull<Local>,
    _pinned: PhantomData<*mut ()>,
}

impl Owner {
    /// Adopt the existing canonical owner before a guest regime or frame is
    /// live. This replaces metadata; it allocates/copies no guest RAM.
    ///
    /// # Safety
    /// This is the source-qualified registered RAM for this executor. Its
    /// all-writer contract is retained. Direct SystemModeV1 guest data writers
    /// must never bypass this all-writer owner, including between checked calls.
    /// Only the source-qualified checked service and registered host/table
    /// publishers may touch data; returning to serial execution additionally
    /// requires the canonical reservation/event ownership join.
    pub(crate) unsafe fn register_system_ram(
        &mut self,
        ram: alloc::sync::Arc<stela_runtime::memory::RegisteredSystemRam>,
    ) -> Result<(), &'static str> {
        if current() != self.local.as_ptr() {
            return Err("native Host owner migrated");
        }
        let state = state();
        if state.native || state.regime.is_some() || state.registered_ram.is_some() {
            return Err("native RAM adoption requires pristine owner-local dispatch");
        }
        state.ram = ram
            .placements()
            .map(|(guest, host, bytes)| super::RamRange {
                guest,
                host,
                bytes: bytes as u64,
            })
            .collect();
        state.registered_ram = Some(ram);
        Ok(())
    }

    /// Bind this actual selected physical core once, before runtime dispatch.
    pub(crate) fn bind_worker(
        &mut self,
        worker: stela_runtime::machine::engine::publication::WorkerId,
        expected_apic: u32,
    ) -> Result<(), &'static str> {
        if current() != self.local.as_ptr() {
            return Err("native Host owner migrated");
        }
        if state().apic.id() != expected_apic {
            return Err("native Host physical identity differs");
        }
        // SAFETY: this processor's unique owner, before any native dispatch;
        // handler code never changes the immutable runtime worker binding.
        let binding = unsafe { &mut *self.local.as_ref().worker.get() };
        if binding.is_some() {
            return Err("native Host worker already bound");
        }
        *binding = Some(worker);
        Ok(())
    }

    /// Borrow the sole host handle while retaining its processor-local owner.
    pub(crate) fn host(&mut self) -> super::BareHost<'_> {
        assert_eq!(current(), self.local.as_ptr(), "host state owner migrated");
        super::BareHost {
            _owner: PhantomData,
            _pinned: PhantomData,
        }
    }
}

const _: () = assert!(core::mem::offset_of!(Local, this) == 0);
pub(super) const RECOVERY_RSP_OFFSET: usize = core::mem::offset_of!(Local, recovery_rsp);
pub(crate) const HANDLER_OFFSET: usize = core::mem::offset_of!(Local, handler);

unsafe fn set_base(base: u64) {
    // SAFETY: the executor owns this processor's GS, and its descriptor/IST
    // setup has already finished. The base remains mapped in every root.
    unsafe {
        asm!("wrmsr", in("ecx") GS_BASE, in("eax") base as u32,
            in("edx") (base >> 32) as u32, options(nostack, preserves_flags));
    }
}

/// # Safety
/// Called once for this processor, with interrupts disabled. `local` is private,
/// pinned and mapped through every root until this processor is permanently
/// stopped; its descriptor owner retains it after this call.
pub(crate) unsafe fn activate(
    local: &mut Local,
    handler: extern "sysv64" fn(&mut super::super::interrupts::Frame),
) {
    assert!(
        local.this.is_null(),
        "host processor local record already active"
    );
    local.handler = handler;
    local.this = local;
    // SAFETY: the descriptor owner pins this private record for the CPU lifetime.
    unsafe { set_base(local as *mut Local as u64) };
}

/// # Safety
/// This processor's descriptor/local record is installed, interrupts are
/// disabled, and the returned owner outlives every local native call/handler.
pub(super) unsafe fn install(state: State) -> Owner {
    let local = NonNull::new(current()).expect("host processor local record absent");
    // SAFETY: this is the sole initialization under the current CPU owner.
    let slot = unsafe { &mut *local.as_ref().state.get() };
    assert!(
        slot.is_none(),
        "host state already installed on this processor"
    );
    *slot = Some(state);
    Owner {
        local,
        _pinned: PhantomData,
    }
}

fn current() -> *mut Local {
    let pointer: *mut Local;
    // SAFETY: the caller retains the local Owner. Guest translations do not
    // change GS, and every engine/shadow root maps this private allocation.
    unsafe {
        asm!("mov {}, gs:[0]", out(reg) pointer, options(readonly, nostack, preserves_flags))
    };
    pointer
}

pub(super) fn state() -> &'static mut State {
    // SAFETY: execution is pinned to the Owner's host CPU. Outside native
    // code interrupts are disabled and calls never overlap; native execution
    // retains no State reference while a fault/helper borrows it.
    unsafe {
        (&mut *(*current()).state.get())
            .as_mut()
            .expect("host state installed")
    }
}

pub(super) fn interrupt() {
    // SAFETY: one processor owns this record for the handler's whole lifetime.
    unsafe { &(*current()).interrupted }.store(true, Ordering::Release);
}

pub(super) fn doorbell_counter() -> &'static AtomicU64 {
    // SAFETY: descriptor/local storage is permanently pinned through parked
    // NMI/MCE entry. Only the current physical processor selects this record.
    unsafe { &(*current()).doorbells }
}

pub(super) fn doorbell() {
    doorbell_counter().fetch_add(1, Ordering::Release);
    interrupt();
}

pub(super) fn clear_interrupt() {
    // SAFETY: as in interrupt; the atomic is separate from mutable host state.
    unsafe { &(*current()).interrupted }.store(false, Ordering::Relaxed);
}

impl Drop for Owner {
    fn drop(&mut self) {
        assert_eq!(current(), self.local.as_ptr(), "host state owner migrated");
        // SAFETY: the owner is processor-local, interrupts are disabled, and
        // the caller has stopped every execution/handler using this record.
        unsafe {
            let local = self.local.as_ref();
            let slot = &mut *local.state.get();
            let state = slot.as_mut().expect("host state owner installed");
            assert!(
                !state.native && *local.recovery_rsp.get() == 0,
                "active native host state dropped"
            );
            state
                .apic
                .write(crate::apic::LVT_TIMER, crate::apic::LVT_MASKED);
            state.apic.write(crate::apic::INITIAL, 0);
            // Descriptor/IST/local storage stays pinned even after host state
            // retires: NMI/MCE can still need it while this processor is parked.
            slot.take();
        }
    }
}

pub(super) fn native_worker() -> Option<stela_runtime::machine::engine::publication::WorkerId> {
    // SAFETY: callers retain this processor's live Owner/GS record. The worker
    // binding is set once by that owner after checking its real local APIC ID.
    unsafe { *(*current()).worker.get() }
}
