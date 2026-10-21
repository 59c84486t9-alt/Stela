//! State owned by this physical host processor for its executor lifetime.
//! GS is private to Stela at CPL0, including translated execution and faults.
use super::State;
use core::{
    arch::asm,
    cell::UnsafeCell,
    marker::PhantomData,
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
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
}

impl Local {
    pub(crate) const fn new() -> Self {
        Self {
            this: core::ptr::null_mut(),
            recovery_rsp: UnsafeCell::new(0),
            handler: super::super::interrupts::interrupt,
            state: UnsafeCell::new(None),
            interrupted: AtomicBool::new(false),
        }
    }
}

/// A CPU-local state allocation. It cannot migrate or be shared with another
/// host processor. The owner must outlive every local native call and handler.
pub(crate) struct Owner {
    local: NonNull<Local>,
    _pinned: PhantomData<*mut ()>,
}

impl Owner {
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
