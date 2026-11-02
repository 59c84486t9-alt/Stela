//! Stacks for the code that expects a process's: Mesa and LLVM run deeper than
//! a PE's or a Linux task's stack. Each lies in the host's page window between
//! absent pages, so running off either end faults.
use super::PAGE;
use crate::{native_memory::SOURCE, native_mmio::Window};
use core::{
    arch::naked_asm,
    ffi::c_void,
    mem::ManuallyDrop,
    sync::atomic::{AtomicU64, Ordering},
};
use stela_boot_core::page_window::Cache;
use stela_drivers::bus::dma::memory::{CacheAttribute, PageSource, PinnedPages};

pub(super) struct Stack {
    window: &'static Window,
    memory: ManuallyDrop<PinnedPages>,
    /// Where the page beneath the stack would be.
    guard: u64,
}

/// The absent pages beneath and above a stack.
const GUARD_PAGES: usize = 2;

/// The one page every software mapping's tail shows (`gate`).
static SCRATCH: AtomicU64 = AtomicU64::new(0);

pub(super) fn scratch_page() -> Option<u64> {
    let known = SCRATCH.load(Ordering::Acquire);
    if known != 0 {
        return Some(known);
    }
    let memory = SOURCE
        .allocate(PAGE as usize, PAGE as usize, CacheAttribute::WriteBack)
        .ok()?;
    let physical = memory.physical_pages()[0];
    // It lasts for the boot; the service's lock keeps this to one.
    core::mem::forget(memory);
    SCRATCH.store(physical, Ordering::Release);
    Some(physical)
}

impl Stack {
    pub(super) fn map(window: &'static Window, bytes: usize) -> Option<Self> {
        let memory = SOURCE
            .allocate(bytes, PAGE as usize, CacheAttribute::WriteBack)
            .ok()?;
        let pages = memory.physical_pages().len();
        let guard = window.reserve(pages + GUARD_PAGES)?;
        let stack = Self {
            window,
            memory: ManuallyDrop::new(memory),
            guard,
        };
        for (&physical, page) in stack.memory.physical_pages().iter().zip(1..) {
            if !window.install(guard + page * PAGE, physical, Cache::WriteBack) {
                return None;
            }
        }
        Some(stack)
    }

    fn pages(&self) -> u64 {
        self.memory.physical_pages().len() as u64
    }

    pub(super) fn bottom(&self) -> u64 {
        self.guard + PAGE
    }

    pub(super) fn top(&self) -> u64 {
        self.bottom() + self.pages() * PAGE
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        let pages = self.pages() as usize + GUARD_PAGES;
        // A processor that kept the translation keeps the memory too.
        if self.window.remove(self.guard, pages) {
            self.window.release(self.guard, pages);
            // SAFETY: nothing maps the pages now, and this is their one drop.
            unsafe { ManuallyDrop::drop(&mut self.memory) };
        }
    }
}

/// This code's stack pointer.
pub(super) fn pointer() -> u64 {
    let pointer: u64;
    // SAFETY: reads a register.
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) pointer, options(nomem, nostack)) };
    pointer
}

#[unsafe(naked)]
unsafe extern "win64" fn switch(
    body: unsafe extern "win64" fn(*mut c_void),
    argument: *mut c_void,
    top: u64,
) {
    naked_asm!(
        "push rbp",
        "mov rbp, rsp",
        "lea rsp, [r8 - 32]",
        "mov rax, rcx",
        "mov rcx, rdx",
        "call rax",
        "mov rsp, rbp",
        "pop rbp",
        "ret",
    );
}

unsafe extern "win64" fn call(context: *mut c_void) {
    // SAFETY: `on_stack` keeps its body through `switch`.
    unsafe { (*context.cast::<&mut dyn FnMut()>())() };
}

/// Runs `body` on the stack ending at `top`, 16-byte aligned.
///
/// # Safety
/// Nothing else uses the stack below `top` until this returns.
pub(super) unsafe fn on_stack(top: u64, mut body: &mut dyn FnMut()) {
    // SAFETY: the caller's contract, and the body outlives the call.
    unsafe { switch(call, (&raw mut body).cast(), top) };
}
