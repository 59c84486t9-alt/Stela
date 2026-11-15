//! A body that runs on a stack of its own and gives its processor back at
//! points it chooses, to be resumed later on any processor: one long piece
//! of host work, such as a shader compilation, split into bounded host steps
//! without changing what it computes.
//!
//! A switch saves what the Microsoft x64 convention keeps across a call
//! (`rbx`, `rbp`, `rdi`, `rsi`, `r12`-`r15`, the stack pointer) and the
//! x87/SSE state with `FXSAVE64`, which keeps `xmm6`-`xmm15`, MXCSR and the
//! x87 control word: the C a fiber runs uses SSE, the code that resumes it
//! may not. Interrupt flags and the task priority are the resumer's: a
//! fiber gives its processor back only from a call it makes itself, never
//! from an interrupt handler.
use alloc::boxed::Box;
use core::{arch::naked_asm, ptr};

/// What a switch keeps of the x87 and SSE state.
const FX_BYTES: u64 = 512;
/// The registers a switch pushes, then the address it returns to.
const REGISTER_WORDS: u64 = 8;

/// A fiber's state, at a fixed address for its switches.
#[repr(C)]
struct Control {
    /// The fiber's stack pointer while it does not run.
    fiber: u64,
    /// Its resumer's while it runs.
    resumer: u64,
    finished: bool,
    running: bool,
    body: Option<Box<dyn FnOnce() + Send>>,
}

/// What [`Fiber::resume`] ended with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// The body gave the processor back ([`Handle::suspend`]).
    Suspended,
    /// The body returned.
    Finished,
}

/// A body on a stack of its own, run in steps by [`Fiber::resume`].
///
/// Dropping a fiber that started and has not finished leaves what its
/// frames hold: drop one only once it finished, or at a stop.
pub struct Fiber {
    /// Boxed, at an address the fiber's frames keep.
    control: *mut Control,
}

// SAFETY: the body is `Send`, and its frames live on the fiber's own stack,
// which only the processor resuming it touches.
unsafe impl Send for Fiber {}

/// What a running fiber's body suspends with.
#[derive(Clone, Copy, Debug)]
pub struct Handle(*mut Control);

// SAFETY: a handle is only used by the fiber it names, on whichever
// processor resumed it.
unsafe impl Send for Handle {}
// SAFETY: as above.
unsafe impl Sync for Handle {}

impl Fiber {
    /// A fiber that runs `body` on the stack below `top` at its first
    /// [`Self::resume`].
    ///
    /// # Safety
    /// The memory below `top` is writable, deep enough for `body`, and used
    /// by nothing else until the fiber finishes or is dropped.
    pub unsafe fn new(top: u64, body: Box<dyn FnOnce() + Send>) -> Self {
        let control = Box::into_raw(Box::new(Control {
            fiber: 0,
            resumer: 0,
            finished: false,
            running: false,
            body: Some(body),
        }));
        // The frame a switch restores, as if the fiber had suspended at the
        // entry of `entry` with `r12` holding its control.
        let registers = (top & !15) - (REGISTER_WORDS + 2) * 8;
        let fx = registers - FX_BYTES - 16;
        let words = [
            0,                         // r15
            0,                         // r14
            0,                         // r13
            control as u64,            // r12
            0,                         // rsi
            0,                         // rdi
            0,                         // rbx
            0,                         // rbp
            entry as *const () as u64, // return address
            0,
        ];
        // SAFETY: the caller's: this stack is writable and the fiber's.
        unsafe {
            for (index, word) in words.into_iter().enumerate() {
                ((registers + index as u64 * 8) as *mut u64).write(word);
            }
            ptr::write_bytes(fx as *mut u8, 0, FX_BYTES as usize);
            // The x87 control word and MXCSR a thread starts with: all
            // exceptions masked, round to nearest, no flush to zero.
            (fx as *mut u16).write(0x037f);
            ((fx + 24) as *mut u32).write(0x1f80);
            ((fx - 16) as *mut u64).write(registers);
            ((fx - 8) as *mut u64).write(registers);
        }
        // SAFETY: just boxed, and no frame runs yet.
        unsafe { (*control).fiber = fx - 16 };
        Self { control }
    }

    /// Runs the body until it suspends or returns.
    ///
    /// # Panics
    /// When the fiber finished, or runs already.
    pub fn resume(&mut self) -> Step {
        let control = self.control;
        // SAFETY: the fiber's control lives until its drop, and only its
        // resumer and its own frames, which run in turn, touch it.
        unsafe {
            assert!(
                !(*control).finished && !(*control).running,
                "a fiber resumed that cannot run"
            );
            (*control).running = true;
            // The fiber's saved frame, made by `new` or a suspension; the
            // switch back to here restores this frame.
            switch(&raw mut (*control).resumer, (*control).fiber);
            (*control).running = false;
            if (*control).finished {
                Step::Finished
            } else {
                Step::Suspended
            }
        }
    }

    /// Whether the body returned.
    pub fn finished(&self) -> bool {
        // SAFETY: as in `resume`.
        unsafe { (*self.control).finished }
    }

    /// What the body suspends with.
    pub fn handle(&self) -> Handle {
        Handle(self.control)
    }
}

impl Drop for Fiber {
    fn drop(&mut self) {
        // SAFETY: boxed by `new`; the fiber does not run while its owner
        // drops it, and its frames are left as the type says.
        drop(unsafe { Box::from_raw(self.control) });
    }
}

impl Handle {
    /// The handle as an address, for a slot a processor keeps it in.
    pub fn address(self) -> usize {
        self.0 as usize
    }

    /// The handle at `address`, as [`Self::address`] gave it.
    ///
    /// # Safety
    /// `address` came from [`Self::address`] of a fiber not yet dropped.
    pub unsafe fn from_address(address: usize) -> Self {
        Self(address as *mut Control)
    }

    /// Gives the processor back to the fiber's resumer; returns when a
    /// later [`Fiber::resume`] runs the fiber again.
    ///
    /// # Safety
    /// Called by the running body of the fiber this handle names, on its
    /// own stack, outside any interrupt handler.
    pub unsafe fn suspend(self) {
        let control = self.0;
        // SAFETY: the caller's; the resumer's frame was saved by `resume`.
        unsafe { switch(&raw mut (*control).fiber, (*control).resumer) };
    }
}

/// Saves this frame's state, stores its stack pointer at `save` and
/// continues the frame whose stack pointer is `load`.
#[unsafe(naked)]
unsafe extern "win64" fn switch(save: *mut u64, load: u64) {
    naked_asm!(
        "push rbp",
        "push rbx",
        "push rdi",
        "push rsi",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov rax, rsp",
        "sub rsp, 528",
        "and rsp, -16",
        "fxsave64 [rsp]",
        "push rax",
        "push rax",
        "mov [rcx], rsp",
        "mov rsp, rdx",
        "pop rax",
        "pop rax",
        "fxrstor64 [rsp]",
        "mov rsp, rax",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rsi",
        "pop rdi",
        "pop rbx",
        "pop rbp",
        "ret",
    );
}

/// Where a new fiber's first switch returns to, with its control in `r12`.
#[unsafe(naked)]
unsafe extern "win64" fn entry() {
    naked_asm!(
        "mov rcx, r12",
        "and rsp, -16",
        "sub rsp, 32",
        "call {main}",
        "ud2",
        main = sym main,
    );
}

/// Runs the body, then switches back for good.
unsafe extern "win64" fn main(control: *mut Control) {
    // SAFETY: the control `new` put in `r12`, live while the fiber runs.
    unsafe {
        if let Some(body) = (*control).body.take() {
            body();
        }
        (*control).finished = true;
        let mut ended = 0;
        switch(&raw mut ended, (*control).resumer);
    }
    unreachable!("a finished fiber is never resumed");
}

#[cfg(test)]
mod tests {
    use super::{Fiber, Handle, Step};
    use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
    use core::sync::atomic::{AtomicU64, Ordering};

    /// A stack for a test fiber, kept with it.
    fn stack() -> (Vec<u64>, u64) {
        let memory = vec![0u64; 64 << 10];
        let top = memory.as_ptr() as u64 + (memory.len() as u64) * 8;
        (memory, top)
    }

    /// A fiber whose body gets its own handle.
    fn fiber(top: u64, body: impl FnOnce(Handle) + Send + 'static) -> Fiber {
        let handle = Arc::new(AtomicU64::new(0));
        let given = handle.clone();
        // SAFETY: the test keeps the stack until the fiber finished.
        let fiber = unsafe {
            Fiber::new(
                top,
                Box::new(move || {
                    let handle = Handle(given.load(Ordering::Acquire) as *mut _);
                    body(handle)
                }),
            )
        };
        handle.store(fiber.handle().0 as u64, Ordering::Release);
        fiber
    }

    /// A long computation that suspends every `every` steps.
    fn digest(steps: u64, every: u64, handle: Option<Handle>) -> u64 {
        let mut value = 0xcbf2_9ce4_8422_2325u64;
        let mut floats = 1.0f64;
        for step in 0..steps {
            value = (value ^ step).wrapping_mul(0x100_0000_01b3);
            floats = floats * 1.000_001 + (step as f64).sqrt();
            if let Some(handle) = handle
                && step % every == every - 1
            {
                // SAFETY: the running body of the fiber the handle names.
                unsafe { handle.suspend() };
            }
        }
        value ^ floats.to_bits()
    }

    #[test]
    fn a_suspended_body_computes_what_a_whole_run_does() {
        let (_memory, top) = stack();
        let result = Arc::new(AtomicU64::new(0));
        let into = result.clone();
        let mut fiber = fiber(top, move |handle| {
            into.store(digest(10_000, 1_000, Some(handle)), Ordering::Release);
        });
        let mut steps = 0;
        while fiber.resume() == Step::Suspended {
            steps += 1;
        }
        assert_eq!(steps, 10);
        assert!(fiber.finished());
        assert_eq!(result.load(Ordering::Acquire), digest(10_000, 1_000, None));
    }

    fn mxcsr() -> u32 {
        let mut value = 0u32;
        // SAFETY: stores MXCSR to a local.
        unsafe { core::arch::asm!("stmxcsr [{}]", in(reg) &raw mut value) };
        value
    }

    fn set_mxcsr(value: u32) {
        // SAFETY: loads a valid MXCSR from a local.
        unsafe { core::arch::asm!("ldmxcsr [{}]", in(reg) &raw const value) };
    }

    #[test]
    fn each_side_keeps_its_own_floating_point_controls() {
        let (_memory, top) = stack();
        let seen = Arc::new(AtomicU64::new(0));
        let into = seen.clone();
        let mut fiber = fiber(top, move |handle| {
            // A fiber starts with the default controls.
            into.store(u64::from(mxcsr()), Ordering::Release);
            // Round toward zero, kept across a suspension.
            set_mxcsr(0x7f80);
            // SAFETY: the running body.
            unsafe { handle.suspend() };
            into.store(u64::from(mxcsr()), Ordering::Release);
            set_mxcsr(0x1f80);
        });
        let before = mxcsr();
        assert_eq!(fiber.resume(), Step::Suspended);
        assert_eq!(seen.load(Ordering::Acquire), 0x1f80);
        assert_eq!(mxcsr(), before, "the resumer's controls come back");
        // Flush to zero on the resumer's side does not reach the fiber.
        set_mxcsr(before | 0x8000);
        assert_eq!(fiber.resume(), Step::Finished);
        assert_eq!(seen.load(Ordering::Acquire), 0x7f80);
        assert_eq!(mxcsr(), before | 0x8000);
        set_mxcsr(before);
    }

    #[test]
    fn a_fiber_moves_between_threads_between_steps() {
        let (memory, top) = stack();
        let result = Arc::new(AtomicU64::new(0));
        let into = result.clone();
        let mut fiber = fiber(top, move |handle| {
            into.store(digest(6_000, 1_000, Some(handle)), Ordering::Release);
        });
        assert_eq!(fiber.resume(), Step::Suspended);
        let fiber = std::thread::spawn(move || {
            let mut fiber = fiber;
            assert_eq!(fiber.resume(), Step::Suspended);
            fiber
        })
        .join()
        .unwrap();
        let mut fiber = fiber;
        while fiber.resume() == Step::Suspended {}
        drop(memory);
        assert_eq!(result.load(Ordering::Acquire), digest(6_000, 1_000, None));
    }

    #[test]
    #[should_panic(expected = "cannot run")]
    fn a_finished_fiber_is_not_resumed() {
        let (_memory, top) = stack();
        let mut fiber = fiber(top, |_| {});
        assert_eq!(fiber.resume(), Step::Finished);
        fiber.resume();
    }
}
