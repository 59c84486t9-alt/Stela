//! Terminal panic path, independent of allocator, output queues and callbacks.
use crate::serial::Serial;
use core::{
    arch::asm,
    fmt::Write,
    panic::PanicInfo,
    sync::atomic::{AtomicBool, Ordering},
};

/// QEMU's raw debug-exit port; no queued/logging output is invoked before it.
pub(super) const EXIT_PORT: u16 = 0xf4;
static PRINTING: AtomicBool = AtomicBool::new(false);

/// The stack words that lie in this image, as offsets from its base: the
/// return addresses among them name the caller, as `stela.pdb` resolves them.
/// A release build has no frame pointers to walk.
fn print_stack() {
    let stack: *const u64;
    // SAFETY: reads the stack pointer.
    unsafe { asm!("mov {}, rsp", out(reg) stack, options(nomem, nostack, preserves_flags)) };
    // SAFETY: a panic runs far enough from its stack's end for these.
    unsafe { print_stack_at(stack) };
}

/// [`print_stack`], from `stack`.
///
/// # Safety
/// `stack` reads as 512 words.
pub(crate) unsafe fn print_stack_at(stack: *const u64) {
    const WORDS: usize = 512;
    const SHOWN: usize = 32;
    unsafe extern "C" {
        static __ImageBase: u8;
    }
    let base = &raw const __ImageBase as u64;
    // SAFETY: the mapped PE headers of this image: the DOS header's
    // `e_lfanew`, and the optional header's `SizeOfImage`.
    let bytes = unsafe {
        let header = u64::from((base as *const u32).byte_add(0x3c).read_unaligned());
        u64::from(
            ((base + header) as *const u32)
                .byte_add(0x50)
                .read_unaligned(),
        )
    };
    let offsets = (0..WORDS)
        // SAFETY: the caller's.
        .map(|word| unsafe { stack.add(word).read() }.wrapping_sub(base))
        .filter(|&offset| offset < bytes)
        .take(SHOWN);
    let _ = write!(Serial, "STELA STACK");
    for offset in offsets {
        let _ = write!(Serial, " {offset:#x}");
    }
    let _ = writeln!(Serial);
}

pub(crate) fn panic(info: &PanicInfo<'_>) -> ! {
    if PRINTING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
        .is_ok()
    {
        // Never invoke arbitrary Display implementations in a failing process.
        // OOM's exact Layout was reported at the first null allocation instead.
        let message = info
            .message()
            .as_str()
            .unwrap_or("<nonliteral panic message omitted>");
        match info.location() {
            Some(at) => {
                let _ = writeln!(
                    Serial,
                    "\nSTELA PANIC at {}:{}: {message}",
                    at.file(),
                    at.line()
                );
            }
            None => {
                let _ = writeln!(Serial, "\nSTELA PANIC: {message}");
            }
        }
        print_stack();
        let _ = writeln!(Serial, "STELA STOPPED code=0x11; power off to continue");
        // SAFETY: native panic executes at CPL0, with the configured raw exit
        // port. No heap/log/runtime code may run between this report and halt.
        unsafe {
            asm!("out dx, eax", in("dx") EXIT_PORT, in("eax") 0x11u32, options(nostack, preserves_flags));
        }
    }
    // Other panicking CPUs must not exit the VM before the first report ends.
    loop {
        // SAFETY: terminal CPL0 path, no continuation or resource release.
        unsafe {
            asm!("cli", "hlt", options(nostack));
        }
    }
}
