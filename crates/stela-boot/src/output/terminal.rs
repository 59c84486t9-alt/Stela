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
