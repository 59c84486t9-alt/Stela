//! Allocation-free, lock-free UART output for the boot processor.
use core::{arch::asm, fmt};
const UART: u16 = 0x3f8;
unsafe fn out(port: u16, value: u8) {
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nostack, preserves_flags));
    }
}
unsafe fn input(port: u16) -> u8 {
    let value;
    unsafe {
        asm!("in al, dx", in("dx") port, out("al") value, options(nostack, preserves_flags));
    }
    value
}
pub fn initialize() {
    // SAFETY: configured development PC UART, exclusive BSP I/O ownership.
    unsafe {
        out(UART + 1, 0);
        out(UART + 3, 0x80);
        out(UART, 1);
        out(UART + 1, 0);
        out(UART + 3, 3);
        out(UART + 2, 0xc7);
        out(UART + 4, 0x0b);
    }
}
fn send(byte: u8) {
    // Bounded polling has no allocator/runtime callback or lock. A broken
    // UART cannot convert panic into deadlock or resumed execution.
    for _ in 0..100_000 {
        if unsafe { input(UART + 5) } & 0x20 != 0 {
            break;
        }
        core::hint::spin_loop();
    }
    unsafe {
        out(UART, byte);
    }
}
pub struct Serial;
impl fmt::Write for Serial {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        for byte in value.bytes() {
            // QEMU's terminal treats LF and CR independently.
            if byte == b'\n' {
                send(b'\r');
            }
            send(byte);
        }
        Ok(())
    }
}
