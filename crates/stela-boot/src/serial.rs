//! Allocation-free, lock-free early/fatal UART output for one boot BSP only.
use core::{
    arch::asm,
    fmt::{self, Write},
};
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
impl Write for Serial {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        for byte in value.bytes() {
            // QEMU's actual VC terminal treats LF and CR independently.
            if byte == b'\n' {
                send(b'\r');
            }
            send(byte);
        }
        Ok(())
    }
}
pub fn arguments(args: fmt::Arguments<'_>) {
    let _ = Serial.write_fmt(args);
}
pub fn terminate(code: u32) -> ! {
    unsafe {
        asm!("out dx, eax", in("dx") 0xf4u16, in("eax") code, options(nostack, preserves_flags));
    }
    loop {
        unsafe {
            asm!("cli", "hlt", options(nostack));
        }
    }
}
pub fn fatal(message: &str) -> ! {
    let _ = Serial.write_str("\nSTELA FATAL ");
    let _ = Serial.write_str(message);
    let _ = Serial.write_str("\n");
    terminate(0x11)
}
