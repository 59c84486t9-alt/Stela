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
/// Whether the transmitter is empty: its FIFO takes 16 bytes now.
pub fn ready() -> bool {
    // SAFETY: reads the line status register of the configured UART.
    let status = unsafe { input(UART + 5) };
    status & 0x20 != 0
}
/// Send `bytes`, line feeds as CR LF, into a transmit FIFO that
/// [`ready`] found empty: at most 16 bytes in all, sent without polling,
/// as one string output, which a hypervisor takes in one exit.
pub fn burst(bytes: &[u8]) {
    let mut fifo = [0u8; 16];
    let mut length = 0;
    for &byte in bytes {
        if byte == b'\n' {
            fifo[length] = b'\r';
            length += 1;
        }
        fifo[length] = byte;
        length += 1;
    }
    // SAFETY: the configured UART's transmit register, with room for all of
    // them; RSI and RCX address and count `fifo`, and DF is clear.
    unsafe {
        asm!(
            "rep outsb",
            in("dx") UART,
            inout("rsi") fifo.as_ptr() => _,
            inout("rcx") length => _,
            options(nostack, preserves_flags, readonly),
        );
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
impl Serial {
    /// Send `bytes`, which may end or start inside a character.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            // QEMU's terminal treats LF and CR independently.
            if byte == b'\n' {
                send(b'\r');
            }
            send(byte);
        }
    }
}
impl fmt::Write for Serial {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.write_bytes(value.as_bytes());
        Ok(())
    }
}
