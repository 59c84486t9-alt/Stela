//! The mount's output: every line goes to the UART and, once installed, the
//! framebuffer console.
use crate::{console, serial::Serial};
use core::{
    arch::asm,
    fmt::{self, Write},
};

/// `isa-debug-exit` under QEMU; an unused port on a PC.
const EXIT_PORT: u16 = 0xf4;

struct Output(console::Color);
impl Write for Output {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let _ = Serial.write_str(value);
        console::write(value, self.0);
        Ok(())
    }
}

pub fn arguments(args: fmt::Arguments<'_>) {
    let _ = Output(console::Color::Text).write_fmt(args);
}

/// Report `code` to QEMU, then halt. On a PC the screen keeps the output
/// until the machine is powered off.
pub fn terminate(code: u32) -> ! {
    arguments(format_args!(
        "STELA STOPPED code={code:#x}; power off to continue\n"
    ));
    unsafe {
        asm!("out dx, eax", in("dx") EXIT_PORT, in("eax") code, options(nostack, preserves_flags));
    }
    loop {
        unsafe {
            asm!("cli", "hlt", options(nostack));
        }
    }
}

pub fn fatal(message: &str) -> ! {
    let _ = Output(console::Color::Fatal).write_fmt(format_args!("\nSTELA FATAL {message}\n"));
    terminate(0x11)
}

pub fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    let mut output = Output(console::Color::Fatal);
    let _ = output.write_str("\nSTELA PANIC");
    if let Some(location) = info.location() {
        let _ = write!(output, " {}:{}", location.file(), location.line());
    }
    let _ = output.write_str("\n");
    terminate(0x11)
}
