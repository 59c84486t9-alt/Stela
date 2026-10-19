//! The host machine's power: the guest's restart and power-off become the
//! host's, through its ACPI fixed hardware (`stela_runtime::pc::power`),
//! and the host's power button becomes the guest's.
//!
//! Each transition first writes the stop code to `isa-debug-exit`, so a
//! QEMU harness run still ends with that code; on other machines the port
//! is unused and the transition follows.
//!
//! - Restart: the FADT's reset register, then the 8042 keyboard
//!   controller's reset pulse (command 0xfe, the PC/AT reset line), then a
//!   triple fault, each given half a second.
//! - Power-off: the S5 soft-off sequence. When it does not take effect, the
//!   mount says so and halts; it never reports a power-off it did not make.
//! - Power button: the fixed-feature button's PWRBTN_STS, polled between
//!   engine slices. The mount takes the fixed events from the firmware as
//!   any ACPI OS does (ACPI_ENABLE to SMI_CMD, then SCI_EN), enables
//!   PWRBTN_EN and clears the status it reads. The status records a press
//!   only, so the guest gets a press and a release.
use super::host;
use crate::output;
use core::arch::asm;
use stela_runtime::machine::apple::AppleDevices;
use stela_runtime::pc::power::{self, HostPower, POWER_BUTTON, ResetRegister, SCI_ENABLE};

/// The stop codes `isa-debug-exit` reports.
pub const RESTART_CODE: u32 = 0x15;
pub const POWER_OFF_CODE: u32 = 0x17;

const PCI_ADDRESS: u16 = 0xcf8;
const PCI_DATA: u16 = 0xcfc;
const KEYBOARD_STATUS: u16 = 0x64;
const KEYBOARD_INPUT_FULL: u8 = 1 << 1;
const KEYBOARD_PULSE_RESET: u8 = 0xfe;

unsafe fn out8(port: u16, value: u8) {
    // SAFETY: the caller's port.
    unsafe { asm!("out dx, al", in("dx") port, in("al") value, options(nostack, preserves_flags)) }
}

unsafe fn in8(port: u16) -> u8 {
    let value;
    // SAFETY: the caller's port.
    unsafe { asm!("in al, dx", in("dx") port, out("al") value, options(nostack, preserves_flags)) }
    value
}

unsafe fn out16(port: u16, value: u16) {
    // SAFETY: the caller's port.
    unsafe { asm!("out dx, ax", in("dx") port, in("ax") value, options(nostack, preserves_flags)) }
}

unsafe fn in16(port: u16) -> u16 {
    let value;
    // SAFETY: the caller's port.
    unsafe { asm!("in ax, dx", in("dx") port, out("ax") value, options(nostack, preserves_flags)) }
    value
}

unsafe fn out32(port: u16, value: u32) {
    // SAFETY: the caller's port.
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") value, options(nostack, preserves_flags))
    }
}

unsafe fn in32(port: u16) -> u32 {
    let value;
    // SAFETY: the caller's port.
    unsafe {
        asm!("in eax, dx", in("dx") port, out("eax") value, options(nostack, preserves_flags))
    }
    value
}

/// Spin until `done` or `milliseconds` pass.
fn wait(tsc_hz: u64, milliseconds: u64, mut done: impl FnMut() -> bool) -> bool {
    let start = host::rdtsc();
    let ticks = tsc_hz / 1000 * milliseconds;
    while host::rdtsc() - start < ticks {
        if done() {
            return true;
        }
        core::hint::spin_loop();
    }
    done()
}

pub struct HostPowerControl {
    power: Option<HostPower>,
    tsc_hz: u64,
    /// The power button is read.
    button: bool,
    /// The guest refused the button once; reported once.
    refused: bool,
}

impl HostPowerControl {
    /// The host's power hardware the loader found, with the fixed power
    /// button armed when there is one.
    pub fn new(power: Option<HostPower>, tsc_hz: u64) -> Self {
        let mut control = Self {
            power,
            tsc_hz,
            button: false,
            refused: false,
        };
        control.button = control.arm_button();
        control
    }

    fn arm_button(&self) -> bool {
        let Some(power) = self.power.filter(|power| power.fixed_power_button) else {
            output::arguments(format_args!(
                "POWER host button: no fixed-feature power button\n"
            ));
            return false;
        };
        let pm1a = power.pm1[0].expect("a fixed button has PM1a");
        // SAFETY: the FADT's PM1a control block.
        let acpi = || unsafe { in16(pm1a.control) } & SCI_ENABLE != 0;
        if !acpi() {
            let Some((command, enable)) = power.acpi_enable else {
                output::arguments(format_args!(
                    "POWER host button: legacy mode with no SMI_CMD; the firmware keeps the button\n"
                ));
                return false;
            };
            // SAFETY: the FADT's SMI command port and its ACPI_ENABLE value.
            unsafe { out8(command, enable) };
            if !wait(self.tsc_hz, 1000, acpi) {
                output::arguments(format_args!(
                    "POWER host button: the firmware did not set SCI_EN; it keeps the button\n"
                ));
                return false;
            }
        }
        for block in power.blocks() {
            let enable = power.enable_port(block);
            // SAFETY: the FADT's PM1 event blocks; a status bit clears on one.
            unsafe {
                out16(block.event, POWER_BUTTON);
                out16(enable, in16(enable) | POWER_BUTTON);
            }
        }
        output::arguments(format_args!(
            "POWER host button: fixed-feature at PM1a_EVT {:#x}\n",
            pm1a.event
        ));
        true
    }

    /// A press of the host's power button since the last poll goes to the
    /// guest as a press and a release.
    pub fn poll(&mut self, devices: &mut AppleDevices) {
        let Some(power) = self.power.filter(|_| self.button) else {
            return;
        };
        let mut pressed = false;
        for block in power.blocks() {
            // SAFETY: the FADT's PM1 status registers.
            unsafe {
                if in16(block.event) & POWER_BUTTON != 0 {
                    out16(block.event, POWER_BUTTON);
                    pressed = true;
                }
            }
        }
        if !pressed {
            return;
        }
        output::arguments(format_args!("POWER host button pressed\n"));
        let result = devices
            .power_button(true)
            .and_then(|()| devices.power_button(false));
        if let Err(error) = result
            && !core::mem::replace(&mut self.refused, true)
        {
            output::arguments(format_args!("POWER host button refused: {error}\n"));
        }
    }

    /// Restart the host machine.
    pub fn restart(&self) -> ! {
        output::arguments(format_args!("STELA RESTART code={RESTART_CODE:#x}\n"));
        output::flush_log();
        output::debug_exit(RESTART_CODE);
        match self.power.and_then(|power| power.reset) {
            Some((register, value)) => {
                // SAFETY: the FADT's reset register; the machine resets.
                unsafe { write_reset(register, value) };
                wait(self.tsc_hz, 500, || false);
                output::arguments(format_args!(
                    "POWER the ACPI reset register did not reset the machine\n"
                ));
            }
            None => output::arguments(format_args!("POWER no ACPI reset register\n")),
        }
        // SAFETY: the 8042's command port, when one answers.
        unsafe {
            if in8(KEYBOARD_STATUS) != 0xff {
                wait(self.tsc_hz, 100, || {
                    in8(KEYBOARD_STATUS) & KEYBOARD_INPUT_FULL == 0
                });
                out8(KEYBOARD_STATUS, KEYBOARD_PULSE_RESET);
                wait(self.tsc_hz, 500, || false);
            }
        }
        output::arguments(format_args!("POWER restarting by triple fault\n"));
        output::flush_log();
        let empty = [0u16; 5];
        // SAFETY: an empty IDT makes the breakpoint a triple fault, which
        // resets the processor.
        unsafe {
            asm!("lidt [{}]", "int3", in(reg) &empty, options(noreturn));
        }
    }

    /// Power the host machine off.
    pub fn power_off(&self) -> ! {
        output::arguments(format_args!("STELA POWER-OFF code={POWER_OFF_CODE:#x}\n"));
        output::flush_log();
        output::debug_exit(POWER_OFF_CODE);
        let soft_off = self.power.and_then(|power| Some((power, power.soft_off?)));
        let Some((power, (a, b))) = soft_off else {
            output::fatal("the host has no ACPI S5 soft-off sequence to power off with")
        };
        for (block, sleep_type) in power.blocks().zip([a, b]) {
            // SAFETY: the FADT's PM1 control blocks; the machine powers off.
            unsafe {
                out16(
                    block.control,
                    power::sleep_control(in16(block.control), sleep_type),
                )
            };
        }
        wait(self.tsc_hz, 1000, || false);
        output::fatal("the host did not power off at S5; its firmware may need _PTS")
    }
}

/// # Safety
///
/// `register` is the FADT's reset register.
unsafe fn write_reset(register: ResetRegister, value: u8) {
    match register {
        // SAFETY: the caller's register.
        ResetRegister::Io(port) => unsafe { out8(port, value) },
        ResetRegister::PciConfiguration {
            device,
            function,
            offset,
        } => {
            let address = 1 << 31
                | u32::from(device) << 11
                | u32::from(function) << 8
                | u32::from(offset & 0xfc);
            let shift = u32::from(offset & 3) * 8;
            // SAFETY: configuration mechanism 1 on bus 0, the caller's
            // register; the other bytes of its dword are written back.
            unsafe {
                out32(PCI_ADDRESS, address);
                let dword = in32(PCI_DATA) & !(0xff << shift) | u32::from(value) << shift;
                out32(PCI_DATA, dword);
            }
        }
    }
}
