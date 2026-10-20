//! The boot processor's local APIC: the xAPIC register page through the
//! address it is mapped at, or the x2APIC MSRs when the firmware left the
//! APIC in x2APIC mode (Intel SDM Vol. 3A chapter 11; AMD APM Vol. 2
//! chapter 16). Its timer is measured against the TSC.
use core::arch::asm;

const BASE_MSR: u32 = 0x1b;
/// IA32_APIC_BASE: x2APIC mode enabled.
const X2APIC_MODE: u64 = 1 << 10;
/// IA32_APIC_BASE: the register page's physical address.
pub const BASE_ADDRESS: u64 = 0x000f_ffff_ffff_f000;
/// The x2APIC MSR of xAPIC register offset `r` is `X2APIC_MSRS + r / 16`.
const X2APIC_MSRS: u32 = 0x800;

pub const EOI: u32 = 0xb0;
pub const SPURIOUS: u32 = 0xf0;
pub const LVT_TIMER: u32 = 0x320;
pub const LVT_LINT0: u32 = 0x350;
pub const INITIAL: u32 = 0x380;
pub const CURRENT: u32 = 0x390;
pub const DIVIDE: u32 = 0x3e0;
pub const LVT_MASKED: u32 = 1 << 16;
pub const TIMER_PERIODIC: u32 = 1 << 17;
const SOFTWARE_ENABLE: u32 = 1 << 8;
const DIVIDE_BY_ONE: u32 = 0b1011;
/// The calibration runs for 1/CALIBRATION_FRACTION of a second.
const CALIBRATION_FRACTION: u64 = 100;
const PIC_MASTER_DATA: u16 = 0x21;
const PIC_SLAVE_DATA: u16 = 0xa1;

pub fn rdtsc() -> u64 {
    let (low, high): (u32, u32);
    // SAFETY: RDTSC has no side effects.
    unsafe { asm!("rdtsc", out("eax") low, out("edx") high, options(nomem, nostack)) };
    (u64::from(high) << 32) | u64::from(low)
}

/// IA32_APIC_BASE, which every x86-64 CPU has.
pub fn base_msr() -> u64 {
    let (low, high): (u32, u32);
    // SAFETY: reading IA32_APIC_BASE has no side effects.
    unsafe {
        asm!("rdmsr", in("ecx") BASE_MSR, out("eax") low, out("edx") high,
            options(nomem, nostack, preserves_flags));
    }
    (u64::from(high) << 32) | u64::from(low)
}

pub struct Apic {
    x2: bool,
    /// Where the xAPIC register page is mapped, uncached.
    registers: u64,
}

impl Apic {
    /// The APIC that `base_msr` (IA32_APIC_BASE) describes, its xAPIC
    /// register page mapped at `registers`.
    pub fn new(base_msr: u64, registers: u64) -> Self {
        Self {
            x2: base_msr & X2APIC_MODE != 0,
            registers,
        }
    }

    pub fn read(&self, register: u32) -> u32 {
        if self.x2 {
            let (low, _high): (u32, u32);
            // SAFETY: an x2APIC MSR of this CPU.
            unsafe {
                asm!("rdmsr", in("ecx") X2APIC_MSRS + (register >> 4), out("eax") low,
                    out("edx") _high, options(nomem, nostack, preserves_flags));
            }
            low
        } else {
            // SAFETY: the caller mapped the xAPIC page at `registers`.
            unsafe { ((self.registers + u64::from(register)) as *const u32).read_volatile() }
        }
    }

    pub fn write(&self, register: u32, value: u32) {
        if self.x2 {
            // SAFETY: an x2APIC MSR of this CPU.
            unsafe {
                asm!("wrmsr", in("ecx") X2APIC_MSRS + (register >> 4), in("eax") value,
                    in("edx") 0, options(nostack, preserves_flags));
            }
        } else {
            // SAFETY: as in `read`.
            unsafe { ((self.registers + u64::from(register)) as *mut u32).write_volatile(value) };
        }
    }

    pub fn eoi(&self) {
        self.write(EOI, 0);
    }

    /// Mask the legacy PICs, enable the APIC with `spurious` as its
    /// spurious vector and LINT0 masked, and measure its timer against the
    /// TSC running at `tsc_hz`, with `timer` masked. Returns the timer's
    /// ticks per second at divide-by-one, the divider it is left at.
    pub fn start(&self, spurious: u8, timer: u8, tsc_hz: u64) -> u64 {
        // SAFETY: the legacy PIC data ports; masking every line.
        unsafe {
            asm!("out dx, al", in("dx") PIC_MASTER_DATA, in("al") 0xffu8, options(nomem, nostack));
            asm!("out dx, al", in("dx") PIC_SLAVE_DATA, in("al") 0xffu8, options(nomem, nostack));
        }
        self.write(SPURIOUS, SOFTWARE_ENABLE | u32::from(spurious));
        self.write(LVT_LINT0, LVT_MASKED);
        self.write(DIVIDE, DIVIDE_BY_ONE);
        self.write(LVT_TIMER, LVT_MASKED | u32::from(timer));
        self.write(INITIAL, u32::MAX);
        let start = rdtsc();
        let wait = tsc_hz / CALIBRATION_FRACTION;
        while rdtsc() - start < wait {
            core::hint::spin_loop();
        }
        let elapsed = u64::from(u32::MAX - self.read(CURRENT));
        let tsc = rdtsc() - start;
        self.write(INITIAL, 0);
        (u128::from(elapsed) * u128::from(tsc_hz) / u128::from(tsc.max(1))) as u64
    }
}
