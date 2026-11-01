//! The boot processor's local APIC: the xAPIC register page through the
//! address it is mapped at, or the x2APIC MSRs when the firmware left the
//! APIC in x2APIC mode (Intel SDM Vol. 3A chapter 11; AMD APM Vol. 2
//! chapter 16). Its timer is measured against the TSC.
use crate::msr;
use core::arch::asm;

/// IA32_APIC_BASE: x2APIC mode enabled.
const X2APIC_MODE: u64 = 1 << 10;
/// IA32_APIC_BASE: the register page's physical address.
pub const BASE_ADDRESS: u64 = 0x000f_ffff_ffff_f000;

pub const EOI: u32 = 0xb0;
pub const SPURIOUS: u32 = 0xf0;
pub const LVT_TIMER: u32 = 0x320;
pub const LVT_LINT0: u32 = 0x350;
pub const INITIAL: u32 = 0x380;
pub const CURRENT: u32 = 0x390;
pub const DIVIDE: u32 = 0x3e0;
const ID: u32 = 0x20;
const ICR_LOW: u32 = 0x300;
const ICR_HIGH: u32 = 0x310;
const ICR_PENDING: u32 = 1 << 12;
const ICR_LEVEL_ASSERT: u32 = 1 << 14;
const ICR_INIT: u32 = 5 << 8;
const ICR_STARTUP: u32 = 6 << 8;
/// The INIT settling and STARTUP acceptance delays of the MP specification,
/// for processors that need them.
const INIT_WAIT_US: u64 = 10_000;
const SIPI_WAIT_US: u64 = 200;
/// The STARTUP acceptance delay where no INIT settling is needed.
const MODERN_SIPI_WAIT_US: u64 = 10;
const DELIVERY_WAIT_US: u64 = 10_000;
const MICROSECONDS_PER_SECOND: u64 = 1_000_000;

/// Whether this processor's family settles INIT at once, as Linux's
/// `smp_quirk_init_udelay` finds it (Intel family 6 on, AMD 0Fh on, Hygon
/// 18h on): its INIT then takes no delay and STARTUP 10 us.
fn settles_at_once() -> bool {
    use core::arch::x86_64::__cpuid;
    let vendor = __cpuid(0);
    let signature = __cpuid(1).eax;
    let base = signature >> 8 & 0xf;
    let family = if base == 0xf {
        base + (signature >> 20 & 0xff)
    } else {
        base
    };
    match (vendor.ebx, vendor.edx, vendor.ecx) {
        // "GenuineIntel", "AuthenticAMD", "HygonGenuine".
        (0x756e_6547, 0x4965_6e69, 0x6c65_746e) => family >= 6,
        (0x6874_7541, 0x6974_6e65, 0x444d_4163) => family >= 0xf,
        (0x6f67_7948, 0x6e65_476e, 0x656e_6975) => family >= 0x18,
        _ => false,
    }
}

fn init_destination(destination: u32, bsp: u32, x2: bool, tsc_hz: u64) -> Result<(), StartupError> {
    if tsc_hz == 0
        || tsc_hz
            .div_ceil(MICROSECONDS_PER_SECOND)
            .checked_mul(INIT_WAIT_US)
            .is_none()
    {
        return Err(StartupError::ClockUnavailable);
    }
    if destination == bsp {
        return Err(StartupError::BootstrapDestination);
    }
    if !x2 && destination > u32::from(u8::MAX) {
        return Err(StartupError::DestinationTooWide);
    }
    // Physical destination all-ones is broadcast, never one owned logical AP.
    if destination == if x2 { u32::MAX } else { u32::from(u8::MAX) } {
        return Err(StartupError::BroadcastDestination);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupError {
    ClockUnavailable,
    DestinationTooWide,
    BootstrapDestination,
    BroadcastDestination,
    InvalidVector,
    DeliveryTimeout,
}
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
    // SAFETY: reading IA32_APIC_BASE has no side effects.
    unsafe { msr::APIC_BASE.read() }
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

    pub fn is_x2apic(&self) -> bool {
        self.x2
    }

    pub fn read(&self, register: u32) -> u32 {
        if self.x2 {
            // SAFETY: an x2APIC MSR of this CPU; register `r` of the xAPIC
            // page is MSR 800h + r / 16.
            unsafe { msr::X2APIC.at(register >> 4).read() as u32 }
        } else {
            // SAFETY: the caller mapped the xAPIC page at `registers`.
            unsafe { ((self.registers + u64::from(register)) as *const u32).read_volatile() }
        }
    }

    pub fn write(&self, register: u32, value: u32) {
        if self.x2 {
            // SAFETY: an x2APIC MSR of this CPU.
            unsafe { msr::X2APIC.at(register >> 4).write(u64::from(value)) }
        } else {
            // SAFETY: as in `read`.
            unsafe { ((self.registers + u64::from(register)) as *mut u32).write_volatile(value) };
        }
    }

    pub fn eoi(&self) {
        self.write(EOI, 0);
    }

    pub fn id(&self) -> u32 {
        let value = self.read(ID);
        if self.x2 { value } else { value >> 24 }
    }

    fn wait_delivery(&self, tsc_hz: u64) -> Result<(), StartupError> {
        let started = rdtsc();
        let limit = tsc_hz
            .div_ceil(MICROSECONDS_PER_SECOND)
            .checked_mul(DELIVERY_WAIT_US)
            .filter(|ticks| *ticks != 0)
            .ok_or(StartupError::ClockUnavailable)?;
        while self.read(ICR_LOW) & ICR_PENDING != 0 {
            if rdtsc().wrapping_sub(started) >= limit {
                return Err(StartupError::DeliveryTimeout);
            }
            core::hint::spin_loop();
        }
        Ok(())
    }

    fn send(&self, destination: u32, command: u32, tsc_hz: u64) -> Result<(), StartupError> {
        self.wait_delivery(tsc_hz)?;
        self.command(destination, command)?;
        self.wait_delivery(tsc_hz)
    }

    /// Write the ICR, which the last command left idle.
    fn command(&self, destination: u32, command: u32) -> Result<(), StartupError> {
        if self.x2 {
            // SAFETY: the local x2APIC ICR, with a physical destination and
            // an explicitly constructed command. A WRMSR to an x2APIC
            // register is not serializing, so without the fences the IPI
            // could reach its destination before the stores announcing its
            // work: Linux's `weak_wrmsr_fence` before `x2apic_send_IPI`.
            unsafe {
                msr::write_fenced(
                    msr::X2APIC.at(ICR_LOW >> 4),
                    u64::from(destination) << 32 | u64::from(command),
                );
            }
        } else {
            let destination =
                u8::try_from(destination).map_err(|_| StartupError::DestinationTooWide)?;
            self.write(ICR_HIGH, u32::from(destination) << 24);
            self.write(ICR_LOW, command);
        }
        Ok(())
    }

    pub fn validate_init(&self, destination: u32, tsc_hz: u64) -> Result<(), StartupError> {
        init_destination(destination, self.id(), self.x2, tsc_hz)
    }

    fn wait_microseconds(&self, microseconds: u64, tsc_hz: u64) {
        let started = rdtsc();
        // INIT destination validation bounds this multiplication; SIPI's wait
        // is smaller. No firmware timer or callback survives into this path.
        let ticks = tsc_hz.div_ceil(MICROSECONDS_PER_SECOND) * microseconds;
        while rdtsc().wrapping_sub(started) < ticks {
            core::hint::spin_loop();
        }
    }

    /// Directed INIT without SIPI. Intel SDM3A, "Local APIC State After an
    /// INIT Reset (Wait-for-SIPI State)": an AP receiving INIT initializes and
    /// waits for startup. No firmware idle loop or private AP stack is needed.
    /// ICR completion plus the architectural 10 ms settling interval, where
    /// the family needs it, reports delivery only, not an independently
    /// observed destination acknowledgement.
    ///
    /// # Safety
    /// Post-EBS BSP, exclusive local ICR with IF clear; the caller owns this
    /// validated enabled logical AP. Firmware code must not resume afterward;
    /// any later SIPI belongs to a separate complete owned startup sequence.
    pub unsafe fn init_only(&self, destination: u32, tsc_hz: u64) -> Result<(), StartupError> {
        self.validate_init(destination, tsc_hz)?;
        self.send(destination, ICR_INIT | ICR_LEVEL_ASSERT, tsc_hz)?;
        if !settles_at_once() {
            self.wait_microseconds(INIT_WAIT_US, tsc_hz);
        }
        Ok(())
    }

    /// Start one enabled AP at its owned SIPI page after ExitBootServices.
    /// Intel SDM Vol. 3A, multiprocessor initialization: directed INIT,
    /// 10 ms, STARTUP, 200 us, second STARTUP for integrated local APICs;
    /// no INIT delay and 10 us where the family settles at once.
    /// This reports delivery only; the caller must separately verify the AP's
    /// identity, entry acknowledgement and stopped/executor lifetime.
    ///
    /// # Safety
    /// The caller owns the destination processor after firmware shutdown. Its
    /// complete trampoline, tables, stack and argument stay pinned and visible;
    /// interrupts are disabled and no other ICR sender runs on this processor.
    pub unsafe fn startup(
        &self,
        destination: u32,
        vector: u8,
        tsc_hz: u64,
    ) -> Result<(), StartupError> {
        self.validate_init(destination, tsc_hz)?;
        if vector == 0 {
            return Err(StartupError::InvalidVector);
        }
        let (init_us, sipi_us) = if settles_at_once() {
            (0, MODERN_SIPI_WAIT_US)
        } else {
            (INIT_WAIT_US, SIPI_WAIT_US)
        };
        self.send(destination, ICR_INIT | ICR_LEVEL_ASSERT, tsc_hz)?;
        self.wait_microseconds(init_us, tsc_hz);
        self.send(destination, ICR_STARTUP | u32::from(vector), tsc_hz)?;
        self.wait_microseconds(sipi_us, tsc_hz);
        self.send(destination, ICR_STARTUP | u32::from(vector), tsc_hz)
    }

    /// Send one fixed physical doorbell, without waiting to see it delivered:
    /// each ICR access traps to a VMM, and the next command's wait finds an
    /// undelivered one. This acknowledges ICR acceptance only, never a
    /// returned native frame, stopped generation or controller effect.
    ///
    /// # Safety
    /// The destination owns this reserved vector and a live private IDT/IST.
    /// The caller exclusively owns the local ICR with interrupts disabled.
    pub unsafe fn notify(
        &self,
        destination: u32,
        vector: u8,
        tsc_hz: u64,
    ) -> Result<(), StartupError> {
        if vector < 32 || vector == u8::MAX {
            return Err(StartupError::InvalidVector);
        }
        self.wait_delivery(tsc_hz)?;
        self.command(destination, u32::from(vector))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directed_init_excludes_bsp_and_broadcast_for_both_apic_modes() {
        for x2 in [false, true] {
            for bsp in [0, 7, 254] {
                assert_eq!(
                    init_destination(bsp, bsp, x2, 4_700_000_000),
                    Err(StartupError::BootstrapDestination)
                );
            }
            assert_eq!(init_destination(0, 7, x2, 1), Ok(()));
            assert_eq!(init_destination(254, 7, x2, 4_700_000_000), Ok(()));
            assert_eq!(
                init_destination(if x2 { u32::MAX } else { 255 }, 7, x2, 1),
                Err(StartupError::BroadcastDestination)
            );
            assert_eq!(
                init_destination(3, 7, x2, 0),
                Err(StartupError::ClockUnavailable)
            );
        }
        assert_eq!(
            init_destination(256, 7, false, 1),
            Err(StartupError::DestinationTooWide)
        );
        assert_eq!(init_destination(256, 7, true, 1), Ok(()));
        assert_eq!(init_destination(255, 7, true, 1), Ok(()));
        assert_eq!(init_destination(u32::MAX - 1, 7, true, 1), Ok(()));
    }
}
