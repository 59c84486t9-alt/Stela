//! PMGR device power-state registers (`apple,t8112-pmgr-pwrstate`; ADT
//! `/arm-io/pmgr` `ps-regs` and `devices`).
//!
//! Documented by Linux `drivers/pmdomain/apple/pmgr-pwrstate.c`, m1n1
//! `src/pmgr.c` and `proxyclient/m1n1/hw/pmgr.py`: each 32-bit register holds
//! the target state [3:0] and the actual state [7:4] (0 power-gated, 4
//! clock-gated, 15 active), WAS_PWRGATED (8) and WAS_CLKGATED (9), which
//! writers mask off, DEV_DISABLE (10), PARENT_OFF (11), the minimum state
//! [19:16], the auto state [27:24], AUTO_ENABLE (28) and RESET (31). Drivers
//! write the target and poll until the actual state equals it.
//!
//! The model reflects every target into the actual state at the write, which
//! is the fastest permitted completion. Inferred, not documented: the WAS_*
//! bits are write-one-to-clear and latch when the actual state enters the
//! gated state; automatic power management never lowers a domain, so the
//! actual state stays at the target. Other states, device reset and
//! quiescing through DEV_DISABLE are refused until a model connects them to
//! the device models. Parent domains are not checked.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use alloc::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

const NAME: &str = "pmgr";

const TARGET: u32 = 0xf;
const ACTUAL_SHIFT: u32 = 4;
const ACTUAL: u32 = 0xf << ACTUAL_SHIFT;
const WAS_PWRGATED: u32 = 1 << 8;
const WAS_CLKGATED: u32 = 1 << 9;
const DEV_DISABLE: u32 = 1 << 10;
const PARENT_OFF: u32 = 1 << 11;
const MIN_STATE: u32 = 0xf << 16;
const AUTO_STATE: u32 = 0xf << 24;
const AUTO_ENABLE: u32 = 1 << 28;
const RESET: u32 = 1 << 31;
const STORED: u32 = MIN_STATE | AUTO_STATE | AUTO_ENABLE;
const KNOWN: u32 =
    TARGET | ACTUAL | WAS_PWRGATED | WAS_CLKGATED | DEV_DISABLE | PARENT_OFF | STORED | RESET;

pub const POWER_GATED: u8 = 0x0;
pub const CLOCK_GATED: u8 = 0x4;
pub const ACTIVE: u8 = 0xf;

/// One power-state register: its guest PA (ADT `reg[ps-regs[i].reg] +
/// ps-regs[i].offset + devices[j].addr_offset * 8`, or a Linux DT
/// `apple,pmgr-pwrstate` child `reg`) and the state the boot firmware left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowerState {
    pub address: u64,
    pub initial: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmgrError {
    UnknownState(u8),
    Misaligned(u64),
    Duplicate(u64),
}

/// All power-state registers of one PMGR. Map each PMGR `reg` range on the
/// bus with `device_offset` equal to its guest PA, so offsets are PAs.
pub struct Pmgr {
    registers: BTreeMap<u64, u32>,
}
impl Pmgr {
    pub fn new(states: impl IntoIterator<Item = PowerState>) -> Result<Self, PmgrError> {
        let mut registers = BTreeMap::new();
        for state in states {
            if state.address % 4 != 0 {
                return Err(PmgrError::Misaligned(state.address));
            }
            let value = encode(state.initial).ok_or(PmgrError::UnknownState(state.initial))?;
            if registers.insert(state.address, value).is_some() {
                return Err(PmgrError::Duplicate(state.address));
            }
        }
        Ok(Self { registers })
    }
    /// Addresses whose actual state is not active, for diagnostics.
    pub fn inactive(&self) -> Vec<u64> {
        self.registers
            .iter()
            .filter(|(_, value)| *value & ACTUAL != u32::from(ACTIVE) << ACTUAL_SHIFT)
            .map(|(address, _)| *address)
            .collect()
    }
}

fn encode(state: u8) -> Option<u32> {
    matches!(state, POWER_GATED | CLOCK_GATED | ACTIVE)
        .then(|| u32::from(state) | u32::from(state) << ACTUAL_SHIFT)
}

fn write_state(old: u32, value: u32) -> Result<u32, &'static str> {
    if value & !KNOWN != 0 {
        return Err("PMGR power-state reserved field is not modeled");
    }
    if value & RESET != 0 {
        return Err("PMGR device reset is not connected to the device models");
    }
    if value & DEV_DISABLE != 0 {
        return Err("PMGR DEV_DISABLE quiescing is not connected to the device models");
    }
    let target = (value & TARGET) as u8;
    let mut new =
        encode(target).ok_or("PMGR power states other than 0, 4 and 15 are not modeled")?;
    let old_actual = ((old & ACTUAL) >> ACTUAL_SHIFT) as u8;
    let mut flags = old & (WAS_PWRGATED | WAS_CLKGATED) & !value;
    if target != old_actual {
        flags |= match target {
            POWER_GATED => WAS_PWRGATED,
            CLOCK_GATED => WAS_CLKGATED,
            _ => 0,
        };
    }
    new |= value & STORED | flags;
    Ok(new)
}

impl MmioDevice for Pmgr {
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Read, reason);
        if width != Width::Word {
            return Err(fail("PMGR registers are 32-bit"));
        }
        let value = self
            .registers
            .get(&offset)
            .ok_or_else(|| fail("PMGR register is not a modeled power state"))?;
        Ok(u64::from(*value))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        if width != Width::Word {
            return Err(fail("PMGR registers are 32-bit"));
        }
        let register = self
            .registers
            .get_mut(&offset)
            .ok_or_else(|| fail("PMGR register is not a modeled power state"))?;
        *register = write_state(*register, value as u32).map_err(fail)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;

    /// `t8112.dtsi` pmgr base and `t8112-pmgr.dtsi` `ps_uart0` / `ps_aic`.
    const PMGR: u64 = 0x2_3b70_0000;
    const UART0: u64 = PMGR + 0x260;
    const AIC: u64 = PMGR + 0x108;

    fn pmgr() -> Pmgr {
        Pmgr::new([
            PowerState {
                address: UART0,
                initial: POWER_GATED,
            },
            PowerState {
                address: AIC,
                initial: ACTIVE,
            },
        ])
        .unwrap()
    }

    /// Linux `apple_pmgr_ps_set`: clear AUTO_ENABLE, the flags and the target,
    /// write the target, poll ACTUAL, then set AUTO_ENABLE.
    fn linux_set(
        pmgr: &mut Pmgr,
        access: &mut Access<'_>,
        address: u64,
        state: u8,
        auto_enable: bool,
    ) {
        let mut reg = pmgr.read(address, Width::Word, access).unwrap() as u32;
        reg &= !(AUTO_ENABLE | WAS_CLKGATED | WAS_PWRGATED | TARGET);
        reg |= u32::from(state);
        pmgr.write(address, Width::Word, reg.into(), access)
            .unwrap();
        let reg = pmgr.read(address, Width::Word, access).unwrap() as u32;
        assert_eq!(
            (reg & ACTUAL) >> ACTUAL_SHIFT,
            u32::from(state),
            "poll completes at once"
        );
        if auto_enable {
            let reg = reg & !(WAS_CLKGATED | WAS_PWRGATED) | AUTO_ENABLE;
            pmgr.write(address, Width::Word, reg.into(), access)
                .unwrap();
        }
    }

    #[test]
    fn linux_power_on_and_off_sequences() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut pmgr = pmgr();
        assert_eq!(pmgr.inactive(), vec![UART0]);
        linux_set(&mut pmgr, &mut access, UART0, ACTIVE, true);
        assert_eq!(
            pmgr.read(UART0, Width::Word, &mut access),
            Ok(u64::from(AUTO_ENABLE | 0xff))
        );
        assert!(pmgr.inactive().is_empty());
        linux_set(&mut pmgr, &mut access, UART0, POWER_GATED, false);
        let reg = pmgr.read(UART0, Width::Word, &mut access).unwrap() as u32;
        assert_eq!(reg, WAS_PWRGATED);
        pmgr.write(UART0, Width::Word, u64::from(WAS_PWRGATED), &mut access)
            .unwrap();
        assert_eq!(pmgr.read(UART0, Width::Word, &mut access), Ok(0));
    }

    /// m1n1 `pmgr_set_mode` clock-gates through a masked write.
    #[test]
    fn m1n1_clock_gate() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut pmgr = pmgr();
        let reg = pmgr.read(AIC, Width::Word, &mut access).unwrap() as u32;
        let reg =
            reg & !(AUTO_ENABLE | WAS_CLKGATED | WAS_PWRGATED | TARGET) | u32::from(CLOCK_GATED);
        pmgr.write(AIC, Width::Word, reg.into(), &mut access)
            .unwrap();
        assert_eq!(
            pmgr.read(AIC, Width::Word, &mut access),
            Ok(u64::from(WAS_CLKGATED | 0x44))
        );
    }

    #[test]
    fn refuses_unmodeled_registers_states_and_controls() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut pmgr = pmgr();
        assert!(pmgr.read(PMGR + 0x268, Width::Word, &mut access).is_err());
        assert!(
            pmgr.write(AIC, Width::Word, 0x3, &mut access).is_err(),
            "state 3"
        );
        assert!(
            pmgr.write(AIC, Width::Word, u64::from(RESET | 0xf), &mut access)
                .is_err()
        );
        assert!(
            pmgr.write(AIC, Width::Word, u64::from(DEV_DISABLE | 0xf), &mut access)
                .is_err()
        );
        assert!(
            pmgr.write(AIC, Width::Word, 1 << 12 | 0xf, &mut access)
                .is_err()
        );
        assert!(pmgr.read(AIC, Width::Double, &mut access).is_err());
        assert_eq!(
            pmgr.read(AIC, Width::Word, &mut access),
            Ok(0xff),
            "refusals left no effect"
        );
        assert_eq!(
            Pmgr::new([PowerState {
                address: AIC,
                initial: 2
            }])
            .err(),
            Some(PmgrError::UnknownState(2))
        );
    }
}
