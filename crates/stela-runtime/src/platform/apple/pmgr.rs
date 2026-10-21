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
//! actual state stays at the target. Other states remain explicit refusals.
//! The complete-consumer mount requires actual checked sinks for every admitted
//! consumer before lifecycle changes, including reset and DEV_DISABLE. Positive
//! unavailable admission evidence permits controller-state completion without
//! inventing a functional device. Uncovered domains retain named refusals. Parent
//! arbitration is not modeled; coverage includes their actual consumers.
pub mod coverage;
pub mod install;
pub mod sequencer;

use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use alloc::collections::{BTreeMap, BTreeSet};
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
    UnknownDomain(u64),
    AlreadyBound(u64),
    LifecycleRefused(u64),
}

/// State the machine must apply to every client of a physical PMGR domain.
/// Quiescing inhibits client activity without discarding retained state;
/// reset assertion restores the client's documented reset image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainState {
    pub power: u8,
    pub disabled: bool,
    pub reset: bool,
}

impl DomainState {
    fn decode(value: u32) -> Self {
        Self {
            power: ((value & ACTUAL) >> ACTUAL_SHIFT) as u8,
            disabled: value & DEV_DISABLE != 0,
            reset: value & RESET != 0,
        }
    }
}

/// One completed register request, ordered with respect to every other
/// lifecycle request. The machine consumes these before resuming clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainTransition {
    pub address: u64,
    pub before: DomainState,
    pub after: DomainState,
}

/// All power-state registers of one PMGR. Map each PMGR `reg` range on the
/// bus with `device_offset` equal to its guest PA, so offsets are PAs.
pub struct Pmgr {
    registers: BTreeMap<u64, u32>,
    lifecycle: BTreeSet<u64>,
    refused: BTreeSet<u64>,
    transitions: Vec<DomainTransition>,
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
        Ok(Self {
            registers,
            lifecycle: BTreeSet::new(),
            refused: BTreeSet::new(),
            transitions: Vec::new(),
        })
    }
    /// Enable controls after complete machine coverage: required clients have
    /// actual sinks, unavailable clients have positive admission evidence.
    /// Mapping or candidate ownership alone is insufficient. Binding preserves
    /// the boot image and grants no functional-device support.
    pub fn bind_lifecycle(&mut self, address: u64) -> Result<(), PmgrError> {
        if !self.registers.contains_key(&address) {
            return Err(PmgrError::UnknownDomain(address));
        }
        if self.refused.contains(&address) {
            return Err(PmgrError::LifecycleRefused(address));
        }
        if !self.lifecycle.insert(address) {
            return Err(PmgrError::AlreadyBound(address));
        }
        Ok(())
    }

    /// Keep a domain's lifecycle unchanged when complete consumer coverage
    /// cannot connect it. The machine retains the named resource reasons.
    /// Harmless configuration and W1C writes remain available.
    pub fn refuse_lifecycle(&mut self, address: u64) -> Result<(), PmgrError> {
        if !self.registers.contains_key(&address) {
            return Err(PmgrError::UnknownDomain(address));
        }
        if self.lifecycle.contains(&address) {
            return Err(PmgrError::AlreadyBound(address));
        }
        self.refused.insert(address);
        Ok(())
    }

    /// Pure request preview used to check every actual consumer before the
    /// machine commits this PMGR register. Read-only ACTUAL/PARENT_OFF bits
    /// in a guest RMW are not lifecycle inputs.
    pub fn preview(&self, address: u64, value: u32) -> Result<DomainTransition, &'static str> {
        self.prepare(address, value)
            .map(|(_, transition)| transition)
    }

    fn prepare(&self, address: u64, value: u32) -> Result<(u32, DomainTransition), &'static str> {
        let old = self
            .registers
            .get(&address)
            .copied()
            .ok_or("PMGR register is not a modeled power state")?;
        if self.refused.contains(&address)
            && value & (TARGET | DEV_DISABLE | RESET) != old & (TARGET | DEV_DISABLE | RESET)
        {
            return Err("PMGR lifecycle has required consumers without connected sinks");
        }
        let next = write_state(old, value, self.lifecycle.contains(&address))?;
        Ok((
            next,
            DomainTransition {
                address,
                before: DomainState::decode(old),
                after: DomainState::decode(next),
            },
        ))
    }

    /// Drain completed lifecycle requests in guest write order. No event is
    /// emitted for a rejected write or a write that leaves state unchanged.
    pub fn take_transitions(&mut self) -> Vec<DomainTransition> {
        core::mem::take(&mut self.transitions)
    }

    /// Completed power, reset and quiesce state of a described domain.
    pub fn domain_state(&self, address: u64) -> Option<DomainState> {
        self.registers
            .get(&address)
            .copied()
            .map(DomainState::decode)
    }

    /// Retained control word for diagnostics, without an MMIO read or effect.
    /// This reports the model's state, not proof of a firmware handoff value.
    pub fn control_word(&self, address: u64) -> Option<u32> {
        self.registers.get(&address).copied()
    }

    /// The completed hardware state of a described domain register.
    pub fn state(&self, address: u64) -> Option<u8> {
        self.registers
            .get(&address)
            .map(|value| ((value & ACTUAL) >> ACTUAL_SHIFT) as u8)
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

fn write_state(old: u32, value: u32, lifecycle: bool) -> Result<u32, &'static str> {
    if value & !KNOWN != 0 {
        return Err("PMGR power-state reserved field is not modeled");
    }
    if !lifecycle && value & RESET != 0 {
        return Err("PMGR device reset is not connected to the device models");
    }
    if !lifecycle && value & DEV_DISABLE != 0 {
        return Err("PMGR DEV_DISABLE quiescing is not connected to the device models");
    }
    let target = (value & TARGET) as u8;
    if value & RESET != 0
        && (target != ACTIVE
            || old & ACTUAL != u32::from(ACTIVE) << ACTUAL_SHIFT
            || value & DEV_DISABLE == 0)
    {
        return Err("PMGR reset requires an active, quiesced domain");
    }
    if old & RESET != 0 && target != ACTIVE {
        return Err("PMGR power change while reset is held is not modeled");
    }
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
    new |= value & (STORED | DEV_DISABLE | RESET) | flags;
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
        let (next, transition) = self.prepare(offset, value as u32).map_err(fail)?;
        *self
            .registers
            .get_mut(&offset)
            .expect("validated power register") = next;
        if transition.before != transition.after && self.lifecycle.contains(&offset) {
            self.transitions.push(transition);
        }
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

    #[test]
    fn request_preview_is_pure_and_matches_committed_target_not_guest_actual_bits() {
        let mut pmgr = pmgr();
        pmgr.bind_lifecycle(AIC).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let before = pmgr.read(AIC, Width::Word, &mut access).unwrap();
        let proposed = pmgr.preview(AIC, 0x3f0).unwrap();
        assert_eq!(proposed.before.power, ACTIVE);
        assert_eq!(proposed.after.power, POWER_GATED);
        assert_eq!(pmgr.read(AIC, Width::Word, &mut access), Ok(before));
        assert!(pmgr.take_transitions().is_empty());
        for value in [1, 0x8000000f, 0x80000400, 0x2000000f] {
            assert!(pmgr.preview(AIC, value).is_err());
            assert_eq!(pmgr.read(AIC, Width::Word, &mut access), Ok(before));
        }
        pmgr.write(AIC, Width::Word, 0x3f0, &mut access).unwrap();
        assert_eq!(pmgr.take_transitions(), [proposed]);
        assert_eq!(
            pmgr.read(AIC, Width::Word, &mut access),
            Ok(u64::from(WAS_PWRGATED))
        );
    }

    #[test]
    fn uncovered_lifecycle_refusals_preserve_registers_and_allow_only_configuration() {
        let mut pmgr = pmgr();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        pmgr.refuse_lifecycle(AIC).unwrap();
        assert_eq!(
            pmgr.bind_lifecycle(AIC),
            Err(PmgrError::LifecycleRefused(AIC))
        );
        assert_eq!(
            pmgr.refuse_lifecycle(AIC + 4),
            Err(PmgrError::UnknownDomain(AIC + 4))
        );
        for value in [0, 4, DEV_DISABLE | 15, RESET | DEV_DISABLE | 15] {
            assert!(
                pmgr.write(AIC, Width::Word, value.into(), &mut access)
                    .is_err()
            );
            assert_eq!(pmgr.read(AIC, Width::Word, &mut access), Ok(0xff));
            assert!(pmgr.take_transitions().is_empty());
        }
        pmgr.write(
            AIC,
            Width::Word,
            (AUTO_ENABLE | MIN_STATE | 15).into(),
            &mut access,
        )
        .unwrap();
        assert_eq!(
            pmgr.read(AIC, Width::Word, &mut access),
            Ok((AUTO_ENABLE | MIN_STATE | 0xff).into())
        );
        assert!(pmgr.take_transitions().is_empty());
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
    fn bound_domains_deliver_the_complete_reset_and_quiesce_sequence() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut pmgr = pmgr();
        pmgr.bind_lifecycle(AIC).unwrap();
        let active = DomainState {
            power: ACTIVE,
            disabled: false,
            reset: false,
        };
        let quiesced = DomainState {
            disabled: true,
            ..active
        };
        let reset = DomainState {
            reset: true,
            ..quiesced
        };
        assert_eq!(pmgr.domain_state(AIC), Some(active));
        assert!(pmgr.take_transitions().is_empty());
        // m1n1 pmgr_reset_device: four RMWs, each independently observable.
        for value in [
            0xff | DEV_DISABLE,
            0xff | DEV_DISABLE | RESET,
            0xff | DEV_DISABLE,
            0xff,
        ] {
            pmgr.write(AIC, Width::Word, value.into(), &mut access)
                .unwrap();
            assert_eq!(pmgr.read(AIC, Width::Word, &mut access), Ok(value.into()));
        }
        let expected = [
            (active, quiesced),
            (quiesced, reset),
            (reset, quiesced),
            (quiesced, active),
        ];
        assert_eq!(
            pmgr.take_transitions(),
            expected.map(|(before, after)| DomainTransition {
                address: AIC,
                before,
                after
            })
        );
        assert!(pmgr.take_transitions().is_empty());
        // State-neutral configuration writes never re-trigger a reset.
        pmgr.write(AIC, Width::Word, (AUTO_ENABLE | 0xff).into(), &mut access)
            .unwrap();
        assert!(pmgr.take_transitions().is_empty());
        assert_eq!(pmgr.domain_state(UART0).unwrap().power, POWER_GATED);
        assert!(
            pmgr.write(UART0, Width::Word, (DEV_DISABLE | 0xff).into(), &mut access)
                .is_err()
        );
    }

    #[test]
    fn lifecycle_events_cover_gate_transitions_and_rejected_writes_are_atomic() {
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut pmgr = pmgr();
        assert_eq!(
            pmgr.bind_lifecycle(AIC + 4),
            Err(PmgrError::UnknownDomain(AIC + 4))
        );
        pmgr.bind_lifecycle(AIC).unwrap();
        assert_eq!(pmgr.bind_lifecycle(AIC), Err(PmgrError::AlreadyBound(AIC)));
        for value in [RESET | 0xf, RESET | DEV_DISABLE | 4, DEV_DISABLE | 3] {
            assert!(
                pmgr.write(AIC, Width::Word, value.into(), &mut access)
                    .is_err()
            );
            assert_eq!(pmgr.read(AIC, Width::Word, &mut access), Ok(0xff));
            assert!(pmgr.take_transitions().is_empty());
        }
        for power in [CLOCK_GATED, POWER_GATED, ACTIVE] {
            let before = pmgr.domain_state(AIC).unwrap();
            pmgr.write(AIC, Width::Word, power.into(), &mut access)
                .unwrap();
            let after = DomainState { power, ..before };
            assert_eq!(
                pmgr.take_transitions(),
                [DomainTransition {
                    address: AIC,
                    before,
                    after
                }]
            );
        }
        pmgr.write(
            AIC,
            Width::Word,
            (RESET | DEV_DISABLE | 0xf).into(),
            &mut access,
        )
        .unwrap();
        let held = pmgr.read(AIC, Width::Word, &mut access).unwrap();
        pmgr.take_transitions();
        for value in [0, 4, RESET | DEV_DISABLE] {
            assert!(
                pmgr.write(AIC, Width::Word, value.into(), &mut access)
                    .is_err()
            );
            assert_eq!(pmgr.read(AIC, Width::Word, &mut access), Ok(held));
            assert!(pmgr.take_transitions().is_empty());
        }
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
