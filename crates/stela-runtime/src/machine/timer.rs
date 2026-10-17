//! The generic timers of Arm ARM DDI0487 D12: the EL1 physical and virtual
//! timers (CNTP, CNTV) and the EL2 physical and virtual timers (CNTHP,
//! CNTHV), whose CTL and CVAL registers live in the System register file. The
//! counter comes from the host. The EL1 virtual timer counts the physical
//! count minus CNTVOFF_EL2; the EL2 virtual timer counts without an offset,
//! because HCR_EL2.E2H is RES1. Apple cores signal the timers as FIQ, and
//! VM_TMR_FIQ_ENA_EL2 gates the EL1 timers (m1n1 `cpu_regs.h`).
use super::{
    cpu::{Cpu, VM_TIMER_FIQ_PHYSICAL, VM_TIMER_FIQ_VIRTUAL},
    system::Register,
};

pub const ENABLE: u64 = 1;
pub const IMASK: u64 = 2;
pub const ISTATUS: u64 = 4;

/// One timer channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Channel {
    pub control: Register,
    pub compare: Register,
    /// Counts the physical count minus CNTVOFF_EL2.
    pub offset: bool,
    /// The VM_TMR_FIQ_ENA_EL2 bit that lets it signal FIQ, if any.
    pub gate: Option<u64>,
}

pub const CHANNELS: [Channel; 4] = [
    Channel {
        control: Register::CNTP_CTL_EL0,
        compare: Register::CNTP_CVAL_EL0,
        offset: false,
        gate: Some(VM_TIMER_FIQ_PHYSICAL),
    },
    Channel {
        control: Register::CNTV_CTL_EL0,
        compare: Register::CNTV_CVAL_EL0,
        offset: true,
        gate: Some(VM_TIMER_FIQ_VIRTUAL),
    },
    Channel {
        control: Register::CNTHP_CTL_EL2,
        compare: Register::CNTHP_CVAL_EL2,
        offset: false,
        gate: None,
    },
    Channel {
        control: Register::CNTHV_CTL_EL2,
        compare: Register::CNTHV_CVAL_EL2,
        offset: false,
        gate: None,
    },
];

impl Channel {
    pub fn by_control(register: Register) -> Option<Self> {
        CHANNELS
            .into_iter()
            .find(|channel| channel.control == register)
    }

    fn count(&self, cpu: &Cpu, physical: u64) -> u64 {
        if self.offset {
            physical.wrapping_sub(cpu.read(Register::CNTVOFF_EL2))
        } else {
            physical
        }
    }

    /// The timer condition, independent of IMASK.
    pub fn met(&self, cpu: &Cpu, physical: u64) -> bool {
        cpu.read(self.control) & ENABLE != 0 && self.count(cpu, physical) >= cpu.read(self.compare)
    }

    /// CTL with ISTATUS.
    pub fn read_control(&self, cpu: &Cpu, physical: u64) -> u64 {
        (cpu.read(self.control) & !ISTATUS) | if self.met(cpu, physical) { ISTATUS } else { 0 }
    }

    /// The FIQ output: enabled, unmasked, met and not gated off.
    pub fn asserted(&self, cpu: &Cpu, physical: u64) -> bool {
        let gated = self
            .gate
            .is_some_and(|bit| cpu.apple.vm_timer_fiq & bit == 0);
        !gated && cpu.read(self.control) & IMASK == 0 && self.met(cpu, physical)
    }

    /// The physical count at which the output can assert.
    pub fn deadline(&self, cpu: &Cpu) -> Option<u64> {
        let gated = self
            .gate
            .is_some_and(|bit| cpu.apple.vm_timer_fiq & bit == 0);
        if gated || cpu.read(self.control) & (ENABLE | IMASK) != ENABLE {
            return None;
        }
        let compare = cpu.read(self.compare);
        Some(if self.offset {
            compare.wrapping_add(cpu.read(Register::CNTVOFF_EL2))
        } else {
            compare
        })
    }
}

/// Whether any timer signals FIQ.
pub fn asserted(cpu: &Cpu, physical: u64) -> bool {
    CHANNELS
        .iter()
        .any(|channel| channel.asserted(cpu, physical))
}

/// The earliest physical count at which a timer can signal FIQ.
pub fn deadline(cpu: &Cpu) -> Option<u64> {
    CHANNELS
        .iter()
        .filter_map(|channel| channel.deadline(cpu))
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::exception::Pstate;

    #[test]
    fn compare_offset_gating_and_status() {
        let mut cpu = Cpu::new(0, Pstate::reset(1));
        let virtual_timer = CHANNELS[1];
        cpu.registers.set(Register::CNTV_CVAL_EL0, 0, 1500);
        cpu.registers.set(Register::CNTVOFF_EL2, 0, 100);
        assert_eq!(deadline(&cpu), None);
        cpu.registers.set(Register::CNTV_CTL_EL0, 0, ENABLE);
        assert_eq!(deadline(&cpu), Some(1600));
        assert!(!asserted(&cpu, 1599) && asserted(&cpu, 1600));
        assert_eq!(virtual_timer.read_control(&cpu, 1600), ENABLE | ISTATUS);
        cpu.apple.vm_timer_fiq = 0;
        assert!(!asserted(&cpu, 1600) && deadline(&cpu).is_none());
        assert!(
            virtual_timer.met(&cpu, 1600),
            "the condition ignores the gate"
        );
        // The EL2 timers are never gated.
        cpu.registers.set(Register::CNTHP_CVAL_EL2, 0, 10);
        cpu.registers
            .set(Register::CNTHP_CTL_EL2, 0, ENABLE | IMASK);
        assert!(!asserted(&cpu, 20));
        cpu.registers.set(Register::CNTHP_CTL_EL2, 0, ENABLE);
        assert!(asserted(&cpu, 20));
    }
}
