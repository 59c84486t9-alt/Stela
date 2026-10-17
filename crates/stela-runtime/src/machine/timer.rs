//! The generic timers of Arm ARM DDI0487 D12: the EL1 physical and virtual
//! timers (CNTP, CNTV) and the EL2 physical and virtual timers (CNTHP,
//! CNTHV), whose CTL and CVAL registers live in the System register file. The
//! counter comes from the host. The EL1 virtual timer counts the physical
//! count minus CNTVOFF_EL2; the EL2 virtual timer counts without an offset,
//! because HCR_EL2.E2H is RES1. Apple cores signal the timers as FIQ, and
//! VM_TMR_FIQ_ENA_EL2 gates the EL1 timers (m1n1 `cpu_regs.h`). The event
//! streams of CNTHCTL_EL2 and CNTKCTL_EL1 set the event register.
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

/// CNTKCTL_EL1 and CNTHCTL_EL2 share the event stream fields.
const EVNTEN: u64 = 1 << 2;
const EVNTDIR: u64 = 1 << 3;
const EVNTI_SHIFT: u32 = 4;
const EVNTIS: u64 = 1 << 17;
const HCR_TGE: u64 = 1 << 27;
const HCR_E2H: u64 = 1 << 34;

/// One generic timer event stream (Arm `TestEventCNTP`, `TestEventCNTV`): an
/// event each time the selected bit of the count minus `offset` rises, or
/// falls under EVNTDIR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stream {
    offset: u64,
    bit: u32,
    falling: bool,
}

impl Stream {
    fn from_control(control: u64, offset: u64) -> Option<Self> {
        if control & EVNTEN == 0 {
            return None;
        }
        // FEAT_ECV's EVNTIS selects bits 8 to 23.
        let scale = if control & EVNTIS != 0 { 8 } else { 0 };
        Some(Self {
            offset,
            bit: (control >> EVNTI_SHIFT) as u32 % 16 + scale,
            falling: control & EVNTDIR != 0,
        })
    }

    fn period(&self) -> u64 {
        1 << (self.bit + 1)
    }

    /// How far the counter at physical count `count` is past this stream's
    /// last edge, within one period.
    fn phase(&self, count: u64) -> u64 {
        let edge = if self.falling { 0 } else { 1 << self.bit };
        count.wrapping_sub(self.offset).wrapping_sub(edge) & (self.period() - 1)
    }

    /// Whether an edge falls in the physical counts (previous, current].
    pub fn signals(&self, previous: u64, current: u64) -> bool {
        current > previous && current - previous >= self.period() - self.phase(previous)
    }

    /// The first physical count after `now` with an edge.
    pub fn next(&self, now: u64) -> u64 {
        now.saturating_add(self.period() - self.phase(now))
    }
}

/// The enabled event streams: CNTHCTL_EL2's on the physical count, and
/// CNTKCTL_EL1's on the virtual count unless HCR_EL2.{E2H,TGE} is {1,1}.
pub fn streams(cpu: &Cpu) -> impl Iterator<Item = Stream> {
    let hcr = cpu.read(Register::CNTHCTL_EL2);
    let physical = Stream::from_control(hcr, 0);
    let host = cpu.read(Register::HCR_EL2) & (HCR_E2H | HCR_TGE) == HCR_E2H | HCR_TGE;
    let virtual_stream = (!host)
        .then(|| {
            Stream::from_control(
                cpu.read(Register::CNTKCTL_EL1),
                cpu.read(Register::CNTVOFF_EL2),
            )
        })
        .flatten();
    physical.into_iter().chain(virtual_stream)
}

/// Whether an enabled event stream signals in the physical counts
/// (previous, current] (Arm `GenericCounterTick`).
pub fn event(cpu: &Cpu, previous: u64, current: u64) -> bool {
    streams(cpu).any(|stream| stream.signals(previous, current))
}

/// The first physical count after `now` at which an event stream signals.
pub fn next_event(cpu: &Cpu, now: u64) -> Option<u64> {
    streams(cpu).map(|stream| stream.next(now)).min()
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

    #[test]
    fn event_streams_signal_on_the_selected_edge() {
        let mut cpu = Cpu::new(0, Pstate::reset(2));
        cpu.registers.set(Register::HCR_EL2, 0, HCR_E2H | HCR_TGE);
        assert_eq!(next_event(&cpu, 0), None);
        // CNTHCTL_EL2: bit 2 rising, at counts 4, 12, 20, ...
        cpu.registers
            .set(Register::CNTHCTL_EL2, 0, EVNTEN | 2 << EVNTI_SHIFT);
        assert!(!event(&cpu, 0, 3) && event(&cpu, 3, 4) && !event(&cpu, 4, 11));
        assert!(event(&cpu, 4, 12) && event(&cpu, 0, 100) && !event(&cpu, 5, 5));
        assert_eq!(
            (next_event(&cpu, 0), next_event(&cpu, 4)),
            (Some(4), Some(12))
        );
        // Falling: at counts 8, 16, ...
        cpu.registers.set(
            Register::CNTHCTL_EL2,
            0,
            EVNTEN | EVNTDIR | 2 << EVNTI_SHIFT,
        );
        assert!(!event(&cpu, 0, 7) && event(&cpu, 7, 8));
        assert_eq!(next_event(&cpu, 8), Some(16));
        // EVNTIS (FEAT_ECV) adds 8 to EVNTI; without it (the M1) the bit is
        // RES0 and EVNTI 0 signals every count.
        cpu.registers.set(Register::CNTHCTL_EL2, 0, EVNTEN | EVNTIS);
        let ecv = crate::machine::system::Feature::FEAT_ECV.on(cpu.registers.chip());
        assert_eq!(next_event(&cpu, 0), Some(if ecv { 256 } else { 1 }));
        // The EL1 stream counts the virtual count and only outside the host.
        cpu.registers.set(Register::CNTHCTL_EL2, 0, 0);
        cpu.registers.set(Register::CNTVOFF_EL2, 0, 1);
        cpu.registers
            .set(Register::CNTKCTL_EL1, 0, EVNTEN | 2 << EVNTI_SHIFT);
        assert_eq!(next_event(&cpu, 0), None);
        cpu.registers.set(Register::HCR_EL2, 0, HCR_E2H);
        assert!(!event(&cpu, 0, 4) && event(&cpu, 4, 5));
        assert_eq!(next_event(&cpu, 5), Some(13));
    }
}
