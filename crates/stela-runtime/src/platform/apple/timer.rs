//! The ARM generic timer as an Apple silicon guest at EL1 sees it: the
//! backend for `crate::system::timer`, which decides traps and offsets and
//! returns a [`BackendRequest`].
//!
//! Architectural behavior follows the Arm ARM generic timer chapter: the
//! condition of a timer is `count - offset >= CVAL` as unsigned 64-bit values,
//! TVAL is the signed 32-bit distance to CVAL, and the interrupt is asserted
//! while ENABLE is set, IMASK is clear and the condition holds. On Apple
//! silicon `CNTFRQ_EL0` is 24 MHz and the EL1 physical and virtual timers are
//! FIQs, not AIC inputs (Linux `irq-apple-aic.c`, `aic_handle_fiq` tests
//! `CNTP_CTL_EL0` and `CNTV_CTL_EL0` directly; `t8112.dtsi` `timer` node).
//!
//! Choices where the architecture leaves values open: a disabled TVAL reads
//! the enabled formula, and a disabled CTL reads ISTATUS as 0. Only the EL1
//! physical and virtual banks exist; EL2 banks and the FEAT_ECV physical
//! offset are refused.
//!
//! The J473AP kernel also reads Apple's `CNTVCT_ALIAS_EL0` (S3_4_C15_C10_6,
//! m1n1 `cpu_regs.h`), which XNU `osfmk/arm64/machine_routines.c` names the
//! non-speculative virtual count (`KERNEL_CNTVCTSS_EL0`; "S3_4_C15_C10_6 and
//! ACNTVCT_EL0 have identical encodings"). It reads the virtual count; the
//! CNTKCTL_EL1.EL0VCTEN gate at EL0 is inferred from CNTVCT_EL0.
use super::counter::FREQUENCY_HZ;
use super::interrupt::{CpuIndex, FiqSource, InterruptSink, Wire};
use crate::system::access::{AccessKind, Encoding, ExceptionLevel};
use crate::system::timer::{
    BackendRequest, CounterOffset, TIMER_WRITABLE_MASK, TimerBank, TimerField, TimerKind,
    compare_from_timer_value, control_value, interrupt_asserted, timer_value,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// CNTKCTL_EL1 EL0PCTEN, EL0VCTEN, EVNTEN, EVNTDIR, EVNTI, EL0VTEN, EL0PTEN.
const KERNEL_CONTROL_FIELDS: u64 = 0x3ff;
const KERNEL_CONTROL_EVENT_ENABLE: u64 = 1 << 2;
const KERNEL_CONTROL_EVENT_DIRECTION: u64 = 1 << 3;
const KERNEL_CONTROL_EVENT_BIT_SHIFT: u32 = 4;
/// CNTKCTL_EL1.EVNTIS (FEAT_ECV).
const KERNEL_CONTROL_EVENT_SCALE: u64 = 1 << 17;
const KERNEL_CONTROL_EL0_VIRTUAL_COUNT: u64 = 1 << 1;

/// Apple `CNTVCT_ALIAS_EL0`, read-only.
pub const VIRTUAL_COUNT_ALIAS: Encoding = Encoding::new(3, 4, 15, 10, 6);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerError {
    UnknownCpu(CpuIndex),
    /// The access traps to EL1 as a system-register access.
    TrapToEl1,
    Unsupported(&'static str),
}

#[derive(Debug, Clone, Copy, Default)]
struct Timer {
    control: u64,
    compare: u64,
    asserted: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct CpuTimers {
    kernel_control: u64,
    physical: Timer,
    virtual_timer: Timer,
}

/// Per-CPU generic timers driven by the system counter value `now`.
pub struct GenericTimer {
    cpus: Vec<CpuTimers>,
    /// CNTVOFF_EL2 as the absent hypervisor leaves it.
    virtual_offset: u64,
}
impl GenericTimer {
    pub fn new(cpus: usize, virtual_offset: u64) -> Self {
        Self {
            cpus: vec![CpuTimers::default(); cpus],
            virtual_offset,
        }
    }
    /// Performs one access resolved by `system::timer::resolve`. Returns the
    /// value read, or 0 for a write.
    pub fn access(
        &mut self,
        cpu: CpuIndex,
        request: BackendRequest,
        now: u64,
        interrupts: &mut dyn InterruptSink,
    ) -> Result<u64, TimerError> {
        let unsupported = |reason| Err(TimerError::Unsupported(reason));
        let virtual_offset = self.virtual_offset;
        let timers = self.cpus.get_mut(cpu).ok_or(TimerError::UnknownCpu(cpu))?;
        let value = match request {
            BackendRequest::Frequency(AccessKind::Read) => FREQUENCY_HZ,
            BackendRequest::Frequency(AccessKind::Write { .. }) => {
                return unsupported("CNTFRQ_EL0 is fixed at 24 MHz on Apple silicon");
            }
            BackendRequest::KernelControl(AccessKind::Read) => timers.kernel_control,
            BackendRequest::KernelControl(AccessKind::Write { value }) => {
                if value & KERNEL_CONTROL_EVENT_SCALE != 0 {
                    return unsupported(
                        "CNTKCTL_EL1.EVNTIS requires FEAT_ECV, which this profile omits",
                    );
                }
                timers.kernel_control = value & KERNEL_CONTROL_FIELDS;
                0
            }
            BackendRequest::Counter { kind, offset, .. } => {
                let offset = counter_offset(kind, offset, virtual_offset)?;
                now.wrapping_sub(offset)
            }
            BackendRequest::Timer {
                bank,
                field,
                access,
                offset,
            } => {
                let (kind, timer) = match bank {
                    TimerBank::PhysicalEl1 => (TimerKind::Physical, &mut timers.physical),
                    TimerBank::VirtualEl1 => (TimerKind::Virtual, &mut timers.virtual_timer),
                    _ => return unsupported("EL2 timer banks are not modeled at EL1"),
                };
                let offset = counter_offset(kind, offset, virtual_offset)?;
                let condition = now.wrapping_sub(offset) >= timer.compare;
                match (field, access) {
                    (TimerField::Control, AccessKind::Read) => {
                        control_value(timer.control, condition).0
                    }
                    (TimerField::Control, AccessKind::Write { value }) => {
                        timer.control = value & TIMER_WRITABLE_MASK;
                        0
                    }
                    (TimerField::CompareValue, AccessKind::Read) => timer.compare,
                    (TimerField::CompareValue, AccessKind::Write { value }) => {
                        timer.compare = value;
                        0
                    }
                    // Read as if enabled: any value is permitted while disabled.
                    (TimerField::TimerValue, AccessKind::Read) => {
                        timer_value(timer.compare, now, offset, true).expect("enabled timer value")
                    }
                    (TimerField::TimerValue, AccessKind::Write { value }) => {
                        timer.compare = compare_from_timer_value(value, now, offset);
                        0
                    }
                }
            }
            BackendRequest::NestedMemory { .. } => {
                return unsupported("FEAT_NV2 timer redirection is not modeled");
            }
        };
        self.update(cpu, now, interrupts);
        Ok(value)
    }
    /// An MRS of [`VIRTUAL_COUNT_ALIAS`] at `el`. The profile has no EL2, so
    /// no hypervisor trap or offset control applies.
    pub fn read_virtual_count_alias(
        &self,
        cpu: CpuIndex,
        el: ExceptionLevel,
        now: u64,
    ) -> Result<u64, TimerError> {
        let timers = self.cpus.get(cpu).ok_or(TimerError::UnknownCpu(cpu))?;
        match el {
            ExceptionLevel::El0
                if timers.kernel_control & KERNEL_CONTROL_EL0_VIRTUAL_COUNT == 0 =>
            {
                Err(TimerError::TrapToEl1)
            }
            ExceptionLevel::El0 | ExceptionLevel::El1 => Ok(now.wrapping_sub(self.virtual_offset)),
            ExceptionLevel::El2 | ExceptionLevel::El3 => Err(TimerError::Unsupported(
                "CNTVCT_ALIAS_EL0 above EL1 is not modeled",
            )),
        }
    }
    /// Re-evaluates every timer at `now`; returns the next counter value at
    /// which an enabled, unmasked timer starts firing.
    pub fn advance(&mut self, now: u64, interrupts: &mut dyn InterruptSink) -> Option<u64> {
        let mut next: Option<u64> = None;
        for cpu in 0..self.cpus.len() {
            self.update(cpu, now, interrupts);
            let timers = &self.cpus[cpu];
            for (timer, offset) in [
                (timers.physical, 0),
                (timers.virtual_timer, self.virtual_offset),
            ] {
                let armed = interrupt_asserted(timer.control, true);
                if armed
                    && !timer.asserted
                    && let Some(deadline) = timer.compare.checked_add(offset)
                {
                    next = Some(next.map_or(deadline, |next| next.min(deadline)));
                }
            }
        }
        next
    }
    /// The next physical count after `now` at which this CPU's CNTKCTL_EL1
    /// event stream signals an event (a transition of the selected bit of the
    /// virtual count), for waking WFE.
    pub fn next_event(&self, cpu: CpuIndex, now: u64) -> Option<u64> {
        let control = self.cpus.get(cpu)?.kernel_control;
        if control & KERNEL_CONTROL_EVENT_ENABLE == 0 {
            return None;
        }
        let bit = (control >> KERNEL_CONTROL_EVENT_BIT_SHIFT & 0xf) as u32;
        let period = 1u64 << (bit + 1);
        let target: u64 = if control & KERNEL_CONTROL_EVENT_DIRECTION == 0 {
            1 << bit
        } else {
            0
        };
        let count = now.wrapping_sub(self.virtual_offset);
        let distance = match target.wrapping_sub(count) % period {
            0 => period,
            distance => distance,
        };
        now.checked_add(distance)
    }
    fn update(&mut self, cpu: CpuIndex, now: u64, interrupts: &mut dyn InterruptSink) {
        let virtual_offset = self.virtual_offset;
        let timers = &mut self.cpus[cpu];
        for (timer, offset, source) in [
            (&mut timers.physical, 0, FiqSource::PhysicalTimer),
            (
                &mut timers.virtual_timer,
                virtual_offset,
                FiqSource::VirtualTimer,
            ),
        ] {
            let level =
                interrupt_asserted(timer.control, now.wrapping_sub(offset) >= timer.compare);
            if level != timer.asserted {
                timer.asserted = level;
                interrupts.set_level(Wire::Fiq(cpu, source), level);
            }
        }
    }
}

fn counter_offset(
    kind: TimerKind,
    offset: CounterOffset,
    virtual_offset: u64,
) -> Result<u64, TimerError> {
    match (kind, offset) {
        (TimerKind::Physical, CounterOffset::None) => Ok(0),
        (TimerKind::Virtual, CounterOffset::VirtualEl2) => Ok(virtual_offset),
        (TimerKind::Virtual, CounterOffset::None) if virtual_offset == 0 => Ok(0),
        (TimerKind::Virtual, CounterOffset::None) => Err(TimerError::Unsupported(
            "virtual count without CNTVOFF contradicts the configured virtual offset",
        )),
        _ => Err(TimerError::Unsupported(
            "the FEAT_ECV physical offset is not modeled",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;
    use crate::system::timer::{CounterOrdering, TIMER_ENABLE, TIMER_IMASK, TIMER_ISTATUS};

    fn timer_request(kind: TimerKind, field: TimerField, access: AccessKind) -> BackendRequest {
        BackendRequest::Timer {
            bank: match kind {
                TimerKind::Physical => TimerBank::PhysicalEl1,
                TimerKind::Virtual => TimerBank::VirtualEl1,
            },
            field,
            access,
            offset: match kind {
                TimerKind::Physical => CounterOffset::None,
                TimerKind::Virtual => CounterOffset::VirtualEl2,
            },
        }
    }
    fn write(
        timer: &mut GenericTimer,
        latch: &mut InterruptLatch,
        kind: TimerKind,
        field: TimerField,
        value: u64,
        now: u64,
    ) {
        timer
            .access(
                0,
                timer_request(kind, field, AccessKind::Write { value }),
                now,
                latch,
            )
            .unwrap();
    }
    fn read(
        timer: &mut GenericTimer,
        latch: &mut InterruptLatch,
        kind: TimerKind,
        field: TimerField,
        now: u64,
    ) -> u64 {
        timer
            .access(0, timer_request(kind, field, AccessKind::Read), now, latch)
            .unwrap()
    }

    #[test]
    fn counters_and_frequency() {
        let mut latch = InterruptLatch::new();
        let mut timer = GenericTimer::new(1, 1000);
        let counter = |kind, offset| BackendRequest::Counter {
            kind,
            offset,
            ordering: CounterOrdering::CounterReads,
        };
        assert_eq!(
            timer.access(
                0,
                BackendRequest::Frequency(AccessKind::Read),
                0,
                &mut latch
            ),
            Ok(24_000_000)
        );
        assert_eq!(
            timer.access(
                0,
                counter(TimerKind::Physical, CounterOffset::None),
                5000,
                &mut latch
            ),
            Ok(5000)
        );
        assert_eq!(
            timer.access(
                0,
                counter(TimerKind::Virtual, CounterOffset::VirtualEl2),
                5000,
                &mut latch
            ),
            Ok(4000)
        );
        assert!(
            timer
                .access(
                    0,
                    counter(TimerKind::Virtual, CounterOffset::None),
                    5000,
                    &mut latch
                )
                .is_err()
        );
        assert!(
            timer
                .access(
                    0,
                    counter(TimerKind::Physical, CounterOffset::PhysicalEl2),
                    5000,
                    &mut latch
                )
                .is_err()
        );
        assert!(
            timer
                .access(
                    0,
                    BackendRequest::Frequency(AccessKind::Write { value: 1 }),
                    0,
                    &mut latch
                )
                .is_err()
        );
    }

    /// Linux `arch_timer_set_next_event_virt` (TVAL then CTL.ENABLE), the FIQ,
    /// and `arch_timer_handler_virt` masking it through CTL.IMASK.
    #[test]
    fn virtual_timer_fires_a_fiq_and_masks() {
        let mut latch = InterruptLatch::new();
        let mut timer = GenericTimer::new(1, 0);
        write(
            &mut timer,
            &mut latch,
            TimerKind::Virtual,
            TimerField::TimerValue,
            240,
            1000,
        );
        write(
            &mut timer,
            &mut latch,
            TimerKind::Virtual,
            TimerField::Control,
            TIMER_ENABLE,
            1000,
        );
        assert_eq!(
            read(
                &mut timer,
                &mut latch,
                TimerKind::Virtual,
                TimerField::CompareValue,
                1000
            ),
            1240
        );
        assert_eq!(
            read(
                &mut timer,
                &mut latch,
                TimerKind::Virtual,
                TimerField::TimerValue,
                1040
            ),
            200
        );
        assert_eq!(timer.advance(1239, &mut latch), Some(1240));
        assert!(!latch.pins(0).fiq);
        assert_eq!(timer.advance(1240, &mut latch), None);
        assert!(latch.is_asserted(Wire::Fiq(0, FiqSource::VirtualTimer)));
        let control = read(
            &mut timer,
            &mut latch,
            TimerKind::Virtual,
            TimerField::Control,
            1300,
        );
        assert_eq!(control, TIMER_ENABLE | TIMER_ISTATUS);
        assert_eq!(
            read(
                &mut timer,
                &mut latch,
                TimerKind::Virtual,
                TimerField::TimerValue,
                1300
            ),
            u64::from((-60i32) as u32)
        );
        write(
            &mut timer,
            &mut latch,
            TimerKind::Virtual,
            TimerField::Control,
            control | TIMER_IMASK,
            1300,
        );
        assert!(!latch.pins(0).fiq);
        assert_eq!(
            read(
                &mut timer,
                &mut latch,
                TimerKind::Virtual,
                TimerField::Control,
                1300
            ),
            TIMER_ENABLE | TIMER_IMASK | TIMER_ISTATUS
        );
    }

    #[test]
    fn physical_timer_uses_the_physical_count() {
        let mut latch = InterruptLatch::new();
        let mut timer = GenericTimer::new(1, 500);
        write(
            &mut timer,
            &mut latch,
            TimerKind::Physical,
            TimerField::CompareValue,
            2000,
            0,
        );
        write(
            &mut timer,
            &mut latch,
            TimerKind::Virtual,
            TimerField::CompareValue,
            2000,
            0,
        );
        write(
            &mut timer,
            &mut latch,
            TimerKind::Physical,
            TimerField::Control,
            TIMER_ENABLE,
            0,
        );
        write(
            &mut timer,
            &mut latch,
            TimerKind::Virtual,
            TimerField::Control,
            TIMER_ENABLE,
            0,
        );
        assert_eq!(timer.advance(0, &mut latch), Some(2000));
        timer.advance(2000, &mut latch);
        assert!(latch.is_asserted(Wire::Fiq(0, FiqSource::PhysicalTimer)));
        assert!(!latch.is_asserted(Wire::Fiq(0, FiqSource::VirtualTimer)));
        assert_eq!(timer.advance(2000, &mut latch), Some(2500));
        // Disabling clears the FIQ immediately.
        write(
            &mut timer,
            &mut latch,
            TimerKind::Physical,
            TimerField::Control,
            0,
            2100,
        );
        assert!(!latch.is_asserted(Wire::Fiq(0, FiqSource::PhysicalTimer)));
    }

    #[test]
    fn virtual_count_alias_reads_the_virtual_count() {
        let mut latch = InterruptLatch::new();
        let mut timer = GenericTimer::new(1, 100);
        assert_eq!(
            timer.read_virtual_count_alias(0, ExceptionLevel::El1, 1000),
            Ok(900)
        );
        assert_eq!(
            timer.read_virtual_count_alias(0, ExceptionLevel::El0, 1000),
            Err(TimerError::TrapToEl1)
        );
        let control = KERNEL_CONTROL_EL0_VIRTUAL_COUNT;
        timer
            .access(
                0,
                BackendRequest::KernelControl(AccessKind::Write { value: control }),
                0,
                &mut latch,
            )
            .unwrap();
        assert_eq!(
            timer.read_virtual_count_alias(0, ExceptionLevel::El0, 1000),
            Ok(900)
        );
        assert!(
            timer
                .read_virtual_count_alias(1, ExceptionLevel::El1, 1000)
                .is_err()
        );
    }

    #[test]
    fn event_stream_follows_cntkctl() {
        let mut latch = InterruptLatch::new();
        let mut timer = GenericTimer::new(1, 0);
        assert_eq!(timer.next_event(0, 0), None);
        // EVNTEN, rising edge of bit 3: counts 8, 24, 40, ...
        let control = KERNEL_CONTROL_EVENT_ENABLE | 3 << KERNEL_CONTROL_EVENT_BIT_SHIFT | 0b11;
        timer
            .access(
                0,
                BackendRequest::KernelControl(AccessKind::Write { value: control }),
                0,
                &mut latch,
            )
            .unwrap();
        assert_eq!(
            timer.access(
                0,
                BackendRequest::KernelControl(AccessKind::Read),
                0,
                &mut latch
            ),
            Ok(control)
        );
        assert_eq!(timer.next_event(0, 0), Some(8));
        assert_eq!(timer.next_event(0, 8), Some(24));
        let falling = control | KERNEL_CONTROL_EVENT_DIRECTION;
        timer
            .access(
                0,
                BackendRequest::KernelControl(AccessKind::Write { value: falling }),
                0,
                &mut latch,
            )
            .unwrap();
        assert_eq!(timer.next_event(0, 9), Some(16));
        assert!(
            timer
                .access(
                    0,
                    BackendRequest::KernelControl(AccessKind::Write {
                        value: KERNEL_CONTROL_EVENT_SCALE
                    }),
                    0,
                    &mut latch
                )
                .is_err()
        );
    }
}
