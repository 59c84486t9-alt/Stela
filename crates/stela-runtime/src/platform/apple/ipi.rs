//! Apple fast IPIs: implementation-defined system registers that raise a FIQ
//! on another CPU without the AIC (AICv2 has no IPI registers).
//!
//! Documented by Linux `drivers/irqchip/irq-apple-aic.c` and m1n1
//! `src/cpu_regs.h`:
//! - `IPI_RR_LOCAL_EL1` (S3_5_C15_C0_0) targets CPU [7:0] in the sender's
//!   cluster; `IPI_RR_GLOBAL_EL1` (S3_5_C15_C0_1) also takes CLUSTER [23:16].
//!   TYPE [29:28] is 0 immediate, 1 retract, 2 deferred, 3 no-wake.
//! - `IPI_SR_EL1` (S3_5_C15_C1_1) bit 0 is the pending FIQ, cleared by writing
//!   1 (`aic_handle_ipi`, `aic_init_cpu`).
//! - `IPI_CR_EL1` (S3_5_C15_C3_1) is the deferred-IPI countdown. XNU
//!   `osfmk/arm64/machine_routines.c` (`ml_cpu_signal_deferred_adjust_timer`)
//!   documents it as one global register of REFCLK ticks in a 16-bit field
//!   that a single write updates for every core.
//! - The cluster and CPU numbers are MPIDR Aff1 and Aff0 (`aic_ipi_send_fast`).
//!
//! Inferred, not documented: a retract cancels a deferred IPI that has not
//! fired yet, and an immediate IPI subsumes one. The IPI_CR reset value is not
//! known, so reading it or sending a deferred IPI before it is written is
//! refused. No-wake requests are refused because their effect on a waiting CPU
//! is not documented.
//!
//! These registers are EL1-accessible; the engine decides EL0 traps before
//! calling [`FastIpi::access`].
use super::interrupt::{CpuIndex, FiqSource, InterruptSink, Wire};
use crate::system::access::{AccessKind, Encoding};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    RequestLocal,
    RequestGlobal,
    Status,
    Countdown,
}
impl Register {
    pub const fn encoding(self) -> Encoding {
        match self {
            Self::RequestLocal => Encoding::new(3, 5, 15, 0, 0),
            Self::RequestGlobal => Encoding::new(3, 5, 15, 0, 1),
            Self::Status => Encoding::new(3, 5, 15, 1, 1),
            Self::Countdown => Encoding::new(3, 5, 15, 3, 1),
        }
    }
    pub fn decode(encoding: Encoding) -> Option<Self> {
        [
            Self::RequestLocal,
            Self::RequestGlobal,
            Self::Status,
            Self::Countdown,
        ]
        .into_iter()
        .find(|register| register.encoding() == encoding)
    }
}

const RR_CPU: u64 = 0xff;
const RR_CLUSTER_SHIFT: u32 = 16;
const RR_CLUSTER: u64 = 0xff << RR_CLUSTER_SHIFT;
const RR_TYPE_SHIFT: u32 = 28;
const RR_TYPE: u64 = 0b11 << RR_TYPE_SHIFT;
const SR_PENDING: u64 = 1;
const CR_COUNTDOWN: u64 = 0xffff;

/// MPIDR affinity of one CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Affinity {
    pub cluster: u8,
    pub cpu: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpiError {
    UnknownCpu(CpuIndex),
    Unsupported(Register, &'static str),
}

#[derive(Debug, Clone, Copy, Default)]
struct CpuState {
    pending: bool,
    /// Counter value at which a deferred IPI fires.
    deferred: Option<u64>,
}

/// Fast-IPI state of every CPU. `cpus[i]` is the affinity of logical CPU `i`.
pub struct FastIpi {
    cpus: Vec<Affinity>,
    state: Vec<CpuState>,
    /// The global IPI_CR value.
    countdown: Option<u64>,
}
impl FastIpi {
    pub fn new(cpus: Vec<Affinity>) -> Self {
        let state = vec![CpuState::default(); cpus.len()];
        Self {
            cpus,
            state,
            countdown: None,
        }
    }
    pub fn pending(&self, cpu: CpuIndex) -> bool {
        self.state.get(cpu).is_some_and(|state| state.pending)
    }
    /// One MRS or MSR by `cpu` at counter value `now`. Returns the value read,
    /// or 0 for a write.
    pub fn access(
        &mut self,
        cpu: CpuIndex,
        register: Register,
        kind: AccessKind,
        now: u64,
        interrupts: &mut dyn InterruptSink,
    ) -> Result<u64, IpiError> {
        let sender = *self.cpus.get(cpu).ok_or(IpiError::UnknownCpu(cpu))?;
        let unsupported = |reason| Err(IpiError::Unsupported(register, reason));
        match (register, kind) {
            (Register::RequestLocal | Register::RequestGlobal, AccessKind::Read) => {
                unsupported("IPI request registers are write-only")
            }
            (Register::RequestLocal | Register::RequestGlobal, AccessKind::Write { value }) => {
                let global = register == Register::RequestGlobal;
                let fields = RR_CPU | RR_TYPE | if global { RR_CLUSTER } else { 0 };
                if value & !fields != 0 {
                    return unsupported("IPI request reserved field is not modeled");
                }
                let target = Affinity {
                    cluster: if global {
                        (value >> RR_CLUSTER_SHIFT) as u8
                    } else {
                        sender.cluster
                    },
                    cpu: (value & RR_CPU) as u8,
                };
                let Some(target) = self.cpus.iter().position(|&affinity| affinity == target) else {
                    return unsupported("IPI request names no CPU of this machine");
                };
                let countdown = self.countdown;
                let state = &mut self.state[target];
                match value >> RR_TYPE_SHIFT & 0b11 {
                    0 => {
                        state.deferred = None;
                        Self::raise(target, state, interrupts);
                    }
                    1 => state.deferred = None,
                    2 => {
                        let Some(countdown) = countdown else {
                            return unsupported("deferred IPI sent before IPI_CR was written");
                        };
                        state.deferred.get_or_insert(now.saturating_add(countdown));
                    }
                    _ => return unsupported("no-wake IPIs are not modeled"),
                }
                Ok(0)
            }
            (Register::Status, AccessKind::Read) => Ok(u64::from(self.state[cpu].pending)),
            (Register::Status, AccessKind::Write { value }) => {
                if value & !SR_PENDING != 0 {
                    return unsupported("IPI_SR fields other than PENDING are not modeled");
                }
                let state = &mut self.state[cpu];
                if value & SR_PENDING != 0 && state.pending {
                    state.pending = false;
                    interrupts.set_level(Wire::Fiq(cpu, FiqSource::FastIpi), false);
                }
                Ok(0)
            }
            (Register::Countdown, AccessKind::Read) => self.countdown.ok_or(IpiError::Unsupported(
                register,
                "IPI_CR read before it was written",
            )),
            (Register::Countdown, AccessKind::Write { value }) => {
                if value & !CR_COUNTDOWN != 0 {
                    return unsupported("IPI_CR has a 16-bit countdown field");
                }
                self.countdown = Some(value);
                Ok(0)
            }
        }
    }
    /// Fires deferred IPIs due at `now`; returns the next deferred deadline.
    pub fn advance(&mut self, now: u64, interrupts: &mut dyn InterruptSink) -> Option<u64> {
        let mut next: Option<u64> = None;
        for (cpu, state) in self.state.iter_mut().enumerate() {
            match state.deferred {
                Some(deadline) if deadline <= now => {
                    state.deferred = None;
                    Self::raise(cpu, state, interrupts);
                }
                Some(deadline) => next = Some(next.map_or(deadline, |next| next.min(deadline))),
                None => {}
            }
        }
        next
    }
    fn raise(cpu: CpuIndex, state: &mut CpuState, interrupts: &mut dyn InterruptSink) {
        if !state.pending {
            state.pending = true;
            interrupts.set_level(Wire::Fiq(cpu, FiqSource::FastIpi), true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;

    /// T8112: four E-cores in cluster 0, four P-cores in cluster 1.
    fn t8112() -> FastIpi {
        FastIpi::new(
            (0..8)
                .map(|index| Affinity {
                    cluster: index / 4,
                    cpu: index % 4,
                })
                .collect(),
        )
    }
    fn write(
        ipi: &mut FastIpi,
        latch: &mut InterruptLatch,
        cpu: CpuIndex,
        register: Register,
        value: u64,
        now: u64,
    ) {
        ipi.access(cpu, register, AccessKind::Write { value }, now, latch)
            .unwrap();
    }

    /// Linux `aic_ipi_send_fast` (local and global) then `aic_handle_ipi`.
    #[test]
    fn linux_send_and_acknowledge() {
        let mut latch = InterruptLatch::new();
        let mut ipi = t8112();
        write(&mut ipi, &mut latch, 0, Register::RequestLocal, 2, 0);
        assert!(latch.pins(2).fiq);
        write(
            &mut ipi,
            &mut latch,
            0,
            Register::RequestGlobal,
            1 << 16 | 3,
            0,
        );
        assert!(latch.pins(7).fiq);
        assert_eq!(
            ipi.access(7, Register::Status, AccessKind::Read, 0, &mut latch),
            Ok(1)
        );
        write(&mut ipi, &mut latch, 7, Register::Status, SR_PENDING, 0);
        assert!(!latch.pins(7).fiq);
        assert_eq!(
            ipi.access(7, Register::Status, AccessKind::Read, 0, &mut latch),
            Ok(0)
        );
        // A P-core's local request stays in cluster 1.
        write(&mut ipi, &mut latch, 5, Register::RequestLocal, 0, 0);
        assert!(latch.pins(4).fiq && !latch.pins(0).fiq);
    }

    #[test]
    fn deferred_ipis_fire_after_the_countdown_unless_retracted() {
        let mut latch = InterruptLatch::new();
        let mut ipi = t8112();
        write(&mut ipi, &mut latch, 0, Register::Countdown, 240, 0);
        write(
            &mut ipi,
            &mut latch,
            0,
            Register::RequestLocal,
            2 << 28 | 1,
            100,
        );
        assert!(!latch.pins(1).fiq);
        assert_eq!(ipi.advance(339, &mut latch), Some(340));
        assert_eq!(ipi.advance(340, &mut latch), None);
        assert!(latch.pins(1).fiq);
        write(&mut ipi, &mut latch, 1, Register::Status, SR_PENDING, 340);
        write(
            &mut ipi,
            &mut latch,
            0,
            Register::RequestLocal,
            2 << 28 | 1,
            400,
        );
        write(
            &mut ipi,
            &mut latch,
            0,
            Register::RequestLocal,
            1 << 28 | 1,
            401,
        );
        assert_eq!(ipi.advance(1000, &mut latch), None);
        assert!(!latch.pins(1).fiq);
    }

    #[test]
    fn decodes_encodings_and_refuses_unmodeled_requests() {
        assert_eq!(
            Register::decode(Encoding::new(3, 5, 15, 1, 1)),
            Some(Register::Status)
        );
        assert_eq!(Register::decode(Encoding::new(3, 5, 15, 1, 3)), None);
        let mut latch = InterruptLatch::new();
        let mut ipi = t8112();
        let mut write =
            |register, value| ipi.access(0, register, AccessKind::Write { value }, 0, &mut latch);
        assert!(write(Register::RequestLocal, 3 << 28).is_err(), "no-wake");
        assert!(
            write(Register::RequestLocal, 1 << 16).is_err(),
            "cluster in LOCAL"
        );
        assert!(
            write(Register::RequestGlobal, 2 << 16).is_err(),
            "no cluster 2"
        );
        assert!(write(Register::Status, 2).is_err());
        assert!(
            write(Register::RequestLocal, 2 << 28 | 1).is_err(),
            "IPI_CR unset"
        );
        assert!(write(Register::Countdown, 0x1_0000).is_err());
        assert!(
            ipi.access(0, Register::RequestLocal, AccessKind::Read, 0, &mut latch)
                .is_err()
        );
        assert_eq!(
            ipi.access(8, Register::Status, AccessKind::Read, 0, &mut latch),
            Err(IpiError::UnknownCpu(8))
        );
    }
}
