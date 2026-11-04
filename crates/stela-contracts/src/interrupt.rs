//! Interrupt wires between the Apple device models and the CPUs.
//!
//! On Apple silicon, peripheral interrupts are AIC inputs that reach a CPU as
//! IRQ, while the generic timers and fast IPIs bypass the AIC and are FIQs
//! (Linux `drivers/irqchip/irq-apple-aic.c`, header comment and
//! `aic_handle_fiq`; Asahi Linux "AIC" documentation: the timer "is wired
//! straight to FIQ"). Every wire is level-sensitive, so a sink only ever sees
//! the current level of each wire.
use alloc::collections::BTreeSet;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Logical CPU number as the system engine numbers its virtual CPUs.
pub type CpuIndex = usize;

/// One AIC input line: DeviceTree `interrupts = <AIC_IRQ [die] irq flags>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AicInput {
    pub die: u8,
    pub irq: u16,
}
impl AicInput {
    pub const fn new(die: u8, irq: u16) -> Self {
        Self { die, irq }
    }
}

/// The per-CPU FIQ sources a model can drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FiqSource {
    /// `CNTP_CTL_EL0` timer condition.
    PhysicalTimer,
    /// `CNTV_CTL_EL0` timer condition.
    VirtualTimer,
    /// `IMP_APL_IPI_SR_EL1.PENDING`.
    FastIpi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Wire {
    /// A device's interrupt output into an AIC input.
    Aic(AicInput),
    /// The AIC's IRQ output to one CPU.
    Irq(CpuIndex),
    /// One FIQ source of one CPU; the CPU's FIQ pin is their OR.
    Fiq(CpuIndex, FiqSource),
}

/// Receives level changes. Models report a wire only when its level changes,
/// after the register effect that caused it; repeated equal levels are allowed.
pub trait InterruptSink {
    fn set_level(&mut self, wire: Wire, asserted: bool);
}

/// The CPU-visible pins of one CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CpuPins {
    pub irq: bool,
    pub fiq: bool,
}

/// A ready-made sink for the system engine: it keeps the current level of
/// every CPU wire and queues AIC input changes for the engine to forward to
/// `aic::Aic2::set_input`, because the AIC usually sits on the same bus as the
/// device whose access raised the wire.
#[derive(Debug, Default)]
pub struct InterruptLatch {
    asserted: BTreeSet<Wire>,
    aic_inputs: Vec<(AicInput, bool)>,
}
/// Retain space for ordinary wire traffic without keeping a large burst.
const RETAINED_AIC_INPUTS: usize = 32;

impl InterruptLatch {
    pub fn new() -> Self {
        Self::default()
    }
    /// AIC input changes in the order they happened, removed from the latch.
    pub fn take_aic_inputs(&mut self) -> Vec<(AicInput, bool)> {
        core::mem::take(&mut self.aic_inputs)
    }

    /// Move queued AIC input changes in order into an existing destination.
    pub fn append_aic_inputs<T>(
        &mut self,
        destination: &mut Vec<T>,
        map: impl FnMut((AicInput, bool)) -> T,
    ) {
        if self.aic_inputs.is_empty() {
            return;
        }
        destination.extend(self.aic_inputs.drain(..).map(map));
        if self.aic_inputs.capacity() > RETAINED_AIC_INPUTS {
            self.aic_inputs = Vec::new();
        }
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn is_asserted(&self, wire: Wire) -> bool {
        self.asserted.contains(&wire)
    }
    pub fn pins(&self, cpu: CpuIndex) -> CpuPins {
        CpuPins {
            irq: self.asserted.contains(&Wire::Irq(cpu)),
            fiq: self
                .asserted
                .range(
                    Wire::Fiq(cpu, FiqSource::PhysicalTimer)..=Wire::Fiq(cpu, FiqSource::FastIpi),
                )
                .next()
                .is_some(),
        }
    }
}
impl InterruptSink for InterruptLatch {
    fn set_level(&mut self, wire: Wire, asserted: bool) {
        let changed = if asserted {
            self.asserted.insert(wire)
        } else {
            self.asserted.remove(&wire)
        };
        if let (Wire::Aic(input), true) = (wire, changed) {
            self.aic_inputs.push((input, asserted));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fiq_pin_is_the_or_of_its_sources() {
        let mut latch = InterruptLatch::new();
        latch.set_level(Wire::Fiq(1, FiqSource::VirtualTimer), true);
        latch.set_level(Wire::Fiq(1, FiqSource::FastIpi), true);
        assert_eq!(latch.pins(0), CpuPins::default());
        assert_eq!(
            latch.pins(1),
            CpuPins {
                irq: false,
                fiq: true
            }
        );
        latch.set_level(Wire::Fiq(1, FiqSource::VirtualTimer), false);
        assert!(latch.pins(1).fiq);
        latch.set_level(Wire::Fiq(1, FiqSource::FastIpi), false);
        assert!(!latch.pins(1).fiq);
        latch.set_level(Wire::Irq(2), true);
        assert_eq!(
            latch.pins(2),
            CpuPins {
                irq: true,
                fiq: false
            }
        );
    }

    #[test]
    fn aic_inputs_queue_only_level_changes() {
        let mut latch = InterruptLatch::new();
        let uart = AicInput::new(0, 739);
        latch.set_level(Wire::Aic(uart), true);
        latch.set_level(Wire::Aic(uart), true);
        latch.set_level(Wire::Aic(uart), false);
        assert_eq!(latch.take_aic_inputs(), vec![(uart, true), (uart, false)]);
        assert!(latch.take_aic_inputs().is_empty());
    }

    #[test]
    fn appending_aic_inputs_reuses_small_buffers_and_releases_large_ones() {
        let mut latch = InterruptLatch::new();
        let input = AicInput::new(0, 739);
        let mut output = vec![(input, false)];
        latch.set_level(Wire::Aic(input), true);
        let capacity = latch.aic_inputs.capacity();
        assert_ne!(capacity, 0);
        latch.append_aic_inputs(&mut output, core::convert::identity);
        assert_eq!(output, [(input, false), (input, true)]);
        assert_eq!(latch.aic_inputs.capacity(), capacity);

        for index in 0..=RETAINED_AIC_INPUTS {
            latch.set_level(Wire::Aic(input), index % 2 != 0);
        }
        output.clear();
        latch.append_aic_inputs(&mut output, core::convert::identity);
        assert!(
            output
                .iter()
                .copied()
                .eq((0..=RETAINED_AIC_INPUTS).map(|index| (input, index % 2 != 0)))
        );
        assert_eq!(latch.aic_inputs.capacity(), 0);
    }
}
