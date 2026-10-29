//! Apple Interrupt Controller v1 (`apple,t8103-aic`, `apple,aic`; ADT
//! `aic,1`), the M1's controller for peripheral IRQs and its two AIC IPIs per
//! CPU. Fast IPIs and timer FIQs bypass it (see `ipi` and `timer`).
//!
//! Documented by Linux `drivers/irqchip/irq-apple-aic.c` (`aic1_info`,
//! `aic_init_cpu`, `aic_handle_ipi`) and m1n1 `src/aic_regs.h`:
//! - `INFO` (0x4) holds NR_IRQ [15:0]; MAX_IRQ is fixed at 0x400
//!   (`AIC_MAX_IRQ`, `AIC1_MAX_IRQ`) and there is one die.
//! - The issuing CPU's view: `WHOAMI` (0x2000) reads its AIC CPU number,
//!   `EVENT` (0x2004) its event, `IPI_SEND` (0x2008) sets the "other" IPI of
//!   each CPU whose bit is written, `IPI_ACK` (0x200c) clears its pending IPIs
//!   and `IPI_MASK_SET`/`IPI_MASK_CLR` (0x2024/0x2028) mask and unmask them,
//!   each IPI register naming OTHER as bit 0 and SELF as bit 31.
//! - From 0x3000, `TARGET_CPU[MAX_IRQ]` holds each IRQ's CPU mask, followed
//!   by `SW_SET`, `SW_CLR`, `MASK_SET`, `MASK_CLR` and `HW_STATE`, each
//!   `MAX_IRQ / 32` words (0x4000, 0x4080, 0x4100, 0x4180 and 0x4200).
//! - Reading `EVENT` returns DIE [31:24], TYPE [23:16] (1 = hardware IRQ,
//!   4 = IPI) and NUM [15:0] (the IRQ, or 1 for OTHER and 2 for SELF), or 0,
//!   and masks what it returns. Software pending bits are ORed with the
//!   hardware line; lower IRQ numbers win. An IPI stays pending until
//!   `IPI_ACK`; Linux unmasks it again once handled ("except auto-masking by
//!   AIC during processing").
//!
//! Inferred, not documented: the reset state masks every IRQ and IPI and
//! targets no CPU; `SET`/`CLR` reads return the current bits; the first CPU
//! of an IRQ's mask to read `EVENT` claims it; a hardware IRQ is returned
//! ahead of an IPI (software drains `EVENT` until it reads 0, so either order
//! is a permitted one). `CONFIG` (0x10), the per-CPU views from 0x5000 and
//! `IPI_SEND` bit 31 have no public description, so they stop explicitly, as
//! does any CPU mask naming a CPU the model does not serve.
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use stela_soc_data::aic::{AIC1_EVENT, AIC1_MAX_IRQ};
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError, stela_contracts::bus::Width,
    stela_contracts::bus::refuse,
};
use {
    stela_contracts::interrupt::AicInput, stela_contracts::interrupt::CpuIndex,
    stela_contracts::interrupt::Wire,
};

const NAME: &str = "aic1";

const INFO: u64 = 0x0004;
const WHOAMI: u64 = 0x2000;
/// The event register, inside the core block (Linux `AIC_EVENT`).
const IPI_SEND: u64 = 0x2008;
const IPI_ACK: u64 = 0x200c;
const IPI_MASK_SET: u64 = 0x2024;
const IPI_MASK_CLR: u64 = 0x2028;
const TARGET_CPU: u64 = 0x3000;
/// The AICv1's IRQs (`AIC_MAX_IRQ`), which fix its array layout.
const MAX_IRQ: u16 = AIC1_MAX_IRQ;
const WORDS: usize = MAX_IRQ as usize / 32;
const ARRAYS: u64 = TARGET_CPU + 4 * MAX_IRQ as u64;
/// The end of the documented registers: past `HW_STATE`.
const ARRAYS_END: u64 = ARRAYS + 4 * 5 * WORDS as u64;
/// The register block Linux and m1n1 map (`t8103.dtsi` `reg`,
/// `AIC_REG_SIZE`), which takes in the per-CPU views.
const SPAN: u64 = 0x8000;

const IPI_OTHER: u32 = 1;
const IPI_SELF: u32 = 1 << 31;
const EVENT_TYPE_IRQ: u32 = 1 << 16;
const EVENT_TYPE_IPI: u32 = 4 << 16;
const EVENT_IPI_OTHER: u32 = 1;
const EVENT_IPI_SELF: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aic1Error {
    InvalidConfig(&'static str),
    UnknownInput(AicInput),
}

/// One CPU's AIC IPIs: pending and masked OTHER and SELF bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ipis {
    pending: u32,
    mask: u32,
}

pub struct Aic1 {
    nr_irq: u16,
    target: Vec<u32>,
    software: Vec<u32>,
    hardware: Vec<u32>,
    mask: Vec<u32>,
    ipis: Vec<Ipis>,
    irq_level: Vec<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Array {
    SoftwareSet,
    SoftwareClear,
    MaskSet,
    MaskClear,
    HardwareState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Register {
    Info,
    WhoAmI,
    Event,
    IpiSend,
    IpiAck,
    IpiMaskSet,
    IpiMaskClear,
    TargetCpu(usize),
    Bits(Array, usize),
}

impl Aic1 {
    /// NR_IRQ is the number of inputs the board wires; `cpus` the PEs the
    /// controller serves, numbered as `WHOAMI` reads them.
    pub fn new(nr_irq: u16, cpus: usize) -> Result<Self, Aic1Error> {
        if nr_irq == 0 || nr_irq > MAX_IRQ {
            return Err(Aic1Error::InvalidConfig("NR_IRQ must be in 1..=0x400"));
        }
        if cpus == 0 || cpus > 31 {
            return Err(Aic1Error::InvalidConfig(
                "the CPU count must be in 1..=31, below IPI_SEND bit 31",
            ));
        }
        let ipis = Ipis {
            pending: 0,
            mask: IPI_OTHER | IPI_SELF,
        };
        Ok(Self {
            nr_irq,
            target: vec![0; usize::from(nr_irq)],
            software: vec![0; WORDS],
            hardware: vec![0; WORDS],
            mask: vec![u32::MAX; WORDS],
            ipis: vec![ipis; cpus],
            irq_level: vec![false; cpus],
        })
    }
    /// Size of the device address space to map.
    pub const fn span() -> u64 {
        SPAN
    }
    /// Sets the level of one hardware input, as wired by the engine from the
    /// device models' `Wire::Aic` outputs.
    pub fn set_input(
        &mut self,
        input: AicInput,
        asserted: bool,
        access: &mut Access<'_>,
    ) -> Result<(), Aic1Error> {
        if input.die != 0 || input.irq >= self.nr_irq {
            return Err(Aic1Error::UnknownInput(input));
        }
        let (word, bit) = position(usize::from(input.irq));
        if asserted {
            self.hardware[word] |= bit;
        } else {
            self.hardware[word] &= !bit;
        }
        self.update(access);
        Ok(())
    }

    fn cpus(&self) -> usize {
        self.ipis.len()
    }
    fn all_cpus(&self) -> u32 {
        (1 << self.cpus()) - 1
    }
    /// The highest-priority deliverable IRQ for `cpu`.
    fn irq_for(&self, cpu: CpuIndex) -> Option<usize> {
        (0..WORDS)
            .flat_map(|word| {
                let pending = (self.software[word] | self.hardware[word]) & !self.mask[word];
                (0..32)
                    .filter(move |bit| pending & 1 << bit != 0)
                    .map(move |bit| word * 32 + bit)
            })
            .take_while(|&irq| irq < usize::from(self.nr_irq))
            .find(|&irq| self.target[irq] & 1 << cpu != 0)
    }
    /// The deliverable IPI bit of `cpu`, OTHER ahead of SELF.
    fn ipi_for(&self, cpu: CpuIndex) -> Option<u32> {
        let ipis = self.ipis[cpu];
        let ready = ipis.pending & !ipis.mask;
        [IPI_OTHER, IPI_SELF]
            .into_iter()
            .find(|bit| ready & bit != 0)
    }
    fn update(&mut self, access: &mut Access<'_>) {
        for cpu in 0..self.cpus() {
            let level = self.irq_for(cpu).is_some() || self.ipi_for(cpu).is_some();
            if self.irq_level[cpu] != level {
                self.irq_level[cpu] = level;
                access.interrupts.set_level(Wire::Irq(cpu), level);
            }
        }
    }
    fn decode(&self, offset: u64) -> Option<Register> {
        let used_words = usize::from(self.nr_irq).div_ceil(32) as u64;
        Some(match offset {
            INFO => Register::Info,
            WHOAMI => Register::WhoAmI,
            AIC1_EVENT => Register::Event,
            IPI_SEND => Register::IpiSend,
            IPI_ACK => Register::IpiAck,
            IPI_MASK_SET => Register::IpiMaskSet,
            IPI_MASK_CLR => Register::IpiMaskClear,
            offset if (TARGET_CPU..ARRAYS).contains(&offset) && offset.is_multiple_of(4) => {
                let irq = (offset - TARGET_CPU) / 4;
                if irq >= u64::from(self.nr_irq) {
                    return None;
                }
                Register::TargetCpu(irq as usize)
            }
            offset if (ARRAYS..ARRAYS_END).contains(&offset) && offset.is_multiple_of(4) => {
                let index = (offset - ARRAYS) / 4;
                let (array, word) = (index / WORDS as u64, index % WORDS as u64);
                if word >= used_words {
                    return None;
                }
                let array = [
                    Array::SoftwareSet,
                    Array::SoftwareClear,
                    Array::MaskSet,
                    Array::MaskClear,
                    Array::HardwareState,
                ][array as usize];
                Register::Bits(array, word as usize)
            }
            _ => return None,
        })
    }
    fn unknown_reason(offset: u64) -> &'static str {
        match offset {
            0x10 => "AIC1 CONFIG is not documented",
            0x5000.. => "the AIC1 per-CPU views are not documented",
            _ => "unknown or unimplemented AIC1 register",
        }
    }
    /// Bits of `word` that name implemented IRQs.
    fn implemented(&self, word: usize) -> u32 {
        let count = usize::from(self.nr_irq).saturating_sub(word * 32).min(32);
        if count == 32 {
            u32::MAX
        } else {
            (1 << count) - 1
        }
    }
    fn read_register(&mut self, register: Register, cpu: CpuIndex) -> Result<u32, &'static str> {
        let served = || {
            if cpu < self.cpus() {
                Ok(cpu)
            } else {
                Err("AIC1 access from a CPU the AIC does not serve")
            }
        };
        Ok(match register {
            Register::Info => u32::from(self.nr_irq),
            Register::WhoAmI => served()? as u32,
            Register::Event => {
                let cpu = served()?;
                if let Some(irq) = self.irq_for(cpu) {
                    let (word, bit) = position(irq);
                    self.mask[word] |= bit;
                    EVENT_TYPE_IRQ | irq as u32
                } else if let Some(ipi) = self.ipi_for(cpu) {
                    self.ipis[cpu].mask |= ipi;
                    EVENT_TYPE_IPI
                        | if ipi == IPI_OTHER {
                            EVENT_IPI_OTHER
                        } else {
                            EVENT_IPI_SELF
                        }
                } else {
                    0
                }
            }
            Register::TargetCpu(irq) => self.target[irq],
            Register::Bits(Array::SoftwareSet | Array::SoftwareClear, word) => self.software[word],
            Register::Bits(Array::MaskSet | Array::MaskClear, word) => {
                self.mask[word] & self.implemented(word)
            }
            Register::Bits(Array::HardwareState, word) => self.hardware[word],
            Register::IpiSend
            | Register::IpiAck
            | Register::IpiMaskSet
            | Register::IpiMaskClear => {
                return Err("AIC1 IPI registers are write-only");
            }
        })
    }
    fn write_register(
        &mut self,
        register: Register,
        value: u32,
        cpu: CpuIndex,
    ) -> Result<(), &'static str> {
        let ipi_bits = |value: u32| {
            if value & !(IPI_OTHER | IPI_SELF) != 0 {
                Err("AIC1 IPI registers have only OTHER (bit 0) and SELF (bit 31)")
            } else {
                Ok(value)
            }
        };
        let served = || {
            if cpu < self.cpus() {
                Ok(cpu)
            } else {
                Err("AIC1 access from a CPU the AIC does not serve")
            }
        };
        match register {
            Register::IpiSend => {
                if value & IPI_SELF != 0 {
                    return Err("AIC1 IPI_SEND bit 31 is not documented");
                }
                if value & !self.all_cpus() != 0 {
                    return Err("AIC1 IPI_SEND names a CPU the AIC does not serve");
                }
                for (target, ipis) in self.ipis.iter_mut().enumerate() {
                    if value & 1 << target != 0 {
                        ipis.pending |= IPI_OTHER;
                    }
                }
            }
            Register::IpiAck => {
                let (bits, cpu) = (ipi_bits(value)?, served()?);
                self.ipis[cpu].pending &= !bits;
            }
            Register::IpiMaskSet => {
                let (bits, cpu) = (ipi_bits(value)?, served()?);
                self.ipis[cpu].mask |= bits;
            }
            Register::IpiMaskClear => {
                let (bits, cpu) = (ipi_bits(value)?, served()?);
                self.ipis[cpu].mask &= !bits;
            }
            Register::TargetCpu(irq) => {
                if value & !self.all_cpus() != 0 {
                    return Err("AIC1 TARGET_CPU names a CPU the AIC does not serve");
                }
                self.target[irq] = value;
            }
            Register::Bits(array, word) => {
                let bits = value & self.implemented(word);
                match array {
                    Array::SoftwareSet => self.software[word] |= bits,
                    Array::SoftwareClear => self.software[word] &= !bits,
                    Array::MaskSet => self.mask[word] |= bits,
                    Array::MaskClear => self.mask[word] &= !bits,
                    Array::HardwareState => return Err("AIC1 HW_STATE is read-only"),
                }
            }
            Register::Info => return Err("AIC1 INFO is read-only"),
            Register::WhoAmI => return Err("AIC1 WHOAMI is read-only"),
            Register::Event => return Err("AIC1 event register is read-only"),
        }
        Ok(())
    }
}

fn position(irq: usize) -> (usize, u32) {
    (irq / 32, 1 << (irq % 32))
}

impl MmioDevice for Aic1 {
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(
        &mut self,
        offset: u64,
        width: Width,
        access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Read, reason);
        if width != Width::Word {
            return Err(fail("AIC1 registers are 32-bit"));
        }
        let register = self
            .decode(offset)
            .ok_or_else(|| fail(Self::unknown_reason(offset)))?;
        let value = self.read_register(register, access.cpu).map_err(fail)?;
        self.update(access);
        Ok(u64::from(value))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        if width != Width::Word {
            return Err(fail("AIC1 registers are 32-bit"));
        }
        let register = self
            .decode(offset)
            .ok_or_else(|| fail(Self::unknown_reason(offset)))?;
        self.write_register(register, value as u32, access.cpu)
            .map_err(fail)?;
        self.update(access);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_contracts::interrupt::InterruptLatch;

    const NR_IRQ: u16 = 0x380;
    const SW_SET: u64 = 0x4000;
    const SW_CLR: u64 = 0x4080;
    const MASK_SET: u64 = 0x4100;
    const MASK_CLR: u64 = 0x4180;
    const HW_STATE: u64 = 0x4200;
    const UART: AicInput = AicInput::new(0, 605);

    fn read(aic: &mut Aic1, latch: &mut InterruptLatch, cpu: CpuIndex, offset: u64) -> u32 {
        aic.read(offset, Width::Word, &mut Access::new(cpu, 0, latch))
            .unwrap() as u32
    }
    fn write(aic: &mut Aic1, latch: &mut InterruptLatch, cpu: CpuIndex, offset: u64, value: u32) {
        aic.write(
            offset,
            Width::Word,
            value.into(),
            &mut Access::new(cpu, 0, latch),
        )
        .unwrap();
    }
    /// Linux `aic_of_ic_init` for AICv1: read INFO, then mask, clear and
    /// target CPU 0 for every IRQ; `aic_init_cpu` then checks WHOAMI, acks
    /// both IPIs and, without fast IPIs, unmasks OTHER.
    fn linux_init(aic: &mut Aic1, latch: &mut InterruptLatch, cpus: usize) {
        assert_eq!(read(aic, latch, 0, INFO) & 0xffff, u32::from(NR_IRQ));
        for word in 0..u64::from(NR_IRQ).div_ceil(32) {
            write(aic, latch, 0, MASK_SET + 4 * word, u32::MAX);
            write(aic, latch, 0, SW_CLR + 4 * word, u32::MAX);
        }
        for irq in 0..u64::from(NR_IRQ) {
            write(aic, latch, 0, TARGET_CPU + 4 * irq, 1);
        }
        for cpu in 0..cpus {
            assert_eq!(read(aic, latch, cpu, WHOAMI), cpu as u32);
            write(aic, latch, cpu, IPI_ACK, IPI_SELF | IPI_OTHER);
            write(aic, latch, cpu, IPI_MASK_SET, IPI_SELF);
            write(aic, latch, cpu, IPI_MASK_CLR, IPI_OTHER);
        }
    }

    /// Linux `aic_irq_unmask`, `aic_handle_irq` (event read with auto-mask)
    /// and `aic_irq_eoi`, and `aic_irq_set_affinity` moving the line.
    #[test]
    fn linux_hardware_irq_cycle_and_affinity() {
        let mut latch = InterruptLatch::new();
        let mut aic = Aic1::new(NR_IRQ, 2).unwrap();
        linux_init(&mut aic, &mut latch, 2);
        let (word, bit) = position(UART.irq.into());
        write(&mut aic, &mut latch, 0, MASK_CLR + 4 * word as u64, bit);
        aic.set_input(UART, true, &mut Access::new(0, 0, &mut latch))
            .unwrap();
        assert!(latch.pins(0).irq && !latch.pins(1).irq);
        assert_eq!(
            read(&mut aic, &mut latch, 0, HW_STATE + 4 * word as u64),
            bit
        );
        assert_eq!(read(&mut aic, &mut latch, 0, AIC1_EVENT), 1 << 16 | 605);
        assert!(!latch.pins(0).irq, "the event read masked the IRQ");
        assert_eq!(read(&mut aic, &mut latch, 0, AIC1_EVENT), 0);
        write(&mut aic, &mut latch, 0, TARGET_CPU + 4 * 605, 0b10);
        write(&mut aic, &mut latch, 0, MASK_CLR + 4 * word as u64, bit);
        assert!(!latch.pins(0).irq && latch.pins(1).irq);
        assert_eq!(read(&mut aic, &mut latch, 0, AIC1_EVENT), 0);
        assert_eq!(read(&mut aic, &mut latch, 1, AIC1_EVENT), 1 << 16 | 605);
        aic.set_input(UART, false, &mut Access::new(0, 0, &mut latch))
            .unwrap();
        assert_eq!(read(&mut aic, &mut latch, 0, HW_STATE + 4 * word as u64), 0);
    }

    #[test]
    fn software_triggers_and_priority() {
        let mut latch = InterruptLatch::new();
        let mut aic = Aic1::new(NR_IRQ, 1).unwrap();
        linux_init(&mut aic, &mut latch, 1);
        write(&mut aic, &mut latch, 0, MASK_CLR, 0b1010);
        write(&mut aic, &mut latch, 0, SW_SET, 0b1110);
        assert_eq!(read(&mut aic, &mut latch, 0, SW_SET), 0b1110);
        assert_eq!(read(&mut aic, &mut latch, 0, MASK_SET), !0b1010);
        assert_eq!(read(&mut aic, &mut latch, 0, AIC1_EVENT), 1 << 16 | 1);
        assert_eq!(read(&mut aic, &mut latch, 0, AIC1_EVENT), 1 << 16 | 3);
        assert_eq!(
            read(&mut aic, &mut latch, 0, AIC1_EVENT),
            0,
            "IRQ 2 stays masked"
        );
        write(&mut aic, &mut latch, 0, SW_CLR, 0b1110);
        write(&mut aic, &mut latch, 0, MASK_CLR, 0b1010);
        assert!(!latch.pins(0).irq);
    }

    /// Linux `aic_ipi_send_single` without fast IPIs, then `aic_handle_ipi`:
    /// the event read masks OTHER, IPI_ACK clears it and IPI_MASK_CLR
    /// unmasks it again.
    #[test]
    fn linux_ipi_cycle() {
        let mut latch = InterruptLatch::new();
        let mut aic = Aic1::new(NR_IRQ, 2).unwrap();
        assert_eq!(read(&mut aic, &mut latch, 1, AIC1_EVENT), 0);
        write(&mut aic, &mut latch, 0, IPI_SEND, 1 << 1);
        assert!(!latch.pins(1).irq, "IPIs reset masked");
        linux_init(&mut aic, &mut latch, 2);
        write(&mut aic, &mut latch, 0, IPI_SEND, 1 << 1);
        assert!(!latch.pins(0).irq && latch.pins(1).irq);
        assert_eq!(read(&mut aic, &mut latch, 1, AIC1_EVENT), 4 << 16 | 1);
        assert!(!latch.pins(1).irq, "the event read masked OTHER");
        write(&mut aic, &mut latch, 1, IPI_ACK, IPI_OTHER);
        write(&mut aic, &mut latch, 1, IPI_MASK_CLR, IPI_OTHER);
        assert!(!latch.pins(1).irq, "the IPI was acknowledged");
        // A hardware IRQ is returned ahead of a pending IPI.
        write(&mut aic, &mut latch, 0, MASK_CLR, 1);
        write(&mut aic, &mut latch, 0, SW_SET, 1);
        write(&mut aic, &mut latch, 0, TARGET_CPU, 0b10);
        write(&mut aic, &mut latch, 0, IPI_SEND, 1 << 1);
        assert_eq!(read(&mut aic, &mut latch, 1, AIC1_EVENT), 1 << 16);
        assert_eq!(read(&mut aic, &mut latch, 1, AIC1_EVENT), 4 << 16 | 1);
        assert_eq!(read(&mut aic, &mut latch, 1, AIC1_EVENT), 0);
    }

    #[test]
    fn undocumented_registers_and_unserved_cpus_refuse() {
        let mut latch = InterruptLatch::new();
        let mut aic = Aic1::new(NR_IRQ, 2).unwrap();
        let mut access = Access::new(0, 0, &mut latch);
        for offset in [
            0x0,
            0x10,
            0x2010,
            0x5008,
            TARGET_CPU + 4 * u64::from(NR_IRQ),
            SW_SET + 4 * u64::from(NR_IRQ).div_ceil(32),
            HW_STATE + 4 * 32,
        ] {
            assert!(
                aic.read(offset, Width::Word, &mut access).is_err(),
                "{offset:#x}"
            );
        }
        for (offset, value) in [
            (IPI_SEND, IPI_SELF),
            (IPI_SEND, 1 << 2),
            (IPI_ACK, 1 << 1),
            (TARGET_CPU, 0b100),
            (HW_STATE, 1),
            (INFO, 0),
            (AIC1_EVENT, 0),
        ] {
            assert!(
                aic.write(offset, Width::Word, value.into(), &mut access)
                    .is_err(),
                "{offset:#x} {value:#x}"
            );
        }
        assert!(aic.read(IPI_SEND, Width::Word, &mut access).is_err());
        assert!(aic.read(AIC1_EVENT, Width::Double, &mut access).is_err());
        let mut access = Access::new(2, 0, &mut latch);
        assert!(aic.read(WHOAMI, Width::Word, &mut access).is_err());
        assert!(aic.read(AIC1_EVENT, Width::Word, &mut access).is_err());
        assert!(
            aic.set_input(AicInput::new(0, NR_IRQ), true, &mut access)
                .is_err()
        );
        assert!(Aic1::new(0x401, 1).is_err());
        assert!(Aic1::new(NR_IRQ, 32).is_err());
        assert_eq!(Aic1::span(), 0x8000);
    }
}
