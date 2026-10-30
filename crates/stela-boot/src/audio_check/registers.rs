//! Read command-engine state before shutdown on a validation error.
use crate::output;
use alloc::rc::Rc;
use core::{cell::RefCell, ops::Range};
use stela_drivers::audio::hda::{MmioRegisters, Registers};

/// Shared only for serial inspection between driver calls on the sole CPU.
/// RefCell prevents overlapping register access; no second MMIO owner is made.
#[derive(Clone)]
pub(super) struct Observed(Rc<RefCell<MmioRegisters>>);

impl Observed {
    pub(super) fn new(registers: MmioRegisters) -> Self {
        Self(Rc::new(RefCell::new(registers)))
    }

    pub(super) fn report(&self, dma: Range<u64>) {
        let mut registers = self.0.borrow_mut();
        for (name, offset, width) in [
            ("INTCTL", 0x20, 4),
            ("CORBLBASE", 0x40, 4),
            ("CORBUBASE", 0x44, 4),
            ("CORBWP", 0x48, 2),
            ("CORBRP", 0x4a, 2),
            ("CORBCTL", 0x4c, 1),
            ("CORBSTS", 0x4d, 1),
            ("CORBSIZE", 0x4e, 1),
            ("RIRBLBASE", 0x50, 4),
            ("RIRBUBASE", 0x54, 4),
            ("RIRBWP", 0x58, 2),
            ("RINTCNT", 0x5a, 2),
            ("RIRBCTL", 0x5c, 1),
            ("RIRBSTS", 0x5d, 1),
            ("RIRBSIZE", 0x5e, 1),
        ] {
            let value = match width {
                1 => u32::from(registers.read8(offset)),
                2 => u32::from(registers.read16(offset)),
                _ => registers.read32(offset),
            };
            output::arguments(format_args!("AUDIO CHECK registers {name}={value:#x}\n"));
        }
        for (name, base_low, pointer, stride) in
            [("CORB", 0x40, 0x48, 4u64), ("RIRB", 0x50, 0x58, 8)]
        {
            let base = u64::from(registers.read32(base_low))
                | u64::from(registers.read32(base_low + 4)) << 32;
            let index = u64::from(registers.read16(pointer) & 0xff);
            let start = base.saturating_add(index * stride);
            if start >= dma.start && start.saturating_add(stride) <= dma.end {
                // SAFETY: live coherent ring inside our reserved DMA range,
                // naturally aligned; no CPU driver call overlaps this.
                let value = unsafe { (start as *const u32).read_volatile() };
                output::arguments(format_args!(
                    "AUDIO CHECK ring={name} base={base:#x} index={index} low={value:#x}\n"
                ));
                if stride == 8 {
                    // SAFETY: same bounded ring entry, upper response word.
                    let high = unsafe { ((start + 4) as *const u32).read_volatile() };
                    output::arguments(format_args!("AUDIO CHECK ring={name} high={high:#x}\n"));
                }
            }
        }
    }
}

impl Registers for Observed {
    fn read8(&mut self, offset: usize) -> u8 {
        self.0.borrow_mut().read8(offset)
    }
    fn read16(&mut self, offset: usize) -> u16 {
        self.0.borrow_mut().read16(offset)
    }
    fn read32(&mut self, offset: usize) -> u32 {
        self.0.borrow_mut().read32(offset)
    }
    fn write8(&mut self, offset: usize, value: u8) {
        self.0.borrow_mut().write8(offset, value);
    }
    fn write16(&mut self, offset: usize, value: u16) {
        self.0.borrow_mut().write16(offset, value);
    }
    fn write32(&mut self, offset: usize, value: u32) {
        self.0.borrow_mut().write32(offset, value);
    }
}
