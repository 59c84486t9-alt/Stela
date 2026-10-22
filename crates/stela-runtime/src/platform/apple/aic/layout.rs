//! Explicit AICv2/v3 register geometry. AICv3's capability offsets and
//! per-array die strides are firmware facts, not generation-wide constants.
//! m1n1 `src/aic.c` reads cap0-offset, maxnumirq-offset,
//! extintrcfg-stride, intmaskset-stride and intmaskclear-stride from the ADT.
//! Unestablished banks must not be supplied using guessed offsets.
use super::{Aic2Config, CONFIG, INFO1, INFO3, TIMESTAMP_STRIDE, VERSION};
use alloc::vec::Vec;

/// Absolute offsets of one die's independent register arrays. The caller
/// must establish all six banks; a die's hardware IRQ state is independent
/// of its peers even when their IRQ numbers are identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aic2DieLayout {
    pub irq_config: u64,
    pub software_set: u64,
    pub software_clear: u64,
    pub mask_set: u64,
    pub mask_clear: u64,
    pub hardware_state: u64,
}

impl Aic2DieLayout {
    /// The contiguous layout documented for AICv2 and early AICv3. The
    /// caller supplies each die's base; later layouts may need independent
    /// array offsets instead.
    pub fn contiguous(irq_config: u64, max_irq: u16) -> Option<Self> {
        let software_set = irq_config.checked_add(4 * u64::from(max_irq))?;
        let bank_bytes = 4 * u64::from(max_irq / 32);
        Some(Self {
            irq_config,
            software_set,
            software_clear: software_set.checked_add(bank_bytes)?,
            mask_set: software_set.checked_add(2 * bank_bytes)?,
            mask_clear: software_set.checked_add(3 * bank_bytes)?,
            hardware_state: software_set.checked_add(4 * bank_bytes)?,
        })
    }

    pub(super) fn banks(self) -> [u64; 6] {
        [
            self.irq_config,
            self.software_set,
            self.software_clear,
            self.mask_set,
            self.mask_clear,
            self.hardware_state,
        ]
    }
}

/// Capability-register offsets and the complete populated die inventory.
/// MAX_DIE is hardware capacity; LAST_DIE reports populated dies minus one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aic2Layout {
    pub info1: u64,
    pub info3: u64,
    pub max_dies: u8,
    pub dies: Vec<Aic2DieLayout>,
}

impl Aic2Layout {
    pub(super) fn single(config: &Aic2Config) -> Option<Self> {
        Some(Self {
            info1: INFO1,
            info3: INFO3,
            max_dies: 1,
            dies: alloc::vec![Aic2DieLayout::contiguous(
                config.irq_config,
                config.max_irq
            )?],
        })
    }

    pub(super) fn validate(&self, config: &Aic2Config) -> Result<u64, &'static str> {
        if self.dies.is_empty()
            || self.dies.len() > usize::from(self.max_dies)
            || self.max_dies > 15
        {
            return Err("AIC populated dies must fit the nonzero four-bit MAX_DIE capacity");
        }
        if self.dies[0].irq_config != config.irq_config {
            return Err("AIC IRQ_CFG disagrees with the first die's explicit layout");
        }
        // Reserve complete banks, including unused IRQ entries. They are
        // not aliases for another die, timestamp or capability register.
        let mut ranges = Vec::new();
        for offset in [VERSION, self.info1, self.info3, CONFIG, config.event_offset] {
            ranges.push((offset, 4));
        }
        if config.timestamps != 0 {
            let bytes = TIMESTAMP_STRIDE
                .checked_mul(config.timestamps as u64)
                .ok_or("AIC timestamp register extent overflows")?;
            ranges.push((config.timestamp_base, bytes));
        }
        let bits_bytes = 4 * u64::from(config.max_irq / 32);
        for die in &self.dies {
            for (index, offset) in die.banks().into_iter().enumerate() {
                ranges.push((
                    offset,
                    if index == 0 {
                        4 * u64::from(config.max_irq)
                    } else {
                        bits_bytes
                    },
                ));
            }
        }
        ranges.sort_unstable();
        let mut end = 0;
        for (offset, bytes) in ranges {
            if !offset.is_multiple_of(4) || offset < end {
                return Err("AIC register banks overlap or are not word aligned");
            }
            end = offset
                .checked_add(bytes)
                .ok_or("AIC register extent overflows")?;
        }
        Ok(end)
    }
}
