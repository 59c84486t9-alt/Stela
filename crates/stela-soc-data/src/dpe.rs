//! Validated SOC DPE register geometry and sample aliases.
//! This describes controls and sample widths without allocating counter
//! state, sampling activity, completion or lifecycle permission.
use crate::Result;
use alloc::{collections::BTreeMap, vec::Vec};
use stela_contracts::refuse;

pub const ENGINES: [u64; 6] = [0x2400, 0x2800, 0x2c00, 0x3000, 0x3400, 0x3800];
pub const CONTROLS: [u64; 3] = [0, 0x200, 0x300];
pub const RESTORE: [u64; 3] = [0x2708, 0x2b08, 0x3308];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    samples: BTreeMap<u64, bool>,
}
impl Layout {
    pub fn new(samples: &[(u64, bool)]) -> Result<Self> {
        let mut described = BTreeMap::new();
        for &(offset, restore) in samples {
            if !offset.is_multiple_of(8)
                || offset.checked_add(8).is_none()
                || Self::controls().any(|c| (offset..offset + 8).contains(&c))
                || described.insert(offset, restore).is_some()
            {
                return Err(refuse!("invalid or duplicate SOC DPE sample offset"));
            }
        }
        // Reporting records and RegGroup save slots are separate sources.
        // Restore slots exist independently and keep their full-width alias.
        for offset in RESTORE {
            described.insert(offset, true);
        }
        Ok(Self { samples: described })
    }
    pub fn controls() -> impl Iterator<Item = u64> {
        ENGINES.into_iter().flat_map(|e| CONTROLS.map(|c| e + c))
    }
    pub fn samples(&self) -> impl Iterator<Item = (u64, bool)> + '_ {
        self.samples
            .iter()
            .map(|(&offset, &restore)| (offset, restore))
    }
    pub fn spans(&self) -> Vec<(u64, u64)> {
        Self::controls()
            .map(|offset| (offset, 4))
            .chain(self.samples.keys().map(|&offset| (offset, 8)))
            .collect()
    }
}
