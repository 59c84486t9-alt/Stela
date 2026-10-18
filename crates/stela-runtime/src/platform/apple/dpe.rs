//! SOC DPE engines (`AppleT8112PMGR::restoreSOCDPE`, kernel file 0x2fa5fe4):
//! six engine offsets at 0x7957d4, each with full32 enable words at +0,
//! +0x200 and +0x300. RegMap 0x4e binds to PMGR reg[29]; `hw-dpe-reg`
//! supplies absolute sample PAs and split-read flags. RegGroups 0x1d/0x1f/
//! 0x1e bind restore samples at bank+0x2708/0x2b08/0x3308 (initRegGroups,
//! 0x2fa3620; snapshot/restore 0x2b840f0/0x2b87eec).
//!
//! Stela hands off disabled zero controls and empty samples. The emulated
//! die has no physical DPE energy activity: counts retain software saves.
//! Each high/low alias shares a full64 accumulator, so high/low/high sampling
//! is coherent. Only restore-capable samples accept full64 reads/writes;
//! other samples expose the DT's split32 read contract. No guessed rates,
//! conversion parameters, status or unlisted engine words are returned.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use super::regfile::Held;
use alloc::{collections::BTreeMap, vec::Vec};
const NAME: &str = "soc-dpe";
pub const ENGINES: [u64; 6] = [0x2400, 0x2800, 0x2c00, 0x3000, 0x3400, 0x3800];
pub const CONTROLS: [u64; 3] = [0, 0x200, 0x300];
pub const RESTORE: [u64; 3] = [0x2708, 0x2b08, 0x3308];
#[derive(Debug, Clone)]
pub struct Dpe {
    controls: Vec<u64>,
    values: Held,
    samples: BTreeMap<u64, (u64, bool)>,
}
impl Dpe {
    pub fn new(samples: &[(u64, bool)]) -> Result<Self, &'static str> {
        let controls: Vec<u64> = ENGINES
            .iter()
            .flat_map(|e| CONTROLS.map(|c| e + c))
            .collect();
        let mut counts = BTreeMap::new();
        for &(offset, restore) in samples {
            if !offset.is_multiple_of(8)
                || offset.checked_add(8).is_none()
                || controls.iter().any(|&c| (offset..offset + 8).contains(&c))
                || counts.insert(offset, (0, restore)).is_some()
            {
                return Err("invalid or duplicate SOC DPE sample offset");
            }
        }
        // Reporting records and RegGroup save slots are distinct address
        // sources. The DT's AVE/MSR/DCS/DRAM samples are +2f08/+3308/
        // +3708/+3b08; restore also owns +2708 and +2b08 independently.
        for offset in RESTORE {
            counts
                .entry(offset)
                .and_modify(|sample| sample.1 = true)
                .or_insert((0, true));
        }
        Ok(Self {
            controls,
            values: Held::default(),
            samples: counts,
        })
    }
    pub fn spans(&self) -> Vec<(u64, u64)> {
        self.controls
            .iter()
            .map(|&o| (o, 4))
            .chain(self.samples.keys().map(|&o| (o, 8)))
            .collect()
    }
    fn sample(
        &mut self,
        offset: u64,
        width: Width,
        write: bool,
    ) -> Result<(&mut u64, bool), &'static str> {
        let base = offset & !7;
        let (count, restore) = self
            .samples
            .get_mut(&base)
            .ok_or("undescribed SOC DPE register")?;
        if width == Width::Double && offset == base && *restore
            || !write && width == Width::Word && offset.is_multiple_of(4)
        {
            Ok((count, offset != base))
        } else {
            Err("SOC DPE sample access without a described width or restore operation")
        }
    }
}
impl MmioDevice for Dpe {
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(&mut self, o: u64, w: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        if self.controls.contains(&o) && w == Width::Word {
            return Ok(self.values.get(o));
        }
        self.sample(o, w, false)
            .map(|(v, high)| {
                if w == Width::Double {
                    *v
                } else if high {
                    *v >> 32
                } else {
                    *v & u64::from(u32::MAX)
                }
            })
            .map_err(|r| refuse(NAME, o, w, Direction::Read, r))
    }
    fn write(&mut self, o: u64, w: Width, v: u64, _: &mut Access<'_>) -> Result<(), MmioError> {
        if self.controls.contains(&o) && w == Width::Word {
            self.values.set(o, v & w.mask());
            return Ok(());
        }
        self.sample(o, w, true)
            .map(|(count, _)| *count = v)
            .map_err(|r| refuse(NAME, o, w, Direction::Write, r))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;
    #[test]
    fn restore_slots_and_dt_reporting_samples_are_independent_address_sources() {
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        let mut d = Dpe::new(&[
            (0x2f08, false),
            (0x3308, false),
            (0x3708, false),
            (0x3b08, false),
        ])
        .unwrap();
        for offset in RESTORE {
            d.write(offset, Width::Double, 0xabcdef0123456789, &mut a)
                .unwrap();
            assert_eq!(
                d.read(offset, Width::Double, &mut a),
                Ok(0xabcdef0123456789)
            );
        }
        for offset in [0x2f08, 0x3708, 0x3b08] {
            assert_eq!(d.read(offset, Width::Word, &mut a), Ok(0));
            assert!(d.write(offset, Width::Double, 0, &mut a).is_err());
        }
    }

    #[test]
    fn aliases_share_saved_samples_and_disabled_handoff_controls_hold_rmw() {
        let mut sink = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut sink);
        let mut d = Dpe::new(&[(0x200, false), (0x2708, true)]).unwrap();
        for e in ENGINES {
            for c in CONTROLS {
                assert_eq!(d.read(e + c, Width::Word, &mut a), Ok(0));
                d.write(e + c, Width::Word, 0x123 | 1, &mut a).unwrap();
                assert_eq!(d.read(e + c, Width::Word, &mut a), Ok(0x123));
            }
        }
        assert_eq!(d.read(0x200, Width::Word, &mut a), Ok(0));
        d.write(0x2708, Width::Double, 0x1234_5678_9abc_def0, &mut a)
            .unwrap();
        assert_eq!(d.read(0x2708, Width::Word, &mut a), Ok(0x9abc_def0));
        assert_eq!(d.read(0x270c, Width::Word, &mut a), Ok(0x1234_5678));
        assert_eq!(
            d.read(0x2708, Width::Double, &mut a),
            Ok(0x1234_5678_9abc_def0)
        );
        for (o, w) in [
            (0x200, Width::Double),
            (0x2708, Width::Word),
            (0x270c, Width::Word),
            (0x2710, Width::Double),
        ] {
            assert!(d.write(o, w, 7, &mut a).is_err());
        }
        assert!(d.read(0x2404, Width::Word, &mut a).is_err());
        assert!(d.read(0x2709, Width::Byte, &mut a).is_err());
        assert!(Dpe::new(&[(0x2400, true)]).is_err());
        assert!(Dpe::new(&[(0x200, false), (0x200, true)]).is_err());
    }
}
