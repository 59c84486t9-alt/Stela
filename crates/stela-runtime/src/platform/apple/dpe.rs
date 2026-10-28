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
//!
//! Retained clock/quiesce pauses preserve all controls and sample aliases.
//! Nonzero sampling controls, physical reset and rail loss require unqualified
//! hardware sampling/restoration effects and refuse before commit. Clock-stop
//! MMIO availability is unqualified; quiesce permits nonmutating reads. This
//! native-bank hook does not establish its implicit PMGR domain association.
use super::regfile::Held;
use alloc::{collections::BTreeMap, vec::Vec};
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction, stela_contracts::bus::Lifecycle,
    stela_contracts::bus::LifecycleState, stela_contracts::bus::MmioDevice,
    stela_contracts::bus::MmioError, stela_contracts::bus::Width, stela_contracts::bus::refuse,
};
const NAME: &str = "soc-dpe";
pub const ENGINES: [u64; 6] = [0x2400, 0x2800, 0x2c00, 0x3000, 0x3400, 0x3800];
pub const CONTROLS: [u64; 3] = [0, 0x200, 0x300];
pub const RESTORE: [u64; 3] = [0x2708, 0x2b08, 0x3308];
#[derive(Debug, Clone)]
pub struct Dpe {
    lifecycle: LifecycleState,
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
            lifecycle: LifecycleState {
                powered: true,
                clocked: true,
                quiesced: false,
                reset: false,
                retention: true,
            },
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
impl Lifecycle for Dpe {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<(), &'static str> {
        if !proposed.powered || proposed.reset {
            return Err(
                "SOC DPE physical reset/supply retention and protected sample restoration are unqualified",
            );
        }
        if (!proposed.clocked || proposed.quiesced)
            && self
                .controls
                .iter()
                .any(|&offset| self.values.get(offset) != 0)
        {
            return Err("SOC DPE pause with nonzero sampling controls is unqualified");
        }
        Ok(())
    }
    fn set_lifecycle(&mut self, proposed: LifecycleState, _: &mut Access<'_>) {
        self.lifecycle = proposed;
    }
}
impl MmioDevice for Dpe {
    fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
        Some(self)
    }
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(&mut self, o: u64, w: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        if !self.lifecycle.clocked {
            return Err(refuse(
                NAME,
                o,
                w,
                Direction::Read,
                "SOC DPE MMIO while the physical clock is stopped is unqualified",
            ));
        }
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
        if !self.lifecycle.clocked || self.lifecycle.quiesced {
            return Err(refuse(
                NAME,
                o,
                w,
                Direction::Write,
                "SOC DPE register changes are paused",
            ));
        }
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
    use stela_contracts::interrupt::InterruptLatch;
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
    #[test]
    fn inactive_sampling_pauses_preserve_full_samples_and_independent_clock_quiesce() {
        let mut d = Dpe::new(&[(0x200, false)]).unwrap();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        let running = d.lifecycle;
        d.write(0x2708, Width::Double, 0x1234_5678_9abc_def0, &mut a)
            .unwrap();
        let paused = LifecycleState {
            clocked: false,
            quiesced: true,
            ..running
        };
        d.check_lifecycle(paused).unwrap();
        d.set_lifecycle(paused, &mut a);
        assert!(d.read(0x2708, Width::Double, &mut a).is_err());
        assert!(d.write(0x2708, Width::Double, 0, &mut a).is_err());
        let quiesced = LifecycleState {
            clocked: true,
            ..paused
        };
        d.check_lifecycle(quiesced).unwrap();
        d.set_lifecycle(quiesced, &mut a);
        assert_eq!(d.read(0x2708, Width::Word, &mut a), Ok(0x9abc_def0));
        assert_eq!(d.read(0x270c, Width::Word, &mut a), Ok(0x1234_5678));
        assert!(d.write(0x2400, Width::Word, 1, &mut a).is_err());
        d.check_lifecycle(running).unwrap();
        d.set_lifecycle(running, &mut a);
        assert_eq!(
            d.read(0x2708, Width::Double, &mut a),
            Ok(0x1234_5678_9abc_def0)
        );
    }
    #[test]
    fn every_sampling_control_and_destructive_state_preflights_before_any_change() {
        let mut d = Dpe::new(&[]).unwrap();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        let running = d.lifecycle;
        d.write(0x2708, Width::Double, 17, &mut a).unwrap();
        for offset in d.controls.clone() {
            // Higher configuration bits are not proof that a sampler is idle.
            d.write(offset, Width::Word, 0x100, &mut a).unwrap();
            for proposed in [
                LifecycleState {
                    clocked: false,
                    ..running
                },
                LifecycleState {
                    quiesced: true,
                    ..running
                },
            ] {
                assert!(d.check_lifecycle(proposed).is_err());
                assert_eq!(d.lifecycle, running);
                assert_eq!(d.read(offset, Width::Word, &mut a), Ok(0x100));
                assert_eq!(d.read(0x2708, Width::Double, &mut a), Ok(17));
            }
            d.write(offset, Width::Word, 0, &mut a).unwrap();
        }
        for proposed in [
            LifecycleState {
                reset: true,
                ..running
            },
            LifecycleState {
                powered: false,
                retention: true,
                ..running
            },
            LifecycleState {
                powered: false,
                retention: false,
                ..running
            },
        ] {
            assert!(d.check_lifecycle(proposed).is_err());
            assert_eq!(d.lifecycle, running);
            assert_eq!(d.read(0x2708, Width::Double, &mut a), Ok(17));
        }
    }
    #[test]
    fn mounted_saved_counter_aliases_keep_the_same_lifecycle_owner() {
        use alloc::boxed::Box;
        use stela_contracts::bus::Bus;
        let mut bus = Bus::new();
        let device = bus.add(Box::new(Dpe::new(&[]).unwrap()));
        bus.map(device, 0x10000, 8, 0x2708).unwrap();
        bus.map(device, 0x20000, 8, 0x2708).unwrap();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 0, &mut latch);
        bus.write(0x10000, Width::Double, 0x9876_5432_1234_5678, &mut a)
            .unwrap();
        let paused = LifecycleState {
            powered: true,
            clocked: false,
            quiesced: true,
            reset: false,
            retention: true,
        };
        let lifecycle = bus.lifecycle(device).unwrap();
        lifecycle.check_lifecycle(paused).unwrap();
        lifecycle.set_lifecycle(paused, &mut a);
        assert!(bus.read(0x10000, Width::Double, &mut a).is_err());
        assert!(bus.read(0x20000, Width::Word, &mut a).is_err());
        let running = LifecycleState {
            clocked: true,
            quiesced: false,
            ..paused
        };
        let lifecycle = bus.lifecycle(device).unwrap();
        lifecycle.check_lifecycle(running).unwrap();
        lifecycle.set_lifecycle(running, &mut a);
        assert_eq!(bus.read(0x20000, Width::Word, &mut a), Ok(0x1234_5678));
        assert_eq!(bus.read(0x20004, Width::Word, &mut a), Ok(0x9876_5432));
    }
    #[cfg(feature = "std")]
    #[test]
    #[ignore = "requires STELA_TEST_PMGR_KERNELCACHE naming the pinned original 26A434 Mach-O"]
    fn original_dpe_map_controls_and_samples_do_not_encode_physical_reset() {
        use sha2::{Digest, Sha256};
        let path =
            std::env::var_os("STELA_TEST_PMGR_KERNELCACHE").expect("original KernelCache path");
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "06846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d"
        );
        for (offset, opcode) in [
            (0x2fa348c, 0x528009c1u32),
            (0x2fa3490, 0x528003a2u32),
            (0x2fa5ff4, 0x36000fc8u32),
            (0x2fa6024, 0x528000d7u32),
            (0x2fa6050, 0x11080282u32),
            (0x2fa6094, 0x32000003u32),
            (0x2fa6164, 0x110c0282u32),
            (0x2fa61ac, 0x32000003u32),
        ] {
            assert_eq!(
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()),
                opcode,
                "original opcode at {offset:#x}"
            );
        }
        let controls: Vec<u64> = bytes[0x7957d4..0x7957d4 + 24]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u64::from(u32::from_le_bytes(*word)))
            .collect();
        assert_eq!(controls, ENGINES);
    }
    #[cfg(feature = "std")]
    #[test]
    #[ignore = "requires STELA_TEST_PMGR_M1_KERNELCACHE naming the pinned original mac13j 26A434 Mach-O"]
    fn original_m1_dpe_geometry_does_not_qualify_the_t8112_bank() {
        use sha2::{Digest, Sha256};
        let path = std::env::var_os("STELA_TEST_PMGR_M1_KERNELCACHE")
            .expect("original M1 Pro KernelCache path");
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "5109fca5209bdbb89cec29e3241cc42a90418cb737d65e31962b059b9879af90"
        );
        // AppleT6000PMGR binds RegMap 4e to reg[42], not T8112 reg[29].
        assert_eq!(
            &bytes[0x2ef531c..0x2ef5324],
            &[0xc1, 9, 0x80, 0x52, 0x42, 5, 0x80, 0x52]
        );
        let engines: Vec<u64> = bytes[0x76d048..0x76d048 + 36]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u64::from(u32::from_le_bytes(*word)))
            .collect();
        assert_eq!(
            engines,
            [
                0x2400, 0x2800, 0x2c00, 0x3000, 0x3400, 0x3800, 0x4000, 0x4400, 0x3c00
            ]
        );
        assert_ne!(engines, ENGINES);
        // Retain complete original group and restore programs: their sampling
        // slots/enable predicates must be qualified before mounting this family.
        for (offset, len, digest) in [
            (
                0x2ef5390,
                512,
                "52c58b510bd65b728b2df5696128856f55a3b7f6e5c751e3cfac102acb35194c",
            ),
            (
                0x2f0ab08,
                552,
                "ed743791e8c6b28b6beb15a7ea4aad604cfd5beddaaf800270d053892de9a891",
            ),
        ] {
            assert_eq!(
                hex::encode(Sha256::digest(&bytes[offset..offset + len])),
                digest
            );
        }
    }
}
