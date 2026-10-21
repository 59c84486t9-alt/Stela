//! PMGR SOC power configuration, placed by the DT `reg` map bindings of
//! `AppleT8112PMGR::initRegMaps` (kernel file 0x2fa31bc..0x2fa3620).
//!
//! VOLMAN (reg[31]): `restoreHW` 0x2fa3c80 checks channel bit24 before
//! clearing configuration, acknowledges channels at +0x24, enables the mask
//! at +0x3f8, and finalizes at +0x3fc. `panicOnDvcDoneErr` 0x2fa3e18 tests
//! low8 (optionally also bits23:16). Low8 writes acknowledge (W1C inference),
//! never inject errors. Actual supplied error/status bits remain visible.
//! A protected channel cannot be rewritten; other configuration words retain full writes.
//!
//! The PS marker (reg[30]+0x17ffc, restoreHW 0x2fa3d88) is a firmware-owned
//! read-only whole-word marker, distinct from the `ps-regs` device registers.
//! GPCE (reg[34], `configCPUComplexPowerState` 0x2f9cab4) retains each complex's
//! low4 request (0/f), preserving the other captured fields. The driver waits
//! for bit4 clear; that expectation is not proof that a request completes.
//! Request writes retain pending ownership and invalidate readiness observation
//! until native controller progress is qualified. They never clear BUSY or
//! claim a native sequence/CPU lifecycle completed.
//!
//! CIO (reg[41], `enableCioReconfig` 0x2fa5a44) reads offsets0x4000/0x8000,
//! sets request bit0 and waits for actual mask2 clearance. The false path
//! performs no access. Both port requests preserve unrelated captured fields,
//! including a same-value request, without selecting an invented native PC.
//! Captured GPCE/CIO unready observations remain explicit even before a new
//! request; a snapshot must not turn prior native work into an empty idle queue.
//!
//! LLB `tunableh_pmgr_soc_gpce0_finalize` (file9c26c/9c2dc) has two actual
//! auxiliary RMWs at +2008/+200c, mask1/set0. Their configuration effects are
//! retained without qualifying the distinct native rearm or engine progress.
//!
//! Power-gate enables (reg[32], restoreHW 0x2f9cc3c and
//! `_enableCPMPowerDomainGating` 0x2f9fd88) retain bit31 and other RMW fields.
//! They permit automatic gating without inventing an electrical idle event.
//! TVM (reg[35], `enableTVM` 0x2fa61f0) has four0x400-spaced controls/status
//! pairs. Configuration does not establish zero pending voltage/thermal status.
//!
//! `new` has unknown handoff words. `from_snapshot` requires every actual bank
//! word; no zero marker, unlocked channel, disabled request or healthy status
//! is inferred from firmware/DT absence. Supplied snapshots grant register
//! observations only, not native execution, functional ownership or PS values.
pub mod t6000;

use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

const NAME: &str = "soc-power";
const STATUS: u64 = 0x24;
const CHANNEL: core::ops::Range<u64> = 0x30..0x50;
const LOCK: u64 = 1 << 24;
const ACK: u64 = 0xff;
const MASK: u64 = 0x3f8;
const FINAL: u64 = 0x3fc;
const REQUEST: u64 = 0xf;
const BUSY: u64 = 1 << 4;
const CIO_REQUEST: u32 = 1;
const CIO_WAIT: u32 = 2;
pub const MARKER: u64 = 0x17ffc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Volman,
    Marker,
    Gpce,
    /// T8112 original RegMap0x63/reg41: both CIO reconfiguration words.
    Cio,
    /// LLB's source GPCE0 finalizer auxiliary controls, not a native PC/status bank.
    GpceFinalize,
    /// Exact T8112 native sequence/table configuration words, placed at their
    /// physical-address offsets. No status, trigger or SRAM aperture is implied.
    NubBindings,
    Gating,
    Tvm,
}

impl Kind {
    pub fn offsets(self) -> Vec<u64> {
        match self {
            Self::Volman => [
                alloc::vec![STATUS, MASK, FINAL],
                CHANNEL.step_by(4).collect(),
            ]
            .concat(),
            Self::Marker => alloc::vec![MARKER],
            Self::Gpce => alloc::vec![0, 4],
            Self::Cio => alloc::vec![0x4000, 0x8000],
            Self::GpceFinalize => alloc::vec![0x2008, 0x200c],
            Self::NubBindings => {
                let mut offsets = alloc::vec![
                    0x23d2d0200,
                    0x23d2d0300,
                    0x23b781000,
                    0x23b78d000,
                    0x23b781004,
                    0x23b781008,
                    0x23b78d004
                ];
                for base in [0x23d2d0200, 0x23d2d0300] {
                    offsets.extend((4..=0x18).step_by(4).map(|offset| base + offset));
                }
                offsets
            }
            Self::Gating => alloc::vec![0, 0x40, 0x80, 0x88],
            Self::Tvm => [0, 0x400, 0x800, 0xc00]
                .into_iter()
                .flat_map(|o| [o, o + 0x3e0])
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotError {
    UnknownOffset(u64),
    Duplicate(u64),
    Missing(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GpceRequest {
    pub offset: u64,
    pub previous: u32,
    pub written: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CioRequest {
    pub offset: u64,
    pub previous: u32,
    pub written: u32,
}

/// A captured driver wait condition was not ready. The observation alone
/// does not reconstruct the native work/PC that must eventually satisfy it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnresolvedReadiness {
    pub offset: u64,
    pub observed: u32,
    pub mask: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigurationRequest {
    pub offset: u64,
    pub previous: u32,
    pub written: u32,
}

#[derive(Debug, Clone, Copy)]
struct Word {
    value: u32,
    known: u32,
}
impl Word {
    fn captured(value: u32) -> Self {
        Self {
            value,
            known: u32::MAX,
        }
    }
}

#[derive(Debug)]
pub struct Power {
    kind: Kind,
    registers: BTreeMap<u64, Word>,
    gpce: Vec<GpceRequest>,
    cio: Vec<CioRequest>,
    unresolved_readiness: Vec<UnresolvedReadiness>,
    pending_configuration: Vec<ConfigurationRequest>,
}
impl Power {
    pub fn new(kind: Kind) -> Self {
        Self {
            kind,
            registers: BTreeMap::new(),
            gpce: Vec::new(),
            cio: Vec::new(),
            unresolved_readiness: Vec::new(),
            pending_configuration: Vec::new(),
        }
    }
    pub fn from_snapshot(
        kind: Kind,
        words: impl IntoIterator<Item = (u64, u32)>,
    ) -> Result<Self, SnapshotError> {
        let mut model = Self::new(kind);
        let offsets = kind.offsets();
        for (offset, value) in words {
            if !offsets.contains(&offset) {
                return Err(SnapshotError::UnknownOffset(offset));
            }
            if model
                .registers
                .insert(offset, Word::captured(value))
                .is_some()
            {
                return Err(SnapshotError::Duplicate(offset));
            }
        }
        for offset in offsets {
            if !model.registers.contains_key(&offset) {
                return Err(SnapshotError::Missing(offset));
            }
            let mask = match kind {
                Kind::Gpce => BUSY as u32,
                Kind::Cio => CIO_WAIT,
                _ => 0,
            };
            let observed = model.registers[&offset].value;
            if observed & mask != 0 {
                model.unresolved_readiness.push(UnresolvedReadiness {
                    offset,
                    observed,
                    mask,
                });
            }
        }
        Ok(model)
    }
    pub fn pending_gpce(&self) -> impl Iterator<Item = GpceRequest> + '_ {
        self.gpce.iter().copied()
    }
    pub fn pending_cio(&self) -> impl Iterator<Item = CioRequest> + '_ {
        self.cio.iter().copied()
    }
    pub fn unresolved_readiness(&self) -> impl Iterator<Item = UnresolvedReadiness> + '_ {
        self.unresolved_readiness.iter().copied()
    }
    pub fn pending_configuration(&self) -> impl Iterator<Item = ConfigurationRequest> + '_ {
        self.pending_configuration.iter().copied()
    }
    fn check(&self, offset: u64, width: Width) -> Result<(), &'static str> {
        if width != Width::Word || !self.kind.offsets().contains(&offset) {
            return Err("SOC power register or width without described meaning");
        }
        Ok(())
    }
    fn observed(&self, offset: u64) -> Result<u32, &'static str> {
        let word = self
            .registers
            .get(&offset)
            .ok_or("SOC power handoff register value is unknown")?;
        if word.known != u32::MAX {
            return Err("SOC power native readiness/status progression is unqualified");
        }
        Ok(word.value)
    }
    fn invalidate(&mut self, offset: u64, mask: u32) {
        if let Some(word) = self.registers.get_mut(&offset) {
            word.known &= !mask;
        }
    }
}
impl MmioDevice for Power {
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Read, reason);
        self.check(offset, width).map_err(fail)?;
        self.observed(offset).map(u64::from).map_err(fail)
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        self.check(offset, width).map_err(fail)?;
        let value = value as u32;
        let old = self.observed(offset).map_err(fail)?;
        if self.kind != Kind::NubBindings
            && self
                .pending_configuration
                .iter()
                .any(|request| request.offset == offset)
        {
            return Err(fail(
                "SOC power configuration retains an earlier native request",
            ));
        }
        match self.kind {
            Kind::Tvm if offset % 0x400 == 0x3e0 => return Err(fail("TVM status is read-only")),
            Kind::Marker => {
                return Err(fail("PS initialization marker is owned by the boot stage"));
            }
            Kind::Volman if offset == STATUS => {
                if u64::from(value) & !ACK != 0 {
                    return Err(fail(
                        "VOLMAN acknowledgement outside the described low8 channels",
                    ));
                }
                self.registers.insert(offset, Word::captured(old & !value));
                return Ok(());
            }
            Kind::Volman
                if CHANNEL.contains(&offset) && u64::from(old) & LOCK != 0 && old != value =>
            {
                return Err(fail("VOLMAN channel configuration is protected by bit24"));
            }
            Kind::Volman if offset == FINAL && value & !1 != 0 => {
                return Err(fail(
                    "VOLMAN finalization fields other than bit0 are undescribed",
                ));
            }
            Kind::NubBindings => {
                let (mask, may_clear) = nub_fields(offset);
                // Table bases are blind source writes of an encoded fragment;
                // captured nonfragment fields cannot silently be cleared.
                if !may_clear && (value & !mask != old & !mask || old & mask & !value != 0) {
                    return Err(fail(
                        "NUB slot programming only qualifies source OR field updates",
                    ));
                }
                if may_clear
                    && !matches!(
                        offset,
                        0x23d2d0200 | 0x23d2d0300 | 0x23b781000 | 0x23b78d000
                    )
                    && ![0, 16].into_iter().any(|shift| {
                        (value ^ old) & !(0x11f << shift) == 0 && value & (0x100 << shift) != 0
                    })
                {
                    return Err(fail(
                        "NUB sequence update must replace one slot, set its enable and preserve other fields",
                    ));
                }
                if matches!(
                    offset,
                    0x23d2d0200 | 0x23d2d0300 | 0x23b781000 | 0x23b78d000
                ) {
                    if value & !mask != 0 {
                        return Err(fail("NUB table base outside source encoded fragment"));
                    }
                    if old & !mask != 0 {
                        return Err(fail(
                            "NUB table write would alter unqualified nonfragment fields",
                        ));
                    }
                    self.registers.insert(offset, Word::captured(value));
                } else {
                    self.registers.insert(offset, Word::captured(value));
                }
                self.pending_configuration.push(ConfigurationRequest {
                    offset,
                    previous: old,
                    written: value,
                });
                return Ok(());
            }
            Kind::Gpce => {
                if !matches!(u64::from(value) & REQUEST, 0 | REQUEST) {
                    return Err(fail("unsupported partial GPCE complex request"));
                }
                if (value ^ old) & !(REQUEST as u32) != 0 {
                    return Err(fail(
                        "GPCE request must preserve captured nonrequest fields",
                    ));
                }
                self.registers.insert(
                    offset,
                    Word {
                        value,
                        known: !(BUSY as u32),
                    },
                );
                self.gpce.push(GpceRequest {
                    offset,
                    previous: old,
                    written: value,
                });
                return Ok(());
            }
            Kind::Cio => {
                // enableCioReconfig(false) returns without touching a bank.
                // Its true path always writes read32 | 1, even if bit0 was
                // already set; equal data is not evidence of no trigger.
                if value != old | CIO_REQUEST {
                    return Err(fail(
                        "CIO reconfiguration only qualifies preserving fields and setting request bit0",
                    ));
                }
                self.registers.insert(
                    offset,
                    Word {
                        value,
                        known: !CIO_WAIT,
                    },
                );
                self.cio.push(CioRequest {
                    offset,
                    previous: old,
                    written: value,
                });
                return Ok(());
            }
            Kind::GpceFinalize => {
                if value != old & !1 {
                    return Err(fail(
                        "GPCE finalization only qualifies clearing bit0 and preserving captured other fields",
                    ));
                }
                self.registers.insert(offset, Word::captured(value));
                self.pending_configuration.push(ConfigurationRequest {
                    offset,
                    previous: old,
                    written: value,
                });
                return Ok(());
            }
            _ => {}
        }
        self.registers.insert(offset, Word::captured(value));
        match self.kind {
            Kind::Tvm => {
                self.invalidate(offset + 0x3e0, u32::MAX);
                self.pending_configuration.push(ConfigurationRequest {
                    offset,
                    previous: old,
                    written: value,
                });
            }
            Kind::Volman if offset == FINAL && value == 1 => {
                self.invalidate(STATUS, u32::MAX);
                self.pending_configuration.push(ConfigurationRequest {
                    offset,
                    previous: old,
                    written: value,
                });
            }
            _ => {}
        }
        Ok(())
    }
    fn advance(&mut self, _: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
        if !self.gpce.is_empty()
            || !self.cio.is_empty()
            || !self.pending_configuration.is_empty()
            || !self.unresolved_readiness.is_empty()
        {
            return Err(refuse(
                NAME,
                0,
                Width::Word,
                Direction::Read,
                "SOC power request retains unqualified native controller progress",
            ));
        }
        Ok(None)
    }
}

/// Only installation configuration fields are qualified here. Source group2/3
/// helpers OR slots; group0/1 replace one slot and set its independent enable.
fn nub_fields(offset: u64) -> (u32, bool) {
    match offset {
        0x23d2d0200 | 0x23d2d0300 => (0x3ff00, true),
        0x23b781000 | 0x23b78d000 => (0xfffffff, true),
        0x23b781004 | 0x23b781008 => (0x1f | (0x1f << 16), false),
        0x23b78d004 => (0x3ff, false),
        _ => (0x11f | (0x11f << 16), true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::{bus::Bus, interrupt::InterruptLatch};
    use alloc::boxed::Box;

    fn snapshot(kind: Kind, value: u32) -> Power {
        Power::from_snapshot(
            kind,
            kind.offsets().into_iter().map(|offset| (offset, value)),
        )
        .unwrap()
    }
    #[test]
    fn unknown_handoff_is_never_zero_marker_unlocked_channel_or_healthy_status() {
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        for kind in [
            Kind::Volman,
            Kind::Marker,
            Kind::Gpce,
            Kind::Cio,
            Kind::GpceFinalize,
            Kind::NubBindings,
            Kind::Gating,
            Kind::Tvm,
        ] {
            let mut model = Power::new(kind);
            for offset in kind.offsets() {
                assert!(matches!(
                    model.read(offset, Width::Word, &mut access),
                    Err(MmioError::Unsupported {
                        reason: "SOC power handoff register value is unknown",
                        ..
                    })
                ));
                assert!(model.write(offset, Width::Word, 0, &mut access).is_err());
            }
            assert!(model.pending_gpce().next().is_none());
        }
        assert!(matches!(
            Power::from_snapshot(Kind::Gpce, [(0, 0)]),
            Err(SnapshotError::Missing(4))
        ));
        assert!(matches!(
            Power::from_snapshot(Kind::Gpce, [(0, 0), (0, 0)]),
            Err(SnapshotError::Duplicate(0))
        ));
        assert!(matches!(
            Power::from_snapshot(Kind::Gpce, [(8, 0)]),
            Err(SnapshotError::UnknownOffset(8))
        ));
    }
    #[test]
    fn mounted_gpce_preserves_real_busy_and_retains_request_without_fake_readiness() {
        let mut bus = Bus::new();
        let id = bus.add(Box::new(
            Power::from_snapshot(Kind::Gpce, [(0, 0x120), (4, 0x830)]).unwrap(),
        ));
        bus.map(id, 0x23b780000, 8, 0).unwrap();
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        assert_eq!(bus.read(0x23b780004, Width::Word, &mut access), Ok(0x830));
        bus.write(0x23b780000, Width::Word, 0x12f, &mut access)
            .unwrap();
        assert!(bus.read(0x23b780000, Width::Word, &mut access).is_err());
        assert_eq!(bus.read(0x23b780004, Width::Word, &mut access), Ok(0x830));
        // Software cannot clear BUSY or overwrite the first pending request.
        assert!(
            bus.write(0x23b780000, Width::Word, 0x120, &mut access)
                .is_err()
        );
        let model = bus.device_mut::<Power>(id).unwrap();
        assert_eq!(
            model.pending_gpce().collect::<Vec<_>>(),
            [GpceRequest {
                offset: 0,
                previous: 0x120,
                written: 0x12f
            }]
        );
        assert!(model.advance(&mut access).is_err());
        assert_eq!(model.pending_gpce().count(), 1);
        assert!(model.write(4, Width::Word, 0x82f, &mut access).is_err());
        assert!(model.write(4, Width::Word, 0x833, &mut access).is_err());
        assert_eq!(model.read(4, Width::Word, &mut access), Ok(0x830));
    }

    #[test]
    fn mounted_cio_preserves_both_ports_and_request_ownership_before_unknown_pc_selection() {
        let mut bus = Bus::new();
        let id = bus.add(Box::new(
            Power::from_snapshot(Kind::Cio, [(0x4000, 0xa0), (0x8000, 0xb1)]).unwrap(),
        ));
        bus.map(id, 0x23b78c000, 0x9000, 0).unwrap();
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        // Refuse a made-up disable and unrelated field changes before effects.
        assert!(
            bus.write(0x23b794000, Width::Word, 0xb0, &mut access)
                .is_err()
        );
        assert!(
            bus.write(0x23b790000, Width::Word, 0x81, &mut access)
                .is_err()
        );
        assert_eq!(bus.read(0x23b794000, Width::Word, &mut access), Ok(0xb1));
        // A same-value bit0 request is still an owned original write. Never
        // mark it idempotent or use it to claim an already completed program.
        bus.write(0x23b794000, Width::Word, 0xb1, &mut access)
            .unwrap();
        assert!(bus.read(0x23b794000, Width::Word, &mut access).is_err());
        assert!(
            bus.write(0x23b794000, Width::Word, 0xb1, &mut access)
                .is_err()
        );
        assert_eq!(bus.read(0x23b790000, Width::Word, &mut access), Ok(0xa0));
        bus.write(0x23b790000, Width::Word, 0xa1, &mut access)
            .unwrap();
        let model = bus.device_mut::<Power>(id).unwrap();
        assert_eq!(
            model.pending_cio().collect::<Vec<_>>(),
            [
                CioRequest {
                    offset: 0x8000,
                    previous: 0xb1,
                    written: 0xb1
                },
                CioRequest {
                    offset: 0x4000,
                    previous: 0xa0,
                    written: 0xa1
                },
            ]
        );
        assert!(model.advance(&mut access).is_err());
        assert_eq!(model.pending_cio().count(), 2);
        assert!(model.read(0, Width::Word, &mut access).is_err());
        assert!(model.read(0x4000, Width::Double, &mut access).is_err());
    }

    #[test]
    fn captured_unready_gpce_and_cio_work_cannot_become_an_empty_idle_queue() {
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        for (kind, entries, mask) in [
            (Kind::Gpce, [(0, 0x10), (4, 0x2f)], 0x10),
            (Kind::Cio, [(0x4000, 0xa2), (0x8000, 0xb1)], 2),
        ] {
            let mut model = Power::from_snapshot(kind, entries).unwrap();
            assert_eq!(
                model.pending_gpce().count() + model.pending_cio().count(),
                0
            );
            assert_eq!(
                model.unresolved_readiness().collect::<Vec<_>>(),
                [UnresolvedReadiness {
                    offset: entries[0].0,
                    observed: entries[0].1,
                    mask
                }]
            );
            assert_eq!(
                model.read(entries[0].0, Width::Word, &mut access),
                Ok(u64::from(entries[0].1))
            );
            assert!(model.advance(&mut access).is_err());
            assert_eq!(model.unresolved_readiness().count(), 1);
            assert_eq!(
                model.read(entries[0].0, Width::Word, &mut access),
                Ok(u64::from(entries[0].1))
            );
        }
    }

    #[test]
    fn actual_gpce_finalization_retains_ordered_masked_effects_without_clearing_native_progress() {
        let mut bus = Bus::new();
        let id = bus.add(Box::new(
            Power::from_snapshot(Kind::GpceFinalize, [(0x2008, 0x123), (0x200c, 0x456)]).unwrap(),
        ));
        bus.map(id, 0x23b782008, 8, 0x2008).unwrap();
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        assert!(bus.write(0x23b782008, Width::Word, 0, &mut access).is_err());
        let first = bus.read(0x23b782008, Width::Word, &mut access).unwrap();
        bus.write(0x23b782008, Width::Word, first & !1, &mut access)
            .unwrap();
        assert_eq!(bus.read(0x23b782008, Width::Word, &mut access), Ok(0x122));
        // Later unqualified rearm refuses without erasing the first write.
        assert!(
            bus.write(0x23b78200c, Width::Word, 0x457, &mut access)
                .is_err()
        );
        assert_eq!(bus.read(0x23b78200c, Width::Word, &mut access), Ok(0x456));
        let second = bus.read(0x23b78200c, Width::Word, &mut access).unwrap();
        // The original RMW stores even when the bit was already clear.
        bus.write(0x23b78200c, Width::Word, second & !1, &mut access)
            .unwrap();
        let model = bus.device_mut::<Power>(id).unwrap();
        assert_eq!(
            model.pending_configuration().collect::<Vec<_>>(),
            [
                ConfigurationRequest {
                    offset: 0x2008,
                    previous: 0x123,
                    written: 0x122
                },
                ConfigurationRequest {
                    offset: 0x200c,
                    previous: 0x456,
                    written: 0x456
                },
            ]
        );
        assert!(model.advance(&mut access).is_err());
        assert_eq!(model.pending_configuration().count(), 2);
        assert!(
            model
                .write(0x2008, Width::Word, 0x122, &mut access)
                .is_err()
        );
    }

    #[test]
    fn native_gpce_status_control_fields_do_not_gain_semantics_from_the_ap_request_setter() {
        let mut model = Power::from_snapshot(Kind::Gpce, [(0, 0xf), (4, 0x2f)]).unwrap();
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        // Original native programs use bit5 too; its hardware effect cannot
        // be invented from the AP driver's preserving low4 update.
        assert!(model.write(0, Width::Word, 0x2f, &mut access).is_err());
        assert!(model.write(4, Width::Word, 0xf, &mut access).is_err());
        assert_eq!(model.read(0, Width::Word, &mut access), Ok(0xf));
        assert_eq!(model.read(4, Width::Word, &mut access), Ok(0x2f));
        assert_eq!(model.pending_gpce().count(), 0);
    }
    #[test]
    fn tvm_retains_config_and_other_domains_without_claiming_idle_progress() {
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        let mut model = snapshot(Kind::Tvm, 0x123);
        model.write(0x400, Width::Word, 0x122, &mut access).unwrap();
        assert_eq!(model.read(0x400, Width::Word, &mut access), Ok(0x122));
        assert!(model.read(0x7e0, Width::Word, &mut access).is_err());
        assert_eq!(model.read(0x3e0, Width::Word, &mut access), Ok(0x123));
        assert!(model.write(0x7e0, Width::Word, 0, &mut access).is_err());
        assert!(model.advance(&mut access).is_err());
    }
    #[test]
    fn captured_volman_errors_acknowledge_without_replacing_them_with_health() {
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        let mut model = snapshot(Kind::Volman, 0);
        model.registers.insert(STATUS, Word::captured(0x120035));
        model.write(STATUS, Width::Word, 5, &mut access).unwrap();
        assert_eq!(model.read(STATUS, Width::Word, &mut access), Ok(0x120030));
        assert!(
            model
                .write(STATUS, Width::Word, 0x10000, &mut access)
                .is_err()
        );
        model
            .write(0x30, Width::Word, LOCK | 7, &mut access)
            .unwrap();
        assert!(model.write(0x30, Width::Word, 0, &mut access).is_err());
        model
            .write(MASK, Width::Word, 0xff000, &mut access)
            .unwrap();
        model.write(FINAL, Width::Word, 1, &mut access).unwrap();
        assert_eq!(model.read(FINAL, Width::Word, &mut access), Ok(1));
        assert!(model.read(STATUS, Width::Word, &mut access).is_err());
        assert!(model.advance(&mut access).is_err());
    }
    #[test]
    fn native_binding_guards_and_pending_requests_preserve_order() {
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        let mut gpce = Power::from_snapshot(Kind::Gpce, [(0, 0x120), (4, 0x830)]).unwrap();
        gpce.write(4, Width::Word, 0x83f, &mut access).unwrap();
        gpce.write(0, Width::Word, 0x12f, &mut access).unwrap();
        assert_eq!(
            gpce.pending_gpce()
                .map(|request| request.offset)
                .collect::<Vec<_>>(),
            [4, 0]
        );
        let mut bindings = snapshot(Kind::NubBindings, 0);
        bindings.registers.insert(0x23d2d0200, Word::captured(1));
        assert!(
            bindings
                .write(0x23d2d0200, Width::Word, 0x5000, &mut access)
                .is_err()
        );
        assert_eq!(bindings.read(0x23d2d0200, Width::Word, &mut access), Ok(1));
        assert_eq!(bindings.pending_configuration().count(), 0);
        bindings
            .write(0x23d2d0204, Width::Word, 0x103, &mut access)
            .unwrap();
        bindings
            .write(0x23d2d0204, Width::Word, 0x1090103, &mut access)
            .unwrap();
        assert!(
            bindings
                .write(0x23d2d0204, Width::Word, 0, &mut access)
                .is_err()
        );
        bindings
            .write(0x23b781004, Width::Word, 1, &mut access)
            .unwrap();
        assert!(
            bindings
                .write(0x23b781004, Width::Word, 0, &mut access)
                .is_err()
        );
        assert_eq!(
            bindings
                .pending_configuration()
                .map(|request| request.offset)
                .collect::<Vec<_>>(),
            [0x23d2d0204, 0x23d2d0204, 0x23b781004]
        );
        assert!(bindings.advance(&mut access).is_err());
    }

    #[test]
    fn marker_and_gating_preserve_supplied_values_without_inventing_power_edges() {
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        let mut marker = snapshot(Kind::Marker, 0xdeadbeef);
        assert_eq!(
            marker.read(MARKER, Width::Word, &mut access),
            Ok(0xdeadbeef)
        );
        assert!(marker.write(MARKER, Width::Word, 0, &mut access).is_err());
        let mut gating = snapshot(Kind::Gating, 0x80000001);
        gating
            .write(0, Width::Word, 0x80000023, &mut access)
            .unwrap();
        assert_eq!(gating.read(0, Width::Word, &mut access), Ok(0x80000023));
        assert_eq!(gating.read(0x40, Width::Word, &mut access), Ok(0x80000001));
        assert!(gating.write(3, Width::Word, 0, &mut access).is_err());
        assert!(gating.read(0, Width::Double, &mut access).is_err());
    }
}
