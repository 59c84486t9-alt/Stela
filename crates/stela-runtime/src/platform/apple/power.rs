//! PMGR SOC power configuration, placed by the DT `reg` map bindings of
//! `AppleT8112PMGR::initRegMaps` (kernel file 0x2fa31bc..0x2fa3620).
//!
//! VOLMAN (reg[31]): `restoreHW` 0x2fa3c80 checks channel bit24 before
//! clearing configuration, acknowledges channels at +0x24, enables the mask
//! at +0x3f8, and finalizes at +0x3fc. `panicOnDvcDoneErr` 0x2fa3e18 tests
//! low8 (optionally also bits23:16). Low8 writes acknowledge (W1C inference),
//! never inject errors. Supplied error/status bits remain visible.
//! A protected channel cannot be rewritten; other configuration words keep full writes.
//!
//! The PS marker (reg[30]+0x17ffc, restoreHW 0x2fa3d88) is a firmware-owned
//! read-only whole-word marker, distinct from the `ps-regs` device registers.
//! GPCE (reg[34], `configCPUComplexPowerState` 0x2f9cab4) keeps each complex's
//! low4 request (0/f), preserving the other captured fields. The driver waits
//! for bit4 clear; that expectation is not proof that a request completes.
//! Request writes keep pending ownership and invalidate readiness observation
//! until native controller progress is checked. They never clear BUSY or
//! claim a native sequence/CPU lifecycle completed.
//!
//! CIO (reg[41], `enableCioReconfig` 0x2fa5a44) reads offsets0x4000/0x8000,
//! sets request bit0 and waits for mask2 clearance. The false path
//! performs no access. Both port requests preserve unrelated captured fields,
//! including a same-value request, without selecting an invented native PC.
//! Captured GPCE/CIO unready observations remain explicit even before a new
//! request; a snapshot must not turn prior native work into an empty idle queue.
//!
//! LLB `tunableh_pmgr_soc_gpce0_finalize` (file9c26c/9c2dc) has two
//! auxiliary RMWs at +2008/+200c, mask1/set0. Their configuration effects are
//! without checking the distinct native rearm or engine progress.
//!
//! Power-gate enables (reg[32], restoreHW 0x2f9cc3c and
//! `_enableCPMPowerDomainGating` 0x2f9fd88) keep bit31 and other RMW fields.
//! They permit automatic gating without inventing an electrical idle event.
//! TVM (reg[35], `enableTVM` 0x2fa61f0) has four0x400-spaced controls/status
//! pairs. Configuration does not establish zero pending voltage/thermal status.
//!
//! `new` has unknown handoff words. `from_snapshot` requires every bank
//! word; no zero marker, unlocked channel, disabled request or healthy status
//! is inferred from firmware/DT absence. Supplied snapshots grant register
//! observations only, not native execution, functional ownership or PS values.
#[cfg(test)]
use stela_soc_data::power::{MARKER, MASK};
pub mod t6000;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError, stela_contracts::bus::Width,
    stela_contracts::bus::refuse,
};

const NAME: &str = "soc-power";
const LOCK: u64 = 1 << 24;
const ACK: u64 = 0xff;
const REQUEST: u64 = 0xf;
const BUSY: u64 = 1 << 4;
const CIO_REQUEST: u32 = 1;
const CIO_WAIT: u32 = 2;

use stela_soc_data::power::{CHANNEL, FINAL, Kind, STATUS};

#[cfg(test)]
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
    #[cfg(test)]
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
    #[cfg(test)]
    pub fn pending_gpce(&self) -> impl Iterator<Item = GpceRequest> + '_ {
        self.gpce.iter().copied()
    }
    #[cfg(test)]
    pub fn pending_cio(&self) -> impl Iterator<Item = CioRequest> + '_ {
        self.cio.iter().copied()
    }
    #[cfg(test)]
    pub fn unresolved_readiness(&self) -> impl Iterator<Item = UnresolvedReadiness> + '_ {
        self.unresolved_readiness.iter().copied()
    }
    #[cfg(test)]
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

/// Only installation configuration fields are checked here. Source group2/3
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
mod tests;
