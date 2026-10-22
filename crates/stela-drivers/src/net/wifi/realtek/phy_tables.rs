// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright(c) 2018-2019 Realtek Corporation
//! RTL8822C source initial table phase and later TRX path configuration.
//! Each phase retains its own completion boundary. Initial dynamic PHY state
//! has no qualified adaptivity policy. RF/DPK/IQK calibration, power tracking
//! and operational radio are separate.
mod board_power;
pub mod channel;
pub mod channel_power;
mod dac;
pub mod source_mac;
pub use board_power::Error as BoardPowerError;
pub use board_power::{FactoryBand, FactoryPower, FactorySheet, GainDelta, QuarterDbmReference};
mod data;
use super::{
    efuse::Board,
    features::Report,
    identity::{Chip, Profile},
    legacy::{self, Io},
    rf::{self, Path},
};
pub use dac::{DacCalibrated, FactoryBytes, FactoryInitialized, PhyInitialized, ThermalTracking};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Hardware(legacy::Error),
    Efuse(super::efuse::Error),
    BoardPower(board_power::Error),
    Fifo(super::fifo::Error),
    ChannelPower(channel_power::Error),
    Rf(rf::Error),
    WrongProfile,
    UnsupportedCut(u8),
    UnsupportedRfe(u8),
    UnsupportedRfLayout,
    InvalidMac,
    TableGrammar { pair: usize },
    TableAddress { address: u32 },
    TableValue { address: u32 },
    IdentityChanged,
    FirmwareNotReady,
    DomainOff,
    DacSamples { accepted: usize },
    DacUnstableSamples,
    DacAdcConvergence { path: Path },
    DacConvergence { path: Path },
    DacReadyTimeout { register: u32 },
    DacAmbiguousReady { register: u32 },
}
impl From<legacy::Error> for Error {
    fn from(e: legacy::Error) -> Self {
        Self::Hardware(e)
    }
}
impl From<rf::Error> for Error {
    fn from(e: rf::Error) -> Self {
        Self::Rf(e)
    }
}

/// Diagnostic record of this bounded source phase. Fingerprints/counts are not
/// transferable requester/epoch credentials or calibrated PHY/radio readiness.
#[derive(Debug)]
pub struct Loaded {
    profile: Profile,
    condition: u32,
    configured: [usize; 6],
    crystal_cap: u8,
    power: FactoryPower,
}
impl Loaded {
    pub fn factory_power(&self) -> &FactoryPower {
        &self.power
    }
    pub fn profile(&self) -> Profile {
        self.profile
    }
    pub fn condition(&self) -> u32 {
        self.condition
    }
    /// Source order: MAC, BB, AGC, RFK-init, path B, path A. Counts include
    /// source delay sentinels; they do not count successful air operations.
    pub fn configured_pairs(&self) -> [usize; 6] {
        self.configured
    }
}
/// Initial two-path BB selection and source IGI latch programming completed.
/// This diagnostic state does not attest RF calibration, channel or TX policy.
#[derive(Debug)]
pub struct PathsConfigured {
    profile: Profile,
    initial_igi: u8,
    crystal_cap: u8,
    power: FactoryPower,
}
impl PathsConfigured {
    pub fn profile(&self) -> Profile {
        self.profile
    }
    pub fn initial_igi(&self) -> u8 {
        self.initial_igi
    }
}
impl Loaded {
    /// Configure the source initial AB transmit/receive paths, fixed A CCK/1SS
    /// selection, three complete BB reset pulses and source IGI latch toggles.
    /// Consuming Loaded prevents repeating this transition through this value.
    ///
    /// # Safety
    /// Same genuine retained requester and uninterrupted boot/reset epoch as
    /// this Loaded state and Report, not matching fingerprints alone. The
    /// initial source table phase completed on this actual Io and has not been
    /// invalidated. All queues/pins/claims remain retained; transmit, competing
    /// reset/IRQ/PHY/RF work remain quiesced. Run once in initial exclusive
    /// process/deferred context. This performs BB resets, never DMA-stop proof.
    pub unsafe fn configure_paths<I: Io>(
        self,
        io: &mut I,
        report: &Report,
    ) -> Result<PathsConfigured, Error> {
        if io.profile() != self.profile || report.profile() != self.profile {
            return Err(Error::WrongProfile);
        }
        let cap = report.capabilities();
        if cap.rf_phys != 2 || cap.rf_paths != 2 || cap.antenna_tx != 3 || cap.antenna_rx != 3 {
            return Err(Error::UnsupportedRfLayout);
        }
        let mut a = Attempt {
            io,
            profile: self.profile,
            done: false,
        };
        a.domain()?;
        let initial_igi = a.trx_initial()?;
        a.domain()?;
        a.done = true;
        Ok(PathsConfigured {
            profile: self.profile,
            initial_igi,
            crystal_cap: self.crystal_cap,
            power: self.power,
        })
    }
}
/// Actual initial dynamic-PHY observations and initialized tracking state.
/// No adaptivity jurisdiction/threshold policy is selected or qualified here.
/// Source initial EDCCA thresholds are hardware setup, never TX permission.
/// RF/IQK/DAC calibration and operational tracking have not run.
#[derive(Debug)]
pub struct InitialPhy {
    profile: Profile,
    igi_history: [u8; 4],
    tracking: InitialTracking,
    cck_bounds: [u8; 2],
    crystal_cap: u8,
    power: FactoryPower,
}
/// Diagnostic initialized tracking values; copying these grants no hardware,
/// calibration or transmit authority. No runtime tracking worker runs yet.
#[derive(Debug)]
pub struct InitialTracking {
    pub fa_history: [u16; 4],
    pub igi_bitmap: u8,
    pub cck_pd_levels: [[u8; 4]; 2],
    /// None represents the source's 0xffffffff uninitialized-average sentinel.
    pub cck_fa_average: Option<u32>,
    pub iqk_done: bool,
    pub cfo_adjusting: bool,
    pub current_tx_path: Path,
    pub path_counts: [u16; 2],
    pub path_sums: [u32; 2],
}
impl InitialPhy {
    pub fn factory_power(&self) -> &FactoryPower {
        &self.power
    }
    pub fn profile(&self) -> Profile {
        self.profile
    }
    pub fn igi_history(&self) -> [u8; 4] {
        self.igi_history
    }
    pub fn tracking(&self) -> &InitialTracking {
        &self.tracking
    }
    /// Actual source upper/lower CCK GI observations (six bits each).
    pub fn cck_bounds(&self) -> [u8; 2] {
        self.cck_bounds
    }
    pub fn crystal_cap(&self) -> u8 {
        self.crystal_cap
    }
}
impl PathsConfigured {
    /// Observe the initial IGI, initialize source common EDCCA registers and
    /// capture actual CCK GI bounds. Initial CFO crystal state derives from
    /// the actual cap programmed by the consumed table/path phase.
    ///
    /// # Safety
    /// Same genuine retained requester and uninterrupted reset/firmware epoch
    /// as this state and Report. Completed tables/paths must remain valid on
    /// this actual Io, with all claims/queues/pins retained and transmit and
    /// competing reset/IRQ/PHY/RF work quiesced. Run once in exclusive initial
    /// process/deferred context. Source adaptivity mode depends on trusted OS
    /// jurisdiction; this phase deliberately leaves it unqualified. No TX,
    /// calibration, channel/power policy or DMA-stop authority is returned.
    pub unsafe fn initialize_dynamic<I: Io>(
        self,
        io: &mut I,
        report: &Report,
    ) -> Result<InitialPhy, Error> {
        if io.profile() != self.profile || report.profile() != self.profile {
            return Err(Error::WrongProfile);
        }
        let cap = report.capabilities();
        if cap.rf_phys != 2 || cap.rf_paths != 2 || cap.antenna_tx != 3 || cap.antenna_rx != 3 {
            return Err(Error::UnsupportedRfLayout);
        }
        let mut a = Attempt {
            io,
            profile: self.profile,
            done: false,
        };
        a.domain()?;
        // Actual fresh source read, not the earlier TRX IGI observation.
        let igi = (a.io.read32(0x1d70)? & 0x7f) as u8;
        // Both source threshold offsets are 0x80: 0x7f + 0x80 = 0xff.
        // This identical initial hardware setup precedes runtime adaptivity
        // for every jurisdiction. It does not select source NORMAL mode.
        a.modify32(0x84c, 0x00ff0000, 0xff)?;
        a.modify32(0x84c, 0xff000000, 0xff)?;
        a.modify32(0x520, 1 << 15, 0)?;
        a.modify32(0x524, 1 << 11, 1)?;
        a.modify32(0x844, 3 << 29, 0)?;
        let upper_msb = (a.io.read32(0x1a98)? & 0xc000) >> 14;
        let upper_lsb = (a.io.read32(0x1aa8)? & 0xf0000) >> 16;
        let lower_msb = (a.io.read32(0x1a98)? & 0xc0) >> 6;
        let lower_lsb = (a.io.read32(0x1a70)? & 0x0f000000) >> 24;
        a.domain()?;
        a.done = true;
        Ok(InitialPhy {
            profile: self.profile,
            igi_history: [igi, 0, 0, 0],
            tracking: InitialTracking {
                fa_history: [0; 4],
                igi_bitmap: 0,
                cck_pd_levels: [[0; 4]; 2],
                cck_fa_average: None,
                iqk_done: false,
                cfo_adjusting: true,
                current_tx_path: Path::A,
                path_counts: [0; 2],
                path_sums: [0; 2],
            },
            cck_bounds: [
                ((upper_msb << 4) | upper_lsb) as u8,
                ((lower_msb << 4) | lower_lsb) as u8,
            ],
            crystal_cap: self.crystal_cap,
            power: self.power,
        })
    }
}
#[derive(Clone, Copy)]
enum Kind {
    Mac,
    Bb,
    Agc,
    Rf(Path),
}
const TABLES: [(&[[u32; 2]], Kind); 6] = [
    (data::MAC, Kind::Mac),
    (data::BB, Kind::Bb),
    (data::AGC, Kind::Agc),
    (data::CAL, Kind::Bb),
    (data::RF_B, Kind::Rf(Path::B)),
    (data::RF_A, Kind::Rf(Path::A)),
];
fn positive(driver: u32, condition: u32) -> bool {
    let cut = (condition >> 24) & 15;
    let pkg = (condition >> 12) & 15;
    let interface = (condition >> 8) & 15;
    (cut == 0 || cut == (driver >> 24) & 15)
        && (pkg == 0 || pkg == (driver >> 12) & 15)
        && (interface == 0 || interface == (driver >> 8) & 15)
        && (condition & 255) == (driver & 255)
}
/// Validate the actual flat source branch stream before any table-driven I/O.
/// Source's positive/negative/else semantics are retained for valid streams;
/// malformed metadata never falls through to successful-looking writes.
fn walk(
    mut driver: u32,
    table: &[[u32; 2]],
    mut emit: impl FnMut(u32, u32) -> Result<(), Error>,
) -> Result<usize, Error> {
    driver &= 0x0fffffff;
    let mut active = false;
    let mut pending = false;
    let mut had_else = false;
    let mut matched = true;
    let mut skipped = false;
    let mut condition = 0;
    let mut count = 0;
    for (pair, &[address, value]) in table.iter().enumerate() {
        if address & (1 << 31) != 0 {
            if address & (1 << 30) != 0 || pending {
                return Err(Error::TableGrammar { pair });
            }
            match (address >> 28) & 3 {
                0 => {
                    if active {
                        return Err(Error::TableGrammar { pair });
                    }
                    active = true;
                    pending = true;
                    had_else = false;
                    condition = address;
                }
                1 => {
                    if !active || had_else {
                        return Err(Error::TableGrammar { pair });
                    }
                    pending = true;
                    condition = address;
                }
                2 => {
                    if !active || had_else {
                        return Err(Error::TableGrammar { pair });
                    }
                    had_else = true;
                    matched = !skipped;
                }
                _ => {
                    if !active {
                        return Err(Error::TableGrammar { pair });
                    }
                    active = false;
                    matched = true;
                    skipped = false;
                }
            }
        } else if address & (1 << 30) != 0 {
            if !pending {
                return Err(Error::TableGrammar { pair });
            }
            pending = false;
            if !skipped {
                matched = positive(driver, condition);
                skipped = matched;
            } else {
                matched = false;
            }
        } else {
            if pending {
                return Err(Error::TableGrammar { pair });
            }
            if matched {
                emit(address, value)?;
                count += 1;
            }
        }
    }
    if active || pending {
        return Err(Error::TableGrammar { pair: table.len() });
    }
    Ok(count)
}
fn check(kind: Kind, address: u32, value: u32) -> Result<(), Error> {
    match kind {
        Kind::Mac => {
            if address >= 0x5000 {
                return Err(Error::TableAddress { address });
            }
            if value > 255 {
                return Err(Error::TableValue { address });
            }
        }
        Kind::Agc => {
            if address >= 0x5000 || address & 3 != 0 {
                return Err(Error::TableAddress { address });
            }
        }
        Kind::Bb => {
            if !(0xf9..=0xfe).contains(&address) && (address >= 0x5000 || address & 3 != 0) {
                return Err(Error::TableAddress { address });
            }
        }
        Kind::Rf(_) => {
            if ![0xffe, 0xfe].contains(&address) {
                if address > 255 {
                    return Err(Error::TableAddress { address });
                }
                if value > 0xfffff {
                    return Err(Error::TableValue { address });
                }
            }
        }
    }
    Ok(())
}
struct Attempt<'a, I: Io> {
    io: &'a mut I,
    profile: Profile,
    done: bool,
}
impl<I: Io> Drop for Attempt<'_, I> {
    fn drop(&mut self) {
        if !self.done {
            self.io.quarantine()
        }
    }
}
impl<I: Io> Attempt<'_, I> {
    fn verify(&mut self) -> Result<(), Error> {
        if self.io.read32(0xf0)? != self.profile.observed().sys_cfg1 {
            return Err(Error::IdentityChanged);
        }
        if self.io.read16(0x80)? & 0xcfff != 0xc078 {
            return Err(Error::FirmwareNotReady);
        }
        Ok(())
    }
    fn domain(&mut self) -> Result<(), Error> {
        self.verify()?;
        let bb = self.io.read8(2)?;
        let rf = self.io.read8(0x1f)?;
        let wlrf = self.io.read32(0xec)?;
        if bb & 3 != 3 || rf & 7 != 7 || wlrf & 0x07000000 != 0x07000000 {
            return Err(Error::DomainOff);
        }
        Ok(())
    }
    fn reset_bb(&mut self) -> Result<(), Error> {
        // Source BB reset uses 16-bit SYS_FUNC_EN accesses, preserving all
        // unrelated PCI/USB/domain bits. Three separate source calls matter.
        for set in [true, false, true] {
            let old = self.io.read16(2)?;
            self.io.write16(2, if set { old | 1 } else { old & !1 })?;
        }
        Ok(())
    }
    fn trx_initial(&mut self) -> Result<u8, Error> {
        // Source config_trx_mode(AB, AB, false). General antenna switching,
        // one-PHY layouts and other runtime modes are not admitted here.
        self.modify32(0x1800, 0xfffff, 0x33312)?;
        self.modify32(0x4100, 0xfffff, 0x33312)?;
        // CCK receive AB, in exact source mask order.
        self.modify32(0x1a2c, 0x00600000, 1)?;
        self.modify32(0x1a2c, 0x00060000, 1)?;
        self.modify32(0x1a04, 0x0f000000, 1)?;
        // OFDM receive AB and both source antenna maps.
        for (address, mask, value) in [
            (0x1d30, 0x300, 1),
            (0x1d30, 0x600000, 1),
            (0xc44, 1 << 17, 1),
            (0xc54, 1 << 20, 1),
            (0xc38, 1 << 24, 1),
            (0x824, 0x0f000000, 3),
            (0x824, 0x000f0000, 3),
        ] {
            self.modify32(address, mask, value)?;
        }
        // Source config_tx_path uses A for CCK and 1SS even in AB mode.
        self.modify32(0x1a04, 0xf0000000, 8)?;
        self.reset_bb()?;
        self.modify32(0x820, 0xff, 0x31)?;
        self.modify32(0x1e2c, 0xffff, 0x0400)?;
        self.reset_bb()?;
        self.reset_bb()?;
        let igi = self.io.read32(0x1d70)? & 0x7f;
        // Source u32 subtraction wraps before the actual masked stores; the
        // 0/1 cases must neither panic nor discard the transient latch writes.
        self.modify32(0x1d70, 0x7f, igi.wrapping_sub(2))?;
        self.modify32(0x1d70, 0x7f00, igi.wrapping_sub(2))?;
        self.modify32(0x1d70, 0x7f, igi)?;
        self.modify32(0x1d70, 0x7f00, igi)?;
        Ok(igi as u8)
    }
    fn modify8(&mut self, address: u32, set: u8) -> Result<(), Error> {
        let old = self.io.read8(address)?;
        self.io.write8(address, old | set)?;
        Ok(())
    }
    fn modify32(&mut self, address: u32, mask: u32, data: u32) -> Result<(), Error> {
        let old = self.io.read32(address)?;
        self.io.write32(
            address,
            (old & !mask) | ((data << mask.trailing_zeros()) & mask),
        )?;
        Ok(())
    }
    fn header(&mut self, pre: bool) -> Result<(), Error> {
        for address in [0x180c, 0x410c] {
            self.modify32(address, 3, 3)?;
            self.modify32(address, 1 << 28, 1)?;
        }
        self.modify32(0x1c3c, 3, if pre { 0 } else { 3 })
    }
    fn table(
        &mut self,
        table: &[[u32; 2]],
        kind: Kind,
        condition: u32,
        report: &Report,
    ) -> Result<usize, Error> {
        self.verify()?;
        let count = match kind {
            Kind::Rf(path) => {
                // SAFETY: outer initializer requires genuine same requester,
                // report boot epoch, retained full BAR/pins and exclusive
                // source-phase ownership; domain enable was performed above.
                let mut rf = unsafe { rf::Registers::new(self.io, report) }?;
                walk(condition, table, |address, value| {
                    match address {
                        0xffe => rf.table_delay_us(50000)?,
                        0xfe => rf.table_delay_us(100)?,
                        _ => {
                            rf.write(path, address as u8, 0xfffff, value)?;
                            rf.table_delay_us(1)?;
                        }
                    }
                    Ok(())
                })?
            }
            _ => walk(condition, table, |address, value| {
                match kind {
                    Kind::Mac => self.io.write8(address, value as u8)?,
                    Kind::Agc => self.io.write32(address, value)?,
                    Kind::Bb => match address {
                        0xfe => self.io.delay_us(50000),
                        0xfd => self.io.delay_us(5000),
                        0xfc => self.io.delay_us(1000),
                        0xfb => self.io.delay_us(50),
                        0xfa => self.io.delay_us(5),
                        0xf9 => self.io.delay_us(1),
                        _ => self.io.write32(address, value)?,
                    },
                    Kind::Rf(_) => unreachable!(),
                }
                Ok(())
            })?,
        };
        self.verify()?;
        Ok(count)
    }
}

/// Prepare concrete source factory PG/by-rate/limit data and load the complete
/// bounded source table phase for admitted two-PHY 8822C. Factory sheets do not
/// select a current OS jurisdiction/channel or qualify operational TX power.
///
/// # Safety
/// The actual Io, immutable OTP Board and fresh firmware Report belong to the
/// same retained physical requester and uninterrupted reset/boot epoch. Matching
/// hardware fingerprints alone do not prove this. Full native HCI/FIFO/MAC
/// configuration and source board power-policy setup precede this call; the
/// actual mapped BAR extends through 0x5000, all actual native queues/pins/claims
/// remain retained and no DMA/reset/IRQ/RF worker competes. Transmit remains
/// quiesced through later source TRX/calibration/channel/policy admission. Call
/// once in the initial source PHY phase per boot. Run in
/// exclusive process/deferred context with calibrated real delays. Loaded is
/// diagnostic data, never an alternative ownership or completed-radio proof.
pub unsafe fn initialize<I: Io>(
    io: &mut I,
    board: &Board,
    report: &Report,
) -> Result<Loaded, Error> {
    let profile = io.profile();
    if profile.chip() != Chip::Rtl8822C || board.profile() != profile || report.profile() != profile
    {
        return Err(Error::WrongProfile);
    }
    if profile.cut() > 6 {
        return Err(Error::UnsupportedCut(profile.cut()));
    }
    let rfe = board
        .source_rfe()
        .map_err(|_| Error::UnsupportedRfe(board.raw().rfe_raw))?;
    board.valid_mac().map_err(|_| Error::InvalidMac)?;
    let cap = report.capabilities();
    // Source .rf_tbl is B then A, with B's table explicitly bound to path B.
    // When source report handling reduces rf_phys/path count to one, its loop
    // selects B and silently ignores its rejected write. Refuse that profile.
    if cap.rf_phys != 2 || cap.rf_paths != 2 {
        return Err(Error::UnsupportedRfLayout);
    }
    // Source 8822C leaves package_type zero: setup maps it to15; PCI interface1.
    // Platform4 is the donor table encoding (not a requested Linux runtime).
    let cut = if profile.cut() == 0 {
        15
    } else {
        u32::from(profile.cut())
    };
    let condition = u32::from(rfe) | (1 << 8) | (15 << 12) | (4 << 16) | (cut << 24);
    let mut configured = [0; 6];
    for (i, &(table, kind)) in TABLES.iter().enumerate() {
        configured[i] = walk(condition, table, |a, v| check(kind, a, v))?;
    }
    let power = FactoryPower::prepare(board).map_err(Error::BoardPower)?;
    // The exact selected immutable streams and profile are admitted before the
    // first hardware mutation. Unknown boards/layouts cannot partially load.
    let mut a = Attempt {
        io,
        profile,
        done: false,
    };
    a.verify()?;
    a.modify8(2, 3)?;
    a.modify8(0x1f, 7)?;
    a.modify32(0xec, 0x07000000, 7)?;
    a.modify32(0xa70, 0x3ff, 0x3ff)?;
    a.header(true)?;
    for (i, &(table, kind)) in TABLES.iter().enumerate() {
        if i == 3 {
            a.modify32(0x1e24, 1 << 17, 1)?;
            for (bit, value) in [(28, 1), (29, 1), (30, 1), (31, 0)] {
                a.modify32(0x1cd0, 1 << bit, value)?;
            }
        }
        let actual = a.table(table, kind, condition, report)?;
        debug_assert_eq!(actual, configured[i]);
    }
    let crystal = u32::from(board.raw().crystal_cap_raw & 0x7f);
    a.modify32(0x1040, 0xfffc00, crystal | (crystal << 7))?;
    a.header(false)?;
    a.verify()?;
    a.done = true;
    Ok(Loaded {
        profile,
        condition,
        configured,
        crystal_cap: crystal as u8,
        power,
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::{sync::Arc, vec, vec::Vec};
    use std::sync::Mutex;
    struct Model {
        profile: Profile,
        bytes: Vec<u8>,
        physical: [u8; 512],
        pending: bool,
        calls: usize,
        fail: Option<usize>,
        mutate: Option<(usize, u32, usize, u32)>,
        record: bool,
        events: Vec<[u32; 4]>,
        quarantined: usize,
        dac: Option<DacModel>,
        fifo_ready: bool,
    }
    #[derive(Default)]
    struct DacModel {
        phase: u8,
        active: u32,
        seed: u32,
        adc_input: i32,
        samples: usize,
        invalid_after: Option<usize>,
        invalid_prefix: usize,
        ready_delay: Option<(u32, usize)>,
        ready_reads: usize,
        unstable: bool,
        adc_residual: u32,
        dac_residual: u32,
        ready_override: Option<(u32, u32)>,
        cache_read: bool,
        distinct_cache: bool,
    }
    impl Model {
        fn get(&self, r: u32, width: usize) -> u32 {
            let mut b = [0; 4];
            b[..width].copy_from_slice(&self.bytes[r as usize..r as usize + width]);
            u32::from_le_bytes(b)
        }
        fn set(&mut self, r: u32, width: usize, v: u32) {
            self.bytes[r as usize..r as usize + width].copy_from_slice(&v.to_le_bytes()[..width]);
        }
        fn dac_read(&mut self, r: u32) -> u32 {
            let mut v = self.get(r, 4);
            let Some(d) = self.dac.as_ref() else {
                return v;
            };
            if r == 0x2dbc {
                let n = d.samples;
                let sample = if n < d.invalid_prefix || d.invalid_after.is_some_and(|at| n >= at) {
                    200
                } else if d.unstable {
                    if n.is_multiple_of(2) { 100 } else { 924 }
                } else {
                    match d.phase {
                        0 => (d.adc_input as u32) & 1023,
                        1 => d.adc_residual,
                        2 => 53,
                        _ => 16 + d.dac_residual,
                    }
                };
                self.dac.as_mut().unwrap().samples += 1;
                return (sample << 12) | sample;
            }
            if let Some((at, raw)) = d.ready_override
                && r == at
            {
                return raw;
            }
            let distinct = d.distinct_cache && d.cache_read;
            let seed = d.seed;
            for p in 0..2 {
                let b = if p == 0 { 0x1800 } else { 0x4100 };
                let rd = if p == 0 { 0x2800 } else { 0x4500 };
                if r == rd + 8 || r == rd + 0x34 {
                    v = (v & !0x7fff80) | (0xffff << 7);
                }
                if r == rd + 0x24 || r == rd + 0x50 {
                    let off = if r == rd + 0x24 { 0xbc } else { 0xd8 };
                    let iq = (self.get(b + off, 4) >> 28) | ((self.get(b + off + 4, 4) & 15) << 4);
                    v = (v & !0x07f80000) | (iq << 19);
                }
                if r == rd + 0x10 || r == rd + 0x3c {
                    let vec = u32::from(r != rd + 0x10);
                    let index = self.get(b + 0xb0 + vec * 0x1c, 4) >> 28;
                    let actual = (seed * 17 + p * 71 + vec * 29 + index * 7) & 511;
                    v = (v & !0x7fc0000) | (actual << 18);
                    self.dac.as_mut().unwrap().cache_read = true;
                }
            }
            if let Some((reg, count)) = self.dac.as_ref().unwrap().ready_delay
                && reg == r
            {
                let d = self.dac.as_mut().unwrap();
                if d.ready_reads < count {
                    v &= !0x7fff80;
                }
                d.ready_reads += 1;
            }
            if distinct {
                match r {
                    0x41bc => v = 0x10000000,
                    0x41c0 => v = 2,
                    0x41d8 => v = 0x30000000,
                    0x41dc => v = 4,
                    _ => {}
                }
            }
            v
        }
        fn dac_written(&mut self, r: u32, v: u32) {
            let Some(d) = self.dac.as_mut() else {
                return;
            };
            if r == 0x1810 {
                d.active = 0;
            }
            if r == 0x4110 {
                d.active = 1;
            }
            let b = if d.active == 0 { 0x1800 } else { 0x4100 };
            let format = self.get(b + 0x10, 4);
            let d = self.dac.as_mut().unwrap();
            if r == 0x1c3c {
                if v & 0xffff == 0x8003 {
                    d.phase = 0;
                } else if v & 0xffff == 0x8103 {
                    d.phase = if format == 0x02dd08c4 { 1 } else { 2 };
                }
            }
            if r == b + 0x68 && format == 0x02d508c5 {
                d.phase = 3;
            }
        }
        fn initial(&mut self, seed: usize) {
            for (i, b) in self.bytes.iter_mut().enumerate() {
                *b = (i * 13 + seed * 7) as u8;
            }
            self.set(0xf0, 4, self.profile.observed().sys_cfg1);
            self.set(0x80, 4, 0xc078);
            self.pending = false;
        }
        fn op(&mut self) -> Result<(), legacy::Error> {
            self.calls += 1;
            if self.fail == Some(self.calls) {
                return Err(legacy::Error::Register);
            }
            if let Some((at, r, w, v)) = self.mutate
                && at == self.calls
            {
                self.set(r, w, v);
            }
            Ok(())
        }
        fn event(&mut self, k: u32, r: u32, w: usize, v: u32) {
            if self.record {
                self.events.push([k, r, w as u32, v]);
            }
        }
    }
    struct Bus {
        model: Arc<Mutex<Model>>,
        panic_delay: bool,
        panic_register: Option<u32>,
    }
    // SAFETY: exclusively serialized physical register/OTP/RF effects model,
    // never an actual device, DMA/calibration or firmware-execution claim.
    unsafe impl Io for Bus {
        fn profile(&self) -> Profile {
            self.model.lock().unwrap().profile
        }
        fn read8(&mut self, r: u32) -> Result<u8, legacy::Error> {
            let mut m = self.model.lock().unwrap();
            m.op()?;
            let v = m.get(r, 1);
            m.event(0, r, 1, v);
            Ok(v as u8)
        }
        fn read16(&mut self, r: u32) -> Result<u16, legacy::Error> {
            let mut m = self.model.lock().unwrap();
            m.op()?;
            let v = m.get(r, 2);
            m.event(0, r, 2, v);
            Ok(v as u16)
        }
        fn read32(&mut self, r: u32) -> Result<u32, legacy::Error> {
            if self.panic_register == Some(r) {
                panic!("modeled register unwind");
            }
            let mut m = self.model.lock().unwrap();
            m.op()?;
            if r == 0x30 && m.pending {
                let control = m.get(r, 4);
                let address = ((control >> 8) & 1023) as usize;
                let value = (control & !255) | (m.physical[address] as u32) | (1 << 31);
                m.set(r, 4, value);
                m.pending = false;
            }
            if r == 0x208 && m.fifo_ready {
                let v = m.get(r, 4) & !1;
                m.set(r, 4, v);
            }
            let v = m.dac_read(r);
            m.event(0, r, 4, v);
            Ok(v)
        }
        fn write8(&mut self, r: u32, v: u8) -> Result<(), legacy::Error> {
            let mut m = self.model.lock().unwrap();
            m.op()?;
            m.event(1, r, 1, v.into());
            m.set(r, 1, v.into());
            Ok(())
        }
        fn write16(&mut self, r: u32, value: u16) -> Result<(), legacy::Error> {
            let mut m = self.model.lock().unwrap();
            m.op()?;
            m.event(1, r, 2, value.into());
            m.set(r, 2, value.into());
            Ok(())
        }
        fn write32(&mut self, r: u32, v: u32) -> Result<(), legacy::Error> {
            let mut m = self.model.lock().unwrap();
            m.op()?;
            m.event(1, r, 4, v);
            m.set(r, 4, v);
            m.dac_written(r, v);
            if r == 0x30 {
                m.pending = true;
            }
            for (path, sipi, base) in [(0, 0x1808, 0x3c00), (1, 0x4108, 0x4c00)] {
                let _ = path;
                if r == sipi {
                    let a = base + (((v >> 20) & 255) * 4);
                    let old = m.get(a, 4);
                    m.set(a, 4, (old & !0xfffff) | (v & 0xfffff));
                }
            }
            Ok(())
        }
        fn delay_us(&mut self, us: u64) {
            if self.panic_delay {
                panic!("modeled timer unwind")
            }
            self.model.lock().unwrap().event(2, 0, 0, us as u32);
        }
        fn submit_beacon(&mut self, _: &[u8]) -> Result<(), legacy::Error> {
            panic!("no PHY DMA publication")
        }
        unsafe fn beacon_consumed(&mut self) -> Result<(), legacy::Error> {
            panic!("no PHY DMA completion")
        }
        fn quarantine(&mut self) {
            self.model.lock().unwrap().quarantined += 1;
        }
    }
    fn setup(
        cut: u8,
        rfe: u8,
        crystal: u8,
        seed: usize,
        one_phy: bool,
        invalid_mac: bool,
    ) -> (Bus, Board, Report) {
        let profile = Profile::select(super::super::identity::Observed {
            vendor: 0x10ec,
            device: 0xc822,
            subsystem_vendor: 0x17aa,
            subsystem_device: 0x1234,
            pci_revision: 1,
            class: [2, 0x80, 0],
            sys_cfg1: (1 << 27) | (u32::from(cut) << 12),
        })
        .unwrap();
        let mut m = Model {
            profile,
            bytes: vec![0; 0x5000],
            physical: [255; 512],
            pending: false,
            calls: 0,
            fail: None,
            mutate: None,
            record: false,
            events: Vec::new(),
            quarantined: 0,
            dac: None,
            fifo_ready: false,
        };
        // Actual read-only OTP transport creates Board provenance, not a
        // public diagnostic constructor or substituted board/RFE token.
        let mac = if invalid_mac {
            [0; 6]
        } else {
            [2, 3, 4, 5, 6, 7]
        };
        let encoded = [
            0xef, 0x2e, 0x7f, crystal, 0x2f, 0x3d, rfe, 0xff, 0x8f, 0x48, mac[0], mac[1], mac[2],
            mac[3], mac[4], mac[5], 0xff,
        ];
        m.physical[..encoded.len()].copy_from_slice(&encoded);
        m.initial(seed);
        let model = Arc::new(Mutex::new(m));
        let mut bus = Bus {
            model: model.clone(),
            panic_delay: false,
            panic_register: None,
        };
        let board = unsafe { super::super::efuse::read(&mut bus) }
            .unwrap()
            .logical()
            .unwrap()
            .board();
        {
            let mut m = model.lock().unwrap();
            m.set(0x1a0, 1, 0x19);
            m.bytes[0x1a2..0x1af].fill(0);
            if one_phy {
                m.set(0x1a8, 1, 0x20);
            }
        }
        let report = super::super::features::read(&mut bus).unwrap();
        {
            let mut m = model.lock().unwrap();
            m.initial(seed);
            m.calls = 0;
            m.events.clear();
            m.record = true;
        }
        (bus, board, report)
    }
    pub(super) fn power_board_fixture(rfe: u8) -> Board {
        let (_, board, _) = setup(1, rfe, 63, 0, false, false);
        board
    }
    fn source_events(events: &[[u32; 4]]) -> Vec<u8> {
        let mut result = Vec::new();
        let mut index = 0;
        while index < events.len() {
            if events[index][..3] == [0, 0xf0, 4] {
                assert_eq!(events[index + 1][..3], [0, 0x80, 2]);
                index += 2;
                // Native RF guard adds actual domain reads; prefix/header
                // source operations never contain this contiguous triple.
                if events.get(index).map(|x| &x[..3]) == Some(&[0, 2, 1][..])
                    && events.get(index + 1).map(|x| &x[..3]) == Some(&[0, 0x1f, 1][..])
                    && events.get(index + 2).map(|x| &x[..3]) == Some(&[0, 0xec, 4][..])
                {
                    index += 3;
                }
            } else {
                for v in events[index] {
                    result.extend_from_slice(&v.to_le_bytes());
                }
                index += 1;
            }
        }
        result
    }
    fn paths_setup(pattern: usize, igi: u32) -> (Bus, Loaded, Report) {
        let (mut bus, board, report) = setup(1, 0, 0x3f, 0, false, false);
        let loaded = unsafe { initialize(&mut bus, &board, &report) }.unwrap();
        {
            let mut m = bus.model.lock().unwrap();
            // Broad source-helper input patterns model volatile BB state at
            // this boundary; the table phase was genuinely executed above.
            m.initial(pattern);
            let bb = m.get(2, 1) | 3;
            m.set(2, 1, bb);
            let rf = m.get(0x1f, 1) | 7;
            m.set(0x1f, 1, rf);
            let wlrf = m.get(0xec, 4) | 0x07000000;
            m.set(0xec, 4, wlrf);
            let raw = (m.get(0x1d70, 4) & !127) | igi;
            m.set(0x1d70, 4, raw);
            m.calls = 0;
            m.events.clear();
        }
        (bus, loaded, report)
    }
    fn dynamic_setup(
        pattern: usize,
        igi: u32,
        crystal: u8,
        upper: u32,
        lower: u32,
    ) -> (Bus, PathsConfigured, Report) {
        let (mut bus, board, report) = setup(1, 0, crystal, 0, false, false);
        let loaded = unsafe { initialize(&mut bus, &board, &report) }.unwrap();
        let paths = unsafe { loaded.configure_paths(&mut bus, &report) }.unwrap();
        {
            let mut m = bus.model.lock().unwrap();
            // Actual prior phases execute above; these broad volatile inputs
            // exercise this bounded phase rather than claim physical RF state.
            m.initial(pattern);
            let bb = m.get(2, 1) | 3;
            m.set(2, 1, bb);
            let rf = m.get(0x1f, 1) | 7;
            m.set(0x1f, 1, rf);
            let wlrf = m.get(0xec, 4) | 0x07000000;
            m.set(0xec, 4, wlrf);
            let raw = (m.get(0x1d70, 4) & !127) | igi;
            m.set(0x1d70, 4, raw);
            let raw = (m.get(0x1a98, 4) & !0xc0c0) | ((upper >> 4) << 14) | ((lower >> 4) << 6);
            m.set(0x1a98, 4, raw);
            let raw = (m.get(0x1aa8, 4) & !0xf0000) | ((upper & 15) << 16);
            m.set(0x1aa8, 4, raw);
            let raw = (m.get(0x1a70, 4) & !0xf000000) | ((lower & 15) << 24);
            m.set(0x1a70, 4, raw);
            m.calls = 0;
            m.events.clear();
        }
        (bus, paths, report)
    }
    fn dynamic_words(state: &InitialPhy) -> Vec<u32> {
        let t = state.tracking();
        let mut words: Vec<u32> = t.fa_history.into_iter().map(u32::from).collect();
        words.push(t.igi_bitmap.into());
        words.extend(state.igi_history().map(u32::from));
        words.extend(t.cck_pd_levels.into_iter().flatten().map(u32::from));
        words.extend([
            t.cck_fa_average.unwrap_or(u32::MAX),
            u32::from(t.iqk_done),
            state.crystal_cap().into(),
            u32::from(t.cfo_adjusting),
            match t.current_tx_path {
                Path::A => 1,
                Path::B => 2,
            },
            t.path_counts[0].into(),
            t.path_sums[0],
            t.path_counts[1].into(),
            t.path_sums[1],
        ]);
        words.extend(state.cck_bounds().map(u32::from));
        words
    }
    fn dac_setup(seed: u32) -> (Bus, InitialPhy, Report) {
        let (mut bus, paths, report) = dynamic_setup(0, 0, 63, 0, 0);
        let initial = unsafe { paths.initialize_dynamic(&mut bus, &report) }.unwrap();
        {
            let mut m = bus.model.lock().unwrap();
            m.initial(seed as usize);
            let bb = m.get(2, 1) | 3;
            m.set(2, 1, bb);
            let rf = m.get(0x1f, 1) | 7;
            m.set(0x1f, 1, rf);
            let wlrf = m.get(0xec, 4) | 0x07000000;
            m.set(0xec, 4, wlrf);
            m.set(0x3e3c, 4, 0x12345678);
            m.set(0x4e3c, 4, 0x12345678);
            m.dac = Some(DacModel {
                seed,
                adc_input: seed as i32 - 32,
                ready_delay: Some((0x2808, (seed % 4) as usize)),
                ..Default::default()
            });
            m.calls = 0;
            m.events.clear();
        }
        (bus, initial, report)
    }
    fn trim_setup(case: u32) -> (Bus, DacCalibrated, Report, super::super::efuse::Physical) {
        let (mut bus, initial, report) = dac_setup(case % 64);
        let calibration = unsafe { initial.calibrate_dac(&mut bus, &report) }.unwrap();
        {
            let mut m = bus.model.lock().unwrap();
            m.dac = None;
            // Factory bytes live entirely in the protected OTP tail, outside
            // the actual logical board stream used by previous phases.
            let addresses = [
                0x1ef, 0x1b0, 0x1d4, 0x1ee, 0x1d2, 0x1ec, 0x1e8, 0x1e4, 0x1e0, 0x1dc, 0x1eb, 0x1e7,
                0x1e3, 0x1df, 0x1db, 0x1d6, 0x1d8, 0x1d5, 0x1d7,
            ];
            for (i, a) in addresses.into_iter().enumerate() {
                m.physical[a] = if case == 0 || (case >> (i % 9)) & 1 == 0 {
                    255
                } else {
                    (case * 37 + i as u32 * 29) as u8
                };
            }
        }
        // This is the real private-provenance 512-byte native OTP transport,
        // not a publicly constructed Physical or copied diagnostic byte token.
        let physical = unsafe { super::super::efuse::read(&mut bus) }.unwrap();
        {
            let mut m = bus.model.lock().unwrap();
            m.initial(case as usize);
            let bb = m.get(2, 1) | 3;
            m.set(2, 1, bb);
            let rf = m.get(0x1f, 1) | 7;
            m.set(0x1f, 1, rf);
            let wlrf = m.get(0xec, 4) | 0x07000000;
            m.set(0xec, 4, wlrf);
            let b8 = (m.get(0x3ee0, 4) & !(1 << 15)) | ((case & 1) << 15);
            m.set(0x3ee0, 4, b8);
            m.calls = 0;
            m.events.clear();
        }
        (bus, calibration, report, physical)
    }
    fn tail_setup(pattern: usize, a: u8, b: u8) -> (Bus, FactoryInitialized, Report) {
        let (mut bus, calibration, report, _) = trim_setup(0);
        {
            let mut m = bus.model.lock().unwrap();
            m.physical[16..21].copy_from_slice(&[0x4f, 0x3e, a, b, 255]);
        }
        let physical = unsafe { super::super::efuse::read(&mut bus) }.unwrap();
        assert_eq!(
            physical.logical().unwrap().board().raw().thermal_raw,
            [a, b]
        );
        let factory =
            unsafe { calibration.initialize_factory(&mut bus, &report, &physical) }.unwrap();
        {
            let mut m = bus.model.lock().unwrap();
            m.initial(pattern);
            let bb = m.get(2, 1) | 3;
            m.set(2, 1, bb);
            let rf = m.get(0x1f, 1) | 7;
            m.set(0x1f, 1, rf);
            let wlrf = m.get(0xec, 4) | 0x07000000;
            m.set(0xec, 4, wlrf);
            m.calls = 0;
            m.events.clear();
        }
        (bus, factory, report)
    }
    fn source_mac_setup(cut: u8) -> (Bus, Report) {
        let (bus, _, report) = setup(cut, 0, 63, 0, false, false);
        {
            let mut m = bus.model.lock().unwrap();
            m.fifo_ready = true;
            m.set(0x10d0, 4, 0);
            m.set(0x10d4, 4, 0);
        }
        (bus, report)
    }
    #[test]
    fn source_mac_executes_real_fifo_protocol_driver_info_interface_and_all_error_retention() {
        let (mut bus, report) = source_mac_setup(3);
        let state = unsafe { source_mac::initialize(&mut bus, &report) }.unwrap();
        assert_eq!(state.rx_filter_map1(), 0xffff);
        assert_eq!(state.fifo().profile(), bus.profile());
        let total = bus.model.lock().unwrap().calls;
        {
            let m = bus.model.lock().unwrap();
            assert!(m.events.iter().any(|e| e[0] == 1 && e[1] == 0x208));
            assert!(
                m.events
                    .iter()
                    .any(|e| e[..3] == [1, 0x522, 2] && e[3] == 0)
            );
            assert_eq!(m.get(0x3fc, 4) & (1 << 26), 1 << 26);
            assert_eq!(m.get(0x60f, 1), 4);
            assert_ne!(m.get(0x608, 4) & (1 << 28), 0);
        }
        for at in 1..=total {
            let (mut bus, report) = source_mac_setup(3);
            bus.model.lock().unwrap().fail = Some(at);
            assert!(
                unsafe { source_mac::initialize(&mut bus, &report) }.is_err(),
                "{at}"
            );
            assert!(bus.model.lock().unwrap().quarantined >= 1, "{at}");
        }
        for (r, w, v, at) in [(0xf0, 4, 0, total - 1), (0x80, 2, 0xffff, total)] {
            let (mut bus, report) = source_mac_setup(3);
            bus.model.lock().unwrap().mutate = Some((at, r, w, v));
            assert!(unsafe { source_mac::initialize(&mut bus, &report) }.is_err());
            assert!(bus.model.lock().unwrap().quarantined >= 1);
        }
        let (mut bus, report) = source_mac_setup(3);
        bus.panic_register = Some(0x1664);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                source_mac::initialize(&mut bus, &report)
            }))
            .is_err()
        );
        assert!(bus.model.lock().unwrap().quarantined >= 1);
    }
    #[test]
    fn source_mac_rejects_unrecognized_cut_or_foreign_report_before_fifo_io() {
        let (mut bus, report) = source_mac_setup(7);
        assert!(matches!(
            unsafe { source_mac::initialize(&mut bus, &report) },
            Err(Error::UnsupportedCut(7))
        ));
        assert_eq!(bus.model.lock().unwrap().calls, 0);
        let (mut bus, _) = source_mac_setup(1);
        let (_, other) = source_mac_setup(2);
        assert!(matches!(
            unsafe { source_mac::initialize(&mut bus, &other) },
            Err(Error::WrongProfile)
        ));
        assert_eq!(bus.model.lock().unwrap().calls, 0);
    }
    #[test]
    #[ignore = "requires unchanged whole MAC protocol/driver-info/PCI interface source oracle"]
    fn source_mac_all_cut_register_patterns_widths_io_and_bar_match() {
        let path = std::path::PathBuf::from(
            std::env::var("STELA_REALTEK_WIFI_SOURCE_MAC_ORACLE").unwrap(),
        );
        assert_eq!(
            std::fs::read(path.parent().unwrap().join("data.rs")).unwrap(),
            include_bytes!("phy_tables/source_mac/data.rs")
        );
        let trace = std::fs::read(path).unwrap();
        let mut offset = 0;
        let mut cases = 0;
        while offset < trace.len() {
            let h: [u32; 4] = core::array::from_fn(|i| {
                u32::from_le_bytes(
                    trace[offset + i * 4..offset + i * 4 + 4]
                        .try_into()
                        .unwrap(),
                )
            });
            offset += 16;
            let (mut bus, _, _) = setup(h[0] as u8, 0, 63, h[1] as usize, false, false);
            let mut a = Attempt {
                profile: bus.profile(),
                io: &mut bus,
                done: false,
            };
            let rx = source_mac::protocol(&mut a).unwrap();
            a.done = true;
            drop(a);
            assert_eq!(u32::from(rx), h[3]);
            let events = &trace[offset..offset + h[2] as usize * 16];
            offset += events.len();
            let bar = &trace[offset..offset + 0x5000];
            offset += bar.len();
            let m = bus.model.lock().unwrap();
            assert_eq!(source_events(&m.events), events, "MAC IO {cases}");
            assert!(
                m.bytes == bar,
                "MAC BAR {cases}: {:?}",
                m.bytes.iter().zip(bar).position(|(a, b)| a != b)
            );
            assert_eq!(m.quarantined, 0);
            cases += 1;
        }
        assert_eq!(cases, 896);
    }
    fn channel_setup() -> (Bus, PhyInitialized, Report, channel_power::Geometry) {
        let (bus, phy, report, _) = power_setup();
        let g = channel_power::Geometry::new(36, channel_power::Width::Mhz80, Some(38), Some(42))
            .unwrap();
        (bus, phy, report, g)
    }
    #[test]
    fn actual_channel_state_binds_next_power_geometry_and_every_uncertain_io_retains_owner() {
        let (mut bus, phy, report, g) = channel_setup();
        let state = unsafe { phy.set_channel(&mut bus, &report, g) }.unwrap();
        assert_eq!(state.geometry(), g);
        assert_eq!(state.primary_index(), 4);
        assert_eq!(state.programmed_rf18() & 255, 42);
        assert_eq!(
            state.initial_igi(),
            bus.model.lock().unwrap().get(0x1d70, 4) as u8 & 127
        );
        let total = bus.model.lock().unwrap().calls;
        let plan = state
            .phy()
            .factory_power()
            .plan_channel_power(g, power_limits())
            .unwrap();
        unsafe { state.program_channel_power(&mut bus, &report, plan) }.unwrap();
        for at in 1..=total {
            let (mut bus, phy, report, g) = channel_setup();
            bus.model.lock().unwrap().fail = Some(at);
            assert!(
                unsafe { phy.set_channel(&mut bus, &report, g) }.is_err(),
                "{at}"
            );
            assert!(bus.model.lock().unwrap().quarantined >= 1, "{at}");
        }
        let (mut bus, phy, report, g) = channel_setup();
        let state = unsafe { phy.set_channel(&mut bus, &report, g) }.unwrap();
        let bad = channel_power::Geometry::new(1, channel_power::Width::Mhz20, None, None).unwrap();
        let plan = state
            .phy()
            .factory_power()
            .plan_channel_power(bad, power_limits())
            .unwrap();
        bus.model.lock().unwrap().calls = 0;
        assert!(matches!(
            unsafe { state.program_channel_power(&mut bus, &report, plan) },
            Err(Error::ChannelPower(channel_power::Error::Geometry))
        ));
        assert_eq!(bus.model.lock().unwrap().calls, 0);
    }
    #[test]
    fn channel_late_domain_loss_reset_and_partial_rf_unwind_quarantines() {
        let (mut bus, phy, report, g) = channel_setup();
        unsafe { phy.set_channel(&mut bus, &report, g) }.unwrap();
        let total = bus.model.lock().unwrap().calls;
        for (r, w, v, at) in [
            (0xf0, 4, 0, total - 4),
            (0x80, 2, 0xffff, total - 3),
            (2, 1, 0, total - 2),
            (0x1f, 1, 0, total - 1),
            (0xec, 4, 0, total),
        ] {
            let (mut bus, phy, report, g) = channel_setup();
            bus.model.lock().unwrap().mutate = Some((at, r, w, v));
            assert!(unsafe { phy.set_channel(&mut bus, &report, g) }.is_err());
            assert!(bus.model.lock().unwrap().quarantined >= 1);
        }
        let (mut bus, phy, report, g) = channel_setup();
        bus.panic_register = Some(0x3fb8);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                phy.set_channel(&mut bus, &report, g)
            }))
            .is_err()
        );
        let m = bus.model.lock().unwrap();
        assert!(m.events.iter().any(|e| e[0] == 1 && e[1] == 0x1c90));
        assert!(m.quarantined >= 1);
    }
    #[test]
    #[ignore = "requires unchanged complete source BB/MAC/RF channel oracle"]
    fn source_all_channel_geometries_igi_wrap_and_whole_io_bar_match() {
        let trace =
            std::fs::read(std::env::var("STELA_REALTEK_WIFI_CHANNEL_ORACLE").unwrap()).unwrap();
        let mut offset = 0;
        let mut cases = 0;
        while offset < trace.len() {
            let h: [u32; 8] = core::array::from_fn(|i| {
                u32::from_le_bytes(
                    trace[offset + i * 4..offset + i * 4 + 4]
                        .try_into()
                        .unwrap(),
                )
            });
            offset += 32;
            let width = match h[1] {
                0 => channel_power::Width::Mhz20,
                1 => channel_power::Width::Mhz40,
                _ => channel_power::Width::Mhz80,
            };
            let g = channel_power::Geometry::new(
                h[0] as u8,
                width,
                if h[2] == 0 { None } else { Some(h[2] as u8) },
                if h[3] == 0 { None } else { Some(h[3] as u8) },
            )
            .unwrap();
            assert_eq!(u32::from(channel::primary_index(g)), h[6]);
            let (mut bus, _, report) = setup(1, 0, 63, h[4] as usize, false, false);
            {
                let mut m = bus.model.lock().unwrap();
                let v = m.get(2, 1) | 3;
                m.set(2, 1, v);
                let v = m.get(0x1f, 1) | 7;
                m.set(0x1f, 1, v);
                let v = m.get(0xec, 4) | 0x07000000;
                m.set(0xec, 4, v);
                let v = (m.get(0x1d70, 4) & !127) | h[5];
                m.set(0x1d70, 4, v);
            }
            let mut a = Attempt {
                profile: bus.profile(),
                io: &mut bus,
                done: false,
            };
            channel::set(&mut a, &report, g, h[6] as u8).unwrap();
            a.done = true;
            drop(a);
            let events = &trace[offset..offset + h[7] as usize * 16];
            offset += events.len();
            let bar = &trace[offset..offset + 0x5000];
            offset += bar.len();
            let m = bus.model.lock().unwrap();
            assert_eq!(source_events(&m.events), events, "source IO {cases}");
            assert!(
                m.bytes == bar,
                "BAR {cases}: {:?}",
                m.bytes.iter().zip(bar).position(|(a, b)| a != b)
            );
            assert_eq!(m.quarantined, 0);
            cases += 1;
        }
        assert_eq!(cases, 360);
    }
    fn power_limits() -> channel_power::Limits {
        channel_power::Limits {
            factory_sheet: FactorySheet::Fcc,
            max_eirp_mbm: 2500,
            antenna_and_combining_mbm: [100, 125],
            sar_quarter_dbm: Some([90, 89]),
            remnant_cck: 0,
            remnant_ofdm: [0; 2],
        }
    }
    fn power_setup() -> (Bus, PhyInitialized, Report, channel_power::Plan) {
        let (mut bus, factory, report) = tail_setup(0, 5, 6);
        let phy = unsafe { factory.finish_initial_phy(&mut bus, &report) }.unwrap();
        let g = channel_power::Geometry::new(1, channel_power::Width::Mhz20, None, None).unwrap();
        let plan = phy
            .factory_power()
            .plan_channel_power(g, power_limits())
            .unwrap();
        {
            let mut m = bus.model.lock().unwrap();
            m.calls = 0;
            m.events.clear();
        }
        (bus, phy, report, plan)
    }
    #[test]
    fn channel_power_consumes_actual_phy_and_every_io_failure_reset_unwind_retains_owner() {
        let (mut bus, phy, report, plan) = power_setup();
        let programmed = unsafe { phy.program_channel_power(&mut bus, &report, plan) }.unwrap();
        assert_eq!(programmed.plan().geometry().primary(), 1);
        assert_eq!(programmed.phy().factory_power().rfe(), 0);
        let _phy = programmed.into_phy();
        let total = bus.model.lock().unwrap().calls;
        for at in 1..=total {
            let (mut bus, phy, report, plan) = power_setup();
            bus.model.lock().unwrap().fail = Some(at);
            assert!(
                unsafe { phy.program_channel_power(&mut bus, &report, plan) }.is_err(),
                "{at}"
            );
            assert_eq!(bus.model.lock().unwrap().quarantined, 1, "{at}");
        }
        for (r, w, v, at) in [
            (0xf0, 4, 0, total - 4),
            (0x80, 2, 0xffff, total - 3),
            (2, 1, 0, total - 2),
            (0x1f, 1, 0, total - 1),
            (0xec, 4, 0, total),
        ] {
            let (mut bus, phy, report, plan) = power_setup();
            bus.model.lock().unwrap().mutate = Some((at, r, w, v));
            assert!(unsafe { phy.program_channel_power(&mut bus, &report, plan) }.is_err());
            assert_eq!(bus.model.lock().unwrap().quarantined, 1);
        }
        let (mut bus, phy, report, plan) = power_setup();
        bus.panic_register = Some(0x3a00);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                phy.program_channel_power(&mut bus, &report, plan)
            }))
            .is_err()
        );
        let m = bus.model.lock().unwrap();
        assert!(m.events.iter().any(|e| e[0] == 1 && e[1] == 0x18e8));
        assert_eq!(m.quarantined, 1);
    }
    #[test]
    fn channel_power_foreign_board_and_unrepresentable_os_limits_have_zero_register_effects() {
        let (mut bus, phy, report, _) = power_setup();
        let g = channel_power::Geometry::new(1, channel_power::Width::Mhz20, None, None).unwrap();
        let other = board_power::channel_fixture(5, [255; 168])
            .plan_channel_power(g, power_limits())
            .unwrap();
        assert!(matches!(
            unsafe { phy.program_channel_power(&mut bus, &report, other) },
            Err(Error::ChannelPower(channel_power::Error::WrongBoard))
        ));
        assert_eq!(bus.model.lock().unwrap().calls, 0);
        let (bus, phy, _, _) = power_setup();
        let mut l = power_limits();
        l.sar_quarter_dbm = Some([i32::MIN; 2]);
        assert!(phy.factory_power().plan_channel_power(g, l).is_err());
        assert_eq!(bus.model.lock().unwrap().calls, 0);
    }
    #[test]
    #[ignore = "requires unchanged complete board/channel gain/SAR/TXAGC oracle"]
    fn channel_power_whole_source_calculations_actual_io_and_bar_match() {
        let trace =
            std::fs::read(std::env::var("STELA_REALTEK_WIFI_CHANNEL_POWER_ORACLE").unwrap())
                .unwrap();
        let mut offset = 0;
        for c in 0..512u32 {
            let h: [u32; 9] = core::array::from_fn(|i| {
                u32::from_le_bytes(
                    trace[offset + i * 4..offset + i * 4 + 4]
                        .try_into()
                        .unwrap(),
                )
            });
            offset += 36;
            assert_eq!(h[0], c);
            let nvm: [u8; 168] = trace[offset..offset + 168].try_into().unwrap();
            offset += 168;
            let table = &trace[offset..offset + 336];
            offset += 336;
            let events = &trace[offset..offset + h[7] as usize * 16];
            offset += events.len();
            let bar = &trace[offset..offset + h[8] as usize];
            offset += bar.len();
            let width = match h[2] {
                0 => channel_power::Width::Mhz20,
                1 => channel_power::Width::Mhz40,
                _ => channel_power::Width::Mhz80,
            };
            let g = channel_power::Geometry::new(
                h[1] as u8,
                width,
                if h[3] == 0 { None } else { Some(h[3] as u8) },
                if h[4] == 0 { None } else { Some(h[4] as u8) },
            )
            .unwrap();
            let limits = channel_power::Limits {
                factory_sheet: FactorySheet::try_from(h[5] as u8).unwrap(),
                max_eirp_mbm: (h[6] as i32 + 2) * 25,
                antenna_and_combining_mbm: [50, 75],
                sar_quarter_dbm: Some([h[6] as i32 + 4, h[6] as i32 - 1]),
                remnant_cck: (c % 3) as i8,
                remnant_ofdm: [(c % 3) as i8, (c % 2) as i8],
            };
            let power = board_power::channel_fixture((c % 7) as u8, nvm);
            let plan = power
                .plan_channel_power(g, limits)
                .unwrap_or_else(|e| panic!("case {c}: {e:?}"));
            for path in 0..2 {
                for rate in 0..84 {
                    if let Some(gain) = plan.gain(path, rate) {
                        assert_eq!(
                            gain,
                            table[path as usize * 84 + rate as usize],
                            "case {c} path {path} rate {rate}"
                        );
                    }
                }
            }
            let (mut bus, _, _) = setup(1, (c % 7) as u8, 63, c as usize, false, false);
            let mut a = Attempt {
                profile: bus.profile(),
                io: &mut bus,
                done: false,
            };
            channel_power::program_registers(&mut a, &plan).unwrap();
            a.done = true;
            drop(a);
            let m = bus.model.lock().unwrap();
            assert_eq!(source_events(&m.events), events, "events {c}");
            assert!(
                m.bytes == bar,
                "BAR {c}: first mismatch {:?}",
                m.bytes.iter().zip(bar).position(|(a, b)| a != b)
            );
            assert_eq!(m.quarantined, 0);
        }
        assert_eq!(trace.len() - offset, 65536 + 384 * 2);
    }
    #[test]
    fn phy_tail_disables_mu_validity_keeps_source_widths_and_raw_thermal_reference() {
        let (mut bus, factory, report) = tail_setup(3, 255, 255);
        let before = bus.model.lock().unwrap().get(0x14c0, 4);
        let initialized = unsafe { factory.finish_initial_phy(&mut bus, &report) }.unwrap();
        let power = initialized
            .factory()
            .calibration()
            .initial()
            .factory_power();
        assert_eq!(power.profile(), bus.profile());
        assert_eq!(power.rfe(), 0);
        assert_eq!(power.limit_sheet_type(), 0);
        let t = initialized.tracking();
        assert_eq!(t.delta_power_index, [0; 4]);
        assert_eq!(t.averages, [None; 4]);
        assert_eq!(t.filter_state, [0; 4]);
        assert!(!t.triggered);
        assert_eq!(t.thermal_reference, 255);
        assert_eq!(t.lck_reference, 255);
        assert_eq!(initialized.factory().raw().thermal, [255; 2]);
        let m = bus.model.lock().unwrap();
        assert_eq!(
            m.get(0x14c0, 4),
            ((before | 0x10000) & !(0xf000 | 0x80 | 0x3f)) | 0xa000
        );
        assert_eq!(m.get(0x14c0, 4) & 0xbf, 0);
        let writes: Vec<_> = m
            .events
            .iter()
            .filter(|e| e[0] == 1)
            .map(|e| (e[1], e[2]))
            .collect();
        assert_eq!(
            writes,
            [
                (0x14c0, 4),
                (0x167c, 1),
                (0x1680, 2),
                (0x42c, 4),
                (0x45f, 1),
                (0x6dc, 4)
            ]
        );
        assert_eq!(m.quarantined, 0);
    }
    #[test]
    fn phy_tail_every_io_failure_late_reset_and_partial_write_unwind_quarantines() {
        let (mut bus, factory, report) = tail_setup(0, 5, 6);
        unsafe { factory.finish_initial_phy(&mut bus, &report) }.unwrap();
        let total = bus.model.lock().unwrap().calls;
        for at in 1..=total {
            let (mut bus, factory, report) = tail_setup(0, 5, 6);
            bus.model.lock().unwrap().fail = Some(at);
            assert!(
                unsafe { factory.finish_initial_phy(&mut bus, &report) }.is_err(),
                "{at}"
            );
            assert_eq!(bus.model.lock().unwrap().quarantined, 1, "{at}");
        }
        for (r, w, v, at) in [
            (0xf0, 4, 0, total - 4),
            (0x80, 2, 0xffff, total - 3),
            (2, 1, 0, total - 2),
            (0x1f, 1, 0, total - 1),
            (0xec, 4, 0, total),
        ] {
            let (mut bus, factory, report) = tail_setup(0, 5, 6);
            bus.model.lock().unwrap().mutate = Some((at, r, w, v));
            assert!(unsafe { factory.finish_initial_phy(&mut bus, &report) }.is_err());
            assert_eq!(bus.model.lock().unwrap().quarantined, 1);
        }
        let (mut bus, factory, report) = tail_setup(0, 5, 6);
        bus.panic_register = Some(0x42c);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                factory.finish_initial_phy(&mut bus, &report)
            }))
            .is_err()
        );
        let m = bus.model.lock().unwrap();
        assert!(m.events.iter().any(|e| e[0] == 1 && e[1] == 0x1680));
        assert_eq!(m.quarantined, 1);
    }
    #[test]
    fn phy_tail_rejects_mismatched_profile_layout_and_initial_domain_without_programming() {
        let (mut bus, factory, _) = tail_setup(0, 0, 0);
        let (_, _, other) = setup(2, 0, 0, 0, false, false);
        assert!(matches!(
            unsafe { factory.finish_initial_phy(&mut bus, &other) },
            Err(Error::WrongProfile)
        ));
        assert_eq!(bus.model.lock().unwrap().calls, 0);
        let (mut bus, factory, _) = tail_setup(0, 0, 0);
        let (_, _, one) = setup(1, 0, 0, 0, true, false);
        assert!(matches!(
            unsafe { factory.finish_initial_phy(&mut bus, &one) },
            Err(Error::UnsupportedRfLayout)
        ));
        assert_eq!(bus.model.lock().unwrap().calls, 0);
        for (r, w) in [(2, 1), (0x1f, 1), (0xec, 4)] {
            let (mut bus, factory, report) = tail_setup(0, 0, 0);
            bus.model.lock().unwrap().set(r, w, 0);
            assert!(matches!(
                unsafe { factory.finish_initial_phy(&mut bus, &report) },
                Err(Error::DomainOff)
            ));
            let m = bus.model.lock().unwrap();
            assert!(!m.events.iter().any(|e| e[0] == 1));
            assert_eq!(m.quarantined, 1);
        }
    }
    #[test]
    #[ignore = "requires unchanged source thermal reset/EWMA initialization and complete beamforming IO/BAR oracle"]
    fn phy_tail_whole_source_io_tracking_and_bar_match() {
        let trace =
            std::fs::read(std::env::var("STELA_REALTEK_WIFI_PHY_TAIL_ORACLE").unwrap()).unwrap();
        let mut offset = 0;
        for case in 0..1024 {
            let head: [u32; 5] = core::array::from_fn(|i| {
                u32::from_le_bytes(
                    trace[offset + i * 4..offset + i * 4 + 4]
                        .try_into()
                        .unwrap(),
                )
            });
            offset += 20;
            let [pattern, a, b, reference, events] = head;
            let (mut bus, factory, report) = tail_setup(pattern as usize, a as u8, b as u8);
            let initialized = unsafe { factory.finish_initial_phy(&mut bus, &report) }.unwrap();
            let t = initialized.tracking();
            assert_eq!(u32::from(t.thermal_reference), reference);
            let m = bus.model.lock().unwrap();
            let native = source_events(&m.events);
            assert_eq!(native.len(), events as usize * 16, "{case}");
            assert_eq!(&native, &trace[offset..offset + native.len()], "{case}");
            offset += native.len();
            let mut words = Vec::new();
            words.extend(t.delta_power_index.map(|v| v as u32));
            words.extend(t.filter_state.map(|v| u32::try_from(v).unwrap()));
            words.extend(t.averages.map(|v| u32::from(v.unwrap_or(255))));
            words.extend([
                u32::from(t.triggered),
                u32::from(t.thermal_reference),
                u32::from(t.lck_reference),
            ]);
            let bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
            assert_eq!(bytes.len(), 60);
            assert_eq!(&bytes, &trace[offset..offset + 60], "{case}");
            offset += 60;
            assert_eq!(&m.bytes, &trace[offset..offset + 0x5000], "{case}");
            offset += 0x5000;
            assert_eq!(m.quarantined, 0);
        }
        assert_eq!(offset, trace.len());
    }
    #[test]
    fn factory_retains_real_blank_optional_and_explicit_source_default_effects() {
        let (mut bus, calibration, report, physical) = trim_setup(0);
        let factory =
            unsafe { calibration.initialize_factory(&mut bus, &report, &physical) }.unwrap();
        assert!(!factory.x2_busy_observed());
        assert_eq!(factory.thermal_written(), [None; 2]);
        assert_eq!(factory.power_gain(), None);
        assert_eq!(factory.power_present_mask(), 0);
        assert_eq!(factory.pa_written(), [[None; 2]; 2]);
        let m = bus.model.lock().unwrap();
        let writes: Vec<_> = m.events.iter().filter(|e| e[0] == 1).collect();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0][1], 0xa70);
        drop(m);
        let (mut bus, calibration, report, physical) = trim_setup(320);
        let factory =
            unsafe { calibration.initialize_factory(&mut bus, &report, &physical) }.unwrap();
        assert_eq!(factory.raw().pa[0][1], 255);
        assert_eq!(factory.raw().pa[1][1], 255);
        assert_eq!(factory.pa_written()[0][1], Some(15));
        assert_eq!(factory.pa_written()[1][1], Some(15));
        let m = bus.model.lock().unwrap();
        assert_eq!(m.get(0x3d80, 4) & 0xf0000, 0xf0000);
        assert_eq!(m.get(0x4d80, 4) & 0xf0000, 0xf0000);
        drop(m);
        let (mut bus, calibration, report, physical) = trim_setup(1);
        let factory =
            unsafe { calibration.initialize_factory(&mut bus, &report, &physical) }.unwrap();
        assert!(factory.x2_busy_observed());
        assert!(factory.thermal_written()[0].is_some());
        assert_eq!(factory.thermal_written()[1], None);
        let gain = factory.power_gain().unwrap();
        assert_eq!(gain[0][0], 0);
        assert_eq!(factory.power_present_mask() & 1, 0);
        assert_ne!(factory.power_present_mask(), 0);
        assert_ne!(factory.power_present_mask(), u16::MAX);
    }
    #[test]
    fn factory_io_failures_late_reset_and_unwind_retain_actual_owner() {
        let (mut bus, calibration, report, physical) = trim_setup(511);
        unsafe { calibration.initialize_factory(&mut bus, &report, &physical) }.unwrap();
        let total = bus.model.lock().unwrap().calls;
        let mut points: Vec<_> = (1..=48).collect();
        points.extend((1..=32).map(|i| i * total / 32));
        points.extend(total - 15..=total);
        points.sort_unstable();
        points.dedup();
        for at in points {
            let (mut bus, calibration, report, physical) = trim_setup(511);
            bus.model.lock().unwrap().fail = Some(at);
            assert!(
                unsafe { calibration.initialize_factory(&mut bus, &report, &physical) }.is_err(),
                "{at}"
            );
            assert!(bus.model.lock().unwrap().quarantined >= 1, "{at}");
        }
        for (r, w, v, at) in [
            (0xf0, 4, 0, total - 4),
            (0x80, 2, 0xffff, total - 3),
            (2, 1, 0, total - 2),
            (0x1f, 1, 0, total - 1),
            (0xec, 4, 0, total),
        ] {
            let (mut bus, calibration, report, physical) = trim_setup(511);
            bus.model.lock().unwrap().mutate = Some((at, r, w, v));
            assert!(
                unsafe { calibration.initialize_factory(&mut bus, &report, &physical) }.is_err()
            );
            assert!(bus.model.lock().unwrap().quarantined >= 1);
        }
        let (mut bus, calibration, report, physical) = trim_setup(511);
        bus.panic_delay = true;
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                calibration.initialize_factory(&mut bus, &report, &physical)
            }))
            .is_err()
        );
        assert_eq!(bus.model.lock().unwrap().quarantined, 1);
    }
    #[test]
    fn factory_rejects_a_different_actual_captured_rfe_or_power_calibration_before_io() {
        for change_rfe in [true, false] {
            let (mut bus, calibration, report, _) = trim_setup(0);
            {
                let mut m = bus.model.lock().unwrap();
                if change_rfe {
                    m.physical[6] = 5;
                } else {
                    // Append a genuine logical power-table word at offset10.
                    m.physical[16..21].copy_from_slice(&[0x2e, 1, 2, 0xff, 0xff]);
                }
            }
            let other = unsafe { super::super::efuse::read(&mut bus) }.unwrap();
            bus.model.lock().unwrap().calls = 0;
            bus.model.lock().unwrap().events.clear();
            assert!(matches!(
                unsafe { calibration.initialize_factory(&mut bus, &report, &other) },
                Err(Error::WrongProfile)
            ));
            assert_eq!(bus.model.lock().unwrap().calls, 0);
        }
    }
    #[test]
    fn factory_report_layout_and_off_domain_reject_before_any_writes() {
        let (mut bus, calibration, _, physical) = trim_setup(0);
        let (_, _, other) = setup(2, 0, 0, 0, false, false);
        assert!(matches!(
            unsafe { calibration.initialize_factory(&mut bus, &other, &physical) },
            Err(Error::WrongProfile)
        ));
        assert_eq!(bus.model.lock().unwrap().calls, 0);
        let (mut bus, calibration, _, physical) = trim_setup(0);
        let (_, _, one) = setup(1, 0, 0, 0, true, false);
        assert!(matches!(
            unsafe { calibration.initialize_factory(&mut bus, &one, &physical) },
            Err(Error::UnsupportedRfLayout)
        ));
        assert_eq!(bus.model.lock().unwrap().calls, 0);
        for (r, w) in [(2, 1), (0x1f, 1), (0xec, 4)] {
            let (mut bus, calibration, report, physical) = trim_setup(0);
            bus.model.lock().unwrap().set(r, w, 0);
            assert!(matches!(
                unsafe { calibration.initialize_factory(&mut bus, &report, &physical) },
                Err(Error::DomainOff)
            ));
            let m = bus.model.lock().unwrap();
            assert!(!m.events.iter().any(|e| e[0] == 1));
            assert_eq!(m.quarantined, 1);
        }
    }
    #[test]
    #[ignore = "requires unchanged pinned source complete factory RF trim traces and real OTP provenance"]
    fn factory_all_optional_blank_combinations_and_actual_source_io_bar_match() {
        let trace =
            std::fs::read(std::env::var("STELA_REALTEK_WIFI_TRIM_ORACLE").unwrap()).unwrap();
        let mut offset = 0;
        for case in 0..512 {
            let head: [u32; 3] = core::array::from_fn(|i| {
                u32::from_le_bytes(
                    trace[offset + i * 4..offset + i * 4 + 4]
                        .try_into()
                        .unwrap(),
                )
            });
            offset += 12;
            let [seed, busy, events] = head;
            assert_eq!(seed, case);
            let (mut bus, calibration, report, physical) = trim_setup(seed);
            assert_eq!(&physical.bytes()[388..], &trace[offset + 388..offset + 512]);
            offset += 512;
            let factory =
                unsafe { calibration.initialize_factory(&mut bus, &report, &physical) }.unwrap();
            assert_eq!(u32::from(factory.x2_busy_observed()), busy);
            let m = bus.model.lock().unwrap();
            let native = source_events(&m.events);
            assert_eq!(native.len(), events as usize * 16, "case {case}");
            assert_eq!(
                &native,
                &trace[offset..offset + native.len()],
                "case {case}"
            );
            offset += native.len();
            assert_eq!(&m.bytes, &trace[offset..offset + 0x5000], "case {case}");
            offset += 0x5000;
            assert_eq!(m.quarantined, 0);
        }
        assert_eq!(offset, trace.len());
    }
    #[test]
    fn dac_requires_real_complete_samples_ready_and_convergence() {
        for (invalid, unstable, adc_residual, dac_residual, expected) in [
            (Some(0), false, 0, 0, Error::DacSamples { accepted: 0 }),
            (Some(99), false, 0, 0, Error::DacSamples { accepted: 99 }),
            (None, true, 0, 0, Error::DacUnstableSamples),
            (
                None,
                false,
                5,
                0,
                Error::DacAdcConvergence { path: Path::A },
            ),
            (None, false, 0, 5, Error::DacConvergence { path: Path::A }),
        ] {
            let (mut bus, initial, report) = dac_setup(0);
            {
                let mut m = bus.model.lock().unwrap();
                let d = m.dac.as_mut().unwrap();
                d.invalid_after = invalid;
                d.unstable = unstable;
                d.adc_residual = adc_residual;
                d.dac_residual = dac_residual;
            }
            assert!(
                matches!(unsafe {initial.calibrate_dac(&mut bus,&report)},Err(e)if e==expected)
            );
            assert!(bus.model.lock().unwrap().quarantined >= 1);
        }
        for (reg, raw, expected) in [
            (0x2808, 0, Error::DacReadyTimeout { register: 0x2808 }),
            (
                0x2808,
                u32::MAX,
                Error::DacAmbiguousReady { register: 0x2808 },
            ),
            (0x2824, 1 << 19, Error::DacReadyTimeout { register: 0x2824 }),
        ] {
            let (mut bus, initial, report) = dac_setup(0);
            bus.model
                .lock()
                .unwrap()
                .dac
                .as_mut()
                .unwrap()
                .ready_override = Some((reg, raw));
            assert!(
                matches!(unsafe {initial.calibrate_dac(&mut bus,&report)},Err(e)if e==expected)
            );
            assert!(bus.model.lock().unwrap().quarantined >= 1);
        }
    }
    #[test]
    fn dac_accepts_complete_last_bounded_sample_and_last_ready_poll() {
        let (mut bus, initial, report) = dac_setup(0);
        {
            let mut m = bus.model.lock().unwrap();
            let d = m.dac.as_mut().unwrap();
            d.invalid_prefix = 9900;
            d.ready_delay = Some((0x2808, 999));
        }
        let calibrated = unsafe { initial.calibrate_dac(&mut bus, &report) }.unwrap();
        assert_eq!(calibrated.residual(), [[0; 2]; 2]);
        let m = bus.model.lock().unwrap();
        assert!(m.dac.as_ref().unwrap().samples >= 10000);
        assert_eq!(m.dac.as_ref().unwrap().ready_reads, 1000);
        assert_eq!(m.quarantined, 0);
    }
    #[test]
    fn dac_retains_distinct_rf_backups_and_each_actual_b_dck_nibble() {
        let (mut bus, initial, report) = dac_setup(0);
        {
            let mut m = bus.model.lock().unwrap();
            m.set(0x3e3c, 4, 0x12345);
            m.set(0x4e3c, 4, 0x6789a);
            m.dac.as_mut().unwrap().distinct_cache = true;
        }
        let calibrated = unsafe { initial.calibrate_dac(&mut bus, &report) }.unwrap();
        assert_eq!(calibrated.dck()[1], [[1, 2], [3, 4]]);
        let m = bus.model.lock().unwrap();
        assert_eq!(m.get(0x3e3c, 4) & 0xfffff, 0x12345);
        assert_eq!(m.get(0x4e3c, 4) & 0xfffff, 0x6789a);
        assert_eq!(calibrated.residual(), [[0; 2]; 2]);
        assert_eq!(m.quarantined, 0);
    }
    #[test]
    fn dac_rejects_wrong_profiles_layout_and_initial_domain_before_writes() {
        let (mut bus, initial, _) = dac_setup(0);
        let (_, _, other) = setup(2, 0, 0, 0, false, false);
        assert!(matches!(
            unsafe { initial.calibrate_dac(&mut bus, &other) },
            Err(Error::WrongProfile)
        ));
        assert_eq!(bus.model.lock().unwrap().calls, 0);
        let (mut bus, initial, _) = dac_setup(0);
        let (_, _, one) = setup(1, 0, 0, 0, true, false);
        assert!(matches!(
            unsafe { initial.calibrate_dac(&mut bus, &one) },
            Err(Error::UnsupportedRfLayout)
        ));
        assert_eq!(bus.model.lock().unwrap().calls, 0);
        for (r, w) in [(2, 1), (0x1f, 1), (0xec, 4)] {
            let (mut bus, initial, report) = dac_setup(0);
            bus.model.lock().unwrap().set(r, w, 0);
            assert!(matches!(
                unsafe { initial.calibrate_dac(&mut bus, &report) },
                Err(Error::DomainOff)
            ));
            let m = bus.model.lock().unwrap();
            assert!(!m.events.iter().any(|e| e[0] == 1));
            assert_eq!(m.quarantined, 1);
        }
    }
    #[test]
    fn dac_partial_io_failures_late_reset_and_unwind_retain_native_owner() {
        let (mut bus, initial, report) = dac_setup(0);
        unsafe { initial.calibrate_dac(&mut bus, &report) }.unwrap();
        let total = bus.model.lock().unwrap().calls;
        let mut points: Vec<_> = (1..=48).collect();
        points.extend((1..=32).map(|i| i * total / 32));
        points.extend(total - 15..=total);
        points.sort_unstable();
        points.dedup();
        for at in points {
            let (mut bus, initial, report) = dac_setup(0);
            bus.model.lock().unwrap().fail = Some(at);
            assert!(
                unsafe { initial.calibrate_dac(&mut bus, &report) }.is_err(),
                "{at}"
            );
            assert!(bus.model.lock().unwrap().quarantined >= 1, "{at}");
        }
        for (r, w, v, at) in [
            (0xf0, 4, 0, total - 4),
            (0x80, 2, 0xffff, total - 3),
            (2, 1, 0, total - 2),
            (0x1f, 1, 0, total - 1),
            (0xec, 4, 0, total),
        ] {
            let (mut bus, initial, report) = dac_setup(0);
            bus.model.lock().unwrap().mutate = Some((at, r, w, v));
            assert!(unsafe { initial.calibrate_dac(&mut bus, &report) }.is_err());
            assert!(bus.model.lock().unwrap().quarantined >= 1);
        }
        let (mut bus, initial, report) = dac_setup(0);
        bus.panic_delay = true;
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
                initial.calibrate_dac(&mut bus, &report)
            }))
            .is_err()
        );
        assert!(bus.model.lock().unwrap().quarantined >= 1);
    }
    #[test]
    #[ignore = "requires unchanged pinned initial empty-cache DAC oracle and donor negative evidence"]
    fn dac_source_complete_initial_sequences_vectors_and_bar_match() {
        let trace = std::fs::read(std::env::var("STELA_REALTEK_WIFI_DAC_ORACLE").unwrap()).unwrap();
        let mut offset = 0;
        for case in 0..64 {
            let header: [u32; 3] = core::array::from_fn(|i| {
                u32::from_le_bytes(
                    trace[offset + i * 4..offset + i * 4 + 4]
                        .try_into()
                        .unwrap(),
                )
            });
            offset += 12;
            let [seed, input, events] = header;
            assert_eq!(input as i32, seed as i32 - 32);
            let (mut bus, initial, report) = dac_setup(seed);
            let calibrated = unsafe { initial.calibrate_dac(&mut bus, &report) }.unwrap();
            let m = bus.model.lock().unwrap();
            let native = source_events(&m.events);
            assert_eq!(native.len(), events as usize * 16, "{case}");
            assert_eq!(
                &native,
                &trace[offset..offset + native.len()],
                "case {case}"
            );
            offset += native.len();
            let mut words = Vec::new();
            words.extend(calibrated.adck());
            words.extend(
                calibrated
                    .msbk()
                    .iter()
                    .flatten()
                    .flatten()
                    .copied()
                    .map(u32::from),
            );
            words.extend(
                calibrated
                    .dck()
                    .into_iter()
                    .flatten()
                    .flatten()
                    .map(u32::from),
            );
            let bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
            assert_eq!(bytes.len(), 70 * 4);
            assert_eq!(&bytes, &trace[offset..offset + bytes.len()], "{case}");
            offset += bytes.len();
            assert_eq!(&m.bytes, &trace[offset..offset + 0x5000], "{case}");
            offset += 0x5000;
            assert_eq!(m.quarantined, 0);
        }
        // Independently consumed by pure compensation test in child module.
        offset += 201 * 12;
        let negative: [u32; 6] = core::array::from_fn(|i| {
            u32::from_le_bytes(
                trace[offset + i * 4..offset + i * 4 + 4]
                    .try_into()
                    .unwrap(),
            )
        });
        assert_eq!(negative, [0x6789a, 0x6789a, 1, 3, 2, 4]);
        offset += 24;
        // Full signed-vector source results are independently consumed in child tests.
        offset += 2048 * 828;
        assert_eq!(offset, trace.len());
    }
    #[test]
    fn initial_dynamic_observes_fresh_igi_cck_and_preserves_unrelated_edcca_bits() {
        let (mut bus, paths, report) = dynamic_setup(3, 127, 0x7f, 63, 0);
        let old = bus.model.lock().unwrap().get(0x84c, 4);
        let state = unsafe { paths.initialize_dynamic(&mut bus, &report) }.unwrap();
        assert_eq!(state.profile(), bus.profile());
        assert_eq!(state.igi_history(), [127, 0, 0, 0]);
        assert_eq!(state.cck_bounds(), [63, 0]);
        assert_eq!(state.crystal_cap(), 127);
        let t = state.tracking();
        assert_eq!(t.fa_history, [0; 4]);
        assert_eq!(t.igi_bitmap, 0);
        assert_eq!(t.cck_pd_levels, [[0; 4]; 2]);
        assert_eq!(t.cck_fa_average, None);
        assert!(!t.iqk_done);
        assert!(t.cfo_adjusting);
        assert_eq!(t.current_tx_path, Path::A);
        assert_eq!(t.path_counts, [0; 2]);
        assert_eq!(t.path_sums, [0; 2]);
        let m = bus.model.lock().unwrap();
        assert_eq!(m.get(0x84c, 4), (old & 0xffff) | 0xffff0000);
        let writes: Vec<_> = m
            .events
            .iter()
            .filter(|e| e[0] == 1)
            .map(|e| (e[1], e[2]))
            .collect();
        assert_eq!(
            writes,
            [(0x84c, 4), (0x84c, 4), (0x520, 4), (0x524, 4), (0x844, 4)]
        );
        assert_eq!(m.quarantined, 0);
    }
    #[test]
    fn dynamic_every_io_failure_and_late_domain_loss_quarantines_without_state() {
        let (mut bus, paths, report) = dynamic_setup(0, 0, 63, 0, 63);
        unsafe { paths.initialize_dynamic(&mut bus, &report) }.unwrap();
        let total = bus.model.lock().unwrap().calls;
        for at in 1..=total {
            let (mut bus, paths, report) = dynamic_setup(0, 0, 63, 0, 63);
            bus.model.lock().unwrap().fail = Some(at);
            assert!(
                unsafe { paths.initialize_dynamic(&mut bus, &report) }.is_err(),
                "{at}"
            );
            assert_eq!(bus.model.lock().unwrap().quarantined, 1, "{at}");
        }
        for (r, w, value, at) in [
            (0xf0, 4, 0, total - 4),
            (0x80, 2, 0xffff, total - 3),
            (2, 1, 0, total - 2),
            (0x1f, 1, 0, total - 1),
            (0xec, 4, 0, total),
        ] {
            let (mut bus, paths, report) = dynamic_setup(0, 0, 63, 0, 63);
            bus.model.lock().unwrap().mutate = Some((at, r, w, value));
            assert!(unsafe { paths.initialize_dynamic(&mut bus, &report) }.is_err());
            let m = bus.model.lock().unwrap();
            assert!(m.events.iter().any(|e| e[0] == 1));
            assert_eq!(m.quarantined, 1);
        }
    }
    #[test]
    fn dynamic_unwind_after_partial_edcca_setup_retains_actual_owner() {
        let (mut bus, paths, report) = dynamic_setup(0, 0, 0, 0, 0);
        bus.panic_register = Some(0x524);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            paths.initialize_dynamic(&mut bus, &report)
        }));
        assert!(caught.is_err());
        let m = bus.model.lock().unwrap();
        assert!(m.events.iter().any(|e| e[0] == 1 && e[1] == 0x520));
        assert_eq!(m.quarantined, 1);
    }
    #[test]
    fn dynamic_rejects_mismatched_report_and_actual_off_domain_before_programming() {
        let (mut bus, paths, _) = dynamic_setup(0, 0, 0, 0, 0);
        let (_, _, other) = setup(2, 0, 0, 0, false, false);
        assert!(matches!(
            unsafe { paths.initialize_dynamic(&mut bus, &other) },
            Err(Error::WrongProfile)
        ));
        assert_eq!(bus.model.lock().unwrap().calls, 0);
        let (mut bus, paths, _) = dynamic_setup(0, 0, 0, 0, 0);
        let (_, _, one) = setup(1, 0, 0, 0, true, false);
        assert!(matches!(
            unsafe { paths.initialize_dynamic(&mut bus, &one) },
            Err(Error::UnsupportedRfLayout)
        ));
        assert_eq!(bus.model.lock().unwrap().calls, 0);
        for (r, w) in [(2, 1), (0x1f, 1), (0xec, 4)] {
            let (mut bus, paths, report) = dynamic_setup(0, 0, 0, 0, 0);
            bus.model.lock().unwrap().set(r, w, 0);
            assert!(matches!(
                unsafe { paths.initialize_dynamic(&mut bus, &report) },
                Err(Error::DomainOff)
            ));
            let m = bus.model.lock().unwrap();
            assert!(!m.events.iter().any(|e| e[0] == 1));
            assert_eq!(m.quarantined, 1);
        }
    }
    #[test]
    #[ignore = "requires unchanged pinned C dynamic hardware/tracking oracle; no jurisdiction selection"]
    fn dynamic_all_source_io_tracking_and_bar_match_with_policy_unqualified() {
        let trace =
            std::fs::read(std::env::var("STELA_REALTEK_WIFI_DYNAMIC_ORACLE").unwrap()).unwrap();
        let mut offset = 0;
        for case in 0..512 {
            let mut header = [0; 6];
            for (i, v) in header.iter_mut().enumerate() {
                *v = u32::from_le_bytes(
                    trace[offset + i * 4..offset + i * 4 + 4]
                        .try_into()
                        .unwrap(),
                );
            }
            offset += 24;
            let [pattern, igi, crystal, upper, lower, events] = header;
            let (mut bus, paths, report) =
                dynamic_setup(pattern as usize, igi, crystal as u8, upper, lower);
            let state = unsafe { paths.initialize_dynamic(&mut bus, &report) }.unwrap();
            let m = bus.model.lock().unwrap();
            let native = source_events(&m.events);
            assert_eq!(native.len(), events as usize * 16, "{case}");
            assert_eq!(&native, &trace[offset..offset + native.len()], "{case}");
            offset += native.len();
            let mut words = Vec::new();
            for word in dynamic_words(&state) {
                words.extend(word.to_le_bytes());
            }
            assert_eq!(words.len(), 28 * 4);
            assert_eq!(&words, &trace[offset..offset + words.len()], "{case}");
            offset += words.len();
            assert_eq!(&m.bytes, &trace[offset..offset + 0x5000], "{case}");
            offset += 0x5000;
            assert_eq!(m.quarantined, 0);
        }
        assert_eq!(offset, trace.len());
    }
    #[test]
    fn initial_paths_preserve_source_reset_width_and_igi_wrap_latch_effects() {
        for igi in [0u32, 1, 2, 63, 127] {
            let (mut bus, loaded, report) = paths_setup(3, igi);
            let original = bus.model.lock().unwrap().get(2, 2);
            let configured = unsafe { loaded.configure_paths(&mut bus, &report) }.unwrap();
            assert_eq!(configured.profile(), bus.profile());
            assert_eq!(u32::from(configured.initial_igi()), igi);
            let m = bus.model.lock().unwrap();
            let resets: Vec<_> = m
                .events
                .iter()
                .filter(|e| e[0] == 1 && e[1] == 2)
                .copied()
                .collect();
            assert_eq!(resets.len(), 9);
            for pulse in resets.as_chunks::<3>().0 {
                assert_eq!(
                    *pulse,
                    [
                        [1, 2, 2, original | 1],
                        [1, 2, 2, original & !1],
                        [1, 2, 2, original | 1]
                    ]
                );
            }
            let latches: Vec<_> = m
                .events
                .iter()
                .filter(|e| e[0] == 1 && e[1] == 0x1d70)
                .map(|e| e[3])
                .collect();
            assert_eq!(latches.len(), 4);
            assert_eq!(latches[0] & 127, igi.wrapping_sub(2) & 127);
            assert_eq!((latches[1] >> 8) & 127, igi.wrapping_sub(2) & 127);
            assert_eq!(latches[2] & 127, igi);
            assert_eq!((latches[3] >> 8) & 127, igi);
            assert_eq!(m.quarantined, 0);
        }
    }
    #[test]
    fn every_path_io_failure_and_late_reset_retains_actual_owner_without_configured_state() {
        let (mut bus, loaded, report) = paths_setup(0, 0);
        unsafe { loaded.configure_paths(&mut bus, &report) }.unwrap();
        let total = bus.model.lock().unwrap().calls;
        for at in 1..=total {
            let (mut bus, loaded, report) = paths_setup(0, 0);
            bus.model.lock().unwrap().fail = Some(at);
            assert!(
                unsafe { loaded.configure_paths(&mut bus, &report) }.is_err(),
                "operation {at}"
            );
            assert!(bus.model.lock().unwrap().quarantined >= 1, "operation {at}");
        }
        for (r, w, value, at) in [(0xf0, 4, 0, total - 4), (0x80, 2, 0xffff, total - 3)] {
            let (mut bus, loaded, report) = paths_setup(0, 0);
            bus.model.lock().unwrap().mutate = Some((at, r, w, value));
            assert!(unsafe { loaded.configure_paths(&mut bus, &report) }.is_err());
            let m = bus.model.lock().unwrap();
            assert!(m.events.iter().any(|e| e[0] == 1 && e[1] == 2 && e[2] == 2));
            assert!(m.quarantined >= 1);
        }
    }
    #[test]
    fn path_profile_report_and_actual_domain_mismatches_do_not_program_bb() {
        let (mut bus, loaded, _) = paths_setup(0, 63);
        let (_, _, other) = setup(2, 0, 0, 0, false, false);
        assert!(matches!(
            unsafe { loaded.configure_paths(&mut bus, &other) },
            Err(Error::WrongProfile)
        ));
        assert_eq!(bus.model.lock().unwrap().calls, 0);
        let (mut bus, loaded, _) = paths_setup(0, 63);
        let (_, _, one) = setup(1, 0, 0, 0, true, false);
        assert!(matches!(
            unsafe { loaded.configure_paths(&mut bus, &one) },
            Err(Error::UnsupportedRfLayout)
        ));
        assert_eq!(bus.model.lock().unwrap().calls, 0);
        for (r, w) in [(2, 1), (0x1f, 1), (0xec, 4)] {
            let (mut bus, loaded, report) = paths_setup(0, 63);
            bus.model.lock().unwrap().set(r, w, 0);
            assert!(matches!(
                unsafe { loaded.configure_paths(&mut bus, &report) },
                Err(Error::DomainOff)
            ));
            let m = bus.model.lock().unwrap();
            assert!(!m.events.iter().any(|e| e[0] == 1));
            assert_eq!(m.quarantined, 1);
        }
    }
    #[test]
    #[ignore = "requires unchanged pinned C initial AB/AB/false TRX oracle"]
    fn every_igi_and_complete_source_trx_trace_and_bar_matches() {
        let trace = std::fs::read(std::env::var("STELA_REALTEK_WIFI_TRX_ORACLE").unwrap()).unwrap();
        let mut offset = 0;
        for case in 0..512 {
            let mut header = [0; 3];
            for (i, v) in header.iter_mut().enumerate() {
                *v = u32::from_le_bytes(
                    trace[offset + i * 4..offset + i * 4 + 4]
                        .try_into()
                        .unwrap(),
                );
            }
            offset += 12;
            let [pattern, igi, events] = header;
            let (mut bus, loaded, report) = paths_setup(pattern as usize, igi);
            let configured = unsafe { loaded.configure_paths(&mut bus, &report) }.unwrap();
            assert_eq!(u32::from(configured.initial_igi()), igi);
            let m = bus.model.lock().unwrap();
            let native = source_events(&m.events);
            assert_eq!(native.len(), events as usize * 16, "case {case}");
            assert_eq!(
                &native,
                &trace[offset..offset + native.len()],
                "case {case}"
            );
            offset += native.len();
            assert_eq!(&m.bytes, &trace[offset..offset + 0x5000], "case {case}");
            offset += 0x5000;
            assert_eq!(m.quarantined, 0);
        }
        assert_eq!(offset, trace.len());
    }
    #[test]
    fn all_compiled_streams_are_structurally_preflighted_and_unknown_profiles_do_no_io() {
        for cut in 0u32..=6 {
            for rfe in 0u8..=6 {
                let condition = u32::from(rfe)
                    | (1 << 8)
                    | (15 << 12)
                    | (4 << 16)
                    | ((if cut == 0 { 15 } else { cut }) << 24);
                for &(table, kind) in &TABLES {
                    walk(condition, table, |a, v| check(kind, a, v)).unwrap();
                }
            }
        }
        for (cut, rfe, one, invalid, expected) in [
            (7, 0, false, false, Error::UnsupportedCut(7)),
            (0, 255, false, false, Error::UnsupportedRfe(255)),
            (0, 0, true, false, Error::UnsupportedRfLayout),
            (0, 0, false, true, Error::InvalidMac),
        ] {
            let (mut bus, board, report) = setup(cut, rfe, 0x3f, 0, one, invalid);
            assert!(matches!(unsafe{initialize(&mut bus,&board,&report)},Err(e)if e==expected));
            let m = bus.model.lock().unwrap();
            assert_eq!(m.calls, 0);
            assert!(m.events.is_empty());
            assert_eq!(m.quarantined, 0);
        }
        let (mut bus, board, _) = setup(0, 0, 0, 0, false, false);
        let (_, _, other) = setup(1, 0, 0, 0, false, false);
        assert!(matches!(
            unsafe { initialize(&mut bus, &board, &other) },
            Err(Error::WrongProfile)
        ));
        assert_eq!(bus.model.lock().unwrap().calls, 0);
    }
    #[test]
    fn flat_branch_semantics_and_malformed_streams_are_explicit() {
        let condition = 5 | (1 << 8) | (15 << 12) | (4 << 16) | (3 << 24);
        let table = [
            [0x800, 1],
            [0x8300f105, 0x12345678],
            [0x40000000, 0],
            [0x804, 2],
            [0x9300f106, 0],
            [0x40000000, 0],
            [0x808, 3],
            [0xa0000000, 0],
            [0x80c, 4],
            [0xb0000000, 0],
            [0x810, 5],
        ];
        let mut actual = Vec::new();
        assert_eq!(
            walk(condition, &table, |a, v| {
                actual.push((a, v));
                Ok(())
            })
            .unwrap(),
            3
        );
        assert_eq!(actual, [(0x800, 1), (0x804, 2), (0x810, 5)]);
        let mut actual = Vec::new();
        walk(condition ^ 3, &table, |a, v| {
            actual.push((a, v));
            Ok(())
        })
        .unwrap();
        assert_eq!(actual, [(0x800, 1), (0x808, 3), (0x810, 5)]);
        for bad in [
            &[[0x40000000, 0]][..],
            &[[0xb0000000, 0]][..],
            &[[0x80000000, 0], [0x804, 1]][..],
            &[[0x80000000, 0], [0x40000000, 0]][..],
            &[[0xc0000000, 0]][..],
            &[
                [0x80000000, 0],
                [0x40000000, 0],
                [0xa0000000, 0],
                [0xa0000000, 0],
                [0xb0000000, 0],
            ][..],
        ] {
            assert!(matches!(
                walk(condition, bad, |_, _| Ok(())),
                Err(Error::TableGrammar { .. })
            ));
        }
        assert_eq!(
            check(Kind::Rf(Path::B), 256, 0),
            Err(Error::TableAddress { address: 256 })
        );
        assert_eq!(
            check(Kind::Rf(Path::A), 1, 0x100000),
            Err(Error::TableValue { address: 1 })
        );
        assert!(check(Kind::Bb, 0x5000, 0).is_err());
        assert!(check(Kind::Agc, 0x801, 0).is_err());
    }
    #[test]
    fn representative_io_failure_late_reset_and_unwind_never_publish_loaded_tables() {
        let (mut bus, board, report) = setup(1, 0, 0x7f, 0, false, false);
        unsafe { initialize(&mut bus, &board, &report) }.unwrap();
        let total = bus.model.lock().unwrap().calls;
        let mut positions: Vec<usize> = (1..=48).collect();
        positions.extend((1..=32).map(|i| (i * total / 32).max(1)));
        positions.extend(total - 15..=total);
        positions.sort_unstable();
        positions.dedup();
        for at in positions {
            let (mut bus, board, report) = setup(1, 0, 0x7f, 0, false, false);
            bus.model.lock().unwrap().fail = Some(at);
            assert!(
                unsafe { initialize(&mut bus, &board, &report) }.is_err(),
                "operation {at}"
            );
            assert!(bus.model.lock().unwrap().quarantined >= 1, "operation {at}");
        }
        for (r, w, v, at) in [(0xf0, 4, 0, total - 1), (0x80, 2, 0xffff, total)] {
            let (mut bus, board, report) = setup(1, 0, 0x7f, 0, false, false);
            bus.model.lock().unwrap().mutate = Some((at, r, w, v));
            assert!(unsafe { initialize(&mut bus, &board, &report) }.is_err());
            let m = bus.model.lock().unwrap();
            assert!(m.events.iter().any(|e| e[0] == 1 && e[1] >= 0x3c00));
            assert!(m.quarantined >= 1);
        }
        let (mut bus, board, report) = setup(1, 0, 0x7f, 0, false, false);
        bus.panic_delay = true;
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            initialize(&mut bus, &board, &report)
        }));
        assert!(caught.is_err());
        assert!(bus.model.lock().unwrap().quarantined >= 1);
    }
    #[test]
    #[ignore = "requires unchanged pinned C complete pre-TRX PHY table phase"]
    fn every_supported_board_cut_and_crystal_endpoint_matches_complete_source_phase() {
        let trace =
            std::fs::read(std::env::var("STELA_REALTEK_WIFI_PHY_TABLES_ORACLE").unwrap()).unwrap();
        let mut offset = 0;
        for case in 0..196 {
            let mut header = [0; 6];
            for (i, v) in header.iter_mut().enumerate() {
                *v = u32::from_le_bytes(
                    trace[offset + i * 4..offset + i * 4 + 4]
                        .try_into()
                        .unwrap(),
                );
            }
            offset += 24;
            let [cut, rfe, crystal, seed, condition, events] = header;
            let (mut bus, board, report) = setup(
                cut as u8,
                rfe as u8,
                crystal as u8,
                seed as usize,
                false,
                false,
            );
            let loaded = unsafe { initialize(&mut bus, &board, &report) }.unwrap();
            assert_eq!(loaded.condition(), condition);
            assert_eq!(loaded.profile(), bus.profile());
            let counts = loaded.configured_pairs();
            assert_eq!(counts[0], 0);
            assert_eq!(counts[3], data::CAL.len());
            assert!(counts[4] > 0 && counts[5] > 0);
            let m = bus.model.lock().unwrap();
            let native = source_events(&m.events);
            assert_eq!(native.len(), events as usize * 16, "case {case}");
            assert_eq!(
                &native,
                &trace[offset..offset + native.len()],
                "case {case}"
            );
            offset += native.len();
            assert_eq!(&m.bytes, &trace[offset..offset + 0x5000], "case {case}");
            offset += 0x5000;
            assert_eq!(m.quarantined, 0);
        }
        // Actual unchanged source one-PHY case selects B and ignores the
        // helper's rejection. Native preflight test above refuses before I/O.
        let mut rejected = [0; 5];
        for (i, value) in rejected.iter_mut().enumerate() {
            *value = u32::from_le_bytes(
                trace[offset + i * 4..offset + i * 4 + 4]
                    .try_into()
                    .unwrap(),
            );
        }
        assert_eq!(&rejected[..4], &[1, 1, 1, 1]);
        let condition = (1 << 24) | (4 << 16) | (15 << 12) | (1 << 8);
        let mut expected_rejections = 0;
        walk(condition, data::RF_B, |address, _| {
            if ![0xffe, 0xfe].contains(&address) {
                expected_rejections += 1;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(rejected[4], expected_rejections);
        offset += 20;
        assert_eq!(offset, trace.len());
    }
}
