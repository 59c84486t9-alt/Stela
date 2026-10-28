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
    io::{self, Io},
    rf::{self, Path},
};
pub use dac::{DacCalibrated, FactoryBytes, FactoryInitialized, PhyInitialized, ThermalTracking};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Hardware(io::Error),
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
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
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
pub(super) fn control_fixture() -> (PhyInitialized, Report) {
    tests::control_fixture()
}
#[cfg(test)]
mod tests;
