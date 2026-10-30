// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2015-2017 Intel Deutschland GmbH
//! Private source-enabled cold response envelope on the original owner.
use super::*;
use crate::wifi::regulatory::{
    HardwareLease, HardwarePolicy, LegacyRate, OsLease, Purpose, TxProfile, Width,
};

const BASIC_24: [LegacyRate; 7] = [
    LegacyRate::Cck1,
    LegacyRate::Cck2,
    LegacyRate::Cck5_5,
    LegacyRate::Cck11,
    LegacyRate::Ofdm6,
    LegacyRate::Ofdm12,
    LegacyRate::Ofdm24,
];
const BASIC_5: [LegacyRate; 3] = [LegacyRate::Ofdm6, LegacyRate::Ofdm12, LegacyRate::Ofdm24];
fn rates(channel: Channel) -> &'static [LegacyRate] {
    match channel.band {
        Band::Ghz2 => &BASIC_24,
        Band::Ghz5 => &BASIC_5,
        Band::Ghz6 => &[],
    }
}
fn cck(rate: LegacyRate) -> bool {
    matches!(
        rate,
        LegacyRate::Cck1 | LegacyRate::Cck2 | LegacyRate::Cck5_5 | LegacyRate::Cck11
    )
}
const LEGACY_RATES: [LegacyRate; 12] = [
    LegacyRate::Cck1,
    LegacyRate::Cck2,
    LegacyRate::Cck5_5,
    LegacyRate::Cck11,
    LegacyRate::Ofdm6,
    LegacyRate::Ofdm9,
    LegacyRate::Ofdm12,
    LegacyRate::Ofdm18,
    LegacyRate::Ofdm24,
    LegacyRate::Ofdm36,
    LegacyRate::Ofdm48,
    LegacyRate::Ofdm54,
];
struct Hardware<'p, 'a, Q: BootIo, B: BiosIo> {
    receive: policy::Hardware<'p, 'a, Q, B>,
    channel: Channel,
    ceiling: i32,
    eligible: bool,
    no_ofdm: bool,
    rate_mask: u16,
}
struct Guard<'g, 'p, 'a, Q: BootIo, B: BiosIo> {
    receive: policy::Guard<'g, 'p, 'a, Q, B>,
    channel: Channel,
    ceiling: i32,
    eligible: bool,
    no_ofdm: bool,
    rate_mask: u16,
}
// SAFETY: construction is private to the original completed power owner. Its
// initialized HR2 firmware/NVM, TX-antenna command, BIOS/board/SAR, MCC
// and SET_LINK ceiling all belong to that same epoch. Firmware owns
// source calibration and rate/antenna power enforcement, as in Linux's unified
// HR2 path; this does not claim host-measured EIRP. The cold MAC has exactly the
// source basic response masks0xf/0x15, long preamble, no associated peer or HT
// transmit configuration and no data queues. The private legacy-peer owner
// may additionally program only a finite NON_HT rate bitmap at20MHz. The
// selected MLD continuation may publish one empty scheduler queue for that
// station, with invalid TFDs and no frame/rate/association change.
// This policy still admits no frame publication. SET_LINK/HR2 calibration
// apply to every such source legacy rate under the same original board/MCC.
// Every enabled response/configured rate is checked against the
// original OS lease at publication; restrictive revocation remains armed until
// unbind/stop under unsafe begin_binding's service contract.
unsafe impl<'p, 'a, Q: BootIo, B: BiosIo> HardwarePolicy for Hardware<'p, 'a, Q, B> {
    type Lease<'g>
        = Guard<'g, 'p, 'a, Q, B>
    where
        Self: 'g;
    fn acquire(&mut self) -> Option<Self::Lease<'_>> {
        Some(Guard {
            receive: self.receive.acquire()?,
            channel: self.channel,
            ceiling: self.ceiling,
            eligible: self.eligible,
            no_ofdm: self.no_ofdm,
            rate_mask: self.rate_mask,
        })
    }
}
impl<Q: BootIo, B: BiosIo> HardwareLease for Guard<'_, '_, '_, Q, B> {
    fn context(&self) -> regulatory::NativeContext {
        self.receive.context()
    }
    fn lookup_channel(&mut self, band: Band, number: u16) -> Option<Channel> {
        self.receive.lookup_channel(band, number)
    }
    fn allows(&mut self, operation: Operation) -> bool {
        match operation {
            Operation::Receive(channel) => self.receive.allows(Operation::Receive(channel)),
            Operation::Transmit {
                channel,
                purpose,
                profile,
            } => {
                self.eligible
                    && channel == self.channel
                    && purpose == Purpose::Management
                    && profile.width == Width::Legacy20
                    && !profile.short_preamble
                    && profile.max_eirp_mbm == self.ceiling
                    && self.rate_mask & (1 << profile.rate as u8) != 0
                    && (!self.no_ofdm || cck(profile.rate))
                    && self.receive.allows(Operation::Receive(channel))
            }
        }
    }
}
/// One hardware-then-OS guard pair covers the complete finite union,
/// then the original native HCMD visibility. No copied admission, caller
/// calibration boolean or single-rate grant can replace any rate check.
pub(super) unsafe fn publish<Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy>(
    power: &mut Ax200TransmitPower<'_, Q, B, O>,
    command: &BindingCommand,
    source: &dyn PageSource,
) -> Result<CommandTicket, Ax200BindingError> {
    // SAFETY: existing exact finite cold response union.
    unsafe { publish_legacy(power, command.id, &command.bytes, 0, source) }
}
/// The private legacy peer may additionally configure a finite NON_HT rate
/// bitmap. This admits no frame or queue publication and no modern rates.
/// Every source-enabled cold response and configured rate is held under the
/// same provider pair; the SET_LINK applies to all these rates.
pub(super) unsafe fn publish_legacy<Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy>(
    power: &mut Ax200TransmitPower<'_, Q, B, O>,
    id: Id,
    bytes: &[u8],
    legacy_mask: u16,
    source: &dyn PageSource,
) -> Result<CommandTicket, Ax200BindingError> {
    // SAFETY: same exact finite envelope and original native page contract;
    // the existing command submission stays inside both leases.
    unsafe {
        with_legacy_policy(power, legacy_mask, |boot| {
            boot.submit_command(id, bytes, source)
        })
    }?
    .map_err(Ax200BindingError::Boot)
}
/// Keep both leases held through a private checked native publication.
/// The queue continuation additionally initializes and exposes its fresh DMA
/// inside this closure, before the HCMD publishes those exact addresses.
/// # Safety
/// The operation must preserve the original exclusive requester/domain/page
/// contract and introduce no response rate outside this checked finite union.
pub(super) unsafe fn with_legacy_policy<T, Q: BootIo, B: BiosIo, O: CountryIo + OsPolicy>(
    power: &mut Ax200TransmitPower<'_, Q, B, O>,
    legacy_mask: u16,
    operation: impl FnOnce(&mut RomBoot<'_, Q>) -> T,
) -> Result<T, Ax200BindingError> {
    let channel = power.phy.channel;
    let allowed = match channel.band {
        Band::Ghz2 => 0xfff,
        Band::Ghz5 => 0xff0,
        Band::Ghz6 => 0,
    };
    if legacy_mask & !allowed != 0 || rates(channel).is_empty() {
        return Err(Ax200BindingError::Regulatory(
            regulatory::Error::Unsupported,
        ));
    }
    let rate_mask = rates(channel)
        .iter()
        .fold(legacy_mask, |mask, rate| mask | (1 << *rate as u8));
    let applied = power.applied.as_ref().ok_or(Ax200BindingError::State)?;
    let ceiling = i32::from(applied.effective_dbm) * 100;
    let nvm = &power.phy.scan.mac.initialized_nvm().information;
    let firmware = &power
        .phy
        .scan
        .mac
        .country
        .board
        .scan
        .mcc
        .setup
        .lari
        .radio
        .initialized
        .boot
        .firmware;
    let mut antennas = ((firmware.phy_sku().ok_or(Ax200BindingError::State)? >> 16) & 15) as u8;
    if nvm.tx_chains as u8 != 0 {
        antennas &= nvm.tx_chains as u8;
    }
    let antennas_valid = antennas != 0 && antennas & !3 == 0;
    let parts = power
        .phy
        .scan
        .mac
        .country
        .scan_policy_parts()
        .ok_or(Ax200BindingError::State)?;
    let rule = parts
        .selection
        .country
        .rule(u32::from(channel.frequency_mhz) * 1000, 20_000)
        .ok_or(Ax200BindingError::Regulatory(
            regulatory::Error::HardwareDenied,
        ))?;
    let no_ofdm = rule.no_ofdm;
    // A station answers its AP: like `cfg80211_chandef_usable` for one, NO-IR,
    // DFS and indoor-only channels carry its frames.
    let country_allowed = ceiling <= i32::from(rule.max_eirp_mbm);
    let mcc_allowed = parts.channels.iter().any(|entry| {
        entry.channel.number == channel.number
            && entry.channel.frequency_mhz == channel.frequency_mhz
            && matches!(
                (entry.channel.band, channel.band),
                (crate::wifi::intel::mcc::channel::Band::Ghz2, Band::Ghz2)
                    | (crate::wifi::intel::mcc::channel::Band::Ghz5, Band::Ghz5)
            )
            && entry.valid
    });
    let mut hardware = Hardware {
        receive: policy::Hardware {
            board: parts.board,
            selection: parts.selection,
            channels: parts.channels,
            native: power.phy.scan.native,
        },
        channel,
        ceiling,
        eligible: antennas_valid && country_allowed && mcc_allowed,
        no_ofdm,
        rate_mask,
    };
    let mut service = policy::Os {
        service: parts.os,
        selection_revision: parts.selection.revision,
    };
    let mut native = hardware.acquire().ok_or(Ax200BindingError::Regulatory(
        regulatory::Error::HardwareUnavailable,
    ))?;
    let mut os = service
        .acquire(native.context())
        .ok_or(Ax200BindingError::Regulatory(
            regulatory::Error::OsUnavailable,
        ))?;
    if rates(channel).is_empty() {
        return Err(Ax200BindingError::Regulatory(
            regulatory::Error::Unsupported,
        ));
    }
    for &rate in &LEGACY_RATES {
        if rate_mask & (1 << rate as u8) == 0 {
            continue;
        }
        let operation = Operation::Transmit {
            channel,
            purpose: Purpose::Management,
            profile: TxProfile {
                width: Width::Legacy20,
                rate,
                short_preamble: false,
                max_eirp_mbm: ceiling,
            },
        };
        if native.lookup_channel(channel.band, channel.number) != Some(channel)
            || !native.allows(operation)
        {
            return Err(Ax200BindingError::Regulatory(
                regulatory::Error::HardwareDenied,
            ));
        }
        if !os.allows(operation) {
            return Err(Ax200BindingError::Regulatory(regulatory::Error::OsDenied));
        }
    }
    // SAFETY: exact private finite response/rate union and same native domain;
    // both leases span the entire operation, including additional DMA handoff.
    let result = unsafe { native.receive.with_boot(operation) };
    drop(os);
    Ok(result)
}
