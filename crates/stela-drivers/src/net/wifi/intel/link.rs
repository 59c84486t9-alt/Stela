// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2015-2017 Intel Deutschland GmbH
//! One AX200/AX210 function brought up as iwlwifi's mvm does it, polled one
//! step at a time: ROM boot to ALIVE, PNVM, unified NVM, the cold radio
//! prefix, LARI, setup, MCC, scan configuration, board power policy, the
//! country, the MLD MAC context (`iwl_mvm_up` and `iwl_mvm_mac_add_interface`),
//! then a passive scan for the configured network and, for the strongest
//! beacon carrying its SSID, the PHY context, transmit power, link, AP
//! station, its management queue and Bluetooth coexistence
//! (`iwl_mvm_mld_assign_vif_chanctx`, `iwl_mvm_mld_add_sta`).
//!
//! Every step's firmware command waits for its own acknowledgement; a
//! failed step keeps every owner the device may still reach.
use super::{
    boot::{
        self, Ax200BindingError, Ax200BindingPhase, Ax200BoardPolicy, Ax200BoardPolicyError,
        Ax200BoardPolicyPhase, Ax200Coexistence, Ax200CoexistenceError, Ax200CoexistencePhase,
        Ax200Country, Ax200CountryError, Ax200CountryPhase, Ax200LegacyPeer, Ax200LegacyPeerError,
        Ax200LegacyPeerPhase, Ax200Mac, Ax200MacError, Ax200MacPhase, Ax200ManagementQueue,
        Ax200ManagementQueueError, Ax200ManagementQueuePhase, Ax200Mcc, Ax200MccError,
        Ax200MccPhase, Ax200Phy, Ax200PhyError, Ax200PhyPhase, Ax200Scan, Ax200ScanConfiguration,
        Ax200ScanConfigurationError, Ax200ScanConfigurationPhase, Ax200ScanError, Ax200ScanPhase,
        Ax200Setup, Ax200SetupError, Ax200SetupOptions, Ax200SetupPhase, Ax200TransmitPower,
        Ax200TransmitPowerError, Ax200TransmitPowerPhase, BootIo, ColdRadio, ColdRadioPhase,
        InitializationProgress, LariError, LariPhase, LariRadio, LegacyPeer, MpduProgress,
        PnvmProgress, RomBoot, ScanResultProgress, UnifiedNvm,
    },
    platform::Observations,
    policy::{Beacons, Regulatory},
    radio::bios::service::BiosIo,
};
use crate::{
    Clock, Deadline,
    bus::dma::memory::PageSource,
    firmware::Provider,
    net::{
        Link, LinkError, Mac,
        wifi::{
            Band,
            network::Network,
            regulatory::database::{self, Database},
            scan::{self as protocol, result::Bss},
        },
    },
};
use alloc::{boxed::Box, format, sync::Arc, vec::Vec};
use core::any::Any;

/// iwlwifi's `IWL_MVM_UCODE_ALIVE_TIMEOUT`.
const ALIVE_TIMEOUT_US: u64 = 2_000_000;
/// iwlwifi's `MVM_UCODE_PNVM_TIMEOUT`.
const PNVM_TIMEOUT_US: u64 = 250_000;
/// The scan budget, the most a single UMAC request may run.
const SCAN_BUDGET_US: u64 = 30_000_000;

type Country<Q, B> = Ax200Country<'static, Q, B, Regulatory>;

/// Why bring-up stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Boot(boot::Error),
    Lari(LariError),
    Setup(Ax200SetupError),
    Mcc(Ax200MccError),
    ScanConfiguration(Ax200ScanConfigurationError),
    Board(Ax200BoardPolicyError),
    Country(Ax200CountryError),
    Regulatory(database::Error),
    Mac(Ax200MacError),
    Scan(Ax200ScanError),
    Phy(Ax200PhyError),
    Power(Ax200TransmitPowerError),
    Binding(Ax200BindingError),
    Peer(Ax200LegacyPeerError),
    Queue(Ax200ManagementQueueError),
    Coexistence(Ax200CoexistenceError),
    /// A step's firmware or host deadline passed.
    Timeout(&'static str),
    /// A step refused to start from the state the previous one left.
    Refused(&'static str),
}

/// Where bring-up is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Booting,
    Initializing,
    Scanning,
    Joining,
    /// The AP station and its management queue are up: authentication may
    /// begin.
    AuthenticationRequired,
    Failed,
}

/// The services bring-up borrows for the rest of the boot.
pub struct Inputs<B> {
    pub firmware: &'static dyn Provider,
    pub observations: Observations,
    pub pages: &'static dyn PageSource,
    pub clock: Clock,
    pub bios: B,
    pub database: Database,
    pub network: Network,
}

enum Stage<Q: BootIo, B: BiosIo> {
    Rom(Box<RomBoot<'static, Q>>),
    Pnvm(Box<RomBoot<'static, Q>>),
    Nvm(Box<UnifiedNvm<'static, Q>>),
    Radio(Box<ColdRadio<'static, Q>>),
    Lari(Box<LariRadio<'static, Q, B>>),
    Setup(Box<Ax200Setup<'static, Q, B>>),
    Mcc(Box<Ax200Mcc<'static, Q, B>>),
    ScanConfiguration(Box<Ax200ScanConfiguration<'static, Q, B>>),
    Board(Box<Ax200BoardPolicy<'static, Q, B>>),
    Country(Box<Country<Q, B>>),
    Mac(Box<Ax200Mac<'static, Q, B, Regulatory>>),
    Scan(Box<Ax200Scan<'static, Q, B, Regulatory>>),
    Phy(Box<Ax200Phy<'static, Q, B, Regulatory>>),
    Power(Box<Ax200TransmitPower<'static, Q, B, Regulatory>>),
    Link(Box<boot::Ax200Binding<'static, Q, B, Regulatory>>),
    Peer(Box<Ax200LegacyPeer<'static, Q, B, Regulatory>>),
    Queue(Box<Ax200ManagementQueue<'static, Q, B, Regulatory>>),
    Coexistence(Box<Ax200Coexistence<'static, Q, B, Regulatory>>),
    Ready(Box<Ax200ManagementQueue<'static, Q, B, Regulatory>>),
    /// Owners a failed step left, kept while the device may reach them.
    Failed {
        _owners: Box<dyn Any>,
    },
    Moving,
}

/// The network a scan chose to join.
#[derive(Clone, Debug)]
pub struct Selected {
    pub bss: Bss,
    pub rates: u16,
}

/// One Intel Wi-Fi function's bring-up.
pub struct Wifi<Q: BootIo, B: BiosIo> {
    stage: Stage<Q, B>,
    firmware: &'static dyn Provider,
    observations: Observations,
    pages: &'static dyn PageSource,
    clock: Clock,
    bios: Option<B>,
    database: Option<Database>,
    network: Network,
    deadline: Option<Deadline>,
    scanning: bool,
    beacons: Option<Arc<Beacons>>,
    candidate: Option<Selected>,
    selected: Option<Selected>,
    address: Mac,
    error: Option<Error>,
    /// Whether the link reported the bring-up failure.
    reported: bool,
}

/// The legacy rate bits `LegacyPeer` takes for the 500 kb/s rate units of a
/// Supported or Extended Supported Rates element, as `ieee80211_get_rates`
/// reads them; unknown rates are ignored.
pub fn legacy_rates(elements: &[u8], band: Band) -> u16 {
    const RATES: [u8; 12] = [2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];
    let mut mask = 0u16;
    let mut rest = elements;
    while let [id, length, tail @ ..] = rest {
        let Some((body, next)) = tail.split_at_checked(usize::from(*length)) else {
            break;
        };
        if matches!(id, 1 | 50) {
            for rate in body {
                if let Some(bit) = RATES.iter().position(|known| *known == rate & 0x7f) {
                    mask |= 1 << bit;
                }
            }
        }
        rest = next;
    }
    match band {
        Band::Ghz2 => mask,
        Band::Ghz5 => mask & 0xff0,
        Band::Ghz6 => 0,
    }
}

impl<Q: BootIo, B: BiosIo> Wifi<Q, B> {
    /// Take over a ROM boot `RomBoot::start` or `start_ax210` published.
    ///
    /// # Safety
    /// `boot`'s publication contract holds for the rest of the boot: `pages`
    /// gives fresh exclusive pages of its requester's domain, nothing else
    /// submits to or resets the function, and `bios` reads this function's
    /// own ACPI companion and the boot's captured variables.
    pub unsafe fn new(boot: RomBoot<'static, Q>, inputs: Inputs<B>) -> Self {
        let deadline = inputs.clock.deadline(ALIVE_TIMEOUT_US);
        Self {
            stage: Stage::Rom(Box::new(boot)),
            firmware: inputs.firmware,
            observations: inputs.observations,
            pages: inputs.pages,
            clock: inputs.clock,
            bios: Some(inputs.bios),
            database: Some(inputs.database),
            network: inputs.network,
            deadline: Some(deadline),
            scanning: false,
            beacons: None,
            candidate: None,
            selected: None,
            address: Mac::default(),
            error: None,
            reported: false,
        }
    }

    /// The station address the NVM holds, once read.
    pub fn address(&self) -> Mac {
        self.address
    }

    pub fn error(&self) -> Option<&Error> {
        self.error.as_ref()
    }

    /// The network the scan chose, once it has.
    pub fn selected(&self) -> Option<&Selected> {
        self.selected.as_ref()
    }

    pub fn phase(&self) -> Phase {
        match &self.stage {
            _ if self.error.is_some() => Phase::Failed,
            Stage::Rom(_)
            | Stage::Pnvm(_)
            | Stage::Nvm(_)
            | Stage::Radio(_)
            | Stage::Lari(_)
            | Stage::Setup(_)
            | Stage::Mcc(_) => Phase::Booting,
            Stage::ScanConfiguration(_) | Stage::Board(_) | Stage::Country(_) | Stage::Mac(_) => {
                Phase::Initializing
            }
            Stage::Scan(_) => Phase::Scanning,
            Stage::Phy(_)
            | Stage::Power(_)
            | Stage::Link(_)
            | Stage::Peer(_)
            | Stage::Queue(_)
            | Stage::Coexistence(_) => Phase::Joining,
            Stage::Ready(_) => Phase::AuthenticationRequired,
            Stage::Failed { .. } | Stage::Moving => Phase::Failed,
        }
    }

    /// Advance bring-up by at most one firmware step, never blocking.
    pub fn poll(&mut self) -> Phase {
        if self.error.is_none() {
            let stage = core::mem::replace(&mut self.stage, Stage::Moving);
            // SAFETY: `new`'s contract covers every page and service handed on.
            self.stage = match unsafe { self.step(stage) } {
                Ok(stage) => stage,
                Err((error, kept)) => {
                    self.error = Some(error);
                    Stage::Failed { _owners: kept }
                }
            };
        }
        self.phase()
    }

    /// The ROM boot the current owner nests, for device models.
    #[cfg(test)]
    pub(crate) fn rom(&self) -> Option<&RomBoot<'static, Q>> {
        match &self.stage {
            Stage::Rom(owner) | Stage::Pnvm(owner) => owner.rom(),
            Stage::Nvm(owner) => owner.rom(),
            Stage::Radio(owner) => owner.rom(),
            Stage::Lari(owner) => owner.rom(),
            Stage::Setup(owner) => owner.rom(),
            Stage::Mcc(owner) => owner.rom(),
            Stage::ScanConfiguration(owner) => owner.rom(),
            Stage::Board(owner) => owner.rom(),
            Stage::Country(owner) => owner.rom(),
            Stage::Mac(owner) => owner.rom(),
            Stage::Scan(owner) => owner.rom(),
            Stage::Phy(owner) => owner.rom(),
            Stage::Power(owner) => owner.rom(),
            Stage::Link(owner) => owner.rom(),
            Stage::Peer(owner) => owner.rom(),
            Stage::Queue(owner) | Stage::Ready(owner) => owner.rom(),
            Stage::Coexistence(owner) => owner.rom(),
            Stage::Failed { .. } | Stage::Moving => None,
        }
    }

    fn expired(&self) -> bool {
        self.deadline.as_ref().is_some_and(Deadline::passed)
    }

    unsafe fn step(&mut self, stage: Stage<Q, B>) -> Result<Stage<Q, B>, (Error, Box<dyn Any>)> {
        let pages = self.pages;
        macro_rules! advance {
            ($owner:ident, $variant:ident, $error:ident, $done:expr, $next:expr) => {{
                // SAFETY: forwarded from `poll`.
                match unsafe { $owner.advance(pages) } {
                    Ok(phase) if phase == $done => $next,
                    Ok(_) => Ok(Stage::$variant($owner)),
                    Err(error) => Err((Error::$error(error), $owner as Box<dyn Any>)),
                }
            }};
        }
        match stage {
            Stage::Rom(mut boot) => match boot.poll() {
                Ok(Some(_alive)) => {
                    // SAFETY: forwarded from `poll`.
                    match unsafe { boot.begin_pnvm(self.firmware, self.observations, pages) } {
                        Ok(PnvmProgress::Skipped | PnvmProgress::Observed) => Ok(self.nvm(*boot)),
                        Ok(PnvmProgress::Waiting) => {
                            self.deadline = Some(self.clock.deadline(PNVM_TIMEOUT_US));
                            Ok(Stage::Pnvm(boot))
                        }
                        Err(error) => Err((Error::Boot(error), boot)),
                    }
                }
                Ok(None) if self.expired() => Err((Error::Timeout("ALIVE"), boot)),
                Ok(None) => Ok(Stage::Rom(boot)),
                Err(error) => Err((Error::Boot(error), boot)),
            },
            Stage::Pnvm(mut boot) => match boot.poll_pnvm() {
                Ok(PnvmProgress::Observed | PnvmProgress::Skipped) => Ok(self.nvm(*boot)),
                Ok(PnvmProgress::Waiting) if self.expired() => Err((Error::Timeout("PNVM"), boot)),
                Ok(PnvmProgress::Waiting) => Ok(Stage::Pnvm(boot)),
                Err(error) => Err((Error::Boot(error), boot)),
            },
            Stage::Nvm(mut nvm) => {
                // SAFETY: forwarded from `poll`.
                match unsafe { nvm.advance(pages) } {
                    Ok(InitializationProgress::Observed) => {
                        self.address = Mac(nvm.receipt().map_or([0; 6], |r| r.address.bytes));
                        match nvm.begin_radio() {
                            Ok(radio) => Ok(Stage::Radio(Box::new(radio))),
                            Err(nvm) => Err((Error::Refused("cold radio"), nvm)),
                        }
                    }
                    Ok(InitializationProgress::Pending(_)) => Ok(Stage::Nvm(nvm)),
                    Err(error) => Err((Error::Boot(error), nvm)),
                }
            }
            Stage::Radio(mut radio) => {
                // SAFETY: forwarded from `poll`.
                match unsafe { radio.advance(pages) } {
                    Ok(ColdRadioPhase::PlatformConfigurationRequired) => {
                        let bios = self
                            .bios
                            .take()
                            .ok_or((Error::Refused("LARI"), Box::new(()) as Box<dyn Any>))?;
                        // SAFETY: `bios` reads this function's companion (`new`).
                        match unsafe { radio.begin_lari(bios) } {
                            Ok(lari) => Ok(Stage::Lari(Box::new(lari))),
                            Err(kept) => Err((Error::Refused("LARI"), kept)),
                        }
                    }
                    Ok(_) => Ok(Stage::Radio(radio)),
                    Err(error) => Err((Error::Boot(error), radio)),
                }
            }
            Stage::Lari(mut lari) => {
                advance!(lari, Lari, Lari, LariPhase::RxQueueConfigurationRequired, {
                    // SAFETY: the handoff clock is calibrated and advances.
                    match unsafe { lari.begin_ax200_setup(Ax200SetupOptions::new(self.clock)) } {
                        Ok(setup) => Ok(Stage::Setup(Box::new(setup))),
                        Err(lari) => Err((Error::Refused("setup"), lari as Box<dyn Any>)),
                    }
                })
            }
            Stage::Setup(mut setup) => {
                advance!(setup, Setup, Setup, Ax200SetupPhase::RegulatoryRequired, {
                    match setup.begin_mcc() {
                        Ok(mcc) => Ok(Stage::Mcc(Box::new(mcc))),
                        Err(setup) => Err((Error::Refused("MCC"), setup as Box<dyn Any>)),
                    }
                })
            }
            Stage::Mcc(mut mcc) => advance!(mcc, Mcc, Mcc, Ax200MccPhase::PolicyRequired, {
                match mcc.begin_scan_configuration() {
                    Ok(next) => Ok(Stage::ScanConfiguration(Box::new(next))),
                    Err(mcc) => Err((Error::Refused("scan configuration"), mcc as Box<dyn Any>)),
                }
            }),
            Stage::ScanConfiguration(mut configuration) => advance!(
                configuration,
                ScanConfiguration,
                ScanConfiguration,
                Ax200ScanConfigurationPhase::BoardPolicyRequired,
                {
                    match configuration.begin_board_policy() {
                        Ok(board) => Ok(Stage::Board(Box::new(board))),
                        Err(kept) => Err((Error::Refused("board policy"), kept as Box<dyn Any>)),
                    }
                }
            ),
            Stage::Board(mut board) => advance!(
                board,
                Board,
                Board,
                Ax200BoardPolicyPhase::CountryRequired,
                { self.country(board) }
            ),
            Stage::Country(mut country) => advance!(
                country,
                Country,
                Country,
                Ax200CountryPhase::MacContextRequired,
                {
                    match country.begin_mld_mac_context() {
                        Ok(mac) => Ok(Stage::Mac(Box::new(mac))),
                        Err(country) => {
                            Err((Error::Refused("MAC context"), country as Box<dyn Any>))
                        }
                    }
                }
            ),
            Stage::Mac(mut mac) => {
                if let Err(error) = mac.replenish_completed_receive() {
                    return Err((Error::Boot(error), mac));
                }
                advance!(mac, Mac, Mac, Ax200MacPhase::ScanRequired, {
                    // SAFETY: `Regulatory` is both the country's selection and
                    // the lease, and no other path publishes to this function.
                    match unsafe { mac.begin_scan() } {
                        Ok(scan) => Ok(Stage::Scan(Box::new(scan))),
                        Err(mac) => Err((Error::Refused("scan"), mac as Box<dyn Any>)),
                    }
                })
            }
            // SAFETY: forwarded from poll.
            Stage::Scan(scan) => unsafe { self.scan(scan) },
            Stage::Phy(mut phy) => advance!(phy, Phy, Phy, Ax200PhyPhase::BindingRequired, {
                // The owner floors the request to the country's ceiling.
                match phy.begin_transmit_power(u8::MAX) {
                    Ok(power) => Ok(Stage::Power(Box::new(power))),
                    Err(phy) => Err((Error::Refused("transmit power"), phy as Box<dyn Any>)),
                }
            }),
            Stage::Power(mut power) => {
                advance!(
                    power,
                    Power,
                    Power,
                    Ax200TransmitPowerPhase::BindingRequired,
                    {
                        if let Err(error) = power.replenish_completed_receive() {
                            return Err((Error::Power(error), power));
                        }
                        // SAFETY: the same regulatory service and requester remain.
                        match unsafe { power.begin_mld_link() } {
                            Ok(link) => Ok(Stage::Link(Box::new(link))),
                            Err(power) => Err((Error::Refused("link"), power as Box<dyn Any>)),
                        }
                    }
                )
            }
            Stage::Link(mut link) => {
                if let Err(error) = link.replenish_completed_receive() {
                    return Err((Error::Binding(error), link));
                }
                advance!(
                    link,
                    Link,
                    Binding,
                    Ax200BindingPhase::AuthenticationRequired,
                    {
                        let Some(selected) = &self.selected else {
                            return Err((Error::Refused("AP station"), link as Box<dyn Any>));
                        };
                        let peer = LegacyPeer {
                            address: selected.bss.bssid,
                            beacon_interval_tu: selected.bss.beacon_interval,
                            rates: selected.rates,
                        };
                        // SAFETY: the rates are the selected AP's own.
                        match unsafe { link.begin_mld_peer(peer) } {
                            Ok(peer) => Ok(Stage::Peer(Box::new(peer))),
                            Err(link) => Err((Error::Refused("AP station"), link as Box<dyn Any>)),
                        }
                    }
                )
            }
            Stage::Peer(mut peer) => {
                if let Err(error) = peer.replenish_completed_receive() {
                    return Err((Error::Peer(error), peer));
                }
                advance!(
                    peer,
                    Peer,
                    Peer,
                    Ax200LegacyPeerPhase::ManagementQueueRequired,
                    {
                        // SAFETY: no other queue, station or interrupt worker exists.
                        match unsafe { peer.begin_mld_management_queue() } {
                            Ok(queue) => Ok(Stage::Queue(Box::new(queue))),
                            Err(peer) => {
                                Err((Error::Refused("management queue"), peer as Box<dyn Any>))
                            }
                        }
                    }
                )
            }
            Stage::Queue(mut queue) => {
                if let Err(error) = queue.replenish_completed_receive() {
                    return Err((Error::Queue(error), queue));
                }
                advance!(
                    queue,
                    Queue,
                    Queue,
                    Ax200ManagementQueuePhase::ManagementFramesRequired,
                    {
                        // SAFETY: as above.
                        match unsafe { queue.begin_mld_coexistence() } {
                            Ok(coexistence) => Ok(Stage::Coexistence(Box::new(coexistence))),
                            Err(queue) => {
                                Err((Error::Refused("coexistence"), queue as Box<dyn Any>))
                            }
                        }
                    }
                )
            }
            Stage::Coexistence(mut coexistence) => {
                if let Err(error) = coexistence.replenish_completed_receive() {
                    return Err((Error::Coexistence(error), coexistence));
                }
                advance!(
                    coexistence,
                    Coexistence,
                    Coexistence,
                    Ax200CoexistencePhase::ManagementFramesRequired,
                    {
                        match coexistence.into_queue() {
                            Ok(queue) => Ok(Stage::Ready(Box::new(queue))),
                            Err(kept) => {
                                Err((Error::Refused("management frames"), kept as Box<dyn Any>))
                            }
                        }
                    }
                )
            }
            Stage::Ready(mut queue) => {
                if let Err(error) = queue.replenish_completed_receive() {
                    return Err((Error::Queue(error), queue));
                }
                Ok(Stage::Ready(queue))
            }
            failed @ Stage::Failed { .. } => Ok(failed),
            Stage::Moving => Err((Error::Refused("bring-up"), Box::new(()))),
        }
    }

    fn nvm(&mut self, boot: RomBoot<'static, Q>) -> Stage<Q, B> {
        self.deadline = None;
        Stage::Nvm(Box::new(boot.initialize_on_device_nvm()))
    }

    fn country(
        &mut self,
        board: Box<Ax200BoardPolicy<'static, Q, B>>,
    ) -> Result<Stage<Q, B>, (Error, Box<dyn Any>)> {
        // `iwl_mvm_init_mcc` leaves the BIOS country, else the current one.
        let firmware = board.profiles().last().map(|profile| profile.country);
        let Some(database) = self.database.take() else {
            return Err((Error::Refused("country"), board));
        };
        let regulatory = match Regulatory::select(database, self.network.country, firmware) {
            Ok(regulatory) => regulatory,
            Err(error) => return Err((Error::Regulatory(error), board)),
        };
        self.beacons = Some(regulatory.beacons());
        // SAFETY: the selection belongs to this function's own adapter.
        match unsafe { board.begin_country(regulatory) } {
            Ok(country) => Ok(Stage::Country(Box::new(country))),
            Err(kept) => Err((Error::Refused("country"), Box::new(kept) as Box<dyn Any>)),
        }
    }

    /// One scan step: start a passive scan of every channel the country's
    /// rules and the firmware allow, keep the strongest beacon carrying the
    /// network's SSID, retire the scan once complete, and scan again until
    /// one is found.
    unsafe fn scan(
        &mut self,
        mut scan: Box<Ax200Scan<'static, Q, B, Regulatory>>,
    ) -> Result<Stage<Q, B>, (Error, Box<dyn Any>)> {
        let pages = self.pages;
        if let Err(error) = scan.replenish_completed_receive() {
            return Err((Error::Boot(error), scan));
        }
        while scan.take_other_notification().is_some() {}
        match scan.phase() {
            Ax200ScanPhase::NotStarted if !self.scanning => {
                if let Some(selected) = self.candidate.take() {
                    self.selected = Some(selected.clone());
                    return match (*scan).begin_phy_context(selected.bss.channel) {
                        Ok(phy) => Ok(Stage::Phy(Box::new(phy))),
                        Err(scan) => Err((Error::Refused("PHY context"), scan as Box<dyn Any>)),
                    };
                }
                loop {
                    match scan.poll_pre_scan_receive() {
                        Ok(MpduProgress::Pending) => break,
                        Ok(_) => {}
                        Err(error) => return Err((Error::Scan(error), scan)),
                    }
                }
                let request = match protocol::Request::new(scan.channels(), Vec::new(), Vec::new())
                {
                    Ok(request) => request,
                    Err(error) => {
                        return Err((Error::Scan(Ax200ScanError::Protocol(error)), scan));
                    }
                };
                // SAFETY: forwarded from `poll`.
                match unsafe { scan.start(request, SCAN_BUDGET_US, pages) } {
                    Ok(_) => {
                        self.scanning = true;
                        Ok(Stage::Scan(scan))
                    }
                    Err(error) => Err((Error::Scan(error), scan)),
                }
            }
            Ax200ScanPhase::DrainRequired => {
                loop {
                    match scan.poll_retiring_receive() {
                        Ok(None) => break,
                        Ok(Some(_)) => {}
                        Err(error) => return Err((Error::Scan(error), scan)),
                    }
                }
                match scan.retire() {
                    Ok(_) => {
                        self.scanning = false;
                        Ok(Stage::Scan(scan))
                    }
                    Err(error) => Err((Error::Scan(error), scan)),
                }
            }
            _ => {
                if matches!(scan.phase(), Ax200ScanPhase::Scanning) {
                    loop {
                        match scan.poll_result() {
                            Ok(ScanResultProgress::Observed(result)) => {
                                if let Ok(bss) = result.result() {
                                    self.consider(bss);
                                }
                            }
                            Ok(ScanResultProgress::Rejected(_)) => {}
                            Ok(
                                ScanResultProgress::Pending
                                | ScanResultProgress::Backpressure { .. },
                            ) => {
                                break;
                            }
                            Err(error) => return Err((Error::Scan(error), scan)),
                        }
                    }
                }
                // SAFETY: forwarded from `poll`.
                match unsafe { scan.advance(pages) } {
                    Ok(_) => Ok(Stage::Scan(scan)),
                    Err(error) => Err((Error::Scan(error), scan)),
                }
            }
        }
    }

    /// Keep `bss` when it carries the network's SSID, has a legacy rate this
    /// band transmits and is stronger than the network found so far.
    fn consider(&mut self, bss: &Bss) {
        // `cfg80211_inform_single_bss_data` hints every ESS beacon's channel.
        if bss.capabilities & 1 != 0
            && let Some(beacons) = &self.beacons
        {
            beacons.heard(bss.channel);
        }
        if bss.ssid.as_deref() != Some(self.network.ssid.as_slice()) {
            return;
        }
        let rates = legacy_rates(&bss.elements, bss.channel.band);
        if rates == 0 {
            return;
        }
        let stronger = self.candidate.as_ref().is_none_or(|current| {
            bss.signal_dbm.unwrap_or(i8::MIN) > current.bss.signal_dbm.unwrap_or(i8::MIN)
        });
        if stronger {
            self.candidate = Some(Selected {
                bss: bss.clone(),
                rates,
            });
        }
    }
}

/// Polling the link advances bring-up; frames flow once the port is open.
impl<Q: BootIo, B: BiosIo> Link for Wifi<Q, B> {
    fn mac(&self) -> Mac {
        self.address
    }
    fn carrier(&mut self) -> bool {
        self.poll();
        false
    }
    fn transmit(&mut self, _: &[u8]) -> Result<(), LinkError> {
        Err(LinkError::NoCarrier)
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        if self.poll() == Phase::Failed && !self.reported {
            self.reported = true;
            return Err(LinkError::Adapter(format!("iwlwifi: {:?}", self.error)));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_rates_read_both_rate_elements_and_drop_cck_at_5_ghz() {
        let elements = [0, 1, b'x', 1, 4, 0x82, 0x84, 0x8b, 0x96, 50, 2, 12, 108];
        assert_eq!(legacy_rates(&elements, Band::Ghz2), 0b1000_0001_1111);
        assert_eq!(legacy_rates(&elements, Band::Ghz5), 0b1000_0001_0000);
        assert_eq!(legacy_rates(&[1, 9, 2], Band::Ghz2), 0);
    }
}
