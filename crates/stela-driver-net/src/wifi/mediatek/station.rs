// SPDX-License-Identifier: GPL-2.0-only
// Adapted from pinned Linux net/mac80211/mlme.c; full source notices in
// THIRD_PARTY.md. The connection policy follows wpa_supplicant's behavior.
//! One MT7925 station kept connected to the configured network, as
//! wpa_supplicant and mac80211 keep one: an active scan, the strongest BSS
//! of the network whose security the station supports, authentication and
//! association on mac80211's channel and mode, the 4-way and group key
//! handshakes, their keys and the controlled port. A lost or failed
//! connection scans again after wpa_supplicant's delays.
use super::{
    bootstrap::client::{
        self, BssHandle, Event, LinkControlError, LinkEvent, ManagedLink, Phase, PolicyError,
        management::Session,
    },
    mcu::{client::Profile, device::Context},
    regd,
    registers::{BarIo, MmioBar},
    ring::{MmioQueue, QueueIo},
};
use crate::{
    Clock, Link, LinkError, Mac,
    bus::dma::memory::PageSource,
    wifi::{
        Band,
        connection::{
            self, Request,
            mode::{self, Channels},
            security::{self, Security},
        },
        network::Network,
        regulatory::database::Country,
        scan::{self, result::Bss},
        security::KeyIdentity,
        station::{
            Join, PortPolicy,
            data::Ingress,
            operations::Operations,
            phy::{Capabilities, Role},
            wire::AssociationRequest,
        },
        supplicant::{EAPOL, IntegrityKey, Step, Supplicant},
    },
};
use alloc::{boxed::Box, format, string::String, sync::Arc, vec, vec::Vec};
use stela_driver_base::entropy::Entropy;
use zeroize::Zeroizing;

/// The longest a scan may run.
const SCAN_BUDGET_US: u64 = 30_000_000;
/// wpa_supplicant's default `scan_interval` after a scan finds nothing.
const SCAN_INTERVAL_US: u64 = 5_000_000;
/// The delay before reconnecting once the AP drops the association.
const RECONNECT_US: u64 = 100_000;
/// wpa_supplicant's 10 s authentication timeout around the handshake.
const HANDSHAKE_TIMEOUT_US: u64 = 10_000_000;
/// mac80211's `hw.conf.listen_interval`: mt76 leaves `max_listen_interval`
/// at mac80211's default of 5.
const LISTEN_INTERVAL: u16 = 5;
/// The AP's WCID, the first `mt76_wcid_alloc` gives the sole station.
const PEER_WCID: u16 = 1;
/// WLAN_REASON_DEAUTH_LEAVING, which `wpa_supplicant_timeout` sends.
const LEAVING: u16 = 3;

/// Whether the link refused a key only until its queued frames drain.
fn deferred(error: &LinkControlError) -> bool {
    matches!(
        error,
        LinkControlError::Backpressure
            | LinkControlError::Policy(PolicyError::Client(client::Error::NeedsDrain))
    )
}

/// wpa_supplicant's `wpas_auth_failed` delay after `failures` consecutive
/// failed connections.
fn failure_delay_us(failures: u32) -> u64 {
    let seconds = match failures {
        51.. => 300,
        11.. => 120,
        6.. => 90,
        4.. => 60,
        3 => 30,
        2 => 20,
        _ => 10,
    };
    seconds * 1_000_000
}

/// The chosen BSS of the network.
struct Candidate {
    bssid: Mac,
    security: Security,
    /// The station's whole RSN element.
    own_rsn: Vec<u8>,
    /// The AP's whole RSN element.
    peer_rsn: Vec<u8>,
}

enum State {
    /// Scan once `at` passes.
    Waiting {
        at: u64,
    },
    Scanning,
    Joining(Box<Candidate>),
    Handshake {
        supplicant: Box<Supplicant>,
        bssid: Mac,
        deadline: u64,
        /// Message 3 failed its MIC: the passphrase may be wrong.
        mic_failed: bool,
        /// The pairwise key message 3 installed.
        ptk: Option<KeyIdentity>,
        /// Message 3's IGTK until the link has drained the frames before it.
        integrity: Option<IntegrityKey>,
        /// The protected-management transport of the IGTK message 3 gave.
        management: Option<Arc<Session>>,
    },
    Connected {
        supplicant: Box<Supplicant>,
        bssid: Mac,
        ptk: KeyIdentity,
        management: Option<Arc<Session>>,
        /// A rekeyed IGTK the link had no room to rotate in yet.
        integrity: Option<IntegrityKey>,
    },
    /// Leave the association, then scan once `at` passes.
    Leaving {
        at: u64,
    },
}

/// An attached MT7925 kept connected to one network.
pub type Wifi<C> = Station<MmioBar, MmioQueue, C, &'static dyn PageSource>;

/// A managed MT7925 link kept connected to one network.
pub struct Station<I: BarIo, Q: QueueIo, C: Send + Sync + 'static, S: PageSource + 'static> {
    link: ManagedLink<I, Q, C, S>,
    interface: Context,
    country: Country,
    network: Network,
    pmk: Zeroizing<[u8; 32]>,
    entropy: Arc<dyn Entropy>,
    clock: Clock,
    state: State,
    /// wpa_supplicant's `auth_failures` for the network.
    failures: u32,
    /// The latest failure, which `receive` reports once.
    failure: Option<String>,
    reported: Option<String>,
}

impl<I: BarIo, Q: QueueIo, C: Send + Sync + 'static, S: PageSource + 'static> Station<I, Q, C, S> {
    /// Keep `link`, whose station interface is `interface`, connected to
    /// `network` in `country`; `entropy` gives each handshake's SNonce.
    pub fn new(
        link: ManagedLink<I, Q, C, S>,
        interface: Context,
        country: Country,
        network: Network,
        entropy: Arc<dyn Entropy>,
        clock: Clock,
    ) -> Self {
        let pmk = network.secret.pmk(&network.ssid);
        Self {
            link,
            interface,
            country,
            network,
            pmk,
            entropy,
            clock,
            state: State::Waiting { at: 0 },
            failures: 0,
            failure: None,
            reported: None,
        }
    }

    fn fail(&mut self, message: String) {
        if self.reported.as_ref() != Some(&message) {
            self.failure = Some(message);
        }
    }

    /// A connection attempt failed: leave it and wait as wpa_supplicant
    /// waits after `failures` attempts.
    fn failed(&mut self, now: u64, message: String) {
        self.failures = self.failures.saturating_add(1);
        self.fail(message);
        if self.link.phase() != Phase::Idle {
            let _ = self.link.deauthenticate(LEAVING);
        }
        self.state = State::Leaving {
            at: now + failure_delay_us(self.failures),
        };
    }

    /// Service the link, take its notices and advance the connection.
    fn poll(&mut self) {
        let now = self.clock.now_us();
        // A rotation waits for the frames queued before it to be taken.
        if let State::Connected {
            integrity: integrity @ Some(_),
            ..
        } = &mut self.state
        {
            let key = integrity.take().unwrap();
            if let Err(message) = self.rotate(key) {
                self.failed(now, message);
            }
        }
        if let Err(error) = self.link.service() {
            self.fail(format!("{error}"));
        }
        let mut notices = Vec::new();
        while let Some(notice) = self.link.take_notice() {
            notices.push(notice);
        }
        for notice in notices {
            match notice.event {
                LinkEvent::Controller(Event::Ingress(Ingress::ControlPort {
                    ethernet, ..
                })) => {
                    self.eapol(&ethernet, now);
                }
                LinkEvent::Controller(Event::ConnectionLost(_)) => {
                    self.fail(String::from("MT7925: the AP ended the association"));
                    self.state = State::Leaving {
                        at: now + RECONNECT_US,
                    };
                }
                _ => {}
            }
        }
        if let Err(message) = self.complete() {
            self.failed(now, message);
        }
        self.advance(now);
    }

    fn advance(&mut self, now: u64) {
        let phase = self.link.phase();
        match &self.state {
            State::Waiting { at } if now >= *at => self.scan(now),
            State::Scanning if phase == Phase::ScanCompleted => {
                // SAFETY: the link is polled with the device's interrupts
                // masked, so the scan's completion event was its last user;
                // the retirement itself refuses while receive work is queued.
                match unsafe { self.link.retire_scan_after_drain() } {
                    Ok(_) => self.choose(now),
                    Err(error) => self.fail(format!("{error}")),
                }
            }
            State::Joining(_) if phase == Phase::AwaitingModernAdmission => self.configure(now),
            State::Joining(_) | State::Handshake { .. } | State::Connected { .. }
                if matches!(phase, Phase::Idle | Phase::NeedsDrain) =>
            {
                self.failed(
                    now,
                    String::from("MT7925: authentication or association failed"),
                );
            }
            State::Handshake {
                deadline,
                mic_failed,
                ..
            } if now >= *deadline => {
                let message = if *mic_failed {
                    "MT7925: the 4-way handshake failed: the passphrase may be wrong"
                } else {
                    "MT7925: the 4-way handshake timed out"
                };
                self.failed(now, String::from(message));
            }
            State::Leaving { at } => match phase {
                Phase::NeedsDrain => {
                    // SAFETY: as for the scan above, the departure's removal
                    // event was its last user, and the retirement refuses
                    // while any peer work is queued.
                    if let Err(error) = unsafe { self.link.retire_peer_after_drain() } {
                        self.fail(format!("{error}"));
                    }
                }
                Phase::Idle => self.state = State::Waiting { at: *at },
                _ => {}
            },
            _ => {}
        }
    }

    /// `wpa_supplicant_req_scan`: an active scan with the wildcard SSID on
    /// every 2.4 and 5 GHz channel that may transmit.
    fn scan(&mut self, now: u64) {
        let channels = [Band::Ghz2, Band::Ghz5]
            .into_iter()
            .flat_map(|band| self.link.channels(band))
            .map(|(channel, _)| channel)
            .collect();
        let started = scan::Request::new(channels, vec![Vec::new()], Vec::new())
            .map_err(|error| format!("MT7925 scan: {error:?}"))
            .and_then(|request| {
                self.link
                    .begin_scan(request, SCAN_BUDGET_US)
                    .map_err(|error| format!("{error}"))
            });
        self.state = match started {
            Ok(_) => State::Scanning,
            Err(message) => {
                self.fail(message);
                State::Waiting {
                    at: now + SCAN_INTERVAL_US,
                }
            }
        };
    }

    /// Join the strongest BSS of the network whose security the station
    /// supports.
    fn choose(&mut self, now: u64) {
        let mut best: Option<(BssHandle, &Bss, Security)> = None;
        let mut refusal = None;
        for (handle, bss) in self.link.bss() {
            if bss.ssid.as_deref() != Some(&self.network.ssid[..])
                || !matches!(bss.channel.band, Band::Ghz2 | Band::Ghz5)
            {
                continue;
            }
            match Security::select(&bss.elements) {
                Ok(security) => {
                    let signal = |bss: &Bss| bss.signal_dbm.unwrap_or(i8::MIN);
                    if best
                        .as_ref()
                        .is_none_or(|(_, b, _)| signal(bss) > signal(b))
                    {
                        best = Some((handle, bss, security));
                    }
                }
                Err(reason) => refusal = Some(reason),
            }
        }
        let ssid = String::from_utf8_lossy(&self.network.ssid).into_owned();
        let Some((handle, bss, security)) = best else {
            self.fail(match refusal {
                Some(reason) => format!("MT7925: {ssid} offers no supported security: {reason:?}"),
                None => format!("MT7925: {ssid} not found"),
            });
            self.state = State::Waiting {
                at: now + SCAN_INTERVAL_US,
            };
            return;
        };
        let bss = bss.clone();
        match self.join(handle, &bss, security) {
            Ok(candidate) => self.state = State::Joining(Box::new(candidate)),
            Err(message) => self.failed(now, message),
        }
    }

    /// `ieee80211_mgd_assoc`: the association request and station profile
    /// for `bss` on mac80211's mode and channel.
    fn join(
        &mut self,
        handle: BssHandle,
        bss: &Bss,
        security: Security,
    ) -> Result<Candidate, String> {
        let band = bss.channel.band;
        let advertisement = self
            .link
            .local_advertisement(band)
            .map_err(|error| format!("{error}"))?;
        let peer = Capabilities::parse(band, Role::AccessPoint, &bss.elements)
            .map_err(|error| format!("MT7925 AP capabilities: {error:?}"))?;
        let operations = Operations::parse(&bss.elements)
            .map_err(|error| format!("MT7925 AP operation: {error:?}"))?;
        let channels = self.link.channels(band);
        let chosen = mode::determine(
            advertisement.capabilities(),
            &peer,
            &operations,
            bss.channel,
            Channels(&channels),
        )
        .map_err(|refusal| format!("MT7925: {refusal:?}"))?;
        let spectrum = connection::spectrum_management(bss.capabilities).then(|| {
            let regulated = self.country.channel(bss.channel.frequency_mhz);
            (
                regulated.max_reg_dbm.clamp(0, 127) as i8,
                regd::channels(band),
            )
        });
        let own_rsn = security.element();
        let elements = connection::request_elements(
            &Request {
                ssid: &self.network.ssid,
                rsn: &own_rsn,
                mode: chosen.mode,
                wmm: peer.wmm().is_some(),
                spectrum,
            },
            advertisement.elements(),
        );
        let mut local = Capabilities::parse(band, Role::Station, &elements)
            .map_err(|error| format!("MT7925 request capabilities: {error:?}"))?;
        if local.he().is_some() {
            local = local
                .with_local_he_source_maps(*advertisement.he_source_maps())
                .map_err(|error| format!("MT7925 request capabilities: {error:?}"))?;
        }
        let rates = local.rates().supported & peer.rates().supported;
        let capability = connection::capability(band, chosen.mode, spectrum.is_some());
        let width = chosen.definition.width;
        let request = if security.management.is_some() {
            AssociationRequest::new_modern_with_local_pmf(
                capability,
                LISTEN_INTERVAL,
                elements,
                local,
                chosen.mode,
                width,
            )
        } else {
            AssociationRequest::new_modern_with_local(
                capability,
                LISTEN_INTERVAL,
                elements,
                local,
                chosen.mode,
                width,
            )
        }
        .map_err(|error| format!("MT7925 association request: {error:?}"))?;
        let dtim_period = connection::find(&bss.elements, 5)
            .and_then(|tim| tim.get(1).copied())
            .filter(|&period| period != 0)
            .unwrap_or(1);
        // mac80211 uses the short slot time on 5 GHz and wherever the AP does.
        let slot_time = if band != Band::Ghz2 || bss.capabilities & (1 << 10) != 0 {
            9
        } else {
            20
        };
        let profile = Profile {
            interface: self.interface,
            peer: bss.bssid,
            wcid: PEER_WCID,
            channel: bss.channel,
            aid: 0,
            basic_rates: peer.rates().basic,
            supported_rates: rates,
            beacon_interval: bss.beacon_interval,
            dtim_period,
            slot_time,
            antenna_mask: advertisement.antenna_mask(),
            // The client takes the cipher from the first installed key.
            cipher: 0,
        };
        let join = Join {
            bssid: bss.bssid,
            channel: bss.channel,
            policy: PortPolicy::Controlled,
            request,
        };
        self.link
            .join(handle, join, profile)
            .map_err(|error| format!("{error}"))?;
        let body = security::rsn_element(&bss.elements).unwrap_or_default();
        let mut peer_rsn = vec![48, body.len() as u8];
        peer_rsn.extend_from_slice(body);
        Ok(Candidate {
            bssid: bss.bssid,
            security,
            own_rsn,
            peer_rsn,
        })
    }

    /// Configure the association the AP accepted, then await message 1.
    fn configure(&mut self, now: u64) {
        let State::Joining(candidate) = core::mem::replace(&mut self.state, State::Scanning) else {
            return;
        };
        if let Err(error) = self.link.configure() {
            return self.failed(now, format!("{error}"));
        }
        match Supplicant::new(
            candidate.security.suites(),
            self.pmk.clone(),
            self.link.mac(),
            candidate.bssid,
            candidate.own_rsn,
            candidate.peer_rsn,
        ) {
            Ok(supplicant) => {
                self.state = State::Handshake {
                    supplicant: Box::new(supplicant),
                    bssid: candidate.bssid,
                    deadline: now + HANDSHAKE_TIMEOUT_US,
                    mic_failed: false,
                    ptk: None,
                    integrity: None,
                    management: None,
                }
            }
            Err(error) => self.failed(now, format!("MT7925 supplicant: {error:?}")),
        }
    }

    /// One EAPOL frame from the AP: answer it, install the keys it carries
    /// and, once message 3 has, open the port.
    fn eapol(&mut self, ethernet: &[u8], now: u64) {
        if ethernet.get(12..14) != Some(&EAPOL.to_be_bytes()[..]) {
            return;
        }
        let mut nonce = [0; 32];
        if let Err(error) = self.entropy.fill(&mut nonce) {
            return self.failed(now, format!("MT7925 SNonce: {error}"));
        }
        let (supplicant, bssid, ptk) = match &mut self.state {
            State::Handshake {
                supplicant, bssid, ..
            } => (supplicant, *bssid, None),
            State::Connected {
                supplicant,
                bssid,
                ptk,
                ..
            } => (supplicant, *bssid, Some(*ptk)),
            _ => return,
        };
        let step = match supplicant.receive(&ethernet[14..], &mut || nonce) {
            Ok(step) => step,
            // wpa_supplicant drops a frame that does not verify.
            Err(error) => {
                if let (crate::wifi::supplicant::Error::Mic, State::Handshake { mic_failed, .. }) =
                    (error, &mut self.state)
                {
                    *mic_failed = true;
                }
                return;
            }
        };
        if let Err(message) = self.apply(step, bssid, ptk) {
            self.failed(now, message);
        }
    }

    /// Send a handshake step's reply, then install its keys as
    /// wpa_supplicant does after message 4.
    fn apply(&mut self, step: Step, bssid: Mac, ptk: Option<KeyIdentity>) -> Result<(), String> {
        if let Some(reply) = step.reply {
            let mut frame = Vec::with_capacity(14 + reply.len());
            frame.extend_from_slice(&bssid.0);
            frame.extend_from_slice(&self.link.mac().0);
            frame.extend_from_slice(&EAPOL.to_be_bytes());
            frame.extend_from_slice(&reply);
            self.link
                .send_control(&frame, ptk)
                .map_err(|error| format!("{error}"))?;
        }
        let pairwise = step
            .pairwise
            .map(|key| {
                self.link
                    .install_key(true, key.index, &key.material, key.receive)
            })
            .transpose()
            .map_err(|error| format!("{error}"))?;
        if let Some(key) = step.group {
            self.link
                .install_key(false, key.index, &key.material, key.receive)
                .map_err(|error| format!("{error}"))?;
        }
        match &mut self.state {
            State::Handshake { ptk, integrity, .. } => {
                *ptk = pairwise.or(*ptk);
                *integrity = step.integrity.or(integrity.take());
            }
            State::Connected { ptk, .. } => {
                *ptk = pairwise.unwrap_or(*ptk);
                if let Some(key) = step.integrity {
                    self.rotate(key)?;
                }
            }
            _ => {}
        }
        self.complete()
    }

    /// Install message 3's IGTK once the link drained the frames before it,
    /// message 4 among them, then open the port.
    fn complete(&mut self) -> Result<(), String> {
        let State::Handshake {
            ptk: Some(ptk),
            integrity,
            management,
            ..
        } = &mut self.state
        else {
            return Ok(());
        };
        let (ptk, pending, protected) = (*ptk, integrity.take(), management.is_some());
        let epoch = self
            .link
            .station()
            .association_epoch()
            .ok_or_else(|| String::from("MT7925: the association ended"))?;
        let installed = match pending {
            // SAFETY: this association's authenticated handshake gave the
            // IGTK, and the link is polled with the device's interrupts
            // masked, so no earlier key user remains.
            Some(key) => match unsafe {
                self.link
                    .install_management_key(epoch, key.index, &key.material, key.receive)
            } {
                Ok(session) => Some(session),
                Err(error) if deferred(&error) => {
                    if let State::Handshake { integrity, .. } = &mut self.state {
                        *integrity = Some(key);
                    }
                    return Ok(());
                }
                Err(error) => return Err(format!("{error}")),
            },
            None => None,
        };
        if installed.is_none() && !protected && self.link.station().requires_protected_management()
        {
            return Ok(());
        }
        self.link
            .authorize_port(epoch)
            .map_err(|error| format!("{error}"))?;
        let State::Handshake {
            supplicant,
            bssid,
            management,
            ..
        } = core::mem::replace(&mut self.state, State::Scanning)
        else {
            unreachable!("matched above")
        };
        self.state = State::Connected {
            supplicant,
            bssid,
            ptk,
            management: installed.or(management),
            integrity: None,
        };
        self.failures = 0;
        Ok(())
    }

    /// Rotate the protected-management transport to a rekeyed IGTK, once the
    /// link holds no frame received before it.
    fn rotate(&mut self, key: IntegrityKey) -> Result<(), String> {
        let State::Connected {
            management,
            integrity,
            ..
        } = &mut self.state
        else {
            return Ok(());
        };
        let session = management
            .as_ref()
            .ok_or_else(|| String::from("MT7925: an IGTK without management protection"))?;
        // SAFETY: as for the initial IGTK.
        match unsafe {
            self.link
                .rotate_management_key(session, key.index, &key.material, key.receive)
        } {
            Ok(session) => *management = Some(session),
            Err(error) if deferred(&error) => *integrity = Some(key),
            Err(error) => return Err(format!("{error}")),
        }
        Ok(())
    }

    /// The failure `receive` has not reported yet.
    fn take_failure(&mut self) -> Option<String> {
        let failure = self.failure.take()?;
        self.reported = Some(failure.clone());
        Some(failure)
    }
}

impl<I: BarIo, Q: QueueIo, C: Send + Sync + 'static, S: PageSource + 'static> Link
    for Station<I, Q, C, S>
{
    fn mac(&self) -> Mac {
        self.link.mac()
    }
    fn carrier(&mut self) -> bool {
        self.poll();
        self.link.carrier()
    }
    fn signals(&self) -> bool {
        self.link.signals()
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        self.link.transmit(frame)
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        self.poll();
        if let Some(failure) = self.take_failure() {
            return Err(LinkError::Adapter(failure));
        }
        self.link.receive()
    }
}
