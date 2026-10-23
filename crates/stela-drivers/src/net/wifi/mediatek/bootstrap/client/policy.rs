// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
// Copyright (C) 2020-2023 MediaTek Inc.
// Channel geometry/policy follows Linux cfg80211/mac80211; see THIRD_PARTY.md.
//! Concrete policy owner for the actual retained MT7925 controller. The normal
//! OS/setup input is a pinned database and explicit country/environment. This
//! wrapper owns the only client and exposes no raw mutable escape. Every method
//! serializes policy validation with actual publication; revocation performs
//! real cancel/remove/disable work and retains all resources through drain.

use super::*;
use reg::database::Country;
use station::phy::{Mode, Width};
use triomphe::Arc as Shared;
use wifi::{Band, Channel, regulatory as reg};

static NEXT_OWNER: wifi::Identities = wifi::Identities::new();
static NEXT_BSS: wifi::Identities = wifi::Identities::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Environment {
    Indoor,
    Outdoor,
}
#[derive(Debug)]
pub enum PolicyError {
    Client(Error),
    Regulatory(reg::Error),
    NoMemory,
    IncompleteProgramming,
    CountryMismatch,
    RestrictionMismatch,
    PowerMismatch,
    Revoked,
    Bss,
}
/// Failed attachment preserves the original native owner for correction/drain.
pub struct AttachError<I: BarIo, Q: QueueIo, C: 'static> {
    pub error: PolicyError,
    pub client: Client<I, Q, C>,
}
impl<I: BarIo, Q: QueueIo, C: 'static> core::fmt::Debug for AttachError<I, Q, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AttachError")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BssHandle(u64);
struct Observed {
    handle: BssHandle,
    seen: u64,
    bss: scan::result::Bss,
}
#[derive(Clone, Copy)]
struct Programmed {
    channel: Channel,
    flags: u32,
    max_half_dbm: i8,
}
struct Snapshot {
    context: reg::NativeContext,
    channels: Vec<Programmed>,
}
struct Hardware(Shared<Snapshot>, Environment);
struct Os {
    country: Shared<Country>,
    environment: Environment,
    context: reg::NativeContext,
}
struct HardwareGuard<'a>(&'a Snapshot, Environment);
struct OsGuard<'a>(&'a Os);
struct Check<'a> {
    snapshot: &'a Snapshot,
    country: &'a Country,
    environment: Environment,
    revoked: bool,
    peer: Option<Channel>,
}

/// Fully owning, source-programmed single-interface client. The underlying
/// Controller/Execution retains board/SAR/CLC inputs under their existing native
/// bootstrap contract. The selected country must match its actual programmed
/// domain; a new country requires stop/drain and a new programmed attachment.
pub struct ManagedClient<I: BarIo, Q: QueueIo, C: 'static> {
    client: Client<I, Q, C>,
    authority: reg::Owner<Hardware, Os>,
    snapshot: Shared<Snapshot>,
    country: Shared<Country>,
    environment: Environment,
    revoked: bool,
    peer: Option<Channel>,
    observed: Vec<Observed>,
}
fn copy_bss(b: &scan::result::Bss) -> Result<scan::result::Bss, PolicyError> {
    fn copy(v: &[u8]) -> Result<Vec<u8>, PolicyError> {
        let mut out = Vec::new();
        out.try_reserve_exact(v.len())
            .map_err(|_| PolicyError::NoMemory)?;
        out.extend_from_slice(v);
        Ok(out)
    }
    Ok(scan::result::Bss {
        ticket: b.ticket,
        kind: b.kind,
        bssid: b.bssid,
        transmitter: b.transmitter,
        timestamp: b.timestamp,
        beacon_interval: b.beacon_interval,
        capabilities: b.capabilities,
        channel: b.channel,
        observed: b.observed.clone(),
        signal_dbm: b.signal_dbm,
        ssid: b.ssid.as_deref().map(copy).transpose()?,
        elements: copy(&b.elements)?,
    })
}
fn band_index(band: Band) -> usize {
    match band {
        Band::Ghz2 => 0,
        Band::Ghz5 => 1,
        Band::Ghz6 => 2,
    }
}
fn channel(band: Band, n: u16) -> Option<Channel> {
    let mhz = match band {
        Band::Ghz2 if (1..=13).contains(&n) => 2407 + 5 * n,
        Band::Ghz2 if n == 14 => 2484,
        Band::Ghz5 if (182..=196).contains(&n) => 4000 + 5 * n,
        Band::Ghz5 if n > 0 && n <= 177 => 5000 + 5 * n,
        Band::Ghz6 if n == 2 => 5935,
        Band::Ghz6 if (1..=233).contains(&n) => 5950 + 5 * n,
        _ => return None,
    };
    Some(Channel {
        band,
        number: n,
        frequency_mhz: mhz,
    })
}
fn sku_max(sku: &[u8], band: Band) -> Option<i8> {
    if sku.len() != 449 {
        return None;
    }
    let mut result = i8::MIN;
    for (i, &raw) in sku.iter().enumerate() {
        let used = (band == Band::Ghz2 && i < 4)
            || (4..12).contains(&i)
            || (44..61).contains(&i)
            || (61..109).contains(&i) && (i - 61) % 12 < 10
            || (109..449).contains(&i);
        if used {
            result = result.max(raw as i8);
        }
    }
    Some(result)
}
impl Snapshot {
    fn read<I: BarIo, Q: QueueIo, C: 'static>(
        client: &Client<I, Q, C>,
        country: &Country,
    ) -> Result<Self, PolicyError> {
        let c = client.state().controller.state();
        if client.phase() != Phase::Idle
            || client.state().controller.phase() != ControllerPhase::StartFacts
        {
            return Err(PolicyError::IncompleteProgramming);
        }
        let (domain, power) = c
            .policy
            .as_ref()
            .and_then(|p| p.programmed_mt7925())
            .ok_or(PolicyError::IncompleteProgramming)?;
        if domain.alpha2() != country.alpha2() || power.alpha2() != country.alpha2() {
            return Err(PolicyError::CountryMismatch);
        }
        let counts = domain.counts();
        let mut channels = Vec::new();
        channels
            .try_reserve_exact(counts.iter().map(|&n| usize::from(n)).sum())
            .map_err(|_| PolicyError::NoMemory)?;
        let mut entries = domain.body()[16..].as_chunks::<8>().0.iter();
        for (band, count) in [Band::Ghz2, Band::Ghz5, Band::Ghz6].into_iter().zip(counts) {
            for _ in 0..count {
                let e = entries.next().ok_or(PolicyError::IncompleteProgramming)?;
                let channel = channel(band, u16::from_le_bytes([e[0], e[1]]))
                    .ok_or(PolicyError::RestrictionMismatch)?;
                let flags = u32::from_le_bytes(e[4..8].try_into().unwrap());
                let rule = country
                    .rule(u32::from(channel.frequency_mhz) * 1000, 20_000)
                    .ok_or(PolicyError::RestrictionMismatch)?;
                if flags & 1 != 0
                    || (rule.no_ir && flags & 2 == 0)
                    || (rule.dfs && flags & 8 == 0)
                    || (rule.indoor_only && flags & (1 << 9) == 0)
                    || (rule.no_ofdm && flags & (1 << 6) == 0)
                    || channels.iter().any(|c: &Programmed| c.channel == channel)
                {
                    return Err(PolicyError::RestrictionMismatch);
                }
                let mut max = None;
                for request in power.requests() {
                    let body = request.body();
                    if request.kind() != wifi::mediatek::mcu::power::Kind::RatePower
                        || body.get(13) != Some(&(band_index(band) as u8 + 1))
                    {
                        continue;
                    }
                    for entry in body
                        .get(52..)
                        .ok_or(PolicyError::IncompleteProgramming)?
                        .as_chunks::<450>()
                        .0
                    {
                        if u16::from(entry[0]) == channel.number {
                            if max.is_some() {
                                return Err(PolicyError::PowerMismatch);
                            }
                            max = sku_max(&entry[1..], band);
                        }
                    }
                }
                let max_half_dbm = max.ok_or(PolicyError::PowerMismatch)?;
                if i32::from(max_half_dbm) * 50 > i32::from(rule.max_eirp_mbm) {
                    return Err(PolicyError::PowerMismatch);
                }
                channels.push(Programmed {
                    channel,
                    flags,
                    max_half_dbm,
                });
            }
        }
        let id = NEXT_OWNER
            .next()
            .ok_or(PolicyError::Regulatory(reg::Error::OwnerExhausted))?;
        Ok(Self {
            context: reg::NativeContext {
                device: id,
                reset_epoch: id,
                firmware_epoch: id,
                policy_revision: id,
            },
            channels,
        })
    }
    fn get(&self, ch: Channel) -> Option<&Programmed> {
        self.channels.iter().find(|c| c.channel == ch)
    }
    fn association(&self, op: &reg::AssociationOperation<'_>, environment: Environment) -> bool {
        let ctx = op.context();
        let def = ctx.definition();
        let n = ctx.negotiated();
        if def.validate().is_err() || matches!(def.width, Width::Mhz80P80 | Width::Mhz320) {
            return false;
        }
        let bw = match def.width {
            Width::Mhz20 => 20,
            Width::Mhz40 => 40,
            Width::Mhz80 => 80,
            Width::Mhz160 => 160,
            _ => return false,
        };
        let start = def.center1_mhz - bw / 2;
        for mhz in (start + 10..start + bw).step_by(20) {
            // Punctured channels remain checked, matching cfg80211 chandef
            // usability; puncturing cannot erase a disabled/no-width rule.
            let Some(c) = self.channels.iter().find(|c| {
                c.channel.band == def.control.band && u32::from(c.channel.frequency_mhz) == mhz
            }) else {
                return false;
            };
            let f = c.flags;
            if f & ((1 << 11) | 1) != 0
                || f & (1 << 9) != 0 && environment != Environment::Indoor
                || f & (1 << 6) != 0
                    && (n.mode != Mode::Legacy
                        || ctx.channel().band != Band::Ghz2
                        || n.legacy.supported & !15 != 0)
                || matches!(n.mode, Mode::He | Mode::Eht) && f & (1 << 13) != 0
                || n.mode == Mode::Eht && f & (1 << 20) != 0
                || bw >= 80 && f & (1 << 7) != 0
                || bw >= 160 && f & (1 << 8) != 0
            {
                return false;
            }
        }
        if bw >= 40 {
            let Some(control) = self.get(def.control) else {
                return false;
            };
            let secondary_above =
                ((u32::from(def.control.frequency_mhz) - start) / 20).is_multiple_of(2);
            if control.flags & (if secondary_above { 1 << 4 } else { 1 << 5 }) != 0 {
                return false;
            }
        }
        true
    }
}
impl reg::HardwareLease for HardwareGuard<'_> {
    fn context(&self) -> reg::NativeContext {
        self.0.context
    }
    fn lookup_channel(&mut self, band: Band, number: u16) -> Option<Channel> {
        self.0
            .channels
            .iter()
            .find(|c| c.channel.band == band && c.channel.number == number)
            .map(|c| c.channel)
    }
    fn allows(&mut self, op: reg::Operation) -> bool {
        let Some(c) = self.0.get(op.channel()) else {
            return false;
        };
        match op {
            reg::Operation::Receive(_) => true,
            reg::Operation::Transmit {
                purpose, profile, ..
            } => {
                c.flags & ((1 << 11) | 1) == 0
                    && (c.flags & (1 << 9) == 0 || self.1 == Environment::Indoor)
                    && (purpose != reg::Purpose::Probe || c.flags & (2 | 8) == 0)
                    && i32::from(c.max_half_dbm) * 50 <= profile.max_eirp_mbm
            }
        }
    }
    fn allows_association(&mut self, op: &reg::AssociationOperation<'_>) -> bool {
        self.0.association(op, self.1)
    }
}
// SAFETY: private provider exists only inside the exclusive ManagedClient. Its
// immutable snapshot comes from that exact retained completed Execution. No raw
// controller/policy mutation escapes. Native operations/revocation take &mut
// that same owner, and its client retains all physical resources through drain.
unsafe impl reg::HardwarePolicy for Hardware {
    type Lease<'a> = HardwareGuard<'a>;
    fn acquire(&mut self) -> Option<Self::Lease<'_>> {
        Some(HardwareGuard(&self.0, self.1))
    }
}
impl Os {
    fn receive(&self, ch: Channel) -> bool {
        self.country
            .rule(u32::from(ch.frequency_mhz) * 1000, 20_000)
            .is_some()
    }
    fn tx(&self, ch: Channel, probe: bool) -> bool {
        self.country
            .rule(u32::from(ch.frequency_mhz) * 1000, 20_000)
            .is_some_and(|r| {
                (!r.indoor_only || self.environment == Environment::Indoor)
                    && (!probe || !r.no_ir && !r.dfs)
            })
    }
    fn association(&self, op: &reg::AssociationOperation<'_>) -> bool {
        let ctx = op.context();
        let def = ctx.definition();
        let n = ctx.negotiated();
        let bw = match def.width {
            Width::Mhz20 => 20,
            Width::Mhz40 => 40,
            Width::Mhz80 => 80,
            Width::Mhz160 => 160,
            _ => return false,
        };
        let start = def.center1_mhz - bw / 2;
        for mhz in (start + 10..start + bw).step_by(20) {
            let Some(r) = self.country.rule(mhz * 1000, 20_000) else {
                return false;
            };
            if (r.indoor_only && self.environment != Environment::Indoor)
                || self.country.bandwidth(r).is_none_or(|max| max < bw * 1000)
                || (r.no_ofdm
                    && (n.mode != Mode::Legacy
                        || ctx.channel().band != Band::Ghz2
                        || n.legacy.supported & !15 != 0))
            {
                return false;
            }
            if let Some(wmm) = r.wmm {
                let Some(actual) = n.wmm.as_ref() else {
                    return false;
                };
                for ac in &actual.access_categories {
                    // Database/mac80211 order VO,VI,BE,BK; on-air ACI BE,BK,VI,VO.
                    let limit = wmm.client[[2, 3, 1, 0][usize::from(ac.aci)]];
                    if ((1u32 << ac.ecw_min) - 1) < u32::from(limit.cw_min)
                        || ((1u32 << ac.ecw_max) - 1) < u32::from(limit.cw_max)
                        || ac.aifsn < limit.aifsn
                        || u32::from(ac.txop_32us) * 32 > limit.cot_us
                    {
                        return false;
                    }
                }
            }
        }
        true
    }
}
impl reg::OsLease for OsGuard<'_> {
    fn revision(&self) -> u64 {
        self.0.context.policy_revision
    }
    fn allows(&mut self, op: reg::Operation) -> bool {
        match op {
            reg::Operation::Receive(ch) => self.0.receive(ch),
            reg::Operation::Transmit {
                channel,
                purpose,
                profile,
            } => {
                self.0.tx(channel, purpose == reg::Purpose::Probe)
                    && self
                        .0
                        .country
                        .rule(u32::from(channel.frequency_mhz) * 1000, 20_000)
                        .is_some_and(|r| profile.max_eirp_mbm <= i32::from(r.max_eirp_mbm))
            }
        }
    }
    fn allows_association(&mut self, op: &reg::AssociationOperation<'_>) -> bool {
        self.0.association(op)
    }
}
// SAFETY: selected source bytes/country/environment are immutable and retained
// privately by the same exclusive live owner. All native publications and the
// real stop/drain path serialize on its &mut borrow; country cannot be replaced
// underneath autonomous firmware work. Context is minted only for this owner.
unsafe impl reg::OsPolicy for Os {
    type Lease<'a> = OsGuard<'a>;
    fn acquire(&mut self, native: reg::NativeContext) -> Option<Self::Lease<'_>> {
        (native == self.context).then_some(OsGuard(self))
    }
}
impl Check<'_> {
    fn receive(&self, ch: Channel) -> bool {
        self.snapshot.get(ch).is_some()
            && self
                .country
                .rule(u32::from(ch.frequency_mhz) * 1000, 20_000)
                .is_some()
    }
    fn tx(&self, ch: Channel, probe: bool) -> bool {
        if self.revoked {
            return false;
        }
        let Some(c) = self.snapshot.get(ch) else {
            return false;
        };
        let Some(r) = self
            .country
            .rule(u32::from(ch.frequency_mhz) * 1000, 20_000)
        else {
            return false;
        };
        // NO_IR/DFS disallow initiation/probes; an observed AP may serve a
        // managed station on that channel. This is no AP/IBSS/radar exception.
        c.flags & (1 | 1 << 11) == 0
            && (!r.indoor_only || self.environment == Environment::Indoor)
            && (c.flags & (1 << 9) == 0 || self.environment == Environment::Indoor)
            && if probe {
                (ch.band == Band::Ghz2 || c.flags & (1 << 6) == 0)
                    && c.flags & (2 | 8) == 0
                    && !r.no_ir
                    && !r.dfs
            } else {
                self.peer == Some(ch)
            }
    }
}
impl scan::Policy for Check<'_> {
    fn allow_receive(&mut self, ch: Channel) -> bool {
        self.receive(ch)
    }
    fn allow_probe(&mut self, ch: Channel) -> bool {
        self.tx(ch, true)
    }
    fn lookup_channel(&mut self, b: Band, n: u16) -> Option<Channel> {
        self.snapshot
            .channels
            .iter()
            .find(|c| c.channel.band == b && c.channel.number == n && self.receive(c.channel))
            .map(|c| c.channel)
    }
}
impl station::RegulatoryPolicy for Check<'_> {
    fn allow_management_tx(&mut self, ch: Channel) -> bool {
        self.tx(ch, false)
    }
    fn allow_data_tx(&mut self, ch: Channel) -> bool {
        self.tx(ch, false)
    }
}
impl<I: BarIo, Q: QueueIo, C: 'static> ManagedClient<I, Q, C> {
    /// Consume the actual exclusive native client; verify selected source
    /// policy against its completed source programming before accepting work.
    // Preserve the original owner even for allocation failure: boxing this
    // error would itself require an allocation while reporting NoMemory.
    #[allow(clippy::result_large_err)]
    pub fn new(
        client: Client<I, Q, C>,
        country: Country,
        environment: Environment,
    ) -> Result<Self, AttachError<I, Q, C>> {
        let snapshot = match Snapshot::read(&client, &country)
            .and_then(|s| Shared::try_new(s).map_err(|_| PolicyError::NoMemory))
        {
            Ok(snapshot) => snapshot,
            Err(error) => return Err(AttachError { error, client }),
        };
        let country = match Shared::try_new(country) {
            Ok(country) => country,
            Err(_) => {
                return Err(AttachError {
                    error: PolicyError::NoMemory,
                    client,
                });
            }
        };
        let authority = match reg::Owner::new(
            Hardware(snapshot.clone(), environment),
            Os {
                country: country.clone(),
                environment,
                context: snapshot.context,
            },
        ) {
            Ok(authority) => authority,
            Err(error) => {
                return Err(AttachError {
                    error: PolicyError::Regulatory(error),
                    client,
                });
            }
        };
        Ok(Self {
            client,
            authority,
            snapshot,
            country,
            environment,
            revoked: false,
            peer: None,
            observed: Vec::new(),
        })
    }
    fn live(&self) -> Result<(), PolicyError> {
        if self.revoked {
            Err(PolicyError::Revoked)
        } else {
            Ok(())
        }
    }
    pub fn phase(&self) -> Phase {
        self.client.phase()
    }
    pub fn local_advertisement(&self, band: Band) -> Result<Advertisement, LocalError> {
        self.client.local_advertisement(band)
    }
    pub fn station(&self) -> &Station {
        self.client.station()
    }
    pub fn country(&self) -> [u8; 2] {
        self.country.alpha2()
    }
    pub fn begin_scan(
        &mut self,
        request: scan::Request,
        now: u64,
        budget: u64,
    ) -> Result<scan::Ticket, PolicyError> {
        self.live()?;
        let mut check = Check {
            snapshot: &self.snapshot,
            country: &self.country,
            environment: self.environment,
            revoked: false,
            peer: self.peer,
        };
        let ticket = self
            .client
            .begin_scan(request, now, budget, &mut check)
            .map_err(PolicyError::Client)?;
        self.observed.clear();
        Ok(ticket)
    }
    pub fn poll(&mut self, now: u64, source: &dyn PageSource) -> Result<Vec<Event>, PolicyError> {
        let mut check = Check {
            snapshot: &self.snapshot,
            country: &self.country,
            environment: self.environment,
            revoked: self.revoked,
            peer: self.peer,
        };
        let events = self
            .client
            .poll(now, source, &mut check)
            .map_err(PolicyError::Client)?;
        self.observed
            .try_reserve(events.len())
            .map_err(|_| PolicyError::NoMemory)?;
        if !self.revoked {
            for event in &events {
                if let Event::Bss(bss) = event {
                    self.observed.retain(|b| {
                        now.checked_sub(b.seen).is_some_and(|age| age <= 30_000_000)
                            && (b.bss.bssid != bss.bssid || b.bss.channel != bss.channel)
                    });
                    if self.observed.len() >= 1024 {
                        self.observed.remove(0);
                    }
                    let handle = BssHandle(NEXT_BSS.next().ok_or(PolicyError::Bss)?);
                    self.observed.push(Observed {
                        handle,
                        seen: now,
                        bss: copy_bss(bss)?,
                    });
                }
            }
        }
        Ok(events)
    }
    pub fn bss(&self) -> impl Iterator<Item = (BssHandle, &scan::result::Bss)> {
        self.observed.iter().map(|b| (b.handle, &b.bss))
    }
    pub fn join_modern(
        &mut self,
        handle: BssHandle,
        join: Join,
        profile: Profile,
        now: u64,
        source: &dyn PageSource,
    ) -> Result<(), PolicyError> {
        self.live()?;
        let observed = self
            .observed
            .iter()
            .find(|b| b.handle == handle)
            .ok_or(PolicyError::Bss)?;
        if now
            .checked_sub(observed.seen)
            .is_none_or(|age| age > 30_000_000)
            || observed.bss.channel != join.channel
            || observed.bss.bssid != join.bssid
        {
            return Err(PolicyError::Bss);
        }
        let mut check = Check {
            snapshot: &self.snapshot,
            country: &self.country,
            environment: self.environment,
            revoked: false,
            peer: Some(join.channel),
        };
        let flags = self
            .snapshot
            .get(profile.channel)
            .ok_or(PolicyError::RestrictionMismatch)?
            .flags;
        if flags & (1 << 6) != 0
            && (profile.channel.band != Band::Ghz2 || profile.basic_rates & 15 == 0)
        {
            return Err(PolicyError::RestrictionMismatch);
        }
        let beacon = copy_bss(&observed.bss)?;
        self.peer = Some(join.channel);
        self.client
            .join_modern(join, beacon, profile, now, source, &mut check)
            .map_err(PolicyError::Client)
    }
    pub fn configure_modern(&mut self, now: u64) -> Result<(), PolicyError> {
        self.live()?;
        let context = self
            .client
            .modern_context()
            .ok_or(PolicyError::Bss)?
            .clone();
        let admission = self
            .authority
            .admit_association(
                self.client.station(),
                context,
                reg::AssociationUse::Configure,
            )
            .map_err(PolicyError::Regulatory)?;
        // SAFETY: authority and client are private disjoint fields of this same
        // exclusive owning attachment. No controller/policy mutator escapes.
        unsafe {
            self.client
                .configure_modern(&mut self.authority, admission, now)
        }
        .map_err(PolicyError::Client)
    }
    pub fn install_key(
        &mut self,
        pairwise: bool,
        index: u8,
        material: &[u8],
        seed: ReplaySeed,
    ) -> Result<KeyIdentity, PolicyError> {
        self.live()?;
        let context = self
            .client
            .modern_context()
            .ok_or(PolicyError::Bss)?
            .clone();
        let admission = self
            .authority
            .admit_association(
                self.client.station(),
                context,
                reg::AssociationUse::Management,
            )
            .map_err(PolicyError::Regulatory)?;
        // SAFETY: same exclusive privately retained controller and authority.
        unsafe {
            self.client.install_key_modern(
                &mut self.authority,
                admission,
                pairwise,
                index,
                material,
                seed,
            )
        }
        .map_err(PolicyError::Client)
    }
    pub fn authorize_port(&mut self, epoch: u64) -> Result<(), PolicyError> {
        self.live()?;
        self.client
            .authorize_port(epoch)
            .map_err(PolicyError::Client)
    }
    pub fn transmit(
        &mut self,
        epoch: u64,
        ethernet: &[u8],
        class: TxClass,
        tid: Option<u8>,
        source: &dyn PageSource,
    ) -> Result<Receipt, PolicyError> {
        self.live()?;
        let context = self
            .client
            .modern_context()
            .ok_or(PolicyError::Bss)?
            .clone();
        let admission = self
            .authority
            .admit_association(self.client.station(), context, reg::AssociationUse::Data)
            .map_err(PolicyError::Regulatory)?;
        let mut check = Check {
            snapshot: &self.snapshot,
            country: &self.country,
            environment: self.environment,
            revoked: false,
            peer: self.peer,
        };
        // SAFETY: same exclusive privately retained controller and authority.
        unsafe {
            self.client.transmit_modern(
                &mut self.authority,
                admission,
                epoch,
                ethernet,
                class,
                tid,
                source,
                &mut check,
            )
        }
        .map_err(PolicyError::Client)
    }
    pub fn poll_station(&mut self, now: u64, source: &dyn PageSource) -> Result<(), PolicyError> {
        let mut check = Check {
            snapshot: &self.snapshot,
            country: &self.country,
            environment: self.environment,
            revoked: self.revoked,
            peer: self.peer,
        };
        self.client
            .poll_station(now, source, &mut check)
            .map_err(PolicyError::Client)
    }
    pub fn poll_released(&mut self) -> Result<Vec<Released<PacketOwner<C>>>, PolicyError> {
        self.client.poll_released().map_err(PolicyError::Client)
    }
    pub fn cancel_scan(&mut self) -> Result<(), PolicyError> {
        self.client.cancel_scan().map_err(PolicyError::Client)
    }
    pub fn disconnect(&mut self) -> Result<(), PolicyError> {
        self.client.disconnect().map_err(PolicyError::Client)
    }
    /// Deny new work before initiating actual cancel/remove/disable commands.
    /// This return never claims completed retirement. Continue polling/draining
    /// the retained owner; no country replacement or raw mutator is exposed.
    pub fn revoke(&mut self) -> Result<(), PolicyError> {
        self.revoked = true;
        self.observed.clear();
        match self.client.phase() {
            Phase::Scanning => self.client.cancel_scan(),
            Phase::Joining | Phase::AwaitingModernAdmission | Phase::Associated => {
                self.client.disconnect()
            }
            Phase::Idle => self.client.stop(),
            Phase::ScanCompleted | Phase::NeedsDrain | Phase::ControllerDrain | Phase::Stopped => {
                Ok(())
            }
            _ => Err(Error::NeedsDrain),
        }
        .map_err(PolicyError::Client)
    }
    /// # Safety
    /// The actual scan radio restoration and DMA/IRQ/late notifications meet
    /// Client::retire_scan_after_drain, independently of its terminal event.
    pub unsafe fn retire_scan_after_drain(&mut self) -> Result<scan::Outcome, PolicyError> {
        // SAFETY: caller establishes the unchanged native scan fence contract.
        let result =
            unsafe { self.client.retire_scan_after_drain() }.map_err(PolicyError::Client)?;
        if self.revoked {
            self.client.stop().map_err(PolicyError::Client)?;
        }
        Ok(result)
    }
    /// # Safety
    /// All actual peer/key/radio/DMA/IRQ/late users meet the native peer fence.
    pub unsafe fn retire_peer_after_drain(&mut self) -> Result<(), PolicyError> {
        // SAFETY: caller establishes the unchanged native peer fence contract.
        unsafe { self.client.retire_peer_after_drain() }.map_err(PolicyError::Client)?;
        self.peer = None;
        if self.revoked {
            self.client.stop().map_err(PolicyError::Client)?;
        }
        Ok(())
    }
    pub fn stop(&mut self) -> Result<(), PolicyError> {
        self.revoked = true;
        self.client.stop().map_err(PolicyError::Client)
    }
    /// # Safety
    /// The independent whole-controller platform fence meets
    /// Client::stop_after_quiesce; local idle alone is insufficient.
    pub unsafe fn stop_after_quiesce(&mut self) -> Result<(), PolicyError> {
        // SAFETY: caller establishes the unchanged native controller fence.
        unsafe { self.client.stop_after_quiesce() }.map_err(PolicyError::Client)
    }
}

#[cfg(test)]
mod tests {
    use super::super::modern::tests::modern_inputs;
    use super::super::tests::*;
    use super::*;
    use crate::net::wifi::mediatek::{
        bootstrap::tests::*,
        mcu::domain,
        ring::{rx::tests::device_receive, tests::Source},
    };
    use core::sync::atomic::Ordering;
    use reg::database::{
        Database,
        tests::{country, fixture},
    };
    use sha2::{Digest, Sha256};

    fn setup_modern() -> (Client<Bar, Q, NativeGuard>, Model) {
        let mut f = NativeFixture::new(Chip::Mt7925);
        f.install().unwrap();
        f.boot(Chip::Mt7925);
        f.policy_channels(
            Chip::Mt7925,
            [true, true, false],
            [
                vec![domain::Channel {
                    hardware_value: 1,
                    flags: 0,
                }],
                [36, 40, 44, 48]
                    .map(|hardware_value| domain::Channel {
                        hardware_value,
                        flags: 1 << 8,
                    })
                    .to_vec(),
                vec![],
            ],
        );
        // SAFETY: actual modeled completed bootstrap, source policy and owner.
        unsafe { f.controller.initialize_mac() }.unwrap();
        unsafe { f.controller.start(Band::Ghz5, 36, 5180) }.unwrap();
        let interface = unsafe { f.controller.register_interface(profile().interface) }.unwrap();
        f.model.lock().unwrap().client_execution = true;
        f.model.lock().unwrap().key_execution = true;
        let NativeFixture {
            controller,
            model,
            bar,
            queues,
            memory,
            drops,
            ..
        } = f;
        let client = unsafe { Client::new(controller, interface) }.unwrap();
        (
            client,
            Model {
                response: model,
                bar,
                queues,
                memory,
                drops,
            },
        )
    }
    fn done(model: &Model) {
        let mut done = vec![0; 52];
        done[..4].copy_from_slice(&(7u32 << 27).to_le_bytes());
        done[36] = 14;
        done[38] = 6;
        done[50] = 4;
        device_receive(&model.queues[&0xd4500], &done, true, 0);
    }
    fn finish_stop(driver: &mut ManagedClient<Bar, Q, NativeGuard>, model: &Model) {
        model.response.lock().unwrap().clc_processing = false;
        model.bar.0.lock().unwrap().values.insert(0xd4208, 0);
        // SAFETY: all modeled device users have completed; no external IRQ/DMA.
        unsafe { driver.stop_after_quiesce() }.unwrap();
        assert_eq!(driver.phase(), Phase::Stopped);
    }
    #[test]
    fn managed_scan_uses_actual_policy_revokes_real_scan_then_stops_and_releases() {
        let (client, model) = setup();
        let mut driver = ManagedClient::new(client, country(), Environment::Indoor).unwrap();
        let count = model.response.lock().unwrap().client_commands.len();
        // This actual programmed domain has NO_IR. A normal source country
        // does not widen it into active-scan or autonomous transmit permission.
        assert!(
            driver
                .begin_scan(
                    scan::Request::new(vec![CHANNEL], vec![vec![]], vec![]).unwrap(),
                    0,
                    1000
                )
                .is_err()
        );
        assert_eq!(count, model.response.lock().unwrap().client_commands.len());
        driver
            .begin_scan(
                scan::Request::new(vec![CHANNEL], vec![], vec![]).unwrap(),
                0,
                1000,
            )
            .unwrap();
        driver.revoke().unwrap();
        assert_eq!(driver.phase(), Phase::Scanning);
        assert!(matches!(
            driver.begin_scan(
                scan::Request::new(vec![CHANNEL], vec![], vec![]).unwrap(),
                1,
                100
            ),
            Err(PolicyError::Revoked)
        ));
        assert!(model.response.lock().unwrap().client_commands.len() >= count + 2);
        done(&model);
        driver.poll(2, &Source).unwrap();
        assert_eq!(driver.phase(), Phase::ScanCompleted);
        // SAFETY: actual modeled terminal/notifications/DMA drained.
        unsafe { driver.retire_scan_after_drain() }.unwrap();
        assert_eq!(driver.phase(), Phase::ControllerDrain);
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
        finish_stop(&mut driver, &model);
        drop(driver);
        assert_eq!(model.drops.load(Ordering::Relaxed), 1);
        assert!(model.memory.lock().unwrap().mappings.is_empty());
    }
    fn awaiting(
        client: Client<Bar, Q, NativeGuard>,
        model: Model,
        country: Country,
    ) -> (ManagedClient<Bar, Q, NativeGuard>, Model) {
        let (join, bss) = modern_inputs(&client);
        let mut driver = ManagedClient::new(client, country, Environment::Indoor).unwrap();
        driver
            .begin_scan(
                scan::Request::new(vec![CHANNEL], vec![], vec![]).unwrap(),
                0,
                1000,
            )
            .unwrap();
        let mut body = vec![0; 8];
        body.extend_from_slice(&100u16.to_le_bytes());
        body.extend_from_slice(&0x11u16.to_le_bytes());
        body.extend_from_slice(&bss.elements);
        let mut beacon = response(0x80, &body);
        beacon[4..10].copy_from_slice(&crate::net::Mac::BROADCAST.0);
        incoming(&model, &beacon, None, false);
        driver.poll(1, &Source).unwrap();
        let handle = driver.bss().next().expect("real DMA-observed AP").0;
        done(&model);
        driver.poll(2, &Source).unwrap();
        unsafe { driver.retire_scan_after_drain() }.unwrap();
        driver
            .join_modern(handle, join, profile(), 100, &Source)
            .unwrap();
        assert_eq!(finish_tx(&model)[0][..2], [0xb0, 0]);
        driver.poll(101, &Source).unwrap();
        driver.poll_released().unwrap();
        incoming(&model, &response(0xb0, &[0, 0, 2, 0, 0, 0]), None, false);
        driver.poll(102, &Source).unwrap();
        assert_eq!(finish_tx(&model)[0][..2], [0, 0]);
        driver.poll(103, &Source).unwrap();
        driver.poll_released().unwrap();
        let mut assoc = vec![0x11, 0, 0, 0, 1, 0xc0];
        assoc.extend_from_slice(&bss.elements);
        incoming(&model, &response(0x10, &assoc), None, false);
        driver.poll(104, &Source).unwrap();
        assert_eq!(driver.phase(), Phase::AwaitingModernAdmission);
        (driver, model)
    }
    #[test]
    fn managed_modern_ap_observation_configures_actual_eht_keys_qos_and_revocation() {
        let (client, model) = setup_modern();
        let (mut driver, model) = awaiting(client, model, country());
        driver.configure_modern(105).unwrap();
        assert_eq!(driver.phase(), Phase::Associated);
        driver
            .install_key(true, 0, &[4; 16], ReplaySeed::ZERO)
            .unwrap();
        driver
            .install_key(false, 2, &[5; 16], ReplaySeed::ZERO)
            .unwrap();
        let epoch = driver.station().association_epoch().unwrap();
        driver.authorize_port(epoch).unwrap();
        driver
            .transmit(epoch, &eth(0x0800), TxClass::Data, Some(5), &Source)
            .unwrap();
        let packets = finish_tx(&model);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0][0] & 0xfc, 0x88);
        driver.poll(106, &Source).unwrap();
        driver.poll_released().unwrap();
        driver.revoke().unwrap();
        assert_eq!(driver.phase(), Phase::NeedsDrain);
        assert!(matches!(
            driver.transmit(epoch, &eth(0x0800), TxClass::Data, Some(5), &Source),
            Err(PolicyError::Revoked)
        ));
        unsafe { driver.retire_peer_after_drain() }.unwrap();
        assert_eq!(driver.phase(), Phase::ControllerDrain);
        finish_stop(&mut driver, &model);
        drop(driver);
        assert_eq!(model.drops.load(Ordering::Relaxed), 1);
        assert!(model.memory.lock().unwrap().mappings.is_empty());
    }
    #[test]
    fn actual_source_hardware_footprint_and_country_width_refuse_before_configuration() {
        for hardware in [true, false] {
            let (client, model) = if hardware { setup() } else { setup_modern() };
            let country = if hardware {
                country()
            } else {
                let mut b = fixture();
                b[60..64].copy_from_slice(&40_000u32.to_be_bytes());
                Database::parse(Arc::from(b.clone()), Sha256::digest(&b).into())
                    .unwrap()
                    .select(*b"US")
                    .unwrap()
            };
            let (mut driver, model) = awaiting(client, model, country);
            let before = model.response.lock().unwrap().client_commands.len();
            let denied = driver.configure_modern(105);
            assert!(
                matches!(
                    denied,
                    Err(PolicyError::Regulatory(reg::Error::HardwareDenied))
                ) && hardware
                    || matches!(denied, Err(PolicyError::Regulatory(reg::Error::OsDenied)))
                        && !hardware
            );
            assert_eq!(before, model.response.lock().unwrap().client_commands.len());
            assert_eq!(driver.phase(), Phase::AwaitingModernAdmission);
            driver.revoke().unwrap();
            unsafe { driver.retire_peer_after_drain() }.unwrap();
            finish_stop(&mut driver, &model);
        }
    }
    #[test]
    fn mismatched_country_returns_original_owner_and_sku_padding_is_not_power() {
        let (client, model) = setup();
        let mut bytes = fixture();
        bytes[8..10].copy_from_slice(b"DE");
        let db = Database::parse(Arc::from(bytes.clone()), Sha256::digest(&bytes).into()).unwrap();
        let error =
            match ManagedClient::new(client, db.select(*b"DE").unwrap(), Environment::Indoor) {
                Err(error) => error,
                Ok(_) => panic!("wrong country admitted"),
            };
        assert!(matches!(error.error, PolicyError::CountryMismatch));
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
        let mut corrected =
            ManagedClient::new(error.client, country(), Environment::Indoor).unwrap();
        corrected.revoke().unwrap();
        finish_stop(&mut corrected, &model);
        drop(corrected);
        assert_eq!(model.drops.load(Ordering::Relaxed), 1);
        let (client, model) = setup();
        // Actual SKU -1.5dBm fits zero dBm but not a hypothetical copied
        // high-power value: directly verify every real used slot, not padding.
        assert_eq!(
            sku_max(
                &wifi::mediatek::mcu::power::Limits::uniform(-3).sku(Chip::Mt7925, Band::Ghz5),
                Band::Ghz5
            ),
            Some(-3)
        );
        let mut country = fixture();
        country[26..28].copy_from_slice(&0u16.to_be_bytes());
        let db =
            Database::parse(Arc::from(country.clone()), Sha256::digest(&country).into()).unwrap();
        let mut driver =
            ManagedClient::new(client, db.select(*b"US").unwrap(), Environment::Indoor).unwrap();
        driver.revoke().unwrap();
        finish_stop(&mut driver, &model);
    }
}
