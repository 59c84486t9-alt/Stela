// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
// Copyright (C) 2020-2023 MediaTek Inc.
//! An owning Ethernet link over the already constructed native policy client.
//! The initial profile is ordinary single-link 2.4/5GHz WPA2-CCMP128. This creates
//! no PCI/requester/coherency, supplicant, regulatory or physical-radio grant.
//! The actual platform still supplies the controller and independent drain fences.

use super::*;
use crate::net::{Link, LinkError, Mac};
use alloc::{collections::VecDeque, format, vec::IntoIter};

const DATA_FRAMES: usize = 64;
const NOTICES: usize = 64;

#[derive(Debug)]
pub enum LinkControlError {
    Policy(PolicyError),
    WrongPhase,
    UnsupportedProfile,
    NoMemory,
    Backpressure,
}
impl From<PolicyError> for LinkControlError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}
impl core::fmt::Display for LinkControlError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MT7925 managed link: {self:?}")
    }
}
impl core::error::Error for LinkControlError {}

/// Construction failure returns both actual owners without changing hardware.
pub struct LinkAttachError<I: BarIo, Q: QueueIo, C: 'static, S: PageSource + 'static> {
    pub error: LinkControlError,
    pub client: ManagedClient<I, Q, C>,
    pub source: S,
}
impl<I: BarIo, Q: QueueIo, C: 'static, S: PageSource + 'static> core::fmt::Debug
    for LinkAttachError<I, Q, C, S>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.error, f)
    }
}

pub enum LinkEvent<C: 'static> {
    /// Original owned controller/control-port event. Ingress::ControlPort must
    /// reach the real supplicant; classification is no handshake/MIC proof.
    Controller(Event),
    /// Both real descriptor consumption and exact-once TX-free completed.
    /// This is resource retirement, never a physical air ACK.
    Released(Released<PacketOwner<C>>),
}
pub struct LinkNotice<C: 'static> {
    /// Original client association when this native poll began. This is useful
    /// for routing; no copy authorizes a delayed association/key operation.
    pub association: Option<u64>,
    pub event: LinkEvent<C>,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinkProgress {
    pub data_frames: usize,
    pub notices: usize,
    /// A destination is full, or a returned native batch awaits room.
    pub backpressured: bool,
}
struct QueuedData {
    association: u64,
    bytes: Vec<u8>,
}
struct PendingEvents {
    association: Option<u64>,
    events: IntoIter<Event>,
}
struct State<I: BarIo, Q: QueueIo, C: 'static, S: PageSource + 'static> {
    client: ManagedClient<I, Q, C>,
    source: S,
    mac: Mac,
    data: VecDeque<QueuedData>,
    notices: VecDeque<LinkNotice<C>>,
    pending: Option<PendingEvents>,
    released: Option<IntoIter<Released<PacketOwner<C>>>>,
    epoch: Option<u64>,
}
/// Owns the exact existing native client and allocation provider. It has no raw
/// mutable-client escape: controls, timers, packets and revocation serialize on
/// this owner. Call service regularly even while there is no Ethernet traffic.
/// Live/uncertain Drop retains this whole object, including pending frontend
/// events and provider, until actual platform quiescence can be established.
pub struct ManagedLink<I: BarIo, Q: QueueIo, C: 'static, S: PageSource + 'static> {
    owned: Option<Box<State<I, Q, C, S>>>,
}
impl<I: BarIo, Q: QueueIo, C: 'static, S: PageSource + 'static> ManagedLink<I, Q, C, S> {
    // Returning the actual owner/provider also on allocation failure avoids a
    // second allocation solely to report failure while preserving ownership.
    #[allow(clippy::result_large_err)]
    pub fn new(
        client: ManagedClient<I, Q, C>,
        source: S,
    ) -> Result<Self, LinkAttachError<I, Q, C, S>> {
        // Begin before any timed scan/join, so all frontend deadlines use the
        // already calibrated controller Clock's single monotonic time domain.
        if client.phase() != Phase::Idle
            || client.revoked
            || client.client.state().controller.phase() != ControllerPhase::StartFacts
        {
            return Err(LinkAttachError {
                error: LinkControlError::WrongPhase,
                client,
                source,
            });
        }
        let Some(interface) = client.client.state().interface.registered_context() else {
            return Err(LinkAttachError {
                error: LinkControlError::WrongPhase,
                client,
                source,
            });
        };
        let mac = interface.address;
        let mut data = VecDeque::new();
        let mut notices = VecDeque::new();
        if data.try_reserve_exact(DATA_FRAMES).is_err()
            || notices.try_reserve_exact(NOTICES).is_err()
        {
            return Err(LinkAttachError {
                error: LinkControlError::NoMemory,
                client,
                source,
            });
        }
        Ok(Self {
            owned: Some(Box::new(State {
                client,
                source,
                mac,
                data,
                notices,
                pending: None,
                released: None,
                epoch: None,
            })),
        })
    }
    fn state(&self) -> &State<I, Q, C, S> {
        self.owned.as_deref().expect("owned managed link")
    }
    fn state_mut(&mut self) -> &mut State<I, Q, C, S> {
        self.owned.as_deref_mut().expect("owned managed link")
    }
    fn now(&self) -> u64 {
        self.state()
            .client
            .client
            .state()
            .controller
            .state()
            .control
            .clock
            .now_us()
    }
    fn up(s: &State<I, Q, C, S>) -> bool {
        let c = s.client.client.state();
        !s.client.revoked
            && c.phase == Phase::Associated
            && c.controller.phase() == ControllerPhase::StartFacts
            && c.profile
                .is_some_and(|p| matches!(p.channel.band, Band::Ghz2 | Band::Ghz5))
            && c.station.port_open(
                c.ptk.as_ref().map(HardwareKey::slot),
                c.gtk.as_ref().map(HardwareKey::slot),
            )
    }
    fn reconcile(s: &mut State<I, Q, C, S>) {
        let epoch = s.client.station().association_epoch();
        if epoch != s.epoch || !Self::up(s) {
            s.data.clear();
        }
        s.epoch = epoch;
    }
    fn progress(s: &State<I, Q, C, S>) -> LinkProgress {
        LinkProgress {
            data_frames: s.data.len(),
            notices: s.notices.len(),
            backpressured: s.pending.is_some()
                || s.released.is_some()
                || s.data.len() == DATA_FRAMES
                || s.notices.len() == NOTICES,
        }
    }
    fn drain(s: &mut State<I, Q, C, S>) {
        while let Some(pending) = s.pending.as_mut() {
            let Some(next) = pending.events.as_slice().first() else {
                s.pending = None;
                continue;
            };
            let data = matches!(next, Event::Ingress(Ingress::Data(_)));
            if (data && s.data.len() == DATA_FRAMES) || (!data && s.notices.len() == NOTICES) {
                break;
            }
            let epoch = pending.association;
            let event = pending.events.next().unwrap();
            if let Event::Ingress(Ingress::Data(bytes)) = event {
                // Linux Link semantics discard held data after carrier loss.
                // Control-port/controller events always retain their own bytes.
                if Self::up(s)
                    && epoch == s.client.station().association_epoch()
                    && let Some(association) = epoch
                {
                    s.data.push_back(QueuedData { association, bytes });
                }
            } else {
                s.notices.push_back(LinkNotice {
                    association: epoch,
                    event: LinkEvent::Controller(event),
                });
            }
        }
        while s.notices.len() < NOTICES {
            let Some(released) = s.released.as_mut() else {
                break;
            };
            let Some(packet) = released.next() else {
                s.released = None;
                break;
            };
            s.notices.push_back(LinkNotice {
                association: Some(packet.context.association_epoch()),
                event: LinkEvent::Released(packet),
            });
        }
    }
    pub fn phase(&self) -> Phase {
        self.state().client.phase()
    }
    pub fn station(&self) -> &Station {
        self.state().client.station()
    }
    pub fn country(&self) -> [u8; 2] {
        self.state().client.country()
    }
    pub fn local_advertisement(&self, band: Band) -> Result<Advertisement, LinkControlError> {
        if band == Band::Ghz6 {
            return Err(LinkControlError::UnsupportedProfile);
        }
        self.state()
            .client
            .local_advertisement(band)
            .map_err(|e| LinkControlError::Policy(PolicyError::Client(Error::Local(e))))
    }
    pub fn bss(&self) -> impl Iterator<Item = (BssHandle, &scan::result::Bss)> {
        self.state().client.bss()
    }
    pub fn take_notice(&mut self) -> Option<LinkNotice<C>> {
        self.state_mut().notices.pop_front()
    }
    pub fn queues(&self) -> LinkProgress {
        Self::progress(self.state())
    }
    /// Process one native RX batch, real TX retirement and station timers. Full
    /// frontend queues retain their batch and apply backpressure without making
    /// a fabricated completion or discarding control-port/event bytes.
    pub fn service(&mut self) -> Result<LinkProgress, LinkControlError> {
        let now = self.now();
        let s = self.state_mut();
        Self::reconcile(s);
        Self::drain(s);
        let mut failure = None;
        if s.pending.is_none()
            && s.notices.len() < NOTICES
            && matches!(
                s.client.phase(),
                Phase::Scanning
                    | Phase::ScanCompleted
                    | Phase::Joining
                    | Phase::AwaitingModernAdmission
                    | Phase::Associated
                    | Phase::Removing
                    | Phase::NeedsDrain
            )
        {
            let epoch = s.client.station().association_epoch();
            match s.client.poll(now, &s.source) {
                Ok(events) if !events.is_empty() => {
                    s.pending = Some(PendingEvents {
                        association: epoch,
                        events: events.into_iter(),
                    });
                }
                Ok(_) => {}
                Err(error) => failure = Some(error),
            }
        }
        // A rejected receive frame must not starve timeouts or actual completed
        // packet retirement. Preserve the first error; any native stop/failure
        // still updates its original owner before carrier/queues are rechecked.
        let timer_now = s
            .client
            .client
            .state()
            .controller
            .state()
            .control
            .clock
            .now_us();
        if matches!(s.client.phase(), Phase::Joining | Phase::Associated)
            && let Err(error) = s.client.poll_station(timer_now, &s.source)
        {
            failure.get_or_insert(error);
        }
        if s.released.is_none()
            && !matches!(
                s.client.phase(),
                Phase::Stopped | Phase::ControllerDrain | Phase::Quarantined
            )
        {
            match s.client.poll_released() {
                Ok(released) if !released.is_empty() => s.released = Some(released.into_iter()),
                Ok(_) => {}
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
        }
        Self::reconcile(s);
        Self::drain(s);
        if let Some(error) = failure {
            return Err(error.into());
        }
        Ok(Self::progress(s))
    }
    pub fn begin_scan(
        &mut self,
        request: scan::Request,
        budget_us: u64,
    ) -> Result<scan::Ticket, LinkControlError> {
        if request.channels().iter().any(|c| c.band == Band::Ghz6) {
            return Err(LinkControlError::UnsupportedProfile);
        }
        let now = self.now();
        Ok(self
            .state_mut()
            .client
            .begin_scan(request, now, budget_us)?)
    }
    pub fn cancel_scan(&mut self) -> Result<(), LinkControlError> {
        Ok(self.state_mut().client.cancel_scan()?)
    }
    /// # Safety
    /// Actual radio restoration and all DMA/IRQ/late users satisfy the original
    /// native client's independent scan drain contract.
    pub unsafe fn retire_scan_after_drain(&mut self) -> Result<scan::Outcome, LinkControlError> {
        // SAFETY: inherited unchanged real native scan drain contract.
        Ok(unsafe { self.state_mut().client.retire_scan_after_drain() }?)
    }
    pub fn join(
        &mut self,
        handle: BssHandle,
        join: Join,
        profile: Profile,
    ) -> Result<(), LinkControlError> {
        if !matches!(join.channel.band, Band::Ghz2 | Band::Ghz5)
            || join.policy != station::PortPolicy::Controlled
            || join.request.key_ciphers() != Some((Cipher::Ccmp128, Cipher::Ccmp128))
        {
            return Err(LinkControlError::UnsupportedProfile);
        }
        let now = self.now();
        let s = self.state_mut();
        let result = s.client.join_modern(handle, join, profile, now, &s.source);
        Self::reconcile(s);
        Ok(result?)
    }
    pub fn configure(&mut self) -> Result<(), LinkControlError> {
        let now = self.now();
        Ok(self.state_mut().client.configure_modern(now)?)
    }
    /// The real OS supplicant supplies the authenticated material and RSC.
    pub fn install_key(
        &mut self,
        pairwise: bool,
        index: u8,
        material: &[u8],
        seed: ReplaySeed,
    ) -> Result<KeyIdentity, LinkControlError> {
        let s = self.state_mut();
        let result = s.client.install_key(pairwise, index, material, seed);
        Self::reconcile(s);
        Ok(result?)
    }
    /// The OS supplies this only after its actual authenticated handshake.
    pub fn authorize_port(&mut self, epoch: u64) -> Result<(), LinkControlError> {
        Ok(self.state_mut().client.authorize_port(epoch)?)
    }
    pub fn send_control(
        &mut self,
        ethernet: &[u8],
        key: Option<KeyIdentity>,
    ) -> Result<Receipt, LinkControlError> {
        if self.service()?.backpressured {
            return Err(LinkControlError::Backpressure);
        }
        let s = self.state_mut();
        let epoch = s
            .client
            .station()
            .association_epoch()
            .ok_or(LinkControlError::WrongPhase)?;
        Ok(s.client.transmit(
            epoch,
            ethernet,
            key.map_or(TxClass::ControlPortPlaintext, TxClass::ControlPortProtected),
            None,
            &s.source,
        )?)
    }
    pub fn disconnect(&mut self) -> Result<(), LinkControlError> {
        let s = self.state_mut();
        let result = s.client.disconnect();
        Self::reconcile(s);
        Ok(result?)
    }
    pub fn revoke(&mut self) -> Result<(), LinkControlError> {
        let s = self.state_mut();
        let result = s.client.revoke();
        Self::reconcile(s);
        Ok(result?)
    }
    /// # Safety
    /// Exact native peer/key removal and all old radio/DMA/IRQ/work users meet
    /// the original independent peer fence; local queue emptiness is no fence.
    pub unsafe fn retire_peer_after_drain(&mut self) -> Result<(), LinkControlError> {
        let s = self.state_mut();
        // SAFETY: inherited unchanged real native peer drain contract.
        let result = unsafe { s.client.retire_peer_after_drain() };
        Self::reconcile(s);
        Ok(result?)
    }
    pub fn stop(&mut self) -> Result<(), LinkControlError> {
        let s = self.state_mut();
        let result = s.client.stop();
        Self::reconcile(s);
        Ok(result?)
    }
    /// # Safety
    /// Exact whole-controller/radio/DMA/IOTLB/IRQ/work quiescence meets the
    /// original native platform fence, independently of stop/idle observations.
    pub unsafe fn stop_after_quiesce(&mut self) -> Result<(), LinkControlError> {
        // SAFETY: inherited unchanged actual native controller fence.
        Ok(unsafe { self.state_mut().client.stop_after_quiesce() }?)
    }
}
impl<I: BarIo, Q: QueueIo, C: 'static, S: PageSource + 'static> Link for ManagedLink<I, Q, C, S> {
    fn mac(&self) -> Mac {
        self.state().mac
    }
    fn carrier(&mut self) -> bool {
        Self::up(self.state())
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        crate::net::check_frame(frame)?;
        let progress = self
            .service()
            .map_err(|e| LinkError::Adapter(format!("{e}")))?;
        let s = self.state_mut();
        if !Self::up(s) {
            return Err(LinkError::NoCarrier);
        }
        if progress.backpressured {
            return Err(LinkError::Adapter(format!(
                "{}",
                LinkControlError::Backpressure
            )));
        }
        let epoch = s
            .client
            .station()
            .association_epoch()
            .ok_or(LinkError::NoCarrier)?;
        s.client
            .transmit(epoch, frame, TxClass::Data, None, &s.source)
            .map(|_| ())
            .map_err(|e| LinkError::Adapter(format!("MT7925 managed link: {e:?}")))
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        self.service()
            .map_err(|e| LinkError::Adapter(format!("{e}")))?;
        let s = self.state_mut();
        while let Some(packet) = s.data.pop_front() {
            if Some(packet.association) == s.client.station().association_epoch() {
                return Ok(Some(packet.bytes));
            }
        }
        Ok(None)
    }
}
impl<I: BarIo, Q: QueueIo, C: 'static, S: PageSource + 'static> Drop for ManagedLink<I, Q, C, S> {
    fn drop(&mut self) {
        if let Some(state) = self.owned.take()
            && state.client.phase() != Phase::Stopped
        {
            core::mem::forget(state);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::tests::{done, setup_modern, setup_modern_radio};
    use super::*;
    use crate::bus::dma::memory::{CacheAttribute, MemoryError, PageGeometry, PinnedPages};
    use crate::net::wifi::mediatek::{
        bootstrap::{
            client::{modern::tests::modern_inputs, tests::*},
            tests::*,
        },
        ring::{rx::tests::device_receive, tests::Source},
    };
    use core::sync::atomic::{AtomicUsize, Ordering};
    use reg::database::tests::country;

    struct Provider(Arc<AtomicUsize>, core::sync::atomic::AtomicBool);
    impl PageSource for Provider {
        fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
            Source.page_geometry()
        }
        fn allocate(
            &self,
            bytes: usize,
            alignment: usize,
            attribute: CacheAttribute,
        ) -> Result<PinnedPages, MemoryError> {
            if self.1.load(Ordering::Relaxed) {
                return Err(MemoryError::OutOfMemory);
            }
            Source.allocate(bytes, alignment, attribute)
        }
    }
    impl Drop for Provider {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    type TestLink = ManagedLink<Bar, Q, NativeGuard, Provider>;
    fn setup_link() -> (TestLink, Model, Join, scan::result::Bss, Arc<AtomicUsize>) {
        let (client, model) = setup_modern();
        let (join, bss) = modern_inputs(&client);
        let client = ManagedClient::new(client, country(), Environment::Indoor).unwrap();
        let drops = Arc::new(AtomicUsize::new(0));
        let link = ManagedLink::new(
            client,
            Provider(drops.clone(), core::sync::atomic::AtomicBool::new(false)),
        )
        .unwrap();
        (link, model, join, bss, drops)
    }
    fn scan_join(
        link: &mut TestLink,
        model: &Model,
        join: Join,
        bss: scan::result::Bss,
    ) -> scan::result::Bss {
        assert_eq!(link.mac(), LOCAL);
        assert!(!link.carrier());
        link.begin_scan(
            scan::Request::new(vec![CHANNEL], vec![], vec![]).unwrap(),
            1_000_000,
        )
        .unwrap();
        let mut body = vec![0; 8];
        body.extend_from_slice(&100u16.to_le_bytes());
        body.extend_from_slice(&0x11u16.to_le_bytes());
        body.extend_from_slice(&bss.elements);
        let mut beacon = response(0x80, &body);
        beacon[4..10].copy_from_slice(&Mac::BROADCAST.0);
        incoming(model, &beacon, None, false);
        link.service().unwrap();
        let handle = link.bss().next().unwrap().0;
        done(model);
        link.service().unwrap();
        // SAFETY: complete source-model terminal scan and actual old-user drain.
        unsafe { link.retire_scan_after_drain() }.unwrap();
        link.join(handle, join, profile()).unwrap();
        bss
    }
    fn associate(link: &mut TestLink, model: &Model, join: Join, bss: scan::result::Bss) {
        let bss = scan_join(link, model, join, bss);
        assert_eq!(finish_tx(model)[0][..2], [0xb0, 0]);
        link.service().unwrap();
        incoming(model, &response(0xb0, &[0, 0, 2, 0, 0, 0]), None, false);
        link.service().unwrap();
        assert_eq!(finish_tx(model)[0][..2], [0, 0]);
        link.service().unwrap();
        let mut assoc = vec![0x11, 0, 0, 0, 1, 0xc0];
        assoc.extend_from_slice(&bss.elements);
        incoming(model, &response(0x10, &assoc), None, false);
        link.service().unwrap();
        assert_eq!(link.phase(), Phase::AwaitingModernAdmission);
        link.configure().unwrap();
        assert_eq!(link.phase(), Phase::Associated);
        assert!(!link.carrier());
    }
    fn secure(link: &mut TestLink) -> KeyIdentity {
        let ptk = link
            .install_key(true, 0, &[4; 16], ReplaySeed::ZERO)
            .unwrap();
        assert!(!link.carrier());
        link.install_key(false, 2, &[5; 16], ReplaySeed::ZERO)
            .unwrap();
        assert!(!link.carrier());
        link.authorize_port(link.station().association_epoch().unwrap())
            .unwrap();
        assert!(link.carrier());
        ptk
    }
    fn drain_notices(link: &mut TestLink) -> Vec<LinkNotice<NativeGuard>> {
        let mut out = Vec::new();
        loop {
            while let Some(n) = link.take_notice() {
                out.push(n);
            }
            link.service().unwrap();
            if link.queues().notices == 0 {
                break;
            }
        }
        out
    }
    fn stop(link: &mut TestLink, model: &Model) {
        link.disconnect().unwrap();
        assert!(!link.carrier());
        assert_eq!(link.phase(), Phase::NeedsDrain);
        // SAFETY: actual source-model peer/key removal and no remaining native old users.
        unsafe { link.retire_peer_after_drain() }.unwrap();
        link.stop().unwrap();
        assert_eq!(link.phase(), Phase::ControllerDrain);
        model.response.lock().unwrap().clc_processing = false;
        model.bar.0.lock().unwrap().values.insert(0xd4208, 0);
        // SAFETY: independent model controller, firmware, DMA and IRQ/work fence.
        unsafe { link.stop_after_quiesce() }.unwrap();
        assert_eq!(link.phase(), Phase::Stopped);
    }
    fn control() -> Vec<u8> {
        let mut frame = eth(0x888e);
        frame[..6].copy_from_slice(&AP.0);
        frame
    }
    fn incoming_control(model: &Model, pn: Option<u64>, marker: u8) {
        let mut bytes = data(false);
        bytes[24 + 6..24 + 8].copy_from_slice(&0x888eu16.to_be_bytes());
        *bytes.last_mut().unwrap() = marker;
        if pn.is_none() {
            bytes[1] &= !0x40;
        }
        let mut raw = incoming_bytes(&bytes, pn.map(|n| (1, 0, n)), false);
        raw[4] = 1; // actual source WCID remains required for plaintext data too
        device_receive(&model.queues[&0xd4520], &raw, true, 0);
    }
    #[test]
    fn actual_link_routes_control_port_then_real_ethernet_and_retires_exact_packets() {
        let (mut link, model, join, bss, provider) = setup_link();
        associate(&mut link, &model, join, bss);
        let original_epoch = link.station().association_epoch().unwrap();
        assert!(matches!(
            link.transmit(&eth(0x800)),
            Err(LinkError::NoCarrier)
        ));
        // EAPOL is available before keys, kept for the real OS supplicant and
        // never promoted to ordinary Ethernet data or handshake completion.
        incoming_control(&model, None, 0x55);
        link.service().unwrap();
        assert!(link.receive().unwrap().is_none());
        let notices = drain_notices(&mut link);
        assert!(notices.iter().any(|n|n.association==Some(original_epoch)&&matches!(&n.event,LinkEvent::Controller(Event::Ingress(Ingress::ControlPort{ethernet,encrypted:false,key:None})) if ethernet.last()==Some(&0x55))));
        assert!(!link.carrier());
        let plain = link.send_control(&control(), None).unwrap();
        assert_eq!(finish_tx(&model)[0][1] & 0x40, 0);
        link.service().unwrap();
        assert!(drain_notices(&mut link).into_iter().any(|n|matches!(n.event,LinkEvent::Released(r) if r.receipt==plain&&r.context.key().is_none())));
        let ptk = secure(&mut link);
        let before = model.queues[&0xd4300].lock().unwrap().head;
        assert!(matches!(
            link.transmit(&control()),
            Err(LinkError::Adapter(_))
        ));
        assert_eq!(model.queues[&0xd4300].lock().unwrap().head, before);
        let protected = link.send_control(&control(), Some(ptk)).unwrap();
        assert_ne!(finish_tx(&model)[0][1] & 0x40, 0);
        link.service().unwrap();
        assert!(drain_notices(&mut link).into_iter().any(|n|matches!(n.event,LinkEvent::Released(r) if r.receipt==protected&&r.context.key()==Some(ptk))));
        assert!(link.transmit(&eth(0x800)).is_ok());
        // Original DMA packet has no release until both actual consumption and TX-free.
        assert!(
            !drain_notices(&mut link)
                .iter()
                .any(|n| matches!(n.event, LinkEvent::Released(_)))
        );
        let frames = finish_tx(&model);
        assert_eq!(frames.len(), 1);
        assert_ne!(frames[0][1] & 0x40, 0);
        link.service().unwrap();
        assert!(
            drain_notices(&mut link)
                .iter()
                .any(|n| matches!(&n.event,LinkEvent::Released(r) if r.context.key()==Some(ptk)))
        );
        incoming(&model, &data(false), Some((1, 0, 1)), false);
        link.service().unwrap();
        let ethernet = link.receive().unwrap().unwrap();
        assert_eq!(&ethernet[..6], &LOCAL.0);
        assert_eq!(&ethernet[12..14], &0x800u16.to_be_bytes());
        stop(&mut link, &model);
        assert_eq!(link.mac(), LOCAL);
        drop(notices);
        drop(link);
        assert_eq!(model.drops.load(Ordering::Relaxed), 1);
        assert_eq!(provider.load(Ordering::Relaxed), 1);
        assert!(model.memory.lock().unwrap().mappings.is_empty());
    }
    #[test]
    fn full_data_and_control_queues_retain_native_batches_in_order() {
        let (mut link, model, join, bss, provider) = setup_link();
        associate(&mut link, &model, join, bss);
        secure(&mut link);
        drop(drain_notices(&mut link));
        for n in 1..=65 {
            let mut bytes = data(false);
            *bytes.last_mut().unwrap() = n;
            incoming(&model, &bytes, Some((1, 0, u64::from(n))), false);
            link.service().unwrap();
        }
        assert_eq!(link.queues().data_frames, DATA_FRAMES);
        assert!(link.queues().backpressured);
        let before = model.queues[&0xd4300].lock().unwrap().head;
        assert!(matches!(
            link.transmit(&eth(0x800)),
            Err(LinkError::Adapter(_))
        ));
        assert_eq!(model.queues[&0xd4300].lock().unwrap().head, before);
        for n in 1..=65 {
            assert_eq!(link.receive().unwrap().unwrap().last(), Some(&n));
        }
        assert!(link.receive().unwrap().is_none());
        for n in 1..=65 {
            incoming_control(&model, Some(65 + u64::from(n)), n);
            link.service().unwrap();
        }
        assert_eq!(link.queues().notices, NOTICES);
        assert!(link.queues().backpressured);
        for n in 1..=65 {
            link.service().unwrap();
            let notice = link.take_notice().unwrap();
            assert!(
                matches!(notice.event,LinkEvent::Controller(Event::Ingress(Ingress::ControlPort{ethernet,encrypted:true,key:Some(_)})) if ethernet.last()==Some(&n))
            );
        }
        link.service().unwrap();
        assert_eq!(link.queues(), LinkProgress::default());
        // Carrier loss discards held data, retaining control notices separately.
        incoming(&model, &data(false), Some((1, 0, 131)), false);
        link.service().unwrap();
        assert_eq!(link.queues().data_frames, 1);
        stop(&mut link, &model);
        assert_eq!(link.queues().data_frames, 0);
        drop(link);
        assert_eq!(model.drops.load(Ordering::Relaxed), 1);
        assert_eq!(provider.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn removal_waits_for_both_real_tx_facts_and_uncertain_stop_retains_frontend_owner() {
        let (mut link, model, join, bss, provider) = setup_link();
        associate(&mut link, &model, join, bss);
        secure(&mut link);
        drop(drain_notices(&mut link));
        link.transmit(&eth(0x800)).unwrap();
        link.disconnect().unwrap();
        assert_eq!(link.phase(), Phase::Removing);
        assert!(!link.carrier());
        assert!(model.response.lock().unwrap().peers.contains_key(&1));
        finish_tx(&model);
        link.service().unwrap();
        assert_eq!(link.phase(), Phase::NeedsDrain);
        assert!(!model.response.lock().unwrap().peers.contains_key(&1));
        assert!(link.queues().notices > 0);
        // SAFETY: exact removal ACKs and all actual old model users have ended.
        unsafe { link.retire_peer_after_drain() }.unwrap();
        model.response.lock().unwrap().bss_status = 0xdead;
        assert!(link.stop().is_err());
        assert_eq!(link.phase(), Phase::Quarantined);
        let notices = link.queues().notices;
        assert!(notices > 0);
        assert!(!link.carrier());
        drop(link);
        assert_eq!(provider.load(Ordering::Relaxed), 0);
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
        assert!(!model.memory.lock().unwrap().mappings.is_empty());
    }
    #[test]
    fn unpublished_allocation_failure_and_bad_rx_never_forge_completion_or_close_valid_port() {
        let (mut link, model, join, bss, provider) = setup_link();
        associate(&mut link, &model, join, bss);
        secure(&mut link);
        drop(drain_notices(&mut link));
        let before = model.queues[&0xd4300].lock().unwrap().head;
        let mappings = model.memory.lock().unwrap().mappings.len();
        link.state().source.1.store(true, Ordering::Relaxed);
        assert!(matches!(
            link.transmit(&eth(0x800)),
            Err(LinkError::Adapter(_))
        ));
        assert_eq!(model.queues[&0xd4300].lock().unwrap().head, before);
        assert_eq!(model.memory.lock().unwrap().mappings.len(), mappings);
        assert!(link.carrier());
        assert_eq!(link.queues().notices, 0);
        link.state().source.1.store(false, Ordering::Relaxed);
        incoming(&model, &data(false), Some((1, 0, 1)), false);
        assert!(link.receive().unwrap().is_some());
        incoming(&model, &data(false), Some((1, 0, 1)), false);
        assert!(matches!(link.receive(), Err(LinkError::Adapter(_))));
        link.transmit(&eth(0x800)).unwrap();
        finish_tx(&model);
        let mut bad = incoming_bytes(&data(false), Some((1, 0, 2)), false);
        bad[7] |= 2;
        device_receive(&model.queues[&0xd4520], &bad, true, 0);
        assert!(matches!(link.receive(), Err(LinkError::Adapter(_))));
        assert!(
            link.state()
                .client
                .client
                .state()
                .controller
                .state()
                .data_tx
                .as_ref()
                .unwrap()
                .outstanding_tokens()
                == 0
        );
        assert!(link.queues().notices > 0);
        assert!(link.carrier());
        incoming(&model, &data(false), Some((1, 0, 2)), false);
        assert!(link.receive().unwrap().is_some());
        stop(&mut link, &model);
        drop(link);
        assert_eq!(provider.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn actual_2ghz_he20_profile_scans_associates_and_carries_ethernet_on_its_real_channel() {
        use station::{
            phy::{Capabilities, Mode, Role, Width},
            wire::AssociationRequest,
        };
        let channel = wifi::Channel {
            band: Band::Ghz2,
            number: 1,
            frequency_mhz: 2412,
        };
        let (client, model) = setup_modern_radio(false, channel);
        let actual = client.local_advertisement(Band::Ghz2).unwrap();
        let mut local = vec![0, 1, b'x'];
        let mut at = 0;
        while at < actual.elements().len() {
            let n = usize::from(actual.elements()[at + 1]);
            let ie = &actual.elements()[at..at + 2 + n];
            // A real frontend can select the retained HE subset. Preserve its
            // original source maps after parsing exactly the advertised bytes.
            if ie[0] != 255 || ie[2] != 108 {
                local.extend_from_slice(ie);
            }
            at += 2 + n;
        }
        local.extend_from_slice(&[
            48, 18, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2,
        ]);
        let caps = Capabilities::parse(Band::Ghz2, Role::Station, &local)
            .unwrap()
            .with_local_he_source_maps(*actual.he_source_maps())
            .unwrap();
        let request = AssociationRequest::new_modern_with_local(
            0x11,
            10,
            local.clone(),
            caps,
            Mode::He,
            Width::Mhz20,
        )
        .unwrap();
        let mut ap = Vec::new();
        at = 0;
        while at < local.len() {
            let n = usize::from(local[at + 1]);
            let ie = &local[at..at + 2 + n];
            if ie[0] == 221 {
                ap.extend_from_slice(&[
                    221, 24, 0, 0x50, 0xf2, 2, 1, 1, 0x80, 0, 3, 0xa4, 0, 0, 0x27, 0xa4, 0, 0,
                    0x42, 0x43, 94, 0, 0x62, 0x32, 47, 0,
                ]);
            } else {
                let offset = ap.len();
                ap.extend_from_slice(ie);
                if ie[0] == 1 {
                    for q in 0..4 {
                        ap[offset + 2 + q] |= 0x80;
                    }
                }
            }
            at += 2 + n;
        }
        let mut ht = [0; 22];
        ht[0] = 1;
        ap.extend_from_slice(&[61, 22]);
        ap.extend_from_slice(&ht);
        ap.extend_from_slice(&[255, 7, 36, 3, 0, 0, 0, 0xff, 0xff, 5, 4, 0, 2, 0, 0]);
        let drops = Arc::new(AtomicUsize::new(0));
        let client = ManagedClient::new(client, country(), Environment::Indoor).unwrap();
        let mut link = ManagedLink::new(
            client,
            Provider(drops.clone(), core::sync::atomic::AtomicBool::new(false)),
        )
        .unwrap();
        let receive = |bytes: &[u8], pn: Option<u64>| {
            let mut raw = incoming_bytes(bytes, pn.map(|n| (1, 0, n)), false);
            raw[13] = 1;
            device_receive(&model.queues[&0xd4520], &raw, true, 0);
        };
        link.begin_scan(
            scan::Request::new(vec![channel], vec![], vec![]).unwrap(),
            1_000_000,
        )
        .unwrap();
        let mut body = vec![0; 8];
        body.extend_from_slice(&100u16.to_le_bytes());
        body.extend_from_slice(&0x11u16.to_le_bytes());
        body.extend_from_slice(&ap);
        let mut beacon = response(0x80, &body);
        beacon[4..10].fill(255);
        receive(&beacon, None);
        link.service().unwrap();
        let handle = link.bss().next().unwrap().0;
        done(&model);
        link.service().unwrap();
        // SAFETY: actual completed model scan/radio/RX work independently drained.
        unsafe { link.retire_scan_after_drain() }.unwrap();
        let mut profile = profile();
        profile.channel = channel;
        profile.basic_rates = 15;
        profile.supported_rates = 0xfff;
        profile.slot_time = 20;
        let join = Join {
            bssid: AP,
            channel,
            policy: station::PortPolicy::Controlled,
            request,
        };
        link.join(handle, join, profile).unwrap();
        assert_eq!(finish_tx_on(&model, 1)[0][..2], [0xb0, 0]);
        link.service().unwrap();
        receive(&response(0xb0, &[0, 0, 2, 0, 0, 0]), None);
        link.service().unwrap();
        assert_eq!(finish_tx_on(&model, 1)[0][..2], [0, 0]);
        link.service().unwrap();
        let mut assoc = vec![0x11, 0, 0, 0, 1, 0xc0];
        assoc.extend_from_slice(&ap);
        receive(&response(0x10, &assoc), None);
        link.service().unwrap();
        link.configure().unwrap();
        secure(&mut link);
        link.transmit(&eth(0x800)).unwrap();
        assert_eq!(finish_tx_on(&model, 1).len(), 1);
        link.service().unwrap();
        receive(&data(false), Some(1));
        let frame = link.receive().unwrap().unwrap();
        assert_eq!(&frame[12..14], &0x800u16.to_be_bytes());
        assert_eq!(model.response.lock().unwrap().home_channel, Some(1));
        stop(&mut link, &model);
        drop(link);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(model.drops.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn native_rx_ring_failure_cannot_leave_cached_association_carrier_up() {
        let (mut link, model, join, bss, provider) = setup_link();
        associate(&mut link, &model, join, bss);
        secure(&mut link);
        drop(drain_notices(&mut link));
        incoming_control(&model, Some(1), 0x33);
        link.service().unwrap();
        incoming(&model, &data(false), Some((1, 0, 2)), false);
        link.service().unwrap();
        assert!(link.carrier());
        assert_eq!(link.queues().data_frames, 1);
        assert_eq!(link.queues().notices, 1);
        model.queues[&0xd4520].lock().unwrap().fail_publish = true;
        incoming(&model, &data(false), Some((1, 0, 3)), false);
        assert!(link.service().is_err());
        assert_eq!(
            link.state().client.client.state().controller.phase(),
            ControllerPhase::Quarantined
        );
        // The historical Station association is still retained for teardown;
        // actual controller failure independently closes carrier and held data.
        assert_eq!(link.station().phase(), station::Phase::Associated);
        assert!(!link.carrier());
        assert_eq!(link.queues().data_frames, 0);
        assert_eq!(link.queues().notices, 1);
        drop(link);
        assert_eq!(provider.load(Ordering::Relaxed), 0);
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
        assert!(!model.memory.lock().unwrap().mappings.is_empty());
    }
    #[test]
    fn malformed_rx_cannot_starve_real_authentication_timeout_and_packet_retirement() {
        let (mut link, model, join, bss, provider) = setup_link();
        scan_join(&mut link, &model, join, bss);
        assert_eq!(finish_tx(&model)[0][..2], [0xb0, 0]);
        // Use the retained calibrated clock and real elapsed time; no ordinal
        // fixture timestamp or copied timer completion advances this exchange.
        std::thread::sleep(std::time::Duration::from_millis(550));
        incoming(&model, &response(0xb1, &[0, 0, 2, 0, 0, 0]), None, false);
        assert!(link.service().is_err());
        assert_eq!(link.phase(), Phase::Joining);
        // The rejected protocol-version frame did not prevent a real timed
        // retry, fresh source ROC grant, or the first packet's actual release.
        assert_eq!(finish_tx(&model)[0][..2], [0xb0, 0]);
        assert!(link.queues().notices > 0);
        link.service().unwrap();
        stop(&mut link, &model);
        drop(link);
        assert_eq!(provider.load(Ordering::Relaxed), 1);
        assert_eq!(model.drops.load(Ordering::Relaxed), 1);
    }
}
