// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! Actual firmware/DMA peers with a retained simulated OS PMF service.
//! These controls supply no physical-radio or production OS qualification.
use super::*;
use crate::net::wifi::mediatek::bootstrap::client::management::{Session, Transmit};
use crate::net::wifi::security::PacketNumber;

type Native = Client<Bar, Q, NativeGuard>;
struct Protection {
    selected: Cell<bool>,
    authenticated: Cell<bool>,
    port: Cell<bool>,
    uses: RefCell<Vec<AssociationUse>>,
}
struct PmfState {
    hardware: Cell<bool>,
    os: Cell<bool>,
    revision: Cell<u64>,
    auth_hardware: Cell<bool>,
    native: reg::NativeContext,
    context: RefCell<Option<Arc<station::AssociationContext>>>,
    observation: Arc<station::NativeBssObservation>,
    selected: Join,
    response: Arc<Mutex<Response>>,
    _memory: Arc<Mutex<Memory>>,
    tickets: RefCell<Vec<station::Ticket>>,
    windows: RefCell<Vec<(usize, usize)>>,
}
struct ProtectedHardware(Rc<PmfState>);
struct ProtectedOs {
    state: Rc<PmfState>,
    protection: Rc<Protection>,
}
struct ProtectedHardwareGuard {
    state: Rc<PmfState>,
    start: usize,
}
struct ProtectedGuard {
    state: Rc<PmfState>,
    protection: Rc<Protection>,
}
impl Drop for ProtectedHardwareGuard {
    fn drop(&mut self) {
        assert!(!self.state.os.get());
        let end = self.state.response.lock().unwrap().client_commands.len();
        self.state.windows.borrow_mut().push((self.start, end));
        self.state.hardware.set(false);
    }
}
impl Drop for ProtectedGuard {
    fn drop(&mut self) {
        assert!(self.state.hardware.get());
        self.state.os.set(false);
    }
}
fn authentication(state: &PmfState, operation: &reg::PmfAuthenticationOperation<'_>) -> bool {
    assert!(state.hardware.get() && state.os.get());
    assert!(Arc::ptr_eq(operation.observation(), &state.observation));
    let join = operation.join();
    state.tickets.borrow_mut().push(operation.ticket());
    if let Some(bytes) = operation.transmit() {
        assert_eq!(&bytes[4..10], &AP.0);
        assert!(matches!(
            u16::from_le_bytes(bytes[..2].try_into().unwrap()),
            0 | 0xb0
        ));
        if bytes[0] == 0 {
            assert!(
                bytes
                    .windows(selected_rsn().len())
                    .any(|v| v == selected_rsn())
            );
        }
    }
    join.bssid == state.selected.bssid
        && join.channel == state.selected.channel
        && join.policy == state.selected.policy
        && join.request.elements() == state.selected.request.elements()
        && join.request.capabilities() == state.selected.request.capabilities()
        && join.request.listen_interval() == state.selected.request.listen_interval()
}
fn current(state: &PmfState, operation: &reg::AssociationOperation<'_>) -> bool {
    assert!(state.hardware.get() && state.os.get());
    let context = state.context.borrow();
    context
        .as_ref()
        .is_some_and(|context| core::ptr::eq(operation.context(), context.as_ref()))
        && operation
            .context()
            .pmf_observation()
            .is_some_and(|source| Arc::ptr_eq(source, &state.observation))
}
impl reg::HardwareLease for ProtectedHardwareGuard {
    fn context(&self) -> reg::NativeContext {
        self.state.native
    }
    fn lookup_channel(&mut self, band: Band, number: u16) -> Option<wifi::Channel> {
        (band == CHANNEL.band && number == CHANNEL.number).then_some(CHANNEL)
    }
    fn allows(&mut self, _: reg::Operation) -> bool {
        false
    }
    fn allows_pmf_authentication(
        &mut self,
        operation: &reg::PmfAuthenticationOperation<'_>,
    ) -> bool {
        authentication(&self.state, operation) && self.state.auth_hardware.get()
    }
    fn allows_association(&mut self, operation: &reg::AssociationOperation<'_>) -> bool {
        let response = self.state.response.lock().unwrap();
        current(&self.state, operation)
            && response.regulatory_domain
            && !response.regulatory_power.is_empty()
            && operation
                .context()
                .negotiated()
                .local()
                .local_he_source_maps()
                .is_some()
    }
}
impl reg::OsLease for ProtectedGuard {
    fn revision(&self) -> u64 {
        self.state.revision.get()
    }
    fn allows(&mut self, _: reg::Operation) -> bool {
        false
    }
    fn allows_pmf_authentication(
        &mut self,
        operation: &reg::PmfAuthenticationOperation<'_>,
    ) -> bool {
        authentication(&self.state, operation) && self.protection.selected.get()
    }
    fn allows_association(&mut self, operation: &reg::AssociationOperation<'_>) -> bool {
        current(&self.state, operation)
    }
    fn allows_protected_management(&mut self, operation: &reg::AssociationOperation<'_>) -> bool {
        assert!(current(&self.state, operation));
        assert_eq!(operation.context().pmf().unwrap().rsn(), selected_rsn());
        self.protection.uses.borrow_mut().push(operation.purpose());
        self.protection.selected.get()
            && match operation.purpose() {
                AssociationUse::Configure
                | AssociationUse::Receive
                | AssociationUse::Authentication => true,
                AssociationUse::Management
                | AssociationUse::Data
                | AssociationUse::ChannelSwitch => self.protection.authenticated.get(),
            }
    }
    fn allows_protected_port(&mut self, operation: &reg::AssociationOperation<'_>) -> bool {
        assert!(current(&self.state, operation));
        assert_eq!(operation.purpose(), AssociationUse::Management);
        self.protection.authenticated.get() && self.protection.port.get()
    }
}
// SAFETY: actual single-threaded model requester and retained native resources;
// revocation obeys the hardware→OS guard order. This grants no physical access.
unsafe impl reg::HardwarePolicy for ProtectedHardware {
    type Lease<'a> = ProtectedHardwareGuard;
    fn acquire(&mut self) -> Option<Self::Lease<'_>> {
        assert!(!self.0.os.get());
        if self.0.hardware.replace(true) {
            return None;
        }
        let start = self.0.response.lock().unwrap().client_commands.len();
        Some(ProtectedHardwareGuard {
            state: self.0.clone(),
            start,
        })
    }
}
// SAFETY: a single retained modeled OS owns this original native observation,
// actual selected request and subsequent real current context through both phases.
unsafe impl reg::OsPolicy for ProtectedOs {
    type Lease<'a> = ProtectedGuard;
    fn acquire(&mut self, native: reg::NativeContext) -> Option<Self::Lease<'_>> {
        assert!(self.state.hardware.get());
        if native != self.state.native || self.state.os.replace(true) {
            return None;
        }
        Some(ProtectedGuard {
            state: self.state.clone(),
            protection: self.protection.clone(),
        })
    }
}
type ProtectedOwner = reg::Owner<ProtectedHardware, ProtectedOs>;
fn authority_pmf(
    observed: Arc<station::NativeBssObservation>,
    join: &Join,
    model: &Model,
) -> (ProtectedOwner, Rc<PmfState>, Rc<Protection>) {
    let state = Rc::new(PmfState {
        hardware: Cell::new(false),
        os: Cell::new(false),
        revision: Cell::new(1),
        auth_hardware: Cell::new(true),
        native: reg::NativeContext {
            device: Arc::as_ptr(&model.memory) as usize as u64,
            reset_epoch: 1,
            firmware_epoch: 1,
            policy_revision: 1,
        },
        context: RefCell::new(None),
        observation: observed,
        selected: join.clone(),
        response: model.response.clone(),
        _memory: model.memory.clone(),
        tickets: RefCell::new(Vec::new()),
        windows: RefCell::new(Vec::new()),
    });
    let protection = Rc::new(Protection {
        selected: Cell::new(true),
        authenticated: Cell::new(false),
        port: Cell::new(false),
        uses: RefCell::new(Vec::new()),
    });
    let owner = reg::Owner::new(
        ProtectedHardware(state.clone()),
        ProtectedOs {
            state: state.clone(),
            protection: protection.clone(),
        },
    )
    .unwrap();
    (owner, state, protection)
}
struct PmfSource(Rc<PmfState>);
impl crate::bus::dma::memory::PageSource for PmfSource {
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: crate::bus::dma::memory::CacheAttribute,
    ) -> Result<crate::bus::dma::memory::PinnedPages, crate::bus::dma::memory::MemoryError> {
        assert!(self.0.hardware.get() && self.0.os.get());
        crate::bus::dma::memory::PageSource::allocate(&Source, bytes, alignment, attribute)
    }
}
fn permit(
    owner: &mut ProtectedOwner,
    driver: &Native,
    purpose: AssociationUse,
) -> reg::AssociationAdmission {
    owner
        .admit_association(
            driver.station(),
            driver.modern_context().unwrap().clone(),
            purpose,
        )
        .unwrap()
}
fn selected_rsn() -> Vec<u8> {
    rsn(2)
}
fn rsn(akm: u8) -> Vec<u8> {
    vec![
        1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, akm, 0xc0, 0, 0, 0, 0, 15, 172,
        6,
    ]
}
fn replace_rsn(elements: &[u8], rsn: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = elements;
    while !rest.is_empty() {
        let len = usize::from(rest[1]);
        if rest[0] == 48 {
            append_ie(&mut out, 48, rsn);
        } else {
            out.extend_from_slice(&rest[..2 + len]);
        }
        rest = &rest[2 + len..];
    }
    out
}
pub(in crate::net::wifi::mediatek::bootstrap::client) fn inputs(
    driver: &Native,
) -> (Join, scan::result::Bss) {
    inputs_akm(driver, 2)
}
/// `inputs` for another AKM, such as SAE's 8.
pub(in crate::net::wifi::mediatek::bootstrap::client) fn inputs_akm(
    driver: &Native,
    akm: u8,
) -> (Join, scan::result::Bss) {
    let (mut join, mut bss) = modern_inputs(driver);
    let local = driver.local_advertisement(Band::Ghz5).unwrap();
    join.request = AssociationRequest::new_modern_with_local_pmf(
        0x11,
        10,
        replace_rsn(join.request.elements(), &rsn(akm)),
        local.capabilities().clone(),
        Mode::Eht,
        Width::Mhz80,
    )
    .unwrap();
    bss.elements = replace_rsn(&bss.elements, &rsn(akm));
    (join, bss)
}
fn observe(
    driver: &mut Native,
    model: &Model,
    bss: &scan::result::Bss,
) -> Arc<station::NativeBssObservation> {
    observe_at(driver, model, bss, 0)
}
fn observe_at(
    driver: &mut Native,
    model: &Model,
    bss: &scan::result::Bss,
    start: u64,
) -> Arc<station::NativeBssObservation> {
    driver
        .begin_scan(
            scan::Request::new(vec![CHANNEL], vec![], vec![]).unwrap(),
            start,
            1_000_000,
            &mut Policy(true),
        )
        .unwrap();
    let mut body = bss.timestamp.to_le_bytes().to_vec();
    body.extend_from_slice(&bss.beacon_interval.to_le_bytes());
    body.extend_from_slice(&bss.capabilities.to_le_bytes());
    body.extend_from_slice(&bss.elements);
    let mut beacon = response(0x80, &body);
    beacon[4..10].fill(255);
    incoming(model, &beacon, None, false);
    let events = driver.poll(start + 1, &Source, &mut Policy(true)).unwrap();
    assert!(matches!(events.as_slice(), [Event::Bss(_)]));
    let observed = driver.pmf_bss_observations().next().unwrap().clone();
    let mut done = vec![0; 52];
    done[..4].copy_from_slice(&(7u32 << 27).to_le_bytes());
    done[36] = 14;
    done[38] = 6;
    done[50] = 4;
    device_receive(&model.queues[&0xd4500], &done, true, 0);
    driver.poll(start + 2, &Source, &mut Policy(true)).unwrap();
    // SAFETY: actual modeled scan terminal event and all model RX/IRQ users drained.
    unsafe { driver.retire_scan_after_drain() }.unwrap();
    observed
}
fn preparing() -> (
    Native,
    Model,
    Join,
    Arc<station::NativeBssObservation>,
    ProtectedOwner,
    Rc<PmfState>,
    Rc<Protection>,
) {
    let (mut driver, model) = setup();
    let (join, bss) = inputs(&driver);
    let observed = observe(&mut driver, &model, &bss);
    let (owner, state, protection) = authority_pmf(observed.clone(), &join, &model);
    (driver, model, join, observed, owner, state, protection)
}

type Awaiting = (
    Native,
    Model,
    usize,
    ProtectedOwner,
    Rc<PmfState>,
    Rc<Protection>,
);
fn awaiting_pmf() -> Awaiting {
    awaiting_with(|_, _, _| {}).unwrap()
}
fn awaiting_with(
    alter: impl FnOnce(&mut Join, &mut scan::result::Bss, &mut Vec<u8>),
) -> Result<Awaiting, ClientError> {
    let (mut driver, model) = setup();
    let (mut join, mut bss) = inputs(&driver);
    let mut response_elements = bss.elements.clone();
    alter(&mut join, &mut bss, &mut response_elements);
    let observed = observe(&mut driver, &model, &bss);
    let (mut owner, state, protection) = authority_pmf(observed.clone(), &join, &model);
    // SAFETY: original actual native scan and this same retained modeled OS selection.
    unsafe {
        driver.join_modern_pmf(
            &mut owner,
            join,
            &observed,
            profile(),
            100,
            &PmfSource(state.clone()),
            &mut Policy(true),
        )
    }?;
    finish_tx(&model);
    unsafe {
        driver.poll_pmf_authentication(
            &mut owner,
            101,
            &PmfSource(state.clone()),
            &mut Policy(true),
        )
    }
    .unwrap();
    driver.poll_released().unwrap();
    incoming(&model, &response(0xb0, &[0, 0, 2, 0, 0, 0]), None, false);
    unsafe {
        driver.poll_pmf_authentication(
            &mut owner,
            102,
            &PmfSource(state.clone()),
            &mut Policy(true),
        )
    }
    .unwrap();
    let assoc = finish_tx(&model);
    assert!(
        assoc[0]
            .windows(selected_rsn().len())
            .any(|v| v == selected_rsn())
    );
    unsafe {
        driver.poll_pmf_authentication(
            &mut owner,
            103,
            &PmfSource(state.clone()),
            &mut Policy(true),
        )
    }
    .unwrap();
    driver.poll_released().unwrap();
    let before = model.response.lock().unwrap().client_commands.len();
    let mut body = vec![0x11, 0, 0, 0, 1, 0xc0];
    body.extend_from_slice(&response_elements);
    incoming(&model, &response(0x10, &body), None, false);
    unsafe {
        driver.poll_pmf_authentication(
            &mut owner,
            104,
            &PmfSource(state.clone()),
            &mut Policy(true),
        )
    }?;
    let context = driver.modern_context().unwrap().clone();
    assert!(Arc::ptr_eq(context.pmf_observation().unwrap(), &observed));
    *state.context.borrow_mut() = Some(context);
    Ok((driver, model, before, owner, state, protection))
}

fn poll(
    driver: &mut Native,
    owner: &mut ProtectedOwner,
    state: &Rc<PmfState>,
    now: u64,
) -> Result<Vec<Event>, ClientError> {
    let admission = permit(owner, driver, AssociationUse::Receive);
    // SAFETY: exact modeled owner, original context and both real model guards.
    unsafe {
        driver.poll_pmf(
            owner,
            admission,
            now,
            &PmfSource(state.clone()),
            &mut Policy(true),
        )
    }
}
fn configured() -> (Native, Model, ProtectedOwner, Rc<PmfState>, Rc<Protection>) {
    let (mut driver, model, before, mut owner, state, protection) = awaiting_pmf();
    // wpa_supplicant registers for its SA Query responses.
    driver.register_action(&[8, 1]).unwrap();
    let admission = permit(&mut owner, &driver, AssociationUse::Configure);
    // SAFETY: original actual modeled requester and explicitly selected OS policy.
    unsafe { driver.configure_modern(&mut owner, admission, 105) }.unwrap();
    assert_eq!(driver.completed_modern_requests(), 7);
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        before + 7
    );
    assert!(!protection.authenticated.get());
    (driver, model, owner, state, protection)
}
fn attach(driver: &mut Native, owner: &mut ProtectedOwner) -> Arc<Session> {
    for (pairwise, index, material) in [(true, 0, 1), (false, 2, 0x44)] {
        let admission = permit(owner, driver, AssociationUse::Management);
        // SAFETY: this model OS supplied its actual authenticated key exchange.
        unsafe {
            driver.install_key_modern(
                owner,
                admission,
                pairwise,
                index,
                &[material; 16],
                ReplaySeed::ZERO,
            )
        }
        .unwrap();
    }
    let admission = permit(owner, driver, AssociationUse::Management);
    let epoch = driver.station().association_epoch().unwrap();
    // SAFETY: actual model queues and external deferred/IRQ/key users are drained.
    unsafe {
        driver.install_management_key_modern(
            owner,
            admission,
            epoch,
            4,
            &[0x55; 16],
            PacketNumber::new(100).unwrap(),
        )
    }
    .unwrap()
}

#[test]
fn actual_pmf_admission_is_explicit_and_legacy_country_authority_fails_closed() {
    let (mut driver, model, before, mut owner, state, protection) = awaiting_pmf();
    let (mut ordinary, _) = authority(&driver, &model);
    assert!(matches!(
        ordinary.admit_association(
            driver.station(),
            driver.modern_context().unwrap().clone(),
            AssociationUse::Configure
        ),
        Err(reg::Error::OsDenied)
    ));
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    let admission = permit(&mut owner, &driver, AssociationUse::Configure);
    protection.selected.set(false);
    assert!(unsafe { driver.configure_modern(&mut owner, admission, 105) }.is_err());
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    assert!(!state.hardware.get() && !state.os.get());
    protection.selected.set(true);
    let admission = permit(&mut owner, &driver, AssociationUse::Configure);
    unsafe { driver.configure_modern(&mut owner, admission, 105) }.unwrap();
    assert_eq!(driver.completed_modern_requests(), 7);
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        before + 7
    );
    assert!(
        protection
            .uses
            .borrow()
            .contains(&AssociationUse::Configure)
    );
}

#[test]
fn actual_prekey_eapol_has_distinct_guarded_transport_and_no_robust_fallback() {
    let (mut driver, model, mut owner, state, protection) = configured();
    let epoch = driver.station().association_epoch().unwrap();
    let admission = permit(&mut owner, &driver, AssociationUse::Authentication);
    let mut frame = eth(0x888e);
    frame[..6].copy_from_slice(&AP.0);
    // SAFETY: only this genuine model OS's EAPOL control-port transport is granted.
    unsafe {
        driver.transmit_modern(
            &mut owner,
            admission,
            epoch,
            &frame,
            TxClass::ControlPortPlaintext,
            None,
            &PmfSource(state.clone()),
            &mut Policy(true),
        )
    }
    .unwrap();
    let sent = finish_tx(&model);
    assert_eq!(sent.len(), 1);
    assert_eq!(&sent[0][24..32], &[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]);
    assert_eq!(
        u16::from_le_bytes(sent[0][..2].try_into().unwrap()) & 0x4000,
        0
    );
    poll(&mut driver, &mut owner, &state, 106).unwrap();
    driver.poll_released().unwrap();
    let eapol = response(0x0208, &[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e, 1, 2, 3]);
    // A plaintext data descriptor still needs the actual configured peer WCID.
    // Retain the original WCID0 input as a hostile profile mismatch first.
    let mut raw = incoming_bytes(&eapol, None, false);
    device_receive(&model.queues[&0xd4520], &raw, true, 0);
    assert!(matches!(
        poll(&mut driver, &mut owner, &state, 107),
        Err(ClientError::WrongProfile)
    ));
    assert!(!protection.authenticated.get());
    assert!(!driver.station().port_open(None, None));
    let peer = driver.state().profile.unwrap().wcid;
    let original = raw.clone();
    let descriptor = u32::from_le_bytes(raw[4..8].try_into().unwrap());
    raw[4..8].copy_from_slice(&((descriptor & !0xfff) | u32::from(peer)).to_le_bytes());
    assert_eq!(&raw[..4], &original[..4]);
    assert_eq!(&raw[8..], &original[8..]);
    assert_eq!(
        u32::from_le_bytes(raw[4..8].try_into().unwrap()) & !0xfff,
        descriptor & !0xfff
    );
    device_receive(&model.queues[&0xd4520], &raw, true, 0);
    let events = poll(&mut driver, &mut owner, &state, 107).unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        Event::Ingress(station::data::Ingress::ControlPort { .. })
    )));
    assert!(!protection.authenticated.get());
    assert!(
        owner
            .admit_association(
                driver.station(),
                driver.modern_context().unwrap().clone(),
                AssociationUse::Data
            )
            .is_err()
    );
    assert!(driver.authorize_port(epoch).is_err());
    assert!(driver.begin_tx_block_ack(6, 0, 108).is_err());
    assert!(driver.poll(108, &Source, &mut Policy(true)).is_err());
    // ieee80211_drop_unencrypted_mgmt drops a robust action before keys,
    // but permits a departure during the 4-way handshake.
    let commands = model.response.lock().unwrap().client_commands.len();
    incoming(&model, &response(0xd0, &[3, 2, 0, 0, 37, 0]), None, false);
    assert!(
        poll(&mut driver, &mut owner, &state, 108)
            .unwrap()
            .is_empty()
    );
    assert_eq!(driver.station().phase(), station::Phase::Associated);
    assert!(driver.station().block_ack_idle());
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        commands
    );
    incoming(&model, &response(0xc0, &[7, 0]), None, false);
    poll(&mut driver, &mut owner, &state, 109).unwrap();
    assert_eq!(driver.station().phase(), station::Phase::Disconnecting);
}

#[test]
fn actual_pmf_port_requires_current_all_key_acks_and_independent_os_handshake() {
    let (mut driver, model, mut owner, state, protection) = configured();
    protection.authenticated.set(true);
    let session = attach(&mut driver, &mut owner);
    let epoch = driver.station().association_epoch().unwrap();
    assert!(driver.authorize_port(epoch).is_err());
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    assert!(unsafe { driver.authorize_port_pmf(&mut owner, admission, &session) }.is_err());
    protection.port.set(true);
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    unsafe { driver.authorize_port_pmf(&mut owner, admission, &session) }.unwrap();
    assert!(driver.station().port_open(
        Some(driver.state().ptk.as_ref().unwrap().slot()),
        Some(driver.state().gtk.as_ref().unwrap().slot())
    ));
    assert_eq!(
        model.response.lock().unwrap().keys[&19],
        [vec![0x44; 16], vec![0x55; 16]].concat()
    );
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    let before = model.response.lock().unwrap().client_commands.len();
    // Revocation after preflight cannot inherit the earlier protected-port grant.
    protection.port.set(false);
    assert!(unsafe { driver.authorize_port_pmf(&mut owner, admission, &session) }.is_err());
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    // Open cached PTK/GTK permission cannot bypass fresh authenticated Data policy.
    let admission = permit(&mut owner, &driver, AssociationUse::Receive);
    protection.authenticated.set(false);
    incoming(&model, &data(false), Some((1, 0, 1)), false);
    assert!(
        unsafe {
            driver.poll_pmf(
                &mut owner,
                admission,
                110,
                &PmfSource(state.clone()),
                &mut Policy(true),
            )
        }
        .is_err()
    );
    assert!(!state.hardware.get() && !state.os.get());
    protection.authenticated.set(true);
    let events = poll(&mut driver, &mut owner, &state, 111).unwrap();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::Ingress(station::data::Ingress::Data(_))))
    );
    // Once keyed, an unprotected departure is reported and dropped, as is a
    // group one without an MMIE.
    let mut group = response(0xc0, &[7, 0]);
    group[4..10].fill(255);
    for frame in [response(0xc0, &[7, 0]), group] {
        incoming(&model, &frame, None, false);
        let events = poll(&mut driver, &mut owner, &state, 112).unwrap();
        assert!(matches!(
            events.as_slice(),
            [Event::UnprotectedDeparture(_)]
        ));
        assert_eq!(driver.station().phase(), station::Phase::Associated);
    }
    // An authenticated SA Query response is the OS's. Its delayed effect must
    // reacquire current OS guards.
    incoming(
        &model,
        &response(0x40d0, &[8, 1, 3, 4]),
        Some((1, 0, 2)),
        false,
    );
    let mut events = poll(&mut driver, &mut owner, &state, 112).unwrap();
    let Event::ProtectedManagement(received) = events.pop().unwrap() else {
        panic!("authenticated PMF envelope")
    };
    assert_eq!(driver.station().phase(), station::Phase::Associated);
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    let value = unsafe {
        driver.with_management_modern(&mut owner, admission, received, |_, body, _| {
            assert!(state.hardware.get() && state.os.get());
            body.to_vec()
        })
    }
    .unwrap();
    assert_eq!(value, [8, 1, 3, 4]);
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    unsafe {
        driver.transmit_management_modern(
            &mut owner,
            admission,
            &session,
            Transmit::SaQueryRequest([3, 4]),
            &PmfSource(state.clone()),
        )
    }
    .unwrap();
    let sent = finish_tx(&model);
    assert_eq!(sent.len(), 1);
    assert_eq!(
        u16::from_le_bytes(sent[0][..2].try_into().unwrap()) & 0x4000,
        0x4000
    );
    assert_eq!(&sent[0][24..], &[8, 0, 3, 4]);
    poll(&mut driver, &mut owner, &state, 113).unwrap();
    driver.poll_released().unwrap();
    // ieee80211_rx_mgmt_deauth: the AP's authenticated departure ends the
    // association, and the OS sees it.
    incoming(&model, &response(0x40c0, &[7, 0]), Some((1, 0, 3)), false);
    let events = poll(&mut driver, &mut owner, &state, 114).unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        Event::ProtectedManagement(rx) if rx.body() == [7, 0]
    )));
    assert_eq!(driver.station().phase(), station::Phase::Disconnecting);
}

#[test]
fn pmf_constructor_is_explicit_and_actual_ap_response_cannot_change_selected_rsn() {
    let (driver, _) = setup();
    for band in [Band::Ghz2, Band::Ghz5] {
        let local = driver.local_advertisement(band).unwrap();
        let mut bytes = vec![0, 1, b'x'];
        bytes.extend_from_slice(local.elements());
        append_ie(&mut bytes, 48, &selected_rsn());
        assert!(
            AssociationRequest::new_modern_with_local(
                0x11,
                10,
                bytes.clone(),
                local.capabilities().clone(),
                Mode::Ht,
                Width::Mhz20
            )
            .is_err()
        );
        let selected = AssociationRequest::new_modern_with_local_pmf(
            0x11,
            10,
            bytes.clone(),
            local.capabilities().clone(),
            Mode::Ht,
            Width::Mhz20,
        )
        .unwrap();
        assert_eq!(selected.pmf().unwrap().rsn(), selected_rsn());
        assert_eq!(selected.elements(), bytes);
        // wpa_supplicant's RSNX (H2E, SAE-PK) travels with the request.
        append_ie(&mut bytes, 244, &[0x20]);
        let extended = AssociationRequest::new_modern_with_local_pmf(
            0x11,
            10,
            bytes.clone(),
            local.capabilities().clone(),
            Mode::Ht,
            Width::Mhz20,
        )
        .unwrap();
        assert_eq!(extended.elements(), bytes);
    }
    for case in 0..4 {
        assert!(
            awaiting_with(|_, bss, response| {
                let mut bad = selected_rsn();
                match case {
                    0 => {
                        bad[17] = 8;
                        bss.elements = replace_rsn(&bss.elements, &bad);
                    }
                    1 => append_ie(&mut bss.elements, 48, &bad),
                    2 => {
                        bad[18] = 0x80;
                        *response = replace_rsn(response, &bad);
                    }
                    _ => append_ie(response, 48, &bad),
                }
            })
            .is_err()
        );
    }
}

#[test]
fn actual_pmf_configuration_and_igtk_failure_never_open_port_or_release_dma() {
    for dropped in [false, true] {
        let (mut driver, model, before, mut owner, state, _) = awaiting_pmf();
        let context = driver.modern_context().unwrap().clone();
        let admission = permit(&mut owner, &driver, AssociationUse::Configure);
        if dropped {
            model.response.lock().unwrap().drop = true;
        } else {
            model.response.lock().unwrap().bss_status = 9;
        }
        assert!(unsafe { driver.configure_modern(&mut owner, admission, 105) }.is_err());
        assert_eq!(driver.phase(), ClientPhase::Quarantined);
        assert_eq!(driver.completed_modern_requests(), 0);
        assert!(Arc::ptr_eq(driver.modern_context().unwrap(), &context));
        assert_eq!(
            model.response.lock().unwrap().client_commands.len(),
            before + 1
        );
        assert!(!driver.station().port_open(None, None));
        drop(driver);
        drop(owner);
        drop(state);
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
        assert!(!model.memory.lock().unwrap().mappings.is_empty());
    }
    for dropped in [false, true] {
        let (mut driver, model, mut owner, state, protection) = configured();
        protection.authenticated.set(true);
        for (pairwise, index, material) in [(true, 0, 1), (false, 2, 0x44)] {
            let admission = permit(&mut owner, &driver, AssociationUse::Management);
            unsafe {
                driver.install_key_modern(
                    &mut owner,
                    admission,
                    pairwise,
                    index,
                    &[material; 16],
                    ReplaySeed::ZERO,
                )
            }
            .unwrap();
        }
        let admission = permit(&mut owner, &driver, AssociationUse::Management);
        let epoch = driver.station().association_epoch().unwrap();
        if dropped {
            model.response.lock().unwrap().drop = true;
        } else {
            model.response.lock().unwrap().status = 9;
        }
        assert!(
            unsafe {
                driver.install_management_key_modern(
                    &mut owner,
                    admission,
                    epoch,
                    4,
                    &[0x55; 16],
                    PacketNumber::new(100).unwrap(),
                )
            }
            .is_err()
        );
        assert_eq!(driver.phase(), ClientPhase::Quarantined);
        assert!(driver.state().management.is_none());
        assert!(!driver.station().port_open(
            Some(driver.state().ptk.as_ref().unwrap().slot()),
            Some(driver.state().gtk.as_ref().unwrap().slot())
        ));
        drop(driver);
        drop(owner);
        drop(state);
        drop(protection);
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
        assert!(!model.memory.lock().unwrap().mappings.is_empty());
    }
}

#[test]
fn actual_pmf_igtk_rotation_revokes_old_session_and_preserves_current_data_keys() {
    let (mut driver, model, mut owner, state, protection) = configured();
    protection.authenticated.set(true);
    protection.port.set(true);
    let first = attach(&mut driver, &mut owner);
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    unsafe { driver.authorize_port_pmf(&mut owner, admission, &first) }.unwrap();
    incoming(
        &model,
        &response(0x40d0, &[8, 1, 3, 4]),
        Some((1, 0, 9)),
        false,
    );
    let mut events = poll(&mut driver, &mut owner, &state, 110).unwrap();
    let Event::ProtectedManagement(delayed) = events.pop().unwrap() else {
        panic!("original authenticated envelope")
    };
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    // SAFETY: same modeled OS exchange, old slot peer-retired, actual users drained.
    let second = unsafe {
        driver.rotate_management_key_modern(
            &mut owner,
            admission,
            &first,
            5,
            &[0x66; 16],
            PacketNumber::new(200).unwrap(),
        )
    }
    .unwrap();
    assert!(!Arc::ptr_eq(&first, &second));
    assert_eq!(first.pairwise_key(), second.pairwise_key());
    assert_eq!(first.group_key(), second.group_key());
    assert!(driver.station().port_open(
        Some(driver.state().ptk.as_ref().unwrap().slot()),
        Some(driver.state().gtk.as_ref().unwrap().slot())
    ));
    let before = model.bar.0.lock().unwrap().log.len();
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    assert!(unsafe { driver.authorize_port_pmf(&mut owner, admission, &first) }.is_err());
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    assert!(
        unsafe {
            driver.with_management_modern::<_, _, ()>(&mut owner, admission, delayed, |_, _, _| {
                panic!("retired Session must remain inert")
            })
        }
        .is_err()
    );
    assert_eq!(model.bar.0.lock().unwrap().log.len(), before);
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    unsafe { driver.authorize_port_pmf(&mut owner, admission, &second) }.unwrap();
    let admission = permit(&mut owner, &driver, AssociationUse::Data);
    let epoch = driver.station().association_epoch().unwrap();
    unsafe {
        driver.transmit_modern(
            &mut owner,
            admission,
            epoch,
            &eth(0x0800),
            TxClass::Data,
            None,
            &PmfSource(state.clone()),
            &mut Policy(true),
        )
    }
    .unwrap();
    assert_eq!(finish_tx(&model).len(), 1);
    poll(&mut driver, &mut owner, &state, 111).unwrap();
    let released = driver.poll_released().unwrap();
    assert_eq!(released.len(), 1);
    assert!(Arc::ptr_eq(
        released[0].context.management_session().unwrap(),
        &second
    ));
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    driver.disconnect().unwrap();
    assert!(unsafe { driver.authorize_port_pmf(&mut owner, admission, &second) }.is_err());
}

#[test]
fn actual_pmf_protected_block_ack_uses_current_session_and_real_firmware_ack() {
    let (mut driver, model, mut owner, state, protection) = configured();
    protection.authenticated.set(true);
    let session = attach(&mut driver, &mut owner);
    assert!(driver.begin_tx_block_ack(6, 0, frontend_tick(110)).is_err());
    let mut request = vec![3, 0, 7];
    request.extend_from_slice(&(3u16 | (6 << 2) | (8 << 6)).to_le_bytes());
    request.extend_from_slice(&0u16.to_le_bytes());
    request.extend_from_slice(&(17u16 << 4).to_le_bytes());
    incoming(
        &model,
        &response(0x40d0, &request),
        Some((1, 0, 101)),
        false,
    );
    let mut events = poll(&mut driver, &mut owner, &state, frontend_tick(111)).unwrap();
    let Event::ProtectedManagement(original) = events.pop().unwrap() else {
        panic!("protected BA observation")
    };
    let mut received = Some(original);
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    unsafe {
        driver.receive_management_block_ack(
            &mut owner,
            admission,
            &mut received,
            frontend_tick(112),
        )
    }
    .unwrap();
    assert!(received.is_none());
    assert!(driver.station().active_rx_block_ack(6).is_none());
    for now in [frontend_tick(113), frontend_tick(114)] {
        let admission = permit(&mut owner, &driver, AssociationUse::Management);
        unsafe { driver.progress_block_ack(&mut owner, admission, &PmfSource(state.clone()), now) }
            .unwrap();
    }
    assert!(driver.station().active_rx_block_ack(6).is_some());
    assert!(
        model
            .response
            .lock()
            .unwrap()
            .receive_ba
            .contains_key(&(1, 6))
    );
    let sent = finish_tx(&model);
    assert_eq!(sent.len(), 1);
    assert_eq!(
        u16::from_le_bytes(sent[0][..2].try_into().unwrap()) & 0x40fc,
        0x40d0
    );
    assert_eq!(&sent[0][24..29], &[3, 1, 7, 0, 0]);
    poll(&mut driver, &mut owner, &state, frontend_tick(115)).unwrap();
    let released = driver.poll_released().unwrap();
    assert_eq!(released.len(), 1);
    assert!(Arc::ptr_eq(
        released[0].context.management_session().unwrap(),
        &session
    ));
}

#[test]
fn actual_pmf_preassociation_denial_cancels_only_unpublished_ticket_and_retry_is_guarded() {
    for hardware in [false, true] {
        let (mut driver, model, join, observed, mut owner, state, protection) = preparing();
        let before = model.bar.0.lock().unwrap().log.len();
        let commands = model.response.lock().unwrap().client_commands.len();
        let mappings = model.memory.lock().unwrap().mappings.len();
        assert!(
            driver
                .join_modern(
                    join.clone(),
                    observed.bss().clone(),
                    profile(),
                    100,
                    &Source,
                    &mut Policy(true)
                )
                .is_err()
        );
        state.auth_hardware.set(hardware);
        protection.selected.set(!hardware);
        assert!(
            unsafe {
                driver.join_modern_pmf(
                    &mut owner,
                    join.clone(),
                    &observed,
                    profile(),
                    100,
                    &PmfSource(state.clone()),
                    &mut Policy(true),
                )
            }
            .is_err()
        );
        assert_eq!(driver.phase(), ClientPhase::Idle);
        assert_eq!(driver.station().phase(), station::Phase::Idle);
        assert_eq!(model.bar.0.lock().unwrap().log.len(), before);
        assert_eq!(
            model.response.lock().unwrap().client_commands.len(),
            commands
        );
        assert_eq!(model.memory.lock().unwrap().mappings.len(), mappings);
        assert!(driver.state().pmf_selected.is_none());
        assert!(driver.state().pmf_authentication.is_none());
        let withdrawn_epoch = state
            .tickets
            .borrow()
            .last()
            .map_or(0, |ticket| ticket.epoch());
        state.auth_hardware.set(true);
        protection.selected.set(true);
        unsafe {
            driver.join_modern_pmf(
                &mut owner,
                join,
                &observed,
                profile(),
                101,
                &PmfSource(state.clone()),
                &mut Policy(true),
            )
        }
        .unwrap();
        assert_eq!(driver.phase(), ClientPhase::Joining);
        assert!(driver.station().association_epoch().unwrap() > withdrawn_epoch);
        assert!(
            state
                .windows
                .borrow()
                .iter()
                .any(|&(start, end)| start == commands && end > start)
        );
        assert_eq!(finish_tx(&model)[0][..2], [0xb0, 0]);
        assert!(!state.hardware.get() && !state.os.get());
    }
}

#[test]
fn actual_pmf_foreign_and_old_scan_observations_cannot_mint_authentication_authority() {
    let (mut driver, model, join, old, _, _, _) = preparing();
    let (_, other_model, _, foreign, _, _, _) = preparing();
    let (mut owner, state, _) = authority_pmf(old.clone(), &join, &model);
    let before = model.bar.0.lock().unwrap().log.len();
    assert!(
        unsafe {
            driver.join_modern_pmf(
                &mut owner,
                join.clone(),
                &foreign,
                profile(),
                100,
                &PmfSource(state.clone()),
                &mut Policy(true),
            )
        }
        .is_err()
    );
    assert_eq!(model.bar.0.lock().unwrap().log.len(), before);
    assert!(state.tickets.borrow().is_empty());
    let (_, bss) = inputs(&driver);
    let fresh = observe_at(&mut driver, &model, &bss, 10);
    assert!(!Arc::ptr_eq(&old, &fresh));
    let (mut owner, state, _) = authority_pmf(fresh.clone(), &join, &model);
    let before = model.bar.0.lock().unwrap().log.len();
    assert!(
        unsafe {
            driver.join_modern_pmf(
                &mut owner,
                join.clone(),
                &old,
                profile(),
                100,
                &PmfSource(state.clone()),
                &mut Policy(true),
            )
        }
        .is_err()
    );
    assert_eq!(model.bar.0.lock().unwrap().log.len(), before);
    assert!(state.tickets.borrow().is_empty());
    unsafe {
        driver.join_modern_pmf(
            &mut owner,
            join,
            &fresh,
            profile(),
            100,
            &PmfSource(state.clone()),
            &mut Policy(true),
        )
    }
    .unwrap();
    assert_eq!(finish_tx(&model)[0][..2], [0xb0, 0]);
    assert!(!other_model.memory.lock().unwrap().mappings.is_empty());
}

#[test]
fn actual_pmf_pending_publication_cannot_inherit_revised_or_foreign_authentication_guards() {
    for revision in [false, true] {
        let (mut driver, model, join, observed, mut owner, state, protection) = preparing();
        unsafe {
            driver.join_modern_pmf(
                &mut owner,
                join.clone(),
                &observed,
                profile(),
                100,
                &PmfSource(state.clone()),
                &mut Policy(true),
            )
        }
        .unwrap();
        let commands = model.response.lock().unwrap().client_commands.len();
        let before = model.bar.0.lock().unwrap().log.len();
        let mappings = model.memory.lock().unwrap().mappings.len();
        let ticket = driver.station().pmf_authentication().unwrap().0;
        if revision {
            state.revision.set(2);
        } else {
            protection.selected.set(false);
        }
        assert!(
            unsafe {
                driver.poll_pmf_authentication(
                    &mut owner,
                    101,
                    &PmfSource(state.clone()),
                    &mut Policy(true),
                )
            }
            .is_err()
        );
        assert!(driver.poll(101, &Source, &mut Policy(true)).is_err());
        assert!(
            driver
                .poll_station(101, &Source, &mut Policy(true))
                .is_err()
        );
        let (mut foreign, foreign_state, _) = authority_pmf(observed, &join, &model);
        assert!(
            unsafe {
                driver.poll_pmf_authentication(
                    &mut foreign,
                    101,
                    &PmfSource(foreign_state),
                    &mut Policy(true),
                )
            }
            .is_err()
        );
        assert_eq!(driver.station().pmf_authentication().unwrap().0, ticket);
        assert_eq!(model.bar.0.lock().unwrap().log.len(), before);
        assert_eq!(
            model.response.lock().unwrap().client_commands.len(),
            commands
        );
        assert_eq!(model.memory.lock().unwrap().mappings.len(), mappings);
        assert!(
            driver
                .state()
                .controller
                .state()
                .data_tx
                .as_ref()
                .unwrap()
                .outstanding_tokens()
                > 0
        );
        drop(driver);
        drop(owner);
        drop(state);
        drop(protection);
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn actual_pmf_timeout_retry_and_auth_response_requalify_each_canonical_ticket() {
    let (mut driver, model, join, observed, mut owner, state, _) = preparing();
    unsafe {
        driver.join_modern_pmf(
            &mut owner,
            join,
            &observed,
            profile(),
            100,
            &PmfSource(state.clone()),
            &mut Policy(true),
        )
    }
    .unwrap();
    let first = driver.station().pmf_authentication().unwrap().0;
    finish_tx(&model);
    unsafe {
        driver.poll_pmf_authentication(
            &mut owner,
            101,
            &PmfSource(state.clone()),
            &mut Policy(true),
        )
    }
    .unwrap();
    driver.poll_released().unwrap();
    unsafe {
        driver.poll_pmf_authentication(
            &mut owner,
            500_101,
            &PmfSource(state.clone()),
            &mut Policy(true),
        )
    }
    .unwrap();
    let retried = driver.station().pmf_authentication().unwrap().0;
    assert_ne!(first, retried);
    assert_eq!(first.epoch(), retried.epoch());
    assert_eq!(finish_tx(&model)[0][..2], [0xb0, 0]);
    unsafe {
        driver.poll_pmf_authentication(
            &mut owner,
            500_102,
            &PmfSource(state.clone()),
            &mut Policy(true),
        )
    }
    .unwrap();
    driver.poll_released().unwrap();
    incoming(&model, &response(0xb0, &[0, 0, 2, 0, 0, 0]), None, false);
    unsafe {
        driver.poll_pmf_authentication(
            &mut owner,
            500_103,
            &PmfSource(state.clone()),
            &mut Policy(true),
        )
    }
    .unwrap();
    let association = driver.station().pmf_authentication().unwrap().0;
    assert_ne!(retried, association);
    assert_eq!(association.epoch(), first.epoch());
    let actual = finish_tx(&model);
    assert_eq!(actual[0][..2], [0, 0]);
    for ticket in [first, retried, association] {
        assert!(state.tickets.borrow().contains(&ticket));
    }
}
