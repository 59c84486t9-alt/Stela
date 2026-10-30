use crate::wifi::regulatory::{self as reg, AssociationUse as Use};
use crate::wifi::station::{
    phy::{Mode, Width},
    tests::*,
    *,
};
use crate::wifi::{Band, Channel};
use alloc::{rc::Rc, sync::Arc, vec::Vec};
use core::cell::{Cell, RefCell};

const NATIVE: reg::NativeContext = reg::NativeContext {
    device: 10,
    reset_epoch: 11,
    firmware_epoch: 12,
    policy_revision: 13,
};
struct Model {
    hw_held: Cell<bool>,
    os_held: Cell<bool>,
    hw_available: Cell<bool>,
    os_available: Cell<bool>,
    native: Cell<reg::NativeContext>,
    revision: Cell<u64>,
    hw_mask: Cell<u8>,
    os_mask: Cell<u8>,
    applied_power: Cell<bool>,
    channel: Cell<Channel>,
    context: Arc<AssociationContext>,
    /// An MLD association's other links, each with the channel the
    /// hardware knows it by.
    links: RefCell<Vec<(Arc<AssociationContext>, Channel)>>,
    log: RefCell<Vec<&'static str>>,
}
impl Model {
    fn knows(&self, context: &AssociationContext) -> bool {
        core::ptr::eq(context, self.context.as_ref())
            || self
                .links
                .borrow()
                .iter()
                .any(|(link, _)| core::ptr::eq(context, link.as_ref()))
    }
}
impl Model {
    fn revoke(&self) -> bool {
        if self.hw_held.get() || self.os_held.get() {
            return false;
        }
        self.hw_available.set(false);
        true
    }
}
struct Hardware(Rc<Model>);
struct Os(Rc<Model>);
struct HardwareGuard(Rc<Model>);
struct OsGuard(Rc<Model>);
fn mask(purpose: Use) -> u8 {
    match purpose {
        Use::Receive => 8,
        Use::Authentication => 16,
        Use::Configure => 1,
        Use::Management => 2,
        Use::Data => 4,
        Use::ChannelSwitch => 32,
    }
}
impl Drop for HardwareGuard {
    fn drop(&mut self) {
        assert!(!self.0.os_held.get());
        self.0.hw_held.set(false);
        self.0.log.borrow_mut().push("drop-hw");
    }
}
impl Drop for OsGuard {
    fn drop(&mut self) {
        assert!(self.0.hw_held.get());
        self.0.os_held.set(false);
        self.0.log.borrow_mut().push("drop-os");
    }
}
impl reg::HardwareLease for HardwareGuard {
    fn context(&self) -> reg::NativeContext {
        self.0.native.get()
    }
    fn lookup_channel(&mut self, band: Band, number: u16) -> Option<Channel> {
        let links = self.0.links.borrow();
        core::iter::once(self.0.channel.get())
            .chain(links.iter().map(|(_, channel)| *channel))
            .find(|c| c.band == band && c.number == number)
    }
    fn allows(&mut self, _: reg::Operation) -> bool {
        true
    }
    fn allows_association(&mut self, op: &reg::AssociationOperation<'_>) -> bool {
        assert!(self.0.hw_held.get() && self.0.os_held.get());
        self.0.knows(op.context())
            && self.0.applied_power.get()
            && self.0.hw_mask.get() & mask(op.purpose()) != 0
    }
}
impl reg::OsLease for OsGuard {
    fn revision(&self) -> u64 {
        self.0.revision.get()
    }
    fn allows(&mut self, _: reg::Operation) -> bool {
        true
    }
    fn allows_association(&mut self, op: &reg::AssociationOperation<'_>) -> bool {
        assert!(self.0.hw_held.get() && self.0.os_held.get());
        self.0.knows(op.context()) && self.0.os_mask.get() & mask(op.purpose()) != 0
    }
    fn allows_protected_management(&mut self, op: &reg::AssociationOperation<'_>) -> bool {
        self.allows_association(op)
    }
}
// SAFETY: synthetic model has no physical permission; its only modeled mutation
// and submission are serialized by the held flags and acquisition ordering.
unsafe impl reg::HardwarePolicy for Hardware {
    type Lease<'a> = HardwareGuard;
    fn acquire(&mut self) -> Option<Self::Lease<'_>> {
        assert!(!self.0.os_held.get());
        if !self.0.hw_available.get() || self.0.hw_held.replace(true) {
            return None;
        }
        self.0.log.borrow_mut().push("acquire-hw");
        Some(HardwareGuard(Rc::clone(&self.0)))
    }
}
// SAFETY: same pure model; acquire checks the native context and keeps
// the modeled OS guard strictly inside its hardware guard's lifetime.
unsafe impl reg::OsPolicy for Os {
    type Lease<'a> = OsGuard;
    fn acquire(&mut self, native: reg::NativeContext) -> Option<Self::Lease<'_>> {
        assert!(self.0.hw_held.get());
        if !self.0.os_available.get()
            || native != self.0.native.get()
            || self.0.os_held.replace(true)
        {
            return None;
        }
        self.0.log.borrow_mut().push("acquire-os");
        Some(OsGuard(Rc::clone(&self.0)))
    }
}
fn current() -> (Station, Arc<AssociationContext>) {
    let mut station = Station::new(LOCAL).unwrap();
    let j = modern_join();
    let Action::Configure {
        context: Some(c), ..
    } = configuration(&mut station, j.clone(), beacon(&j)).unwrap()
    else {
        panic!("modern context")
    };
    (station, c)
}
fn fixture() -> (
    Station,
    Arc<AssociationContext>,
    reg::Owner<Hardware, Os>,
    Rc<Model>,
) {
    let (station, c) = current();
    model(station, c)
}
fn model(
    station: Station,
    c: Arc<AssociationContext>,
) -> (
    Station,
    Arc<AssociationContext>,
    reg::Owner<Hardware, Os>,
    Rc<Model>,
) {
    let model = Rc::new(Model {
        hw_held: Cell::new(false),
        os_held: Cell::new(false),
        hw_available: Cell::new(true),
        os_available: Cell::new(true),
        native: Cell::new(NATIVE),
        revision: Cell::new(1),
        hw_mask: Cell::new(7),
        os_mask: Cell::new(7),
        applied_power: Cell::new(true),
        channel: Cell::new(c.channel()),
        context: Arc::clone(&c),
        links: RefCell::new(Vec::new()),
        log: RefCell::new(Vec::new()),
    });
    let owner = reg::Owner::new(Hardware(Rc::clone(&model)), Os(Rc::clone(&model))).unwrap();
    (station, c, owner, model)
}
fn associated(s: &mut Station, c: &AssociationContext) {
    s.complete_configuration(c.ticket(), Completion::Accepted, 3)
        .unwrap();
}

#[test]
fn a_channel_switch_is_admitted_on_its_target_and_moves_later_uses_there() {
    let (mut s, c, mut owner, m) = fixture();
    associated(&mut s, &c);
    m.hw_mask.set(7 | 32);
    m.os_mask.set(7 | 32);
    let target = operations::ChannelDefinition {
        control: Channel {
            band: Band::Ghz5,
            number: 149,
            frequency_mhz: 5745,
        },
        width: Width::Mhz20,
        center1_mhz: 5745,
        center2_mhz: None,
        punctured: 0,
    };
    assert_eq!(
        owner
            .admit_association(&s, Arc::clone(&c), Use::ChannelSwitch)
            .unwrap_err(),
        reg::Error::Mismatch
    );
    // The hardware does not offer the target yet.
    assert_eq!(
        owner
            .admit_channel_switch(&s, Arc::clone(&c), target)
            .unwrap_err(),
        reg::Error::HardwareDenied
    );
    let old = owner
        .admit_association(&s, Arc::clone(&c), Use::Management)
        .unwrap();
    m.channel.set(target.control);
    let switch = owner
        .admit_channel_switch(&s, Arc::clone(&c), target)
        .unwrap();
    // SAFETY: the pure model's same-device publication only.
    unsafe {
        owner.publish_association(switch, &s, Use::ChannelSwitch, |_, op| {
            assert_eq!(op.definition(), target);
            assert_eq!(op.context().channel().number, 36);
        })
    }
    .unwrap();
    let mut other = target;
    other.control.band = Band::Ghz2;
    assert!(s.switch_channel(&c, other).is_err());
    s.switch_channel(&c, target).unwrap();
    assert_eq!(s.operating_definition(), Some(target));
    // Uses admitted on the old channel are stale; new ones run on the new.
    // SAFETY: no model publication is permitted on a stale admission.
    assert_eq!(
        // SAFETY: the admission belongs to this test, and the callback runs synchronously on
        // this thread.
        unsafe { owner.publish_association::<()>(old, &s, Use::Management, |_, _| panic!()) }
            .unwrap_err(),
        reg::Error::Stale
    );
    let new = owner
        .admit_association(&s, Arc::clone(&c), Use::Management)
        .unwrap();
    assert_eq!(new.operation().channel(), target.control);
}

#[test]
fn same_private_context_and_whole_profile_reach_both_held_guards() {
    let (s, c, mut owner, m) = fixture();
    let admission = owner
        .admit_association(&s, Arc::clone(&c), Use::Configure)
        .unwrap();
    assert!(core::ptr::eq(admission.operation().context(), c.as_ref()));
    m.log.borrow_mut().clear();
    // SAFETY: this closure is the pure model's same-device publication only.
    let result = unsafe {
        owner.publish_association(admission, &s, Use::Configure, |guard, op| {
            assert!(guard.0.hw_held.get() && guard.0.os_held.get());
            assert!(!guard.0.revoke());
            assert!(core::ptr::eq(op.context(), c.as_ref()));
            assert_eq!(op.context().negotiated().mode, Mode::Eht);
            assert_eq!(op.context().definition().width, Width::Mhz80);
            assert!(op.context().negotiated().eht.is_some());
            assert!(op.context().negotiated().wmm.is_some());
            guard.0.log.borrow_mut().push("submit");
            Err::<(), _>("actual-command-uncertain")
        })
    }
    .unwrap();
    assert_eq!(result, Err("actual-command-uncertain"));
    assert_eq!(
        *m.log.borrow(),
        ["acquire-hw", "acquire-os", "submit", "drop-os", "drop-hw"]
    );
    assert_eq!(s.phase(), Phase::Configuring); // Closure return cannot ACK station.
    assert!(m.revoke());
}

#[test]
fn current_context_phase_and_purpose_cannot_be_substituted() {
    let (mut s, c, mut owner, _) = fixture();
    assert_eq!(
        owner
            .admit_association(&s, Arc::clone(&c), Use::Data)
            .unwrap_err(),
        reg::Error::Mismatch
    );
    let admission = owner
        .admit_association(&s, Arc::clone(&c), Use::Configure)
        .unwrap();
    assert_eq!(
        // SAFETY: no model publication is permitted on a mismatched request.
        unsafe { owner.publish_association::<()>(admission, &s, Use::Management, |_, _| panic!()) }
            .unwrap_err(),
        reg::Error::Mismatch
    );
    let admission = owner
        .admit_association(&s, Arc::clone(&c), Use::Configure)
        .unwrap();
    associated(&mut s, &c);
    assert_eq!(
        // SAFETY: a phase change must reject before the closure.
        unsafe { owner.publish_association::<()>(admission, &s, Use::Configure, |_, _| panic!()) }
            .unwrap_err(),
        reg::Error::Mismatch
    );
    assert!(
        owner
            .admit_association(&s, Arc::clone(&c), Use::Management)
            .is_ok()
    );
    assert!(
        owner
            .admit_association(&s, Arc::clone(&c), Use::Data)
            .is_ok()
    );
    let (other_station, other_context) = current();
    assert_eq!(
        owner
            .admit_association(&other_station, Arc::clone(&c), Use::Configure)
            .unwrap_err(),
        reg::Error::Stale
    );
    assert_eq!(
        owner
            .admit_association(&s, other_context, Use::Data)
            .unwrap_err(),
        reg::Error::Stale
    );
}

#[test]
fn disconnect_uncertainty_and_timeout_revoke_identity_before_publication() {
    for transition in 0..3 {
        let (mut s, c, mut owner, _) = fixture();
        let admission = owner
            .admit_association(&s, Arc::clone(&c), Use::Configure)
            .unwrap();
        match transition {
            0 => {
                s.disconnect().unwrap();
            }
            1 => {
                s.complete_configuration(c.ticket(), Completion::Uncertain, 3)
                    .unwrap();
            }
            _ => {
                assert!(matches!(
                    s.poll(600_000, &mut Policy(true)),
                    Err(Error::Timeout)
                ));
            }
        }
        assert_eq!(
            // SAFETY: stale modeled identity is rejected before native publication.
            unsafe {
                owner.publish_association::<()>(admission, &s, Use::Configure, |_, _| panic!())
            }
            .unwrap_err(),
            reg::Error::Stale
        );
    }
}

#[test]
fn owner_native_epochs_and_os_revision_never_reuse_preflight() {
    for change in 0..6 {
        let (s, c, mut owner, m) = fixture();
        let admission = owner
            .admit_association(&s, Arc::clone(&c), Use::Configure)
            .unwrap();
        let mut n = NATIVE;
        match change {
            0 => n.device += 1,
            1 => n.reset_epoch += 1,
            2 => n.firmware_epoch += 1,
            3 => n.policy_revision += 1,
            4 => m.revision.set(2),
            _ => {
                owner = reg::Owner::new(Hardware(Rc::clone(&m)), Os(Rc::clone(&m))).unwrap();
            }
        }
        m.native.set(n);
        assert_eq!(
            // SAFETY: changed permission must reject before modeled publication.
            unsafe {
                owner.publish_association::<()>(admission, &s, Use::Configure, |_, _| panic!())
            }
            .unwrap_err(),
            reg::Error::Stale
        );
        assert!(!m.hw_held.get() && !m.os_held.get());
    }
}

#[test]
fn all_context_purposes_need_independent_current_hardware_and_os_permission() {
    for hw in 0..8 {
        for os in 0..8 {
            for purpose in [Use::Configure, Use::Management, Use::Data] {
                let (mut s, c, mut owner, m) = fixture();
                if purpose != Use::Configure {
                    associated(&mut s, &c);
                }
                m.hw_mask.set(hw);
                m.os_mask.set(os);
                assert_eq!(
                    owner.admit_association(&s, Arc::clone(&c), purpose).is_ok(),
                    hw & os & mask(purpose) != 0
                );
                assert!(!m.hw_held.get() && !m.os_held.get());
            }
        }
    }
}

#[test]
fn missing_power_permission_revocation_and_exact_channel_are_rechecked() {
    for change in 0..6 {
        let (s, c, mut owner, m) = fixture();
        let admission = owner
            .admit_association(&s, Arc::clone(&c), Use::Configure)
            .unwrap();
        let expected = match change {
            0 => {
                m.hw_available.set(false);
                reg::Error::HardwareUnavailable
            }
            1 => {
                m.os_available.set(false);
                reg::Error::OsUnavailable
            }
            2 => {
                m.applied_power.set(false);
                reg::Error::HardwareDenied
            }
            3 => {
                m.hw_mask.set(0);
                reg::Error::HardwareDenied
            }
            4 => {
                m.os_mask.set(0);
                reg::Error::OsDenied
            }
            _ => {
                let mut channel = c.channel();
                channel.frequency_mhz += 1;
                m.channel.set(channel);
                reg::Error::HardwareDenied
            }
        };
        assert_eq!(
            // SAFETY: revoked modeled permission cannot execute this publication.
            unsafe {
                owner.publish_association::<()>(admission, &s, Use::Configure, |_, _| panic!())
            }
            .unwrap_err(),
            expected
        );
        assert!(!m.hw_held.get() && !m.os_held.get());
    }
}

struct LegacyHardware(Hardware);
struct LegacyHardwareGuard(HardwareGuard);
impl reg::HardwareLease for LegacyHardwareGuard {
    fn context(&self) -> reg::NativeContext {
        reg::HardwareLease::context(&self.0)
    }
    fn lookup_channel(&mut self, band: Band, number: u16) -> Option<Channel> {
        reg::HardwareLease::lookup_channel(&mut self.0, band, number)
    }
    fn allows(&mut self, op: reg::Operation) -> bool {
        reg::HardwareLease::allows(&mut self.0, op)
    }
}
// SAFETY: delegates the same bounded model's ordering/guard contract unchanged.
unsafe impl reg::HardwarePolicy for LegacyHardware {
    type Lease<'a> = LegacyHardwareGuard;
    fn acquire(&mut self) -> Option<Self::Lease<'_>> {
        reg::HardwarePolicy::acquire(&mut self.0).map(LegacyHardwareGuard)
    }
}
struct LegacyOs(Os);
struct LegacyOsGuard(OsGuard);
impl reg::OsLease for LegacyOsGuard {
    fn revision(&self) -> u64 {
        reg::OsLease::revision(&self.0)
    }
    fn allows(&mut self, op: reg::Operation) -> bool {
        reg::OsLease::allows(&mut self.0, op)
    }
}
// SAFETY: delegates the same bounded model's ordering/guard contract unchanged.
unsafe impl reg::OsPolicy for LegacyOs {
    type Lease<'a> = LegacyOsGuard;
    fn acquire(&mut self, native: reg::NativeContext) -> Option<Self::Lease<'_>> {
        reg::OsPolicy::acquire(&mut self.0, native).map(LegacyOsGuard)
    }
}
#[test]
fn legacy_permissions_never_implicitly_authorize_a_modern_context() {
    let (s, c, _, m) = fixture();
    let mut owner =
        reg::Owner::new(LegacyHardware(Hardware(Rc::clone(&m))), Os(Rc::clone(&m))).unwrap();
    assert_eq!(
        owner
            .admit_association(&s, Arc::clone(&c), Use::Configure)
            .unwrap_err(),
        reg::Error::HardwareDenied
    );
    let mut owner = reg::Owner::new(Hardware(Rc::clone(&m)), LegacyOs(Os(Rc::clone(&m)))).unwrap();
    assert_eq!(
        owner.admit_association(&s, c, Use::Configure).unwrap_err(),
        reg::Error::OsDenied
    );
}

#[test]
fn mutable_management_consumer_holds_both_original_guards_through_transition() {
    let (mut station, context, mut owner, model) = fixture();
    associated(&mut station, &context);
    let permit = owner
        .admit_association(&station, context.clone(), Use::Management)
        .unwrap();
    // SAFETY: the pure provider fixture owns this Station exclusively.
    unsafe {
        owner.consume_association(permit, &mut station, |station, operation| {
            assert!(model.hw_held.get() && model.os_held.get());
            assert!(!model.revoke());
            assert!(core::ptr::eq(operation.context(), context.as_ref()));
            station.disconnect().unwrap();
            assert!(model.hw_held.get() && model.os_held.get());
        })
    }
    .unwrap();
    assert!(!model.hw_held.get() && !model.os_held.get());
    assert_ne!(station.phase(), Phase::Associated);
    assert!(model.revoke());
}

#[test]
fn mutable_management_consumer_denies_foreign_purpose_epochs_and_revoked_guards() {
    for fault in 0..10 {
        let (mut station, context, mut owner, model) = fixture();
        associated(&mut station, &context);
        let permit = owner
            .admit_association(
                &station,
                context.clone(),
                if fault == 0 {
                    Use::Data
                } else {
                    Use::Management
                },
            )
            .unwrap();
        match fault {
            0 => {}
            1 => model.hw_available.set(false),
            2 => model.os_available.set(false),
            3 => model.hw_mask.set(0),
            4 => model.os_mask.set(0),
            5 => model.revision.set(2),
            6 => {
                let mut native = model.native.get();
                native.reset_epoch += 1;
                model.native.set(native);
            }
            7 => owner = reg::Owner::new(Hardware(model.clone()), Os(model.clone())).unwrap(),
            8 => {
                station.disconnect().unwrap();
            }
            _ => model.applied_power.set(false),
        }
        let phase = station.phase();
        assert!(
            // SAFETY: each rejected provider boundary must avoid the effect.
            unsafe {
                owner.consume_association::<()>(permit, &mut station, |_, _| {
                    panic!("denied management consumer reached canonical state")
                })
            }
            .is_err(),
            "fault {fault}"
        );
        assert_eq!(station.phase(), phase);
        assert!(!model.hw_held.get() && !model.os_held.get());
    }
}

/// Each link of an AP MLD association is its own operation on its own
/// channel, which both providers check.
#[test]
fn every_link_of_an_mld_association_is_admitted_on_its_own_channel() {
    use crate::wifi::station::multi_link::tests::{
        answer, associate_station, association_response,
    };
    let (station, action) = associate_station(association_response(vec![answer(0)]));
    let Action::Configure {
        context: Some(c),
        links,
        ..
    } = action
    else {
        panic!("configuration");
    };
    let [link] = &links[..] else {
        panic!("one other link");
    };
    assert_ne!(link.channel(), c.channel());
    let (s, c, mut owner, m) = model(station, c);
    // Unknown to both providers, the other link keeps the setup out.
    assert_eq!(
        owner
            .admit_association(&s, Arc::clone(&c), Use::Configure)
            .unwrap_err(),
        reg::Error::HardwareDenied
    );
    m.links
        .borrow_mut()
        .push((Arc::clone(link), link.channel()));
    let admission = owner
        .admit_association(&s, Arc::clone(&c), Use::Configure)
        .unwrap();
    // SAFETY: the model publication has no native effect.
    unsafe { owner.publish_association(admission, &s, Use::Configure, |_, _| ()) }.unwrap();
    // A channel the hardware no longer has for the link refuses it again.
    let admission = owner
        .admit_association(&s, Arc::clone(&c), Use::Configure)
        .unwrap();
    m.links.borrow_mut()[0].1.frequency_mhz += 1;
    assert_eq!(
        // SAFETY: the refused publication cannot execute.
        unsafe { owner.publish_association::<()>(admission, &s, Use::Configure, |_, _| panic!()) }
            .unwrap_err(),
        reg::Error::HardwareDenied
    );
}
