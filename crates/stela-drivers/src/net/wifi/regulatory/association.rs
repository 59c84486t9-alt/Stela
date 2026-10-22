//! Context-bound admission for actual source-enabled station radio work.
//!
//! This permission does not authenticate a peer, open the controlled port,
//! install keys or bypass per-MPDU/replay checks. Native packet owners must
//! independently retain and validate those exact existing capabilities.

use super::{Error, HardwareLease, HardwarePolicy, OsLease, OsPolicy, Owner};
use crate::net::wifi::station::{AssociationContext, Phase, Station};
use alloc::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssociationUse {
    /// Enable/configure the complete context, including autonomous responses.
    Configure,
    Management,
    Data,
}

/// Exact borrowed profile for providers to qualify; this is not a permit.
/// Providers must inspect the complete enabled source envelope, including basic
/// rates and autonomous responses, not just the selected width/MCS or one MPDU.
#[derive(Debug)]
pub struct AssociationOperation<'a> {
    context: &'a AssociationContext,
    purpose: AssociationUse,
}
impl AssociationOperation<'_> {
    pub fn context(&self) -> &AssociationContext {
        self.context
    }
    pub const fn purpose(&self) -> AssociationUse {
        self.purpose
    }
}

/// A private, single-use preflight result retaining the exact current context.
/// Publication must reacquire both real providers and revalidate station state.
///
/// ```compile_fail
/// use stela_drivers::net::wifi::regulatory::AssociationAdmission;
/// let admission = AssociationAdmission { owner: 1 };
/// ```
#[derive(Debug)]
pub struct AssociationAdmission {
    owner: u64,
    native: super::NativeContext,
    os_revision: u64,
    context: Arc<AssociationContext>,
    purpose: AssociationUse,
}
impl AssociationAdmission {
    pub fn operation(&self) -> AssociationOperation<'_> {
        AssociationOperation {
            context: &self.context,
            purpose: self.purpose,
        }
    }
}

fn current(station: &Station, operation: &AssociationOperation<'_>) -> Result<(), Error> {
    station
        .validate_association_context(operation.context)
        .map_err(|_| Error::Stale)?;
    let required = match operation.purpose {
        AssociationUse::Configure => Phase::Configuring,
        AssociationUse::Management | AssociationUse::Data => Phase::Associated,
    };
    if station.phase() != required {
        return Err(Error::Mismatch);
    }
    Ok(())
}

fn check(
    hardware: &mut impl HardwareLease,
    os: &mut impl OsLease,
    operation: &AssociationOperation<'_>,
) -> Result<(), Error> {
    let channel = operation.context.channel();
    if hardware.lookup_channel(channel.band, channel.number) != Some(channel)
        || !hardware.allows_association(operation)
    {
        return Err(Error::HardwareDenied);
    }
    if !os.allows_association(operation) {
        return Err(Error::OsDenied);
    }
    Ok(())
}

impl<H: HardwarePolicy, O: OsPolicy> Owner<H, O> {
    /// Check actual current context identity, phase and the entire enabled
    /// profile with both genuine providers. No native effects occur here.
    pub fn admit_association(
        &mut self,
        station: &Station,
        context: Arc<AssociationContext>,
        purpose: AssociationUse,
    ) -> Result<AssociationAdmission, Error> {
        let operation = AssociationOperation {
            context: &context,
            purpose,
        };
        current(station, &operation)?;
        let mut hardware = self.hardware.acquire().ok_or(Error::HardwareUnavailable)?;
        let native = hardware.context();
        let mut os = self.os.acquire(native).ok_or(Error::OsUnavailable)?;
        check(&mut hardware, &mut os, &operation)?;
        Ok(AssociationAdmission {
            owner: self.identity,
            native,
            os_revision: os.revision(),
            context,
            purpose,
        })
    }

    /// Recheck the exact context and purpose at native publication, holding the
    /// immutable station plus hardware then OS guards through `submit`.
    /// Closure return is not command ACK, association success, air completion or
    /// retirement. Keep the context/policy/key/queue alive through actual native
    /// completions and uncertainty; revocation must disable/drain or enforce
    /// restrictions on previously armed/queued autonomous and packet work.
    ///
    /// # Safety
    /// Submit must use this concrete guard's same retained physical controller
    /// and encode only this exact context/purpose through its actual qualified
    /// source path. It must not defer publication beyond the held guards, target
    /// another device, substitute legacy commands, or widen enabled effects.
    /// The backend must preserve the providers' revocation/stop/drain contract
    /// after return. Failed/uncertain publication does not authorize success.
    pub unsafe fn publish_association<'a, T>(
        &'a mut self,
        admission: AssociationAdmission,
        station: &Station,
        purpose: AssociationUse,
        submit: impl FnOnce(&mut H::Lease<'a>, &AssociationOperation<'_>) -> T,
    ) -> Result<T, Error> {
        if admission.owner != self.identity {
            return Err(Error::Stale);
        }
        if admission.purpose != purpose {
            return Err(Error::Mismatch);
        }
        let operation = admission.operation();
        current(station, &operation)?;
        let mut hardware = self.hardware.acquire().ok_or(Error::HardwareUnavailable)?;
        let native = hardware.context();
        if admission.native != native {
            return Err(Error::Stale);
        }
        let mut os = self.os.acquire(native).ok_or(Error::OsUnavailable)?;
        if admission.os_revision != os.revision() {
            return Err(Error::Stale);
        }
        check(&mut hardware, &mut os, &operation)?;
        let result = submit(&mut hardware, &operation);
        drop(os);
        drop(hardware);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use crate::net::wifi::regulatory::{self as reg, AssociationUse as Use};
    use crate::net::wifi::station::{
        phy::{Mode, Width},
        tests::*,
        *,
    };
    use crate::net::wifi::{Band, Channel};
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
        log: RefCell<Vec<&'static str>>,
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
            Use::Configure => 1,
            Use::Management => 2,
            Use::Data => 4,
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
            let c = self.0.channel.get();
            (c.band == band && c.number == number).then_some(c)
        }
        fn allows(&mut self, _: reg::Operation) -> bool {
            true
        }
        fn allows_association(&mut self, op: &reg::AssociationOperation<'_>) -> bool {
            assert!(self.0.hw_held.get() && self.0.os_held.get());
            core::ptr::eq(op.context(), self.0.context.as_ref())
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
            core::ptr::eq(op.context(), self.0.context.as_ref())
                && self.0.os_mask.get() & mask(op.purpose()) != 0
        }
    }
    // SAFETY: synthetic model has no physical authority; its only modeled mutation
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
    // SAFETY: same pure model; acquire checks the exact native context and retains
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
        // SAFETY: no model publication is permitted on a mismatched request.
        assert_eq!(
            unsafe {
                owner.publish_association::<()>(admission, &s, Use::Management, |_, _| panic!())
            }
            .unwrap_err(),
            reg::Error::Mismatch
        );
        let admission = owner
            .admit_association(&s, Arc::clone(&c), Use::Configure)
            .unwrap();
        associated(&mut s, &c);
        // SAFETY: a phase change must reject before the closure.
        assert_eq!(
            unsafe {
                owner.publish_association::<()>(admission, &s, Use::Configure, |_, _| panic!())
            }
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
            // SAFETY: stale modeled identity is rejected before native publication.
            assert_eq!(
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
            // SAFETY: changed authority must reject before modeled publication.
            assert_eq!(
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
    fn missing_power_authority_revocation_and_exact_channel_are_rechecked() {
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
            // SAFETY: revoked modeled authority cannot execute this publication.
            assert_eq!(
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
        let mut owner =
            reg::Owner::new(Hardware(Rc::clone(&m)), LegacyOs(Os(Rc::clone(&m)))).unwrap();
        assert_eq!(
            owner.admit_association(&s, c, Use::Configure).unwrap_err(),
            reg::Error::OsDenied
        );
    }
}
