// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! MediaTek EDCA policy fixtures.
use super::*;

#[test]
fn revoked_and_foreign_update_admission() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut driver, model, mut owner, state) = secure_modern();
    let frame = beacon(&driver, 1, |_| {});
    observe(&mut driver, &model, &frame).unwrap();
    let before = commands(&model);
    let old = *driver.applied_edca().unwrap();
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    state.allowed.set(false);
    assert!(
        // SAFETY: The original context, pending observation and native backing remain
        // kept, but OS policy was revoked after preflight. Fresh guards must deny
        // queue publication without changing the applied state.
        unsafe { driver.update_edca_modern(&mut owner, permit, None) }.is_err()
    );
    assert_eq!(commands(&model), before);
    assert_eq!(*driver.applied_edca().unwrap(), old);
    assert_eq!(driver.phase(), ClientPhase::Associated);
    assert!(driver.pending_edca());
    state.allowed.set(true);
    let (other, _other_model, mut other_owner, _) = secure_modern();
    let permit = admit(&mut other_owner, &other, AssociationUse::Management);
    assert!(
        // SAFETY: Both original and foreign model requesters keep their backing live. The
        // foreign owner/admission must be rejected before rebranding this
        // observation or publishing an EDCA command.
        unsafe { driver.update_edca_modern(&mut other_owner, permit, None) }.is_err()
    );
    assert_eq!(commands(&model), before);
    assert_eq!(*driver.applied_edca().unwrap(), old);
    update(&mut driver, &mut owner, None).unwrap();
}

#[test]
fn independent_queue_policy_denials() {
    if crate::test_process::isolate_model() {
        return;
    }
    let (mut driver, model, mut owner, state) = secure_modern();
    let frame = beacon(&driver, 1, |_| {});
    observe(&mut driver, &model, &frame).unwrap();
    let before = commands(&model);
    let old = *driver.applied_edca().unwrap();
    for hardware in [true, false] {
        state.edca_hardware.set(!hardware);
        state.edca_os.set(hardware);
        // Original context admission still succeeds. Only the exact new queue
        // operation is denied by the independently held dynamic provider.
        let permit = admit(&mut owner, &driver, AssociationUse::Management);
        let result =
        // SAFETY: The pending observation and native owners remain live under the
        // original association admission. One dynamic hardware/OS hook is
        // denied; fresh operation-specific guards must refuse before
        // publication.
        unsafe { driver.update_edca_modern(&mut owner, permit, None) };
        match result {
            Err(ClientError::Regulatory(reg::Error::HardwareDenied)) if hardware => {}
            Err(ClientError::Regulatory(reg::Error::OsDenied)) if !hardware => {}
            other => panic!("exact current provider denial expected: {other:?}"),
        }
        assert_eq!(commands(&model), before);
        assert_eq!(driver.phase(), ClientPhase::Associated);
        assert_eq!(*driver.applied_edca().unwrap(), old);
        assert!(driver.pending_edca());
    }
    state.edca_hardware.set(true);
    state.edca_os.set(true);
    update(&mut driver, &mut owner, None).unwrap();
}

#[test]
fn association_permission_does_not_grant_edca() {
    if crate::test_process::isolate_model() {
        return;
    }
    struct OriginalOnly(Hardware);
    struct Guard(HardwareGuard);
    impl reg::HardwareLease for Guard {
        fn context(&self) -> reg::NativeContext {
            reg::HardwareLease::context(&self.0)
        }
        fn lookup_channel(&mut self, band: Band, number: u16) -> Option<wifi::Channel> {
            reg::HardwareLease::lookup_channel(&mut self.0, band, number)
        }
        fn allows(&mut self, operation: reg::Operation) -> bool {
            reg::HardwareLease::allows(&mut self.0, operation)
        }
        fn allows_association(&mut self, operation: &reg::AssociationOperation<'_>) -> bool {
            reg::HardwareLease::allows_association(&mut self.0, operation)
        }
        // Uses the default-deny dynamic provider hook.
    }
    // SAFETY: delegates this model policy/guard without extending
    // its accepted operations; original context permission never grants EDCA.
    unsafe impl reg::HardwarePolicy for OriginalOnly {
        type Lease<'a> = Guard;
        fn acquire(&mut self) -> Option<Self::Lease<'_>> {
            reg::HardwarePolicy::acquire(&mut self.0).map(Guard)
        }
    }
    let (mut driver, model, _, state) = secure_modern();
    let mut owner = reg::Owner::new(OriginalOnly(Hardware(state.clone())), Os(state)).unwrap();
    let frame = beacon(&driver, 1, |_| {});
    observe(&mut driver, &model, &frame).unwrap();
    let before = commands(&model);
    let permit = owner
        .admit_association(
            driver.station(),
            driver.modern_context().unwrap().clone(),
            AssociationUse::Management,
        )
        .unwrap();
    assert!(matches!(
        // SAFETY: The wrapper keeps the original model requester and delegates its
        // real lease/context unchanged. Its dynamic-queue hook default-
        // denies, so association permission cannot publish this EDCA update.
        unsafe { driver.update_edca_modern(&mut owner, permit, None) },
        Err(ClientError::Regulatory(reg::Error::HardwareDenied))
    ));
    assert_eq!(commands(&model), before);
    assert!(driver.pending_edca());
    assert_eq!(driver.phase(), ClientPhase::Associated);
    assert_eq!(driver.applied_edca().unwrap().parameter_set_count, 0);
}
