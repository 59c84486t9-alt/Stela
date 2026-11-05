// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2007-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2016-2017 Intel Deutschland GmbH
use super::*;

#[test]
fn ax210_product_reset_uses_explicit_unmanaged_policy_and_refuses_managed_without_provider() {
    if crate::test_process::isolate_model() {
        return;
    }
    let bytes = ax210_bytes();
    let catalog = catalog_for(&ax210_profile(), Family::Ax210.firmware_name(), &bytes);
    let (observation, step_catalog) = step_fixture();
    let source = Source::default();
    let domain = Arc::new(Domain::default());
    let state = ax210_state();
    let drops = Arc::new(AtomicUsize::new(0));
    state.lock().unwrap().registers.insert(0x450, 0x80);
    let step = crate::wifi::intel::platform::load_step(observation, &step_catalog).unwrap();
    let mut boot = start_ax210(&catalog, step, &source, &domain, &state, &drops);
    assert_eq!(
        boot.product_reset_observation(),
        Some(ProductResetObservation {
            sb_configuration: 0x80,
            coordination: ProductResetCoordination::NotPerformedNoIwlmei
        })
    );
    let ops = state.lock().unwrap().ops.clone();
    let sb = ops
        .iter()
        .position(|op| *op == Op::Write(0x448, 0x03d03088))
        .unwrap();
    assert_eq!(ops[sb + 1], Op::Read(0x450));
    assert!(!ops.iter().any(|op| matches!(op, Op::Write(0x440, _))));
    let context = ops
        .iter()
        .position(|op| matches!(op, Op::Write(0x118, _)))
        .unwrap();
    assert!(sb < context);
    boot.stop().unwrap();
    assert!(domain.records.lock().unwrap().live.is_empty());
    let source = Source::default();
    let domain = Arc::new(Domain::default());
    let state = ax210_state();
    let drops = Arc::new(AtomicUsize::new(0));
    let power = awake_profile(state.clone(), drops.clone(), ax210_profile());
    let before = state.lock().unwrap().ops.len();
    let step = crate::wifi::intel::platform::load_step(observation, &step_catalog).unwrap();
    // SAFETY: This model has fresh exclusive Source/Domain RAM and no active SAP user;
    // ManagedSap is refused before publication rather than inventing a provider.
    let result = unsafe {
        RomBoot::start_ax210(
            power,
            crate::wifi::intel::identity::stage(&ax210_profile(), &catalog).unwrap(),
            step,
            &source,
            Some(domain.clone()),
            32,
            ProductResetPolicy::ManagedSap,
        )
    };
    assert!(matches!(result, Err(Error::ManagedSapUnsupported)));
    assert_eq!(state.lock().unwrap().ops.len(), before);
    assert_eq!(source.calls.load(Ordering::Relaxed), 0);
    assert!(domain.records.lock().unwrap().live.is_empty());
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}
