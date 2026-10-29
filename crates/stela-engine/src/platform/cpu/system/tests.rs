use super::*;
fn baseline() -> Observation {
    Observation {
        declarations: CpuDeclarations {
            vendor: TargetCpu::INTEL_VENDOR,
            cpuid1_ecx: 0,
            cpuid1_edx: CPUID_FLOOR_EDX,
            extended_edx: CPUID_LONG_NX,
            cpuid7_ecx: 0,
            identity: IdentityProbe::Topology(0x1f),
        },
        controls: NativeControls {
            apic_id: 0x1234,
            cs: 8,
            cr0: CR0_REQUIRED,
            cr4: CR4_REQUIRED,
            efer: EFER_REQUIRED,
            flags: 0,
        },
    }
}

#[test]
fn legacy_xmm_floor_never_invents_extended_features() {
    let mut actual = baseline();
    assert_eq!(actual.target(), Ok(TargetCpu::Baseline));
    actual.declarations.cpuid1_edx |= 1 << 8;
    actual.declarations.cpuid1_ecx |= 1 << 13;
    let expected = TargetCpu::Baseline.with_cx8().with_cx16();
    assert_eq!(actual.target(), Ok(expected));
    actual.controls.cr4 |= 1 << 18; // OSXSAVE does not admit AVX or a wider target.
    actual.declarations.cpuid1_ecx |= !(1 << 28);
    assert_eq!(actual.target(), Ok(expected));
    actual.controls.cr4 |= 1 << 12;
    assert_eq!(actual.target(), Err(Refusal::Controls));
    actual.declarations.cpuid7_ecx |= 1 << 16;
    assert_eq!(actual.target(), Ok(expected));
}
#[test]
fn aligned_atomic_legacy_xmm_capability_is_independent_of_os_avx_state() {
    let mut actual = baseline();
    actual.declarations.cpuid1_ecx |= 1 << 28;
    assert_eq!(actual.target(), Ok(TargetCpu::AtomicLoad16));
    assert_eq!(actual.controls.cr4 & (1 << 18), 0);
    assert!(!actual.target().unwrap().supports(TargetCpu::Avx2));
    actual.controls.cr4 |= 1 << 18;
    assert_eq!(actual.target(), Ok(TargetCpu::AtomicLoad16));
    let proof = NativeSystemTarget {
        observed: actual,
        lease: None,
        target: actual.target().unwrap(),
    };
    actual.declarations.cpuid1_ecx &= !(1 << 28);
    assert_eq!(
        proof.revalidate_observation(actual),
        Err(Refusal::TargetChanged)
    );
    actual.declarations.cpuid1_ecx |= 1 << 28;
    actual.declarations.vendor = TargetCpu::AMD_VENDOR;
    assert_eq!(actual.target(), Ok(TargetCpu::AtomicLoad16));
    actual.controls.cr4 &= !(1 << 18);
    assert_eq!(actual.target(), Ok(TargetCpu::AtomicLoad16));
    actual.declarations.vendor = [0; 3];
    assert_eq!(actual.target(), Ok(TargetCpu::Baseline));
    assert_eq!(
        proof.revalidate_observation(actual),
        Err(Refusal::ProcessorChanged)
    );
}

#[test]
fn all_effective_native_requirements_are_checked_before_entry() {
    for bit in [0, 1, 5, 16, 31] {
        let mut actual = baseline();
        actual.controls.cr0 &= !(1 << bit);
        assert_eq!(actual.target(), Err(Refusal::Controls));
    }
    for bit in [2, 3, 29, 30] {
        let mut actual = baseline();
        actual.controls.cr0 |= 1 << bit;
        assert_eq!(actual.target(), Err(Refusal::Controls));
    }
    for bit in [5, 9, 10] {
        let mut actual = baseline();
        actual.controls.cr4 &= !(1 << bit);
        assert_eq!(actual.target(), Err(Refusal::Controls));
    }
    for bit in [7, 17, 23] {
        let mut actual = baseline();
        actual.controls.cr4 |= 1 << bit;
        assert_eq!(actual.target(), Err(Refusal::Controls));
    }
    let mut actual = baseline();
    actual.controls.flags = IF;
    assert_eq!(actual.target(), Err(Refusal::InterruptsEnabled));
}
#[test]
fn physical_migration_control_changes_and_lost_capability_refuse() {
    let mut actual = baseline();
    actual.declarations.cpuid1_ecx |= 1 << 13;
    let proof = NativeSystemTarget {
        observed: actual,
        lease: None,
        target: actual.target().unwrap(),
    };
    assert_eq!(proof.revalidate_observation(actual), Ok(()));
    actual.controls.apic_id = 0x34;
    assert_eq!(
        proof.revalidate_observation(actual),
        Err(Refusal::ProcessorChanged)
    );
    actual = proof.observed;
    actual.controls.cr4 |= 1 << 18;
    assert_eq!(proof.revalidate_observation(actual), Err(Refusal::Controls));
    actual = proof.observed;
    actual.declarations.cpuid1_ecx &= !(1 << 13);
    assert_eq!(
        proof.revalidate_observation(actual),
        Err(Refusal::TargetChanged)
    );
    assert_eq!(
        NativeSystemTarget::capture().unwrap_err(),
        Refusal::UnsupportedHost
    );
}

// Private observation models exercise the same validators. They are not
// a public fake-hardware constructor and establish no CPL0 validation.
fn modeled_owner(actual: Observation) -> NativeCpuOwner {
    NativeCpuOwner::admit(WorkerId(17), actual.controls.apic_id, actual).unwrap()
}

fn modeled_capture(
    owner: &NativeCpuOwner,
    controls: NativeControls,
) -> Result<NativeSystemTarget, Refusal> {
    NativeSystemTarget::capture_with(
        Some((WorkerId(17), owner.lease())),
        || panic!("supplied lease must never fall back"),
        |_| Ok(controls),
    )
}

#[test]
fn declaration_construction_requires_complete_floor_and_actual_local_owner() {
    let actual = baseline();
    for bit in 0..32 {
        if CPUID_FLOOR_EDX & (1 << bit) != 0 {
            let mut changed = actual;
            changed.declarations.cpuid1_edx &= !(1 << bit);
            assert_eq!(
                NativeCpuOwner::admit(WorkerId(17), actual.controls.apic_id, changed).unwrap_err(),
                Refusal::MissingCpuFeatures
            );
        }
    }
    for bit in [20, 29] {
        let mut changed = actual;
        changed.declarations.extended_edx &= !(1 << bit);
        assert_eq!(
            NativeCpuOwner::admit(WorkerId(17), actual.controls.apic_id, changed).unwrap_err(),
            Refusal::MissingCpuFeatures
        );
    }
    assert_eq!(
        NativeCpuOwner::admit(WorkerId(17), 0x34, actual).unwrap_err(),
        Refusal::ProcessorChanged
    );
    // Public construction cannot use the modeled observations on a POSIX
    // process, even with a baseline artifact and plausible numeric IDs.
    assert_eq!(
        // SAFETY: the mismatched worker is refused before any CPU state is touched.
        unsafe { NativeCpuOwner::new(WorkerId(17), actual.controls.apic_id) }.unwrap_err(),
        Refusal::UnsupportedHost
    );
}

fn invalid_controls() -> alloc::vec::Vec<(NativeControls, Refusal)> {
    let base = baseline().controls;
    let mut cases = alloc::vec::Vec::new();
    for cs in [3, 0x1b] {
        cases.push((NativeControls { cs, ..base }, Refusal::Privilege));
    }
    cases.push((
        NativeControls { flags: IF, ..base },
        Refusal::InterruptsEnabled,
    ));
    cases.push((
        NativeControls {
            apic_id: 0x34,
            ..base
        },
        Refusal::ProcessorChanged,
    ));
    for bit in [0, 1, 5, 16, 31] {
        cases.push((
            NativeControls {
                cr0: base.cr0 & !(1 << bit),
                ..base
            },
            Refusal::Controls,
        ));
    }
    for bit in [2, 3, 29, 30] {
        cases.push((
            NativeControls {
                cr0: base.cr0 | (1 << bit),
                ..base
            },
            Refusal::Controls,
        ));
    }
    for bit in [5, 9, 10] {
        cases.push((
            NativeControls {
                cr4: base.cr4 & !(1 << bit),
                ..base
            },
            Refusal::Controls,
        ));
    }
    for bit in [7, 17, 23] {
        cases.push((
            NativeControls {
                cr4: base.cr4 | (1 << bit),
                ..base
            },
            Refusal::Controls,
        ));
    }
    for bit in [10, 11] {
        cases.push((
            NativeControls {
                efer: base.efer & !(1 << bit),
                ..base
            },
            Refusal::Controls,
        ));
    }
    // LA57 without an immutable hardware declaration refuses at capture.
    cases.push((
        NativeControls {
            cr4: base.cr4 | (1 << 12),
            ..base
        },
        Refusal::Controls,
    ));
    cases
}

#[test]
fn leased_capture_and_all_three_rechecks_validate_actual_live_controls() {
    let actual = baseline();
    for (changed, expected) in invalid_controls() {
        let candidate = Observation {
            controls: changed,
            ..actual
        };
        assert!(NativeCpuOwner::admit(WorkerId(17), actual.controls.apic_id, candidate).is_err());
        for boundary in 0..4 {
            let owner = modeled_owner(actual);
            let initial = if boundary == 0 {
                changed
            } else {
                actual.controls
            };
            let proof = modeled_capture(&owner, initial);
            if boundary == 0 {
                assert_eq!(proof.unwrap_err(), expected);
                continue;
            }
            let proof = proof.unwrap();
            for recheck in 1..=boundary {
                let live = if recheck == boundary {
                    changed
                } else {
                    actual.controls
                };
                let result = proof.revalidate_with(
                    || panic!("leased recheck cannot enumerate declarations"),
                    |_| Ok(live),
                );
                assert_eq!(
                    result,
                    if recheck == boundary {
                        Err(expected)
                    } else {
                        Ok(())
                    }
                );
            }
        }
    }
}

#[test]
fn body_controls_are_exact_even_when_a_new_capture_would_admit_them() {
    let actual = baseline();
    let owner = modeled_owner(actual);
    let proof = modeled_capture(&owner, actual.controls).unwrap();
    for changed in [
        NativeControls {
            cs: 16,
            ..actual.controls
        },
        NativeControls {
            cr0: actual.controls.cr0 | (1 << 18),
            ..actual.controls
        },
        NativeControls {
            cr4: actual.controls.cr4 | (1 << 18),
            ..actual.controls
        },
        NativeControls {
            efer: actual.controls.efer | 1,
            ..actual.controls
        },
    ] {
        assert!(modeled_capture(&owner, changed).is_ok());
        for _boundary in 1..4 {
            assert_eq!(
                proof.revalidate_with(|| panic!("no fallback"), |_| Ok(changed)),
                Err(Refusal::Controls)
            );
        }
    }
}

#[test]
fn revoked_wrong_worker_and_replaced_owners_never_fall_back() {
    let actual = baseline();
    let mut owner = modeled_owner(actual);
    let lease = owner.lease();
    assert_eq!(
        NativeSystemTarget::capture_with(
            Some((WorkerId(18), lease.clone())),
            || panic!("wrong worker must not enumerate"),
            |_| panic!("wrong worker must not probe"),
        )
        .unwrap_err(),
        Refusal::WorkerChanged
    );
    let proof = modeled_capture(&owner, actual.controls).unwrap();
    owner.revoke();
    assert_eq!(
        modeled_capture(&owner, actual.controls).unwrap_err(),
        Refusal::OwnerRevoked
    );
    assert_eq!(
        proof.revalidate_with(|| panic!("no fallback"), |_| panic!("revoked before probe")),
        Err(Refusal::OwnerRevoked)
    );
    let replacement = modeled_owner(actual);
    assert!(!Rc::ptr_eq(&lease.seal, &replacement.seal));
    assert!(modeled_capture(&replacement, actual.controls).is_ok());
    assert_eq!(lease.check(WorkerId(17)), Err(Refusal::OwnerRevoked));
    let replacement_lease = replacement.lease();
    drop(replacement);
    assert_eq!(
        replacement_lease.check(WorkerId(17)),
        Err(Refusal::OwnerRevoked)
    );
}

#[test]
fn revocation_during_observation_or_callback_finalization_refuses() {
    let actual = baseline();
    let mut owner = modeled_owner(actual);
    assert_eq!(
        NativeSystemTarget::capture_with(
            Some((WorkerId(17), owner.lease())),
            || panic!("no fallback"),
            |_| {
                owner.revoke();
                Ok(actual.controls)
            },
        )
        .unwrap_err(),
        Refusal::OwnerRevoked
    );
    for boundary in 1..4 {
        let mut owner = modeled_owner(actual);
        let proof = modeled_capture(&owner, actual.controls).unwrap();
        for _ in 1..boundary {
            proof
                .revalidate_with(|| panic!("no fallback"), |_| Ok(actual.controls))
                .unwrap();
        }
        // At boundary 3 this models retirement during callback/finalization;
        // the post-check rejects before the caller may settle success.
        owner.revoke();
        assert_eq!(
            proof.revalidate_with(|| panic!("no fallback"), |_| panic!("revoked before probe")),
            Err(Refusal::OwnerRevoked)
        );
    }
}

#[test]
fn default_selection_keeps_complete_capture_and_revalidation() {
    let actual = baseline();
    let full = Cell::new(0);
    let proof = NativeSystemTarget::capture_with(
        None,
        || {
            full.set(full.get() + 1);
            Ok(actual)
        },
        |_| panic!("no owner means full observation"),
    )
    .unwrap();
    for _ in 1..4 {
        proof
            .revalidate_with(
                || {
                    full.set(full.get() + 1);
                    Ok(actual)
                },
                |_| panic!("no owner means full revalidation"),
            )
            .unwrap();
    }
    assert_eq!(full.get(), 4);
    assert!(proof.lease.is_none());
    let mut changed = actual;
    changed.declarations.cpuid1_edx = 0;
    assert_eq!(
        proof.revalidate_with(|| Ok(changed), |_| panic!("no owner")),
        Err(Refusal::MissingCpuFeatures)
    );
}

#[test]
fn retirement_reenumerates_mixed_worker_capabilities_without_promoting_avx() {
    let mut rich = baseline();
    rich.declarations.cpuid1_ecx = (1 << 13) | (1 << 28);
    rich.declarations.cpuid1_edx |= 1 << 8;
    rich.controls.cr4 |= 1 << 18;
    let mut owner = modeled_owner(rich);
    let proof = modeled_capture(&owner, rich.controls).unwrap();
    assert!(proof.target().supports(TargetCpu::Cx16));
    assert!(proof.target().supports(TargetCpu::AtomicLoad16));
    assert!(!proof.target().supports(TargetCpu::Avx2));
    let other = modeled_owner(baseline());
    assert_eq!(
        modeled_capture(&other, baseline().controls)
            .unwrap()
            .target(),
        TargetCpu::Baseline
    );
    owner.revoke();
    let replacement = modeled_owner(baseline());
    assert_eq!(
        proof.revalidate_with(|| panic!("no fallback"), |_| Ok(rich.controls)),
        Err(Refusal::OwnerRevoked)
    );
    assert_eq!(
        modeled_capture(&replacement, baseline().controls)
            .unwrap()
            .target(),
        TargetCpu::Baseline
    );
    rich.declarations.vendor = [0; 3];
    let unknown = modeled_owner(rich);
    assert!(
        !modeled_capture(&unknown, rich.controls)
            .unwrap()
            .target()
            .supports(TargetCpu::AtomicLoad16)
    );
}

fn declarations(
    vendor: [u32; 3],
    maximum: u32,
    extended: u32,
    topology: bool,
    leaf1f: Cpuid,
    leafb: Cpuid,
) -> (CpuDeclarations, u32) {
    enumerate(|leaf, _| match leaf {
        0 => Cpuid {
            eax: maximum,
            ebx: vendor[0],
            edx: vendor[1],
            ecx: vendor[2],
        },
        1 => Cpuid {
            ebx: 0x34 << 24,
            edx: CPUID_FLOOR_EDX,
            ..Cpuid::default()
        },
        0x8000_0000 => Cpuid {
            eax: extended,
            ..Cpuid::default()
        },
        0x8000_0001 => Cpuid {
            ecx: if topology { 1 << 22 } else { 0 },
            edx: CPUID_LONG_NX,
            ..Cpuid::default()
        },
        0x1f => leaf1f,
        0xb => leafb,
        0x8000_001e => Cpuid {
            eax: 0x1234,
            ..Cpuid::default()
        },
        7 => Cpuid::default(),
        _ => panic!("unexpected leaf"),
    })
    .unwrap()
}

#[test]
fn identity_probe_selection_obeys_maxima_amd_gate_and_full_width_topology() {
    let valid = Cpuid {
        ebx: 2,
        ecx: 1 << 8,
        edx: 0x1234,
        ..Cpuid::default()
    };
    let invalid = Cpuid::default();
    for (maximum, first, second, expected) in [
        (1, valid, valid, IdentityProbe::Legacy),
        (0xb, valid, valid, IdentityProbe::Topology(0xb)),
        (0x1f, valid, valid, IdentityProbe::Topology(0x1f)),
        (0x1f, invalid, valid, IdentityProbe::Topology(0xb)),
        (0x1f, invalid, invalid, IdentityProbe::Legacy),
    ] {
        let (d, id) = declarations(
            TargetCpu::INTEL_VENDOR,
            maximum,
            0x8000_0001,
            false,
            first,
            second,
        );
        assert_eq!(d.identity, expected);
        assert_eq!(
            id,
            if expected == IdentityProbe::Legacy {
                0x34
            } else {
                0x1234
            }
        );
    }
    for vendor in [TargetCpu::AMD_VENDOR, TargetCpu::INTEL_VENDOR, [0; 3]] {
        for maximum in [0x8000_0001, 0x8000_001d, 0x8000_001e] {
            for topology in [false, true] {
                let (d, id) = declarations(vendor, 1, maximum, topology, invalid, invalid);
                let amd = vendor == TargetCpu::AMD_VENDOR && maximum >= 0x8000_001e && topology;
                assert_eq!(
                    d.identity,
                    if amd {
                        IdentityProbe::Amd
                    } else {
                        IdentityProbe::Legacy
                    }
                );
                assert_eq!(id, if amd { 0x1234 } else { 0x34 });
            }
        }
    }
    // A selected topology route never silently falls back or truncates
    // after a now-invalid record. Count uses the architectural low 16 bits.
    for invalid in [
        Cpuid {
            ebx: 1 << 16,
            ..valid
        },
        Cpuid { ecx: 0, ..valid },
    ] {
        assert_eq!(
            IdentityProbe::Topology(0x1f).read(|leaf, _| {
                assert_eq!(leaf, 0x1f);
                invalid
            }),
            Err(Refusal::ProcessorChanged)
        );
    }
    assert_eq!(
        IdentityProbe::Amd.read(|leaf, _| {
            assert_eq!(leaf, 0x8000_001e);
            valid
        }),
        Ok(valid.eax)
    );
    assert_eq!(
        IdentityProbe::Legacy.read(|leaf, _| {
            assert_eq!(leaf, 1);
            Cpuid {
                ebx: 0xfe << 24,
                ..valid
            }
        }),
        Ok(0xfe)
    );
    for (maximum, extended) in [(0, 0x8000_0001), (1, 0x8000_0000)] {
        assert_eq!(
            enumerate(|leaf, _| Cpuid {
                eax: if leaf == 0 { maximum } else { extended },
                ..Cpuid::default()
            })
            .unwrap_err(),
            Refusal::MissingCpuFeatures
        );
    }
}

#[test]
fn one_owner_enumeration_then_one_live_identity_probe_per_boundary() {
    let actual = baseline();
    let enumerations = Cell::new(0);
    let (d, id) = enumerate(|leaf, _| {
        enumerations.set(enumerations.get() + 1);
        match leaf {
            0 => Cpuid {
                eax: 0x1f,
                ebx: TargetCpu::INTEL_VENDOR[0],
                edx: TargetCpu::INTEL_VENDOR[1],
                ecx: TargetCpu::INTEL_VENDOR[2],
            },
            1 => Cpuid {
                edx: CPUID_FLOOR_EDX,
                ..Cpuid::default()
            },
            0x8000_0000 => Cpuid {
                eax: 0x8000_0001,
                ..Cpuid::default()
            },
            0x8000_0001 => Cpuid {
                edx: CPUID_LONG_NX,
                ..Cpuid::default()
            },
            0x1f => Cpuid {
                ebx: 2,
                ecx: 1 << 8,
                edx: actual.controls.apic_id,
                ..Cpuid::default()
            },
            7 => Cpuid::default(),
            _ => panic!("unexpected leaf"),
        }
    })
    .unwrap();
    assert_eq!(enumerations.get(), 6);
    let owner = modeled_owner(Observation {
        declarations: d,
        controls: NativeControls {
            apic_id: id,
            ..actual.controls
        },
    });
    let probes = Cell::new(0);
    let live = |probe: IdentityProbe| {
        let apic_id = probe.read(|leaf, _| {
            assert_eq!(leaf, 0x1f);
            probes.set(probes.get() + 1);
            Cpuid {
                ebx: 2,
                ecx: 1 << 8,
                edx: id,
                ..Cpuid::default()
            }
        })?;
        Ok(NativeControls {
            apic_id,
            ..actual.controls
        })
    };
    let proof = NativeSystemTarget::capture_with(
        Some((WorkerId(17), owner.lease())),
        || panic!("no reenumeration"),
        live,
    )
    .unwrap();
    for _ in 1..4 {
        proof
            .revalidate_with(|| panic!("no reenumeration"), live)
            .unwrap();
    }
    assert_eq!(probes.get(), 4);
    assert_eq!(enumerations.get(), 6);
}
