//! Pure policy tests with explicitly synthetic provenance. These establish no
//! authentic CPU facts, original execution, access admission, or service effects.

use super::*;

fn facts() -> BaseEl1FeatureFacts {
    BaseEl1FeatureFacts {
        pauth: Presence::Absent,
        pan: PanFeatures::Absent,
        ssbs: Presence::Absent,
        exs: Presence::Absent,
        asid_bits: AsidBits::Eight,
        endianness: Endianness::LittleOnly,
    }
}

fn provenance() -> PolicyProvenance {
    PolicyProvenance {
        cpu_features: EvidenceBinding {
            id: "synthetic test CPU facts",
            sha256: [1; 32],
        },
        implementation_choices: EvidenceBinding {
            id: "synthetic test policy choices",
            sha256: [2; 32],
        },
    }
}

fn policy(register: Register) -> RegisterPolicy {
    RegisterPolicy::base_el1(register, facts(), provenance()).unwrap()
}

#[test]
fn selected_profiles_partition_every_bit_for_every_feature_combination() {
    let registers = [
        Register::SctlrEl1,
        Register::TcrEl1,
        Register::Ttbr0El1,
        Register::Ttbr1El1,
        Register::MairEl1,
    ];
    for selected in 0_u8..64 {
        let present = |bit| {
            if selected & (1u8 << bit) == 0u8 {
                Presence::Absent
            } else {
                Presence::Present
            }
        };
        let facts = BaseEl1FeatureFacts {
            pauth: present(0),
            pan: if selected & 2 == 0 {
                PanFeatures::Absent
            } else {
                PanFeatures::Pan3
            },
            ssbs: present(2),
            exs: present(3),
            asid_bits: if selected & 16 == 0 {
                AsidBits::Eight
            } else {
                AsidBits::Sixteen
            },
            endianness: if selected & 32 == 0 {
                Endianness::LittleOnly
            } else {
                Endianness::MixedEl0El1
            },
        };
        for register in registers {
            let policy = RegisterPolicy::base_el1(register, facts, provenance()).unwrap();
            assert_eq!(policy.facts, facts);
            assert_eq!(policy.provenance, provenance());
            assert_eq!(policy.masks.read_stored, u64::MAX);
            assert_eq!(policy.masks.write_stored, u64::MAX);
            for operand in [0, u64::MAX, 0x1200_1000_fc14_793d, 0x0008_0022_6511_a511] {
                let result = policy.apply(!operand, operand).unwrap();
                assert_eq!(result.readback, operand);
                assert_eq!(result.effective & policy.masks.effect_zero, 0);
                assert_eq!(
                    result.effective & policy.masks.effect_one,
                    policy.masks.effect_one
                );
            }
        }
    }
}

#[test]
fn inactive_reserved_fields_store_legal_writes_without_fabricating_active_features() {
    let sctlr = policy(Register::SctlrEl1);
    let operand = sctlr::EN_TP2
        | sctlr::EPAN
        | sctlr::DSSBS
        | sctlr::PAUTH
        | sctlr::ALWAYS_RESERVED
        | sctlr::EE
        | sctlr::E0E;
    let result = sctlr.apply(0, operand).unwrap();
    assert_eq!(result.readback, operand);
    assert_eq!(result.effective, sctlr::EOS | sctlr::EIS);

    let tcr = policy(Register::TcrEl1);
    let operand = tcr::TBID0 | tcr::TBID1 | tcr::AS | tcr::DS | tcr::ALWAYS_RESERVED;
    assert_eq!(
        tcr.apply(0, operand).unwrap(),
        AppliedWrite {
            readback: operand,
            effective: 0
        }
    );
}

#[test]
fn optional_active_controls_are_retained_for_their_real_consumers() {
    let facts = BaseEl1FeatureFacts {
        pauth: Presence::Present,
        pan: PanFeatures::Pan3,
        ssbs: Presence::Present,
        exs: Presence::Present,
        asid_bits: AsidBits::Sixteen,
        endianness: Endianness::MixedEl0El1,
    };
    let sctlr = RegisterPolicy::base_el1(Register::SctlrEl1, facts, provenance()).unwrap();
    let operand = sctlr::PAUTH | sctlr::PAN | sctlr::DSSBS | sctlr::EXS | sctlr::ENDIAN;
    assert_eq!(
        sctlr.apply(0, operand).unwrap(),
        AppliedWrite {
            readback: operand,
            effective: operand
        }
    );
    assert_eq!(sctlr.apply(operand, 0).unwrap().effective, 0);
    let tcr = RegisterPolicy::base_el1(Register::TcrEl1, facts, provenance()).unwrap();
    let operand = tcr::PAUTH | tcr::AS;
    assert_eq!(tcr.apply(0, operand).unwrap().effective, operand);
}

#[test]
fn absent_exs_retains_readback_but_supplies_implicit_exception_synchronization_controls() {
    let policy = policy(Register::SctlrEl1);
    assert_eq!(policy.apply(0, 0).unwrap().readback, 0);
    assert_eq!(policy.effective(0) & sctlr::EXS, sctlr::EXS);
    assert_eq!(policy.apply(0, sctlr::EXS).unwrap().readback, sctlr::EXS);
}

#[test]
fn ttbr_keeps_low_root_bits_and_separates_readback_from_asid_and_cnp_effects() {
    for register in [Register::Ttbr0El1, Register::Ttbr1El1] {
        let policy = policy(register);
        let operand = ttbr::ASID_HIGH | ttbr::ASID_LOW | 0x3fff;
        let result = policy.apply(0, operand).unwrap();
        assert_eq!(result.readback, operand);
        assert_eq!(result.effective, ttbr::ASID_LOW | 0x3ffe);
        assert_eq!(result.effective & ttbr::ASID_HIGH, 0);
        assert_eq!(result.effective & ttbr::CNP, 0);
    }
}

#[test]
fn sixteen_bit_asid_input_retains_upper_byte_for_canonical_tcr_as_selection() {
    let facts = BaseEl1FeatureFacts {
        asid_bits: AsidBits::Sixteen,
        ..facts()
    };
    let policy = RegisterPolicy::base_el1(Register::Ttbr1El1, facts, provenance()).unwrap();
    assert_eq!(
        policy.apply(0, ttbr::ASID_HIGH).unwrap().effective,
        ttbr::ASID_HIGH
    );
}

#[test]
fn tcr_keeps_intermediate_and_reserved_granule_encodings_for_canonical_access_policy() {
    let policy = policy(Register::TcrEl1);
    // TG0=0b11 is reserved. TG1=0b00 is reserved. This layer stores the
    // selected programmed-value readback; it supplies no fallback granule.
    let operand = tcr::TG0 | tcr::IPS | tcr::T0SZ | tcr::T1SZ;
    assert_eq!(
        policy.apply(0, operand).unwrap(),
        AppliedWrite {
            readback: operand,
            effective: operand
        }
    );
}

#[test]
fn mair_preserves_every_attribute_without_admitting_its_memory_semantics() {
    let policy = policy(Register::MairEl1);
    let operand = 0x0c08_04ff_00bb_44ff;
    assert_eq!(
        policy.apply(0, operand).unwrap(),
        AppliedWrite {
            readback: operand,
            effective: operand
        }
    );
    for (index, mask) in mair::ATTR.into_iter().enumerate() {
        assert_eq!(mask, 0xff_u64 << (index * 8));
    }
}

#[test]
fn provenance_must_be_explicit_and_structurally_complete() {
    let mut proof = provenance();
    proof.cpu_features.id = "  ";
    assert_eq!(
        RegisterPolicy::base_el1(Register::SctlrEl1, facts(), proof),
        Err(FieldError::MissingPolicyProvenance)
    );
    let mut proof = provenance();
    proof.implementation_choices.sha256 = [0; 32];
    assert_eq!(
        RegisterPolicy::base_el1(Register::SctlrEl1, facts(), proof),
        Err(FieldError::MissingPolicyProvenance)
    );
}

#[test]
fn private_mechanism_rejects_incomplete_overlapping_or_inconsistent_classes() {
    let good = policy(Register::SctlrEl1);
    let mut masks = good.masks;
    masks.effect_zero &= !sctlr::EN_TP2;
    assert_eq!(
        RegisterPolicy::checked(Register::SctlrEl1, facts(), provenance(), masks),
        Err(FieldError::NonExhaustiveOrOverlappingClassification)
    );
    let mut masks = good.masks;
    masks.effect_zero |= sctlr::M;
    assert_eq!(
        RegisterPolicy::checked(Register::SctlrEl1, facts(), provenance(), masks),
        Err(FieldError::NonExhaustiveOrOverlappingClassification)
    );
    let mut masks = good.masks;
    masks.read_stored &= !sctlr::M;
    masks.read_zero |= sctlr::M;
    assert_eq!(
        RegisterPolicy::checked(Register::SctlrEl1, facts(), provenance(), masks),
        Err(FieldError::InconsistentStorageClassification)
    );
}

#[test]
fn private_constant_readback_policy_validates_initial_state_and_ignores_only_selected_bits() {
    let mut masks = policy(Register::SctlrEl1).masks;
    masks.read_stored &= !(sctlr::M | sctlr::C);
    masks.read_zero = sctlr::M;
    masks.read_one = sctlr::C;
    masks.write_stored &= !(sctlr::M | sctlr::C);
    masks.write_ignored = sctlr::M | sctlr::C;
    let policy = RegisterPolicy::checked(Register::SctlrEl1, facts(), provenance(), masks).unwrap();
    assert_eq!(
        policy.validate_initial(sctlr::M),
        Err(FieldError::InvalidInitialReadback {
            register: Register::SctlrEl1,
            bits: sctlr::M | sctlr::C,
        })
    );
    assert!(policy.apply(sctlr::M, 0).is_err());
    let result = policy.apply(sctlr::C, sctlr::M | sctlr::A).unwrap();
    assert_eq!(result.readback, sctlr::C | sctlr::A);
}
