use super::*;
use crate::coprocessor::{
    configuration::tests::{config_policy, provenance},
    tests::{fixture, prepare, w32, w64},
};
use anyhow::Result;

fn original(width: Width) -> Vec<u8> {
    let mut b = fixture();
    b[0x1200..0x1230].fill(0);
    for (at, tag, bytes) in [(0x1200, ADDRESS, 8), (0x1210, LENGTH, 4)] {
        w32(&mut b, at, tag);
        w32(&mut b, at + 4, bytes);
    }
    w64(&mut b, 32 + 232 + 40, 28);
    w64(&mut b, 0x1208, 0x800);
    w32(&mut b, 0x1218, (HEADER_BYTES + 4 * width.bytes()) as u32);
    b[0x1800..0x1808].copy_from_slice(&[
        1,
        2 + u8::from(width == Width::Bits64),
        4,
        0,
        0xff,
        0xff,
        0xff,
        0xff,
    ]);
    b[0x1808..0x1808 + 4 * width.bytes()].fill(0x71);
    b
}
fn input(width: Width) -> Result<Input> {
    Ok(Input {
        native_override: Override::Absent(provenance()),
        compiled: Tables {
            provenance: provenance(),
            primary: Some(source::tests::table(width)?),
            additional: [
                Phase {
                    enabled: Some(false),
                    provenance: provenance(),
                    table: Some(source::tests::table(width)?),
                },
                Phase {
                    enabled: Some(true),
                    provenance: provenance(),
                    table: Some(source::tests::table(width)?),
                },
            ],
        },
    })
}
#[test]
fn tuning_changes_only_target_records_count_and_configuration_hash() -> Result<()> {
    for width in [Width::Bits32, Width::Bits64] {
        let b = original(width);
        let p = prepare(&b)?;
        let policy = config_policy(p.plan());
        let staged = p.stage(0x800000, 0x3000)?;
        let original = staged.bytes().to_vec();
        let proposal = staged.tuning_proposal(input(width)?)?;
        assert_eq!(proposal.receipt().entries, 2);
        assert_eq!(staged.bytes(), original);
        let configured = staged.configure(policy)?.apply_tuning(proposal)?;
        configured.validate_tuning()?;
        let raw = configured.bytes();
        assert_eq!(raw[0x803], 2);
        assert_eq!(&raw[0x804..0x808], &[0xff; 4]);
        assert_eq!(&raw[0x808..0x80c], &0x124u32.to_le_bytes());
        assert_eq!(&raw[..0x800], &original[..0x800]);
        assert_eq!(
            &raw[0x808 + 2 * width.bytes()..],
            &original[0x808 + 2 * width.bytes()..]
        );
        assert!(configured.receipt().tuning.is_some());
        assert_ne!(
            configured.receipt().configured_sha256,
            configured.placement().staged_sha256
        );
        assert_eq!(configured.receipt().configured_sha256, sha256(raw));
    }
    Ok(())
}
#[test]
fn format_capacity_source_and_cold_chain_overlap_refuse() -> Result<()> {
    for case in 0..10 {
        let mut b = original(Width::Bits64);
        match case {
            0 => b[0x1800] = 2,
            1 => b[0x1801] = 1,
            2 => b[0x1802] = 0,
            3 => b[0x1802] = 255,
            4 => w64(&mut b, 0x1208, 0x1000), // unmapped gap
            5 => w64(&mut b, 0x1208, 0x2000), // original encoded chains
            6 => w64(&mut b, 0x1208, 0x200),  // patchbay itself
            7 => b[0x1802] = 1,
            _ => (),
        }
        let s = prepare(&b)?.stage(0x800000, 0x3000)?;
        let mut policy = input(Width::Bits64)?;
        if case == 8 {
            policy.native_override = Override::Required(provenance());
        }
        if case == 9 {
            policy.compiled.additional[0].enabled = None;
        }
        assert!(s.tuning_proposal(policy).is_err(), "case {case}");
    }
    let s = prepare(&original(Width::Bits64))?.stage(0x800000, 0x3000)?;
    assert!(s.tuning_proposal(input(Width::Bits32)?).is_err());
    Ok(())
}
#[test]
fn join_rejects_stale_role_scalar_and_target_without_publishing_a_mutation() -> Result<()> {
    let b = original(Width::Bits64);
    for case in 0..4 {
        let p = prepare(&b)?;
        let mut policy = config_policy(p.plan());
        let s = p.stage(0x800000, 0x3000)?;
        let mut proposal = s.tuning_proposal(input(Width::Bits64)?)?;
        match case {
            0 => proposal.receipt.hardware.role = "other".into(),
            1 => {
                policy.fields[0].action =
                    super::super::Action::Replace(0x804u64.to_le_bytes().to_vec())
            }
            2 => proposal.receipt.original_target_sha256 = "3".repeat(64),
            _ => proposal.receipt.original_staged_sha256 = "3".repeat(64),
        }
        assert!(s.configure(policy)?.apply_tuning(proposal).is_err());
    }
    Ok(())
}

#[test]
fn publication_requires_prepared_tuning_and_detects_later_byte_changes() -> Result<()> {
    use crate::coprocessor::publication::tests::publication_policy;
    let b = original(Width::Bits64);
    let p = prepare(&b)?;
    let policy = config_policy(p.plan());
    let s = p.stage(0x800000, 0x3000)?;
    let proposal = s.tuning_proposal(input(Width::Bits64)?)?;
    let c = s.configure(policy)?;
    assert!(c.publication_proposal(publication_policy(&c)).is_err());
    let mut c = c.apply_tuning(proposal)?;
    c.publication_proposal(publication_policy(&c))?;
    c.staged.bytes[0x808] ^= 1;
    assert!(c.publication_proposal(publication_policy(&c)).is_err());
    Ok(())
}

#[test]
#[ignore = "oracle: STELA_COPROCESSOR_FIXTURE_DIR, STELA_COPROCESSOR_IBOOT_FIXTURE"]
#[cfg(feature = "std")]
fn original_t6000_tuning_tables_prepare_complete_bounded_mutation() -> Result<()> {
    use crate::{
        boot_bundle::Source,
        coprocessor::{HardwareIdentity, Limits, prepare_im4p},
    };
    let dir = std::env::var("STELA_COPROCESSOR_FIXTURE_DIR")?;
    let iboot = std::fs::read(std::env::var("STELA_COPROCESSOR_IBOOT_FIXTURE")?)?;
    assert_eq!(
        sha256(&iboot),
        "20dfa3a5e6d4e4b2844c7558e6d4f8ab74397d11eae63312f00a559cf9612b03"
    );
    let claim = |at: usize, bytes: usize| Provenance {
        input_sha256: sha256(&iboot),
        coordinates: alloc::format!("original iBoot file {at:#x}+{bytes:#x}"),
        span_sha256: sha256(&iboot[at..at + bytes]),
    };
    let container = std::fs::read(std::path::Path::new(&dir).join("t600xdcp_restore.im4p"))?;
    let source = Source {
        component: "RestoreDCP".into(),
        member: "Firmware/dcp/t600xdcp_restore.im4p".into(),
        container_sha256: "9a071477954b6888a98fb801a1112ba8be4ff1dfe4f6fe84dc57580fa941ccb9".into(),
        payload_type: "dcpf".into(),
        description: "1".into(),
        decoded_bytes: 11685888,
        decoded_sha256: "976b952c0e36d34af7912b115feef2d3982053133055bb93bcbca54a423f0a10".into(),
    };
    let mut outputs = Vec::new();
    // Threshold branches are source fixtures, not a physical revision claim.
    for revision in [0x10, 0x20] {
        let p = prepare_im4p(
            &container,
            source.clone(),
            "26A434".into(),
            HardwareIdentity {
                role: "DCPEXT0".into(),
                compatible: "iop,ascwrap-v4".into(),
            },
            Limits::default(),
        )?;
        let mut policy = config_policy(p.plan()); // Mechanism test, not complete native cold policy.
        let image_bytes = p.plan().image_bytes;
        let s = p.stage(0x9000_0000, image_bytes)?;
        let embedded = s.embedded_arguments(claim(0x153288, 0x214))?;
        assert_eq!(embedded.native_length, 0);
        *policy
            .fields
            .iter_mut()
            .find(|f| f.tag == u32::from_be_bytes(*b"bArg"))
            .unwrap() = embedded.field;
        let slide = s.cold_slide_proposal(
            crate::coprocessor::configuration::native::tests::slide_input(0x40, 0),
        )?;
        *policy
            .fields
            .iter_mut()
            .find(|f| f.tag == u32::from_be_bytes(*b"SLID"))
            .unwrap() = slide.field(claim(0x1538a4, 0x15c))?;
        let original_chains = s
            .plan()
            .chains
            .pointers
            .iter()
            .map(|p| (p.image_offset, p.raw))
            .collect::<Vec<_>>();
        let table = Table::select(
            &iboot,
            source::Input {
                image_base: 0x102_0000_0000,
                groups_file_offset: 0x183020,
                groups: 13,
                kind: 1,
                hardware_id: 0x37,
                revision,
                source_provenance: claim(0x183020, 13 * 0x38),
                hardware_provenance: claim(0x1fbf60, 0x1a8),
                filter: source::Filter::Absent(claim(0x13533c, 8)),
            },
            Width::Bits64,
        )?;
        let proposal = s.tuning_proposal(Input {
            native_override: Override::Absent(claim(0x1351b8, 20)),
            compiled: Tables {
                provenance: claim(0x113954, 0x1cc),
                primary: table,
                additional: [
                    Phase {
                        enabled: None,
                        provenance: claim(0x1d1d10, 40),
                        table: None,
                    },
                    Phase {
                        enabled: None,
                        provenance: claim(0x1d1d38, 40),
                        table: None,
                    },
                ],
            },
        })?;
        assert_eq!(proposal.receipt().entries, 21);
        assert_eq!(proposal.receipt().capacity, 24);
        let c = s.configure_cold(policy, slide)?.apply_tuning(proposal)?;
        let publication = crate::coprocessor::publication::Policy {
            allocation_owner: "synthetic original-fixture allocation".into(),
            mapping_owner: "synthetic original-fixture remap".into(),
            configured_sha256: c.receipt().configured_sha256.clone(),
            segments: c
                .plan()
                .segments
                .iter()
                .map(|s| crate::coprocessor::publication::SegmentPolicy {
                    name: s.segment.name.clone(),
                    action: if s.segment.vm_size == 0 {
                        crate::coprocessor::publication::Action::Omit
                    } else {
                        crate::coprocessor::publication::Action::Publish {
                            iop_remap: s.segment.vm_address,
                            raw_flags: if s.segment.name == "__OS_LOG" { 2 } else { 0 },
                        }
                    },
                    provenance: claim(0x10e568, 0x20c),
                })
                .collect(),
        };
        // Real source flags and metadata; mapping coordinates remain a fixture.
        let (c, publication) = c.finalize_cold_mappings(
            publication,
            crate::coprocessor::configuration::finalization::Input {
                descriptor_flags: iboot[0x196298 + 0x265],
                provenance: claim(0x196298, 0x268),
            },
        )?;
        assert_eq!(
            c.receipt().finalization.as_ref().unwrap().metadata_records,
            [0x1244]
        );
        assert!(c.receipt().finalization.as_ref().unwrap().writes.is_empty());
        c.publication_proposal(publication)?;
        assert!(c.bytes()[0x9624e8..0x9628e8].iter().all(|&b| b == 0));
        let argument = c
            .receipt()
            .fields
            .iter()
            .find(|f| f.tag == u32::from_be_bytes(*b"bArg"))
            .unwrap();
        assert!(matches!(
            argument.decision,
            crate::coprocessor::configuration::Decision::Preserve
        ));
        assert!(!argument.changed);
        let tuned = &c.bytes()[0x962c2a..0x962c2a + 0x1e8];
        assert_eq!(&tuned[..8], &[1, 3, 24, 21, 0xff, 0xff, 0xff, 0xff]);
        assert!(tuned[8 + 21 * 20..].iter().all(|&b| b == 0));
        assert_eq!(&tuned[8..12], &0x51c18u32.to_le_bytes());
        for (offset, raw) in original_chains {
            assert_eq!(
                &c.bytes()[offset as usize..offset as usize + 8],
                &raw.to_le_bytes()
            );
        }
        outputs.push(sha256(tuned));
    }
    assert_eq!(outputs[0], outputs[1]);
    assert_eq!(
        outputs[0],
        "7d9e1ad33f9eaaac71d28d9c92982c23f521b236c3bf1d86f28dabb280fafba4"
    );
    Ok(())
}
