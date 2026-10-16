use super::*;
use alloc::{string::ToString, vec};
use stela_compiler::GuestAddress;

#[test]
fn generated_artifact_preserves_the_original_compilation_plan() -> anyhow::Result<()> {
    use stela_compiler::{
        TargetCpu,
        block::{BlockProfile, CompilationPlan},
    };
    let source: alloc::vec::Vec<u8> = [0x9100_1c00u32, 0xd65f_03c0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    let base = GuestAddress(0x1000);
    let plan = CompilationPlan::new(&source, base, BlockProfile::Ordinary, TargetCpu::Baseline)?;
    let identity = crate::block_plan_identity(&source, base, TargetCpu::Baseline, &plan)?;
    let requirements = plan.memory_requirements();
    let original =
        CompilationPlan::new(&source, base, BlockProfile::Ordinary, TargetCpu::Baseline)?
            .compile()?
            .native;
    let calls = core::cell::Cell::new(0);
    let (manifest, native) = generate(identity.clone(), requirements, || {
        calls.set(calls.get() + 1);
        plan.compile().map(|compiled| compiled.native)
    })?;
    assert_eq!(calls.get(), 1);
    assert_eq!(native, original.x86_64_code);
    assert_eq!(manifest.source_map, original.source_map);
    assert!(!manifest.verified);
    validate_preparation_metadata(&manifest, &identity, requirements)?;
    validate_preparation_native(&manifest, &native)?;
    validate_preparation_claim(&manifest)?;
    Ok(())
}

#[test]
fn empty_generation_cannot_publish_a_successful_manifest() {
    let (identity, _, _) = fixture();
    assert!(
        generate(identity, None, || Ok(stela_compiler::NativeBlock {
            x86_64_code: vec![],
            source_map: vec![],
        }))
        .is_err()
    );
}

fn fixture() -> (Identity, Manifest, &'static [u8]) {
    let identity = Identity {
        schema_version: 1,
        source_sha256: "source digest".into(),
        compiler_source_sha256: "compiler digest".into(),
        guest_base: 0x1000,
        abi: "context block ABI".into(),
        target_cpu: "x86 baseline".into(),
        memory_specialization_sha256: None,
    };
    // These bytes are never mapped or executed.
    let native = b"immutable original native snapshot";
    let manifest = Manifest {
        identity: identity.clone(),
        native_sha256: crate::sha256(native),
        native_bytes: native.len(),
        source_map: vec![(GuestAddress(0x1000), 0)],
        verified: false,
        memory_requirements: Some(MemoryRequirements::default()),
    };
    (identity, manifest, native)
}

#[test]
fn shared_validation_accepts_original_descriptive_inputs() {
    let (identity, manifest, native) = fixture();
    let serialized = b"original serialized manifest bytes";
    validate_manifest_bytes(serialized, &crate::sha256(serialized)).unwrap();
    validate_preparation_metadata(&manifest, &identity, manifest.memory_requirements).unwrap();
    validate_preparation_native(&manifest, native).unwrap();
    validate_preparation_claim(&manifest).unwrap();
}

#[test]
fn fresh_requirements_distinguish_absence_from_checked_empty_body() {
    let (identity, manifest, _) = fixture();
    let error = validate_preparation_metadata(&manifest, &identity, None).unwrap_err();
    assert_eq!(
        error.to_string(),
        "cached memory requirements differ from freshly decoded source"
    );
}

#[test]
fn every_identity_field_remains_bound() {
    let (identity, manifest, _) = fixture();
    let mut changed = [
        identity.clone(),
        identity.clone(),
        identity.clone(),
        identity.clone(),
        identity.clone(),
        identity.clone(),
        identity,
    ];
    changed[0].schema_version += 1;
    changed[1].source_sha256.push('x');
    changed[2].compiler_source_sha256.push('x');
    changed[3].guest_base += 4;
    changed[4].abi.push('x');
    changed[5].target_cpu.push('x');
    changed[6].memory_specialization_sha256 = Some("changed specialization digest".into());
    for identity in changed {
        let error =
            validate_preparation_metadata(&manifest, &identity, manifest.memory_requirements)
                .unwrap_err();
        assert_eq!(
            error.to_string(),
            "cached source/compiler/ABI identity mismatch"
        );
    }
}

#[test]
fn metadata_native_size_is_checked_before_bytes() {
    let (identity, mut manifest, _) = fixture();
    for bytes in [0, MAX_CACHE_NATIVE_BYTES + 1] {
        manifest.native_bytes = bytes;
        let error =
            validate_preparation_metadata(&manifest, &identity, manifest.memory_requirements)
                .unwrap_err();
        assert_eq!(error.to_string(), "invalid cached native code size");
    }
}

#[test]
fn checksums_and_verification_claims_remain_separate_refusals() {
    let (_, mut manifest, native) = fixture();
    let error = validate_manifest_bytes(b"changed manifest", "wrong digest").unwrap_err();
    assert_eq!(error.to_string(), "cached manifest checksum mismatch");
    let error = validate_preparation_native(&manifest, b"changed native").unwrap_err();
    assert_eq!(error.to_string(), "native snapshot checksum mismatch");
    manifest.verified = true;
    validate_preparation_native(&manifest, native).unwrap();
    let error = validate_preparation_claim(&manifest).unwrap_err();
    assert_eq!(
        error.to_string(),
        "cache metadata cannot attest to verification"
    );
}
