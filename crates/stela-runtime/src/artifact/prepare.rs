//! Byte and metadata validation shared by hosted cache and boot artifact intake.
//! Inputs are descriptive data. These checks mint no source, PE or RX authority.
//! Expected identity/requirements still come from the SAME CompilationPlan and
//! actual source owner. JSON decoding and source-map geometry remain original.
use super::{ArtifactError, Identity, Manifest, validate_native_snapshot};
use stela_compiler::context::memory::MemoryRequirements;

pub(crate) const MAX_CACHE_NATIVE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_CACHE_MANIFEST_BYTES: usize = 64 * 1024 * 1024;

/// Validate exact serialized manifest bytes before the existing codec decodes
/// them. This checksum does not associate a separately supplied typed Manifest
/// with those bytes; the actual byte provider must retain that codec association.
pub(crate) fn validate_manifest_bytes(
    manifest_bytes: &[u8],
    expected_sha256: &str,
) -> Result<(), ArtifactError> {
    if manifest_bytes.len() > MAX_CACHE_MANIFEST_BYTES {
        return Err(ArtifactError("cache file exceeds size limit"));
    }
    if stela_core::sha256(manifest_bytes) != expected_sha256 {
        return Err(ArtifactError("cached manifest checksum mismatch"));
    }
    Ok(())
}

/// Validate the actual decoded metadata BEFORE opening/reading native bytes.
/// This preserves the original hosted refusal and I/O order. It neither decodes
/// source nor chooses an ABI/profile; the original compiler/source owner does.
pub(crate) fn validate_preparation_metadata(
    manifest: &Manifest,
    identity: &Identity,
    memory_requirements: Option<MemoryRequirements>,
) -> Result<(), ArtifactError> {
    if manifest.memory_requirements != memory_requirements {
        return Err(ArtifactError(
            "cached memory requirements differ from freshly decoded source",
        ));
    }
    if manifest.identity != *identity {
        return Err(ArtifactError(
            "cached source/compiler/ABI identity mismatch",
        ));
    }
    if manifest.native_bytes == 0 || manifest.native_bytes > MAX_CACHE_NATIVE_BYTES {
        return Err(ArtifactError("invalid cached native code size"));
    }
    Ok(())
}

/// Bind exact bounded native bytes through the ORIGINAL snapshot validator.
/// The caller retains the original "cached native code checksum mismatch"
/// context for this function's native-snapshot error. Verified metadata is
/// checked separately afterwards, preserving the original error ordering.
pub(crate) fn validate_preparation_native(
    manifest: &Manifest,
    native: &[u8],
) -> Result<(), ArtifactError> {
    if native.len() > MAX_CACHE_NATIVE_BYTES {
        return Err(ArtifactError("cache file exceeds size limit"));
    }
    validate_native_snapshot(manifest, native)
}

pub(crate) fn validate_preparation_claim(manifest: &Manifest) -> Result<(), ArtifactError> {
    if manifest.verified {
        return Err(ArtifactError(
            "cache metadata cannot attest to verification",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec};
    use stela_compiler::GuestAddress;

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
        // Descriptive cache fixture only; these bytes are never mapped/executed.
        let native = b"immutable original native snapshot";
        let manifest = Manifest {
            identity: identity.clone(),
            native_sha256: stela_core::sha256(native),
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
        validate_manifest_bytes(serialized, &stela_core::sha256(serialized)).unwrap();
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
}
