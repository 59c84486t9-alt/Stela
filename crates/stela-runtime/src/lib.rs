//! First-launch AOT cache for the supported raw leaf-function subset.
//! Full application launch, Mach-O linking and dynamic code dispatch are future work.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use stela_compiler::{GuestAddress, NATIVE_ABI, NativeBlock};
use stela_core::{read_json, sha256, write_json};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub schema_version: u32,
    pub source_sha256: String,
    pub compiler_source_sha256: String,
    pub guest_base: u64,
    pub abi: String,
    pub target_cpu: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub identity: Identity,
    pub native_sha256: String,
    pub native_bytes: usize,
    pub source_map: Vec<(GuestAddress, usize)>,
    pub verified: bool,
}

#[derive(Debug, Serialize)]
pub struct Prepared {
    pub key: String,
    pub cache_hit: bool,
    pub directory: PathBuf,
    pub manifest: Manifest,
}

fn validate(directory: &Path, identity: &Identity) -> Result<Manifest> {
    let manifest_bytes = std::fs::read(directory.join("manifest.json"))?;
    let expected: String = read_json(&directory.join("manifest.sha256.json"))?;
    ensure!(
        sha256(&manifest_bytes) == expected,
        "cached manifest checksum mismatch"
    );
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
    ensure!(
        manifest.identity == *identity,
        "cached source/compiler/ABI identity mismatch"
    );
    let native = std::fs::read(directory.join("native.bin"))?;
    ensure!(
        native.len() == manifest.native_bytes && sha256(&native) == manifest.native_sha256,
        "cached native code checksum mismatch"
    );
    ensure!(
        !manifest.verified,
        "cache metadata cannot attest to verification"
    );
    Ok(manifest)
}

pub fn prepare_leaf(source: &[u8], base: GuestAddress, root: &Path) -> Result<Prepared> {
    let identity = Identity {
        schema_version: 1,
        source_sha256: sha256(source),
        compiler_source_sha256: sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
        guest_base: base.0,
        abi: NATIVE_ABI.into(),
        target_cpu: "x86_64-baseline".into(),
    };
    let key = sha256(&serde_json::to_vec(&identity)?);
    std::fs::create_dir_all(root)?;
    let root = root.canonicalize()?;
    let directory = root.join(&key);
    if directory.exists() {
        let manifest = validate(&directory, &identity)
            .context("refusing invalid cached translation; remove this cache entry to rebuild")?;
        return Ok(Prepared {
            key,
            cache_hit: true,
            directory,
            manifest,
        });
    }
    // Compile before creating an entry. Unsupported code never produces a hit.
    let NativeBlock {
        x86_64_code,
        source_map,
    } = stela_compiler::compile(source, base)?;
    let pending = tempfile::tempdir_in(&root)?;
    let manifest = Manifest {
        identity: identity.clone(),
        native_sha256: sha256(&x86_64_code),
        native_bytes: x86_64_code.len(),
        source_map,
        verified: false,
    };
    let path = pending.path().join("native.bin");
    std::fs::write(&path, &x86_64_code)?;
    std::fs::File::open(path)?.sync_all()?;
    write_json(&pending.path().join("manifest.json"), &manifest)?;
    let manifest_hash = sha256(&std::fs::read(pending.path().join("manifest.json"))?);
    write_json(&pending.path().join("manifest.sha256.json"), &manifest_hash)?;
    match std::fs::rename(pending.path(), &directory) {
        Ok(()) => Ok(Prepared {
            key,
            cache_hit: false,
            directory,
            manifest,
        }),
        Err(error) if directory.exists() => {
            let manifest = validate(&directory, &identity)
                .with_context(|| format!("concurrent cache publication failed: {error}"))?;
            Ok(Prepared {
                key,
                cache_hit: true,
                directory,
                manifest,
            })
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn source(value: u32) -> Vec<u8> {
        [0xd2800000 | (value << 5), 0xd65f03c0]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect()
    }
    #[test]
    fn reuses_only_exact_input_and_context_and_rejects_corruption() -> Result<()> {
        let root = tempfile::tempdir()?;
        let first = prepare_leaf(&source(40), GuestAddress(0x1000), root.path())?;
        assert!(!first.cache_hit);
        assert!(prepare_leaf(&source(40), GuestAddress(0x1000), root.path())?.cache_hit);
        assert_ne!(
            first.key,
            prepare_leaf(&source(41), GuestAddress(0x1000), root.path())?.key
        );
        assert_ne!(
            first.key,
            prepare_leaf(&source(40), GuestAddress(0x2000), root.path())?.key
        );
        std::fs::write(first.directory.join("native.bin"), b"changed")?;
        assert!(prepare_leaf(&source(40), GuestAddress(0x1000), root.path()).is_err());
        assert!(prepare_leaf(&[0, 0, 0, 0], GuestAddress(0), root.path()).is_err());
        Ok(())
    }
    #[test]
    fn concurrent_requests_publish_a_complete_single_entry() -> Result<()> {
        let root = tempfile::tempdir()?;
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let path = root.path().to_path_buf();
                std::thread::spawn(move || prepare_leaf(&source(42), GuestAddress(0), &path))
            })
            .collect();
        let results: Vec<_> = threads
            .into_iter()
            .map(|t| t.join().unwrap().unwrap())
            .collect();
        assert!(results.iter().all(|r| r.key == results[0].key));
        assert_eq!(std::fs::read_dir(root.path())?.count(), 1);
        Ok(())
    }
}
