//! Boot trust caches as iBoot delivers them in `/chosen/memory-map/TrustCache`.
//!
//! Public XNU `bsd/sys/trust_caches.h` at `xnu-12377.121.6` defines the
//! region as `trust_cache_offsets_t { u32 num_caches; u32 offsets[]; }`
//! followed by the modules, each offset counted from the start of the region;
//! `bsd/kern/kern_trustcache.c` `load_static_trust_cache` loads module 0 as
//! the static trust cache. A module is the plaintext payload of a `trst`
//! IM4P: `u32 version`, a 16-byte UUID, `u32 count` and fixed-size entries.
use crate::Result;
use alloc::{string::String, vec, vec::Vec};
use serde::Serialize;
use sha2::{Digest, Sha256};
use stela_contracts::{refuse, require};

const HEADER_BYTES: usize = 4 + 16 + 4;
/// Module placement inside the composed region.
const MODULE_ALIGNMENT: usize = 16;
/// `CS_HASHTYPE_SHA256`, the hash a signature's CDHash truncates.
const HASH_TYPE_SHA256: u8 = 2;

/// A code directory's identity in a trust cache.
pub type CodeHash = [u8; 20];

/// Read the complete hash list a kext's `TrustedCode` file carries.
pub fn code_hashes(bytes: &[u8]) -> Result<Vec<CodeHash>> {
    require!(
        bytes.len().is_multiple_of(size_of::<CodeHash>()),
        "trusted code hash list ends in a partial hash"
    );
    Ok(bytes.as_chunks::<{ size_of::<CodeHash>() }>().0.to_vec())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModuleSummary {
    pub version: u32,
    pub uuid: String,
    pub entries: u32,
    pub bytes: usize,
}

/// Entry width of each module version: version 1 entries are a 20-byte
/// CDHash, hash type and flags; version 2 adds a constraint category and a
/// reserved byte.
fn entry_bytes(version: u32) -> Result<usize> {
    Ok(match version {
        1 => 22,
        2 => 24,
        other => {
            return Err(refuse!("unsupported trust cache module version {other}", other).into());
        }
    })
}

/// Validate one module and describe it; its extent must be exact.
pub fn inspect_module(module: &[u8]) -> Result<ModuleSummary> {
    require!(
        module.len() >= HEADER_BYTES,
        "trust cache module is truncated"
    );
    let version = u32::from_le_bytes(module[0..4].try_into().unwrap());
    let entries = u32::from_le_bytes(module[20..24].try_into().unwrap());
    let expected = (entries as usize)
        .checked_mul(entry_bytes(version)?)
        .and_then(|n| n.checked_add(HEADER_BYTES))
        .ok_or(refuse!("trust cache module size overflows"))?;
    require!(
        module.len() == expected,
        "trust cache module is {module_len} bytes; its header describes {expected}",
        module_len = module.len(),
        expected
    );
    Ok(ModuleSummary {
        version,
        uuid: hex::encode(&module[4..20]),
        entries,
        bytes: module.len(),
    })
}

/// A version 2 module, the version Apple's boot modules use, trusting
/// `hashes` with no launch constraint. Lookups search a module's entries, so
/// they are sorted, and the UUID is their digest.
pub fn module(hashes: &[CodeHash]) -> Result<Vec<u8>> {
    let mut hashes = hashes.to_vec();
    hashes.sort_unstable();
    hashes.dedup();
    let count = u32::try_from(hashes.len()).map_err(|_| refuse!("too many trusted code hashes"))?;
    let mut digest = Sha256::new();
    for hash in &hashes {
        digest.update(hash);
    }
    let mut out = 2u32.to_le_bytes().to_vec();
    out.extend_from_slice(&digest.finalize()[..16]);
    out.extend_from_slice(&count.to_le_bytes());
    for hash in &hashes {
        out.extend_from_slice(hash);
        out.extend_from_slice(&[HASH_TYPE_SHA256, 0, 0, 0]);
    }
    Ok(out)
}

/// Compose the boot trust cache region; the first module is the static one.
pub fn compose(modules: &[&[u8]]) -> Result<Vec<u8>> {
    require!(
        !modules.is_empty(),
        "the boot trust cache region needs a module"
    );
    for module in modules {
        inspect_module(module)?;
    }
    let mut out = vec![];
    out.extend((modules.len() as u32).to_le_bytes());
    out.resize(4 + 4 * modules.len(), 0);
    for (index, module) in modules.iter().enumerate() {
        out.resize(out.len().next_multiple_of(MODULE_ALIGNMENT), 0);
        let offset =
            u32::try_from(out.len()).map_err(|_| refuse!("trust cache region is too large"))?;
        out[4 + 4 * index..8 + 4 * index].copy_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(module);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    fn module(version: u32, entries: u32) -> Vec<u8> {
        let mut out = version.to_le_bytes().to_vec();
        out.extend([0x11; 16]);
        out.extend(entries.to_le_bytes());
        out.resize(
            HEADER_BYTES + entries as usize * entry_bytes(version).unwrap_or(0),
            0xcd,
        );
        out
    }

    #[test]
    fn composes_offsets_from_the_region_start() -> Result<()> {
        let first = module(2, 3);
        let second = module(1, 1);
        let region = compose(&[&first, &second])?;
        assert_eq!(u32::from_le_bytes(region[0..4].try_into().unwrap()), 2);
        let offsets = [
            u32::from_le_bytes(region[4..8].try_into().unwrap()) as usize,
            u32::from_le_bytes(region[8..12].try_into().unwrap()) as usize,
        ];
        assert_eq!(offsets[0], 16);
        assert_eq!(
            &region[offsets[0]..offsets[0] + first.len()],
            first.as_slice()
        );
        assert_eq!(offsets[1] % MODULE_ALIGNMENT, 0);
        assert_eq!(&region[offsets[1]..], second.as_slice());
        assert_eq!(inspect_module(&first)?.entries, 3);
        Ok(())
    }

    #[test]
    fn a_built_module_is_sorted_and_exact() -> Result<()> {
        let built = super::module(&[[2; 20], [1; 20], [2; 20]])?;
        let summary = inspect_module(&built)?;
        assert_eq!((summary.version, summary.entries), (2, 2));
        assert_eq!(built[HEADER_BYTES..HEADER_BYTES + 20], [1; 20]);
        assert_eq!(built[HEADER_BYTES + 20], HASH_TYPE_SHA256);
        assert_eq!(built[HEADER_BYTES + 24..HEADER_BYTES + 44], [2; 20]);
        assert_eq!(built, super::module(&[[1; 20], [2; 20]])?);
        assert_ne!(built[4..20], super::module(&[[1; 20]])?[4..20]);
        Ok(())
    }

    #[test]
    fn trusted_code_requires_whole_hashes() -> Result<()> {
        assert!(code_hashes(&[])?.is_empty());
        assert_eq!(
            code_hashes(&[[1; 20], [2; 20]].concat())?,
            [[1; 20], [2; 20]]
        );
        for size in [1, 19, 21, 39, 41] {
            assert!(code_hashes(&vec![0; size]).is_err());
        }
        Ok(())
    }

    #[test]
    fn rejects_unknown_versions_and_inexact_extents() {
        assert!(inspect_module(&module(3, 0)).is_err());
        let mut long = module(2, 1);
        long.push(0);
        assert!(inspect_module(&long).is_err());
        assert!(compose(&[]).is_err());
    }
}
