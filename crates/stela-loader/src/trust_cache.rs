//! Boot trust caches as iBoot delivers them in `/chosen/memory-map/TrustCache`.
//!
//! Public XNU `bsd/sys/trust_caches.h` at `xnu-12377.121.6` defines the
//! region as `trust_cache_offsets_t { u32 num_caches; u32 offsets[]; }`
//! followed by the modules, each offset counted from the start of the region;
//! `bsd/kern/kern_trustcache.c` `load_static_trust_cache` loads module 0 as
//! the static trust cache. A module is the plaintext payload of a `trst`
//! IM4P: `u32 version`, a 16-byte UUID, `u32 count` and fixed-size entries.
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;

const HEADER_BYTES: usize = 4 + 16 + 4;
/// Module placement inside the composed region.
const MODULE_ALIGNMENT: usize = 16;

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
        other => bail!("unsupported trust cache module version {other}"),
    })
}

/// Validate one module and describe it; its extent must be exact.
pub fn inspect_module(module: &[u8]) -> Result<ModuleSummary> {
    ensure!(
        module.len() >= HEADER_BYTES,
        "trust cache module is truncated"
    );
    let version = u32::from_le_bytes(module[0..4].try_into()?);
    let entries = u32::from_le_bytes(module[20..24].try_into()?);
    let expected = (entries as usize)
        .checked_mul(entry_bytes(version)?)
        .and_then(|n| n.checked_add(HEADER_BYTES))
        .context("trust cache module size overflows")?;
    ensure!(
        module.len() == expected,
        "trust cache module is {} bytes; its header describes {expected}",
        module.len()
    );
    Ok(ModuleSummary {
        version,
        uuid: hex::encode(&module[4..20]),
        entries,
        bytes: module.len(),
    })
}

/// Compose the boot trust cache region; the first module is the static one.
pub fn compose(modules: &[&[u8]]) -> Result<Vec<u8>> {
    ensure!(
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
        let offset = u32::try_from(out.len()).context("trust cache region is too large")?;
        out[4 + 4 * index..8 + 4 * index].copy_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(module);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(u32::from_le_bytes(region[0..4].try_into()?), 2);
        let offsets = [
            u32::from_le_bytes(region[4..8].try_into()?) as usize,
            u32::from_le_bytes(region[8..12].try_into()?) as usize,
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
    fn rejects_unknown_versions_and_inexact_extents() {
        assert!(inspect_module(&module(3, 0)).is_err());
        let mut long = module(2, 1);
        long.push(0);
        assert!(inspect_module(&long).is_err());
        assert!(compose(&[]).is_err());
    }
}
