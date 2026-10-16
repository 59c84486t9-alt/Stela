//! Mach-O loading: slice selection, load plans, chained fixups, exports,
//! dependency discovery and image mappings, plus the restore-image formats
//! the kernel boot hand-off consumes.
pub mod apple_device_tree;
pub mod boot_args;
pub mod boot_bundle;
pub mod chained_fixups;
pub mod dependency_graph;
pub mod dependency_paths;
pub mod exports;
pub mod im4m;
pub mod im4p;
pub mod inventory;
pub mod kernel_collection;
pub mod linked_images;
pub mod load_plan;
pub mod mapped_image;
mod thread_state;
pub mod trust_cache;
use anyhow::{Context, Result, ensure};
use inventory::{Artifact, Inventory, ScanIssue};
use object::{Object, ObjectSection};
use std::{fs::File, io::Read, path::Path};
use stela_runtime::sha256;

fn slice(data: &[u8], offset: u64, size: u64) -> Result<&[u8]> {
    let start = usize::try_from(offset)?;
    let end = usize::try_from(offset.checked_add(size).context("slice range overflow")?)?;
    data.get(start..end)
        .context("Mach-O slice is out of bounds")
}

fn integer(data: &[u8], start: usize, width: usize, little: bool) -> Result<u64> {
    let bytes = data
        .get(start..start + width)
        .context("truncated fat header")?;
    let mut padded = [0u8; 8];
    if little {
        padded[..width].copy_from_slice(bytes);
        Ok(u64::from_le_bytes(padded))
    } else {
        padded[8 - width..].copy_from_slice(bytes);
        Ok(u64::from_be_bytes(padded))
    }
}

fn artifact(data: &[u8], path: &str, offset: u64) -> Result<Artifact> {
    let file = object::File::parse(data)?;
    ensure!(
        file.format() == object::BinaryFormat::MachO,
        "not a Mach-O slice"
    );
    let architecture = match file.architecture() {
        object::Architecture::Aarch64 => {
            // cpu_subtype's high byte contains capability flags.
            let subtype = integer(data, 8, 4, file.is_little_endian())? as u32 & 0x00ff_ffff;
            match subtype {
                0 => "arm64".to_owned(),
                2 => "arm64e".to_owned(),
                // LLVM MachO.h 4a0a7e3ddc3b: CPU_SUBTYPE_ARM64E_X1.
                // Naming this slice does not admit it to the execution profile.
                12 => "arm64e.x1".to_owned(),
                other => format!("arm64-subtype-{other}"),
            }
        }
        object::Architecture::X86_64 => "x86_64".to_owned(),
        other => format!("{other:?}"),
    };
    let text_bytes = file
        .sections()
        .filter(|s| s.kind() == object::SectionKind::Text)
        .map(|s| s.size())
        .sum();
    let hash = sha256(data);
    let id = sha256(format!("{path}\0{offset}\0{hash}").as_bytes());
    Ok(Artifact {
        id,
        path: path.into(),
        sha256: hash,
        architecture,
        slice_offset: offset,
        text_bytes,
    })
}

fn is_macho(data: &[u8]) -> bool {
    matches!(
        data.get(..4),
        Some(
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe]
                | [0xbe, 0xba, 0xfe, 0xca]
                | [0xca, 0xfe, 0xba, 0xbf]
                | [0xbf, 0xba, 0xfe, 0xca]
        )
    )
}

pub fn split_slices(data: &[u8]) -> Result<Vec<(u64, &[u8])>> {
    let magic = data
        .get(..4)
        .context("file is shorter than a Mach-O magic")?;
    let fat = match magic {
        [0xca, 0xfe, 0xba, 0xbe] => Some((false, false)),
        [0xbe, 0xba, 0xfe, 0xca] => Some((true, false)),
        [0xca, 0xfe, 0xba, 0xbf] => Some((false, true)),
        [0xbf, 0xba, 0xfe, 0xca] => Some((true, true)),
        _ => None,
    };
    let Some((little, wide)) = fat else {
        return Ok(vec![(0, data)]);
    };
    let count = integer(data, 4, 4, little)? as usize;
    let stride = if wide { 32 } else { 20 };
    ensure!(count > 0 && count <= 128, "invalid fat slice count");
    ensure!(8 + count * stride <= data.len(), "truncated fat table");
    let mut ranges = vec![];
    let mut slices = vec![];
    for i in 0..count {
        let start = 8 + i * stride;
        let offset = integer(data, start + 8, if wide { 8 } else { 4 }, little)?;
        let size = integer(
            data,
            start + if wide { 16 } else { 12 },
            if wide { 8 } else { 4 },
            little,
        )?;
        let end = offset.checked_add(size).context("fat range overflow")?;
        ensure!(
            offset >= (8 + count * stride) as u64 && size > 0,
            "fat slice overlaps header or is empty"
        );
        ensure!(
            ranges.iter().all(|&(a, b)| end <= a || offset >= b),
            "fat slices overlap"
        );
        ranges.push((offset, end));
        slices.push((offset, slice(data, offset, size)?));
    }
    Ok(slices)
}

pub fn inspect(data: &[u8], path: &str) -> Result<Vec<Artifact>> {
    split_slices(data)?
        .into_iter()
        .map(|(offset, bytes)| artifact(bytes, path, offset))
        .collect()
}

pub fn scan(root: &Path, build: &str) -> Result<Inventory> {
    ensure!(
        root.is_dir(),
        "inventory requires an extracted filesystem directory"
    );
    ensure!(!build.trim().is_empty(), "build must not be empty");
    let root = root.canonicalize()?;
    let mut inventory = Inventory {
        schema_version: 1,
        build: build.into(),
        root: root.display().to_string(),
        artifacts: vec![],
        issues: vec![],
        excluded_containers: vec![],
    };
    for entry in walkdir::WalkDir::new(&root)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                inventory.issues.push(ScanIssue {
                    path: error
                        .path()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                    reason: error.to_string(),
                });
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry
            .path()
            .strip_prefix(&root)?
            .to_string_lossy()
            .into_owned();
        let result = (|| -> Result<()> {
            let mut file = File::open(entry.path())?;
            let mut header = [0u8; 16];
            let n = file.read(&mut header)?;
            if header[..n].starts_with(b"dyld_v")
                || matches!(
                    entry.path().extension().and_then(|s| s.to_str()),
                    Some("kc" | "im4p" | "img4" | "dmg" | "ipsw")
                )
                || entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("kernelcache")
            {
                inventory.excluded_containers.push(ScanIssue { path: path.clone(), reason: "container requires a dedicated extractor; excluded from translation denominator".into() });
            } else if is_macho(&header[..n]) {
                let data = std::fs::read(entry.path())?;
                inventory.artifacts.extend(inspect(&data, &path)?);
            }
            Ok(())
        })();
        if let Err(error) = result {
            inventory.issues.push(ScanIssue {
                path,
                reason: format!("{error:#}"),
            });
        }
    }
    Ok(inventory)
}

/// The single arm64/arm64e slice of `data`, optionally narrowed by architecture.
pub fn select_slice<'a>(
    data: &'a [u8],
    path: &std::path::Path,
    architecture: Option<&str>,
) -> Result<(u64, &'a [u8])> {
    let artifacts = inspect(data, &path.display().to_string())?;
    let slices = split_slices(data)?;
    let selected: Vec<_> = artifacts
        .iter()
        .zip(slices)
        .filter(|(artifact, _)| {
            matches!(artifact.architecture.as_str(), "arm64" | "arm64e")
                && architecture.is_none_or(|wanted| wanted == artifact.architecture)
        })
        .collect();
    ensure!(
        selected.len() == 1,
        "expected exactly one matching Apple executable slice, found {}; select --architecture arm64 or arm64e",
        selected.len()
    );
    Ok(selected[0].1)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn thin(cpu: u32, subtype: u32) -> Vec<u8> {
        let mut data = vec![];
        for value in [0xfeedfacf, cpu, subtype, 2, 0, 0, 0, 0] {
            data.extend(value.to_le_bytes());
        }
        data
    }
    #[test]
    fn reads_arm64e_and_fat_slices_and_rejects_bad_ranges() -> Result<()> {
        let arm = thin(0x0100000c, 0x80000002);
        assert_eq!(inspect(&arm, "arm")?[0].architecture, "arm64e");
        let intel = thin(0x01000007, 3);
        let mut fat = vec![];
        for value in [
            0xcafebabeu32,
            2,
            0x0100000c,
            2,
            48,
            32,
            0,
            0x01000007,
            3,
            80,
            32,
            0,
        ] {
            fat.extend(value.to_be_bytes());
        }
        fat.extend(arm);
        fat.extend(intel);
        let slices = inspect(&fat, "universal")?;
        assert_eq!(slices.len(), 2);
        assert_eq!(slices[1].architecture, "x86_64");
        fat[36..40].copy_from_slice(&4096u32.to_be_bytes());
        assert!(inspect(&fat, "broken").is_err());
        Ok(())
    }
    #[test]
    fn new_apple_subtypes_are_named_without_becoming_baseline_execution() -> Result<()> {
        for (subtype, label) in [(0x8000000c, "arm64e.x1"), (0x8000007f, "arm64-subtype-127")] {
            let bytes = thin(0x0100000c, subtype);
            assert_eq!(inspect(&bytes, "own-subtype")?[0].architecture, label);
            assert!(
                matches!(load_plan::plan(&bytes), Err(load_plan::PlanError::UnsupportedCpu { cpu_subtype, .. }) if cpu_subtype == subtype)
            );
        }
        Ok(())
    }
    #[test]
    fn containers_and_parse_errors_are_visible() -> Result<()> {
        let root = tempfile::tempdir()?;
        std::fs::write(
            root.path().join("dyld_shared_cache_arm64e"),
            b"dyld_v1 arm64e",
        )?;
        std::fs::write(root.path().join("broken"), [0xcf, 0xfa, 0xed, 0xfe])?;
        let inv = scan(root.path(), "test")?;
        assert_eq!(inv.issues.len(), 1);
        assert_eq!(inv.excluded_containers.len(), 1);
        Ok(())
    }
}
