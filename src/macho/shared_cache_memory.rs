//! Original cache VM ownership probe. Encoded pointers remain encoded.
//!
//! Read-only MAP_PRIVATE views test the original VM/file relationship, not
//! executable readiness. External source mutation/truncation is outside this
//! trusted, serialized acquisition experiment and can fault a host mapping.
use super::shared_cache::{file_identity, hash_file, same_file};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use stela_runtime::memory::{FileMemoryRegionSpec, OwnedMemory};
use std::{fs::File, fs::Metadata, path::Path};

fn number(value: &Value, field: &str) -> Result<u64> {
    value[field]
        .as_u64()
        .with_context(|| format!("missing cache field {field}"))
}

fn checked_file(value: &Value) -> Result<(File, Metadata)> {
    let path = Path::new(value["path"].as_str().context("missing cache path")?);
    let before = path.symlink_metadata()?;
    ensure!(
        before.is_file() && !before.file_type().is_symlink(),
        "cache mapping source must be an ordinary nonsymlink file"
    );
    ensure!(
        file_identity(&before) == value["source_identity"],
        "cache source identity changed since inventory"
    );
    let mut file = File::open(path)?;
    ensure!(
        same_file(&before, &file.metadata()?),
        "cache source changed while opening"
    );
    ensure!(
        hash_file(&mut file)? == value["source_sha256"],
        "cache mapping source bytes changed since inventory"
    );
    ensure!(
        same_file(&before, &file.metadata()?) && same_file(&before, &path.symlink_metadata()?),
        "cache source changed while hashing"
    );
    Ok((file, before))
}

fn slide_for(set: &Value, load_base: u64) -> Result<u64> {
    ensure!(
        set["kind"] == "dyld_shared_cache_set_manifest" && set["cache_set_files_verified"] == true,
        "cache mapping probe requires a verified original set"
    );
    let preferred = number(&set["files"][0]["header"], "shared_region_start")?;
    let region_bytes = number(&set["files"][0]["header"], "shared_region_bytes")?;
    ensure!(
        region_bytes > 0 && number(&set["files"][0]["mappings"][0], "address")? == preferred,
        "original shared region is empty or disagrees with the base mapping"
    );
    let region_end = preferred
        .checked_add(region_bytes)
        .context("shared region overflow")?;
    for mapping in set["combined_mappings"]
        .as_array()
        .context("missing combined mappings")?
    {
        let address = number(mapping, "address")?;
        ensure!(
            address >= preferred
                && address
                    .checked_add(number(mapping, "size")?)
                    .context("mapping extent overflow")?
                    <= region_end,
            "cache mapping exceeds original shared region"
        );
    }
    let slide = load_base
        .checked_sub(preferred)
        .context("cache base is below the original shared region")?;
    ensure!(
        load_base.is_multiple_of(16384) && slide.is_multiple_of(16384),
        "original Apple cache placement requires 16 KiB alignment"
    );
    ensure!(
        slide <= number(&set["files"][0]["header"], "maximum_slide")?,
        "cache slide exceeds the original declared ASLR range"
    );
    Ok(slide)
}

/// Inventory and briefly map the original set read-only, checking its VM views.
/// No fixups, authentication, image initialization or native code execute here.
///
/// # Safety
/// The input and every declared subcache inode must remain free of external
/// writes/truncation throughout this call. Hash/identity checks detect changes;
/// they do not lock the files or make concurrent file-backed access safe.
pub unsafe fn probe(input: &Path, load_base: Option<u64>) -> Result<Value> {
    let set = super::shared_cache::manifest_set(input)?;
    let preferred = number(&set["files"][0]["header"], "shared_region_start")?;
    // SAFETY: this function's caller establishes the source lifetime contract.
    unsafe { probe_set(&set, load_base.unwrap_or(preferred)) }
}

unsafe fn probe_set(set: &Value, load_base: u64) -> Result<Value> {
    let slide = slide_for(set, load_base)?;
    let sources = set["files"].as_array().context("cache set has no files")?;
    ensure!(
        !sources.is_empty() && sources.len() <= 256,
        "cache file limit"
    );
    let mut files = sources
        .iter()
        .map(checked_file)
        .collect::<Result<Vec<_>>>()?;
    let mappings = set["combined_mappings"]
        .as_array()
        .context("cache set has no mappings")?;
    ensure!(
        !mappings.is_empty() && mappings.len() <= 4096,
        "cache mapping count limit"
    );
    let mut specs = Vec::with_capacity(mappings.len());
    let mut mapped_bytes = 0u64;
    for mapping in mappings {
        let file_index = usize::try_from(number(mapping, "source_cache_index")?)?;
        let (file, _) = files
            .get(file_index)
            .context("invalid cache mapping source")?;
        let size = number(mapping, "size")?;
        mapped_bytes = mapped_bytes
            .checked_add(size)
            .context("cache size overflow")?;
        specs.push(FileMemoryRegionSpec {
            guest_address: number(mapping, "address")?
                .checked_add(slide)
                .context("cache mapped address overflow")?,
            virtual_bytes: size,
            file: file.try_clone()?,
            file_offset: number(mapping, "file_offset")?,
            readable: number(mapping, "initial_protection")? & 1 != 0,
            // Encoded data is deliberately read-only for this observation.
            writable: false,
            executable: number(mapping, "initial_protection")? & 4 != 0,
        });
    }
    // SAFETY: the caller guarantees stable original inodes throughout this
    // function. Source handles are retained; all mappings are read-only here.
    let memory = unsafe { OwnedMemory::map_files(specs)? };
    let mut samples = Vec::with_capacity(mappings.len() * 2);
    let mut sampled_bytes = 0u64;
    let mut sample_digest = Sha256::new();
    for mapping in mappings {
        let size = number(mapping, "size")?;
        let count = size.min(64);
        for relative in [0, size - count] {
            let address = number(mapping, "address")?
                .checked_add(relative)
                .and_then(|value| value.checked_add(slide))
                .context("cache sample address overflow")?;
            let file_index = usize::try_from(number(mapping, "source_cache_index")?)?;
            let file_offset = number(mapping, "file_offset")?
                .checked_add(relative)
                .context("cache sample file offset overflow")?;
            let mut expected = vec![0; usize::try_from(count)?];
            use std::io::{Read, Seek, SeekFrom};
            files[file_index].0.seek(SeekFrom::Start(file_offset))?;
            files[file_index].0.read_exact(&mut expected)?;
            let observed = memory.read_snapshot(address, expected.len())?;
            ensure!(observed == expected, "cache mapped/file sample mismatch");
            let digest = Sha256::digest(&observed);
            sample_digest.update(address.to_le_bytes());
            sample_digest.update(count.to_le_bytes());
            sample_digest.update(digest);
            sampled_bytes += count;
            samples.push(json!({"address":address,"source_cache_index":file_index,
                "file_offset":file_offset,"bytes":count,"sha256":hex::encode(digest)}));
        }
    }
    let images = set["images"]
        .as_array()
        .context("cache set has no images")?;
    ensure!(images.len() <= 1_000_000, "cache image count limit");
    let mut header_bytes = 0u64;
    let mut header_digest = Sha256::new();
    for image in images {
        let count = number(&image["mach_o"], "load_command_bytes")?
            .checked_add(32)
            .context("cache header size overflow")?;
        ensure!(count <= 1024 * 1024 + 32, "cache image header limit");
        header_bytes = header_bytes
            .checked_add(count)
            .context("cache header total overflow")?;
        ensure!(header_bytes <= 64 * 1024 * 1024, "cache header read budget");
        let address = number(image, "address")?
            .checked_add(slide)
            .context("cache image address overflow")?;
        let observed = memory.read_snapshot(address, usize::try_from(count)?)?;
        let digest = Sha256::digest(&observed);
        ensure!(
            hex::encode(digest) == image["header_and_commands_sha256"],
            "cache mapped image header differs from original inventory"
        );
        header_digest.update(address.to_le_bytes());
        header_digest.update(count.to_le_bytes());
        header_digest.update(digest);
    }
    for ((file, before), source) in files.iter_mut().zip(sources) {
        ensure!(
            hash_file(file)? == source["source_sha256"],
            "cache changed during map probe"
        );
        let path = Path::new(source["path"].as_str().context("missing cache path")?);
        let after = path.symlink_metadata()?;
        ensure!(
            after.is_file()
                && !after.file_type().is_symlink()
                && same_file(before, &after)
                && same_file(before, &file.metadata()?),
            "cache source identity changed during map probe"
        );
    }
    Ok(
        json!({"schema_version":1,"kind":"original_dyld_cache_mapping_probe",
        "source_sha256":set["source_sha256"],"cache_base":load_base,"slide":slide,
        "input_manifest_sha256":stela_core::sha256(&serde_json::to_vec(set)?),
        "file_count":sources.len(),"mapping_count":mappings.len(),"mapped_bytes":mapped_bytes,
        "original_mappings":mappings,"mapped_regions":memory.regions(),"mapping_samples":samples,
        "mapping_sample_bytes":sampled_bytes,"mapping_samples_sha256":hex::encode(sample_digest.finalize()),
        "image_headers_verified":images.len(),"image_header_bytes":header_bytes,
        "image_header_reads_sha256":hex::encode(header_digest.finalize()),
        "sources":sources.iter().map(|f|json!({"path":f["path"],"uuid":f["header"]["uuid"],
            "source_sha256":f["source_sha256"],"source_identity":f["source_identity"]})).collect::<Vec<_>>(),
        "probe_source_sha256":stela_core::sha256(include_bytes!("shared_cache_memory.rs")),
        "runtime_memory_source_sha256":stela_core::sha256(include_bytes!("../../crates/stela-runtime/src/memory.rs")),
        "read_only":true,"source_identity_checks_passed":true,"fixups_applied":false,
        "pointers_authenticated":false,"native_code_executed":false,
        "executable_ready":false,"complete_binary_verified":false,
        "limits":"Brief trusted read-only original cache VM/file ownership probe. Samples and original Mach-O headers verified; not a byte-for-byte RAM dump. Encoded pointers remain encoded. No signing/trust, slide fixups, authentication, initializer, process or boot execution. Caller must keep original inodes stable; pre/post hashes do not lock/freeze them. External file mutation/truncation can invalidate file-backed views."}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placement_refuses_unreviewed_relocations_and_alignment() -> Result<()> {
        let set = json!({"kind":"dyld_shared_cache_set_manifest","cache_set_files_verified":true,
            "files":[{"header":{"shared_region_start":0x180000000u64,"shared_region_bytes":0x10000,
                "maximum_slide":0x20000000u64},"mappings":[{"address":0x180000000u64}]}],
            "combined_mappings":[{"address":0x180000000u64,"size":0x10000}]});
        assert_eq!(slide_for(&set, 0x180004000)?, 0x4000);
        for base in [0x17fffffff, 0x180000004, 0x1a0004000] {
            assert!(slide_for(&set, base).is_err());
        }
        let mut outside = set.clone();
        outside["combined_mappings"][0]["size"] = json!(0x10001);
        assert!(slide_for(&outside, 0x180000000).is_err());
        Ok(())
    }

    #[test]
    fn original_source_identity_is_required_before_mapping() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("cache");
        std::fs::write(&path, b"original cache")?;
        let value = json!({"path":path,"source_identity":file_identity(&path.metadata()?),
            "source_sha256":stela_core::sha256(b"original cache")});
        checked_file(&value)?;
        std::fs::write(&path, b"modified cache")?;
        assert!(checked_file(&value).is_err());
        Ok(())
    }
}
