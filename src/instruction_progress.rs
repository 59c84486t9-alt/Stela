//! Honest source-word counts using the current semantic decoder and backend.
//! Emission is probed in isolation, never executed or promoted to verification.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use stela_compiler::{Backend, GuestAddress, Lifter, UnsupportedReason};
use stela_core::sha256;
use std::path::Path;

const PROBE_VERSION: &str = "isolated-word-emission-v1";

#[derive(Debug, Clone)]
struct Extent {
    scope: u64,
    file_offset: u64,
    guest_address: u64,
    bytes: u64,
}

fn range(data: &[u8], offset: u64, bytes: u64) -> Result<&[u8]> {
    let end = offset.checked_add(bytes).context("source range overflow")?;
    data.get(usize::try_from(offset)?..usize::try_from(end)?)
        .context("source range exceeds input")
}

fn number(value: &Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .with_context(|| format!("missing unsigned manifest field {field}"))
}

fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        data.get(offset..offset + 4)
            .context("truncated Mach-O word")?
            .try_into()?,
    ))
}

fn u64_at(data: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        data.get(offset..offset + 8)
            .context("truncated Mach-O address")?
            .try_into()?,
    ))
}

/// Recover physical section locations omitted by the text-export API, while
/// requiring the exported text bytes to agree with the bounded section table.
fn section_locations(data: &[u8]) -> Result<Vec<(String, u64, u64, u64)>> {
    ensure!(
        u32_at(data, 0)? == 0xfeedfacf,
        "progress requires little-endian ARM64 Mach-O"
    );
    ensure!(
        u32_at(data, 4)? == 0x0100000c,
        "progress requires ARM64 CPU type"
    );
    ensure!(
        u32_at(data, 12)? != 0xc,
        "fileset progress requires a fileset manifest"
    );
    let command_bytes = u32_at(data, 20)? as usize;
    let end = 32usize
        .checked_add(command_bytes)
        .context("load-command range overflow")?;
    ensure!(end <= data.len(), "load commands exceed slice");
    let mut cursor = 32usize;
    let mut sections = vec![];
    for _ in 0..u32_at(data, 16)? {
        ensure!(cursor <= end && end - cursor >= 8, "truncated load command");
        let size = u32_at(data, cursor + 4)? as usize;
        ensure!(
            size >= 8 && size.is_multiple_of(8) && size <= end - cursor,
            "invalid load-command extent"
        );
        if u32_at(data, cursor)? == 0x19 {
            ensure!(size >= 72, "truncated LC_SEGMENT_64");
            let count = u32_at(data, cursor + 64)? as usize;
            ensure!(
                count <= (size - 72) / 80,
                "section table exceeds segment command"
            );
            for index in 0..count {
                let position = cursor + 72 + index * 80;
                let raw_name = &data[position..position + 16];
                let length = raw_name.iter().position(|b| *b == 0).unwrap_or(16);
                let name = std::str::from_utf8(&raw_name[..length])?.to_owned();
                let address = u64_at(data, position + 32)?;
                let bytes = u64_at(data, position + 40)?;
                let offset = u64::from(u32_at(data, position + 48)?);
                let section_type = u32_at(data, position + 64)? & 0xff;
                if !matches!(section_type, 1 | 0xc | 0x12) {
                    range(data, offset, bytes)?;
                    sections.push((name, address, bytes, offset));
                }
            }
        }
        cursor += size;
    }
    ensure!(cursor == end, "load-command count/size mismatch");
    Ok(sections)
}

fn ordinary_extents(data: &[u8], path: &Path) -> Result<(Vec<Extent>, Value)> {
    let slices = crate::macho::text_slices(data, &path.display().to_string())?;
    let raw_slices = crate::macho::split_slices(data)?;
    let mut extents = vec![];
    let mut identities = vec![];
    for (scope, slice) in slices.iter().enumerate() {
        if !matches!(slice.artifact.architecture.as_str(), "arm64" | "arm64e") {
            continue;
        }
        let (_, source) = raw_slices
            .iter()
            .find(|(offset, _)| *offset == slice.artifact.slice_offset)
            .context("text slice has no source slice")?;
        let locations = section_locations(source)?;
        let mut section_count = 0;
        for section in &slice.sections {
            let bytes = hex::decode(&section.data_hex)?;
            let matches: Vec<_> = locations
                .iter()
                .filter(|(name, address, size, _)| {
                    name == &section.name
                        && *address == section.guest_address
                        && *size == bytes.len() as u64
                })
                .collect();
            ensure!(
                matches.len() == 1,
                "text section has ambiguous/missing physical extent"
            );
            let offset = matches[0].3;
            ensure!(
                range(source, offset, bytes.len() as u64)? == bytes,
                "text export/source mismatch"
            );
            if bytes.is_empty() {
                continue;
            }
            extents.push(Extent {
                scope: scope as u64,
                file_offset: slice
                    .artifact
                    .slice_offset
                    .checked_add(offset)
                    .context("slice offset overflow")?,
                guest_address: section.guest_address,
                bytes: bytes.len() as u64,
            });
            section_count += 1;
        }
        identities.push(json!({"architecture":slice.artifact.architecture,
            "slice_offset":slice.artifact.slice_offset, "slice_sha256":slice.artifact.sha256,
            "instruction_sections":section_count}));
    }
    ensure!(!identities.is_empty(), "input has no ARM64/ARM64e slices");
    Ok((
        extents,
        json!({"kind":"standalone-arm64-text-sections", "arm_slices":identities,
        "independent_address_spaces":"one per Mach-O slice", "non_arm_slices_excluded":true}),
    ))
}

fn fileset_extents(data: &[u8], manifest: &Value) -> Result<(Vec<Extent>, Value)> {
    ensure!(
        number(manifest, "schema_version")? == 1,
        "unsupported fileset schema"
    );
    ensure!(
        number(manifest, "container_bytes")? == data.len() as u64,
        "fileset byte identity mismatch"
    );
    ensure!(
        manifest["container_sha256"].as_str() == Some(sha256(data).as_str()),
        "fileset hash identity mismatch"
    );
    // Reinspect instead of trusting arbitrary manifest extents or CPU fields.
    let inspected = serde_json::to_value(crate::macho::fileset::inspect(data)?)?;
    ensure!(
        &inspected == manifest,
        "fileset manifest differs from independently parsed container"
    );
    ensure!(
        number(&manifest["root"], "cpu_type")? == 0x0100000c,
        "fileset root is not ARM64"
    );
    let images = manifest["images"]
        .as_array()
        .context("missing fileset images")?;
    let mut extents = vec![];
    let mut section_count = 0;
    for image in images {
        ensure!(
            number(image, "cpu_type")? == 0x0100000c,
            "fileset image is not ARM64"
        );
        for section in image["sections"]
            .as_array()
            .context("missing image sections")?
        {
            if section["instructions"].as_bool() != Some(true)
                || section["zero_fill"].as_bool() != Some(false)
            {
                continue;
            }
            let size = number(section, "bytes")?;
            let offset = number(section, "file_offset")?;
            ensure!(
                section["sha256"].as_str() == Some(sha256(range(data, offset, size)?).as_str()),
                "instruction section identity mismatch"
            );
            if size == 0 {
                continue;
            }
            extents.push(Extent {
                scope: 0,
                file_offset: offset,
                guest_address: number(section, "vm_address")?,
                bytes: size,
            });
            section_count += 1;
        }
    }
    Ok((
        extents,
        json!({"kind":"embedded-fileset-instruction-sections", "images":images.len(),
        "instruction_sections":section_count, "root_aggregate_sections_excluded":true,
        "independent_address_spaces":"one collection-wide guest address space"}),
    ))
}

/// Validate aliases by comparing affine section mappings, then merge physical
/// intervals. This avoids allocating a tree entry for every kernel instruction.
fn normalize(data: &[u8], mut extents: Vec<Extent>) -> Result<Vec<Extent>> {
    for extent in &extents {
        ensure!(
            extent.bytes > 0
                && extent.bytes.is_multiple_of(4)
                && extent.file_offset.is_multiple_of(4)
                && extent.guest_address.is_multiple_of(4),
            "instruction extents must contain complete aligned 4-byte words"
        );
        range(data, extent.file_offset, extent.bytes)?;
        extent
            .guest_address
            .checked_add(extent.bytes)
            .context("guest instruction range overflow")?;
    }
    for (index, first) in extents.iter().enumerate() {
        for second in &extents[index + 1..] {
            let start = first.file_offset.max(second.file_offset);
            let end = (first.file_offset + first.bytes).min(second.file_offset + second.bytes);
            if start < end {
                ensure!(
                    first.scope == second.scope
                        && first.guest_address + (start - first.file_offset)
                            == second.guest_address + (start - second.file_offset),
                    "physical instruction bytes have conflicting guest aliases"
                );
            }
            if first.scope == second.scope {
                let start = first.guest_address.max(second.guest_address);
                let end =
                    (first.guest_address + first.bytes).min(second.guest_address + second.bytes);
                if start < end {
                    ensure!(
                        first.file_offset + (start - first.guest_address)
                            == second.file_offset + (start - second.guest_address),
                        "guest instruction addresses map to conflicting physical bytes"
                    );
                }
            }
        }
    }
    extents.sort_by_key(|extent| extent.file_offset);
    let mut merged: Vec<Extent> = vec![];
    for extent in extents {
        if let Some(previous) = merged.last_mut()
            && extent.file_offset < previous.file_offset + previous.bytes
        {
            previous.bytes = (previous.file_offset + previous.bytes)
                .max(extent.file_offset + extent.bytes)
                - previous.file_offset;
        } else {
            merged.push(extent);
        }
    }
    Ok(merged)
}

#[derive(Debug, Default)]
struct Counts {
    source_word_instances: u64,
    decoded_lifted_words: u64,
    native_emitted_words: u64,
    unsupported_words: u64,
    unresolved_control_flow_words: u64,
    native_emitted_bytes: u64,
}

fn unresolved(error: &UnsupportedReason) -> bool {
    matches!(
        error,
        UnsupportedReason::UnresolvedDirectTarget { .. }
            | UnsupportedReason::UnresolvedIndirectTarget { .. }
    )
}

fn probe(data: &[u8], extents: &[Extent]) -> Result<(Counts, String, String)> {
    let mut counts = Counts::default();
    let mut source_hash = Sha256::new();
    let mut emitted_hash = Sha256::new();
    for extent in extents {
        for (index, bytes) in range(data, extent.file_offset, extent.bytes)?
            .as_chunks::<4>()
            .0
            .iter()
            .enumerate()
        {
            let file_offset = extent.file_offset + index as u64 * 4;
            let pc = GuestAddress(extent.guest_address + index as u64 * 4);
            source_hash.update(extent.scope.to_le_bytes());
            source_hash.update(file_offset.to_le_bytes());
            source_hash.update(pc.0.to_le_bytes());
            source_hash.update(bytes);
            emitted_hash.update(extent.scope.to_le_bytes());
            emitted_hash.update(file_offset.to_le_bytes());
            emitted_hash.update(pc.0.to_le_bytes());
            emitted_hash.update(bytes);
            counts.source_word_instances += 1;
            let result = stela_compiler::aarch64::Decoder.lift(pc, u32::from_le_bytes(*bytes));
            match result {
                Ok(instruction) => {
                    counts.decoded_lifted_words += 1;
                    match stela_compiler::x86_64::Emitter.emit(&[instruction]) {
                        Ok(block) => {
                            ensure!(
                                !block.x86_64_code.is_empty(),
                                "backend emitted empty instruction probe"
                            );
                            ensure!(
                                block.source_map == vec![(pc, 0)],
                                "isolated emitter source-map mismatch"
                            );
                            counts.native_emitted_words += 1;
                            counts.native_emitted_bytes += block.x86_64_code.len() as u64;
                            emitted_hash.update([0]);
                            emitted_hash.update((block.x86_64_code.len() as u64).to_le_bytes());
                            emitted_hash.update(&block.x86_64_code);
                        }
                        Err(error) => {
                            let status = if unresolved(&error) {
                                counts.unresolved_control_flow_words += 1;
                                1
                            } else {
                                counts.unsupported_words += 1;
                                2
                            };
                            emitted_hash.update([status]);
                            emitted_hash.update(format!("{error:?}").as_bytes());
                        }
                    }
                }
                Err(error) => {
                    let status = if unresolved(&error) {
                        counts.unresolved_control_flow_words += 1;
                        3
                    } else {
                        counts.unsupported_words += 1;
                        4
                    };
                    emitted_hash.update([status]);
                    emitted_hash.update(format!("{error:?}").as_bytes());
                }
            }
        }
    }
    Ok((
        counts,
        hex::encode(source_hash.finalize()),
        hex::encode(emitted_hash.finalize()),
    ))
}

pub fn measure(input: &Path, fileset_manifest: Option<&Path>) -> Result<Value> {
    let data = std::fs::read(input)?;
    let (extents, scope, manifest_hash) = if let Some(path) = fileset_manifest {
        let bytes = std::fs::read(path)?;
        let (extents, scope) = fileset_extents(&data, &serde_json::from_slice(&bytes)?)?;
        (extents, scope, Some(sha256(&bytes)))
    } else {
        let (extents, scope) = ordinary_extents(&data, input)?;
        (extents, scope, None)
    };
    let section_word_instances = extents.iter().try_fold(0u64, |sum, extent| {
        sum.checked_add(extent.bytes / 4)
            .context("section count overflow")
    })?;
    let extents = normalize(&data, extents)?;
    ensure!(
        !extents.is_empty(),
        "input has no nonempty ARM instruction extents"
    );
    let (counts, source_words_sha256, emission_probe_sha256) = probe(&data, &extents)?;
    let percentage = ((u128::from(counts.native_emitted_words) * 1_000_000
        + u128::from(counts.source_word_instances) / 2)
        / u128::from(counts.source_word_instances)) as f64
        / 10_000.0;
    let ranges: Vec<_> = extents.iter().map(|extent| json!({"address_space":extent.scope,
        "file_offset":extent.file_offset, "guest_address":extent.guest_address, "bytes":extent.bytes,
        "sha256":sha256(range(&data,extent.file_offset,extent.bytes).expect("validated extent"))})).collect();
    Ok(
        json!({"schema_version":1,"kind":"isolated_instruction_codegen_progress",
        "probe_version":PROBE_VERSION, "source_sha256":sha256(&data),"source_bytes":data.len(),
        "fileset_manifest_sha256":manifest_hash,
        "compiler_source_sha256":sha256(stela_compiler::SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
        "compiler_probe_source_sha256":sha256(include_bytes!("instruction_progress.rs")),
        "input_scope":scope,"unique_source_ranges":ranges,
        "duplicate_section_words_deduplicated":section_word_instances-counts.source_word_instances,
        "counts":{"source_word_instances":counts.source_word_instances,
            "decoded_lifted_words":counts.decoded_lifted_words,"native_emitted_words":counts.native_emitted_words,
            "unsupported_words":counts.unsupported_words,"unresolved_control_flow_words":counts.unresolved_control_flow_words,
            "native_emitted_bytes":counts.native_emitted_bytes},
        "percentage":{"numerator":counts.native_emitted_words,"denominator":counts.source_word_instances,
            "units":"source 4-byte instruction-word instances","decimal_places":4,
            "rounding":"nearest; ties upward","value":percentage},
        "verified_words":null,"source_words_sha256":source_words_sha256,"emission_probe_sha256":emission_probe_sha256,
        "limits":"Linear source-word instances in the stated instruction sections, including possible padding/data/unreachable words. Each decoded word is emitted alone by the real backend without patched targets or fake RET. Outward branches are unresolved; self-target branches can emit. No native execution, verification count, function linking, register-state reconstruction, application compatibility or macOS boot is inferred. Current direct-private-RAM and bounded-leaf backend profile applies."}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extent(file_offset: u64, guest_address: u64, bytes: u64) -> Extent {
        Extent {
            scope: 0,
            file_offset,
            guest_address,
            bytes,
        }
    }

    #[test]
    fn probes_real_emission_and_reports_unresolved_control_flow_separately() -> Result<()> {
        let source: Vec<_> = [0xd2800540u32, 0xf9400001, 0, 0x14000002, 0x14000000]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let extents = normalize(&source, vec![extent(0, 0x1000, source.len() as u64)])?;
        let (counts, source_hash, emission_hash) = probe(&source, &extents)?;
        assert_eq!(counts.source_word_instances, 5);
        assert_eq!(counts.decoded_lifted_words, 4);
        assert_eq!(counts.native_emitted_words, 3);
        assert_eq!(counts.unsupported_words, 1);
        assert_eq!(counts.unresolved_control_flow_words, 1);
        assert!(counts.native_emitted_bytes > 0);
        assert_eq!(source_hash.len(), 64);
        assert_eq!(emission_hash.len(), 64);
        Ok(())
    }

    #[test]
    fn overlapping_identical_aliases_count_each_physical_word_once() -> Result<()> {
        let source = vec![0; 24];
        let extents = normalize(&source, vec![extent(0, 0x1000, 16), extent(8, 0x1008, 16)])?;
        assert_eq!(extents.len(), 1);
        assert_eq!(extents[0].bytes, 24);
        assert_eq!(probe(&source, &extents)?.0.source_word_instances, 6);
        Ok(())
    }

    #[test]
    fn conflicting_aliases_and_incomplete_or_unaligned_extents_fail() {
        let source = vec![0; 32];
        for extents in [
            vec![extent(0, 0x1000, 16), extent(8, 0x2000, 16)],
            vec![extent(0, 0x1000, 8), extent(16, 0x1000, 8)],
            vec![extent(0, 0x1000, 3)],
            vec![extent(1, 0x1000, 4)],
            vec![extent(0, 0x1001, 4)],
            vec![extent(32, 0x1000, 4)],
            vec![extent(0, u64::MAX - 3, 4)],
        ] {
            assert!(normalize(&source, extents).is_err());
        }
    }

    #[test]
    fn independent_slices_can_reuse_guest_virtual_addresses() -> Result<()> {
        let source = vec![0; 16];
        let mut other = extent(8, 0x1000, 8);
        other.scope = 1;
        assert_eq!(
            normalize(&source, vec![extent(0, 0x1000, 8), other])?.len(),
            2
        );
        Ok(())
    }
}
