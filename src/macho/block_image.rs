//! Owned instruction-fetch windows from a structurally validated executable.
//! This is not a process loader: segments are not mapped and deferred work remains.
use super::load_plan::{self, LoadPlan, PlanError};
use anyhow::{Context, Result, ensure};
use object::macho;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug)]
pub struct ExecutableRegion {
    segment_name: String,
    guest_address: u64,
    file_offset: u64,
    bytes: Box<[u8]>,
}
impl ExecutableRegion {
    pub fn segment_name(&self) -> &str {
        &self.segment_name
    }
    pub fn guest_address(&self) -> u64 {
        self.guest_address
    }
    pub fn file_offset(&self) -> u64 {
        self.file_offset
    }
    /// Exact file-backed segment bytes, not a claim that every byte is code.
    /// Decode only from a requested guest PC and stop on unsupported instructions;
    /// executable segments can also contain Mach-O headers and constant data.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Declared embedded data and its conservative instruction-fetch exclusion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DataInCodeRange {
    pub image_offset: u64,
    pub guest_address: u64,
    pub file_offset: u64,
    pub length: u16,
    pub kind: u16,
    pub excluded_guest_address: u64,
    pub excluded_bytes: u64,
}
#[derive(Debug)]
pub struct DiscoverySources {
    pub roots: Vec<u64>,
    pub regions: Vec<ExecutableRegion>,
    pub data_in_code: Vec<DataInCodeRange>,
    pub function_start_count: usize,
}

#[derive(Debug)]
pub struct BlockImage {
    plan: LoadPlan,
    entry_address: u64,
    regions: Vec<ExecutableRegion>,
}
impl BlockImage {
    /// Validate one selected thin slice and snapshot its executable file ranges.
    /// Container selection remains the caller's responsibility. No slide, fixup,
    /// import substitution, instruction patch or executable zero-fill is applied.
    pub fn from_slice(data: &[u8]) -> Result<Self, PlanError> {
        let plan = load_plan::plan(data)?;
        let entry_address = plan.executable_entry()?.guest_address;
        Self::snapshot(data, plan, entry_address)
    }
    /// Explicit dynamic-linker mode retains its UNIXTHREAD entry separately;
    /// the underlying image never acquires a fabricated LC_MAIN entry.
    pub fn from_dynamic_linker_slice(data: &[u8]) -> Result<Self, PlanError> {
        let linker = load_plan::plan_dynamic_linker(data)?;
        Self::snapshot(data, linker.image, linker.thread.pc)
    }
    fn snapshot(data: &[u8], plan: LoadPlan, entry_address: u64) -> Result<Self, PlanError> {
        let mut regions = Vec::new();
        for segment in &plan.segments {
            if segment.initial_protection & macho::VM_PROT_EXECUTE == 0 || segment.file.bytes == 0 {
                continue;
            }
            // Planning already checked these extents. Keep checked conversions here
            // rather than making instruction-fetch safety depend on that invariant.
            let end = segment
                .file
                .offset
                .checked_add(segment.file.bytes)
                .ok_or_else(|| PlanError::Malformed("executable file range overflow".into()))?;
            let start = usize::try_from(segment.file.offset).map_err(|_| {
                PlanError::Malformed("executable file offset exceeds host size".into())
            })?;
            let end = usize::try_from(end).map_err(|_| {
                PlanError::Malformed("executable file extent exceeds host size".into())
            })?;
            let bytes = data.get(start..end).ok_or_else(|| {
                PlanError::Malformed("executable file extent exceeds slice".into())
            })?;
            regions.push(ExecutableRegion {
                segment_name: segment.name.clone(),
                guest_address: segment.guest.address,
                file_offset: segment.file.offset,
                bytes: bytes.into(),
            });
        }
        Ok(Self {
            plan,
            entry_address,
            regions,
        })
    }
    /// Seed only declared executable entry/function starts and remove declared
    /// embedded data from fetch snapshots. Metadata does not certify every byte
    /// in the remaining regions as instructions, or establish process readiness.
    pub fn discovery_sources(
        &self,
        data: &[u8],
        include_function_starts: bool,
    ) -> Result<DiscoverySources> {
        ensure!(
            self.plan.slice_bytes == data.len() as u64
                && self.plan.slice_sha256 == stela_core::sha256(data),
            "discovery input differs from original planned slice"
        );
        let text = self
            .plan
            .segments
            .iter()
            .find(|s| s.name == "__TEXT")
            .context("discovery requires preferred __TEXT")?;
        let base = text.guest.address;
        let readable = self
            .regions
            .iter()
            .filter(|region| {
                self.plan.segments.iter().any(|s| {
                    s.guest.address == region.guest_address
                        && s.initial_protection & (macho::VM_PROT_READ | macho::VM_PROT_EXECUTE)
                            == (macho::VM_PROT_READ | macho::VM_PROT_EXECUTE)
                })
            })
            .collect::<Vec<_>>();
        for region in &readable {
            ensure!(
                region.guest_address.is_multiple_of(4),
                "discovery executable snapshot base is unaligned"
            );
        }
        let max_end = readable
            .iter()
            .map(|r| {
                r.guest_address
                    .checked_add(r.bytes.len() as u64)
                    .context("discovery source extent overflow")
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .max()
            .context("discovery has no readable executable file bytes")?;
        let mut data_in_code = Vec::new();
        let mut starts = None;
        let mut saw_data = false;
        for payload in &self.plan.payloads {
            if !matches!(
                payload.command,
                macho::LC_FUNCTION_STARTS | macho::LC_DATA_IN_CODE
            ) {
                continue;
            }
            ensure!(
                payload.file.bytes <= 16 * 1024 * 1024,
                "discovery metadata payload exceeds budget"
            );
            let end = payload
                .file
                .offset
                .checked_add(payload.file.bytes)
                .context("discovery payload extent overflow")?;
            let bytes = data
                .get(usize::try_from(payload.file.offset)?..usize::try_from(end)?)
                .context("discovery payload exceeds original slice")?;
            ensure!(
                payload.sha256 == stela_core::sha256(bytes),
                "discovery payload identity differs from plan"
            );
            if payload.command == macho::LC_FUNCTION_STARTS {
                ensure!(starts.is_none(), "duplicate function-start metadata");
                // Empty payload explicitly means no additional function roots.
                starts = Some(if bytes.is_empty() {
                    Vec::new()
                } else {
                    super::shared_cache_exports::function_starts(bytes, base, max_end)?
                });
            } else {
                ensure!(
                    !saw_data && bytes.len().is_multiple_of(8),
                    "duplicate or malformed data-in-code metadata size"
                );
                saw_data = true;
                ensure!(
                    bytes.len() / 8 <= 65536,
                    "data-in-code entry count exceeds budget"
                );
                for entry in bytes.as_chunks::<8>().0 {
                    let image_offset = u64::from(u32::from_le_bytes(entry[..4].try_into()?));
                    let length = u16::from_le_bytes(entry[4..6].try_into()?);
                    let kind = u16::from_le_bytes(entry[6..8].try_into()?);
                    ensure!(
                        length > 0 && (1..=5).contains(&kind),
                        "invalid data-in-code length/kind"
                    );
                    let address = base
                        .checked_add(image_offset)
                        .context("data-in-code guest address overflow")?;
                    let end = address
                        .checked_add(u64::from(length))
                        .context("data-in-code extent overflow")?;
                    let region = readable
                        .iter()
                        .find(|r| {
                            r.guest_address <= address
                                && end <= r.guest_address + r.bytes.len() as u64
                        })
                        .context("data-in-code is outside readable executable file bytes")?;
                    let excluded_start = address & !3;
                    let excluded_end = end
                        .checked_add(3)
                        .context("data-in-code alignment overflow")?
                        & !3;
                    data_in_code.push(DataInCodeRange {
                        image_offset,
                        guest_address: address,
                        file_offset: region.file_offset + (address - region.guest_address),
                        length,
                        kind,
                        excluded_guest_address: excluded_start,
                        excluded_bytes: excluded_end - excluded_start,
                    });
                }
            }
        }
        data_in_code.sort_by_key(|range| range.guest_address);
        for pair in data_in_code.windows(2) {
            ensure!(
                pair[0].guest_address + u64::from(pair[0].length) <= pair[1].guest_address,
                "overlapping data-in-code ranges"
            );
        }
        let mut regions = Vec::new();
        for source in readable {
            let source_end = source.guest_address + source.bytes.len() as u64;
            let mut at = source.guest_address;
            for excluded in data_in_code.iter().filter(|r| {
                r.excluded_guest_address >= source.guest_address
                    && r.excluded_guest_address < source_end
            }) {
                if at < excluded.excluded_guest_address {
                    snapshot_piece(source, at, excluded.excluded_guest_address, &mut regions)?;
                }
                at = at.max(excluded.excluded_guest_address + excluded.excluded_bytes);
            }
            if at < source_end {
                snapshot_piece(source, at, source_end, &mut regions)?;
            }
        }
        let entry = self.entry_address;
        let function_start_count = starts.as_ref().map_or(0, Vec::len);
        let mut roots = BTreeSet::from([entry]);
        if include_function_starts {
            for start in starts.unwrap_or_default() {
                roots.insert(start);
            }
        }
        for root in &roots {
            ensure!(
                root.is_multiple_of(4)
                    && regions.iter().any(|r| r.guest_address <= *root
                        && root
                            .checked_add(4)
                            .is_some_and(|end| end <= r.guest_address + r.bytes.len() as u64)),
                "discovery root is not a complete readable executable instruction outside declared data: {root:#x}"
            );
        }
        Ok(DiscoverySources {
            roots: roots.into_iter().collect(),
            regions,
            data_in_code,
            function_start_count,
        })
    }
    /// Includes the original slice hash, CPU subtype, entry and pending loader work.
    /// Successful window extraction does not change `execution_supported`.
    pub fn plan(&self) -> &LoadPlan {
        &self.plan
    }
    pub fn regions(&self) -> &[ExecutableRegion] {
        &self.regions
    }
}

fn snapshot_piece(
    source: &ExecutableRegion,
    start: u64,
    end: u64,
    result: &mut Vec<ExecutableRegion>,
) -> Result<()> {
    // Fragments with no complete word cannot be registered/fetched. Preserve
    // partial tails attached to a larger region; never invent padding bytes.
    if end - start < 4 {
        return Ok(());
    }
    let offset = usize::try_from(start - source.guest_address)?;
    let end_offset = usize::try_from(end - source.guest_address)?;
    result.push(ExecutableRegion {
        segment_name: source.segment_name.clone(),
        guest_address: start,
        file_offset: source.file_offset + offset as u64,
        bytes: source.bytes[offset..end_offset].into(),
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_core::sha256;
    const BASE: u64 = 0x1_0000_0000;
    fn put32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(data: &mut [u8], offset: usize, value: u64) {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn segment(name: &[u8], address: u64, fileoff: u64, filesize: u64, init: u32) -> Vec<u8> {
        let mut result = vec![0; 72];
        put32(&mut result, 0, macho::LC_SEGMENT_64);
        put32(&mut result, 4, 72);
        result[8..8 + name.len()].copy_from_slice(name);
        put64(&mut result, 24, address);
        put64(&mut result, 32, 0x1000);
        put64(&mut result, 40, fileoff);
        put64(&mut result, 48, filesize);
        put32(&mut result, 56, 7);
        put32(&mut result, 60, init);
        result
    }
    fn image(entryoff: u64, subtype: u32, extra: Vec<Vec<u8>>) -> Vec<u8> {
        let mut main = vec![0; 24];
        put32(&mut main, 0, macho::LC_MAIN);
        put32(&mut main, 4, 24);
        put64(&mut main, 8, entryoff);
        let mut commands = vec![segment(b"__TEXT", BASE, 0, 0x303, 5), main];
        commands.extend(extra);
        let mut data = vec![0; 0x500];
        for (index, value) in [
            0xfeedfacf,
            macho::CPU_TYPE_ARM64,
            subtype,
            macho::MH_EXECUTE,
            commands.len() as u32,
            commands.iter().map(|c| c.len() as u32).sum(),
            0,
            0,
        ]
        .into_iter()
        .enumerate()
        {
            put32(&mut data, index * 4, value);
        }
        let mut at = 32;
        for command in commands {
            data[at..at + command.len()].copy_from_slice(&command);
            at += command.len();
        }
        put32(&mut data, 0x200, 0xd65f03c0); // RET X30
        data[0x300..0x303].copy_from_slice(&[1, 2, 3]);
        data
    }
    fn metadata_command(command: u32, offset: u32, size: u32) -> Vec<u8> {
        let mut b = vec![0; 16];
        put32(&mut b, 0, command);
        put32(&mut b, 4, 16);
        put32(&mut b, 8, offset);
        put32(&mut b, 12, size);
        b
    }
    fn metadata_image(entry: u64, starts: &[u8], records: &[(u32, u16, u16)]) -> Vec<u8> {
        let extra = vec![
            segment(b"__LINKEDIT", BASE + 0x5000, 0x400, 0x100, 1),
            metadata_command(macho::LC_FUNCTION_STARTS, 0x400, starts.len() as u32),
            metadata_command(macho::LC_DATA_IN_CODE, 0x420, (records.len() * 8) as u32),
        ];
        let mut input = image(entry, 0, extra);
        input[0x400..0x400 + starts.len()].copy_from_slice(starts);
        for (index, (offset, length, kind)) in records.iter().enumerate() {
            let at = 0x420 + index * 8;
            put32(&mut input, at, *offset);
            input[at + 4..at + 6].copy_from_slice(&length.to_le_bytes());
            input[at + 6..at + 8].copy_from_slice(&kind.to_le_bytes());
        }
        put32(&mut input, 0x210, 0xd65f03c0);
        put32(&mut input, 0x220, 0xd65f03c0);
        input
    }
    #[test]
    fn dynamic_linker_discovery_requires_explicit_mode_and_keeps_unixthread_entry_typed() {
        let mut thread = vec![0; 288];
        put32(&mut thread, 0, macho::LC_UNIXTHREAD);
        put32(&mut thread, 4, 288);
        put32(&mut thread, 8, 6);
        put32(&mut thread, 12, 68);
        put64(&mut thread, 272, BASE + 0x280);
        let mut identity = vec![0; 32];
        put32(&mut identity, 0, macho::LC_ID_DYLINKER);
        put32(&mut identity, 4, 32);
        put32(&mut identity, 8, 12);
        identity[12..25].copy_from_slice(b"/usr/lib/dyld");
        let commands = [segment(b"__TEXT", BASE, 0, 0x400, 5), thread, identity];
        let mut input = vec![0; 0x400];
        for (index, value) in [
            0xfeedfacf,
            macho::CPU_TYPE_ARM64,
            2,
            macho::MH_DYLINKER,
            3,
            commands.iter().map(|c| c.len() as u32).sum(),
            0,
            0,
        ]
        .into_iter()
        .enumerate()
        {
            put32(&mut input, index * 4, value);
        }
        let mut at = 32;
        for command in commands {
            input[at..at + command.len()].copy_from_slice(&command);
            at += command.len();
        }
        put32(&mut input, 0x280, 0xd65f03c0);
        assert!(BlockImage::from_slice(&input).is_err());
        let image = BlockImage::from_dynamic_linker_slice(&input).unwrap();
        assert!(image.plan.entry.is_none());
        assert!(image.plan.executable_entry().is_err());
        let sources = image.discovery_sources(&input, false).unwrap();
        assert_eq!(sources.roots, [BASE + 0x280]);
        assert_eq!(sources.regions[0].bytes(), input);
        input[0x280] ^= 1;
        assert!(image.discovery_sources(&input, false).is_err());
    }
    #[test]
    fn discovery_seeds_only_declared_roots_and_splits_data_without_changing_original_bytes() {
        let mut input = metadata_image(0x200, &[0x80, 4, 0x10, 0x10, 0], &[(0x215, 3, 3)]);
        input[0x214..0x218].copy_from_slice(&0x14000000u32.to_le_bytes()); // Decodable jump-table bytes remain data.
        let image = BlockImage::from_slice(&input).unwrap();
        let sources = image.discovery_sources(&input, true).unwrap();
        assert_eq!(sources.roots, [BASE + 0x200, BASE + 0x210, BASE + 0x220]);
        assert_eq!(sources.function_start_count, 3);
        assert_eq!(sources.regions.len(), 2);
        assert_eq!(sources.data_in_code[0].excluded_guest_address, BASE + 0x214);
        assert_eq!(sources.data_in_code[0].excluded_bytes, 4);
        assert_eq!(sources.data_in_code[0].file_offset, 0x215);
        for region in &sources.regions {
            let at = region.file_offset() as usize;
            assert_eq!(region.bytes(), &input[at..at + region.bytes().len()]);
        }
        assert_eq!(sources.regions[0].bytes(), &input[..0x214]);
        assert_eq!(sources.regions[1].guest_address(), BASE + 0x218);
        assert_eq!(sources.regions[1].bytes(), &input[0x218..0x303]);
        assert_eq!(image.regions()[0].bytes(), &input[..0x303]); // Existing entry probe's snapshots remain unchanged.
        let entry_only = image.discovery_sources(&input, false).unwrap();
        assert_eq!(entry_only.roots, [BASE + 0x200]);
        assert_eq!(entry_only.function_start_count, 3);
        input.fill(0);
        assert_eq!(
            &sources.regions[0].bytes()[0x200..0x204],
            &0xd65f03c0u32.to_le_bytes()
        );
    }
    #[test]
    fn discovery_merges_rounded_exclusions_but_rejects_overlapping_declared_data() {
        let input = metadata_image(0x200, &[], &[(0x215, 1, 1), (0x217, 1, 2)]);
        let image = BlockImage::from_slice(&input).unwrap();
        let sources = image.discovery_sources(&input, false).unwrap();
        assert_eq!(sources.regions.len(), 2);
        assert_eq!(sources.regions[1].guest_address(), BASE + 0x218);
        let input = metadata_image(0x200, &[], &[(0x214, 4, 1), (0x216, 4, 1)]);
        let image = BlockImage::from_slice(&input).unwrap();
        assert!(
            image
                .discovery_sources(&input, false)
                .unwrap_err()
                .to_string()
                .contains("overlap")
        );
        let input = metadata_image(0x200, &[], &[(0x301, 2, 1)]);
        let image = BlockImage::from_slice(&input).unwrap();
        let sources = image.discovery_sources(&input, false).unwrap();
        assert_eq!(sources.regions.last().unwrap().bytes().len(), 0x300);
        assert_eq!(sources.data_in_code[0].excluded_guest_address, BASE + 0x300);
        assert_eq!(sources.data_in_code[0].excluded_bytes, 4);
    }
    #[test]
    fn discovery_rejects_declared_data_roots_unknown_kinds_bad_lengths_and_ranges() {
        for (entry, records) in [
            (0x214, vec![(0x215, 1, 1)]),
            (0x200, vec![(0x214, 0, 1)]),
            (0x200, vec![(0x214, 4, 0)]),
            (0x200, vec![(0x214, 4, 6)]),
            (0x200, vec![(0x302, 2, 1)]),
            (0x200, vec![(0x400, 4, 1)]),
            (0x200, vec![(u32::MAX, 4, 1)]),
        ] {
            let input = metadata_image(entry, &[], &records);
            let image = BlockImage::from_slice(&input).unwrap();
            assert!(image.discovery_sources(&input, false).is_err());
        }
        let input = metadata_image(0x200, &[0x94, 4, 0], &[(0x214, 4, 1)]);
        let image = BlockImage::from_slice(&input).unwrap();
        assert!(image.discovery_sources(&input, true).is_err());
        assert!(image.discovery_sources(&input, false).is_ok());
    }
    #[test]
    fn discovery_validates_slice_payload_identity_and_function_metadata_without_padding() {
        let input = metadata_image(0x200, &[0x80, 4, 0], &[]);
        let mut image = BlockImage::from_slice(&input).unwrap();
        let mut changed = input.clone();
        changed[0x200] ^= 1;
        assert!(image.discovery_sources(&changed, true).is_err());
        image.plan.payloads[0].sha256 = "wrong".into();
        assert!(image.discovery_sources(&input, true).is_err());
        for stream in [
            vec![0x80],
            vec![0x80, 0, 0],
            vec![0x82, 4, 0],
            vec![0x80, 6, 0],
            vec![0x80, 4, 0, 1],
        ] {
            let input = metadata_image(0x200, &stream, &[]);
            let image = BlockImage::from_slice(&input).unwrap();
            assert!(image.discovery_sources(&input, true).is_err());
        }
        let mut input = metadata_image(0x200, &[], &[]);
        let at = 32 + 72 + 24 + 72 + 16;
        put32(&mut input, at + 12, 7);
        let image = BlockImage::from_slice(&input).unwrap();
        assert!(image.discovery_sources(&input, false).is_err());
    }
    #[test]
    fn discovery_never_silently_truncates_function_roots_to_runtime_budget() {
        let mut starts = vec![0x80, 4];
        starts.extend(vec![4; 1024]);
        starts.push(0);
        let mut input = image(
            0x200,
            0,
            vec![metadata_command(
                macho::LC_FUNCTION_STARTS,
                0x1800,
                starts.len() as u32,
            )],
        );
        input.resize(0x2000, 0);
        put64(&mut input, 32 + 32, 0x3000);
        put64(&mut input, 32 + 48, 0x2000);
        input[0x1800..0x1800 + starts.len()].copy_from_slice(&starts);
        let image = BlockImage::from_slice(&input).unwrap();
        let all = image.discovery_sources(&input, true).unwrap();
        assert_eq!(all.function_start_count, 1025);
        assert_eq!(all.roots.len(), 1025);
        let entry_only = image.discovery_sources(&input, false).unwrap();
        assert_eq!(entry_only.roots, [BASE + 0x200]);
        assert_eq!(entry_only.function_start_count, 1025);
    }

    #[test]
    fn discovery_resolves_header_relative_data_offsets_through_secondary_executable_mapping() {
        let mut input = image(
            0x200,
            0,
            vec![
                segment(b"__CODE", BASE + 0x3000, 0x400, 0x100, 5),
                metadata_command(macho::LC_DATA_IN_CODE, 0x280, 8),
            ],
        );
        put32(&mut input, 0x280, 0x3005);
        input[0x284..0x286].copy_from_slice(&3u16.to_le_bytes());
        input[0x286..0x288].copy_from_slice(&4u16.to_le_bytes());
        let image = BlockImage::from_slice(&input).unwrap();
        let sources = image.discovery_sources(&input, false).unwrap();
        assert_eq!(sources.data_in_code[0].guest_address, BASE + 0x3005);
        assert_eq!(sources.data_in_code[0].file_offset, 0x405);
        assert_eq!(
            sources.data_in_code[0].excluded_guest_address,
            BASE + 0x3004
        );
        let code = sources
            .regions
            .iter()
            .filter(|r| r.segment_name() == "__CODE")
            .collect::<Vec<_>>();
        assert_eq!(code.len(), 2);
        assert_eq!(code[0].file_offset(), 0x400);
        assert_eq!(code[0].bytes(), &input[0x400..0x404]);
        assert_eq!(code[1].file_offset(), 0x408);
        assert_eq!(code[1].bytes(), &input[0x408..0x500]);
    }

    #[test]
    fn retains_exact_file_window_and_arm64e_identity_without_padding() {
        let input = image(0x200, 0x8000_0002, vec![]);
        let result = BlockImage::from_slice(&input).unwrap();
        let region = &result.regions()[0];
        assert_eq!(result.plan().slice_sha256, sha256(&input));
        assert_eq!(result.plan().architecture, "arm64e");
        assert_eq!(result.plan().cpu_subtype, 0x8000_0002);
        assert_eq!(
            result.plan().entry.as_ref().unwrap().guest_address,
            BASE + 0x200
        );
        assert_eq!(region.segment_name(), "__TEXT");
        assert_eq!(region.guest_address(), BASE);
        assert_eq!(region.file_offset(), 0);
        assert_eq!(region.bytes(), &input[..0x303]);
        assert_eq!(&region.bytes()[0x300..], &[1, 2, 3]);
        assert_eq!(result.plan().segments[0].zero_fill.bytes, 0xcfd);
        assert!(!result.plan().execution_supported);
        assert!(
            result
                .plan()
                .unresolved_requirements
                .iter()
                .any(|s| s.contains("process/thread ABI"))
        );
        assert!(
            result
                .plan()
                .unresolved_requirements
                .iter()
                .any(|s| s.contains("pointer-authentication ABI"))
        );
    }
    #[test]
    fn snapshots_owned_bytes_and_uses_initial_execute_protection() {
        let extra = vec![segment(b"__DATA", BASE + 0x2000, 0x400, 0x100, 3)];
        let mut input = image(0x200, 0, extra);
        let result = BlockImage::from_slice(&input).unwrap();
        input.fill(0);
        assert_eq!(result.regions().len(), 1);
        assert_eq!(
            &result.regions()[0].bytes()[0x200..0x204],
            &0xd65f03c0u32.to_le_bytes()
        );
        assert_eq!(result.plan().architecture, "arm64");
    }
    #[test]
    fn preserves_nonzero_file_offset_and_guest_gap_for_secondary_executable() {
        let extra = vec![segment(b"__CODE", BASE + 0x3000, 0x400, 0x100, 5)];
        let mut input = image(0x3004, 0, extra);
        put32(&mut input, 0x404, 0xd65f03c0);
        let result = BlockImage::from_slice(&input).unwrap();
        assert_eq!(result.plan().entry.as_ref().unwrap().file_offset, 0x404);
        assert_eq!(
            result.plan().entry.as_ref().unwrap().guest_address,
            BASE + 0x3004
        );
        let code = &result.regions()[1];
        assert_eq!(code.guest_address(), BASE + 0x3000);
        assert_eq!(code.file_offset(), 0x400);
        assert_eq!(code.bytes(), &input[0x400..0x500]);
    }
    #[test]
    fn retains_dynamic_loader_requirements() {
        let mut dylinker = vec![0; 32];
        put32(&mut dylinker, 0, macho::LC_LOAD_DYLINKER);
        put32(&mut dylinker, 4, 32);
        put32(&mut dylinker, 8, 12);
        dylinker[12..25].copy_from_slice(b"/usr/lib/dyld");
        let input = image(0x200, 0, vec![dylinker]);
        let result = BlockImage::from_slice(&input).unwrap();
        assert_eq!(result.plan().dylinker.as_deref(), Some("/usr/lib/dyld"));
        assert!(
            result
                .plan()
                .unresolved_requirements
                .iter()
                .any(|s| s.contains("dependency resolution"))
        );
        assert!(!result.plan().execution_supported);
    }
    #[test]
    fn rejects_incomplete_unaligned_and_zero_fill_entries() {
        for entry in [0x300, 0x202, 0x304] {
            assert!(BlockImage::from_slice(&image(entry, 0, vec![])).is_err());
        }
    }
}
