//! Owned instruction-fetch windows from a structurally validated executable.
//! This is not a process loader: segments are not mapped and deferred work remains.
use super::load_plan::{self, LoadPlan, PlanError};
use object::macho;

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

#[derive(Debug)]
pub struct BlockImage {
    plan: LoadPlan,
    regions: Vec<ExecutableRegion>,
}
impl BlockImage {
    /// Validate one selected thin slice and snapshot its executable file ranges.
    /// Container selection remains the caller's responsibility. No slide, fixup,
    /// import substitution, instruction patch or executable zero-fill is applied.
    pub fn from_slice(data: &[u8]) -> Result<Self, PlanError> {
        let plan = load_plan::plan(data)?;
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
        Ok(Self { plan, regions })
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
    #[test]
    fn retains_exact_file_window_and_arm64e_identity_without_padding() {
        let input = image(0x200, 0x8000_0002, vec![]);
        let result = BlockImage::from_slice(&input).unwrap();
        let region = &result.regions()[0];
        assert_eq!(result.plan().slice_sha256, sha256(&input));
        assert_eq!(result.plan().architecture, "arm64e");
        assert_eq!(result.plan().cpu_subtype, 0x8000_0002);
        assert_eq!(result.plan().entry.guest_address, BASE + 0x200);
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
        assert_eq!(result.plan().entry.file_offset, 0x404);
        assert_eq!(result.plan().entry.guest_address, BASE + 0x3004);
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
