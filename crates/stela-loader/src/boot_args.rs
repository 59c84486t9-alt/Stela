//! The arm64 `boot_args` structure iBoot passes to XNU (and to SPTM) in x0.
//!
//! Layout from public XNU `pexpert/pexpert/arm64/boot.h` at tag
//! `xnu-12377.121.6` (commit `ac9718fb1af618d5ce8678d0dc6e8a58f252216f`),
//! with natural alignment and `BOOT_LINE_LENGTH` 1024. The header names
//! revisions 1 and 2 only; Asahi m1n1 `proxyclient/m1n1/tgtypes.py` records
//! that iBoot for macOS 12 and later reports revision 3 with this same
//! 1024-byte command line, so that is the revision emitted here.
use anyhow::{Result, ensure};
use serde::Serialize;

pub const BOOT_LINE_LENGTH: usize = 1024;
pub const REVISION: u16 = 3;
pub const VERSION: u16 = 2;
/// `Boot_Video.v_depth` bits 0..8 hold bits per pixel.
pub const VIDEO_DEPTH_MASK: u64 = 0xff;
/// `kBootFlagsDarkBoot`.
pub const BOOT_FLAG_DARK_BOOT: u64 = 1;

/// Byte offsets of each field, for in-place patches by the UEFI mount.
pub mod offset {
    pub const REVISION: usize = 0;
    pub const VERSION: usize = 2;
    pub const VIRT_BASE: usize = 8;
    pub const PHYS_BASE: usize = 16;
    pub const MEM_SIZE: usize = 24;
    pub const TOP_OF_KERNEL_DATA: usize = 32;
    pub const VIDEO_BASE: usize = 40;
    pub const VIDEO_DISPLAY: usize = 48;
    pub const VIDEO_ROW_BYTES: usize = 56;
    pub const VIDEO_WIDTH: usize = 64;
    pub const VIDEO_HEIGHT: usize = 72;
    pub const VIDEO_DEPTH: usize = 80;
    pub const MACHINE_TYPE: usize = 88;
    pub const DEVICE_TREE: usize = 96;
    pub const DEVICE_TREE_LENGTH: usize = 104;
    pub const COMMAND_LINE: usize = 108;
    pub const BOOT_FLAGS: usize = COMMAND_LINE + super::BOOT_LINE_LENGTH + 4;
    pub const MEM_SIZE_ACTUAL: usize = BOOT_FLAGS + 8;
}

/// `sizeof(boot_args)`.
pub const BYTES: usize = offset::MEM_SIZE_ACTUAL + 8;

/// `Boot_Video`: the framebuffer XNU draws its console on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Video {
    pub base: u64,
    pub display: u64,
    pub row_bytes: u64,
    pub width: u64,
    pub height: u64,
    pub depth: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BootArgs {
    pub revision: u16,
    pub version: u16,
    /// Kernel virtual address of `phys_base` in XNU's physical aperture.
    pub virt_base: u64,
    pub phys_base: u64,
    /// Bytes of memory from `phys_base` that the kernel may manage.
    pub mem_size: u64,
    pub top_of_kernel_data: u64,
    pub video: Video,
    pub machine_type: u32,
    /// Kernel virtual address of the flattened DeviceTree.
    pub device_tree: u64,
    pub device_tree_length: u32,
    pub command_line: String,
    pub boot_flags: u64,
    /// Installed DRAM, including memory below `phys_base`.
    pub mem_size_actual: u64,
}

impl BootArgs {
    pub fn encode(&self) -> Result<[u8; BYTES]> {
        ensure!(
            self.command_line.len() < BOOT_LINE_LENGTH && !self.command_line.contains('\0'),
            "boot-args must be under {BOOT_LINE_LENGTH} bytes without NUL"
        );
        let mut out = [0u8; BYTES];
        let mut put = |at: usize, bytes: &[u8]| out[at..at + bytes.len()].copy_from_slice(bytes);
        put(offset::REVISION, &self.revision.to_le_bytes());
        put(offset::VERSION, &self.version.to_le_bytes());
        put(offset::VIRT_BASE, &self.virt_base.to_le_bytes());
        put(offset::PHYS_BASE, &self.phys_base.to_le_bytes());
        put(offset::MEM_SIZE, &self.mem_size.to_le_bytes());
        put(
            offset::TOP_OF_KERNEL_DATA,
            &self.top_of_kernel_data.to_le_bytes(),
        );
        put(offset::VIDEO_BASE, &self.video.base.to_le_bytes());
        put(offset::VIDEO_DISPLAY, &self.video.display.to_le_bytes());
        put(offset::VIDEO_ROW_BYTES, &self.video.row_bytes.to_le_bytes());
        put(offset::VIDEO_WIDTH, &self.video.width.to_le_bytes());
        put(offset::VIDEO_HEIGHT, &self.video.height.to_le_bytes());
        put(offset::VIDEO_DEPTH, &self.video.depth.to_le_bytes());
        put(offset::MACHINE_TYPE, &self.machine_type.to_le_bytes());
        put(offset::DEVICE_TREE, &self.device_tree.to_le_bytes());
        put(
            offset::DEVICE_TREE_LENGTH,
            &self.device_tree_length.to_le_bytes(),
        );
        put(offset::COMMAND_LINE, self.command_line.as_bytes());
        put(offset::BOOT_FLAGS, &self.boot_flags.to_le_bytes());
        put(offset::MEM_SIZE_ACTUAL, &self.mem_size_actual.to_le_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() >= BYTES, "boot_args needs {BYTES} bytes");
        let u16_at = |at: usize| u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap());
        let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let u64_at = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        let line = &bytes[offset::COMMAND_LINE..offset::COMMAND_LINE + BOOT_LINE_LENGTH];
        let end = line.iter().position(|&b| b == 0).unwrap_or(line.len());
        Ok(Self {
            revision: u16_at(offset::REVISION),
            version: u16_at(offset::VERSION),
            virt_base: u64_at(offset::VIRT_BASE),
            phys_base: u64_at(offset::PHYS_BASE),
            mem_size: u64_at(offset::MEM_SIZE),
            top_of_kernel_data: u64_at(offset::TOP_OF_KERNEL_DATA),
            video: Video {
                base: u64_at(offset::VIDEO_BASE),
                display: u64_at(offset::VIDEO_DISPLAY),
                row_bytes: u64_at(offset::VIDEO_ROW_BYTES),
                width: u64_at(offset::VIDEO_WIDTH),
                height: u64_at(offset::VIDEO_HEIGHT),
                depth: u64_at(offset::VIDEO_DEPTH),
            },
            machine_type: u32_at(offset::MACHINE_TYPE),
            device_tree: u64_at(offset::DEVICE_TREE),
            device_tree_length: u32_at(offset::DEVICE_TREE_LENGTH),
            command_line: String::from_utf8(line[..end].to_vec())?,
            boot_flags: u64_at(offset::BOOT_FLAGS),
            mem_size_actual: u64_at(offset::MEM_SIZE_ACTUAL),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_matches_the_natural_alignment_of_boot_h() {
        // uint64 fields after the two uint16s start at 8; deviceTreeP after the
        // uint32 machineType realigns to 96; bootFlags after the 1024-byte
        // line at 108 realigns to 1136.
        assert_eq!(offset::DEVICE_TREE, 96);
        assert_eq!(offset::BOOT_FLAGS, 1136);
        assert_eq!(BYTES, 1152);
    }

    #[test]
    fn encodes_and_decodes_every_field() -> Result<()> {
        let args = BootArgs {
            revision: REVISION,
            version: VERSION,
            virt_base: 0xfffffe0010000000,
            phys_base: 0x8_0000_0000,
            mem_size: 0x2_0000_0000,
            top_of_kernel_data: 0x8_0800_0000,
            video: Video {
                base: 0xc000_0000,
                display: 1,
                row_bytes: 7680,
                width: 1920,
                height: 1080,
                depth: 32,
            },
            machine_type: 0,
            device_tree: 0xfffffe0010004000,
            device_tree_length: 0x48000,
            command_line: "-v debug=0x8".into(),
            boot_flags: BOOT_FLAG_DARK_BOOT,
            mem_size_actual: 0x2_0000_0000,
        };
        let bytes = args.encode()?;
        assert_eq!(
            &bytes[offset::COMMAND_LINE..offset::COMMAND_LINE + 2],
            b"-v"
        );
        assert_eq!(BootArgs::decode(&bytes)?, args);
        let long = BootArgs {
            command_line: "x".repeat(BOOT_LINE_LENGTH),
            ..args
        };
        assert!(long.encode().is_err());
        Ok(())
    }
}
