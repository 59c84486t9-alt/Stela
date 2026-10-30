//! The arm64 `boot_args` structure iBoot passes to XNU (and to SPTM) in x0.
//!
//! Layout from public XNU `pexpert/pexpert/arm64/boot.h` at tag
//! `xnu-12377.121.6` (commit `ac9718fb1af618d5ce8678d0dc6e8a58f252216f`),
//! with natural alignment and `BOOT_LINE_LENGTH` 1024. The header names
//! revisions 1 and 2 only; Asahi m1n1 `proxyclient/m1n1/tgtypes.py` records
//! that iBoot for macOS 12 and later reports revision 3 with this same
//! 1024-byte command line, so that is the revision emitted here.
use crate::Result;
use alloc::string::String;
use stela_contracts::{refuse, require};
pub use {stela_formats::boot_bundle::schema::BootArgs, stela_formats::boot_bundle::schema::Video};

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

pub fn encode(args: &BootArgs) -> Result<[u8; BYTES]> {
    require!(
        args.command_line.len() < BOOT_LINE_LENGTH && !args.command_line.contains('\0'),
        "boot-args must be under {BOOT_LINE_LENGTH} bytes without NUL",
        BOOT_LINE_LENGTH
    );
    let mut out = [0u8; BYTES];
    let mut put = |at: usize, bytes: &[u8]| out[at..at + bytes.len()].copy_from_slice(bytes);
    put(offset::REVISION, &args.revision.to_le_bytes());
    put(offset::VERSION, &args.version.to_le_bytes());
    put(offset::VIRT_BASE, &args.virt_base.to_le_bytes());
    put(offset::PHYS_BASE, &args.phys_base.to_le_bytes());
    put(offset::MEM_SIZE, &args.mem_size.to_le_bytes());
    put(
        offset::TOP_OF_KERNEL_DATA,
        &args.top_of_kernel_data.to_le_bytes(),
    );
    put(offset::VIDEO_BASE, &args.video.base.to_le_bytes());
    put(offset::VIDEO_DISPLAY, &args.video.display.to_le_bytes());
    put(offset::VIDEO_ROW_BYTES, &args.video.row_bytes.to_le_bytes());
    put(offset::VIDEO_WIDTH, &args.video.width.to_le_bytes());
    put(offset::VIDEO_HEIGHT, &args.video.height.to_le_bytes());
    put(offset::VIDEO_DEPTH, &args.video.depth.to_le_bytes());
    put(offset::MACHINE_TYPE, &args.machine_type.to_le_bytes());
    put(offset::DEVICE_TREE, &args.device_tree.to_le_bytes());
    put(
        offset::DEVICE_TREE_LENGTH,
        &args.device_tree_length.to_le_bytes(),
    );
    put(offset::COMMAND_LINE, args.command_line.as_bytes());
    put(offset::BOOT_FLAGS, &args.boot_flags.to_le_bytes());
    put(offset::MEM_SIZE_ACTUAL, &args.mem_size_actual.to_le_bytes());
    Ok(out)
}

pub fn decode(bytes: &[u8]) -> Result<BootArgs> {
    require!(bytes.len() >= BYTES, "boot_args needs {BYTES} bytes", BYTES);
    let u16_at = |at: usize| u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap());
    let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    let u64_at = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    let line = &bytes[offset::COMMAND_LINE..offset::COMMAND_LINE + BOOT_LINE_LENGTH];
    let end = line.iter().position(|&b| b == 0).unwrap_or(line.len());
    Ok(BootArgs {
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
        command_line: String::from_utf8(line[..end].to_vec())
            .map_err(|_| refuse!("boot-args command line is not UTF-8"))?,
        boot_flags: u64_at(offset::BOOT_FLAGS),
        mem_size_actual: u64_at(offset::MEM_SIZE_ACTUAL),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

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
        let bytes = encode(&args)?;
        assert_eq!(
            &bytes[offset::COMMAND_LINE..offset::COMMAND_LINE + 2],
            b"-v"
        );
        assert_eq!(decode(&bytes)?, args);
        let long = BootArgs {
            command_line: "x".repeat(BOOT_LINE_LENGTH),
            ..args
        };
        assert!(encode(&long).is_err());
        Ok(())
    }
}
