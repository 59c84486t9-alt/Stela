//! Private controller data chosen by Stela's emulated die. Each populated
//! field cites its AP consumer; unconsumed output fields have no modeled
//! private meaning. See docs/research/ans2.md for the complete consumer audit.
use super::{
    commands::{put16, put32, put64},
    namespace::Medium,
};
use crate::Result;
use stela_contracts::refuse;

/// Emulated die: Stela's choice, consumed by IdentifyNamespaces
/// 0x3db2608..0x3db2748 / 0x3db2878 as vendor YMTC (6), generation
/// 1x (0), SLC (0), planar (0), one plane, ECC revision zero. These
/// are descriptive fields, not a physical NAND address translation.
/// GetNANDInfo 0x3dbebb8 exposes this same descriptor as two CQ words;
/// its kernel caller AppleNVMeUpdateUC::GetNANDInfo copies the opaque
/// 64-bit value to its caller without deriving namespace capacities.
pub(super) const DESCRIPTOR: u64 = 6 | (1 << 21);
pub(super) const NAND_ID: u64 = 0x9b;

/// Output bytes of the sanitize-counter tunnel (request type 0x0d):
/// `GetSanitizeCounters` (0x3dc29a8) allocates and sends exactly this.
pub(super) const SANITIZE_COUNTER_BYTES: u32 = 0x10_0000;

/// Emulated die: Stela's choice, consumed by `ParseSanitizeCounters`
/// (0x3dc2c48..0x3dc2e7c) as the `SanitizeStart`, `SanitizeDone` and
/// `SanitizeFailed` properties. The parser walks the whole output as
/// records of a u64 header (key in the low word, value count in the
/// high word) and that many u64 values; an empty header is one word.
/// The model refuses the Sanitize command, so the die has never started
/// one and every counter is zero.
pub(super) const SANITIZE_COUNTERS: [(u32, u64); 3] = [(0x695, 0), (0x696, 0), (0x697, 0)];

pub(super) fn identify(medium: &Medium, data: &mut [u8]) -> Result<()> {
    // Emulated die: Stela's choice, consumed by
    // IdentifyNamespaces (0x3db2904..0x3db2974) as the count
    // (minimum three on CGv2) used by DetermineNamespaces.
    put32(data, 0x204, medium.namespaces.len() as u32);
    // Emulated die: Stela's choice, consumed at 0x3db252c
    // and 0x3db2a34 as the NUL-terminated msp-version string.
    ascii_z(&mut data[0xc00..0xc10], b"Stela ANS2 1.0");
    // Emulated die: Stela's choice, consumed at 0x3db2548,
    // 0x3db26b0 and 0x3db26fc as MSP part S3E, revision A1.
    data[0xc1c] = 0;
    data[0xc1d] = 1;
    // Legacy geometry and ECC are zero: the nonzero packed
    // descriptor selects the extended path at 0x3db25f4.
    // Emulated die: Stela's choice, consumed at 0x3db28b0
    // and 0x3db28d0 as logged FTL 1.0 / DM version 1.
    data[0xc21] = 1;
    data[0xc23] = 1;
    put64(data, 0xd00, DESCRIPTOR);
    // Emulated die: Stela's choice, consumed at 0x3db2978
    // (must be nonzero), SetSwapWriteLimit (0x3df6614) as
    // endurance tier, and 0x3db2ad4 as decimal GB * 10^9.
    // Round up solely for this whole-GB descriptive field;
    // namespace NCAP remains the exact backing capacity.
    let id = medium.device.identity();
    let bytes = id
        .blocks
        .checked_mul(u64::from(id.block_size))
        .ok_or(refuse!("ANS backing byte capacity overflows"))?;
    let gb = bytes.div_ceil(1_000_000_000);
    let gb = u16::try_from(gb)
        .map_err(|_| refuse!("ANS backing capacity exceeds private Identify GB field"))?;
    put16(data, 0xe06, gb.max(1));
    // Emulated die: Stela's choice, consumed at 0x3db2534,
    // 0x3db2540 and 0x3db29ec..0x3db2a18 as vendor-name
    // and nand-marketing-name, never firmware impersonation.
    ascii_z(&mut data[0xe18..0xe38], b"Stela persistent storage");
    ascii_z(&mut data[0xe38..0xe48], b"Stela");
    Ok(())
}

/// Emulated die: Stela's choice, consumed by SetNANDGeomPropertiesV2
/// (0x3dfb610..0x3dfb7dc). One bus, one die, one CAU, one SLC plane;
/// 4 KiB pages and 256 pages per erase block. The final erase block may
/// have unused pages; exact logical capacity is still namespace NCAP.
/// Return only fields the consumer reads, leaving unknown output bytes
/// untouched. No physical NAND operations are exposed by this model.
pub(super) fn geometry(medium: &Medium) -> Result<[(usize, u32); 16]> {
    let pages: u64 = medium.namespaces.iter().map(|ns| ns.blocks).sum();
    let blocks = u32::try_from(pages.div_ceil(256))
        .map_err(|_| refuse!("ANS NAND geometry exceeds blocks-per-CAU field"))?;
    Ok([
        (0x04, 1),      // 0x3dfb730: cau-per-die.
        (0x08, 1),      // 0x3dfb610/678: num-bus; clamped to 16.
        (0x0c, 1),      // 0x3dfb744: num-dip.
        (0x10, blocks), // 0x3dfb638: blocks-per-cau.
        (0x14, 1),      // 0x3dfb64c/758: sec-per-page; <<12 for page-size.
        (0x18, 256),    // 0x3dfb76c: sec-per-full-band.
        (0x1c, 256),    // 0x3dfb780: sec-per-full-band-slc.
        (0x20, 0),      // 0x3dfb794: bytes-per-sec-meta.
        (0x24, 256),    // 0x3dfb664: pages-per-block-mlc.
        (0x28, 256),    // 0x3dfb6e0: pages-per-block-slc.
        (0x2c, 256),    // 0x3dfb7a8: pages-per-block0.
        (0x30, 1),      // 0x3dfb68c/7bc: default-bits-per-cell/cell-type.
        (0x34, 1),      // 0x3dfb6f4: pages-in-read-verify.
        (0x38, blocks), // 0x3dfb708: package_blocks_at_EOL.
        (0x3c, 0),      // 0x3dfb71c: block-pairing-scheme (none).
        (0x40, 0),      // 0x3dfb7d0: program-scheme (linear).
    ])
}

fn ascii_z(data: &mut [u8], value: &[u8]) {
    data.fill(0);
    let count = value.len().min(data.len() - 1);
    data[..count].copy_from_slice(&value[..count]);
}
