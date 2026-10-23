// SPDX-License-Identifier: GPL-2.0-only
//! Shared SD/MMC register encodings and card metadata; hardware transports
//! retain their own native command, completion and physical operating state.
use crate::block::BlockError;
use alloc::vec::Vec;
pub(super) mod protocol;
pub(super) mod wire;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Sd,
    Mmc,
}
/// Actual card registers and the acknowledged physical operating mode.
#[derive(Clone, Debug)]
pub struct CardInfo {
    pub kind: Kind,
    pub cid: [u32; 4],
    pub csd: [u32; 4],
    pub scr: Option<[u8; 8]>,
    pub ext_csd: Option<Vec<u8>>,
    pub clock_hz: u32,
    pub bus_width: u8,
}
/// Register bits use the card's127..0 numbering, after actual R2 reconstruction.
pub(super) fn bits(words: [u32; 4], start: u32, count: u32) -> u32 {
    let word = (3 - start / 32) as usize;
    let shift = start % 32;
    let value = u64::from(words[word]) >> shift
        | if shift + count > 32 {
            u64::from(words[word - 1]) << (32 - shift)
        } else {
            0
        };
    (value & ((1u64 << count) - 1)) as u32
}
pub(super) fn capacity(kind: Kind, csd: [u32; 4]) -> Result<(u64, u32), BlockError> {
    let structure = bits(csd, 126, 2);
    let block_bits = bits(csd, 80, 4);
    let blocks = if kind == Kind::Sd && structure == 1 {
        (u64::from(bits(csd, 48, 22)) + 1) * 1024
    } else if kind == Kind::Sd && structure != 0 {
        return Err(BlockError::Unsupported(
            "SDUC extended addressing requires explicit support",
        ));
    } else {
        if kind == Kind::Mmc && structure == 0 || !(9..=11).contains(&block_bits) {
            return Err(BlockError::Unsupported(
                "MMC/SD invalid CSD structure/block length",
            ));
        }
        (u64::from(bits(csd, 62, 12)) + 1) << (bits(csd, 47, 3) + 2 + block_bits - 9)
    };
    let exp = [10_000u32, 100_000, 1_000_000, 10_000_000, 0, 0, 0, 0];
    let mant = [
        0u32, 10, 12, 13, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 70, 80,
    ];
    let hz = exp[bits(csd, 96, 3) as usize] * mant[bits(csd, 99, 4) as usize];
    if hz == 0 || blocks == 0 {
        return Err(BlockError::Unsupported(
            "MMC/SD invalid CSD transfer speed/capacity",
        ));
    }
    Ok((blocks, hz))
}
