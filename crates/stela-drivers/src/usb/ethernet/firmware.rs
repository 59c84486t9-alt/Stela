// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2014 Realtek Semiconductor Corp. All rights reserved.
//! RTL8153/8156 firmware file validation adapted from rtl8152_check_firmware
//! and rtl8152_is_fw_*_ok in pinned Linux r8152.c. This validates the complete
//! image before any hardware upload. It does not enable unfinished revisions.
//!
//! The embedded SHA-256 is an integrity checksum, not a vendor signature.
//! Setup's independently pinned manifest and exact resource target are still
//! required. Unknown block effects are refused instead of silently skipped.
use super::rtl815x::Revision;
use crate::{block::BlockError, firmware as resources};
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::fmt;
use sha2::{Digest, Sha256};

const HEADER: usize = 64;
const MAX_BYTES: usize = 128 * 1024;
const MAX_BLOCKS: usize = 256;
const MAC_HEADER: usize = 63;
const PHY_NC_HEADER: usize = 40;
const PHY_UNION_HEADER: usize = 58;

const END: u32 = 0;
const PLA: u32 = 1;
const USB: u32 = 2;
const START: u32 = 3;
const STOP: u32 = 4;
const NC: u32 = 5;
const FIXUP: u32 = 6;
const UNION_NC: u32 = 7;
const UNION_NC1: u32 = 8;
const UNION_NC2: u32 = 9;
const UNION_UC2: u32 = 10;
const UNION_UC: u32 = 11;
const UNION_MISC: u32 = 12;
const SPEED_UP: u32 = 13;
const VERSION: u32 = 14;

/// Owned exact target, preserved when a catalog lookup or image parse fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub name: String,
    pub hardware: String,
    pub revision: String,
}

impl Request {
    pub fn new(descriptor: &[u8; 18], revision: Revision) -> Option<Self> {
        Some(Self {
            name: String::from(revision.firmware()?),
            hardware: format!(
                "usb:{:04x}:{:04x}:{:04x}",
                u16::from_le_bytes([descriptor[8], descriptor[9]]),
                u16::from_le_bytes([descriptor[10], descriptor[11]]),
                u16::from_le_bytes([descriptor[12], descriptor[13]])
            ),
            revision: format!("tcr-{:04x}", revision.0),
        })
    }

    fn requirement(&self) -> resources::Requirement<'_> {
        resources::Requirement {
            name: &self.name,
            target: resources::Target {
                driver: "usb-rtl815x",
                hardware: &self.hardware,
                revision: &self.revision,
                board: None,
            },
            minimum_bytes: HEADER + 8,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Device(BlockError),
    Firmware {
        request: Request,
        error: Box<resources::Error>,
    },
    Image {
        request: Request,
        reason: &'static str,
    },
    UnsupportedRevision(Revision),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Device(error) => error.fmt(f),
            Self::Firmware { request, error } => write!(f, "USB RTL815x {request:?}: {error}"),
            Self::Image { request, reason } => write!(f, "USB RTL815x {request:?}: {reason}"),
            Self::UnsupportedRevision(revision) => write!(
                f,
                "USB RTL815x revision {:04x} initialization/upload is not implemented",
                revision.0
            ),
        }
    }
}
impl core::error::Error for Error {}
impl From<BlockError> for Error {
    fn from(error: BlockError) -> Self {
        Self::Device(error)
    }
}

/// Borrow exactly the resource selected by the observed hardware. The image
/// and parsed blocks cannot outlive the Provider. No image bytes are cloned.
pub fn load<'a>(
    provider: &'a dyn resources::Provider,
    descriptor: &[u8; 18],
    revision: Revision,
) -> Result<Option<(resources::Image<'a>, Firmware<'a>)>, Error> {
    let Some(request) = Request::new(descriptor, revision) else {
        return Ok(None);
    };
    let image = provider
        .load(request.requirement())
        .map_err(|error| Error::Firmware {
            request: request.clone(),
            error: Box::new(error),
        })?;
    let parsed = Firmware::parse(image.bytes(), revision)
        .map_err(|reason| Error::Image { request, reason })?;
    Ok(Some((image, parsed)))
}

fn word(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}
fn dword(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bank {
    Pla,
    Usb,
}

/// A validated MAC block. Its register destinations and active breakpoint
/// count have been checked against the exact hardware revision and bank.
#[derive(Debug)]
pub struct Mac<'a> {
    bytes: &'a [u8],
    payload: &'a [u8],
    bank: Bank,
}
impl<'a> Mac<'a> {
    pub fn bank(&self) -> Bank {
        self.bank
    }
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
    pub fn register(&self) -> u16 {
        word(self.bytes, 10)
    }
    pub fn breakpoint_base(&self) -> (u16, u16) {
        (word(self.bytes, 12), word(self.bytes, 14))
    }
    pub fn breakpoint_enable(&self) -> (u16, u16) {
        (word(self.bytes, 16), word(self.bytes, 18))
    }
    pub fn breakpoint_start(&self) -> u16 {
        word(self.bytes, 20)
    }
    pub fn breakpoints(&self) -> impl Iterator<Item = u16> + '_ {
        (0..usize::from(word(self.bytes, 22))).map(|i| word(self.bytes, 24 + 2 * i))
    }
    pub fn version_register(&self) -> (u16, u8) {
        (word(self.bytes, 60), self.bytes[62])
    }
}

#[derive(Debug)]
pub struct PhyNc<'a> {
    bytes: &'a [u8],
    payload: &'a [u8],
}
impl<'a> PhyNc<'a> {
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
    pub fn register(&self) -> u16 {
        word(self.bytes, 10)
    }
    pub fn base(&self) -> (u16, u16) {
        (word(self.bytes, 12), word(self.bytes, 14))
    }
    pub fn patch_enable(&self) -> (u16, u16) {
        (word(self.bytes, 16), word(self.bytes, 18))
    }
    pub fn mode(&self) -> (u16, u16, u16) {
        (
            word(self.bytes, 20),
            word(self.bytes, 22),
            word(self.bytes, 24),
        )
    }
    pub fn breakpoint_start(&self) -> u16 {
        word(self.bytes, 28)
    }
    pub fn breakpoints(&self) -> impl Iterator<Item = u16> + '_ {
        (0..usize::from(word(self.bytes, 30))).map(|i| word(self.bytes, 32 + 2 * i))
    }
}

#[derive(Debug)]
pub struct PhyUnion<'a> {
    bytes: &'a [u8],
    payload: &'a [u8],
}
impl<'a> PhyUnion<'a> {
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
    pub fn register(&self) -> u16 {
        word(self.bytes, 10)
    }
    pub fn presets(&self) -> impl Iterator<Item = (u16, u16)> + '_ {
        (0..usize::from(self.bytes[56]))
            .map(|i| (word(self.bytes, 12 + 4 * i), word(self.bytes, 14 + 4 * i)))
    }
    pub fn breakpoints(&self) -> impl Iterator<Item = (u16, u16)> + '_ {
        (0..usize::from(self.bytes[57]))
            .map(|i| (word(self.bytes, 20 + 4 * i), word(self.bytes, 22 + 4 * i)))
    }
    pub fn breakpoint_enable(&self) -> Option<(u16, u16)> {
        (self.bytes[57] != 0 && word(self.bytes, 52) != 0)
            .then(|| (word(self.bytes, 52), word(self.bytes, 54)))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fixup {
    And,
    Or,
    Clear,
    Xor,
}

/// Every block represents an effect that an uploader must either perform or
/// explicitly reject. There is no unexamined raw/unknown block variant.
#[derive(Debug)]
pub enum Block<'a> {
    Mac(Mac<'a>),
    PhyStart {
        key_register: u16,
        key: u16,
    },
    PhyStop,
    PhyNc(PhyNc<'a>),
    PhyUnion(PhyUnion<'a>),
    PhyFixup {
        register: u16,
        value: u16,
        operation: Fixup,
    },
    PhySpeedUp {
        register: u16,
        version: u16,
        payload: &'a [u8],
    },
    PhyVersion {
        register: u16,
        version: u16,
    },
}

#[derive(Debug)]
pub struct Firmware<'a> {
    revision: Revision,
    version: &'a [u8],
    blocks: Vec<Block<'a>>,
}

fn payload(bytes: &[u8], header: usize, alignment: usize) -> Result<&[u8], &'static str> {
    if bytes.len() < header {
        return Err("RTL815x short firmware block header");
    }
    let offset = usize::from(word(bytes, 8));
    if offset < header || offset >= bytes.len() || !(bytes.len() - offset).is_multiple_of(alignment)
    {
        return Err("RTL815x invalid firmware payload offset/length");
    }
    Ok(&bytes[offset..])
}

impl<'a> Firmware<'a> {
    pub fn revision(&self) -> Revision {
        self.revision
    }
    /// Bounded original bytes, without interpretation as untrusted log text.
    pub fn version(&self) -> &'a [u8] {
        self.version
    }
    pub fn blocks(&self) -> &[Block<'a>] {
        &self.blocks
    }

    pub fn parse(bytes: &'a [u8], revision: Revision) -> Result<Self, &'static str> {
        if bytes.len() < HEADER + 8 || bytes.len() > MAX_BYTES || revision.firmware().is_none() {
            return Err("RTL815x invalid firmware length/revision");
        }
        if Sha256::digest(&bytes[32..]).as_slice() != &bytes[..32] {
            return Err("RTL815x firmware checksum mismatch");
        }
        let mut at = HEADER;
        let mut blocks = Vec::new();
        let mut seen = [false; 15];
        loop {
            let header = bytes
                .get(at..at + 8)
                .ok_or("RTL815x missing firmware END block")?;
            let kind = dword(header, 0);
            let length = dword(header, 4) as usize;
            if length < 8 {
                return Err("RTL815x invalid firmware block length");
            }
            let end = at
                .checked_add(length)
                .ok_or("RTL815x firmware block overflow")?;
            let block = bytes
                .get(at..end)
                .ok_or("RTL815x truncated firmware block")?;
            if kind == END {
                if length != 8
                    || end != bytes.len()
                    || (seen[START as usize] && !seen[STOP as usize])
                    || blocks.is_empty()
                {
                    return Err("RTL815x invalid firmware END/PHY_STOP");
                }
                let version = &bytes[32..HEADER];
                let version = &version[..version
                    .iter()
                    .position(|b| *b == 0)
                    .unwrap_or(version.len())];
                return Ok(Self {
                    revision,
                    version,
                    blocks,
                });
            }
            if blocks.len() >= MAX_BLOCKS {
                return Err("RTL815x too many firmware blocks");
            }
            let has = |k: u32| seen[k as usize];
            let phy = has(START) && !has(STOP);
            let ordered = match kind {
                PLA | USB | SPEED_UP => !has(kind),
                START => ![START, STOP, NC, UNION_NC1, UNION_NC2, UNION_UC2, UNION_UC]
                    .iter()
                    .any(|k| has(*k)),
                STOP => has(START) && !has(STOP),
                NC => phy && !has(NC),
                UNION_NC => {
                    phy && ![NC, UNION_NC1, UNION_NC2, UNION_UC2, UNION_UC]
                        .iter()
                        .any(|k| has(*k))
                }
                UNION_NC1 => {
                    phy && ![UNION_NC1, UNION_NC2, UNION_UC2, UNION_UC]
                        .iter()
                        .any(|k| has(*k))
                }
                UNION_NC2 => phy && ![UNION_NC2, UNION_UC2, UNION_UC].iter().any(|k| has(*k)),
                UNION_UC2 => phy && !has(UNION_UC2) && !has(UNION_UC),
                UNION_UC => phy && !has(UNION_UC),
                UNION_MISC | FIXUP => true,
                VERSION => ![
                    VERSION, START, STOP, NC, UNION_NC1, UNION_NC2, UNION_UC2, UNION_UC,
                ]
                .iter()
                .any(|k| has(*k)),
                _ => return Err("RTL815x unknown firmware block effect"),
            };
            if !ordered {
                return Err("RTL815x duplicate/out-of-order firmware block");
            }
            let decoded = match kind {
                PLA | USB => Block::Mac(parse_mac(block, revision, kind == PLA)?),
                START if length == 16 && word(block, 8) != 0 => Block::PhyStart {
                    key_register: word(block, 8),
                    key: word(block, 10),
                },
                STOP if length == 8 => Block::PhyStop,
                NC => {
                    let data = payload(block, PHY_NC_HEADER, 2)?;
                    if !matches!(revision.0, 0x5c10 | 0x5c20 | 0x5c30)
                        || word(block, 10) != 0xa014
                        || word(block, 12) != 0xa012
                        || word(block, 16) != 0xa01a
                        || word(block, 20) != 0xb820
                        || word(block, 28) != 0xa000
                        || word(block, 30) > 4
                    {
                        return Err("RTL815x wrong PHY NC registers/revision/breakpoints");
                    }
                    Block::PhyNc(PhyNc {
                        bytes: block,
                        payload: data,
                    })
                }
                UNION_NC..=UNION_MISC => {
                    let data = payload(block, PHY_UNION_HEADER, 2)?;
                    if !matches!(revision.0, 0x7030 | 0x7410 | 0x7420)
                        || block[56] > 2
                        || block[57] > 8
                    {
                        return Err("RTL815x invalid PHY union revision/counts");
                    }
                    Block::PhyUnion(PhyUnion {
                        bytes: block,
                        payload: data,
                    })
                }
                FIXUP
                    if length == 16
                        && matches!(revision.0, 0x7030 | 0x7410 | 0x7420)
                        && word(block, 8) == 0xb820
                        && word(block, 10) == 0x80 =>
                {
                    let operation = match word(block, 12) {
                        0 => Fixup::And,
                        1 => Fixup::Or,
                        2 => Fixup::Clear,
                        3 => Fixup::Xor,
                        _ => return Err("RTL815x unknown PHY fixup operation"),
                    };
                    Block::PhyFixup {
                        register: word(block, 8),
                        value: word(block, 10),
                        operation,
                    }
                }
                SPEED_UP => {
                    let data = payload(block, 16, 4)?;
                    if !matches!(revision.0, 0x7410 | 0x7420) || word(block, 12) != 0x9a00 {
                        return Err("RTL815x invalid PHY speed-up revision/register");
                    }
                    Block::PhySpeedUp {
                        register: word(block, 12),
                        version: word(block, 10),
                        payload: data,
                    }
                }
                VERSION
                    if length == 16
                        && matches!(revision.0, 0x7030 | 0x7410 | 0x7420)
                        && word(block, 8) == 0x801e =>
                {
                    Block::PhyVersion {
                        register: word(block, 8),
                        version: word(block, 10),
                    }
                }
                _ => return Err("RTL815x invalid firmware block structure"),
            };
            seen[if kind == UNION_NC { NC } else { kind } as usize] = true;
            blocks.push(decoded);
            at = end
                .checked_next_multiple_of(8)
                .ok_or("RTL815x firmware alignment overflow")?;
        }
    }
}

fn parse_mac(bytes: &[u8], revision: Revision, pla: bool) -> Result<Mac<'_>, &'static str> {
    let data = payload(bytes, MAC_HEADER, 4)?;
    let (register, enable, maximum) = if pla {
        if revision.0 == 0x6400 {
            (0xf800, 0xfc48, 16)
        } else {
            (0xf800, 0xfc38, 8)
        }
    } else if matches!(revision.0, 0x5c10 | 0x5c20 | 0x5c30) {
        (0xf800, 0xfc38, 8)
    } else {
        (0xe600, 0xfc48, 16)
    };
    let count = usize::from(word(bytes, 22));
    if word(bytes, 10) != register
        || word(bytes, 12) != 0xfc26
        || word(bytes, 16) != enable
        || word(bytes, 20) != 0xfc28
        || count > maximum
        || usize::from(register) + data.len() >= 0x10000
    {
        return Err("RTL815x invalid MAC firmware registers/breakpoints/range");
    }
    if (count..maximum).any(|i| word(bytes, 24 + i * 2) != 0) {
        return Err("RTL815x nonzero unused MAC breakpoint");
    }
    Ok(Mac {
        bytes,
        payload: data,
        bank: if pla { Bank::Pla } else { Bank::Usb },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(bytes: &mut [u8], at: usize, value: u16) {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn block(kind: u32, length: usize) -> Vec<u8> {
        let mut bytes = vec![0; length];
        bytes[..4].copy_from_slice(&kind.to_le_bytes());
        bytes[4..8].copy_from_slice(&(length as u32).to_le_bytes());
        bytes
    }
    fn mac(pla: bool, old_usb: bool) -> Vec<u8> {
        let mut bytes = block(if pla { PLA } else { USB }, 72);
        put(&mut bytes, 8, 64);
        put(&mut bytes, 10, if pla || old_usb { 0xf800 } else { 0xe600 });
        put(&mut bytes, 12, 0xfc26);
        put(&mut bytes, 16, if pla || old_usb { 0xfc38 } else { 0xfc48 });
        put(&mut bytes, 20, 0xfc28);
        put(&mut bytes, 22, 1);
        put(&mut bytes, 24, 0x3210);
        bytes[64..].fill(0x5a);
        bytes
    }
    fn start() -> Vec<u8> {
        let mut bytes = block(START, 16);
        put(&mut bytes, 8, 0x8146);
        put(&mut bytes, 10, 0x7000);
        bytes
    }
    fn nc() -> Vec<u8> {
        let mut bytes = block(NC, 48);
        for (at, value) in [
            (8, 40),
            (10, 0xa014),
            (12, 0xa012),
            (16, 0xa01a),
            (20, 0xb820),
            (28, 0xa000),
            (30, 4),
        ] {
            put(&mut bytes, at, value);
        }
        bytes
    }
    fn union(kind: u32) -> Vec<u8> {
        let mut bytes = block(kind, 66);
        put(&mut bytes, 8, 58);
        put(&mut bytes, 10, 0xa000);
        bytes[56] = 2;
        bytes[57] = 8;
        bytes
    }
    fn image(blocks: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = vec![0; HEADER];
        bytes[32..39].copy_from_slice(b"fixture");
        for block in blocks {
            bytes.extend(block);
            bytes.resize(bytes.len().next_multiple_of(8), 0);
        }
        bytes.extend(block(END, 8));
        checksum(&mut bytes);
        bytes
    }
    fn checksum(bytes: &mut [u8]) {
        let digest = Sha256::digest(&bytes[32..]);
        bytes[..32].copy_from_slice(&digest);
    }

    #[test]
    fn all_mainstream_firmware_block_forms_are_typed_and_revision_checked() {
        for revision in [0x5c10, 0x5c20, 0x5c30] {
            let bytes = image(&[
                mac(false, true),
                mac(true, true),
                start(),
                nc(),
                block(STOP, 8),
            ]);
            let firmware = Firmware::parse(&bytes, Revision(revision)).unwrap();
            assert_eq!(firmware.revision(), Revision(revision));
            assert_eq!(firmware.version(), b"fixture");
            assert_eq!(firmware.blocks().len(), 5);
            let Block::Mac(mac) = &firmware.blocks()[0] else {
                panic!()
            };
            assert_eq!(mac.bank(), Bank::Usb);
            assert_eq!(mac.register(), 0xf800);
            assert_eq!(mac.payload(), &[0x5a; 8]);
            assert_eq!(mac.breakpoints().collect::<Vec<_>>(), [0x3210]);
            assert!(Firmware::parse(&bytes, Revision(0x7030)).is_err());
        }
        let mut version = block(VERSION, 16);
        put(&mut version, 8, 0x801e);
        let mut fixup = block(FIXUP, 16);
        put(&mut fixup, 8, 0xb820);
        put(&mut fixup, 10, 0x80);
        let bytes = image(&[
            mac(false, false),
            mac(true, false),
            version,
            start(),
            fixup,
            union(UNION_NC),
            union(UNION_NC1),
            union(UNION_NC2),
            union(UNION_UC2),
            union(UNION_UC),
            union(UNION_MISC),
            block(STOP, 8),
            union(UNION_MISC),
        ]);
        assert_eq!(
            Firmware::parse(&bytes, Revision(0x7030))
                .unwrap()
                .blocks()
                .len(),
            13
        );
        assert!(Firmware::parse(&bytes, Revision(0x5c10)).is_err());
        let mut speed = block(SPEED_UP, 24);
        put(&mut speed, 8, 16);
        put(&mut speed, 12, 0x9a00);
        let bytes = image(&[mac(false, false), mac(true, false), speed]);
        assert!(Firmware::parse(&bytes, Revision(0x7410)).is_ok());
        assert!(Firmware::parse(&bytes, Revision(0x7420)).is_ok());
        assert!(Firmware::parse(&bytes, Revision(0x7030)).is_err());
    }

    #[test]
    fn full_checksum_framing_and_all_truncations_are_required() {
        let bytes = image(&[mac(true, true)]);
        for end in 0..bytes.len() {
            assert!(Firmware::parse(&bytes[..end], Revision(0x5c10)).is_err());
        }
        for at in 0..bytes.len() {
            let mut bad = bytes.clone();
            bad[at] ^= 1;
            assert!(Firmware::parse(&bad, Revision(0x5c10)).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        checksum(&mut extra);
        assert!(Firmware::parse(&extra, Revision(0x5c10)).is_err());
        for length in [0, 7, u32::MAX] {
            let mut malformed = bytes.clone();
            malformed[68..72].copy_from_slice(&length.to_le_bytes());
            checksum(&mut malformed);
            assert!(Firmware::parse(&malformed, Revision(0x5c10)).is_err());
        }
        assert!(Firmware::parse(&image(&[block(0xffff, 8)]), Revision(0x5c10)).is_err());
        assert!(Firmware::parse(&bytes, Revision(0x4c10)).is_err());
    }

    #[test]
    fn register_counts_offsets_and_phy_order_fail_before_upload() {
        for (at, value) in [
            (8, 62),
            (8, 72),
            (10, 0xe600),
            (12, 0xfc24),
            (16, 0xfc48),
            (20, 0xfc26),
            (22, 9),
            (26, 1),
        ] {
            let mut bad = mac(true, true);
            put(&mut bad, at, value);
            assert!(Firmware::parse(&image(&[bad]), Revision(0x5c10)).is_err());
        }
        for blocks in [
            vec![mac(true, true), mac(true, true)],
            vec![start(), nc()],
            vec![nc(), start(), block(STOP, 8)],
            vec![start(), start(), block(STOP, 8)],
            vec![start(), nc(), nc(), block(STOP, 8)],
            vec![block(STOP, 8)],
            vec![start(), block(STOP, 8), nc()],
        ] {
            assert!(Firmware::parse(&image(&blocks), Revision(0x5c10)).is_err());
        }
        for (at, value) in [
            (8, 38),
            (10, 0xa012),
            (12, 0xa014),
            (16, 0xa01c),
            (20, 0xb822),
            (28, 0xa002),
            (30, 5),
        ] {
            let mut bad = nc();
            put(&mut bad, at, value);
            assert!(
                Firmware::parse(&image(&[start(), bad, block(STOP, 8)]), Revision(0x5c10)).is_err()
            );
        }
        for at in [56, 57] {
            let mut bad = union(UNION_NC);
            bad[at] = 9;
            assert!(
                Firmware::parse(&image(&[start(), bad, block(STOP, 8)]), Revision(0x7030)).is_err()
            );
        }
    }

    #[test]
    fn provider_boundary_preserves_exact_target_errors_and_borrowed_image_storage() {
        use crate::firmware::{
            Catalog, ErrorKind, HandoffProvider, Provenance, Provider, Resource, Target,
        };
        use core::cell::RefCell;
        struct Recording {
            catalog: Catalog,
            requests: RefCell<Vec<(String, String, String)>>,
        }
        impl Provider for Recording {
            fn load(
                &self,
                requirement: resources::Requirement<'_>,
            ) -> Result<resources::Image<'_>, resources::Error> {
                assert_eq!(requirement.target.driver, "usb-rtl815x");
                assert_eq!(requirement.target.board, None);
                self.requests.borrow_mut().push((
                    requirement.name.into(),
                    requirement.target.hardware.into(),
                    requirement.target.revision.into(),
                ));
                self.catalog.load(requirement)
            }
        }
        fn catalog(bytes: Vec<u8>, hardware: &str) -> Catalog {
            let hash = Sha256::digest(&bytes).into();
            Catalog::from_handoff(vec![Resource {
                name: "rtl_nic/rtl8153a-2.fw",
                target: Target {
                    driver: "usb-rtl815x",
                    hardware,
                    revision: "tcr-5c10",
                    board: None,
                },
                provenance: Provenance {
                    source: "linux-firmware-test",
                    revision: "immutable-fixture",
                    member: "rtl_nic/rtl8153a-2.fw",
                    license: "LICENCE.rtlwifi_firmware.txt",
                },
                expected_length: bytes.len(),
                expected_sha256: hash,
                bytes,
            }])
            .unwrap()
        }
        let mut descriptor = [0; 18];
        descriptor[8..14].copy_from_slice(&[0xda, 0x0b, 0x53, 0x81, 0x00, 0x30]);
        let bytes = image(&[mac(true, true)]);
        let original = bytes.as_ptr();
        let provider = Recording {
            catalog: catalog(bytes, "usb:0bda:8153:3000"),
            requests: RefCell::new(Vec::new()),
        };
        assert!(
            load(&provider, &descriptor, Revision(0x4c10))
                .unwrap()
                .is_none()
        );
        assert!(provider.requests.borrow().is_empty());
        let (resource, parsed) = load(&provider, &descriptor, Revision(0x5c10))
            .unwrap()
            .unwrap();
        assert_eq!(resource.bytes().as_ptr(), original);
        assert_eq!(parsed.blocks().len(), 1);
        assert_eq!(
            provider.requests.borrow()[0],
            (
                "rtl_nic/rtl8153a-2.fw".into(),
                "usb:0bda:8153:3000".into(),
                "tcr-5c10".into()
            )
        );
        descriptor[12] = 1;
        let Err(Error::Firmware { request, error }) =
            load(&provider, &descriptor, Revision(0x5c10))
        else {
            panic!()
        };
        assert_eq!(error.kind, ErrorKind::WrongTarget);
        assert_eq!(request.hardware, "usb:0bda:8153:3001");
        let empty = HandoffProvider::new(None);
        let Err(Error::Firmware { request, error }) = load(&empty, &descriptor, Revision(0x5c10))
        else {
            panic!()
        };
        assert_eq!(request.name, "rtl_nic/rtl8153a-2.fw");
        assert_eq!(request.revision, "tcr-5c10");
        assert_eq!(error.kind, ErrorKind::Missing);
        descriptor[12] = 0;
        let mut bytes = image(&[mac(true, true)]);
        bytes[32] ^= 1; // Catalog-valid image, invalid vendor checksum.
        let invalid = catalog(bytes, "usb:0bda:8153:3000");
        assert!(matches!(
            load(&invalid, &descriptor, Revision(0x5c10)),
            Err(Error::Image { .. })
        ));
    }

    #[test]
    #[ignore = "requires seven immutable linux-firmware fixtures; see THIRD_PARTY.md"]
    fn pinned_real_firmware_files_parse_all_observed_block_effects() {
        extern crate std;
        let directory =
            std::env::var("STELA_RTL815X_FIRMWARE").expect("path to pinned fixture directory");
        for (name, revision, count, hash) in [
            (
                "rtl8153a-2.fw",
                0x5c10,
                5,
                "7d4f422ec0e8141576c1b486fe6b7c6ce8ec9ea1f650815fd4058878c038366d",
            ),
            (
                "rtl8153a-3.fw",
                0x5c20,
                5,
                "c7099a1b0fc80e02ff7276aacbb08b5771e2f5c763fb76a7a8df3a89d58d8208",
            ),
            (
                "rtl8153a-4.fw",
                0x5c30,
                5,
                "99a05414fc0ae3b99a453d73b5cae90bfa6d371320f78011fc58cb03a33e2a09",
            ),
            (
                "rtl8153b-2.fw",
                0x6010,
                2,
                "137c9c752e8648ecfcf3b74ffc7d675c098145c222e2969721e6257af31716bc",
            ),
            (
                "rtl8153c-1.fw",
                0x6400,
                2,
                "bbe5f74bd2625b71c9a70e0588472ef670b5eeb65f83b1202cd25b3381720a3f",
            ),
            (
                "rtl8156a-2.fw",
                0x7030,
                14,
                "7b50f4a307bde7b3f384935537c4d9705457fa42613eb0003ffbc4e19461a1e0",
            ),
            (
                "rtl8156b-2.fw",
                0x7410,
                3,
                "5a3b21e27305876af8eac4b9bd11a821487b338e4ac1b58b8be8d23467d3f91f",
            ),
        ] {
            let bytes = std::fs::read(std::path::Path::new(&directory).join(name)).unwrap();
            assert_eq!(alloc::format!("{:x}", Sha256::digest(&bytes)), hash);
            let firmware = Firmware::parse(&bytes, Revision(revision)).unwrap();
            assert_eq!(firmware.blocks().len(), count, "{name}");
        }
    }

    #[test]
    #[ignore = "requires unchanged pinned Linux validator cases; see tests/reference/rtl815x_firmware_oracle.py"]
    fn unchanged_linux_firmware_validators_match_real_and_mutated_fields() {
        extern crate std;
        let path = std::env::var("STELA_RTL815X_FIRMWARE_ORACLE")
            .expect("path to source oracle cases.txt");
        let cases = std::fs::read_to_string(path).unwrap();
        let mut count = 0;
        let mut accepted = 0;
        for line in cases.lines() {
            let mut fields = line.splitn(3, ' ');
            let revision = Revision(u16::from_str_radix(fields.next().unwrap(), 16).unwrap());
            let expected = fields.next().unwrap() == "1";
            let filename = fields.next().unwrap();
            let bytes = std::fs::read(filename).unwrap();
            let result = Firmware::parse(&bytes, revision);
            assert_eq!(result.is_ok(), expected, "{filename}: {result:?}");
            count += 1;
            accepted += usize::from(expected);
        }
        assert!(count > 200);
        assert!(accepted >= 7);
        assert!(accepted < count);
    }
}
