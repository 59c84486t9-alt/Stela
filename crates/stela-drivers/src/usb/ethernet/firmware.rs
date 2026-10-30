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
use crate::bytes::{le16, le32};
use crate::{block::BlockError, firmware as resources};
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::fmt;
use stela_crypto::{Sha256, digest::Digest};

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

/// Owned upload provenance. No image bytes or borrowed Provider storage escape
/// synchronous construction of an initialized native backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub request: Request,
    pub length: usize,
    pub sha256: [u8; 32],
    pub source: String,
    pub source_revision: String,
    pub member: String,
    pub license: String,
}

impl Receipt {
    pub(crate) fn from_image(image: resources::Image<'_>) -> Self {
        let target = image.target();
        let provenance = image.provenance();
        Self {
            request: Request {
                name: image.name().into(),
                hardware: target.hardware.into(),
                revision: target.revision.into(),
            },
            length: image.bytes().len(),
            sha256: image.sha256(),
            source: provenance.source.into(),
            source_revision: provenance.revision.into(),
            member: provenance.member.into(),
            license: provenance.license.into(),
        }
    }
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
        le16(self.bytes, 10)
    }
    pub fn breakpoint_base(&self) -> (u16, u16) {
        (le16(self.bytes, 12), le16(self.bytes, 14))
    }
    pub fn breakpoint_enable(&self) -> (u16, u16) {
        (le16(self.bytes, 16), le16(self.bytes, 18))
    }
    pub fn breakpoint_start(&self) -> u16 {
        le16(self.bytes, 20)
    }
    pub fn breakpoints(&self) -> impl Iterator<Item = u16> + '_ {
        (0..usize::from(le16(self.bytes, 22))).map(|i| le16(self.bytes, 24 + 2 * i))
    }
    pub fn version_register(&self) -> (u16, u8) {
        (le16(self.bytes, 60), self.bytes[62])
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
        le16(self.bytes, 10)
    }
    pub fn base(&self) -> (u16, u16) {
        (le16(self.bytes, 12), le16(self.bytes, 14))
    }
    pub fn patch_enable(&self) -> (u16, u16) {
        (le16(self.bytes, 16), le16(self.bytes, 18))
    }
    pub fn mode(&self) -> (u16, u16, u16) {
        (
            le16(self.bytes, 20),
            le16(self.bytes, 22),
            le16(self.bytes, 24),
        )
    }
    pub fn breakpoint_start(&self) -> u16 {
        le16(self.bytes, 28)
    }
    pub fn breakpoints(&self) -> impl Iterator<Item = u16> + '_ {
        (0..usize::from(le16(self.bytes, 30))).map(|i| le16(self.bytes, 32 + 2 * i))
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
        le16(self.bytes, 10)
    }
    pub fn presets(&self) -> impl Iterator<Item = (u16, u16)> + '_ {
        (0..usize::from(self.bytes[56]))
            .map(|i| (le16(self.bytes, 12 + 4 * i), le16(self.bytes, 14 + 4 * i)))
    }
    pub fn breakpoints(&self) -> impl Iterator<Item = (u16, u16)> + '_ {
        (0..usize::from(self.bytes[57]))
            .map(|i| (le16(self.bytes, 20 + 4 * i), le16(self.bytes, 22 + 4 * i)))
    }
    pub fn breakpoint_enable(&self) -> Option<(u16, u16)> {
        (self.bytes[57] != 0 && le16(self.bytes, 52) != 0)
            .then(|| (le16(self.bytes, 52), le16(self.bytes, 54)))
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
    let offset = usize::from(le16(bytes, 8));
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
            let kind = le32(header, 0);
            let length = le32(header, 4) as usize;
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
                START if length == 16 && le16(block, 8) != 0 => Block::PhyStart {
                    key_register: le16(block, 8),
                    key: le16(block, 10),
                },
                STOP if length == 8 => Block::PhyStop,
                NC => {
                    let data = payload(block, PHY_NC_HEADER, 2)?;
                    if !matches!(revision.0, 0x5c10 | 0x5c20 | 0x5c30)
                        || le16(block, 10) != 0xa014
                        || le16(block, 12) != 0xa012
                        || le16(block, 16) != 0xa01a
                        || le16(block, 20) != 0xb820
                        || le16(block, 28) != 0xa000
                        || le16(block, 30) > 4
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
                        && le16(block, 8) == 0xb820
                        && le16(block, 10) == 0x80 =>
                {
                    let operation = match le16(block, 12) {
                        0 => Fixup::And,
                        1 => Fixup::Or,
                        2 => Fixup::Clear,
                        3 => Fixup::Xor,
                        _ => return Err("RTL815x unknown PHY fixup operation"),
                    };
                    Block::PhyFixup {
                        register: le16(block, 8),
                        value: le16(block, 10),
                        operation,
                    }
                }
                SPEED_UP => {
                    let data = payload(block, 16, 4)?;
                    if !matches!(revision.0, 0x7410 | 0x7420) || le16(block, 12) != 0x9a00 {
                        return Err("RTL815x invalid PHY speed-up revision/register");
                    }
                    Block::PhySpeedUp {
                        register: le16(block, 12),
                        version: le16(block, 10),
                        payload: data,
                    }
                }
                VERSION
                    if length == 16
                        && matches!(revision.0, 0x7030 | 0x7410 | 0x7420)
                        && le16(block, 8) == 0x801e =>
                {
                    Block::PhyVersion {
                        register: le16(block, 8),
                        version: le16(block, 10),
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
    let count = usize::from(le16(bytes, 22));
    if le16(bytes, 10) != register
        || le16(bytes, 12) != 0xfc26
        || le16(bytes, 16) != enable
        || le16(bytes, 20) != 0xfc28
        || count > maximum
        || usize::from(register) + data.len() >= 0x10000
    {
        return Err("RTL815x invalid MAC firmware registers/breakpoints/range");
    }
    if (count..maximum).any(|i| le16(bytes, 24 + i * 2) != 0) {
        return Err("RTL815x nonzero unused MAC breakpoint");
    }
    Ok(Mac {
        bytes,
        payload: data,
        bank: if pla { Bank::Pla } else { Bank::Usb },
    })
}

#[cfg(test)]
pub(crate) mod tests;
