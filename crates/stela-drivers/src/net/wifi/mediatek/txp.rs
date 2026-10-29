// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Ordinary hardware TXP scatter descriptors from mt76_connac_write_hw_txp.
//! Mapped spans keep canonical leases borrowed while encoding. This is
//! wire construction, not publication, token allocation or DMA completion.
use crate::bus::dma::mapping::{DmaError, DmaMapping};
use alloc::vec::Vec;

pub const BYTES: usize = 32;
pub const TXWI_BYTES: usize = 32 + BYTES;
const MAX_TOKEN: u16 = 8192;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidToken,
    InvalidSegmentCount,
    InvalidSegmentLength,
    InvalidRange,
    AddressLimit,
    Dma(DmaError),
}
impl From<DmaError> for Error {
    fn from(e: DmaError) -> Self {
        Self::Dma(e)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek TXP: {self:?}")
    }
}
impl core::error::Error for Error {}

#[derive(Clone)]
pub struct Span<'a> {
    mapping: &'a DmaMapping,
    offset: usize,
    bytes: u16,
}
impl<'a> Span<'a> {
    pub fn new(mapping: &'a DmaMapping, offset: usize, bytes: usize) -> Result<Self, Error> {
        if !(1..=0xfff).contains(&bytes) {
            return Err(Error::InvalidSegmentLength);
        }
        if offset
            .checked_add(bytes)
            .is_none_or(|end| end > mapping.bytes())
        {
            return Err(Error::InvalidRange);
        }
        let span = Self {
            mapping,
            offset,
            bytes: bytes as u16,
        };
        span.address()?;
        Ok(span)
    }
    fn address(&self) -> Result<u32, Error> {
        let address = self
            .mapping
            .address()?
            .checked_add(self.offset as u64)
            .ok_or(Error::AddressLimit)?;
        if address
            .checked_add(u64::from(self.bytes) - 1)
            .is_none_or(|end| end > u64::from(u32::MAX))
        {
            return Err(Error::AddressLimit);
        }
        u32::try_from(address).map_err(|_| Error::AddressLimit)
    }
}

pub struct Encoded<'a> {
    bytes: [u8; BYTES],
    _spans: Vec<Span<'a>>,
}
impl<'a> Encoded<'a> {
    /// Encode one live token and 1..=4 mapped data segments. The owner
    /// must keep those mappings, the separate 32-byte TXD and PCI
    /// requester through device publication, DMA consumption and firmware TX-free.
    /// This borrow only protects construction; copying the wire bytes is not a
    /// lifetime, direction, coherence, key-generation or hardware-epoch proof.
    pub fn new(token: u16, spans: &[Span<'a>]) -> Result<Self, Error> {
        if token >= MAX_TOKEN {
            return Err(Error::InvalidToken);
        }
        if !(1..=4).contains(&spans.len()) {
            return Err(Error::InvalidSegmentCount);
        }
        let raw: Vec<_> = spans
            .iter()
            .map(|span| span.address().map(|address| (address, span.bytes)))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            bytes: encode(token, &raw)?,
            _spans: spans.to_vec(),
        })
    }
    pub fn bytes(&self) -> &[u8; BYTES] {
        &self.bytes
    }
}
fn encode(token: u16, spans: &[(u32, u16)]) -> Result<[u8; BYTES], Error> {
    if token >= MAX_TOKEN {
        return Err(Error::InvalidToken);
    }
    if !(1..=4).contains(&spans.len()) {
        return Err(Error::InvalidSegmentCount);
    }
    let mut bytes = [0u8; BYTES];
    bytes[..2].copy_from_slice(&(token | 0x8000).to_le_bytes());
    for (i, &(address, len)) in spans.iter().enumerate() {
        if !(1..=0xfff).contains(&len) {
            return Err(Error::InvalidSegmentLength);
        }
        if address.checked_add(u32::from(len) - 1).is_none() {
            return Err(Error::AddressLimit);
        }
        let at = 8 + (i / 2) * 12;
        let last = if i + 1 == spans.len() { 0x8000 } else { 0 };
        let (address_at, length_at) = if i % 2 == 0 {
            (at, at + 4)
        } else {
            (at + 8, at + 6)
        };
        bytes[address_at..address_at + 4].copy_from_slice(&address.to_le_bytes());
        bytes[length_at..length_at + 2].copy_from_slice(&(len | last).to_le_bytes());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::dma::{
        mapping::{Direction, DmaDomain},
        memory::{CacheAttribute, PageSource},
    };
    use crate::net::wifi::mediatek::ring::tests::{Domain, Memory, Source};
    use alloc::sync::Arc;
    extern crate std;
    use std::sync::Mutex;
    #[test]
    fn canonical_iova_ranges_and_last_segment_are_encoded_without_cpu_substitution() {
        let memory = Arc::new(Mutex::new(Memory::default()));
        let domain: Arc<dyn DmaDomain> = Arc::new(Domain(memory.clone()));
        let pins = Source
            .allocate(8192, 4096, CacheAttribute::WriteBack)
            .unwrap();
        let mut mapping =
            DmaMapping::map(domain, pins, Direction::ToDevice, u32::MAX.into()).unwrap();
        let address = mapping.address().unwrap() as u32;
        let spans = [
            Span::new(&mapping, 17, 4095).unwrap(),
            Span::new(&mapping, 4112, 17).unwrap(),
        ];
        assert!(matches!(
            Encoded::new(8192, &spans),
            Err(Error::InvalidToken)
        ));
        assert!(matches!(
            Encoded::new(1, &[]),
            Err(Error::InvalidSegmentCount)
        ));
        assert!(matches!(
            Encoded::new(1, &vec![spans[0].clone(); 5]),
            Err(Error::InvalidSegmentCount)
        ));
        let encoded = Encoded::new(8191, &spans).unwrap();
        let b = encoded.bytes();
        assert_eq!(&b[..8], &[0xff, 0x9f, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&b[8..12], &(address + 17).to_le_bytes());
        assert_eq!(&b[12..16], &[0xff, 0x0f, 0x11, 0x80]);
        assert_eq!(&b[16..20], &(address + 4112).to_le_bytes());
        assert_eq!(&b[20..], &[0; 12]);
        assert_ne!(
            u64::from(address),
            memory.lock().unwrap().mappings[&u64::from(address)].1 as u64
        );
        drop(encoded);
        // SAFETY: this mapping was used only by the bounded codec model and
        // never published to any hardware or model DMA engine.
        unsafe { mapping.unmap() }.unwrap();
        assert!(memory.lock().unwrap().mappings.is_empty());
    }
    #[test]
    fn token_counts_lengths_ranges_and_address_overflow_cannot_be_silently_truncated() {
        assert_eq!(encode(8192, &[(0x1000, 1)]), Err(Error::InvalidToken));
        for n in [0, 5] {
            assert_eq!(
                encode(1, &vec![(0x1000, 1); n]),
                Err(Error::InvalidSegmentCount)
            );
        }
        for len in [0, 4096, u16::MAX] {
            assert_eq!(
                encode(1, &[(0x1000, len)]),
                Err(Error::InvalidSegmentLength)
            );
        }
        assert_eq!(encode(1, &[(u32::MAX, 2)]), Err(Error::AddressLimit));
        assert_eq!(encode(0, &[(u32::MAX, 1)]).unwrap()[12..14], [1, 0x80]);
        let domain: Arc<dyn DmaDomain> = Arc::new(Domain(Arc::new(Mutex::new(Memory::default()))));
        let pins = Source
            .allocate(4096, 4096, CacheAttribute::WriteBack)
            .unwrap();
        let mut mapping =
            DmaMapping::map(domain, pins, Direction::ToDevice, u32::MAX.into()).unwrap();
        assert!(matches!(
            Span::new(&mapping, usize::MAX, 1),
            Err(Error::InvalidRange)
        ));
        assert!(matches!(
            Span::new(&mapping, 4095, 2),
            Err(Error::InvalidRange)
        ));
        assert!(matches!(
            Span::new(&mapping, 0, 4096),
            Err(Error::InvalidSegmentLength)
        ));
        // SAFETY: the model device is stopped and drained, so nothing still uses what this
        // releases.
        unsafe { mapping.unmap() }.unwrap();
        assert!(matches!(
            Span::new(&mapping, 0, 1),
            Err(Error::Dma(DmaError::Unmapped))
        ));
    }
    #[test]
    #[ignore = "oracle: STELA_MT792X_TXP_ORACLE"]
    fn unchanged_pinned_hw_txp_matches_every_scatter_byte_and_txwi_size() {
        let root = std::env::var_os("STELA_MT792X_TXP_ORACLE").expect("reference trace directory");
        for chip in [7921, 7922, 7925] {
            let bytes =
                std::fs::read(std::path::Path::new(&root).join(format!("mt{chip}.bin"))).unwrap();
            let mut at = 0;
            let word = |at: &mut usize| {
                let v = u32::from_le_bytes(bytes[*at..*at + 4].try_into().unwrap());
                *at += 4;
                v
            };
            for _ in 0..100 {
                let token = u16::try_from(word(&mut at)).unwrap();
                let count = word(&mut at);
                let spans: Vec<_> = (0..count)
                    .map(|_| (word(&mut at), u16::try_from(word(&mut at)).unwrap()))
                    .collect();
                let actual = encode(token, &spans).unwrap();
                assert_eq!(actual, &bytes[at..at + BYTES]);
                at += BYTES;
                assert_eq!(word(&mut at), TXWI_BYTES as u32);
                assert_eq!(word(&mut at), 1);
            }
            assert_eq!(at, bytes.len());
        }
    }
}
