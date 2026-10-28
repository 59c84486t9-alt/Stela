//! AP-produced SEP shared-memory directory, inspected through dart-sep.
//!
//! `AppleSEPSharedMemoryBuffer::createWithOwnerChannelsAndMapper` (kernel
//! file 0x2d65690..0x2d659f4) copies 16-byte {name:u32,size:u32,base:u64}
//! entries, then {name:'null',size:0,base:0}. Non-TXMB bases are offsets;
//! TXMB's base is a separately mapped IOVA (`_mapStandaloneChannel`,
//! 0x2d654f4). The directory and ordinary channel sizes round to the SEP
//! page size (4 or 16 KiB). This decoder grants no boot acknowledgement or
//! authority to consume a channel whose own content protocol is unknown.
use super::{
    super::asc::Message,
    message::{self, Frame},
};
use alloc::vec::Vec;
use {stela_contracts::dma::DmaError, stela_contracts::dma::Port};

const ENTRY_BYTES: u64 = 16;
const NULL: u32 = u32::from_be_bytes(*b"null");
const TXMB: u32 = u32::from_be_bytes(*b"TXMB");
const WIRE_PAGE_SHIFT: u32 = 12;
const WIRE_PAGE: u64 = 1 << WIRE_PAGE_SHIFT;
/// Stela's directory bound, not a fabricated channel-count register.
const MAX_CHANNELS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub address: u64,
    pub bytes: u64,
}

impl Region {
    /// `AppleSEPBooter::bootSEP`, 0x2d73ddc..0x2d73e68. This is a
    /// normal service-0xfe frame with a 16-bit page count across op/param.
    pub fn from_message(message: Message) -> Result<Self, &'static str> {
        let frame = Frame::from_mailbox(message)?;
        if frame.service != message::BOOT || frame.tag != 0 {
            return Err("SEP shared-memory frame service/tag is invalid");
        }
        let pages = u16::from_le_bytes([frame.opcode, frame.parameter]);
        if pages == 0 || frame.data == 0 {
            return Err("SEP shared-memory address or length is zero");
        }
        Ok(Self {
            address: u64::from(frame.data) << WIRE_PAGE_SHIFT,
            bytes: u64::from(pages) << WIRE_PAGE_SHIFT,
        })
    }

    pub fn subregion(self, offset: u64, bytes: u64) -> Result<Self, &'static str> {
        if bytes == 0 || offset.checked_add(bytes).is_none_or(|end| end > self.bytes) {
            return Err("SEP channel extent is outside its region");
        }
        let address = self
            .address
            .checked_add(offset)
            .ok_or("SEP channel address overflows")?;
        address
            .checked_add(bytes)
            .ok_or("SEP channel extent overflows")?;
        Ok(Self { address, bytes })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Channel {
    pub name: u32,
    pub region: Region,
    pub standalone: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub region: Region,
    pub channels: Vec<Channel>,
}

impl Layout {
    /// Inspect metadata only, preserving guest RAM. Page size must be supplied
    /// by the platform's SEP configuration; it is never guessed from offsets.
    pub fn read(port: &mut Port<'_, '_>, region: Region, page: u64) -> Result<Self, DmaError> {
        let bad = DmaError::Unsupported;
        if ![WIRE_PAGE, WIRE_PAGE * 4].contains(&page)
            || !region.address.is_multiple_of(page)
            || !region.bytes.is_multiple_of(page)
            || region.bytes < page
        {
            return Err(bad(
                "SEP shared-memory alignment or page size is unsupported",
            ));
        }
        region
            .address
            .checked_add(region.bytes)
            .ok_or(bad("SEP shared-memory extent overflows"))?;
        let mut channels: Vec<Channel> = Vec::new();
        let mut directory_end = None;
        for index in 0..=MAX_CHANNELS {
            let mut entry = [0; ENTRY_BYTES as usize];
            port.read(region.address + index as u64 * ENTRY_BYTES, &mut entry)?;
            let name = u32::from_le_bytes(entry[..4].try_into().unwrap());
            let bytes = u64::from(u32::from_le_bytes(entry[4..8].try_into().unwrap()));
            let base = u64::from_le_bytes(entry[8..].try_into().unwrap());
            if name == NULL {
                if bytes != 0 || base != 0 {
                    return Err(bad("SEP shared-memory terminator is malformed"));
                }
                directory_end = Some(((index as u64 + 1) * ENTRY_BYTES).next_multiple_of(page));
                break;
            }
            if index == MAX_CHANNELS {
                return Err(bad(
                    "SEP shared-memory directory exceeds the resource bound",
                ));
            }
            if channels.iter().any(|c| c.name == name) {
                return Err(bad("SEP shared-memory channel name is duplicated"));
            }
            if bytes == 0 || !bytes.is_multiple_of(page) || !base.is_multiple_of(page) {
                return Err(bad(
                    "SEP shared-memory channel alignment or size is invalid",
                ));
            }
            let standalone = name == TXMB;
            let channel = if standalone {
                if base == 0 || bytes != page {
                    return Err(bad("SEP TXMB must name one separately mapped page"));
                }
                base.checked_add(bytes)
                    .ok_or(bad("SEP standalone channel extent overflows"))?;
                Region {
                    address: base,
                    bytes,
                }
            } else {
                region.subregion(base, bytes).map_err(bad)?
            };
            channels.push(Channel {
                name,
                region: channel,
                standalone,
            });
        }
        let directory_end =
            directory_end.ok_or(bad("SEP shared-memory directory has no terminator"))?;
        for (index, channel) in channels.iter().enumerate() {
            if channel.region.address < region.address + directory_end
                && region.address < channel.region.address + channel.region.bytes
            {
                return Err(bad("SEP channel overlaps its directory"));
            }
            for other in &channels[..index] {
                if channel.region.address < other.region.address + other.region.bytes
                    && other.region.address < channel.region.address + channel.region.bytes
                {
                    return Err(bad("SEP shared-memory channel IOVAs overlap"));
                }
            }
        }
        Ok(Self { region, channels })
    }
}

/// `_timebaseUpdate` 0x2d732d0 calls `sendRawMessage` (0x2d6ae10,
/// mode 3). `_sendMessageGated` 0x2d6abcc/0x2d6ac90 preserves ALL payload
/// bits in raw mode: there is no service byte to mask away. Only a caller
/// already in the timebase phase may interpret this word as a timebase.
#[cfg(test)]
pub fn raw_timebase(message: Message) -> Result<u64, &'static str> {
    if message.endpoint != 0 {
        return Err("SEP raw timebase requires ASC endpoint zero");
    }
    Ok(message.payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use {
        stela_contracts::bus::Access, stela_contracts::dma::Iommu, stela_contracts::dma::Memory,
        stela_contracts::dma::test_support::Ram, stela_contracts::interrupt::InterruptLatch,
    };

    struct Mapper {
        translations: usize,
        deny: bool,
    }
    impl Iommu for Mapper {
        fn page(&self) -> u64 {
            WIRE_PAGE
        }
        fn translate(
            &mut self,
            _: &mut dyn Memory,
            stream: usize,
            iova: u64,
            last: u64,
            write: bool,
            _: &mut Access<'_>,
        ) -> Result<u64, DmaError> {
            assert_eq!(stream, 0);
            assert!(!write);
            assert_eq!(iova / WIRE_PAGE, last / WIRE_PAGE);
            self.translations += 1;
            if self.deny {
                Err(DmaError::Fault(7))
            } else {
                Ok(iova + 0x10000)
            }
        }
    }
    fn entry(name: u32, bytes: u32, base: u64) -> [u8; 16] {
        let mut b = [0; 16];
        b[..4].copy_from_slice(&name.to_le_bytes());
        b[4..8].copy_from_slice(&bytes.to_le_bytes());
        b[8..].copy_from_slice(&base.to_le_bytes());
        b
    }
    fn read(entries: &[[u8; 16]], deny: bool) -> Result<Layout, DmaError> {
        let mut ram = Ram::new(0x14000, 0x4000);
        for (dst, src) in ram.bytes.chunks_mut(16).zip(entries) {
            dst.copy_from_slice(src);
        }
        let before = ram.bytes.clone();
        let mut mapper = Mapper {
            translations: 0,
            deny,
        };
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let result = Layout::read(
            &mut Port {
                iommu: &mut mapper,
                stream: 0,
                memory: &mut ram,
                access: &mut access,
            },
            Region {
                address: 0x4000,
                bytes: 0xc000,
            },
            0x4000,
        );
        assert_eq!(ram.bytes, before);
        assert!(mapper.translations > 0);
        result
    }
    #[test]
    fn channels_use_directory_offsets_and_txmb_uses_an_independent_iova() {
        let name = u32::from_be_bytes(*b"FLAG");
        let layout = read(
            &[
                entry(name, 0x4000, 0x4000),
                entry(TXMB, 0x4000, 0x14000),
                entry(NULL, 0, 0),
            ],
            false,
        )
        .unwrap();
        assert_eq!(
            layout.channels[0].region,
            Region {
                address: 0x8000,
                bytes: 0x4000
            }
        );
        assert!(!layout.channels[0].standalone);
        assert!(layout.channels[1].standalone);
        assert_eq!(layout.channels[1].region.address, 0x14000);
        assert_eq!(read(&[entry(NULL, 0, 0)], true), Err(DmaError::Fault(7)));
    }
    #[test]
    fn malformed_directories_and_overlaps_refuse_without_guest_writes() {
        for entries in [
            alloc::vec![entry(NULL, 1, 0)],
            alloc::vec![entry(1, 0x4000, 0), entry(NULL, 0, 0)],
            alloc::vec![
                entry(1, 0x4000, 0x4000),
                entry(1, 0x4000, 0x8000),
                entry(NULL, 0, 0)
            ],
            alloc::vec![
                entry(1, 0x8000, 0x4000),
                entry(2, 0x4000, 0x8000),
                entry(NULL, 0, 0)
            ],
            alloc::vec![entry(1, 0x4000, 0xc000), entry(NULL, 0, 0)],
            alloc::vec![entry(TXMB, 0x4000, 0), entry(NULL, 0, 0)],
            alloc::vec![entry(1, 1, 0x4000), entry(NULL, 0, 0)],
        ] {
            assert!(read(&entries, false).is_err());
        }
    }
    #[test]
    fn boot_frame_and_raw_timebase_have_distinct_encodings() {
        let message = Message {
            endpoint: 0,
            payload: 0x0001_2345_0020_00fe,
        };
        assert_eq!(
            Region::from_message(message),
            Ok(Region {
                address: 0x1234_5000,
                bytes: 0x20000
            })
        );
        assert!(
            Region::from_message(Message {
                endpoint: 0,
                payload: 0xfe
            })
            .is_err()
        );
        assert!(
            Region::from_message(Message {
                endpoint: 0,
                payload: message.payload | 0x100
            })
            .is_err()
        );
        let raw = Message {
            endpoint: 0,
            payload: 0x1234_5678_9abc_def0,
        };
        assert_eq!(raw_timebase(raw), Ok(raw.payload));
        assert!(raw_timebase(Message { endpoint: 1, ..raw }).is_err());
        assert!(
            Region {
                address: u64::MAX - 1,
                bytes: 8
            }
            .subregion(1, 2)
            .is_err()
        );
    }
}
