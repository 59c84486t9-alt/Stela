//! Block devices addressed by logical block, with explicit errors.
use alloc::{boxed::Box, rc::Rc, string::String};
use core::cell::RefCell;
use core::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockError {
    /// The transfer is not a whole number of blocks.
    Misaligned { bytes: usize, block_size: u32 },
    /// The transfer reaches past the last block.
    OutOfRange {
        lba: u64,
        blocks: u64,
        capacity: u64,
    },
    /// The device refuses writes.
    ReadOnly,
    /// The device reported a failure with this controller status.
    Device { status: u32 },
    /// The device did not complete in time.
    Timeout,
    /// The DMA pages are exhausted.
    NoDmaMemory,
    /// The device needs something these drivers do not implement.
    Unsupported(&'static str),
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Misaligned { bytes, block_size } => {
                write!(
                    f,
                    "{bytes} bytes is not a multiple of {block_size}-byte blocks"
                )
            }
            Self::OutOfRange {
                lba,
                blocks,
                capacity,
            } => write!(f, "blocks {lba}+{blocks} exceed capacity {capacity}"),
            Self::ReadOnly => f.write_str("device is read-only"),
            Self::Device { status } => write!(f, "device status {status:#x}"),
            Self::Timeout => f.write_str("device timeout"),
            Self::NoDmaMemory => f.write_str("DMA pages exhausted"),
            Self::Unsupported(what) => write!(f, "unsupported: {what}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    VirtioBlk,
    Nvme,
    Ahci,
    /// USB mass storage (Bulk-Only) behind an xHCI controller.
    Usb,
}

/// What a device reports about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub transport: Transport,
    /// The PCI function, and the NVMe namespace or AHCI port behind it.
    pub location: String,
    pub model: String,
    /// The serial number without padding; empty when the device has none.
    pub serial: String,
    pub blocks: u64,
    pub block_size: u32,
    pub read_only: bool,
}

impl Identity {
    pub fn bytes(&self) -> u64 {
        self.blocks * u64::from(self.block_size)
    }

    /// The number of blocks in a `bytes`-long transfer at `lba`, after
    /// checking alignment and range.
    pub fn check(&self, lba: u64, bytes: usize) -> Result<u64, BlockError> {
        let block_size = self.block_size as usize;
        if !bytes.is_multiple_of(block_size) {
            return Err(BlockError::Misaligned {
                bytes,
                block_size: self.block_size,
            });
        }
        let blocks = (bytes / block_size) as u64;
        match lba.checked_add(blocks) {
            Some(end) if end <= self.blocks => Ok(blocks),
            _ => Err(BlockError::OutOfRange {
                lba,
                blocks,
                capacity: self.blocks,
            }),
        }
    }

    pub fn check_write(&self, lba: u64, bytes: usize) -> Result<u64, BlockError> {
        if self.read_only {
            return Err(BlockError::ReadOnly);
        }
        self.check(lba, bytes)
    }
}

/// A disk or a view of one. Transfers are whole blocks; a call returns only
/// after the device completed it.
pub trait BlockDevice {
    fn identity(&self) -> &Identity;
    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError>;
    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError>;
    /// Make every completed write durable.
    fn flush(&mut self) -> Result<(), BlockError>;
}

impl<D: BlockDevice + ?Sized> BlockDevice for Box<D> {
    fn identity(&self) -> &Identity {
        (**self).identity()
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        (**self).read(lba, buffer)
    }

    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        (**self).write(lba, data)
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        (**self).flush()
    }
}

/// ASCII from a fixed-width identify field, trimmed of padding.
pub(crate) fn ascii(bytes: &[u8]) -> String {
    let text: String = bytes
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| match byte {
            0x20..=0x7e => *byte as char,
            _ => '?',
        })
        .collect();
    String::from(text.trim())
}

/// One disk several owners share, each through its own [`Window`].
#[derive(Clone)]
pub struct Shared(Rc<RefCell<Box<dyn BlockDevice>>>);

impl Shared {
    pub fn new(device: Box<dyn BlockDevice>) -> Self {
        Self(Rc::new(RefCell::new(device)))
    }

    /// Every block, as a device of its own.
    pub fn whole(&self) -> Window {
        let identity = self.0.borrow().identity().clone();
        Window {
            disk: self.clone(),
            first: 0,
            identity,
        }
    }

    /// The `blocks` blocks from `first`, as a device of their own.
    pub fn window(&self, first: u64, blocks: u64) -> Result<Window, BlockError> {
        let mut identity = self.0.borrow().identity().clone();
        match first.checked_add(blocks) {
            Some(end) if end <= identity.blocks => (),
            _ => {
                return Err(BlockError::OutOfRange {
                    lba: first,
                    blocks,
                    capacity: identity.blocks,
                });
            }
        }
        identity.blocks = blocks;
        Ok(Window {
            disk: self.clone(),
            first,
            identity,
        })
    }
}

/// A run of blocks of a [`Shared`] disk.
pub struct Window {
    disk: Shared,
    first: u64,
    identity: Identity,
}

impl BlockDevice for Window {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.identity.check(lba, buffer.len())?;
        self.disk.0.borrow_mut().read(self.first + lba, buffer)
    }

    fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        self.identity.check_write(lba, data.len())?;
        self.disk.0.borrow_mut().write(self.first + lba, data)
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        self.disk.0.borrow_mut().flush()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// A RAM disk for the partition and selection tests.
    pub(crate) struct RamDisk {
        pub(crate) identity: Identity,
        pub(crate) bytes: Vec<u8>,
        pub(crate) flushes: usize,
    }

    impl RamDisk {
        pub(crate) fn new(serial: &str, blocks: u64, block_size: u32) -> Self {
            Self {
                identity: Identity {
                    transport: Transport::VirtioBlk,
                    location: String::from("test"),
                    model: String::from("RAM"),
                    serial: String::from(serial),
                    blocks,
                    block_size,
                    read_only: false,
                },
                bytes: vec![0; (blocks * u64::from(block_size)) as usize],
                flushes: 0,
            }
        }

        fn span(&self, lba: u64, bytes: usize) -> core::ops::Range<usize> {
            let start = (lba * u64::from(self.identity.block_size)) as usize;
            start..start + bytes
        }
    }

    impl BlockDevice for RamDisk {
        fn identity(&self) -> &Identity {
            &self.identity
        }

        fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
            self.identity.check(lba, buffer.len())?;
            buffer.copy_from_slice(&self.bytes[self.span(lba, buffer.len())]);
            Ok(())
        }

        fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
            self.identity.check_write(lba, data.len())?;
            let span = self.span(lba, data.len());
            self.bytes[span].copy_from_slice(data);
            Ok(())
        }

        fn flush(&mut self) -> Result<(), BlockError> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[test]
    fn transfers_must_be_whole_blocks_inside_the_device() {
        let disk = RamDisk::new("s", 8, 512);
        assert_eq!(disk.identity.check(0, 4096), Ok(8));
        assert_eq!(disk.identity.check(7, 512), Ok(1));
        assert_eq!(
            disk.identity.check(7, 1024),
            Err(BlockError::OutOfRange {
                lba: 7,
                blocks: 2,
                capacity: 8
            })
        );
        assert_eq!(
            disk.identity.check(u64::MAX, 512),
            Err(BlockError::OutOfRange {
                lba: u64::MAX,
                blocks: 1,
                capacity: 8
            })
        );
        assert_eq!(
            disk.identity.check(0, 100),
            Err(BlockError::Misaligned {
                bytes: 100,
                block_size: 512
            })
        );
        let mut read_only = disk.identity.clone();
        read_only.read_only = true;
        assert_eq!(read_only.check_write(0, 512), Err(BlockError::ReadOnly));
    }

    #[test]
    fn windows_share_one_disk_and_stay_inside_their_blocks() {
        let shared = Shared::new(Box::new(RamDisk::new("s", 8, 512)));
        let mut low = shared.window(0, 4).unwrap();
        let mut high = shared.window(4, 4).unwrap();
        assert!(shared.window(6, 3).is_err());
        assert_eq!(high.identity().blocks, 4);
        high.write(0, &[7; 512]).unwrap();
        let mut block = [0; 512];
        low.read(3, &mut block).unwrap();
        assert_eq!(block, [0; 512]);
        assert!(low.read(4, &mut block).is_err());
        let mut whole = shared.window(0, 8).unwrap();
        whole.read(4, &mut block).unwrap();
        assert_eq!(block, [7; 512]);
        low.flush().unwrap();
    }

    #[test]
    fn identify_strings_lose_padding_and_terminators() {
        assert_eq!(ascii(b"  S4EVNX0R123   "), "S4EVNX0R123");
        assert_eq!(ascii(b"QEMU\0junk"), "QEMU");
        assert_eq!(ascii(b"a\x01b"), "a?b");
    }
}
