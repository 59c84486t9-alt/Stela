//! Single-wire, 24-bit SPI NOR behind `spi::Spi`.
//!
//! Contract: 26A434 `AppleARMSPIFlashController::_readJedecId` file
//! 0x1c7d364 (9f), `_readRDSR` 0x1c7d1b8 (05), `_writeEnable`
//! 0x1c7d048 (06/04), `_programBytes` 0x1c7c894 (02), `_eraseSector`
//! 0x1c7c480 (20), `_eraseBlock` 0x1c7c288 (d8), `readBuffer`
//! 0x1c9ffdc (03). The identifier table at 0x1c7b7a0 accepts ef6514.
//! Stela chooses that identifier for a 1 MiB emulated die, with 256-byte
//! pages, 4 KiB sectors and 64 KiB blocks. It is not a claim about the
//! physical board's flash vendor. J473AP `spinor/ranges` spans 1 MiB;
//! its partition `reg`s are empty, so Stela's boot firmware assigns them.
//!
//! Commands commit on CS rising. This functional die completes program and
//! erase at that boundary (zero busy latency), so WIP is always clear;
//! status WEL follows WREN/WRDI and is consumed by program/erase/WRSR.
//! Unsupported commands refuse before their byte is accepted.
use alloc::{collections::BTreeSet, vec, vec::Vec};
pub mod nvram;
pub mod persist;

pub const CAPACITY: usize = 0x100000;
pub const PAGE_SIZE: usize = 256;
pub const SECTOR_SIZE: usize = 0x1000;
pub const BLOCK_SIZE: usize = 0x10000;
pub const JEDEC_ID: [u8; 3] = [0xef, 0x65, 0x14];
pub const ERASED: u8 = 0xff;
/// Stela boot-chain partition choices, all erase-block aligned.
pub const FIRMWARE: (u32, u32) = (0, 0xc0000);
pub const ANVRAM: (u32, u32) = (0xc0000, 0x20000);
pub const SYSCFG: (u32, u32) = (0xe0000, 0x20000);
const WEL: u8 = 2;
const READ: u8 = 0x03;
const FAST_READ: u8 = 0x0b;
const PROGRAM: u8 = 0x02;
const ERASE_SECTOR: u8 = 0x20;
const ERASE_BLOCK: u8 = 0xd8;
const READ_STATUS: u8 = 0x05;
const WRITE_STATUS: u8 = 0x01;
const WRITE_ENABLE: u8 = 0x06;
const WRITE_DISABLE: u8 = 0x04;
const READ_ID: u8 = 0x9f;

/// The NOR image. [`persist`] loads a whole image from a host partition
/// before boot, the proxy is derived from it ([`Image::current_bank`]), and
/// the die reports the sectors each committed program or erase changed
/// ([`Nor::take_dirty`]) for the host to store; there is no independent
/// proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image(Vec<u8>);
impl Image {
    pub fn fresh() -> Self {
        let mut image = Self(vec![ERASED; CAPACITY]);
        image.0[ANVRAM.0 as usize..ANVRAM.0 as usize + nvram::BANK_SIZE]
            .copy_from_slice(&nvram::empty_bank());
        image
    }
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, &'static str> {
        if bytes.len() != CAPACITY {
            return Err("NOR image is not 1 MiB");
        }
        Ok(Self(bytes))
    }
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn bank(&self, bank: u32) -> Result<&[u8], &'static str> {
        if bank >= nvram::BANK_COUNT {
            return Err("NVRAM bank is outside anvram");
        }
        let start = ANVRAM.0 as usize + bank as usize * nvram::BANK_SIZE;
        Ok(&self.0[start..start + nvram::BANK_SIZE])
    }
    /// The newest valid NVRAM bank, by generation; the lower bank wins a
    /// tie.
    pub fn current_bank(&self) -> Result<u32, &'static str> {
        (0..nvram::BANK_COUNT)
            .filter_map(|bank| {
                let bytes = self.bank(bank).ok()?;
                nvram::validate(bytes).ok()?;
                Some((nvram::generation(bytes), bank))
            })
            .max_by_key(|&(generation, bank)| (generation, core::cmp::Reverse(bank)))
            .map(|(_, bank)| bank)
            .ok_or("the NOR image holds no valid NVRAM bank")
    }
    pub fn with_proxy(mut self, bank: u32, proxy: &[u8]) -> Result<Self, &'static str> {
        nvram::validate(proxy)?;
        self.bank(bank)?;
        let start = ANVRAM.0 as usize + bank as usize * nvram::BANK_SIZE;
        self.0[start..start + proxy.len()].copy_from_slice(proxy);
        Ok(self)
    }
}

#[derive(Clone)]
struct Transaction {
    command: u8,
    position: usize,
    address: usize,
    data: Vec<u8>,
}

pub(crate) struct Checkpoint(Option<Transaction>);

pub struct Nor {
    image: Image,
    enabled: bool,
    selected: bool,
    transaction: Option<Transaction>,
    /// Sectors committed programs and erases changed since the host last
    /// took them.
    dirty: BTreeSet<usize>,
}
impl Nor {
    pub fn new(image: Image) -> Self {
        Self {
            image,
            enabled: false,
            selected: false,
            transaction: None,
            dirty: BTreeSet::new(),
        }
    }
    /// The changed sectors, each as (offset, its current bytes).
    pub fn take_dirty(&mut self) -> Vec<(usize, Vec<u8>)> {
        core::mem::take(&mut self.dirty)
            .into_iter()
            .map(|sector| {
                let offset = sector * SECTOR_SIZE;
                (offset, self.image.0[offset..offset + SECTOR_SIZE].to_vec())
            })
            .collect()
    }
    pub(crate) fn checkpoint(&self) -> Checkpoint {
        Checkpoint(self.transaction.clone())
    }
    pub(crate) fn restore(&mut self, checkpoint: Checkpoint) {
        self.transaction = checkpoint.0;
    }
    pub fn image(&self) -> &Image {
        &self.image
    }
    pub fn selected(&self) -> bool {
        self.selected
    }

    pub(crate) fn check_select(&self, selected: bool) -> Result<(), &'static str> {
        if !selected && let Some(t) = &self.transaction {
            let required = match t.command {
                READ | PROGRAM | ERASE_SECTOR | ERASE_BLOCK => 3,
                FAST_READ => 4,
                WRITE_STATUS => 1,
                _ => 0,
            };
            if t.position < required {
                return Err("incomplete NOR command at CS rising");
            }
            if t.command == PROGRAM && t.data.is_empty() {
                return Err("empty NOR page program");
            }
            if t.command == WRITE_STATUS && t.data != [0] {
                return Err("NOR status protection fields are not modeled");
            }
        }
        Ok(())
    }

    /// CS active low; a rising edge terminates the command, retaining all
    /// bytes between falling/rising edges across controller transfers.
    pub fn select(&mut self, selected: bool) -> Result<(), &'static str> {
        if self.selected == selected {
            return Ok(());
        }
        self.check_select(selected)?;
        if !selected && let Some(t) = self.transaction.take() {
            match t.command {
                WRITE_ENABLE => self.enabled = true,
                WRITE_DISABLE => self.enabled = false,
                PROGRAM if self.enabled => {
                    let base = t.address & !(PAGE_SIZE - 1);
                    for (i, byte) in t.data.into_iter().enumerate() {
                        let offset = (base | ((t.address + i) & (PAGE_SIZE - 1))) % CAPACITY;
                        self.image.0[offset] &= byte;
                        self.dirty.insert(offset / SECTOR_SIZE);
                    }
                    self.enabled = false;
                }
                ERASE_SECTOR | ERASE_BLOCK if self.enabled => {
                    let size = if t.command == ERASE_SECTOR {
                        SECTOR_SIZE
                    } else {
                        BLOCK_SIZE
                    };
                    let base = (t.address % CAPACITY) & !(size - 1);
                    self.image.0[base..base + size].fill(ERASED);
                    self.dirty
                        .extend(base / SECTOR_SIZE..(base + size) / SECTOR_SIZE);
                    self.enabled = false;
                }
                WRITE_STATUS if self.enabled => self.enabled = false,
                _ => (), // JEDEC ignores mutations when WEL is clear.
            }
        }
        self.selected = selected;
        Ok(())
    }

    /// One MSB-first SPI byte; an unselected die leaves MISO pulled high.
    pub fn shift(&mut self, byte: u8) -> Result<u8, &'static str> {
        if !self.selected {
            return Ok(ERASED);
        }
        let Some(t) = &mut self.transaction else {
            if !matches!(
                byte,
                READ | FAST_READ
                    | PROGRAM
                    | ERASE_SECTOR
                    | ERASE_BLOCK
                    | READ_STATUS
                    | WRITE_STATUS
                    | WRITE_ENABLE
                    | WRITE_DISABLE
                    | READ_ID
            ) {
                return Err(
                    "unsupported NOR opcode (SFDP, quad and vendor commands are not modeled)",
                );
            }
            self.transaction = Some(Transaction {
                command: byte,
                position: 0,
                address: 0,
                data: Vec::new(),
            });
            return Ok(ERASED);
        };
        let result = match t.command {
            READ_ID => JEDEC_ID
                .get(t.position)
                .copied()
                .ok_or("NOR ID has only three modeled bytes")?,
            READ_STATUS => {
                if self.enabled {
                    WEL
                } else {
                    0
                }
            }
            READ | FAST_READ | PROGRAM | ERASE_SECTOR | ERASE_BLOCK if t.position < 3 => {
                t.address = t.address << 8 | usize::from(byte);
                ERASED
            }
            FAST_READ if t.position == 3 => ERASED,
            READ | FAST_READ => {
                let prefix = if t.command == READ { 3 } else { 4 };
                self.image.0[(t.address + t.position - prefix) % CAPACITY]
            }
            PROGRAM => {
                if t.data.len() == PAGE_SIZE {
                    return Err("NOR program exceeds the modeled page buffer");
                }
                t.data.push(byte);
                ERASED
            }
            WRITE_STATUS if t.position == 0 && byte == 0 => {
                t.data.push(byte);
                ERASED
            }
            _ => return Err("unsupported NOR command length or status fields"),
        };
        t.position += 1;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn command(nor: &mut Nor, bytes: &[u8]) -> Vec<u8> {
        nor.select(true).unwrap();
        let result = bytes.iter().map(|&b| nor.shift(b).unwrap()).collect();
        nor.select(false).unwrap();
        result
    }
    #[test]
    fn inactive_nvram_bank_program_block_erase_wrdi_and_fast_read() {
        let mut nor = Nor::new(Image::fresh());
        command(&mut nor, &[WRITE_ENABLE]);
        command(&mut nor, &[WRITE_DISABLE]);
        command(&mut nor, &[PROGRAM, 0x0d, 0, 0, 0x42]);
        assert_eq!(nor.image.bank(1).unwrap()[0], ERASED);
        command(&mut nor, &[WRITE_ENABLE]);
        command(&mut nor, &[WRITE_STATUS, 0]);
        assert_eq!(command(&mut nor, &[READ_STATUS, 0xff])[1], 0);
        command(&mut nor, &[WRITE_ENABLE]);
        command(&mut nor, &[PROGRAM, 0x0d, 0, 0, 0x42]);
        assert_eq!(
            command(&mut nor, &[FAST_READ, 0x0d, 0, 0, 0, 0xff])[5],
            0x42
        );
        assert_eq!(nor.image.bank(1).unwrap()[0], 0x42);
        command(&mut nor, &[WRITE_ENABLE]);
        command(&mut nor, &[ERASE_BLOCK, 0x0d, 0x21, 0]);
        assert!(nor.image.bank(1).unwrap().iter().all(|&b| b == ERASED));
        assert_eq!(nvram::validate(nor.image.bank(0).unwrap()), Ok(()));
    }

    #[test]
    fn jedec_status_program_erase_and_read_share_the_image() {
        let mut nor = Nor::new(Image::fresh());
        assert_eq!(
            command(&mut nor, &[READ_ID, 0xff, 0xff, 0xff]),
            [0xff, 0xef, 0x65, 0x14]
        );
        command(&mut nor, &[PROGRAM, 0, 0, 0, 0x12]);
        assert_eq!(nor.image.bytes()[0], ERASED);
        command(&mut nor, &[WRITE_ENABLE]);
        assert_eq!(
            command(&mut nor, &[READ_STATUS, 0xff, 0xff]),
            [0xff, WEL, WEL]
        );
        command(&mut nor, &[PROGRAM, 0, 0, 0, 0x12, 0x34]);
        assert_eq!(
            command(&mut nor, &[READ, 0, 0, 0, 0xff, 0xff]),
            [0xff, 0xff, 0xff, 0xff, 0x12, 0x34]
        );
        assert_eq!(command(&mut nor, &[READ_STATUS, 0]), [0xff, 0]);
        command(&mut nor, &[WRITE_ENABLE]);
        command(&mut nor, &[PROGRAM, 0, 0, 0, 0xff]);
        assert_eq!(nor.image.bytes()[0], 0x12);
        command(&mut nor, &[WRITE_ENABLE]);
        command(&mut nor, &[ERASE_SECTOR, 0, 1, 0]);
        assert!(
            nor.image.bytes()[..SECTOR_SIZE]
                .iter()
                .all(|&b| b == ERASED)
        );
    }
    #[test]
    fn committed_programs_and_erases_report_their_sectors_once() {
        let mut nor = Nor::new(Image::fresh());
        command(&mut nor, &[PROGRAM, 0, 0x10, 0, 0]);
        assert!(nor.take_dirty().is_empty());
        command(&mut nor, &[WRITE_ENABLE]);
        command(&mut nor, &[PROGRAM, 0, 0x10, 0, 0x5a]);
        let dirty = nor.take_dirty();
        assert_eq!(dirty.len(), 1);
        assert_eq!((dirty[0].0, dirty[0].1[0]), (0x1000, 0x5a));
        assert!(nor.take_dirty().is_empty());
        command(&mut nor, &[WRITE_ENABLE]);
        command(&mut nor, &[ERASE_BLOCK, 0x01, 0, 0]);
        let erased: Vec<usize> = nor.take_dirty().into_iter().map(|(o, _)| o).collect();
        assert_eq!(
            erased,
            (0x10000..0x20000).step_by(SECTOR_SIZE).collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_newest_valid_bank_is_current() {
        let image = Image::fresh();
        assert_eq!(image.current_bank(), Ok(0));
        let newer = nvram::empty_bank_of(2);
        let image = image.with_proxy(1, &newer).unwrap();
        assert_eq!(image.current_bank(), Ok(1));
        let blank = Image::from_bytes(vec![ERASED; CAPACITY]).unwrap();
        assert!(blank.current_bank().is_err());
    }

    #[test]
    fn nvram_image_has_one_valid_bank_and_other_regions_are_erased() {
        let image = Image::fresh();
        assert_eq!(nvram::validate(image.bank(0).unwrap()), Ok(()));
        assert!(image.bank(1).unwrap().iter().all(|&b| b == ERASED));
        assert!(
            image.bytes()[..ANVRAM.0 as usize]
                .iter()
                .all(|&b| b == ERASED)
        );
        assert!(
            image.bytes()[SYSCFG.0 as usize..]
                .iter()
                .all(|&b| b == ERASED)
        );
    }
    #[test]
    fn page_wrap_and_refusal_preserve_flash_until_cs_rises() {
        let mut nor = Nor::new(Image::fresh());
        command(&mut nor, &[WRITE_ENABLE]);
        nor.select(true).unwrap();
        for b in [PROGRAM, 0, 0, 255, 0x12, 0x34] {
            nor.shift(b).unwrap();
        }
        assert_eq!(nor.image.bytes()[255], ERASED);
        nor.select(false).unwrap();
        assert_eq!(nor.image.bytes()[255], 0x12);
        assert_eq!(nor.image.bytes()[0], 0x34);
        nor.select(true).unwrap();
        assert!(nor.shift(0x5a).is_err());
        assert_eq!(nor.shift(READ_ID), Ok(ERASED));
    }
}
