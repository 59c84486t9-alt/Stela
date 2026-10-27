//! Single-wire, 24-bit SPI NOR behind `spi::Spi`.
//!
//! Contract: 26A434 `AppleARMSPIFlashController::_readJedecId` file
//! 0x1c7d364 (9f), `_readRDSR` 0x1c7d1b8 (05), `_writeEnable`
//! 0x1c7d048 (06/04), `_programBytes` 0x1c7c894 (02), `_eraseSector`
//! 0x1c7c480 (20), `_eraseBlock` 0x1c7c288 (d8), `readBuffer`
//! 0x1c9ffdc (03). `_identifyNORDevice` at 0x1c7b7a0 selects ef6017's
//! geometry through 0x1c7ba1c..0x1c7ba28 -> 0x1c7bfe4 -> 0x1c7c030;
//! the constants at 0x1759f0 are 2048 sectors, 4096 bytes, 256-byte pages
//! and 50. The former ef6514 selects only 256 sectors at 0x175a20 (1 MiB).
//! Stela reports the matching identifier for its 8 MiB die, with 256-byte
//! pages, 4 KiB sectors and 64 KiB blocks. It is not a claim about the
//! physical board's flash vendor. The 26A434 J473 `mBoot` image's table at
//! file 0x1b0110 supplies the 8 MiB capacity and partition regions below;
//! boot firmware normalizes the DeviceTree's placeholder partition `reg`s
//! and publishes that resolved geometry to the kernel.
//!
//! Commands commit on CS rising. This functional die completes program and
//! erase at that boundary (zero busy latency), so WIP is always clear;
//! status WEL follows WREN/WRDI and is consumed by program/erase/WRSR.
//! Unsupported commands refuse before their byte is accepted.
use alloc::{collections::BTreeSet, vec, vec::Vec};
pub mod nvram;
pub mod persist;

pub const CAPACITY: usize = 0x800000;
pub const PAGE_SIZE: usize = 256;
pub const SECTOR_SIZE: usize = 0x1000;
pub const BLOCK_SIZE: usize = 0x10000;
pub const JEDEC_ID: [u8; 3] = [0xef, 0x60, 0x17];
pub const ERASED: u8 = 0xff;
/// J473 boot-firmware regions: header space, then the two iBoot slots.
pub const FIRMWARE: [(u32, u32); 3] = [(0, 0x20000), (0x20000, 0x2c0000), (0x2e0000, 0x2c0000)];
/// The CHRP NVRAM partition. Its two active banks occupy its first 128 KiB.
pub const ANVRAM: (u32, u32) = (0x700000, 0x100000);
/// J473 diagnostic-data regions.
pub const SYSCFG: [(u32, u32); 2] = [(0x5a0000, 0x2000), (0x5a4000, 0x20000)];
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
            return Err("NOR image is not 8 MiB");
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
    /// The newest valid NVRAM bank, by generation; the higher bank wins a
    /// tie.
    pub fn current_bank(&self) -> Result<u32, &'static str> {
        (0..nvram::BANK_COUNT)
            .filter_map(|bank| {
                let bytes = self.bank(bank).ok()?;
                nvram::validate(bytes).ok()?;
                Some((nvram::generation(bytes), bank))
            })
            .max_by_key(|&(generation, bank)| (generation, bank))
            .map(|(_, bank)| bank)
            .ok_or("the NOR image holds no valid NVRAM bank")
    }
    /// The bank boot firmware hands off, without changing the flash image.
    ///
    /// iBoot's CHRP reader skips bad banks, including bad Adler-32, and
    /// succeeds with no imported variables when none survives (26A434 J473
    /// raw offsets 0xec2ec..0xec2f4, 0xec52c..0xec598). Its handoff then
    /// serializes the environment when no bank was loaded (0xece34..0xece50).
    /// Stela supplies its empty environment in that case. The damaged banks
    /// remain on the die until the guest erases/programs them itself.
    ///
    /// A checksummed Apple header at a bank boundary identifies damaged NOR;
    /// a completely erased die is also NOR. Unidentified nonblank data is
    /// refused, rather than treating a wrong host partition as corrupt NVRAM.
    pub fn boot_bank(&self) -> Result<(u32, Vec<u8>), &'static str> {
        if let Ok(current) = self.current_bank() {
            return Ok((current, self.bank(current)?.to_vec()));
        }
        if self.0.iter().all(|&byte| byte == ERASED)
            || (0..nvram::BANK_COUNT)
                .any(|bank| nvram::has_apple_header(self.bank(bank).expect("bank in anvram")))
        {
            return Ok((nvram::CURRENT_BANK, nvram::empty_bank()));
        }
        Err("the NOR image has neither a valid NVRAM bank nor an identifiable Apple bank header")
    }
    /// Save `bank` as XNU's `IONVRAMCHRPHandler` does: into the bank after
    /// the current one, round robin. `bank` must be valid and newer than the
    /// current bank. Returns the bank written and the offsets of the erase
    /// sectors it changed, for the host to store.
    pub fn save_bank(&mut self, bank: &[u8]) -> Result<(u32, Vec<usize>), &'static str> {
        nvram::validate(bank)?;
        let current = self.current_bank()?;
        let old = nvram::generation(self.bank(current)?);
        if nvram::generation(bank) <= old {
            return Err("a saved NVRAM bank must be newer than the current one");
        }
        let next = (current + 1) % nvram::BANK_COUNT;
        let start = ANVRAM.0 as usize + next as usize * nvram::BANK_SIZE;
        let changed = (start..start + nvram::BANK_SIZE)
            .step_by(SECTOR_SIZE)
            .filter(|&sector| {
                self.0[sector..sector + SECTOR_SIZE] != bank[sector - start..][..SECTOR_SIZE]
            })
            .collect();
        self.0[start..start + nvram::BANK_SIZE].copy_from_slice(bank);
        Ok((next, changed))
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
        let inactive = ANVRAM.0 as usize + nvram::BANK_SIZE;
        let addressed = |command, offset: usize, tail: &[u8]| {
            let mut bytes = vec![
                command,
                (offset >> 16) as u8,
                (offset >> 8) as u8,
                offset as u8,
            ];
            bytes.extend_from_slice(tail);
            bytes
        };
        command(&mut nor, &[WRITE_ENABLE]);
        command(&mut nor, &[WRITE_DISABLE]);
        command(&mut nor, &addressed(PROGRAM, inactive, &[0x42]));
        assert_eq!(nor.image.bank(1).unwrap()[0], ERASED);
        command(&mut nor, &[WRITE_ENABLE]);
        command(&mut nor, &[WRITE_STATUS, 0]);
        assert_eq!(command(&mut nor, &[READ_STATUS, 0xff])[1], 0);
        command(&mut nor, &[WRITE_ENABLE]);
        command(&mut nor, &addressed(PROGRAM, inactive, &[0x42]));
        assert_eq!(
            command(&mut nor, &addressed(FAST_READ, inactive, &[0, 0xff]))[5],
            0x42
        );
        assert_eq!(nor.image.bank(1).unwrap()[0], 0x42);
        command(&mut nor, &[WRITE_ENABLE]);
        command(&mut nor, &addressed(ERASE_BLOCK, inactive + 0x2100, &[]));
        assert!(nor.image.bank(1).unwrap().iter().all(|&b| b == ERASED));
        assert_eq!(nvram::validate(nor.image.bank(0).unwrap()), Ok(()));
    }

    #[test]
    fn jedec_status_program_erase_and_read_share_the_image() {
        let mut nor = Nor::new(Image::fresh());
        let id = command(&mut nor, &[READ_ID, 0xff, 0xff, 0xff]);
        assert_eq!(id, [0xff, 0xef, 0x60, 0x17]);
        assert_eq!(1usize << u32::from(id[3]), nor.image.bytes().len());
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
        let tied = image.with_proxy(0, &newer).unwrap();
        assert_eq!(tied.current_bank(), Ok(1));
        let blank = Image::from_bytes(vec![ERASED; CAPACITY]).unwrap();
        assert!(blank.current_bank().is_err());
    }

    #[test]
    fn invalid_banks_supply_an_empty_proxy_without_rewriting_the_flash() {
        let mut image = Image::fresh()
            .with_proxy(1, &nvram::empty_bank_of(2))
            .unwrap();
        // A nonempty bank whose payload was not programmed completely.
        for bank in 0..nvram::BANK_COUNT {
            let start = ANVRAM.0 as usize + bank as usize * nvram::BANK_SIZE;
            image.0[start + PAGE_SIZE..start + nvram::BANK_SIZE].fill(ERASED);
        }
        image.0[SYSCFG[0].0 as usize + 10] = 0x42;
        let before = image.clone();
        assert!(image.current_bank().is_err());
        let (bank, proxy) = image.boot_bank().unwrap();
        assert_eq!(bank, nvram::CURRENT_BANK);
        assert_eq!(proxy, nvram::empty_bank());
        assert_eq!(image, before);
        // A valid bank always takes precedence over damaged ones.
        let valid = image.with_proxy(1, &nvram::empty_bank_of(3)).unwrap();
        assert_eq!(valid.boot_bank().unwrap(), (1, nvram::empty_bank_of(3)));
    }

    #[test]
    fn erased_flash_recovers_but_unidentified_data_and_corrupt_headers_refuse() {
        let mut image = Image::from_bytes(vec![ERASED; CAPACITY]).unwrap();
        assert_eq!(image.boot_bank().unwrap().1, nvram::empty_bank());
        image.0[12] = 0x42;
        assert!(image.boot_bank().is_err());
        let mut image = Image::fresh();
        image.0[ANVRAM.0 as usize + 1] ^= 1;
        assert!(image.boot_bank().is_err());
    }

    #[test]
    fn a_guest_save_after_recovery_replaces_only_its_selected_bank() {
        let mut image = Image::fresh();
        image.0[ANVRAM.0 as usize + 100] ^= 1;
        let (_, proxy) = image.boot_bank().unwrap();
        let mut variables = nvram::Variables::parse(&proxy).unwrap();
        variables
            .set(nvram::Partition::System, b"boot-command", b"recover")
            .unwrap();
        let saved = variables.encode().unwrap();
        let untouched = image.bank(0).unwrap().to_vec();
        let mut nor = Nor::new(image);
        let bank = ANVRAM.0 as usize + nvram::BANK_SIZE;
        command(&mut nor, &[WRITE_ENABLE]);
        command(
            &mut nor,
            &[
                ERASE_BLOCK,
                (bank >> 16) as u8,
                (bank >> 8) as u8,
                bank as u8,
            ],
        );
        for (page, bytes) in saved.chunks(PAGE_SIZE).enumerate() {
            let address = ANVRAM.0 as usize + nvram::BANK_SIZE + page * PAGE_SIZE;
            let mut program = vec![
                PROGRAM,
                (address >> 16) as u8,
                (address >> 8) as u8,
                address as u8,
            ];
            program.extend_from_slice(bytes);
            command(&mut nor, &[WRITE_ENABLE]);
            command(&mut nor, &program);
        }
        assert_eq!(nor.image.current_bank(), Ok(1));
        assert_eq!(nor.image.boot_bank().unwrap(), (1, saved));
        assert_eq!(nor.image.bank(0).unwrap(), untouched);
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
            image.bytes()[ANVRAM.0 as usize + nvram::BANK_SIZE..]
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
