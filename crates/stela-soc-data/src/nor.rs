//! Source-qualified SPI NOR image geometry and CHRP bank representation.
//! This image is data. Flash commands, selected transactions and durability
//! remain owned by the native device and block-storage adapters.
use alloc::{vec, vec::Vec};
pub mod nvram;

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
    /// Mutate the owned image without changing its validated fixed capacity.
    /// This performs no flash transaction, mapping or durability operation.
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
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
