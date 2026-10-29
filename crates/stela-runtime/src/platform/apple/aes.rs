//! The Apple AES engine of S8000 layout (`aes,s8000`; ADT `/arm-io/aes`), the
//! DMA engine behind XNU's IOAESAccelerator service.
//!
//! Documented by the qemu-t8030 `apple_aes` model (register and command
//! layouts) and checked against the macOS 26 J473 AppleS8000AESAccelerator
//! driver, which reads `aes-version` from the ADT. The first `reg` range
//! holds the block registers, 32-bit:
//! - CONTROL (0x8): START 0 and STOP 1 start and stop the command FIFO.
//! - STATUS (0xc): COMMAND_FIFO_ENABLED 6; from version 2 the driver waits
//!   for bits 7 and 8 (TEXT and KEY_UNWRAP DPA random seeded), from version 3
//!   for bits 7 to 13, after it enables the engine.
//! - INT_STATUS (0x18, write one to clear) and INT_ENABLE (0x1c):
//!   COMMAND_FIFO_LOW 0, COMMAND_FIFO_OVERFLOW 1, INVALID_COMMAND 2, AXI read
//!   and write response errors 3 and 4, FLAG_COMMAND 5, INVALID_DATA_LENGTH
//!   6, and per key context (bits 7 and 13 up) KEY_DISABLED +0 and
//!   KEY_INVALID_AT_USE_TIME +3. The interrupt is any enabled status bit.
//! - WATERMARKS (0x20): COMMAND_FIFO_LOW [6:0], in words.
//! - COMMAND_FIFO_STATUS (0x24): LOW 0 (level below the watermark), EMPTY 1,
//!   FULL 2, OVERFLOW 3, LEVEL [15:8] in words. The driver counts free space
//!   as 128 words less LEVEL.
//! - FLAG_COMMAND (0x30): the code [7:0] of the last FLAG command; the driver
//!   reads it again while [15:8] is nonzero.
//! - CLEAR_FIFO (0x38): bit 0 empties the command FIFO (versions 0 and 1).
//! - COMMAND_FIFO (0x200, 0x100 in version 0): each word written joins the
//!   FIFO.
//!
//! The second range holds the key-disable words. The word at
//! `sioaesdisable-offset` (default 0) has a sticky bit per hardware key:
//! UID1 0, GID0 1, GID1 2 and a fourth key 3 (IOAESAccelerator handle 3000),
//! each set by writing it as one. A key whose ADT names its own word
//! (`sioaesdisableuid1-offset`, `-gid0-`, `-gid1-`; 0x40, 0x44, 0x48 on M3
//! and M4, 4, 8, 0xc on M5 and M6) is enabled while that word reads
//! 0xa050c030, and writing 0xa55ac33c disables it (`OverrideRegMap`,
//! `_isKeyDisabled`, `disableHardwareKey`). The layout follows the ADT, not
//! `aes-version`: version 3 M3 boards have the separate words too.
//!
//! The 26A434 driver is one binary for every board (M2 J473, M3 J613, M4
//! J773g, M5 J813 and M6 J873g, identical code apart from relocation and
//! the M6 build's lack of pointer authentication). Its only `aes-version`
//! branches: the FIFO at 0x100 in version 0; CLEAR_FIFO before version 2;
//! the seeded STATUS bits and interrupt masks from version 2; a third
//! `reg` range, the DKey range, from version 5 (`start`); its distribution
//! register at 4 in version 5 and 8 from version 6 (`_distribute_dkey`);
//! and the H16 scrambler option from version 5 (`getSupportedOptions`).
//! Distribution writes one and waits up to 5 s for bit 0 to clear; it
//! precedes command 13 (H16 scrambled key) for AppleAVD, whose payload
//! seed the driver first writes to the block's 0x50-0x5c. The ADT
//! `address-width` (default 36) sets the high address fields: 10 bits at
//! 42 (every M3 to M6 board, whose `dart-sio` window starts at 2^40),
//! 8 bits otherwise.
//!
//! Commands are an opcode [31:28] and its operands, in FIFO words:
//! - KEY (1): context 27, select [26:24] (0 software, 1 UID1, 2 and 3 GID0
//!   and GID1, 4 to 7 HDCP), length [23:22] (128, 192, 256 bits), WRAPPED
//!   21, ENCRYPT 20, function [19:18] (0 none), mode [17:16] (ECB, CBC,
//!   CTR), then a software key's words.
//! - IV (2): context [27:26], then four words.
//! - DATA (5): key context 27, IV context [26:25], length [23:0] in bytes,
//!   then the source's high address bits from bit 16 and the destination's
//!   from bit 0 (8 or 10 bits each), the source's and the destination's
//!   low 32 bits: I/O addresses through the engine's IOMMU stream.
//! - STORE_IV (6): context [27:26], destination high bits from bit 0, then
//!   its low 32 bits: writes the context's chaining value.
//! - FLAG (8): code [7:0], STOP 26, INTERRUPT 27.
//!
//! Inferred, not documented: the engine has no DPA countermeasure to seed,
//! so the seeded STATUS bits read set from reset; commands run as soon as
//! the FIFO is started and holds a whole one, so the FIFO drains before the
//! guest's next access; CTR increments its 128-bit counter big-endian; a
//! hardware key the key-disable register disables raises KEY_DISABLED and
//! leaves its context without a key, and DATA with no key raises
//! KEY_INVALID_AT_USE_TIME, transferring nothing; a FLAG with STOP stops the
//! FIFO like CONTROL STOP; a key's own disable word reads zero once
//! disabled (the driver only compares it with the enabled value); the
//! per-key bit word reports a key with its own word in that key's bit, and
//! writing such a bit there is refused. Stela has no Apple GID keys, so
//! GID0, GID1 and the fourth key read disabled; UID1 is the board's own
//! per-installation key when it has one, else disabled too. VERSION,
//! CONFIG, KEY_ID, AXI_STATUS, COMMAND_FIFO_COUNT, SKG_KEY, the history
//! FIFO, the tag registers (0x50-0x6c), RESET and RESET_AES, wrapped keys,
//! key functions, HDCP keys, the DSB, SKG, WRITE_REG and H16 scrambled-key
//! commands, DKey distribution, DATA bit 24 and the reserved bits of the
//! address words are refused until their values or behavior are known.
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use alloc::collections::VecDeque;
#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(test)]
use stela_soc_data::aes::DEFAULT_ADDRESS_WIDTH;
#[cfg(test)]
use stela_soc_data::aes::DKEY_DISTRIBUTE_V5;
#[cfg(test)]
use stela_soc_data::aes::DKEY_DISTRIBUTE_V6;
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction, stela_contracts::bus::Lifecycle,
    stela_contracts::bus::LifecycleState, stela_contracts::bus::MmioDevice,
    stela_contracts::bus::MmioError, stela_contracts::bus::Width, stela_contracts::bus::refuse,
};
use {stela_contracts::dma::DmaError, stela_contracts::dma::Port};
use {stela_contracts::interrupt::AicInput, stela_contracts::interrupt::Wire};

const NAME: &str = "aes-s8000";

/// Bytes of the block register range; the key-disable range follows it,
/// then the DKey range from version 5.
pub const BLOCK_BYTES: u64 = 0x4000;
const SOURCE_HIGH_SHIFT: u32 = 16;
const CONTROL: u64 = 0x8;
const STATUS: u64 = 0xc;
const INT_STATUS: u64 = 0x18;
const INT_ENABLE: u64 = 0x1c;
const WATERMARKS: u64 = 0x20;
const FIFO_STATUS: u64 = 0x24;
const FLAG_COMMAND: u64 = 0x30;
const CLEAR_FIFO: u64 = 0x38;

const CONTROL_START: u32 = 1;
const CONTROL_STOP: u32 = 1 << 1;
const STATUS_FIFO_ENABLED: u32 = 1 << 6;
const STATUS_SEEDED: u32 = 0x3f80;

const INT_FIFO_LOW: u32 = 1;
const INT_FIFO_OVERFLOW: u32 = 1 << 1;
const INT_INVALID_COMMAND: u32 = 1 << 2;
const INT_AXI_READ: u32 = 1 << 3;
const INT_AXI_WRITE: u32 = 1 << 4;
const INT_FLAG: u32 = 1 << 5;
const INT_INVALID_LENGTH: u32 = 1 << 6;
const INT_KEY_DISABLED: [u32; 2] = [1 << 7, 1 << 13];
const INT_KEY_INVALID_AT_USE: [u32; 2] = [1 << 10, 1 << 16];
const INT_KNOWN: u32 = 0x7_ffff;

const FIFO_LOW: u32 = 1;
const FIFO_EMPTY: u32 = 1 << 1;
const FIFO_FULL: u32 = 1 << 2;
const FIFO_OVERFLOW: u32 = 1 << 3;
const FIFO_LEVEL_SHIFT: u32 = 8;
const FIFO_WORDS: usize = 128;
const WATERMARK: u32 = 0x7f;

/// Key-disable bits: UID1, GID0, GID1 and the fourth hardware key.
const DISABLE_UID1: u32 = 1;
const DISABLE_KNOWN: u32 = 0xf;
const DISABLE_ALL_BUT_UID1: u32 = DISABLE_KNOWN & !DISABLE_UID1;
/// What a key's own disable word reads while the key is enabled.
const KEY_ENABLED: u32 = 0xa050_c030;
/// The value that disables a key through its own word.
const KEY_DISABLE: u32 = 0xa55a_c33c;
/// What a key's own disable word reads once disabled (inferred).
const KEY_DISABLED: u32 = 0;

const OPCODE_KEY: u32 = 1;
const OPCODE_IV: u32 = 2;
const OPCODE_DSB: u32 = 3;
const OPCODE_SKG: u32 = 4;
const OPCODE_DATA: u32 = 5;
const OPCODE_STORE_IV: u32 = 6;
const OPCODE_WRITE_REG: u32 = 7;
const OPCODE_FLAG: u32 = 8;
const OPCODE_SCRAMBLED_KEY: u32 = 0xd;

const OPCODE_SHIFT: u32 = 28;
const OPCODE_FIELD: u32 = 0xf << OPCODE_SHIFT;
const KEY_WRAPPED: u32 = 1 << 21;
const KEY_ENCRYPT: u32 = 1 << 20;
const FLAG_STOP: u32 = 1 << 26;
const FLAG_INTERRUPT: u32 = 1 << 27;
const DATA_LENGTH: u32 = 0xff_ffff;
/// DATA bit 24, which the driver never sets.
const DATA_RESERVED: u32 = 1 << 24;
const STORE_IV_CONTEXT_SHIFT: u32 = 26;
const CONTEXT_MASK: u32 = 3;

/// Operand words of the longest command, a KEY with a 256-bit key.
const MAX_OPERANDS: usize = 8;
const BLOCK: usize = 16;
/// Bytes a DATA command moves per DMA read and write.
const CHUNK: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Ecb,
    Cbc,
    Ctr,
}

enum Cipher {
    Aes128(stela_crypto::Aes128),
    Aes192(stela_crypto::Aes192),
    Aes256(stela_crypto::Aes256),
}

impl Cipher {
    fn new(key: &[u8]) -> Option<Self> {
        Some(match key.len() {
            16 => Self::Aes128(stela_crypto::Aes128::new_from_slice(key).ok()?),
            24 => Self::Aes192(stela_crypto::Aes192::new_from_slice(key).ok()?),
            32 => Self::Aes256(stela_crypto::Aes256::new_from_slice(key).ok()?),
            _ => return None,
        })
    }

    fn encrypt(&self, block: &mut [u8; BLOCK]) {
        let block = aes::Block::from_mut_slice(block);
        match self {
            Self::Aes128(cipher) => cipher.encrypt_block(block),
            Self::Aes192(cipher) => cipher.encrypt_block(block),
            Self::Aes256(cipher) => cipher.encrypt_block(block),
        }
    }

    fn decrypt(&self, block: &mut [u8; BLOCK]) {
        let block = aes::Block::from_mut_slice(block);
        match self {
            Self::Aes128(cipher) => cipher.decrypt_block(block),
            Self::Aes192(cipher) => cipher.decrypt_block(block),
            Self::Aes256(cipher) => cipher.decrypt_block(block),
        }
    }
}

struct Key {
    cipher: Cipher,
    mode: Mode,
    encrypt: bool,
}

impl Key {
    /// Transform `data` in place, whole blocks, chaining through `iv`.
    fn apply(&self, iv: &mut [u8; BLOCK], data: &mut [u8]) {
        for block in data.as_chunks_mut::<BLOCK>().0 {
            match (self.mode, self.encrypt) {
                (Mode::Ecb, true) => self.cipher.encrypt(block),
                (Mode::Ecb, false) => self.cipher.decrypt(block),
                (Mode::Cbc, true) => {
                    xor(block, iv);
                    self.cipher.encrypt(block);
                    *iv = *block;
                }
                (Mode::Cbc, false) => {
                    let input = *block;
                    self.cipher.decrypt(block);
                    xor(block, iv);
                    *iv = input;
                }
                (Mode::Ctr, _) => {
                    let mut stream = *iv;
                    self.cipher.encrypt(&mut stream);
                    xor(block, &stream);
                    *iv = (u128::from_be_bytes(*iv).wrapping_add(1)).to_be_bytes();
                }
            }
        }
    }
}

fn xor(block: &mut [u8; BLOCK], other: &[u8; BLOCK]) {
    for (byte, other) in block.iter_mut().zip(other) {
        *byte ^= other;
    }
}

use stela_soc_data::aes::Config;
#[cfg(test)]
use stela_soc_data::aes::KeyDisable;

/// Where a device offset lands.
enum Space {
    Block(u64),
    KeyDisable(u64),
    DKey(u64),
}

pub struct Aes {
    lifecycle: LifecycleState,
    config: Config,
    irq: Option<AicInput>,
    irq_level: bool,
    uid: Option<[u8; 32]>,
    disabled: u32,
    started: bool,
    /// Unsupported DMA may already have committed RAM and chaining state.
    /// Keep the cause until a checked recovery can authorize execution.
    dma_failure: Option<&'static str>,
    fifo: VecDeque<u32>,
    overflow: bool,
    watermark: u32,
    int_status: u32,
    int_enable: u32,
    flag: u32,
    keys: [Option<Key>; 2],
    ivs: [[u8; BLOCK]; 4],
}

impl Aes {
    /// An engine as the ADT describes it in `config`, interrupting on
    /// `irq`, whose UID1 key is `uid` (disabled without one).
    pub fn new(
        config: Config,
        irq: Option<AicInput>,
        uid: Option<[u8; 32]>,
    ) -> Result<Self, &'static str> {
        config.validate()?;
        let disabled = match uid {
            Some(_) => DISABLE_ALL_BUT_UID1,
            None => DISABLE_KNOWN,
        };
        Ok(Self {
            lifecycle: LifecycleState {
                powered: true,
                clocked: true,
                quiesced: false,
                reset: false,
                retention: false,
            },
            config,
            irq,
            irq_level: false,
            uid,
            disabled,
            started: false,
            dma_failure: None,
            fifo: VecDeque::with_capacity(FIFO_WORDS),
            overflow: false,
            watermark: 0,
            int_status: 0,
            int_enable: 0,
            flag: 0,
            keys: [None, None],
            ivs: [[0; BLOCK]; 4],
        })
    }

    fn space(&self, offset: u64) -> Space {
        let disable = BLOCK_BYTES + self.config.key_disable.bytes;
        if offset < BLOCK_BYTES {
            Space::Block(offset)
        } else if offset < disable {
            Space::KeyDisable(offset - BLOCK_BYTES)
        } else {
            Space::DKey(offset - disable)
        }
    }

    /// The key-disable bit of the key whose own word is at `offset`.
    fn own_word(&self, offset: u64) -> Option<u32> {
        let keys = self.config.key_disable.keys;
        let index = keys
            .iter()
            .position(|&word| word.map(u64::from) == Some(offset))?;
        Some(1 << index)
    }

    /// The key-disable bits of the keys that have their own words.
    fn own_words(&self) -> u32 {
        let keys = self.config.key_disable.keys.iter();
        keys.enumerate()
            .filter(|(_, word)| word.is_some())
            .fold(0, |bits, (index, _)| bits | 1 << index)
    }

    fn read_key_disable(&self, offset: u64) -> Option<u32> {
        if offset == u64::from(self.config.key_disable.word) {
            return Some(self.disabled);
        }
        let bit = self.own_word(offset)?;
        Some(if self.disabled & bit != 0 {
            KEY_DISABLED
        } else {
            KEY_ENABLED
        })
    }

    fn write_key_disable(&mut self, offset: u64, value: u32) -> Result<(), &'static str> {
        if offset == u64::from(self.config.key_disable.word) {
            if value & !DISABLE_KNOWN != 0 {
                return Err("AES key-disable reserved bits");
            }
            if value & self.own_words() != 0 {
                return Err("AES key-disable bit of a key with its own disable word");
            }
            self.disabled |= value;
            return Ok(());
        }
        let bit = self
            .own_word(offset)
            .ok_or("unknown AES key-disable register")?;
        if value != KEY_DISABLE {
            return Err("AES key-disable word value other than the disable value");
        }
        self.disabled |= bit;
        Ok(())
    }

    /// Why an access at `offset` in the DKey range is refused.
    fn dkey_refusal(&self, offset: u64) -> &'static str {
        if !self.config.has_dkey() {
            "unknown AES register"
        } else if offset == self.config.dkey_distribute() {
            "AES DKey distribution to AppleAVD"
        } else {
            "unknown AES DKey register"
        }
    }

    fn executing(&self) -> bool {
        self.accessible().is_ok() && !self.lifecycle.quiesced
    }

    fn accessible(&self) -> Result<(), &'static str> {
        if !self.lifecycle.powered {
            return Err("AES power domain is off");
        }
        if !self.lifecycle.clocked {
            return Err("AES clock is gated");
        }
        if self.lifecycle.reset {
            return Err("AES physical reset is asserted");
        }
        Ok(())
    }

    fn command_fifo(&self) -> u64 {
        if self.config.version == 0 {
            0x100
        } else {
            0x200
        }
    }

    fn low(&self) -> bool {
        (self.fifo.len() as u32) < self.watermark
    }

    fn status(&self) -> u32 {
        self.int_status | if self.low() { INT_FIFO_LOW } else { 0 }
    }

    fn fifo_status(&self) -> u32 {
        let level = self.fifo.len();
        let mut status = (level as u32) << FIFO_LEVEL_SHIFT;
        for (set, bit) in [
            (self.low(), FIFO_LOW),
            (level == 0, FIFO_EMPTY),
            (level >= FIFO_WORDS, FIFO_FULL),
            (self.overflow, FIFO_OVERFLOW),
        ] {
            if set {
                status |= bit;
            }
        }
        status
    }

    fn signal(&mut self, access: &mut Access<'_>) {
        let level = self.status() & self.int_enable != 0;
        if level != self.irq_level {
            self.irq_level = level;
            if let Some(irq) = self.irq {
                access.interrupts.set_level(Wire::Aic(irq), level);
            }
        }
    }

    /// Whether commands wait for [`Self::run`].
    pub fn pending(&self) -> bool {
        self.dma_failure.is_none() && self.executing() && self.started && !self.fifo.is_empty()
    }

    /// Run every whole command at the head of the started FIFO, moving data
    /// through `port`. A command the model does not implement is refused
    /// and stays queued. An unsupported DMA transfer keeps its cause and
    /// command without replay: accepted prefixes and chaining state cannot be
    /// undone or restarted by FIFO submission, START or CLEAR_FIFO.
    pub fn run(&mut self, port: &mut Port<'_, '_>) -> Result<(), MmioError> {
        if !self.executing() {
            return Err(refuse(
                NAME,
                self.command_fifo(),
                Width::Word,
                Direction::Write,
                "AES DMA while PMGR inhibits execution",
            ));
        }
        if let Some(reason) = self.dma_failure {
            return Err(refuse(
                NAME,
                self.command_fifo(),
                Width::Word,
                Direction::Write,
                reason,
            ));
        }
        while self.started {
            let Some(&command) = self.fifo.front() else {
                break;
            };
            let words = self.words(command)?;
            if self.fifo.len() < words {
                break;
            }
            let mut operands = [0; MAX_OPERANDS];
            for (slot, &word) in operands.iter_mut().zip(self.fifo.iter().skip(1)) {
                *slot = word;
            }
            self.execute(command, &operands[..words - 1], port)?;
            self.fifo.drain(..words);
        }
        self.signal(port.access);
        Ok(())
    }

    /// FIFO words of the command `command` begins, itself included.
    fn words(&self, command: u32) -> Result<usize, MmioError> {
        let fail = |reason| {
            refuse(
                NAME,
                self.command_fifo(),
                Width::Word,
                Direction::Write,
                reason,
            )
        };
        Ok(match command >> OPCODE_SHIFT {
            OPCODE_KEY if (command >> 24) & 7 == 0 => 1 + key_bytes(command) / 4,
            OPCODE_KEY => 1,
            OPCODE_IV => 5,
            OPCODE_DATA => 4,
            OPCODE_STORE_IV => 2,
            OPCODE_FLAG => 1,
            OPCODE_DSB => return Err(fail("AES DSB command")),
            OPCODE_SKG => return Err(fail("AES SKG command")),
            OPCODE_WRITE_REG => return Err(fail("AES WRITE_REG command")),
            OPCODE_SCRAMBLED_KEY => return Err(fail("AES H16 scrambled-key command")),
            _ => 1,
        })
    }

    fn execute(
        &mut self,
        command: u32,
        operands: &[u32],
        port: &mut Port<'_, '_>,
    ) -> Result<(), MmioError> {
        let fail = |reason| {
            refuse(
                NAME,
                self.command_fifo(),
                Width::Word,
                Direction::Write,
                reason,
            )
        };
        match command >> OPCODE_SHIFT {
            OPCODE_KEY => {
                if command & KEY_WRAPPED != 0 {
                    return Err(fail("AES wrapped keys"));
                }
                if (command >> 18) & 3 != 0 {
                    return Err(fail("AES key functions"));
                }
                let context = (command >> 27 & 1) as usize;
                let mode = match (command >> 16) & 3 {
                    0 => Mode::Ecb,
                    1 => Mode::Cbc,
                    2 => Mode::Ctr,
                    _ => {
                        self.keys[context] = None;
                        self.int_status |= INT_INVALID_COMMAND;
                        return Ok(());
                    }
                };
                let length = key_bytes(command);
                let mut material = [0; 32];
                match (command >> 24) & 7 {
                    0 => {
                        for (bytes, word) in
                            material.as_chunks_mut::<4>().0.iter_mut().zip(operands)
                        {
                            bytes.copy_from_slice(&word.to_le_bytes());
                        }
                    }
                    select @ 1..=3 => {
                        let bit = 1 << (select - 1);
                        match self.uid.filter(|_| self.disabled & bit == 0) {
                            Some(uid) => material = uid,
                            None => {
                                self.keys[context] = None;
                                self.int_status |= INT_KEY_DISABLED[context];
                                return Ok(());
                            }
                        }
                    }
                    _ => return Err(fail("AES HDCP keys")),
                }
                self.keys[context] = match Cipher::new(&material[..length]) {
                    Some(cipher) => Some(Key {
                        cipher,
                        mode,
                        encrypt: command & KEY_ENCRYPT != 0,
                    }),
                    None => {
                        self.int_status |= INT_INVALID_COMMAND;
                        None
                    }
                };
            }
            OPCODE_IV => {
                let context = (command >> 26 & 3) as usize;
                for (bytes, word) in self.ivs[context]
                    .as_chunks_mut::<4>()
                    .0
                    .iter_mut()
                    .zip(operands)
                {
                    bytes.copy_from_slice(&word.to_le_bytes());
                }
            }
            OPCODE_DATA => self.data(command, operands, port)?,
            OPCODE_STORE_IV => {
                let high = self.config.high_mask();
                let fields = OPCODE_FIELD | CONTEXT_MASK << STORE_IV_CONTEXT_SHIFT | high;
                if command & !fields != 0 {
                    return Err(fail("AES STORE_IV reserved bits"));
                }
                let context = (command >> STORE_IV_CONTEXT_SHIFT & CONTEXT_MASK) as usize;
                let destination = u64::from(command & high) << 32 | u64::from(operands[0]);
                let iv = self.ivs[context];
                if let Err(error) = port.write(destination, &iv) {
                    self.dma_failed(error, INT_AXI_WRITE)?;
                }
            }
            OPCODE_FLAG => {
                self.flag = command & 0xff;
                if command & FLAG_INTERRUPT != 0 {
                    self.int_status |= INT_FLAG;
                }
                if command & FLAG_STOP != 0 {
                    self.started = false;
                }
            }
            _ => self.int_status |= INT_INVALID_COMMAND,
        }
        Ok(())
    }

    fn data(
        &mut self,
        command: u32,
        operands: &[u32],
        port: &mut Port<'_, '_>,
    ) -> Result<(), MmioError> {
        let fail = |reason| {
            refuse(
                NAME,
                self.command_fifo(),
                Width::Word,
                Direction::Write,
                reason,
            )
        };
        let length = (command & DATA_LENGTH) as usize;
        let context = (command >> 27 & 1) as usize;
        let iv_context = (command >> 25 & CONTEXT_MASK) as usize;
        let [upper, source, destination] = [operands[0], operands[1], operands[2]];
        let high = self.config.high_mask();
        if command & DATA_RESERVED != 0 {
            return Err(fail("AES DATA bit 24"));
        }
        if upper & !(high << SOURCE_HIGH_SHIFT | high) != 0 {
            return Err(fail("AES DATA address word reserved bits"));
        }
        let source = u64::from(upper >> SOURCE_HIGH_SHIFT & high) << 32 | u64::from(source);
        let destination = u64::from(upper & high) << 32 | u64::from(destination);
        if !length.is_multiple_of(BLOCK) {
            self.int_status |= INT_INVALID_LENGTH;
            return Ok(());
        }
        let Some(key) = &self.keys[context] else {
            self.int_status |= INT_KEY_INVALID_AT_USE[context];
            return Ok(());
        };
        let mut iv = self.ivs[iv_context];
        let mut buffer = vec![0; length.min(CHUNK)];
        let mut done = 0;
        let mut failed = None;
        while done < length {
            let chunk = &mut buffer[..(length - done).min(CHUNK)];
            if let Err(error) = port.read(source + done as u64, chunk) {
                failed = Some((error, INT_AXI_READ));
                break;
            }
            key.apply(&mut iv, chunk);
            if let Err(error) = port.write(destination + done as u64, chunk) {
                failed = Some((error, INT_AXI_WRITE));
                break;
            }
            done += chunk.len();
        }
        self.ivs[iv_context] = iv;
        match failed {
            Some((error, interrupt)) => self.dma_failed(error, interrupt),
            None => Ok(()),
        }
    }

    /// An AXI error interrupt for a DMA the IOMMU faulted or that missed
    /// RAM; a stream configuration the model lacks is refused.
    fn dma_failed(&mut self, error: DmaError, interrupt: u32) -> Result<(), MmioError> {
        match error {
            DmaError::Fault(_) | DmaError::Memory => {
                self.int_status |= interrupt;
                Ok(())
            }
            DmaError::Unsupported(reason) => {
                self.dma_failure = Some(reason);
                Err(refuse(
                    NAME,
                    self.command_fifo(),
                    Width::Word,
                    Direction::Write,
                    reason,
                ))
            }
        }
    }
}

/// Bytes of the key a KEY command's length field selects.
fn key_bytes(command: u32) -> usize {
    match (command >> 22) & 3 {
        0 => 16,
        1 => 24,
        _ => 32,
    }
}

impl Lifecycle for Aes {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<(), &'static str> {
        if !self.lifecycle.reset && proposed.reset
            || self.lifecycle.powered && !proposed.powered && !proposed.retention
        {
            return Err(
                "AES physical reset or nonretained power loss requires qualified key-disable, context and entropy restore semantics",
            );
        }
        Ok(())
    }

    fn set_lifecycle(&mut self, proposed: LifecycleState, access: &mut Access<'_>) {
        // Gates preserve accepted commands, sticky disable bits,
        // key contexts, chaining values and already pending interrupts.
        self.lifecycle = proposed;
        self.signal(access);
    }
}

impl MmioDevice for Aes {
    fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
        Some(self)
    }
    fn name(&self) -> &'static str {
        NAME
    }

    fn read(
        &mut self,
        offset: u64,
        width: Width,
        _access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Read, reason);
        self.accessible().map_err(fail)?;
        if width != Width::Word {
            return Err(fail("AES registers are 32-bit"));
        }
        let offset = match self.space(offset) {
            Space::Block(offset) => offset,
            Space::KeyDisable(at) => {
                let value = self.read_key_disable(at);
                return value
                    .map(u64::from)
                    .ok_or_else(|| fail("unknown AES key-disable register"));
            }
            Space::DKey(at) => return Err(fail(self.dkey_refusal(at))),
        };
        let value = match offset {
            CONTROL => 0,
            STATUS => STATUS_SEEDED | if self.started { STATUS_FIFO_ENABLED } else { 0 },
            INT_STATUS => self.status(),
            INT_ENABLE => self.int_enable,
            WATERMARKS => self.watermark,
            FIFO_STATUS => self.fifo_status(),
            FLAG_COMMAND => self.flag,
            _ => return Err(fail("unknown AES register")),
        };
        Ok(u64::from(value))
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        self.accessible().map_err(fail)?;
        if self.lifecycle.quiesced
            && (offset == self.command_fifo()
                || offset == CONTROL && value == u64::from(CONTROL_START))
        {
            return Err(fail("AES command submission while PMGR quiesced"));
        }
        if width != Width::Word {
            return Err(fail("AES registers are 32-bit"));
        }
        let value = value as u32;
        let offset = match self.space(offset) {
            Space::Block(offset) => offset,
            Space::KeyDisable(at) => return self.write_key_disable(at, value).map_err(fail),
            Space::DKey(at) => return Err(fail(self.dkey_refusal(at))),
        };
        match offset {
            CONTROL => match value {
                CONTROL_START => self.started = true,
                CONTROL_STOP => self.started = false,
                _ => return Err(fail("AES CONTROL other than START or STOP")),
            },
            INT_STATUS => self.int_status &= !value,
            INT_ENABLE if value & !INT_KNOWN == 0 => self.int_enable = value,
            INT_ENABLE => return Err(fail("AES INT_ENABLE reserved bits")),
            WATERMARKS => self.watermark = value & WATERMARK,
            CLEAR_FIFO => {
                if value & 1 != 0 {
                    self.fifo.clear();
                    self.overflow = false;
                }
            }
            _ if offset == self.command_fifo() => {
                if let Some(reason) = self.dma_failure {
                    return Err(fail(reason));
                }
                if self.fifo.len() < FIFO_WORDS {
                    self.fifo.push_back(value);
                } else {
                    self.overflow = true;
                    self.int_status |= INT_FIFO_OVERFLOW;
                }
            }
            _ => return Err(fail("unknown AES register")),
        }
        self.signal(access);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_contracts::interrupt::InterruptLatch;
    use {
        stela_contracts::dma::Iommu, stela_contracts::dma::Memory,
        stela_contracts::dma::test_support::Ram,
    };

    const RAM: u64 = 0x8_0000_0000;
    const FIFO: u64 = 0x200;
    const SOURCE: u64 = RAM + 0x1000;
    const DESTINATION: u64 = RAM + 0x2000;

    /// The per-key bit word of the J473 layout, which has no others.
    const DISABLE_WORD: u64 = BLOCK_BYTES;
    /// J773g `dart-sio` `vm-base`: I/O addresses above 40 bits.
    const VM_BASE: u64 = 0x100_0000_0000;

    /// Every stream reaches RAM at its I/O address less `iova`, plus [`RAM`].
    struct Window {
        iova: u64,
    }
    impl Iommu for Window {
        fn page(&self) -> u64 {
            0x4000
        }
        fn translate(
            &mut self,
            _: &mut dyn Memory,
            _: usize,
            iova: u64,
            _: u64,
            _: bool,
            _: &mut Access<'_>,
        ) -> Result<u64, DmaError> {
            Ok(iova - self.iova + RAM)
        }
    }

    /// The J473 ADT: version 3, no `address-width`, one key-disable word.
    fn j473() -> Config {
        Config {
            version: 3,
            address_width: DEFAULT_ADDRESS_WIDTH,
            key_disable: KeyDisable {
                bytes: 0x8000,
                word: 0,
                keys: [None; 3],
            },
        }
    }

    /// The J773g ADT: version 5, 42-bit addresses, a word per key.
    fn j773g() -> Config {
        Config {
            version: 5,
            address_width: 42,
            key_disable: KeyDisable {
                bytes: 0x8000,
                word: 0,
                keys: [Some(0x40), Some(0x44), Some(0x48)],
            },
        }
    }

    fn hex(text: &str) -> alloc::vec::Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    fn words(bytes: &[u8]) -> impl Iterator<Item = u32> + '_ {
        bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_le_bytes(*word))
    }

    struct Bench {
        aes: Aes,
        ram: Ram,
        latch: InterruptLatch,
        /// The I/O address of [`RAM`].
        iova: u64,
    }

    impl Bench {
        /// The J473 driver's `_enableAES(true)` on a version 3 engine.
        fn new(uid: Option<[u8; 32]>) -> Self {
            Self::with(j473(), uid, RAM)
        }
        /// `_enableAES(true)` on an engine of `config` whose stream maps
        /// RAM at `iova`.
        fn with(config: Config, uid: Option<[u8; 32]>, iova: u64) -> Self {
            let mut bench = Self {
                aes: Aes::new(config, Some(AicInput::new(0, 0x2f7)), uid).unwrap(),
                ram: Ram::new(RAM, 0x4000),
                latch: InterruptLatch::new(),
                iova,
            };
            assert_eq!(bench.read(STATUS) & STATUS_SEEDED, STATUS_SEEDED);
            let status = bench.read(INT_STATUS);
            bench.write(INT_STATUS, u64::from(status));
            bench.write(INT_ENABLE, 0x3effe);
            bench.write(WATERMARKS, 0x40);
            bench.write(CONTROL, u64::from(CONTROL_START));
            bench
        }
        /// The I/O address of `physical`.
        fn io(&self, physical: u64) -> u64 {
            physical - RAM + self.iova
        }
        /// A 32-bit read, or a write of `value`, that may be refused.
        fn access(&mut self, offset: u64, value: Option<u64>) -> Result<u64, MmioError> {
            let mut access = Access::new(0, 0, &mut self.latch);
            match value {
                Some(value) => self
                    .aes
                    .write(offset, Width::Word, value, &mut access)
                    .map(|()| value),
                None => self.aes.read(offset, Width::Word, &mut access),
            }
        }
        fn read(&mut self, offset: u64) -> u32 {
            let mut access = Access::new(0, 0, &mut self.latch);
            self.aes.read(offset, Width::Word, &mut access).unwrap() as u32
        }
        fn write(&mut self, offset: u64, value: u64) {
            let mut access = Access::new(0, 0, &mut self.latch);
            self.aes
                .write(offset, Width::Word, value, &mut access)
                .unwrap();
        }
        /// Push `command` and run what the FIFO holds, as the engine does
        /// after each device write.
        fn push(&mut self, command: impl IntoIterator<Item = u32>) -> Result<(), MmioError> {
            for word in command {
                self.write(FIFO, u64::from(word));
            }
            let mut access = Access::new(0, 0, &mut self.latch);
            let mut port = Port {
                iommu: &mut Window { iova: self.iova },
                stream: 1,
                memory: &mut self.ram,
                access: &mut access,
            };
            self.aes.run(&mut port)
        }
        fn data(&mut self, command: u32, length: usize) -> Result<(), MmioError> {
            let [source, destination] = [self.io(SOURCE), self.io(DESTINATION)];
            let upper = ((source >> 32) << SOURCE_HIGH_SHIFT | destination >> 32) as u32;
            self.push([
                OPCODE_DATA << OPCODE_SHIFT | command | length as u32,
                upper,
                source as u32,
                destination as u32,
            ])
        }
        fn bytes(&mut self, physical: u64, length: usize) -> alloc::vec::Vec<u8> {
            let mut bytes = vec![0; length];
            assert!(self.ram.read(physical, &mut bytes));
            bytes
        }
    }

    fn check_unsupported_dart_dma_prefix(write_failure: bool, version: u32) {
        use super::super::dart::Dart;
        use stela_soc_data::dart::Profile;
        const PAGE: u64 = 0x4000;
        const INPUT: u64 = 0x200_7000;
        let mut config = j473();
        config.version = version;
        let mut bench = Bench::with(config, None, RAM);
        bench.ram = Ram::new(RAM, (6 * PAGE) as usize);
        let entry = |address: u64| address >> 4 | 1;
        bench.ram.put_u64(RAM + 8, entry(RAM + PAGE));
        for (slot, page, unsupported) in [
            (1, 2, false),
            (2, 3, !write_failure),
            (3, 4, false),
            (4, 5, write_failure),
        ] {
            bench.ram.put_u64(
                RAM + PAGE + slot * 8,
                entry(RAM + page * PAGE) | 0xfff << 40 | if unsupported { 1 << 9 } else { 0 },
            );
        }
        let length = if write_failure { CHUNK } else { 2 * CHUNK };
        let committed = if write_failure { BLOCK } else { CHUNK };
        let destination = if write_failure {
            0x200_fff0
        } else {
            0x200_c000
        };
        let physical_destination = RAM + 4 * PAGE + (destination & (PAGE - 1));
        let plain = vec![0x11; length];
        assert!(bench.ram.write(RAM + 3 * PAGE - CHUNK as u64, &plain));
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        bench
            .push(
                core::iter::once(OPCODE_KEY << OPCODE_SHIFT | KEY_ENCRYPT | 1 << 16)
                    .chain(words(&key)),
            )
            .unwrap();
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        bench
            .push(core::iter::once(OPCODE_IV << OPCODE_SHIFT).chain(words(&iv)))
            .unwrap();
        let mut dart = Dart::for_profile(Profile::T8110, 16, None).unwrap();
        {
            let mut access = Access::new(0, 0, &mut bench.latch);
            for (offset, value) in [(0xc00, 2), (0x1004, 1), (0x1404, RAM >> 14 << 2 | 1)] {
                dart.write(offset, Width::Word, value, &mut access).unwrap();
            }
        }
        for word in [
            OPCODE_DATA << OPCODE_SHIFT | length as u32,
            0,
            INPUT as u32,
            destination as u32,
        ] {
            bench.write(FIFO, u64::from(word));
        }
        let run = |bench: &mut Bench, dart: &mut Dart| {
            let mut access = Access::new(0, 0, &mut bench.latch);
            bench.aes.run(&mut Port {
                iommu: dart,
                stream: 1,
                memory: &mut bench.ram,
                access: &mut access,
            })
        };
        assert_eq!(
            reason(run(&mut bench, &mut dart)),
            "DART descriptor contains unmodeled attributes"
        );
        let prefix = bench.bytes(physical_destination, committed);
        assert_ne!(prefix, plain[..committed]);
        assert_eq!(
            bench.bytes(physical_destination + committed as u64, BLOCK),
            [0; BLOCK]
        );
        let chaining = bench.aes.ivs[0];
        // A natural next guest FIFO store must not authorize DATA offset zero again.
        let submitted = bench.access(
            FIFO,
            Some(u64::from(
                OPCODE_FLAG << OPCODE_SHIFT | FLAG_INTERRUPT | 0x2a,
            )),
        );
        assert!(run(&mut bench, &mut dart).is_err());
        assert_eq!(
            bench.bytes(physical_destination, committed),
            prefix,
            "CBC prefix replay, write_failure={write_failure}"
        );
        assert_eq!(bench.aes.ivs[0], chaining);
        assert_eq!(bench.read(FLAG_COMMAND), 0);
        assert!(!bench.aes.pending());
        assert!(submitted.is_err());
        if version < 2 {
            bench.write(CLEAR_FIFO, 1);
            bench.write(CONTROL, u64::from(CONTROL_STOP));
            bench.write(CONTROL, u64::from(CONTROL_START));
            assert!(!bench.aes.pending());
            assert!(run(&mut bench, &mut dart).is_err());
            assert_eq!(bench.bytes(physical_destination, committed), prefix);
            assert_eq!(bench.aes.ivs[0], chaining);
        }
    }

    #[test]
    fn unsupported_dart_read_after_prefix_never_replays() {
        check_unsupported_dart_dma_prefix(false, 3);
    }

    #[test]
    fn unsupported_dart_write_after_prefix_never_replays() {
        check_unsupported_dart_dma_prefix(true, 3);
    }

    #[test]
    fn unsupported_dma_replay_is_not_authorized_by_fifo_clear_or_start() {
        check_unsupported_dart_dma_prefix(false, 1);
    }

    /// NIST SP 800-38A F.2.1 (CBC-AES128.Encrypt), the chaining value the
    /// engine stores afterwards, and the FLAG that completes the request.
    #[test]
    fn software_keys_encrypt_cbc_store_the_chain_and_flag_completion() {
        let mut bench = Bench::new(None);
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let plain = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        assert!(bench.ram.write(SOURCE, &plain));
        // KEY context 0, software, 128-bit, encrypt, CBC.
        let command = OPCODE_KEY << 28 | KEY_ENCRYPT | 1 << 16;
        bench
            .push(core::iter::once(command).chain(words(&key)))
            .unwrap();
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        bench
            .push(core::iter::once(OPCODE_IV << 28 | 1 << 26).chain(words(&iv)))
            .unwrap();
        bench.data(1 << 25, 32).unwrap();
        assert_eq!(
            bench.bytes(DESTINATION, 32),
            hex("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2")
        );
        bench
            .push([
                OPCODE_STORE_IV << 28 | 1 << 26 | (RAM >> 32) as u32,
                RAM as u32,
            ])
            .unwrap();
        assert_eq!(
            bench.bytes(RAM, 16),
            hex("5086cb9b507219ee95db113a917678b2")
        );
        assert!(!bench.aes.irq_level);
        bench
            .push([OPCODE_FLAG << 28 | FLAG_INTERRUPT | 0x2a])
            .unwrap();
        assert_eq!(bench.read(FLAG_COMMAND), 0x2a);
        assert_eq!(bench.read(INT_STATUS) & INT_FLAG, INT_FLAG);
        assert!(bench.aes.irq_level);
        bench.write(INT_STATUS, u64::from(INT_FLAG));
        assert!(!bench.aes.irq_level);
        assert_eq!(bench.read(FIFO_STATUS), FIFO_LOW | FIFO_EMPTY);
    }

    #[test]
    fn retained_gates_preserve_keys_chaining_queued_dma_and_completed_interrupts() {
        let mut bench = Bench::new(Some([0x69; 32]));
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        bench
            .push(core::iter::once(OPCODE_KEY << 28 | KEY_ENCRYPT | 1 << 16).chain(words(&key)))
            .unwrap();
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        bench
            .push(core::iter::once(OPCODE_IV << 28).chain(words(&iv)))
            .unwrap();
        bench
            .push([OPCODE_FLAG << 28 | FLAG_INTERRUPT | 0x2a])
            .unwrap();
        let plain = hex("6bc1bee22e409f96e93d7e117393172a");
        assert!(bench.ram.write(SOURCE, &plain));
        assert!(bench.ram.write(DESTINATION, &[0xa5; 16]));
        for word in [
            OPCODE_DATA << 28 | 16,
            ((SOURCE >> 32) << 16 | DESTINATION >> 32) as u32,
            SOURCE as u32,
            DESTINATION as u32,
        ] {
            bench.write(FIFO, u64::from(word));
        }
        let active = bench.aes.lifecycle;
        let fifo = bench.aes.fifo.clone();
        let ivs = bench.aes.ivs;
        let disabled = bench.aes.disabled;
        for paused in [
            LifecycleState {
                clocked: false,
                ..active
            },
            LifecycleState {
                quiesced: true,
                ..active
            },
            LifecycleState {
                powered: false,
                retention: true,
                ..active
            },
        ] {
            bench.aes.check_lifecycle(paused).unwrap();
            bench
                .aes
                .set_lifecycle(paused, &mut Access::new(0, 0, &mut bench.latch));
            assert!(!bench.aes.pending());
            assert!(bench.push([]).is_err());
            assert!(
                bench
                    .aes
                    .write(
                        FIFO,
                        Width::Word,
                        0,
                        &mut Access::new(0, 0, &mut bench.latch)
                    )
                    .is_err()
            );
            assert_eq!(bench.aes.fifo, fifo);
            assert_eq!(bench.aes.ivs, ivs);
            assert_eq!(bench.aes.disabled, disabled);
            assert_eq!(bench.bytes(DESTINATION, 16), [0xa5; 16]);
            assert!(bench.latch.is_asserted(Wire::Aic(AicInput::new(0, 0x2f7))));
            bench
                .aes
                .set_lifecycle(active, &mut Access::new(0, 0, &mut bench.latch));
            assert!(bench.aes.pending());
        }
        for destructive in [
            LifecycleState {
                reset: true,
                ..active
            },
            LifecycleState {
                powered: false,
                ..active
            },
        ] {
            assert!(bench.aes.check_lifecycle(destructive).is_err());
            assert_eq!(bench.aes.lifecycle, active);
            assert_eq!(bench.aes.fifo, fifo);
            assert_eq!(bench.aes.uid, Some([0x69; 32]));
        }
        bench.push([]).unwrap();
        assert_eq!(
            bench.bytes(DESTINATION, 16),
            hex("7649abac8119b246cee98e9b12e9197d")
        );
        assert!(bench.aes.fifo.is_empty());
        let completed_iv = bench.aes.ivs;
        bench.push([]).unwrap();
        assert_eq!(
            bench.aes.ivs, completed_iv,
            "gate release cannot replay DMA"
        );
        assert_eq!(bench.read(FLAG_COMMAND), 0x2a);
    }

    /// NIST SP 800-38A F.5.2 (CTR-AES128.Decrypt) and F.2.2
    /// (CBC-AES128.Decrypt), through the second key and IV contexts.
    #[test]
    fn ctr_and_cbc_decrypt_through_other_contexts() {
        let mut bench = Bench::new(None);
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let ctr = OPCODE_KEY << 28 | 1 << 27 | 2 << 16;
        bench
            .push(core::iter::once(ctr).chain(words(&key)))
            .unwrap();
        let counter = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        bench
            .push(core::iter::once(OPCODE_IV << 28 | 3 << 26).chain(words(&counter)))
            .unwrap();
        let cipher = hex("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff");
        assert!(bench.ram.write(SOURCE, &cipher));
        bench.data(1 << 27 | 3 << 25, 32).unwrap();
        assert_eq!(
            bench.bytes(DESTINATION, 32),
            hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
        );
        assert_eq!(bench.aes.ivs[3][15], 0x01, "the counter advanced twice");
        let cbc = OPCODE_KEY << 28 | 1 << 16;
        bench
            .push(core::iter::once(cbc).chain(words(&key)))
            .unwrap();
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        bench
            .push(core::iter::once(OPCODE_IV << 28).chain(words(&iv)))
            .unwrap();
        assert!(
            bench
                .ram
                .write(SOURCE, &hex("7649abac8119b246cee98e9b12e9197d"))
        );
        bench.data(0, 16).unwrap();
        assert_eq!(
            bench.bytes(DESTINATION, 16),
            hex("6bc1bee22e409f96e93d7e117393172a")
        );
        assert_eq!(bench.read(INT_STATUS) & !INT_FIFO_LOW, 0);
    }

    #[test]
    fn hardware_keys_follow_the_key_disable_register() {
        let uid = [0x5a; 32];
        let mut bench = Bench::new(Some(uid));
        assert_eq!(bench.read(DISABLE_WORD), DISABLE_ALL_BUT_UID1);
        assert!(bench.ram.write(SOURCE, &[0; 16]));
        // UID1, 256-bit ECB encrypt matches the same key given in software.
        bench
            .push([OPCODE_KEY << 28 | 1 << 24 | 2 << 22 | KEY_ENCRYPT])
            .unwrap();
        bench.data(0, 16).unwrap();
        let hardware = bench.bytes(DESTINATION, 16);
        let software = OPCODE_KEY << 28 | 2 << 22 | KEY_ENCRYPT;
        bench
            .push(core::iter::once(software).chain(words(&uid)))
            .unwrap();
        bench.data(0, 16).unwrap();
        assert_eq!(bench.bytes(DESTINATION, 16), hardware);
        assert_ne!(hardware, [0; 16]);
        // GID0 is disabled; so is UID1 once software disables it.
        bench
            .push([OPCODE_KEY << 28 | 2 << 24 | KEY_ENCRYPT])
            .unwrap();
        assert_eq!(
            bench.read(INT_STATUS) & INT_KEY_DISABLED[0],
            INT_KEY_DISABLED[0]
        );
        assert!(bench.aes.irq_level);
        bench.data(0, 16).unwrap();
        assert_ne!(bench.read(INT_STATUS) & INT_KEY_INVALID_AT_USE[0], 0);
        bench.write(INT_STATUS, u64::from(INT_KNOWN));
        bench.write(DISABLE_WORD, u64::from(DISABLE_UID1));
        assert_eq!(bench.read(DISABLE_WORD), DISABLE_KNOWN);
        bench.push([OPCODE_KEY << 28 | 1 << 27 | 1 << 24]).unwrap();
        assert_eq!(
            bench.read(INT_STATUS) & INT_KEY_DISABLED[1],
            INT_KEY_DISABLED[1]
        );
        // Without a UID every hardware key reads disabled.
        assert_eq!(Bench::new(None).read(DISABLE_WORD), DISABLE_KNOWN);
    }

    #[test]
    fn stopped_fifos_queue_and_unknown_commands_are_refused() {
        let mut bench = Bench::new(None);
        bench.write(CONTROL, u64::from(CONTROL_STOP));
        bench.push([OPCODE_FLAG << 28; 3]).unwrap();
        assert_eq!(bench.read(FIFO_STATUS), 3 << FIFO_LEVEL_SHIFT | FIFO_LOW);
        assert_eq!(bench.read(STATUS) & STATUS_FIFO_ENABLED, 0);
        bench.write(CONTROL, u64::from(CONTROL_START));
        bench.push([]).unwrap();
        assert_eq!(bench.read(FIFO_STATUS) & FIFO_EMPTY, FIFO_EMPTY);
        // A partial command waits for the rest of its words.
        bench.push([OPCODE_IV << 28, 1, 2]).unwrap();
        assert_eq!(bench.read(FIFO_STATUS) >> FIFO_LEVEL_SHIFT, 3);
        bench.push([3, 4]).unwrap();
        assert_eq!(bench.read(FIFO_STATUS) >> FIFO_LEVEL_SHIFT, 0);
        assert!(bench.push([OPCODE_DSB << 28]).is_err());
        bench.write(CLEAR_FIFO, 1);
        assert!(
            bench
                .push([OPCODE_KEY << 28 | KEY_WRAPPED | 1 << 24])
                .is_err()
        );
        bench.write(CLEAR_FIFO, 1);
        let mut access = Access::new(0, 0, &mut bench.latch);
        assert!(bench.aes.read(0x0, Width::Word, &mut access).is_err());
        assert!(bench.aes.write(0x50, Width::Word, 0, &mut access).is_err());
    }

    fn reason(result: Result<impl core::fmt::Debug, MmioError>) -> &'static str {
        match result {
            Err(MmioError::Unsupported { reason, .. }) => reason,
            other => panic!("not refused: {other:?}"),
        }
    }

    /// NIST SP 800-38A F.2.1 through the J773g `dart-sio` window above
    /// 2^40: the 10-bit high address fields of `address-width` 42.
    #[test]
    fn wide_address_engines_move_data_and_chaining_values_above_40_bits() {
        let mut bench = Bench::with(j773g(), None, VM_BASE);
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let plain = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        assert!(bench.ram.write(SOURCE, &plain));
        let command = OPCODE_KEY << OPCODE_SHIFT | KEY_ENCRYPT | 1 << 16;
        bench
            .push(core::iter::once(command).chain(words(&key)))
            .unwrap();
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        bench
            .push(core::iter::once(OPCODE_IV << OPCODE_SHIFT).chain(words(&iv)))
            .unwrap();
        // The driver's `_prepareTransfer` word: 0x100 above bit 16 and 0.
        assert_eq!(bench.io(SOURCE) >> 32, 0x100);
        bench.data(0, 32).unwrap();
        assert_eq!(
            bench.bytes(DESTINATION, 32),
            hex("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2")
        );
        let chain = bench.io(RAM);
        bench
            .push([
                OPCODE_STORE_IV << OPCODE_SHIFT | (chain >> 32) as u32,
                chain as u32,
            ])
            .unwrap();
        assert_eq!(
            bench.bytes(RAM, 16),
            hex("5086cb9b507219ee95db113a917678b2")
        );
        assert_eq!(bench.read(INT_STATUS) & !INT_FIFO_LOW, 0);
    }

    /// Bits the established encodings leave clear stay queued and refuse:
    /// a narrow engine has no high address bits 8 and 9.
    #[test]
    fn reserved_command_bits_refuse_and_stay_queued() {
        let mut bench = Bench::with(j473(), None, VM_BASE);
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        bench
            .push(core::iter::once(OPCODE_KEY << OPCODE_SHIFT | KEY_ENCRYPT).chain(words(&key)))
            .unwrap();
        assert_eq!(
            reason(bench.data(0, 16)),
            "AES DATA address word reserved bits"
        );
        assert_eq!(bench.read(FIFO_STATUS) >> FIFO_LEVEL_SHIFT, 4);
        bench.write(CLEAR_FIFO, 1);
        let mut bench = Bench::new(None);
        assert_eq!(reason(bench.data(DATA_RESERVED, 16)), "AES DATA bit 24");
        bench.write(CLEAR_FIFO, 1);
        let store = OPCODE_STORE_IV << OPCODE_SHIFT | 1 << 8;
        assert_eq!(reason(bench.push([store, 0])), "AES STORE_IV reserved bits");
        bench.write(CLEAR_FIFO, 1);
        let scrambled = OPCODE_SCRAMBLED_KEY << OPCODE_SHIFT;
        assert_eq!(
            reason(bench.push([scrambled])),
            "AES H16 scrambled-key command"
        );
    }

    /// The J773g (0x40, 0x44, 0x48) and J813 (4, 8, 0xc) key words.
    #[test]
    fn keys_with_their_own_disable_words_follow_the_adt_offsets() {
        for keys in [[0x40, 0x44, 0x48], [4, 8, 0xc]] {
            let mut config = j773g();
            config.key_disable.keys = keys.map(Some);
            let [uid1, gid0, gid1] = keys.map(|offset| BLOCK_BYTES + u64::from(offset));
            let uid = [0x5a; 32];
            let mut bench = Bench::with(config, Some(uid), VM_BASE);
            assert_eq!(bench.read(uid1), KEY_ENABLED);
            assert_eq!(bench.read(gid0), KEY_DISABLED);
            assert_eq!(bench.read(gid1), KEY_DISABLED);
            assert_eq!(bench.read(DISABLE_WORD), DISABLE_ALL_BUT_UID1);
            // UID1 encrypts as the same key given in software.
            assert!(bench.ram.write(SOURCE, &[0; 16]));
            let hardware = OPCODE_KEY << OPCODE_SHIFT | 1 << 24 | 2 << 22 | KEY_ENCRYPT;
            bench.push([hardware]).unwrap();
            bench.data(0, 16).unwrap();
            let encrypted = bench.bytes(DESTINATION, 16);
            let software = OPCODE_KEY << OPCODE_SHIFT | 2 << 22 | KEY_ENCRYPT;
            bench
                .push(core::iter::once(software).chain(words(&uid)))
                .unwrap();
            bench.data(0, 16).unwrap();
            assert_eq!(bench.bytes(DESTINATION, 16), encrypted);
            // Only the disable value disables, and only through the word.
            assert_eq!(
                reason(bench.access(uid1, Some(u64::from(KEY_ENABLED)))),
                "AES key-disable word value other than the disable value"
            );
            assert_eq!(
                reason(bench.access(DISABLE_WORD, Some(u64::from(DISABLE_UID1)))),
                "AES key-disable bit of a key with its own disable word"
            );
            assert_eq!(bench.read(uid1), KEY_ENABLED);
            bench.write(uid1, u64::from(KEY_DISABLE));
            assert_eq!(bench.read(uid1), KEY_DISABLED);
            assert_eq!(bench.read(DISABLE_WORD), DISABLE_KNOWN);
            bench.push([hardware]).unwrap();
            assert_ne!(bench.read(INT_STATUS) & INT_KEY_DISABLED[0], 0);
            // The fourth key keeps its bit in the shared word.
            bench.write(DISABLE_WORD, 1 << 3);
            assert_eq!(
                reason(bench.access(BLOCK_BYTES + 0x10, None)),
                "unknown AES key-disable register"
            );
        }
        // J473 names no own words.
        let mut bench = Bench::new(None);
        assert_eq!(
            reason(bench.access(BLOCK_BYTES + 0x40, None)),
            "unknown AES key-disable register"
        );
    }

    /// `_distribute_dkey` writes the third range's 4 in version 5 and 8 in
    /// version 6; the distribution to AppleAVD is not modeled.
    #[test]
    fn dkey_distribution_refuses_at_its_version_register() {
        let dkey = BLOCK_BYTES + 0x8000;
        let mut v5 = Bench::with(j773g(), None, VM_BASE);
        assert_eq!(
            reason(v5.access(dkey + DKEY_DISTRIBUTE_V5, Some(1))),
            "AES DKey distribution to AppleAVD"
        );
        assert_eq!(
            reason(v5.access(dkey + DKEY_DISTRIBUTE_V6, None)),
            "unknown AES DKey register"
        );
        let mut config = j773g();
        config.version = 6;
        let mut v6 = Bench::with(config, None, VM_BASE);
        assert_eq!(
            reason(v6.access(dkey + DKEY_DISTRIBUTE_V6, Some(1))),
            "AES DKey distribution to AppleAVD"
        );
        assert_eq!(
            reason(Bench::new(None).access(dkey + DKEY_DISTRIBUTE_V5, Some(1))),
            "unknown AES register"
        );
        assert!(config.has_dkey() && !j473().has_dkey());
    }

    #[test]
    fn configs_without_an_established_contract_refuse() {
        let with = |change: fn(&mut Config)| {
            let mut config = j773g();
            change(&mut config);
            Aes::new(config, None, None).err()
        };
        assert_eq!(with(|_| {}), None);
        assert_eq!(with(|config| config.address_width = 40), None);
        for version in [4, 7] {
            let mut config = j773g();
            config.version = version;
            assert_eq!(
                Aes::new(config, None, None).err(),
                Some("AES aes-version without an established layout")
            );
        }
        assert_eq!(
            with(|config| config.address_width = 41),
            Some("AES address-width without an established address field width")
        );
        let outside = Some("AES key-disable word outside its range or unaligned");
        assert_eq!(
            with(|config| config.key_disable.keys[0] = Some(0x42)),
            outside
        );
        assert_eq!(with(|config| config.key_disable.word = 0x7ffd), outside);
        assert_eq!(
            with(|config| config.key_disable.keys[2] = Some(0x8000)),
            outside
        );
        assert_eq!(
            with(|config| config.key_disable.keys[1] = Some(0)),
            Some("AES key-disable words overlap")
        );
    }
}
