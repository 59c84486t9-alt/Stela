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
//! The second range holds the key-disable register at its start (the
//! driver's default `sioaesdisable-offset`): UID1 0, GID0 1, GID1 2 and a
//! fourth hardware key 3, each sticky once written as one.
//!
//! Commands are an opcode [31:28] and its operands, in FIFO words:
//! - KEY (1): context 27, select [26:24] (0 software, 1 UID1, 2 and 3 GID0
//!   and GID1, 4 to 7 HDCP), length [23:22] (128, 192, 256 bits), WRAPPED
//!   21, ENCRYPT 20, function [19:18] (0 none), mode [17:16] (ECB, CBC,
//!   CTR), then a software key's words.
//! - IV (2): context [27:26], then four words.
//! - DATA (5): key context 27, IV context [26:25], length [23:0] in bytes,
//!   then source [23:16] and destination [7:0] high address bits, the
//!   source's and the destination's low 32 bits: I/O addresses through the
//!   engine's IOMMU stream.
//! - STORE_IV (6): context [27:26], destination high bits [7:0], then its
//!   low 32 bits: writes the context's chaining value.
//! - FLAG (8): code [7:0], STOP 26, INTERRUPT 27.
//!
//! Inferred, not documented: the engine has no DPA countermeasure to seed,
//! so the seeded STATUS bits read set from reset; commands run as soon as
//! the FIFO is started and holds a whole one, so the FIFO drains before the
//! guest's next access; CTR increments its 128-bit counter big-endian; a
//! hardware key the key-disable register disables raises KEY_DISABLED and
//! leaves its context without a key, and DATA with no key raises
//! KEY_INVALID_AT_USE_TIME, transferring nothing; a FLAG with STOP stops the
//! FIFO like CONTROL STOP. Stela has no Apple GID keys, so GID0, GID1 and the
//! fourth key read disabled; UID1 is the board's own per-installation key
//! when it has one, else disabled too. VERSION, CONFIG, KEY_ID, AXI_STATUS,
//! COMMAND_FIFO_COUNT, SKG_KEY, the history FIFO, the tag registers
//! (0x50-0x6c), RESET and RESET_AES, wrapped keys, key functions, HDCP keys
//! and the DSB, SKG and WRITE_REG commands are refused until their values or
//! behavior are known.
use super::bus::{
    Access, Direction, Lifecycle, LifecycleState, MmioDevice, MmioError, Width, refuse,
};
use super::interrupt::{AicInput, Wire};
use crate::platform::dma::{DmaError, Port};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use alloc::collections::VecDeque;
#[cfg(not(feature = "std"))]
use alloc::vec;

const NAME: &str = "aes-s8000";

/// Bytes of the block register range; the key-disable range follows it.
pub const BLOCK_BYTES: u64 = 0x4000;
const CONTROL: u64 = 0x8;
const STATUS: u64 = 0xc;
const INT_STATUS: u64 = 0x18;
const INT_ENABLE: u64 = 0x1c;
const WATERMARKS: u64 = 0x20;
const FIFO_STATUS: u64 = 0x24;
const FLAG_COMMAND: u64 = 0x30;
const CLEAR_FIFO: u64 = 0x38;
const KEY_DISABLE: u64 = BLOCK_BYTES;

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

const OPCODE_KEY: u32 = 1;
const OPCODE_IV: u32 = 2;
const OPCODE_DSB: u32 = 3;
const OPCODE_SKG: u32 = 4;
const OPCODE_DATA: u32 = 5;
const OPCODE_STORE_IV: u32 = 6;
const OPCODE_WRITE_REG: u32 = 7;
const OPCODE_FLAG: u32 = 8;

const KEY_WRAPPED: u32 = 1 << 21;
const KEY_ENCRYPT: u32 = 1 << 20;
const FLAG_STOP: u32 = 1 << 26;
const FLAG_INTERRUPT: u32 = 1 << 27;

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
    Aes128(aes::Aes128),
    Aes192(aes::Aes192),
    Aes256(aes::Aes256),
}

impl Cipher {
    fn new(key: &[u8]) -> Option<Self> {
        Some(match key.len() {
            16 => Self::Aes128(aes::Aes128::new_from_slice(key).ok()?),
            24 => Self::Aes192(aes::Aes192::new_from_slice(key).ok()?),
            32 => Self::Aes256(aes::Aes256::new_from_slice(key).ok()?),
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

pub struct Aes {
    lifecycle: LifecycleState,
    version: u32,
    irq: Option<AicInput>,
    irq_level: bool,
    uid: Option<[u8; 32]>,
    disabled: u32,
    started: bool,
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
    /// An engine of ADT `aes-version` `version`, interrupting on `irq`,
    /// whose UID1 key is `uid` (disabled without one).
    pub fn new(version: u32, irq: Option<AicInput>, uid: Option<[u8; 32]>) -> Self {
        let disabled = match uid {
            Some(_) => DISABLE_ALL_BUT_UID1,
            None => DISABLE_KNOWN,
        };
        Self {
            lifecycle: LifecycleState {
                powered: true,
                clocked: true,
                quiesced: false,
                reset: false,
                retention: false,
            },
            version,
            irq,
            irq_level: false,
            uid,
            disabled,
            started: false,
            fifo: VecDeque::with_capacity(FIFO_WORDS),
            overflow: false,
            watermark: 0,
            int_status: 0,
            int_enable: 0,
            flag: 0,
            keys: [None, None],
            ivs: [[0; BLOCK]; 4],
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
        if self.version == 0 { 0x100 } else { 0x200 }
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
        self.executing() && self.started && !self.fifo.is_empty()
    }

    /// Run every whole command at the head of the started FIFO, moving data
    /// through `port`. A command the model does not implement is refused
    /// and stays queued.
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
        Ok(match command >> 28 {
            OPCODE_KEY if (command >> 24) & 7 == 0 => 1 + key_bytes(command) / 4,
            OPCODE_KEY => 1,
            OPCODE_IV => 5,
            OPCODE_DATA => 4,
            OPCODE_STORE_IV => 2,
            OPCODE_FLAG => 1,
            OPCODE_DSB => return Err(fail("AES DSB command")),
            OPCODE_SKG => return Err(fail("AES SKG command")),
            OPCODE_WRITE_REG => return Err(fail("AES WRITE_REG command")),
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
        match command >> 28 {
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
                let context = (command >> 26 & 3) as usize;
                let destination = u64::from(command & 0xff) << 32 | u64::from(operands[0]);
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
        let length = (command & 0xff_ffff) as usize;
        let context = (command >> 27 & 1) as usize;
        let iv_context = (command >> 25 & 3) as usize;
        let [upper, source, destination] = [operands[0], operands[1], operands[2]];
        let source = u64::from(upper >> 16 & 0xff) << 32 | u64::from(source);
        let destination = u64::from(upper & 0xff) << 32 | u64::from(destination);
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
            DmaError::Unsupported(reason) => Err(refuse(
                NAME,
                self.command_fifo(),
                Width::Word,
                Direction::Write,
                reason,
            )),
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
        // Retained gates preserve accepted commands, sticky disable bits,
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
        let value = match offset {
            CONTROL => 0,
            STATUS => STATUS_SEEDED | if self.started { STATUS_FIFO_ENABLED } else { 0 },
            INT_STATUS => self.status(),
            INT_ENABLE => self.int_enable,
            WATERMARKS => self.watermark,
            FIFO_STATUS => self.fifo_status(),
            FLAG_COMMAND => self.flag,
            KEY_DISABLE => self.disabled,
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
            KEY_DISABLE if value & !DISABLE_KNOWN == 0 => self.disabled |= value,
            KEY_DISABLE => return Err(fail("AES key-disable reserved bits")),
            _ if offset == self.command_fifo() => {
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
    use crate::platform::apple::interrupt::InterruptLatch;
    use crate::platform::dma::{Iommu, Memory, tests::Ram};

    const RAM: u64 = 0x8_0000_0000;
    const FIFO: u64 = 0x200;
    const SOURCE: u64 = RAM + 0x1000;
    const DESTINATION: u64 = RAM + 0x2000;

    /// Every stream reaches RAM at its I/O address.
    struct Identity;
    impl Iommu for Identity {
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
            Ok(iova)
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
    }

    impl Bench {
        /// The J473 driver's `_enableAES(true)` on a version 3 engine.
        fn new(uid: Option<[u8; 32]>) -> Self {
            let mut bench = Self {
                aes: Aes::new(3, Some(AicInput::new(0, 0x2f7)), uid),
                ram: Ram::new(RAM, 0x4000),
                latch: InterruptLatch::new(),
            };
            assert_eq!(bench.read(STATUS) & STATUS_SEEDED, STATUS_SEEDED);
            let status = bench.read(INT_STATUS);
            bench.write(INT_STATUS, u64::from(status));
            bench.write(INT_ENABLE, 0x3effe);
            bench.write(WATERMARKS, 0x40);
            bench.write(CONTROL, u64::from(CONTROL_START));
            bench
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
                iommu: &mut Identity,
                stream: 1,
                memory: &mut self.ram,
                access: &mut access,
            };
            self.aes.run(&mut port)
        }
        fn data(&mut self, command: u32, length: usize) -> Result<(), MmioError> {
            let upper = ((SOURCE >> 32) << 16 | DESTINATION >> 32) as u32;
            self.push([
                OPCODE_DATA << 28 | command | length as u32,
                upper,
                SOURCE as u32,
                DESTINATION as u32,
            ])
        }
        fn bytes(&mut self, physical: u64, length: usize) -> alloc::vec::Vec<u8> {
            let mut bytes = vec![0; length];
            assert!(self.ram.read(physical, &mut bytes));
            bytes
        }
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
        assert_eq!(bench.read(KEY_DISABLE), DISABLE_ALL_BUT_UID1);
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
        bench.write(KEY_DISABLE, u64::from(DISABLE_UID1));
        assert_eq!(bench.read(KEY_DISABLE), DISABLE_KNOWN);
        bench.push([OPCODE_KEY << 28 | 1 << 27 | 1 << 24]).unwrap();
        assert_eq!(
            bench.read(INT_STATUS) & INT_KEY_DISABLED[1],
            INT_KEY_DISABLED[1]
        );
        // Without a UID every hardware key reads disabled.
        assert_eq!(Bench::new(None).read(KEY_DISABLE), DISABLE_KNOWN);
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
}
