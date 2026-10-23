// SPDX-License-Identifier: GPL-2.0-only
//! SD and MMC initialization, actual card capabilities and durable block I/O.
use super::{wire::*, *};
use crate::{
    Clock,
    block::{Identity, Transport},
};
use alloc::format;

const COMMAND_US: u64 = 1_000_000;
const DATA_US: u64 = 5_000_000;

const OCR_READY: u32 = 1 << 31;
const OCR_SECTOR: u32 = 1 << 30;
pub(in crate::storage) const OCR_330: u32 = 3 << 20;
pub(in crate::storage) const OCR_300: u32 = 3 << 17;
pub(in crate::storage) const OCR_180: u32 = 1 << 7;
const R1_ILLEGAL: u32 = 1 << 22;
const SD_APP: u32 = 1 << 5;
const EXT_PARTITION: usize = 179;
const EXT_BUS_WIDTH: usize = 183;
const EXT_TIMING: usize = 185;
const EXT_REVISION: usize = 192;
const EXT_CARD_TYPE: usize = 196;
const EXT_SECTORS: usize = 212;
const EXT_CACHE_CONTROL: usize = 33;
const EXT_CACHE_SIZE: usize = 249;
// The complete immutable-byte set from pinned mmc_compare_ext_csds. Mutable
// BUS_WIDTH, HS_TIMING, partition access and cache/notification controls stay
// outside this comparison; their actual command acknowledgements own them.
const BUS_WIDTH_READ_ONLY: &[usize] = &[
    160, 181, 192, 194, 196, 217, 221, 223, 224, 229, 230, 231, 232, 212, 213, 214, 215, 200, 201,
    202, 203, 236, 237, 238, 239, 253,
];

pub(in crate::storage) trait Host {
    fn command(
        &mut self,
        opcode: Opcode,
        argument: u32,
        response: Response,
        read_bytes: Option<usize>,
    ) -> Result<[u32; 4], BlockError>;
    fn clock(&self) -> Clock;
    fn location(&self) -> &str;
    fn voltage(&mut self) -> Result<u32, BlockError>;
    fn writable(&mut self) -> Result<bool, BlockError>;
    fn allow_kind(&self, kind: Kind) -> Result<(), BlockError>;
    fn high_speed_supported(&self) -> bool;
    fn mmc_width(&self) -> u8;
    fn set_bus_width(&mut self, width: u8) -> Result<(), BlockError>;
    fn set_high_speed(&mut self) -> Result<(), BlockError>;
    fn set_clock(&mut self, requested: u32) -> Result<u32, BlockError>;
    fn scratch(&self) -> &[u8];
    fn retire(&mut self) -> Result<(), BlockError>;
}

pub(in crate::storage) struct Description {
    pub rca: u16,
    pub identity: Identity,
    pub kind: Kind,
    pub sector_addressed: bool,
    pub cache: bool,
    pub info: CardInfo,
    pub notify: bool,
}

pub(in crate::storage) struct Session<'a, H: Host> {
    host: &'a mut H,
    rca: u16,
    clock: Clock,
}
impl<'a, H: Host> Session<'a, H> {
    pub fn new(host: &'a mut H, rca: u16) -> Self {
        let clock = host.clock();
        Self { host, rca, clock }
    }
    fn execute(
        &mut self,
        opcode: Opcode,
        argument: u32,
        response: Response,
        read_bytes: Option<usize>,
    ) -> Result<[u32; 4], BlockError> {
        self.host.command(opcode, argument, response, read_bytes)
    }
}

impl<H: Host> Session<'_, H> {
    pub(in crate::storage) fn identify(&mut self) -> Result<Description, BlockError> {
        self.rca = 0;
        self.execute(GO_IDLE, 0, Response::None, None)?;
        let voltage = self.host.voltage()?;
        let v2 = match self.execute(SD_SEND_IF_COND, 0x1aa, Response::Echo, None) {
            Ok(response) if response[0] == 0x1aa => true,
            Ok(response) if response[0] & R1_ERRORS == R1_ILLEGAL => false,
            Ok(_) => {
                return Err(BlockError::Unsupported(
                    "SD SEND_IF_COND echo or voltage mismatch",
                ));
            }
            Err(error) if unavailable(&error) => false,
            Err(error) => return Err(error),
        };
        let sd = match self.application(0) {
            Ok(()) => true,
            Err(error) if unavailable(&error) => false,
            Err(error) => return Err(error),
        };
        let kind = if sd { Kind::Sd } else { Kind::Mmc };
        self.host.allow_kind(kind)?;
        if sd && voltage == OCR_180 {
            return Err(BlockError::Unsupported(
                "SD memory requires initial3.3V signaling",
            ));
        }
        let request = voltage | if v2 || !sd { OCR_SECTOR } else { 0 };
        let deadline = self.clock.deadline(COMMAND_US);
        let ocr = loop {
            let response = if sd {
                self.application(0)?;
                self.execute(SD_SEND_OP_COND, request, Response::Ocr, None)?[0]
            } else {
                self.execute(MMC_SEND_OP_COND, request, Response::Ocr, None)?[0]
            };
            if response & voltage == 0 {
                return Err(BlockError::Unsupported(
                    "MMC/SD card does not support the actual supply",
                ));
            }
            if response & OCR_READY != 0 {
                break response;
            }
            if deadline.passed() {
                return Err(BlockError::Timeout);
            }
            self.clock.delay(10_000);
        };
        let cid = self.execute(ALL_SEND_CID, 0, Response::Long, None)?;
        self.rca = if sd {
            let rca = (self.execute(SET_RELATIVE_ADDRESS, 0, Response::Rca, None)?[0] >> 16) as u16;
            if rca == 0 {
                return Err(BlockError::Unsupported(
                    "SD card returned zero relative address",
                ));
            }
            rca
        } else {
            self.execute(SET_RELATIVE_ADDRESS, 1 << 16, Response::Status, None)?;
            1
        };
        let csd = self.execute(SEND_CSD, u32::from(self.rca) << 16, Response::Long, None)?;
        let mmc_version = bits(csd, 122, 4);
        if !sd && mmc_version > 4 {
            return Err(BlockError::Unsupported(
                "MMC reserved CSD specification version",
            ));
        }

        let (mut blocks, maximum_hz) = capacity(kind, csd)?;
        let sector_addressed = ocr & OCR_SECTOR != 0;
        if sd && !v2 && sector_addressed {
            return Err(BlockError::Unsupported(
                "legacy SD card advertised unsupported sector addressing",
            ));
        }
        if sd && (bits(csd, 126, 2) != 0) != sector_addressed {
            return Err(BlockError::Unsupported(
                "SD OCR/CSD addressing disagreement",
            ));
        }
        let classes = bits(csd, 84, 12);
        if classes & (1 << 2) == 0 {
            return Err(BlockError::Unsupported(
                "MMC/SD card has no block-read command class",
            ));
        }
        let read_only = classes & (1 << 4) == 0
            || kind == Kind::Sd && !self.host.writable()?
            || bits(csd, 12, 2) != 0;
        self.execute(SELECT_CARD, u32::from(self.rca) << 16, Response::Busy, None)?;
        self.wait_card_ready()?;
        let mut info = CardInfo {
            kind,
            cid,
            csd,
            scr: None,
            ext_csd: None,
            clock_hz: maximum_hz.min(25_000_000),
            bus_width: 1,
        };
        let mut cache = false;
        let mut notify = false;
        if sd {
            self.application(self.rca)?;
            self.execute(SD_SEND_SCR, 0, Response::Status, Some(8))?;
            let scr: [u8; 8] = self.host.scratch()[..8].try_into().unwrap();
            if scr[0] >> 4 != 0 || scr[1] & 1 == 0 {
                return Err(BlockError::Unsupported(
                    "SD invalid SCR structure or one-bit support",
                ));
            }
            if scr[1] & 4 != 0 {
                self.application(self.rca)?;
                self.execute(SWITCH, 2, Response::Status, None)?;
                self.host.set_bus_width(4)?;
                info.bus_width = 4;
            }
            info.scr = Some(scr);
            if scr[0] & 15 >= 1
                && self.host.high_speed_supported()
                && bits(csd, 84, 12) & (1 << 10) != 0
            {
                self.execute(SWITCH, 0x00ff_fff1, Response::Status, Some(64))?;
                if self.host.scratch()[13] & 2 != 0 {
                    self.execute(SWITCH, 0x80ff_fff1, Response::Status, Some(64))?;
                    if self.host.scratch()[16] & 15 != 1 {
                        return Err(BlockError::Unsupported(
                            "SD high-speed selection was not acknowledged",
                        ));
                    }
                    self.host.set_high_speed()?;
                    info.clock_hz = 50_000_000;
                }
            }
        } else if bits(csd, 122, 4) >= 4 {
            self.execute(MMC_SEND_EXT_CSD, 0, Response::Status, Some(512))?;
            let mut ext = self.host.scratch()[..512].to_vec();
            if ext[EXT_REVISION] > 8 || ext[194] > 2 {
                return Err(BlockError::Unsupported(
                    "MMC unknown EXT_CSD revision/structure",
                ));
            }
            let sectors = u32::from_le_bytes(ext[EXT_SECTORS..EXT_SECTORS + 4].try_into().unwrap());
            if sector_addressed {
                if sectors == 0 {
                    return Err(BlockError::Unsupported(
                        "MMC sector-addressed card has zero EXT_CSD capacity",
                    ));
                }
                blocks = u64::from(sectors);
            }
            if ext[61] != 0 {
                return Err(BlockError::Unsupported(
                    "MMC native4KiB data sectors require explicit support",
                ));
            }
            if ext[15] != 0 {
                self.mmc_switch(15, 0)?;
                ext[15] = 0;
            }
            if ext[EXT_PARTITION] & 7 != 0 {
                let value = ext[EXT_PARTITION] & !7;
                self.mmc_switch(EXT_PARTITION as u8, value)?;
                ext[EXT_PARTITION] = value;
            }
            // Only an exact source-declared board profile grants eight pins;
            // generic controller CAP_8BIT never establishes board wiring.
            let width = self.host.mmc_width();
            let wire_width = if width == 8 { 2 } else { 1 };
            self.mmc_switch(EXT_BUS_WIDTH as u8, wire_width)?;
            self.host.set_bus_width(width)?;
            info.bus_width = width;
            ext[EXT_BUS_WIDTH] = wire_width;
            // Reread EXT_CSD at the new actual bus width and compare immutable
            // identity/capacity bytes, as Linux's bus-width validation does.
            self.execute(MMC_SEND_EXT_CSD, 0, Response::Status, Some(512))?;
            let check = self.host.scratch();
            if BUS_WIDTH_READ_ONLY
                .iter()
                .any(|index| check[*index] != ext[*index])
            {
                return Err(BlockError::Unsupported("MMC bus-width validation failed"));
            }
            if self.host.high_speed_supported() && ext[EXT_CARD_TYPE] & 3 != 0 {
                let voltage180 = voltage == OCR_180;
                let faster = ext[EXT_CARD_TYPE] & 2 != 0;
                let power_index = match (voltage180, faster) {
                    (true, false) => 201,
                    (true, true) => 200,
                    (false, false) => 203,
                    (false, true) => 202,
                };
                let power_class = ext[power_index] >> if width == 8 { 4 } else { 0 } & 15;
                if power_class != 0 {
                    self.mmc_switch(187, power_class)?;
                    ext[187] = power_class;
                }

                self.mmc_switch(EXT_TIMING as u8, 1)?;
                ext[EXT_TIMING] = 1;
                self.host.set_high_speed()?;
                info.clock_hz = if ext[EXT_CARD_TYPE] & 2 != 0 {
                    52_000_000
                } else {
                    26_000_000
                };
            }
            cache = ext[EXT_CACHE_CONTROL] & 1 != 0
                && u32::from_le_bytes(ext[EXT_CACHE_SIZE..EXT_CACHE_SIZE + 4].try_into().unwrap())
                    != 0;
            if ext[EXT_REVISION] >= 6 {
                self.mmc_switch(34, 1)?;
                ext[34] = 1;
                notify = true;
            }
            info.ext_csd = Some(ext);
        } else if sector_addressed {
            return Err(BlockError::Unsupported(
                "MMC sector addressing requires EXT_CSD",
            ));
        }
        if !sector_addressed {
            self.execute(SET_BLOCK_LENGTH, 512, Response::Status, None)?;
        }
        info.clock_hz = self.host.set_clock(info.clock_hz)?;
        let product: Vec<u8> = (0..if sd {
            5
        } else if bits(csd, 122, 4) <= 1 {
            7
        } else {
            6
        })
            .map(|i| bits(cid, 96 - i * 8, 8) as u8)
            .collect();
        let serial = if sd {
            bits(cid, 24, 32)
        } else if bits(csd, 122, 4) <= 1 {
            bits(cid, 16, 24)
        } else {
            bits(cid, 16, 32)
        };
        let serial = if !sd && mmc_version <= 1 {
            format!("{:06x}-{serial:06x}", bits(cid, 104, 24))
        } else {
            format!("{:02x}-{serial:08x}", bits(cid, 120, 8))
        };
        let identity = Identity {
            transport: Transport::SdMmc,
            location: self.host.location().into(),
            model: crate::block::ascii(&product),
            serial,
            blocks,
            block_size: 512,
            read_only,
        };
        self.wait_card_ready()?;
        Ok(Description {
            rca: self.rca,
            identity,
            kind,
            sector_addressed,
            cache,
            info,
            notify,
        })
    }
    fn application(&mut self, rca: u16) -> Result<(), BlockError> {
        let status = self.execute(APP_CMD, u32::from(rca) << 16, Response::Status, None)?[0];
        if status & SD_APP == 0 {
            return Err(BlockError::Device { status: R1_ILLEGAL });
        }
        Ok(())
    }
    pub(in crate::storage) fn mmc_switch(
        &mut self,
        index: u8,
        value: u8,
    ) -> Result<(), BlockError> {
        self.execute(
            SWITCH,
            3 << 24 | u32::from(index) << 16 | u32::from(value) << 8,
            Response::Busy,
            None,
        )?;
        self.wait_card_ready()
    }
    /// mmc_poweroff_notify uses send_status=false: a compliant card may stop
    /// accepting commands immediately after the notification's busy release.
    pub(in crate::storage) fn power_off_notify(&mut self) -> Result<(), BlockError> {
        self.execute(SWITCH, 3 << 24 | 34 << 16 | 3 << 8, Response::Busy, None)?;
        Ok(())
    }
    pub(in crate::storage) fn wait_card_ready(&mut self) -> Result<(), BlockError> {
        let deadline = self.clock.deadline(DATA_US);
        loop {
            let status = self.execute(
                SEND_STATUS,
                u32::from(self.rca) << 16,
                Response::Status,
                None,
            )?[0];
            if status & (1 << 8) != 0 && status >> 9 & 15 == 4 {
                return Ok(());
            }
            if deadline.passed() {
                self.host.retire()?;
                return Err(BlockError::Timeout);
            }
            self.clock.delay(1000);
        }
    }
}
fn unavailable(error: &BlockError) -> bool {
    matches!(error, BlockError::Timeout)
        || matches!(error, BlockError::Device { status } if status & R1_ERRORS == R1_ILLEGAL)
}
