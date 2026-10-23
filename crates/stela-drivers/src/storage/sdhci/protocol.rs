// SPDX-License-Identifier: GPL-2.0-only
//! SD and MMC initialization, actual card capabilities and durable block I/O.
use super::{command::*, *};

const OCR_READY: u32 = 1 << 31;
const OCR_SECTOR: u32 = 1 << 30;
const OCR_330: u32 = 3 << 20;
const OCR_300: u32 = 3 << 17;
const OCR_180: u32 = 1 << 7;
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

impl Engine {
    pub(super) fn identify(&mut self) -> Result<Medium, BlockError> {
        self.rca = 0;
        self.execute(GO_IDLE, 0, Response::None, None)?;
        let voltage = match self.registers.read8(POWER) & !POWER_ON {
            POWER_330 => OCR_330,
            POWER_300 => OCR_300,
            POWER_180 => OCR_180,
            _ => return Err(BlockError::Unsupported("SDHCI actual power supply")),
        };
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
            || kind == Kind::Sd && self.registers.read32(PRESENT) & WRITE_ALLOWED == 0
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
            self.execute(
                SD_SEND_SCR,
                0,
                Response::Status,
                Some(Data {
                    bytes: 8,
                    block: 8,
                    read: true,
                    pio: true,
                }),
            )?;
            let scr: [u8; 8] = self.data.bytes()[..8].try_into().unwrap();
            if scr[0] >> 4 != 0 || scr[1] & 1 == 0 {
                return Err(BlockError::Unsupported(
                    "SD invalid SCR structure or one-bit support",
                ));
            }
            if scr[1] & 4 != 0 {
                self.application(self.rca)?;
                self.execute(SWITCH, 2, Response::Status, None)?;
                let control = self.registers.read8(HOST_CONTROL);
                self.set_ios_control(control | BUS4)?;
                info.bus_width = 4;
            }
            info.scr = Some(scr);
            if scr[0] & 15 >= 1
                && self.capabilities & CAP_HIGH_SPEED != 0
                && bits(csd, 84, 12) & (1 << 10) != 0
            {
                self.execute(
                    SWITCH,
                    0x00ff_fff1,
                    Response::Status,
                    Some(Data {
                        bytes: 64,
                        block: 64,
                        read: true,
                        pio: true,
                    }),
                )?;
                if self.data.bytes()[13] & 2 != 0 {
                    self.execute(
                        SWITCH,
                        0x80ff_fff1,
                        Response::Status,
                        Some(Data {
                            bytes: 64,
                            block: 64,
                            read: true,
                            pio: true,
                        }),
                    )?;
                    if self.data.bytes()[16] & 15 != 1 {
                        return Err(BlockError::Unsupported(
                            "SD high-speed selection was not acknowledged",
                        ));
                    }
                    let control = self.registers.read8(HOST_CONTROL);
                    self.set_ios_control(control | HIGH_SPEED)?;
                    info.clock_hz = 50_000_000;
                }
            }
        } else if bits(csd, 122, 4) >= 4 {
            self.execute(
                MMC_SEND_EXT_CSD,
                0,
                Response::Status,
                Some(Data {
                    bytes: 512,
                    block: 512,
                    read: true,
                    pio: true,
                }),
            )?;
            let mut ext = self.data.bytes()[..512].to_vec();
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
            // sdhci_setup_host deliberately does not infer board wiring from
            // the controller's 8-bit capability. Generic PCI uses four-bit
            // mode; an 8-bit profile needs separate board-wiring evidence.
            self.mmc_switch(EXT_BUS_WIDTH as u8, 1)?;
            let control = self.registers.read8(HOST_CONTROL) & !(BUS4 | BUS8);
            self.set_ios_control(control | BUS4)?;
            info.bus_width = 4;
            ext[EXT_BUS_WIDTH] = 1;
            // Reread EXT_CSD at the new actual bus width and compare immutable
            // identity/capacity bytes, as Linux's bus-width validation does.
            self.execute(
                MMC_SEND_EXT_CSD,
                0,
                Response::Status,
                Some(Data {
                    bytes: 512,
                    block: 512,
                    read: true,
                    pio: true,
                }),
            )?;
            let check = self.data.bytes();
            if BUS_WIDTH_READ_ONLY
                .iter()
                .any(|index| check[*index] != ext[*index])
            {
                return Err(BlockError::Unsupported("MMC bus-width validation failed"));
            }
            if self.capabilities & CAP_HIGH_SPEED != 0 && ext[EXT_CARD_TYPE] & 3 != 0 {
                let voltage180 = voltage == OCR_180;
                let faster = ext[EXT_CARD_TYPE] & 2 != 0;
                let power_index = match (voltage180, faster) {
                    (true, false) => 201,
                    (true, true) => 200,
                    (false, false) => 203,
                    (false, true) => 202,
                };
                let power_class = ext[power_index] & 15;
                if power_class != 0 {
                    self.mmc_switch(187, power_class)?;
                    ext[187] = power_class;
                }

                self.mmc_switch(EXT_TIMING as u8, 1)?;
                ext[EXT_TIMING] = 1;
                let control = self.registers.read8(HOST_CONTROL);
                self.set_ios_control(control | HIGH_SPEED)?;
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
        self.set_clock(info.clock_hz)?;
        let (_, actual_hz) = clock_divisor(self.version, self.base_hz, info.clock_hz)?;
        info.clock_hz = actual_hz;
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
            location: self.location.clone(),
            model: crate::block::ascii(&product),
            serial,
            blocks,
            block_size: 512,
            read_only,
        };
        self.wait_card_ready()?;
        Ok(Medium {
            id: generation()?,
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
    pub(super) fn mmc_switch(&mut self, index: u8, value: u8) -> Result<(), BlockError> {
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
    pub(super) fn power_off_notify(&mut self) -> Result<(), BlockError> {
        self.execute(SWITCH, 3 << 24 | 34 << 16 | 3 << 8, Response::Busy, None)?;
        Ok(())
    }
    pub(super) fn wait_card_ready(&mut self) -> Result<(), BlockError> {
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
                self.medium = None;
                self.reset(RESET_COMMAND | RESET_DATA)?;
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
/// Register bits use the card's127..0 numbering, after actual R2 reconstruction.
fn bits(words: [u32; 4], start: u32, count: u32) -> u32 {
    let word = (3 - start / 32) as usize;
    let shift = start % 32;
    let value = u64::from(words[word]) >> shift
        | if shift + count > 32 {
            u64::from(words[word - 1]) << (32 - shift)
        } else {
            0
        };
    (value & ((1u64 << count) - 1)) as u32
}
pub(super) fn capacity(kind: Kind, csd: [u32; 4]) -> Result<(u64, u32), BlockError> {
    let structure = bits(csd, 126, 2);
    let block_bits = bits(csd, 80, 4);
    let blocks = if kind == Kind::Sd && structure == 1 {
        (u64::from(bits(csd, 48, 22)) + 1) * 1024
    } else if kind == Kind::Sd && structure != 0 {
        return Err(BlockError::Unsupported(
            "SDUC extended addressing requires explicit support",
        ));
    } else {
        if kind == Kind::Mmc && structure == 0 || !(9..=11).contains(&block_bits) {
            return Err(BlockError::Unsupported(
                "MMC/SD invalid CSD structure/block length",
            ));
        }
        (u64::from(bits(csd, 62, 12)) + 1) << (bits(csd, 47, 3) + 2 + block_bits - 9)
    };
    let exp = [10_000u32, 100_000, 1_000_000, 10_000_000, 0, 0, 0, 0];
    let mant = [
        0u32, 10, 12, 13, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 70, 80,
    ];
    let hz = exp[bits(csd, 96, 3) as usize] * mant[bits(csd, 99, 4) as usize];
    if hz == 0 || blocks == 0 {
        return Err(BlockError::Unsupported(
            "MMC/SD invalid CSD transfer speed/capacity",
        ));
    }
    Ok((blocks, hz))
}
