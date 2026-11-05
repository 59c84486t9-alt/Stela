// SPDX-License-Identifier: GPL-2.0-only
// Firmware admission and volatile download adapted from Linux
// xhci-pci-renesas.c. Copyright (C) 2019-2020 Linaro Limited.
//! uPD720201/202 firmware bring-up through the PCI owner. External ROM
//! is only read here; firmware upload targets volatile controller SRAM.
use super::*;
use crate::{bus::pci::ConfigSpace, firmware};

const VENDOR: u16 = 0x1912;
const FW_VERSION: u16 = 0x6c;
const FW_STATUS: u16 = 0xf4;
const FW_MSB: u16 = 0xf5;
const ROM_STATUS: u16 = 0xf6;
const DATA0: u16 = 0xf8;
const DATA1: u16 = 0xfc;
const ENABLE: u8 = 1;
const LOCK: u8 = 2;
const RESULT: u8 = 0x70;
const SUCCESSFUL: u8 = 0x10;
const ROM_EXISTS: u16 = 1 << 15;
const RETRIES: usize = 50_000;
const DELAY_US: u64 = 10;
const NAME: &str = "renesas_usb_fw.mem";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Firmware(firmware::Error),
    Transport(BlockError),
    Image(&'static str),
    Download {
        error: BlockError,
        image: Box<Source>,
    },
}
impl Error {
    pub(super) fn transport(self) -> BlockError {
        match self {
            Self::Transport(error) | Self::Download { error, .. } => error,
            Self::Firmware(_) => BlockError::Unsupported(
                "Renesas renesas_usb_fw.mem exact-target firmware unavailable",
            ),
            Self::Image(why) => BlockError::Unsupported(why),
        }
    }
}
impl From<BlockError> for Error {
    fn from(value: BlockError) -> Self {
        Self::Transport(value)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    ResidentRom,
    ResidentSram,
    VolatileUpload {
        name: String,
        length: usize,
        sha256: [u8; 32],
        source: String,
        revision: String,
        member: String,
        license: String,
        embedded_version: u16,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub device: u16,
    pub silicon_revision: u8,
    pub firmware_version: u32,
    pub source: Source,
}

fn read<C: ConfigSpace>(config: &mut C, at: u16) -> Result<u8, BlockError> {
    match config.read8(at).map_err(BlockError::Config)? {
        u8::MAX => Err(BlockError::Unsupported(
            "Renesas PCI firmware interface disappeared",
        )),
        value => Ok(value),
    }
}
fn running(value: u8) -> Result<bool, BlockError> {
    if value & ENABLE != 0 {
        return Err(BlockError::Unsupported(
            "Renesas stale firmware download requires power-cycle",
        ));
    }
    if value & RESULT == SUCCESSFUL {
        return Ok(true);
    }
    if value & LOCK != 0 || value & RESULT != 0 {
        return Err(BlockError::Device {
            status: u32::from(value),
        });
    }
    Ok(false)
}
fn validate(bytes: &[u8]) -> Result<u16, Error> {
    if !(0x1000..0x10000).contains(&bytes.len()) || !bytes.len().is_multiple_of(4) {
        return Err(Error::Image(
            "Renesas firmware length must be 4 KiB to below 64 KiB and whole dwords",
        ));
    }
    if bytes[..2] != [0xaa, 0x55] {
        return Err(Error::Image("Renesas firmware has no 55aa header"));
    }
    let at = usize::from(u16::from_le_bytes([bytes[4], bytes[5]]));
    if at + 2 >= bytes.len() {
        return Err(Error::Image(
            "Renesas firmware version pointer outside image",
        ));
    }
    Ok(u16::from_le_bytes([bytes[at], bytes[at + 1]]))
}
fn wait_bank<C: ConfigSpace>(config: &mut C, clock: Clock, mask: u8) -> Result<(), BlockError> {
    for _ in 0..RETRIES {
        if read(config, FW_MSB)? & mask == 0 {
            return Ok(());
        }
        clock.delay(DELAY_US);
    }
    Err(BlockError::Timeout)
}
fn upload<C: ConfigSpace>(
    config: &mut C,
    clock: Clock,
    bytes: &[u8],
    minimum: &Minimum,
) -> Result<(), BlockError> {
    minimum.check()?;
    config
        .write8(FW_STATUS, ENABLE)
        .map_err(BlockError::Config)?;
    if read(config, FW_STATUS)? & ENABLE == 0 {
        return Err(BlockError::Unsupported(
            "Renesas firmware download enable not acknowledged",
        ));
    }
    for (step, word) in bytes.as_chunks::<4>().0.iter().enumerate() {
        let bank = (step & 1) as u8;
        wait_bank(config, clock, 1 << bank)?;
        config
            .write32(
                if bank == 0 { DATA0 } else { DATA1 },
                u32::from_le_bytes(*word),
            )
            .map_err(BlockError::Config)?;
        minimum.wait_us(100)?;
        config
            .write8(FW_MSB, 1 << bank)
            .map_err(BlockError::Config)?;
    }
    wait_bank(config, clock, 3)?;
    config.write8(FW_STATUS, 0).map_err(BlockError::Config)?;
    for _ in 0..RETRIES {
        let state = read(config, FW_STATUS)?;
        if running(state)? {
            return Ok(());
        }
        clock.delay(DELAY_US);
    }
    Err(BlockError::Timeout)
}

/// Exact firmware preparation before BAR access/reset. The detailed error keeps
/// the provider's original requirement/manifest error available to callers.
/// ROM success or firmware-status success is required, never ROM presence.
/// A failed download leaves its busy/enable state intact; no retry can
/// silently resume a partial firmware generation.
pub fn prepare<C: ConfigSpace>(
    function: &mut Function<C>,
    clock: Clock,
    provider: &dyn firmware::Provider,
    minimum: Rc<dyn crate::bus::pci::power::Timer>,
) -> Result<Option<Receipt>, Error> {
    let minimum = Minimum::retain(minimum);
    prepare_with_minimum(function, clock, provider, &minimum)
}
pub(super) fn prepare_with_minimum<C: ConfigSpace>(
    function: &mut Function<C>,
    clock: Clock,
    provider: &dyn firmware::Provider,
    minimum: &Minimum,
) -> Result<Option<Receipt>, Error> {
    minimum.check()?;
    streams::pci_policy(function)?;
    if function.vendor != VENDOR || !matches!(function.device, 0x0014 | 0x0015) {
        return Ok(None);
    }
    let device = function.device;
    let revision = function.config().read8(8).map_err(BlockError::Config)?;
    let config = function.config();
    let rom = config.read16(ROM_STATUS).map_err(BlockError::Config)?;
    if rom == u16::MAX {
        return Err(BlockError::Unsupported("Renesas ROM status inaccessible").into());
    }
    let source = if rom & ROM_EXISTS != 0 && (rom as u8 & RESULT) == SUCCESSFUL {
        Source::ResidentRom
    } else if running(read(config, FW_STATUS)?)? {
        Source::ResidentSram
    } else {
        let hardware = format!("{VENDOR:04x}:{device:04x}");
        let revision_name = format!("{revision:02x}");
        let image = provider
            .load(firmware::Requirement {
                name: NAME,
                target: firmware::Target {
                    driver: "usb-xhci-renesas",
                    hardware: &hardware,
                    revision: &revision_name,
                    board: None,
                },
                minimum_bytes: 0x1000,
            })
            .map_err(Error::Firmware)?;
        let embedded_version = validate(image.bytes())?;
        // Keep metadata before any hardware download mutation.
        let p = image.provenance();
        let source = Box::new(Source::VolatileUpload {
            name: image.name().into(),
            length: image.bytes().len(),
            sha256: image.sha256(),
            source: p.source.into(),
            revision: p.revision.into(),
            member: p.member.into(),
            license: p.license.into(),
            embedded_version,
        });
        if let Err(error) = upload(config, clock, image.bytes(), minimum) {
            return Err(Error::Download {
                error,
                image: source,
            });
        }
        *source
    };
    let version = config.read32(FW_VERSION).map_err(BlockError::Config)?;
    if version == u32::MAX {
        return Err(BlockError::Unsupported("Renesas firmware version inaccessible").into());
    }
    Ok(Some(Receipt {
        device,
        silicon_revision: revision,
        firmware_version: (version & 0x00ff_ff80) >> 8,
        source,
    }))
}

#[cfg(test)]
mod tests;
