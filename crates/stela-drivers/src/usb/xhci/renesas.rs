// SPDX-License-Identifier: GPL-2.0-only
// Firmware admission and volatile download adapted from Linux
// xhci-pci-renesas.c. Copyright (C) 2019-2020 Linaro Limited.
//! uPD720201/202 firmware bring-up through the actual PCI owner. External ROM
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
    match config.read8(at) {
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
fn upload<C: ConfigSpace>(config: &mut C, clock: Clock, bytes: &[u8]) -> Result<(), BlockError> {
    config.write8(FW_STATUS, ENABLE);
    if read(config, FW_STATUS)? & ENABLE == 0 {
        return Err(BlockError::Unsupported(
            "Renesas firmware download enable not acknowledged",
        ));
    }
    for (step, word) in bytes.chunks_exact(4).enumerate() {
        let bank = (step & 1) as u8;
        wait_bank(config, clock, 1 << bank)?;
        config.write32(
            if bank == 0 { DATA0 } else { DATA1 },
            u32::from_le_bytes(word.try_into().unwrap()),
        );
        clock.delay(100);
        config.write8(FW_MSB, 1 << bank);
    }
    wait_bank(config, clock, 3)?;
    config.write8(FW_STATUS, 0);
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
/// Actual ROM success or firmware-status success is required, never ROM presence.
/// A failed download leaves its actual busy/enable state intact; no retry can
/// silently resume a partial firmware generation.
pub fn prepare<C: ConfigSpace>(
    function: &mut Function<C>,
    clock: Clock,
    provider: &dyn firmware::Provider,
) -> Result<Option<Receipt>, Error> {
    streams::pci_policy(function)?;
    if function.vendor != VENDOR || !matches!(function.device, 0x0014 | 0x0015) {
        return Ok(None);
    }
    let device = function.device;
    let revision = function.config().read8(8);
    let config = function.config();
    let rom = config.read16(ROM_STATUS);
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
        // Retain metadata before any hardware download mutation.
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
        if let Err(error) = upload(config, clock, image.bytes()) {
            return Err(Error::Download {
                error,
                image: source,
            });
        }
        *source
    };
    let version = config.read32(FW_VERSION);
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
mod tests {
    use super::*;
    use crate::bus::pci::Address;
    use sha2::{Digest, Sha256};

    struct Model {
        status: u8,
        rom: u16,
        busy: u8,
        silent: bool,
        words: [u32; 2],
        pending: Vec<(u8, u32)>,
        accepted: Vec<u8>,
        writes: Vec<(u16, u32, u8)>,
    }
    struct Config(Rc<RefCell<Model>>);
    impl ConfigSpace for Config {
        fn read32(&self, at: u16) -> u32 {
            match at {
                0 => 0x0014_1912,
                8 => 0x0c03_3003,
                FW_VERSION => 0x2026 << 8,
                _ => 0,
            }
        }
        fn read16(&self, at: u16) -> u16 {
            if at == ROM_STATUS {
                self.0.borrow().rom
            } else {
                (self.read32(at & !3) >> ((at & 2) * 8)) as u16
            }
        }
        fn read8(&self, at: u16) -> u8 {
            let mut m = self.0.borrow_mut();
            match at {
                FW_STATUS => m.status,
                FW_MSB => {
                    let value = m.busy;
                    if !m.silent {
                        for (_, word) in core::mem::take(&mut m.pending) {
                            m.accepted.extend_from_slice(&word.to_le_bytes());
                        }
                        m.busy = 0;
                    }
                    value
                }
                _ => (self.read32(at & !3) >> ((at & 3) * 8)) as u8,
            }
        }
        fn write32(&mut self, at: u16, value: u32) {
            let mut m = self.0.borrow_mut();
            m.writes.push((at, value, 4));
            m.words[usize::from(at == DATA1)] = value;
        }
        fn write8(&mut self, at: u16, value: u8) {
            let mut m = self.0.borrow_mut();
            m.writes.push((at, u32::from(value), 1));
            match at {
                FW_STATUS => {
                    m.status = if value == 0 && m.busy == 0 && !m.accepted.is_empty() {
                        SUCCESSFUL
                    } else {
                        value
                    }
                }
                FW_MSB => {
                    let bank = u8::from(value == 2);
                    assert_eq!(m.busy & value, 0);
                    let word = m.words[usize::from(bank)];
                    m.pending.push((bank, word));
                    m.busy |= value;
                }
                _ => panic!("unexpected firmware byte write"),
            }
        }
    }
    fn function(status: u8, rom: u16) -> (Function<Config>, Rc<RefCell<Model>>) {
        let model = Rc::new(RefCell::new(Model {
            status,
            rom,
            busy: 0,
            silent: false,
            words: [0; 2],
            pending: Vec::new(),
            accepted: Vec::new(),
            writes: Vec::new(),
        }));
        let f = Function::new(
            Address {
                segment: 0,
                bus: 0,
                device: 1,
                function: 0,
            },
            Config(model.clone()),
        )
        .unwrap();
        (f, model)
    }
    fn bytes() -> Vec<u8> {
        let mut bytes = vec![0; 4096];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = index as u8;
        }
        bytes[..2].copy_from_slice(&[0xaa, 0x55]);
        bytes[4..6].copy_from_slice(&8u16.to_le_bytes());
        bytes[8..10].copy_from_slice(&0x2026u16.to_le_bytes());
        bytes
    }
    fn catalog(bytes: Vec<u8>) -> firmware::Catalog {
        firmware::Catalog::from_handoff(vec![firmware::Resource {
            name: NAME,
            target: firmware::Target {
                driver: "usb-xhci-renesas",
                hardware: "1912:0014",
                revision: "03",
                board: None,
            },
            provenance: firmware::Provenance {
                source: "authored model fixture",
                revision: "1",
                member: "renesas_usb_fw.mem",
                license: "test-only",
            },
            expected_length: bytes.len(),
            expected_sha256: Sha256::digest(&bytes).into(),
            bytes,
        }])
        .unwrap()
    }
    #[test]
    fn real_mailbox_words_are_acknowledged_and_exact_metadata_survives_provider_drop() {
        let bytes = bytes();
        let (mut f, model) = function(0, 0);
        let receipt = {
            let catalog = catalog(bytes.clone());
            prepare(
                &mut f,
                Clock {
                    ticks_per_microsecond: 1,
                },
                &catalog,
            )
            .unwrap()
            .unwrap()
        };
        assert_eq!(model.borrow().accepted, bytes);
        assert_eq!(receipt.firmware_version, 0x2026);
        let Source::VolatileUpload {
            embedded_version,
            sha256,
            ..
        } = receipt.source
        else {
            panic!()
        };
        assert_eq!(embedded_version, 0x2026);
        assert_eq!(sha256, <[u8; 32]>::from(Sha256::digest(&bytes)));
        assert_eq!(
            model
                .borrow()
                .writes
                .iter()
                .filter(|(_, _, width)| *width == 4)
                .count(),
            1024
        );
        assert!(
            model
                .borrow()
                .writes
                .iter()
                .all(|(at, _, _)| *at != ROM_STATUS)
        );
    }
    #[test]
    fn rom_presence_never_substitutes_for_firmware_success_and_stale_download_stays_failed() {
        let empty = firmware::Catalog::from_handoff(vec![]).unwrap();
        let clock = Clock {
            ticks_per_microsecond: 1,
        };
        let (mut f, model) = function(0, ROM_EXISTS);
        assert!(matches!(
            prepare(&mut f, clock, &empty),
            Err(Error::Firmware(_))
        ));
        assert!(model.borrow().writes.is_empty());
        let (mut f, model) = function(ENABLE, 0);
        assert!(prepare(&mut f, clock, &catalog(bytes())).is_err());
        assert!(model.borrow().writes.is_empty());
        let (mut f, model) = function(0, 0);
        model.borrow_mut().silent = true;
        assert!(prepare(&mut f, clock, &catalog(bytes())).is_err());
        let writes = model.borrow().writes.len();
        assert_ne!(model.borrow().status & ENABLE, 0);
        assert!(prepare(&mut f, clock, &catalog(bytes())).is_err());
        assert_eq!(model.borrow().writes.len(), writes);
    }
    #[test]
    fn acknowledged_resident_images_need_no_download_and_invalid_images_never_publish_enable() {
        let empty = firmware::Catalog::from_handoff(vec![]).unwrap();
        for (status, rom, expected) in [
            (SUCCESSFUL | LOCK, 0, Source::ResidentSram),
            (0, ROM_EXISTS | u16::from(SUCCESSFUL), Source::ResidentRom),
        ] {
            let (mut f, model) = function(status, rom);
            let receipt = prepare(
                &mut f,
                Clock {
                    ticks_per_microsecond: 1,
                },
                &empty,
            )
            .unwrap()
            .unwrap();
            assert_eq!(receipt.source, expected);
            assert!(model.borrow().writes.is_empty());
        }
        let mut image = bytes();
        image[4..6].copy_from_slice(&4095u16.to_le_bytes());
        let (mut f, model) = function(0, 0);
        assert!(matches!(
            prepare(
                &mut f,
                Clock {
                    ticks_per_microsecond: 1
                },
                &catalog(image)
            ),
            Err(Error::Image(_))
        ));
        assert!(model.borrow().writes.is_empty());
    }
}
