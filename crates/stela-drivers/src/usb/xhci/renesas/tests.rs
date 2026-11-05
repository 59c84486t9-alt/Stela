// SPDX-License-Identifier: GPL-2.0-only
// xhci-pci-renesas.c. Copyright (C) 2019-2020 Linaro Limited.
//! Isolated protocol models and source-bound failure controls.
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
    fn read32(&self, at: u16) -> core::result::Result<u32, crate::bus::pci::ConfigError> {
        Ok({
            match at {
                0 => 0x0014_1912,
                8 => 0x0c03_3003,
                FW_VERSION => 0x2026 << 8,
                _ => 0,
            }
        })
    }
    fn read16(&self, at: u16) -> core::result::Result<u16, crate::bus::pci::ConfigError> {
        Ok({
            if at == ROM_STATUS {
                self.0.borrow().rom
            } else {
                (self.read32(at & !3)? >> ((at & 2) * 8)) as u16
            }
        })
    }
    fn read8(&self, at: u16) -> core::result::Result<u8, crate::bus::pci::ConfigError> {
        Ok({
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
                _ => (self.read32(at & !3)? >> ((at & 3) * 8)) as u8,
            }
        })
    }
    fn write32(
        &mut self,
        at: u16,
        value: u32,
    ) -> core::result::Result<(), crate::bus::pci::ConfigError> {
        let mut m = self.0.borrow_mut();
        m.writes.push((at, value, 4));
        m.words[usize::from(at == DATA1)] = value;

        Ok(())
    }
    fn write8(
        &mut self,
        at: u16,
        value: u8,
    ) -> core::result::Result<(), crate::bus::pci::ConfigError> {
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

        Ok(())
    }

    fn write16(
        &mut self,
        offset: u16,
        value: u16,
    ) -> core::result::Result<(), crate::bus::pci::ConfigError> {
        let shift = (offset & 2) * 8;
        let word = self.read32(offset & !3)? & !(0xffff << shift) | u32::from(value) << shift;
        self.write32(offset & !3, word)
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
fn interrupted_data_minimum_never_kicks_the_bank_or_retries_partial_firmware() {
    struct Interrupted(Rc<dyn crate::bus::pci::power::Timer>);
    // SAFETY: test-only current-thread virtual timer; unsuccessful wait
    // grants no elapsed time or native effect permission.
    unsafe impl crate::bus::pci::power::Timer for Interrupted {
        fn check(&self) -> Result<(), crate::bus::pci::power::Error> {
            self.0.check()
        }
        fn wait_us(&self, us: u64) -> Result<(), crate::bus::pci::power::Error> {
            self.0.check()?;
            assert_eq!(us, 100);
            Err(crate::bus::pci::power::Error::Interrupted)
        }
    }
    let clock = Clock {
        ticks_per_microsecond: 1,
    };
    let (mut function, model) = function(0, 0);
    let catalog = catalog(bytes());
    let timer = Rc::new(Interrupted(crate::minimum_model::owned(clock)));
    assert!(matches!(
        prepare(&mut function, clock, &catalog, timer),
        Err(Error::Download {
            error: BlockError::PciPower(crate::bus::pci::power::Error::Interrupted),
            ..
        })
    ));
    let before = model.borrow().writes.clone();
    assert_eq!(before.len(), 2);
    assert_eq!(before[0], (FW_STATUS, u32::from(ENABLE), 1));
    assert_eq!(before[1].0, DATA0);
    assert!(model.borrow().accepted.is_empty() && model.borrow().pending.is_empty());
    assert!(matches!(
        prepare(
            &mut function,
            clock,
            &catalog,
            crate::minimum_model::owned(clock)
        ),
        Err(Error::Transport(BlockError::Unsupported(_)))
    ));
    assert_eq!(model.borrow().writes, before);
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
            crate::minimum_model::owned(Clock {
                ticks_per_microsecond: 1,
            }),
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
        prepare(&mut f, clock, &empty, crate::minimum_model::owned(clock)),
        Err(Error::Firmware(_))
    ));
    assert!(model.borrow().writes.is_empty());
    let (mut f, model) = function(ENABLE, 0);
    assert!(
        prepare(
            &mut f,
            clock,
            &catalog(bytes()),
            crate::minimum_model::owned(clock)
        )
        .is_err()
    );
    assert!(model.borrow().writes.is_empty());
    let (mut f, model) = function(0, 0);
    model.borrow_mut().silent = true;
    assert!(
        prepare(
            &mut f,
            clock,
            &catalog(bytes()),
            crate::minimum_model::owned(clock)
        )
        .is_err()
    );
    let writes = model.borrow().writes.len();
    assert_ne!(model.borrow().status & ENABLE, 0);
    assert!(
        prepare(
            &mut f,
            clock,
            &catalog(bytes()),
            crate::minimum_model::owned(clock)
        )
        .is_err()
    );
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
            crate::minimum_model::owned(Clock {
                ticks_per_microsecond: 1,
            }),
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
            &catalog(image),
            crate::minimum_model::owned(Clock {
                ticks_per_microsecond: 1
            })
        ),
        Err(Error::Image(_))
    ));
    assert!(model.borrow().writes.is_empty());
}
