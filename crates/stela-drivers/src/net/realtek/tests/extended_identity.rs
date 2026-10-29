// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! Extended identity cases.
use super::*;

#[test]
fn extended_xid_checks_aperture_before_read_and_keeps_raw_and_classification() {
    struct Version {
        raw: u32,
        reads: Cell<usize>,
    }
    impl Registers for Version {
        fn read32(&self, offset: usize) -> u32 {
            assert_eq!(offset, TX_CONFIG_V2);
            self.reads.set(self.reads.get() + 1);
            self.raw
        }
        fn read8(&self, _: usize) -> u8 {
            panic!("unexpected read")
        }
        fn read16(&self, _: usize) -> u16 {
            panic!("unexpected read")
        }
        fn write8(&self, _: usize, _: u8) {
            panic!("unexpected write")
        }
        fn write16(&self, _: usize, _: u16) {
            panic!("unexpected write")
        }
        fn write32(&self, _: usize, _: u32) {
            panic!("unexpected write")
        }
    }
    for raw in [0, 0x8000_0000, 1, 0x8000_0001, u32::MAX] {
        let regs = Version {
            raw,
            reads: Cell::new(0),
        };
        let result = detect_revision(&regs, 0x7c8 << 20, |bytes| {
            assert_eq!(bytes, 0x60b4);
            assert_eq!(regs.reads.get(), 0);
            Ok(())
        });
        assert_eq!(regs.reads.get(), 1);
        if raw & 0x7fff_ffff == 0 {
            let r = result.unwrap();
            assert_eq!(r.xid, 0x7c8);
            assert_eq!(r.extended_xid, Some(raw));
            assert_eq!(r.extended_classification(), Some(0));
            assert_eq!(r.version, 64);
            assert_eq!(r.name, "RTL9151AS");
            assert_eq!(r.firmware, Some("rtl_nic/rtl9151a-1.fw"));
            assert!(r.implemented());
            assert!(revision::pci_family(0x8125, r));
        } else if raw == u32::MAX {
            assert_eq!(
                result,
                Err(Error::Device(BlockError::Device { status: u32::MAX }))
            );
        } else {
            assert_eq!(
                result,
                Err(Error::UnknownExtendedMac {
                    primary: 0x7c8,
                    extended: raw
                })
            );
            assert!(format!("{}", result.unwrap_err()).contains(&format!("{raw:08x}")));
        }
    }
    let alias = revision::detect_extended(0xfc8 << 20, 0x80000000).unwrap();
    assert_eq!(alias.xid, 0xfc8);
    assert_eq!(alias.extended_xid, Some(0x80000000));
    let regs = Version {
        raw: 0,
        reads: Cell::new(0),
    };
    assert_eq!(
        detect_revision(&regs, 0x7c8 << 20, |_| Err(BlockError::Unsupported(
            "unmapped extended BAR"
        ))),
        Err(Error::Device(BlockError::Unsupported(
            "unmapped extended BAR"
        )))
    );
    assert_eq!(regs.reads.get(), 0);
    let r = detect_revision(&regs, 0x688 << 20, |bytes| {
        assert_eq!(bytes, 0x604a);
        Ok(())
    })
    .unwrap();
    assert_eq!(r.extended_xid, None);
    assert_eq!(r.extended_classification(), None);
    assert_eq!(regs.reads.get(), 0);
    assert!(detect_revision(&regs, u32::MAX, |_| panic!("failed primary read")).is_err());
    assert_eq!(regs.reads.get(), 0);
    assert!(revision::detect_extended(0x688 << 20, 0).is_none());
}

#[test]
fn extended_firmware_catalog_uses_full_raw_identity_without_historical_fallback() {
    use resources::{Catalog, ErrorKind, Provenance, Resource, Target};
    let digest = [
        0x23, 0xc3, 0xcf, 0xd9, 0x9c, 0xa0, 0x28, 0xa0, 0xba, 0x72, 0xe8, 0x92, 0x40, 0xe4, 0xb4,
        0xf8, 0x93, 0xc1, 0xb4, 0x26, 0xa2, 0x1a, 0x6e, 0x89, 0x36, 0xfd, 0x43, 0x13, 0x6b, 0x13,
        0xc1, 0xba,
    ];
    for (raw, key) in [
        (0, "xid-7c8-ext-00000000"),
        (0x80000000, "xid-7c8-ext-80000000"),
    ] {
        let catalog = Catalog::from_handoff(vec![Resource {
            name: "rtl_nic/rtl9151a-1.fw",
            target: Target {
                driver: "realtek",
                hardware: "10ec:8125",
                revision: key,
                board: None,
            },
            provenance: Provenance {
                source: "synthetic-test",
                revision: "1",
                member: "rtl_nic/rtl9151a-1.fw",
                license: "MIT",
            },
            expected_length: 4,
            expected_sha256: digest,
            bytes: 0x801f0000u32.to_le_bytes().to_vec(),
        }])
        .unwrap();
        let extended_revision = revision::detect_extended(0x7c8 << 20, raw).unwrap();
        assert_eq!(
            load_firmware(&catalog, "10ec:8125", extended_revision)
                .unwrap()
                .unwrap()
                .bytes(),
            &0x801f0000u32.to_le_bytes()
        );
        let mut primary_alias = extended_revision;
        primary_alias.xid = 0xfc8;
        assert!(load_firmware(&catalog, "10ec:8125", primary_alias).is_err());
        let other = revision::detect_extended(0x7c8 << 20, raw ^ 0x80000000).unwrap();
        assert!(matches!(
            load_firmware(&catalog, "10ec:8125", other),
            Err(Error::Firmware(resources::Error {
                kind: ErrorKind::WrongTarget,
                ..
            }))
        ));
        assert!(load_firmware(&catalog, "10ec:8125", revision(64)).is_err());
        let historical = revision::detect(0x68b << 20).unwrap();
        assert!(load_firmware(&catalog, "10ec:8125", historical).is_err());
        let mut missing_extended = extended_revision;
        missing_extended.extended_xid = None;
        assert!(load_firmware(&catalog, "10ec:8125", missing_extended).is_err());
        assert!(load_firmware(&catalog, "10ec:8168", extended_revision).is_err());
    }
}
