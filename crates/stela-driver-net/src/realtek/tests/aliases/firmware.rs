// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Stela contributors
//! Aliases firmware cases.
use super::*;

#[test]
fn alias_firmware_catalog_binds_pci_identity_and_borrows_exact_bytes() {
    use resources::{Catalog, Provenance, Resource, Target};
    let digest = [
        0x23, 0xc3, 0xcf, 0xd9, 0x9c, 0xa0, 0x28, 0xa0, 0xba, 0x72, 0xe8, 0x92, 0x40, 0xe4, 0xb4,
        0xf8, 0x93, 0xc1, 0xb4, 0x26, 0xa2, 0x1a, 0x6e, 0x89, 0x36, 0xfd, 0x43, 0x13, 0x6b, 0x13,
        0xc1, 0xba,
    ];
    for alias in [
        0x2502, 0x2600, 0x8129, 0x8162, 0x8167, 0x3000, 0x5000, 0x0e10,
    ] {
        let hardware = format!("10ec:{alias:04x}");
        for (revision, key, name) in [
            (revision(34), "xid-2c8", "rtl_nic/rtl8168e-3.fw"),
            (
                revision::detect_extended(0x7c8 << 20, 0x80000000).unwrap(),
                "xid-7c8-ext-80000000",
                "rtl_nic/rtl9151a-1.fw",
            ),
        ] {
            let bytes = 0x801f0000u32.to_le_bytes().to_vec();
            let pointer = bytes.as_ptr();
            let catalog = Catalog::from_handoff(vec![Resource {
                name,
                target: Target {
                    driver: "realtek",
                    hardware: &hardware,
                    revision: key,
                    board: None,
                },
                provenance: Provenance {
                    source: "synthetic-test",
                    revision: "1",
                    member: name,
                    license: "MIT",
                },
                expected_length: 4,
                expected_sha256: digest,
                bytes,
            }])
            .unwrap();
            let image = load_firmware(&catalog, &hardware, revision)
                .unwrap()
                .unwrap();
            assert_eq!(image.bytes().as_ptr(), pointer);
            for wrong in ["10ec:8125", "10ec:8168", "1186:4300"] {
                assert!(load_firmware(&catalog, wrong, revision).is_err());
            }
            let mut wrong = revision;
            wrong.xid ^= 1;
            assert!(load_firmware(&catalog, &hardware, wrong).is_err());
        }
    }
}

#[test]
fn alias_admission_preserves_required_phy_identity_capability_and_bus_failures() {
    let bytes = 0x8016_a55au32.to_le_bytes();
    let script = Script::parse(&bytes).unwrap();
    for alias in [
        0x2502, 0x2600, 0x8129, 0x8162, 0x8167, 0x3000, 0x5000, 0x0e10,
    ] {
        for version in [17, 34, 64, 70] {
            for failure in 0..5 {
                if failure == 2 && version == 17 {
                    continue;
                } // This path requires no script.
                let time = Time::default();
                let mut model = if version >= 61 {
                    Model::nbase(&time)
                } else {
                    Model::ready(&time)
                };
                let revision = revision(version);
                admit_revision(alias, Some(0x50), revision).unwrap();
                if failure == 1 {
                    let mut state = model.state.borrow_mut();
                    if revision.nbase() {
                        state.phy_ocp.insert(0xa406, 0xc999);
                    } else {
                        state.phy.insert((0, 3), 0xc999);
                    }
                }
                if failure == 3 {
                    model.fault = Some(if revision.nbase() {
                        PHY_OCP
                    } else {
                        PHY_ACCESS
                    });
                }
                if failure == 4 {
                    let mut state = model.state.borrow_mut();
                    if revision.nbase() {
                        state.phy_ocp.insert(0xa616, 0x70);
                    } else {
                        state.phy.insert((0, 1), 0);
                    }
                }
                let mut hw = Hardware::new(&model, &time, revision, 2);
                let result = hw.configure_phy((failure != 2).then_some(&script), false);
                match failure {
                    0 => {
                        result.unwrap();
                        let state = model.state.borrow();
                        assert_eq!(
                            if revision.nbase() {
                                state.phy_ocp[&0xa400]
                            } else {
                                state.phy[&(0, 0)]
                            },
                            0x1200
                        );
                    }
                    1 => assert!(matches!(result, Err(Error::UnsupportedPhy(0x001c_c999)))),
                    2 => assert!(matches!(result, Err(Error::Script(_)))),
                    3 => assert_eq!(result, Err(Error::Device(BlockError::Timeout))),
                    _ => assert!(result.is_err()),
                }
                assert!(
                    !model
                        .state
                        .borrow()
                        .writes
                        .iter()
                        .any(|(r, _, _)| matches!(*r, TX_HIGH | TX_LOW | RX_HIGH | RX_LOW))
                );
            }
        }
    }
}
