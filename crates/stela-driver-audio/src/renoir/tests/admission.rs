// SPDX-License-Identifier: GPL-2.0-only
//! Admission cases.
use super::*;

#[test]
fn same_function_presence_selector_and_all_source_board_exclusions() {
    for cfg in [
        Config {
            ownership: Ownership::Unknown,
            ..config()
        },
        Config {
            ownership: Ownership::FirmwareDsp,
            ..config()
        },
        Config {
            wov: None,
            ..config()
        },
        Config {
            wov: Some(0),
            ..config()
        },
        Config {
            board: None,
            ..config()
        },
        Config {
            acp_config: None,
            ..config()
        },
        Config {
            acp_config: Some(1),
            ..config()
        },
        Config {
            acp_config: Some(2),
            ..config()
        },
        Config {
            acp_config: Some(4),
            ..config()
        },
        Config {
            gain: 4,
            ..config()
        },
        Config {
            dma_address_bits: 64,
            ..config()
        },
    ] {
        assert_claim_refuses(cfg);
    }
    for (product_name, board_name) in [
        ("81NB", "Other"),
        ("81X2", "Other"),
        ("81YQ", "Other"),
        ("Other", "20T6CTO1WW"),
        ("Other", "20NLCTO1WW"),
    ] {
        let board = BoardIdentity {
            board_vendor: "LENOVO",
            product_name,
            board_name,
        };
        assert_claim_refuses(Config {
            board: Some(board),
            ..config()
        });
        // Pinned DMI_EXACT_MATCH, not substring, casefold or product prefix.
        for altered in [
            BoardIdentity {
                board_vendor: "Lenovo",
                ..board
            },
            BoardIdentity {
                board_vendor: "LENOVO Inc.",
                ..board
            },
        ] {
            assert!(!altered.microphone_excluded());
        }
    }
    for revision in [0, 2, 0x50, 0x60, 0x62, 0x63, 0x6f, 0x70] {
        assert!(!Renoir::supported(Identity {
            vendor: 0x1022,
            device: 0x15e2,
            revision
        }));
    }
    // A board name can only exclude: no _WOV and no selector still refuse.
    let (mut controller, device, _) = fixture(1);
    controller.initialize().unwrap();
    assert_eq!(device.lock().unwrap().words[0x1804 / 4], 1 << 29);
    controller.shutdown().unwrap();
}
