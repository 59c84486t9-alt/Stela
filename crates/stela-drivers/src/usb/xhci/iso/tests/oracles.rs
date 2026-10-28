// SPDX-License-Identifier: GPL-2.0-only
//! xHCI isochronous oracles fixtures.
use super::*;

#[test]
#[ignore = "oracle: STELA_XHCI_ISO_ORACLE"]
fn xhci_iso_contexts_match_linux() {
    use sha2::{Digest, Sha256};
    let trace = std::fs::read_to_string(
        std::env::var("STELA_XHCI_ISO_ORACLE").expect("path to fresh source oracle trace"),
    )
    .unwrap();
    assert_eq!(
        alloc::format!("{:x}", Sha256::digest(trace.as_bytes())),
        "8dff7cfded211423e137dde9864585635f4ac2467fe7c93057081a0c925927e6"
    );
    let mut count = 0;
    for line in trace.lines() {
        let mut fields = line.split_whitespace();
        let kind = fields.next().unwrap();
        let values: Vec<i64> = fields.map(|v| v.parse().unwrap()).collect();
        match kind {
            "E" => {
                assert_eq!(values.len(), 8);
                let speed = if values[0] == 2 {
                    FULL_SPEED
                } else {
                    HIGH_SPEED
                };
                let ep = Endpoint {
                    address: if values[3] != 0 { 0x81 } else { 1 },
                    attributes: 1,
                    max_packet: values[4] as u16 | (values[2] as u16) << 11,
                    interval: values[1] as u8,
                    companion: None,
                };
                match Recipe::new(&ep, speed) {
                    Ok(recipe) => {
                        let context = recipe.context();
                        assert_eq!(
                            [context.info, context.info2, context.tx_info],
                            [values[5] as u32, values[6] as u32, values[7] as u32]
                        );
                    }
                    Err(_) => assert!(values[5] >> 16 > 12),
                }
            }
            "S" => {
                assert_eq!(values.len(), 8);
                let caps = Capabilities::new(
                    0x110,
                    values[1] as u32,
                    if values[2] != 0 { 1 << 11 } else { 0 },
                );
                let next = if values[4] < 0 {
                    None
                } else {
                    Some(values[4] as u32)
                };
                // Linux only logs a start outside the window (values[7]).
                let (start, field) = schedule(values[0] as u32, caps, values[3] as u32, next);
                assert_eq!(start, values[5] as u32);
                assert_eq!(
                    field,
                    if values[6] != 0 {
                        (start / 8) << 20
                    } else {
                        SIA
                    }
                );
            }
            "C" => {
                assert_eq!(values.len(), 6);
                assert_eq!(values[4], 1); // process_isoc_td reached finish callback.
                if matches!(values[0], 6 | 22) {
                    // The original finish path still requires halt/slot recovery:
                    // its packet-status assignment is not a DMA-release ACK.
                    assert!(completion(values[0] as u32, 128, values[1] as usize).is_err());
                    assert_eq!(values[3], -71);
                    assert_eq!(values[5], i64::from(values[0] == 6));
                } else {
                    assert_eq!(values[5], 0);
                    let packet = completion(values[0] as u32, 128, values[1] as usize).unwrap();
                    assert_eq!(packet.bytes, values[2] as usize);
                    assert_eq!(
                        match packet.status {
                            IsoStatus::Success | IsoStatus::Short => 0,
                            IsoStatus::MissedService => -18,
                            IsoStatus::Transaction => -71,
                            IsoStatus::Babble | IsoStatus::BufferOverrun => -75,
                            IsoStatus::Bandwidth => -70,
                        },
                        values[3]
                    );
                }
            }
            "B" => {
                assert_eq!(values.len(), 3);
                let recipe = Recipe::new(&endpoint(0x81, HIGH_SPEED), HIGH_SPEED).unwrap();
                let field = trb_control(recipe, values[0] as usize * 1024, 0);
                assert_eq!(field >> 7 & 3, values[1] as u32);
                assert_eq!(field >> 16 & 15, values[2] as u32);
            }
            _ => panic!("unknown source trace row"),
        }
        count += 1;
    }
    assert_eq!(count, 4656);
}

#[test]
#[ignore = "oracle: STELA_XHCI_AMD_PCI_ORACLE"]
fn xhci_amd_quirks_match_linux() {
    use sha2::{Digest, Sha256};
    let trace = std::fs::read_to_string(
        std::env::var("STELA_XHCI_AMD_PCI_ORACLE").expect("path to fresh source oracle trace"),
    )
    .unwrap();
    assert_eq!(
        alloc::format!("{:x}", Sha256::digest(trace.as_bytes())),
        "f15c7bae3478f2cbf04438ef5fa64d24799ee708dc73d32fec4d1f687c4e57b9"
    );
    let mut count = 0;
    let mut legacy_positive = false;
    let mut actual_negative = 0;
    for line in trace.lines() {
        let mut fields = line.split_whitespace();
        let kind = fields.next().unwrap();
        let values: Vec<u64> = fields.map(|v| v.parse().unwrap()).collect();
        assert_eq!(values.len(), 5);
        match kind {
            "P" => {
                assert!(matches!(values[0], 0x15b6 | 0x15b7 | 0x15b8 | 0x43fc));
                Capabilities::new(values[2] as u16, 0, 0).admit().unwrap();
                // xHCI>=1.2 permits runtime PM generically; this cold polled
                // backend does not claim a suspend/runtime-power service.
                assert_eq!(values[3], if values[2] >= 0x120 { 1 << 33 } else { 0 });
                assert_eq!(values[4], 0);
            }
            "L" => {
                if values[0] == 0x1022 && values[1] == 0x790b {
                    assert_eq!(values[3], 0);
                    actual_negative += 1;
                }
                legacy_positive |= values[3] != 0;
            }
            _ => panic!("unknown PCI source trace"),
        }
        count += 1;
    }
    assert_eq!(count, 4096);
    assert_eq!(actual_negative, 256);
    assert!(legacy_positive);
}
