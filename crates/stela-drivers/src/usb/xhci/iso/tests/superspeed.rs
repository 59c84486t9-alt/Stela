// SPDX-License-Identifier: GPL-2.0-only
//! xHCI isochronous superspeed fixtures.
use super::*;

#[test]
#[ignore = "requires fresh pinned Linux STELA_XHCI_SS_ISO_ORACLE directory; authored UNRUN"]
fn unchanged_linux_superspeed_iso_burst_counts_and_large_esit_mult() {
    use sha2::{Digest, Sha256};
    let directory = std::path::PathBuf::from(std::env::var("STELA_XHCI_SS_ISO_ORACLE").unwrap());
    let trace = std::fs::read(directory.join("trace.txt")).unwrap();
    let receipt = std::fs::read_to_string(directory.join("receipt.json")).unwrap();
    for digest in [
        "abfe6f6f70bdeaf7a279a734bdab034ef014f329785ccb8c5f5cf3e763320198",
        "8c15822f3e118fc5ee9e647b5fc82f75d72f51519f1d9f6dee96d222fe6c9882",
    ] {
        assert!(receipt.contains(digest));
    }
    assert!(receipt.contains(&alloc::format!(
        "\"trace_sha256\": \"{:x}\"",
        Sha256::digest(&trace)
    )));
    let text = std::str::from_utf8(&trace).unwrap();
    let mut count = 0;
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields[0], "B");
        let values: Vec<u32> = fields[1..]
            .iter()
            .map(|value| value.parse().unwrap())
            .collect();
        assert_eq!(values.len(), 8);
        let speed = values[0] as u8;
        let payload = 1024 * (values[2] + 1) * (values[3] + 1);
        let ep = Endpoint {
            address: 0x81,
            attributes: 1,
            max_packet: 1024,
            interval: 1,
            companion: Some(SuperSpeedCompanion {
                max_burst: values[2] as u8,
                attributes: values[3] as u8,
                bytes_per_interval: payload as u16,
            }),
        };
        let recipe = Recipe::new(&ep, speed).unwrap();
        let caps = Capabilities::new(0x110, 0, 0).extended(values[1] << 4);
        let context = caps.context(recipe.context());
        let control = trb_control(recipe, values[4] as usize * 1024, 0);
        assert_eq!(context.info >> 8 & 3, values[5]);
        assert_eq!(control >> 7 & 3, values[6]);
        assert_eq!(control >> 16 & 15, values[7]);
        count += 1;
    }
    assert_eq!(count, 3264);
    assert!(receipt.contains("\"rows\": 3264"));
}

#[test]
fn superspeed_service_bursts_and_lec_contexts_cover_all_standard_mult_values() {
    for speed in [SUPER_SPEED, SUPER_SPEED_PLUS] {
        for burst in 0..=15u8 {
            for mult in 0..=2u8 {
                let payload = 1024 * (u16::from(burst) + 1) * (u16::from(mult) + 1);
                let ep = Endpoint {
                    address: 0x81,
                    attributes: 1,
                    max_packet: 1024,
                    interval: 4,
                    companion: Some(SuperSpeedCompanion {
                        max_burst: burst,
                        attributes: mult,
                        bytes_per_interval: payload,
                    }),
                };
                let recipe = Recipe::new(&ep, speed).unwrap();
                let context = recipe.context();
                assert_eq!(context.info, 3 << 16 | u32::from(mult) << 8);
                assert_eq!(context.info2, 5 << 3 | u32::from(burst) << 8 | 1024 << 16);
                assert_eq!(
                    context.tx_info,
                    u32::from(payload) | u32::from(payload) << 16
                );
                let lec = Capabilities::new(0x110, 0, 0)
                    .extended(1 << 4)
                    .context(context);
                assert_eq!(lec.info, 3 << 16);
                for packets in 1..=(u32::from(burst) + 1) * (u32::from(mult) + 1) {
                    let field = trb_control(recipe, packets as usize * 1024, 0);
                    assert_eq!(field >> 7 & 3, (packets - 1) / (u32::from(burst) + 1));
                    assert_eq!(field >> 16 & 15, (packets - 1) % (u32::from(burst) + 1));
                }
            }
        }
    }
}
