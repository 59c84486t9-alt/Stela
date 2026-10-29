// SPDX-License-Identifier: GPL-2.0-only
// Interval/burst mapping follows Linux xhci-mem.c, pinned in THIRD_PARTY.md.
// Copyright (C) 2008 Intel Corp. Author: Sarah Sharp.
//! Validated bulk/interrupt and root-direct USB2 isochronous context fields. Validate before allocating or
//! publishing DMA: invalid descriptors cannot partially configure a device.
use super::{
    BlockError, Endpoint, FULL_SPEED, HIGH_SPEED, LOW_SPEED, SUPER_SPEED, SUPER_SPEED_PLUS,
};

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Context {
    pub info: u32,
    pub info2: u32,
    pub tx_info: u32,
}

impl Context {
    pub fn new(ep: &Endpoint, speed: u8) -> Result<Self, BlockError> {
        if ep.kind() == 1 {
            return super::iso::Recipe::new(ep, speed).map(|recipe| recipe.context());
        }
        let invalid = || BlockError::Unsupported("invalid speed-specific USB endpoint descriptor");
        let packet = u32::from(ep.max_packet & 0x7ff);
        let interrupt = ep.kind() == 3;
        if !matches!(ep.kind(), 2 | 3) || packet == 0 || ep.max_packet & 0xe000 != 0 {
            return Err(invalid());
        }
        // Bulk permits no usage/synchronization bits. Interrupt usage bits
        // 5:4 distinguish periodic and notification (USB 3.x 9.6.6).
        if ep.attributes & if interrupt { 0xcf } else { 0xff } != ep.kind()
            || (interrupt && ep.attributes & 0x30 > 0x10)
        {
            return Err(invalid());
        }
        let (burst, interval, payload) = match speed {
            SUPER_SPEED | SUPER_SPEED_PLUS => {
                let companion = ep.companion.ok_or(BlockError::Unsupported(
                    "missing USB SuperSpeed endpoint companion",
                ))?;
                if ep.max_packet & 0x1800 != 0 || companion.max_burst > 15 {
                    return Err(invalid());
                }
                let burst = u32::from(companion.max_burst);
                if interrupt {
                    let payload = u32::from(companion.bytes_per_interval);
                    if packet > 1024
                        || companion.attributes != 0
                        || !(1..=16).contains(&ep.interval)
                        || payload == 0
                        || payload > packet * (burst + 1)
                    {
                        return Err(invalid());
                    }
                    (burst, u32::from(ep.interval - 1), payload)
                } else {
                    if packet != 1024
                        || companion.bytes_per_interval != 0
                        || companion.attributes & 0xe0 != 0
                    {
                        return Err(invalid());
                    }
                    if companion.attributes > 16 {
                        return Err(invalid());
                    }
                    // MaxStreams advertises a capability, not an instruction
                    // to enable it. Ordinary contexts keep MaxPStreams/LSA zero;
                    // configure_streams enables a checked primary array.
                    (burst, 0, 0)
                }
            }
            HIGH_SPEED | FULL_SPEED | LOW_SPEED => {
                if ep.companion.is_some() || (ep.attributes & 0x30 != 0) {
                    return Err(invalid());
                }
                let transactions = u32::from(ep.max_packet >> 11 & 3);
                if interrupt {
                    let maximum = match speed {
                        HIGH_SPEED => 1024,
                        FULL_SPEED => 64,
                        _ => 8,
                    };
                    if packet > maximum || ep.interval == 0 {
                        return Err(invalid());
                    }
                    let (burst, interval) = if speed == HIGH_SPEED {
                        if transactions > 2 || ep.interval > 16 {
                            return Err(invalid());
                        }
                        (transactions, u32::from(ep.interval - 1))
                    } else {
                        if transactions != 0 {
                            return Err(invalid());
                        }
                        // Linux xhci_parse_frame_interval: floor(log2(frames*8)).
                        let frames = u32::from(ep.interval) * 8;
                        (0, (31 - frames.leading_zeros()).clamp(3, 10))
                    };
                    (burst, interval, packet * (burst + 1))
                } else {
                    if transactions != 0
                        || match speed {
                            HIGH_SPEED => packet != 512,
                            FULL_SPEED => !matches!(packet, 8 | 16 | 32 | 64),
                            _ => true,
                        }
                    {
                        return Err(invalid());
                    }
                    // HS bulk bInterval is its maximum NAK rate, in microframes.
                    let interval = if speed == HIGH_SPEED && ep.interval != 0 {
                        31 - u32::from(ep.interval).leading_zeros()
                    } else {
                        0
                    };
                    (0, interval, 0)
                }
            }
            _ => return Err(BlockError::Unsupported("unknown USB endpoint speed")),
        };
        let kind = match (interrupt, ep.is_in()) {
            (false, false) => 2,
            (true, false) => 3,
            (false, true) => 6,
            (true, true) => 7,
        };
        // Bulk has no periodic payload. Keep the existing 3072-byte average
        // transfer hint; periodic hints use the advertised service bytes.
        Ok(Self {
            info: interval << 16,
            info2: 3 << 1 | kind << 3 | burst << 8 | packet << 16,
            tx_info: if interrupt { payload } else { 3072 } | payload << 16,
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::usb::xhci::SuperSpeedCompanion;

    fn endpoint(kind: u8, packet: u16, interval: u8) -> Endpoint {
        Endpoint {
            address: 0x81,
            attributes: kind,
            max_packet: packet,
            interval,
            companion: None,
        }
    }

    #[test]
    #[ignore = "oracle: STELA_XHCI_ENDPOINT_ORACLE"]
    fn unchanged_linux_endpoint_interval_and_burst_helpers() {
        use sha2::{Digest, Sha256};
        let path =
            std::env::var("STELA_XHCI_ENDPOINT_ORACLE").expect("path to generated donor trace");
        let trace = std::fs::read_to_string(path).unwrap();
        assert_eq!(
            alloc::format!("{:x}", Sha256::digest(trace.as_bytes())),
            "1748ad66b0968a25ee390fd496ec56d5d54d6dd7c23ac51b233ddae66056c7cb"
        );
        let mut count = 0;
        for line in trace.lines() {
            let values: alloc::vec::Vec<u32> = line
                .split_whitespace()
                .map(|n| n.parse().unwrap())
                .collect();
            assert_eq!(values.len(), 7);
            let mut ep = endpoint(values[1] as u8, values[2] as u16, values[3] as u8);
            if values[0] >= u32::from(SUPER_SPEED) {
                ep.companion = Some(SuperSpeedCompanion {
                    max_burst: values[4] as u8,
                    attributes: 0,
                    bytes_per_interval: if ep.kind() == 3 {
                        (1024 * (values[4] + 1)) as u16
                    } else {
                        0
                    },
                });
            }
            // The C harness labels semantic speeds; xHCI swaps FS/LS IDs.
            let speed = match values[0] {
                1 => LOW_SPEED,
                2 => FULL_SPEED,
                n => n as u8,
            };
            let context = Context::new(&ep, speed).unwrap_or_else(|e| panic!("{line}: {e:?}"));
            assert_eq!(context.info >> 16, values[5], "{line}");
            assert_eq!(context.info2 >> 8 & 255, values[6], "{line}");
            count += 1;
        }
        assert_eq!(count, 9774);
    }

    #[test]
    fn speed_specific_intervals_and_usb2_transactions() {
        for interval in 1..=255u8 {
            let ep = endpoint(3, 8, interval);
            for speed in [LOW_SPEED, FULL_SPEED] {
                let context = Context::new(&ep, speed).unwrap();
                assert_eq!(
                    context.info >> 16,
                    (31 - (u32::from(interval) * 8).leading_zeros()).clamp(3, 10)
                );
                assert_eq!(context.tx_info, 8 | 8 << 16);
            }
            let ep = endpoint(2, 512, interval);
            assert_eq!(
                Context::new(&ep, HIGH_SPEED).unwrap().info >> 16,
                31 - u32::from(interval).leading_zeros()
            );
        }
        for transactions in 0..=2 {
            for interval in 1..=16 {
                let ep = endpoint(3, 1024 | transactions << 11, interval);
                let context = Context::new(&ep, HIGH_SPEED).unwrap();
                assert_eq!(context.info, u32::from(interval - 1) << 16);
                assert_eq!(context.info2 >> 8 & 255, u32::from(transactions));
                assert_eq!(
                    context.tx_info,
                    (1024 * (u32::from(transactions) + 1)) * 0x10001
                );
            }
        }
    }

    #[test]
    fn superspeed_companion_controls_burst_and_periodic_payload() {
        for speed in [SUPER_SPEED, SUPER_SPEED_PLUS] {
            for burst in 0..=15 {
                let mut ep = endpoint(2, 1024, 0);
                ep.companion = Some(SuperSpeedCompanion {
                    max_burst: burst,
                    attributes: 0,
                    bytes_per_interval: 0,
                });
                let context = Context::new(&ep, speed).unwrap();
                assert_eq!(context.info, 0);
                assert_eq!(context.info2 >> 8 & 255, u32::from(burst));
                assert_eq!(context.tx_info, 3072);
                ep.attributes = 3;
                ep.interval = 16;
                ep.companion.as_mut().unwrap().bytes_per_interval = 17;
                let context = Context::new(&ep, speed).unwrap();
                assert_eq!(context.info, 15 << 16);
                assert_eq!(context.tx_info, 17 | 17 << 16);
            }
        }
    }

    #[test]
    fn advertised_stream_capability_does_not_enable_streams_in_an_ordinary_context() {
        for attributes in 1..=16 {
            let mut ep = endpoint(2, 1024, 0);
            ep.companion = Some(SuperSpeedCompanion {
                max_burst: 15,
                attributes,
                bytes_per_interval: 0,
            });
            for speed in [SUPER_SPEED, SUPER_SPEED_PLUS] {
                assert_eq!(Context::new(&ep, speed).unwrap().info & 0xfc00, 0);
            }
        }
    }

    #[test]
    fn malformed_speed_packet_interval_streams_and_companions_refuse() {
        for (speed, kind, packet, interval) in [
            (LOW_SPEED, 2, 8, 0),
            (LOW_SPEED, 3, 9, 1),
            (FULL_SPEED, 2, 63, 0),
            (FULL_SPEED, 3, 65, 1),
            (FULL_SPEED, 3, 8 | 1 << 11, 1),
            (HIGH_SPEED, 2, 64, 0),
            (HIGH_SPEED, 3, 1025, 1),
            (HIGH_SPEED, 3, 8 | 3 << 11, 1),
            (HIGH_SPEED, 3, 8, 0),
            (HIGH_SPEED, 3, 8, 17),
            (FULL_SPEED, 3, 8, 0),
            (0, 2, 64, 0),
            (SUPER_SPEED, 2, 1024, 0),
            (SUPER_SPEED_PLUS, 3, 8, 1),
        ] {
            assert!(Context::new(&endpoint(kind, packet, interval), speed).is_err());
        }
        let mut ep = endpoint(2, 1024, 0);
        ep.companion = Some(SuperSpeedCompanion {
            max_burst: 0,
            attributes: 0,
            bytes_per_interval: 0,
        });
        for speed in [SUPER_SPEED, SUPER_SPEED_PLUS] {
            for (packet, burst, attributes, bytes) in [
                (512, 0, 0, 0),
                (1024, 16, 0, 0),
                (1024, 0, 17, 0),
                (1024, 0, 0x80, 0),
                (1024, 0, 0, 1),
                (1024 | 1 << 11, 0, 0, 0),
            ] {
                let mut bad = ep;
                bad.max_packet = packet;
                bad.companion = Some(SuperSpeedCompanion {
                    max_burst: burst,
                    attributes,
                    bytes_per_interval: bytes,
                });
                assert!(Context::new(&bad, speed).is_err());
            }
            for (interval, attributes, bytes) in
                [(0, 0, 1), (17, 0, 1), (1, 1, 1), (1, 0, 0), (1, 0, 1025)]
            {
                let mut bad = ep;
                bad.attributes = 3;
                bad.interval = interval;
                bad.companion.as_mut().unwrap().attributes = attributes;
                bad.companion.as_mut().unwrap().bytes_per_interval = bytes;
                assert!(Context::new(&bad, speed).is_err());
            }
        }
        assert!(Context::new(&ep, HIGH_SPEED).is_err());
    }
}
