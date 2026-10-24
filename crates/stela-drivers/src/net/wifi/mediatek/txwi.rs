// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Ordinary raw-802.11 PCIe TXD construction, adapted from Connac2/MT7925.
//! Input metadata must come from the shared validated MPDU and actual installed
//! firmware station/rate context. Encoding does not install keys, allocate a
//! token, publish DMA or claim the hardware transmitted an indicated sequence.
use super::identity::Chip;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidLength,
    InvalidHeader,
    InvalidStation,
    InvalidVif,
    InvalidTid,
    InvalidSequence,
    InvalidRate,
    MissingRate,
    UnsupportedFragment,
    UnsupportedFrame,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MediaTek TXWI: {self:?}")
    }
}
impl core::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Management,
    Control,
    Data,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Sequence {
    /// Source ordinary path: hardware assigns the air sequence. Host MPDU
    /// bytes alone must not be reported as the actual transmitted sequence.
    Hardware,
    /// Source injected path: SN_VALID and the explicit 12-bit sequence are set.
    Explicit(u16),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fragment {
    None,
    First,
    Middle,
    Last,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Queue {
    Data { access_category: u8 },
    Management,
    Beacon,
    Discovery,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vif {
    pub omac: u8,
    pub wmm: u8,
    /// Actual firmware hardware-band index, not the radio frequency band.
    pub band: u8,
    pub mld: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedRate {
    /// Actual source PHY-encoded legacy rate word, selected from negotiated
    /// basic rates. This helper never guesses a channel/rate or substitutes zero.
    Connac2(u16),
    /// Actual configured firmware basic/multicast/beacon rate table index.
    Connac3(u8),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame {
    pub bytes: usize,
    pub header_bytes: u8,
    pub kind: Kind,
    pub subtype: u8,
    pub tid: u8,
    pub multicast: bool,
    pub fragment: Fragment,
    pub sequence: Sequence,
    /// Ordinary management or data only. Action frames require actual body
    /// qualification below; BIP/MMIE/translated 802.3 and monitor radiotap
    /// policy remain outside this explicitly bounded profile.
    pub minimum_rate: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    pub chip: Chip,
    pub wcid: u16,
    pub vif: Option<Vif>,
    pub phy_band_one: bool,
    pub queue: Queue,
    pub pid: u8,
    pub frame: Frame,
    /// A current acknowledged actual hardware-key context must exist at
    /// publication. This wire flag neither proves encryption nor owns a PN.
    pub protect: bool,
    pub no_ack: bool,
    pub hardware_amsdu: bool,
    /// Used only when frame type/multicast/minimum_rate selects the source
    /// fixed-rate path; providing this context alone never forces a rate.
    pub fixed_rate: Option<FixedRate>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum QualifiedAction {
    BlockAck(u8),
    SaQuery,
}

pub fn encode(c: Config) -> Result<[u8; 32], Error> {
    encode_inner(c, None)
}

/// Body-qualified MT7925 Block Ack and protected unicast SA Query path.
/// Metadata-only Action encoding remains refused: the real category/action bytes select the donor
/// ADDBA-request TID independently of ordinary response/DELBA management.
/// This constructs no agreement, radio permission, protection or air receipt.
pub(in crate::net::wifi::mediatek) fn encode_mpdu(
    c: Config,
    bytes: &[u8],
) -> Result<[u8; 32], Error> {
    if c.frame.kind != Kind::Management || c.frame.subtype != 13 {
        return encode(c);
    }
    let h = crate::net::wifi::frame::Header::parse(bytes).map_err(|_| Error::InvalidHeader)?;
    if c.chip != Chip::Mt7925
        || h.fragmented()
        || h.control & 0x00fc != 0x00d0
        || h.length != 24
        || usize::from(c.frame.header_bytes) != h.length
        || c.frame.bytes != bytes.len()
    {
        return Err(Error::UnsupportedFrame);
    }
    let body = bytes.get(h.length..).ok_or(Error::InvalidHeader)?;
    if c.protect != h.protected() {
        return Err(Error::UnsupportedFrame);
    }
    if c.protect
        && (h.receiver.is_multicast()
            || h.control & 0x0300 != 0
            || c.frame.multicast
            || c.queue != Queue::Management)
    {
        return Err(Error::UnsupportedFrame);
    }
    if c.protect && body.first() == Some(&8) {
        if body.len() != 4 || body[1] > 1 {
            return Err(Error::UnsupportedFrame);
        }
        return encode_inner(c, Some(QualifiedAction::SaQuery));
    }
    if body.first() != Some(&3) {
        return Err(Error::UnsupportedFrame);
    }
    let action = *body.get(1).ok_or(Error::InvalidHeader)?;
    let minimum = match action {
        0 | 1 => 9,
        2 => 6,
        _ => return Err(Error::UnsupportedFrame),
    };
    if body.len() < minimum {
        return Err(Error::InvalidHeader);
    }
    encode_inner(c, Some(QualifiedAction::BlockAck(action)))
}

fn encode_inner(c: Config, action: Option<QualifiedAction>) -> Result<[u8; 32], Error> {
    let f = c.frame;
    let connac3 = c.chip == Chip::Mt7925;
    // BAR derives TID/start sequence from its body; Action can select the
    // ADDBA-specific TID/flag path. This bounded metadata has neither body.
    if (f.kind == Kind::Control && f.subtype == 8)
        || (f.kind == Kind::Management && f.subtype == 13 && action.is_none())
    {
        return Err(Error::UnsupportedFrame);
    }
    if c.wcid >= 20 {
        return Err(Error::InvalidStation);
    }
    if f.bytes
        .checked_add(32)
        .is_none_or(|n| n > u16::MAX as usize)
    {
        return Err(Error::InvalidLength);
    }
    if f.header_bytes < 10
        || f.header_bytes > 62
        || !f.header_bytes.is_multiple_of(2)
        || usize::from(f.header_bytes) > f.bytes
        || f.subtype > 15
    {
        return Err(Error::InvalidHeader);
    }
    if f.tid > 15 || (!connac3 && f.tid > 7) {
        return Err(Error::InvalidTid);
    }
    if let Sequence::Explicit(n) = f.sequence
        && n > 4095
    {
        return Err(Error::InvalidSequence);
    }
    if connac3 && f.fragment != Fragment::None {
        return Err(Error::UnsupportedFragment);
    }
    if let Some(v) = c.vif
        && (v.omac > 63 || v.wmm > 3 || (v.band > 3 && v.band != 255))
    {
        return Err(Error::InvalidVif);
    }
    let vif = c.vif.unwrap_or(Vif {
        omac: 0,
        wmm: 0,
        band: 0,
        mld: false,
    });
    if (connac3 && c.phy_band_one) || (!connac3 && vif.mld) {
        return Err(Error::InvalidVif);
    }
    if !connac3 && vif.band > 1 {
        return Err(Error::InvalidVif);
    }
    let (format, queue) = match c.queue {
        Queue::Data { access_category } if access_category < 4 => {
            (0, u32::from(vif.wmm) * 4 + 3 - u32::from(access_category))
        }
        Queue::Data { .. } => return Err(Error::InvalidVif),
        Queue::Management => (0, 16),
        Queue::Beacon => (3, 18),
        Queue::Discovery => (3, 16),
    };
    let kind = match f.kind {
        Kind::Management => 0,
        Kind::Control => 1,
        Kind::Data => 2,
    };
    let fixed = f.kind != Kind::Data || f.multicast || f.minimum_rate;
    let mut words = [0u32; 8];
    words[0] = (f.bytes + 32) as u32 | (format << 23) | (queue << 25);
    words[1] = u32::from(c.wcid);
    words[2] = (kind << 4) | u32::from(f.subtype);
    words[3] = 15 << 11 | u32::from(c.protect) << 1 | u32::from(c.no_ack);
    words[5] = u32::from(c.pid) | if c.pid >= 3 { 1 << 10 } else { 0 };
    let mut amsdu = c.hardware_amsdu && c.pid < 3;
    if connac3 {
        // pinned connac3 tx_mgnt_type::{MT_TX_NORMAL=0,MT_TX_ADDBA=2}.
        let tid = if action == Some(QualifiedAction::BlockAck(0)) {
            2
        } else if f.kind == Kind::Management {
            0
        } else {
            f.tid
        };
        words[1] |= u32::from(vif.omac) << 25
            | u32::from(tid) << 21
            | u32::from(f.header_bytes / 2) << 16
            | 2 << 14;
        if vif.band != 0 && vif.band != 255 {
            words[1] |= u32::from(vif.band) << 12;
        }
        words[3] |= u32::from(f.multicast) << 4;
        if c.pid >= 3 {
            words[3] |= 1 << 28;
        }
        words[6] = (1 << 2) | (1 << 4);
        if c.vif.is_some() && (!vif.mld || (16..=18).contains(&queue)) {
            words[6] |= 1 << 3;
        }
        if fixed {
            words[1] |= 1 << 31;
        }
    } else {
        words[1] |= 1 << 31
            | u32::from(vif.omac) << 24
            | u32::from(f.tid) << 20
            | 2 << 16
            | u32::from(f.header_bytes / 2) << 11;
        if c.phy_band_one || vif.band != 0 {
            words[1] |= 1 << 30;
        }
        words[2] |= u32::from(f.multicast) << 10;
        let frag = match f.fragment {
            Fragment::None => 0,
            Fragment::First => 1,
            Fragment::Middle => 2,
            Fragment::Last => 3,
        };
        words[2] |= frag << 14;
        words[7] = kind << 20 | u32::from(f.subtype) << 16;
        if fixed {
            words[2] |= 1 << 31;
        }
    }
    if f.kind == Kind::Management && f.subtype == 8 {
        words[3] |= 31 << 11;
    }
    if let Sequence::Explicit(seq) = f.sequence {
        words[3] |= 1 << 31 | u32::from(seq) << 16;
        amsdu = false;
    }
    if fixed {
        match (connac3, c.fixed_rate) {
            (false, Some(FixedRate::Connac2(rate))) if rate < 0x4000 => {
                words[2] |= 1 << 13;
                words[6] = (1 << 2) | (u32::from(rate) << 16);
            }
            (true, Some(FixedRate::Connac3(index))) if index < 64 => {
                words[6] |= u32::from(index) << 16;
            }
            (_, None) => return Err(Error::MissingRate),
            _ => return Err(Error::InvalidRate),
        }
        words[3] |= 1 << 28;
        // Connac2 clears HW_AMSDU on fixed-rate frames. Normal MT7925's
        // source keeps its bit unless PID/status or explicit sequence clears it.
        if !connac3 {
            amsdu = false;
        }
    }
    if amsdu {
        if connac3 {
            words[3] |= 1 << 5;
        } else {
            words[7] |= 1 << 10;
        }
    }
    let mut bytes = [0u8; 32];
    for (i, word) in words.into_iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn base(chip: Chip) -> Config {
        Config {
            chip,
            wcid: 7,
            vif: Some(Vif {
                omac: 2,
                wmm: 1,
                band: 0,
                mld: false,
            }),
            phy_band_one: false,
            queue: Queue::Data { access_category: 0 },
            pid: 3,
            frame: Frame {
                bytes: 128,
                header_bytes: 26,
                kind: Kind::Data,
                subtype: 8,
                tid: 5,
                multicast: false,
                fragment: Fragment::None,
                sequence: Sequence::Hardware,
                minimum_rate: false,
            },
            protect: true,
            no_ack: false,
            hardware_amsdu: true,
            fixed_rate: None,
        }
    }
    fn words(bytes: [u8; 32]) -> [u32; 8] {
        core::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap()))
    }
    #[test]
    fn distinct_raw_data_layouts_keep_firmware_sequence_and_pn_ownership_explicit() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let mut c = base(chip);
            let w = words(encode(c).unwrap());
            assert_eq!(w[0], 160 | (7 << 25));
            assert_eq!(w[3] & ((1 << 31) | (1 << 30) | (0xfff << 16)), 0);
            assert_eq!(w[4], 0); // no fabricated host PN
            assert_eq!(w[5], 3 | (1 << 10));
            assert_eq!(w[3] & 2, 2);
            if chip == Chip::Mt7925 {
                assert_eq!(w[1], 7 | (2 << 25) | (5 << 21) | (13 << 16) | (2 << 14));
                assert_eq!(w[3], (15 << 11) | (1 << 28) | 2);
                assert_eq!(w[6], 0x1c);
                assert_eq!(w[7], 0);
            } else {
                assert_eq!(
                    w[1],
                    7 | (1 << 31) | (2 << 24) | (5 << 20) | (2 << 16) | (13 << 11)
                );
                assert_eq!(w[2], 0x28);
                assert_eq!(w[3], (15 << 11) | 2);
                assert_eq!(w[6], 0);
                assert_eq!(w[7], (2 << 20) | (8 << 16));
            }
            c.pid = 0;
            c.frame.sequence = Sequence::Explicit(0xabc);
            let w = words(encode(c).unwrap());
            assert_eq!(
                w[3] & ((1 << 31) | (0xfff << 16)),
                (1 << 31) | (0xabc << 16)
            );
            assert_eq!(w[3] & (1 << 30), 0);
            assert_eq!(
                if chip == Chip::Mt7925 {
                    w[3] & (1 << 5)
                } else {
                    w[7] & (1 << 10)
                },
                0
            );
            c.frame.sequence = Sequence::Hardware;
            let w = words(encode(c).unwrap());
            assert_ne!(
                if chip == Chip::Mt7925 {
                    w[3] & (1 << 5)
                } else {
                    w[7] & (1 << 10)
                },
                0
            );
        }
    }
    #[test]
    fn fixed_management_multicast_paths_require_actual_chip_rate_context() {
        for chip in [Chip::Mt7921, Chip::Mt7925] {
            let mut c = base(chip);
            c.frame.kind = Kind::Management;
            c.frame.subtype = 0xb;
            c.frame.header_bytes = 24;
            c.queue = Queue::Management;
            c.pid = 0;
            assert_eq!(encode(c), Err(Error::MissingRate));
            c.fixed_rate = Some(if chip == Chip::Mt7925 {
                FixedRate::Connac3(31)
            } else {
                FixedRate::Connac2(0x4b)
            });
            let w = words(encode(c).unwrap());
            assert_eq!(w[0] >> 25, 16);
            assert_ne!(w[3] & (1 << 28), 0);
            if chip == Chip::Mt7925 {
                assert_eq!((w[1] >> 21) & 15, 0);
                assert_ne!(w[1] & (1 << 31), 0);
                assert_eq!((w[6] >> 16) & 63, 31);
                assert_ne!(w[3] & (1 << 5), 0);
            } else {
                assert_ne!(w[2] & (1 << 31), 0);
                assert_ne!(w[2] & (1 << 13), 0);
                assert_eq!(w[6], (0x4b << 16) | 4);
                assert_eq!(w[7] & (1 << 10), 0);
            }
            c.frame.kind = Kind::Data;
            c.frame.multicast = true;
            let w = words(encode(c).unwrap());
            assert_ne!(
                if chip == Chip::Mt7925 {
                    w[3] & (1 << 4)
                } else {
                    w[2] & (1 << 10)
                },
                0
            );
            c.fixed_rate = Some(if chip == Chip::Mt7925 {
                FixedRate::Connac2(0)
            } else {
                FixedRate::Connac3(0)
            });
            assert_eq!(encode(c), Err(Error::InvalidRate));
        }
    }
    #[test]
    fn fields_and_unsupported_profiles_do_not_silently_truncate() {
        let c = base(Chip::Mt7921);
        for bytes in [usize::MAX, 65504] {
            assert_eq!(
                encode(Config {
                    frame: Frame { bytes, ..c.frame },
                    ..c
                }),
                Err(Error::InvalidLength)
            );
        }
        for header_bytes in [0, 9, 11, 64] {
            assert_eq!(
                encode(Config {
                    frame: Frame {
                        header_bytes,
                        ..c.frame
                    },
                    ..c
                }),
                Err(Error::InvalidHeader)
            );
        }
        assert_eq!(encode(Config { wcid: 20, ..c }), Err(Error::InvalidStation));
        assert_eq!(
            encode(Config {
                frame: Frame { tid: 8, ..c.frame },
                ..c
            }),
            Err(Error::InvalidTid)
        );
        assert_eq!(
            encode(Config {
                frame: Frame {
                    sequence: Sequence::Explicit(4096),
                    ..c.frame
                },
                ..c
            }),
            Err(Error::InvalidSequence)
        );
        for v in [
            Vif {
                omac: 64,
                wmm: 0,
                band: 0,
                mld: false,
            },
            Vif {
                omac: 0,
                wmm: 4,
                band: 0,
                mld: false,
            },
            Vif {
                omac: 0,
                wmm: 0,
                band: 2,
                mld: false,
            },
            Vif {
                omac: 0,
                wmm: 0,
                band: 0,
                mld: true,
            },
        ] {
            assert_eq!(encode(Config { vif: Some(v), ..c }), Err(Error::InvalidVif));
        }
        let c = base(Chip::Mt7925);
        assert_eq!(
            encode(Config {
                phy_band_one: true,
                ..c
            }),
            Err(Error::InvalidVif)
        );
        assert_eq!(
            encode(Config {
                frame: Frame {
                    fragment: Fragment::First,
                    ..c.frame
                },
                ..c
            }),
            Err(Error::UnsupportedFragment)
        );
        let w = words(
            encode(Config {
                vif: Some(Vif {
                    omac: 1,
                    wmm: 0,
                    band: 255,
                    mld: true,
                }),
                ..c
            })
            .unwrap(),
        );
        assert_eq!(w[1] & (3 << 12), 0);
        assert_eq!(w[6] & 8, 0);
    }

    #[test]
    fn bar_and_action_require_the_unimplemented_body_specific_profile() {
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            for sequence in [Sequence::Hardware, Sequence::Explicit(123)] {
                for (kind, subtype) in [(Kind::Control, 8), (Kind::Management, 13)] {
                    let c = base(chip);
                    assert_eq!(
                        encode(Config {
                            frame: Frame {
                                kind,
                                subtype,
                                sequence,
                                ..c.frame
                            },
                            ..c
                        }),
                        Err(Error::UnsupportedFrame)
                    );
                }
            }
        }
    }
    #[test]
    fn actual_block_ack_action_body_selects_source_request_or_normal_management_tid() {
        for action in 0..=2u8 {
            let mut bytes = [0; 33];
            bytes[..2].copy_from_slice(&0x00d0u16.to_le_bytes());
            bytes[4] = 2;
            bytes[24] = 3;
            bytes[25] = action;
            let mut c = base(Chip::Mt7925);
            c.frame = Frame {
                bytes: bytes.len(),
                header_bytes: 24,
                kind: Kind::Management,
                subtype: 13,
                tid: 7,
                multicast: false,
                fragment: Fragment::None,
                sequence: Sequence::Hardware,
                minimum_rate: true,
            };
            c.protect = false;
            c.hardware_amsdu = false;
            c.fixed_rate = Some(FixedRate::Connac3(18));
            assert_eq!(encode(c), Err(Error::UnsupportedFrame));
            let w = words(encode_mpdu(c, &bytes).unwrap());
            assert_eq!((w[1] >> 21) & 15, if action == 0 { 2 } else { 0 });
            assert_eq!(w[2] & 0x3f, 13);
            assert_ne!(w[1] & (1 << 31), 0);
            assert_eq!(encode_mpdu(c, &bytes[..25]), Err(Error::UnsupportedFrame));
            bytes[24] = 4;
            assert_eq!(encode_mpdu(c, &bytes), Err(Error::UnsupportedFrame));
        }
    }
    #[test]
    fn protected_sa_query_requires_exact_body_and_both_wire_and_descriptor_protection() {
        for action in 0..=1u8 {
            let mut bytes = [0; 28];
            bytes[..2].copy_from_slice(&0x40d0u16.to_le_bytes());
            bytes[4] = 2;
            bytes[24..].copy_from_slice(&[8, action, 0xa5, 0x5a]);
            let mut config = base(Chip::Mt7925);
            config.frame = Frame {
                bytes: bytes.len(),
                header_bytes: 24,
                kind: Kind::Management,
                subtype: 13,
                tid: 7,
                multicast: false,
                fragment: Fragment::None,
                sequence: Sequence::Hardware,
                minimum_rate: true,
            };
            config.queue = Queue::Management;
            config.hardware_amsdu = false;
            config.fixed_rate = Some(FixedRate::Connac3(18));
            assert_eq!(encode(config), Err(Error::UnsupportedFrame));
            let encoded = words(encode_mpdu(config, &bytes).unwrap());
            assert_eq!((encoded[1] >> 21) & 15, 0);
            assert_eq!(encoded[3] & 2, 2);
            for fault in 0..10 {
                let mut bad = bytes;
                let mut selected = config;
                match fault {
                    0 => bad[24] = 4,
                    1 => bad[25] = 2,
                    2 => bad[1] &= !0x40,
                    3 => selected.protect = false,
                    4 => bad[4] |= 1,
                    5 => bad[1] |= 1,
                    6 => bad[22] = 1,
                    7 => selected.frame.multicast = true,
                    8 => selected.queue = Queue::Data { access_category: 0 },
                    _ => selected.chip = Chip::Mt7922,
                }
                assert!(encode_mpdu(selected, &bad).is_err(), "fault {fault}");
            }
            let mut short = config;
            short.frame.bytes -= 1;
            assert!(encode_mpdu(short, &bytes[..27]).is_err());
            let mut long = config;
            long.frame.bytes += 1;
            let mut trailing = bytes.to_vec();
            trailing.push(0);
            assert!(encode_mpdu(long, &trailing).is_err());
        }
    }

    #[test]
    fn protected_block_ack_uses_source_tid_and_cipher_with_exact_body_qualification() {
        for action in 0..=2u8 {
            let len = if action == 2 { 30 } else { 33 };
            let mut bytes = vec![0; len];
            bytes[..2].copy_from_slice(&0x00d0u16.to_le_bytes());
            bytes[4] = 2;
            bytes[24] = 3;
            bytes[25] = action;
            let mut config = base(Chip::Mt7925);
            config.frame = Frame {
                bytes: len,
                header_bytes: 24,
                kind: Kind::Management,
                subtype: 13,
                tid: 7,
                multicast: false,
                fragment: Fragment::None,
                sequence: Sequence::Hardware,
                minimum_rate: true,
            };
            config.queue = Queue::Management;
            config.hardware_amsdu = false;
            config.fixed_rate = Some(FixedRate::Connac3(18));
            config.protect = false;
            let plain = words(encode_mpdu(config, &bytes).unwrap());
            bytes[1] |= 0x40;
            config.protect = true;
            let protected = words(encode_mpdu(config, &bytes).unwrap());
            assert_eq!((protected[1] >> 21) & 15, if action == 0 { 2 } else { 0 });
            for index in 0..8 {
                assert_eq!(
                    protected[index],
                    plain[index] | if index == 3 { 2 } else { 0 }
                );
            }
            for fault in 0..11 {
                let mut bad = bytes.clone();
                let mut selected = config;
                match fault {
                    0 => bad[1] &= !0x40,
                    1 => selected.protect = false,
                    2 => bad[4] |= 1,
                    3 => bad[1] |= 1,
                    4 => bad[22] |= 1,
                    5 => selected.frame.multicast = true,
                    6 => selected.queue = Queue::Data { access_category: 0 },
                    7 => bad[24] = 4,
                    8 => bad[25] = 3,
                    9 => selected.chip = Chip::Mt7922,
                    _ => {
                        bad.pop();
                        selected.frame.bytes -= 1;
                    }
                }
                assert!(
                    encode_mpdu(selected, &bad).is_err(),
                    "action {action}, fault {fault}"
                );
            }
        }
    }

    #[test]
    #[ignore = "requires STELA_MT792X_TXWI_ORACLE from unchanged pinned raw80211 descriptor writers"]
    fn unchanged_pinned_raw80211_writers_match_every_descriptor_word() {
        extern crate std;
        let root = std::env::var_os("STELA_MT792X_TXWI_ORACLE").expect("reference trace directory");
        for chip in [Chip::Mt7921, Chip::Mt7922, Chip::Mt7925] {
            let name = match chip {
                Chip::Mt7921 => "7921",
                Chip::Mt7922 => "7922",
                Chip::Mt7925 => "7925",
            };
            let bytes =
                std::fs::read(std::path::Path::new(&root).join(format!("mt{name}.bin"))).unwrap();
            assert_eq!(bytes.len(), 256 * 128);
            for (case, record) in bytes.as_chunks::<128>().0.iter().enumerate() {
                let v: [u32; 24] = core::array::from_fn(|i| {
                    u32::from_le_bytes(record[i * 4..i * 4 + 4].try_into().unwrap())
                });
                let f = Frame {
                    bytes: v[10] as usize,
                    header_bytes: v[11] as u8,
                    kind: match v[12] {
                        0 => Kind::Management,
                        1 => Kind::Control,
                        2 => Kind::Data,
                        _ => panic!("frame"),
                    },
                    subtype: v[13] as u8,
                    tid: v[14] as u8,
                    multicast: v[15] != 0,
                    fragment: match v[16] {
                        0 => Fragment::None,
                        1 => Fragment::First,
                        2 => Fragment::Middle,
                        3 => Fragment::Last,
                        _ => panic!("fragment"),
                    },
                    sequence: if v[17] != 0 {
                        Sequence::Explicit(v[18] as u16)
                    } else {
                        Sequence::Hardware
                    },
                    minimum_rate: v[22] != 0,
                };
                let config = Config {
                    chip,
                    wcid: v[0] as u16,
                    vif: (v[1] != 0).then_some(Vif {
                        omac: v[2] as u8,
                        wmm: v[3] as u8,
                        band: v[4] as u8,
                        mld: v[5] != 0,
                    }),
                    phy_band_one: v[6] != 0,
                    queue: match v[7] {
                        0 => Queue::Data {
                            access_category: v[8] as u8,
                        },
                        1 => Queue::Management,
                        2 => Queue::Beacon,
                        3 => Queue::Discovery,
                        _ => panic!("queue"),
                    },
                    pid: v[9] as u8,
                    frame: f,
                    protect: v[19] != 0,
                    no_ack: v[20] != 0,
                    hardware_amsdu: v[21] != 0,
                    fixed_rate: Some(if chip == Chip::Mt7925 {
                        FixedRate::Connac3(v[23] as u8)
                    } else {
                        FixedRate::Connac2(v[23] as u16)
                    }),
                };
                assert_eq!(
                    encode(config).unwrap(),
                    &record[96..],
                    "chip {name} case {case} {config:?}"
                );
            }
        }
    }
}
