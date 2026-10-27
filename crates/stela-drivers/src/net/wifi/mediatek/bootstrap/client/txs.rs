// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2023 MediaTek Inc.
//! TX status (TXS) as mt7925 requests and reports it. Auth and association
//! requests, control-port frames and one peer frame each quarter second ask
//! the firmware for status by packet ID (`mt76_tx_status_skb_add`); its TXS
//! reports acknowledgement and the rate used (`mt7925_mac_add_txs_skb`).
use super::*;
use crate::net::wifi::{Bandwidth, Encoding, RxRate, mediatek::rx};
use core::cell::Cell;

/// mt76 MT_PACKET_ID_NO_ACK, MT_PACKET_ID_NO_SKB and MT_PACKET_ID_FIRST;
/// requested IDs stay below MT_PACKET_ID_MASK.
const NO_ACK: u8 = 0;
const NO_SKB: u8 = 1;
const FIRST: u8 = 3;
const LAST: u8 = 126;
/// mt7925 asks one peer frame's status every HZ / 4.
const SAMPLE_US: u64 = 250_000;
/// MT_TX_STATUS_SKB_TIMEOUT: how long a released frame's status is awaited.
const TIMEOUT_US: u64 = 250_000;

/// One requested frame's outcome. A frame whose status did not arrive in
/// time is reported unacknowledged, as mt76 times it out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxStatus {
    pub association: u64,
    pub receipt: Receipt,
    pub acked: bool,
}

struct Waiting {
    pid: u8,
    association: u64,
    receipt: Receipt,
    released: u64,
}

#[derive(Default)]
pub(super) struct State {
    next: Cell<u8>,
    last_sample: Cell<Option<u64>>,
    /// Released frames awaiting their TXS.
    waiting: Vec<Waiting>,
    /// TXS that arrived before their frame's TX-free, by packet ID.
    early: Vec<(u8, bool)>,
    /// Outcomes found at release, reported by the next poll.
    pub(super) ready: Vec<TxStatus>,
    /// `wcid->rate`: the rate of the last reported frame.
    pub(super) rate: Option<RxRate>,
}

impl State {
    /// The TXWI packet ID for a frame to the peer.
    pub(super) fn pid(&self, no_ack: bool, request: bool, now: u64) -> u8 {
        if no_ack {
            return NO_ACK;
        }
        if !request {
            if self
                .last_sample
                .get()
                .is_some_and(|last| now < last.saturating_add(SAMPLE_US))
            {
                return NO_SKB;
            }
            self.last_sample.set(Some(now));
        }
        let pid = self.next.get().clamp(FIRST, LAST);
        self.next.set(if pid == LAST { FIRST } else { pid + 1 });
        pid
    }

    /// Records TX-free for frames that asked for status.
    pub(super) fn released<C>(&mut self, released: &[Released<PacketOwner<C>>], now: u64) {
        for packet in released.iter().filter(|p| p.context.pid >= FIRST) {
            let pid = packet.context.pid;
            let association = packet.context.association;
            if let Some(at) = self.early.iter().position(|&(early, _)| early == pid) {
                let (_, acked) = self.early.remove(at);
                self.ready.push(TxStatus {
                    association,
                    receipt: packet.receipt,
                    acked,
                });
            } else {
                self.waiting.retain(|waiting| waiting.pid != pid);
                self.waiting.push(Waiting {
                    pid,
                    association,
                    receipt: packet.receipt,
                    released: now,
                });
            }
        }
    }

    /// `mt76_tx_status_check`: frames released too long ago are reported
    /// unacknowledged.
    pub(super) fn expire(&mut self, now: u64) {
        let ready = &mut self.ready;
        self.waiting.retain(|waiting| {
            let live = now < waiting.released.saturating_add(TIMEOUT_US);
            if !live {
                ready.push(TxStatus {
                    association: waiting.association,
                    receipt: waiting.receipt,
                    acked: false,
                });
            }
            live
        });
    }

    /// `mt7925_mac_add_txs` over one TXS packet: eight-word records after a
    /// two-word header. Records for other stations or unrequested IDs are
    /// ignored.
    pub(super) fn receive(&mut self, bytes: &[u8], wcid: u16, band: wifi::Band) -> Vec<TxStatus> {
        let mut out = Vec::new();
        for record in bytes.get(8..).unwrap_or_default().as_chunks::<32>().0 {
            let word = |i: usize| u32::from_le_bytes(record[i * 4..i * 4 + 4].try_into().unwrap());
            let (w0, w3) = (word(0), word(3));
            let pid = (w3 >> 24) as u8;
            if (w0 >> 23) & 3 > 1 || pid < FIRST || ((word(2) >> 16) & 0xfff) as u16 != wcid {
                continue;
            }
            let acked = w0 & (7 << 16) == 0;
            if let Some(rate) = rate(w0, w3, band, self.rate) {
                self.rate = Some(rate);
            }
            if let Some(at) = self.waiting.iter().position(|waiting| waiting.pid == pid) {
                let waiting = self.waiting.remove(at);
                out.push(TxStatus {
                    association: waiting.association,
                    receipt: waiting.receipt,
                    acked,
                });
            } else {
                self.early.retain(|&(early, _)| early != pid);
                self.early.push((pid, acked));
            }
        }
        out
    }
}

impl<I: BarIo, Q: QueueIo, C: 'static> Client<I, Q, C> {
    /// The rate of the peer's last reported frame, `wcid->rate`.
    pub fn tx_rate(&self) -> Option<RxRate> {
        self.state().txs.rate
    }
}

/// `mt7925_mac_add_txs_skb`'s rate: `None` for a mode or MCS it leaves
/// unrecorded. HT short GI and the HE/EHT GI carry over from the last rate.
fn rate(w0: u32, w3: u32, band: wifi::Band, last: Option<RxRate>) -> Option<RxRate> {
    let txrate = w0 & 0x3fff;
    let last = last.unwrap_or_default();
    let mut nss = ((txrate >> 10) & 15) as u8 + 1;
    if w3 & (1 << 7) != 0 && nss > 1 {
        nss >>= 1;
    }
    let mut rate = RxRate {
        index: (txrate & 0x3f) as u8,
        nss,
        ..RxRate::default()
    };
    let mode = (txrate >> 6) & 15;
    match mode {
        0 | 1 => rate.index = rx::legacy_rate_index(band, rate.index, mode == 0),
        2 | 3 if rate.index <= 31 => {
            rate.encoding = Encoding::Ht;
            rate.short_gi = last.short_gi;
        }
        4 if rate.index <= 9 => rate.encoding = Encoding::Vht,
        8..=11 if rate.index <= 11 => {
            rate.encoding = Encoding::He;
            rate.gi = last.gi;
            rate.he_dcm = txrate & (1 << 4) != 0;
        }
        13..=15 if rate.index <= 13 => {
            rate.encoding = Encoding::Eht;
            rate.gi = last.gi;
        }
        _ => return None,
    }
    rate.bandwidth = match w0 >> 29 {
        4 => Bandwidth::Mhz320,
        3 => Bandwidth::Mhz160,
        2 => Bandwidth::Mhz80,
        1 => Bandwidth::Mhz40,
        _ => Bandwidth::Mhz20,
    };
    Some(rate)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(acked: bool, txrate: u32, bw: u32, pid: u8, wcid: u16) -> [u8; 32] {
        let mut out = [0; 32];
        let w0 = bw << 29 | u32::from(!acked) << 16 | txrate;
        out[..4].copy_from_slice(&w0.to_le_bytes());
        out[8..12].copy_from_slice(&(u32::from(wcid) << 16).to_le_bytes());
        out[12..16].copy_from_slice(&(u32::from(pid) << 24).to_le_bytes());
        out
    }

    #[test]
    fn packet_ids_request_status_like_mt76_tx_status_skb_add() {
        let state = State::default();
        assert_eq!(state.pid(true, true, 0), NO_ACK);
        // The first frame samples; the next quarter second needs a request.
        assert_eq!(state.pid(false, false, 0), FIRST);
        assert_eq!(state.pid(false, false, SAMPLE_US - 1), NO_SKB);
        assert_eq!(state.pid(false, true, SAMPLE_US - 1), FIRST + 1);
        assert_eq!(state.pid(false, false, SAMPLE_US), FIRST + 2);
        state.next.set(LAST);
        assert_eq!([LAST, FIRST], [0, 0].map(|_| state.pid(false, true, 0)));
    }

    #[test]
    fn status_reports_ack_and_rate_like_mt7925_mac_add_txs() {
        let mut state = State::default();
        let receipt = Receipt::for_tests;
        // A TXS before its TX-free, one after, and one that never arrives.
        let mut bytes = vec![0; 8];
        bytes.extend_from_slice(&record(true, 4 << 6 | 1 << 10 | 7, 2, 3, 5));
        bytes.extend_from_slice(&record(true, 0, 0, 9, 6));
        assert!(state.receive(&bytes, 5, wifi::Band::Ghz5).is_empty());
        let vht = state.rate.unwrap();
        assert_eq!(
            (vht.encoding, vht.index, vht.nss, vht.bandwidth),
            (Encoding::Vht, 7, 2, Bandwidth::Mhz80)
        );
        let owner = |pid| PacketOwner::<()>::for_tests(1, pid);
        let released = [3, 4, 5].map(|pid| Released {
            receipt: receipt(u64::from(pid)),
            evidence: crate::net::wifi::mediatek::ring::data::FreeEvidence {
                header: [0; 2],
                wcid: None,
                pair_word: None,
                accounting: None,
                accounting_word: None,
                release_word: 0,
            },
            context: owner(pid),
        });
        state.released(&released, 100);
        assert_eq!(
            state.ready,
            [TxStatus {
                association: 1,
                receipt: receipt(3),
                acked: true,
            }]
        );
        let mut bytes = vec![0; 8];
        bytes.extend_from_slice(&record(false, 1 << 6 | 12, 0, 4, 5));
        let late = state.receive(&bytes, 5, wifi::Band::Ghz5);
        assert_eq!((late[0].receipt, late[0].acked), (receipt(4), false));
        assert_eq!(state.rate.unwrap().index, 7); // 54 Mb/s on 5 GHz
        state.expire(100 + TIMEOUT_US - 1);
        assert_eq!(state.ready.len(), 1);
        state.expire(100 + TIMEOUT_US);
        assert_eq!(
            state.ready[1],
            TxStatus {
                association: 1,
                receipt: receipt(5),
                acked: false,
            }
        );
        // VHT MCS 10 leaves the rate as it was.
        assert_eq!(rate(4 << 6 | 10, 0, wifi::Band::Ghz5, None), None);
    }
}
