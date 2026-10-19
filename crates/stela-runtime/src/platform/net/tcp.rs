//! One TCP client connection (RFC 9293 sections 3.3 to 3.10): active
//! open, in-order delivery, retransmission with exponential backoff, and a
//! graceful close.
//!
//! Simplifications, each one a refusal or a conservative choice rather
//! than an approximation of the protocol: segments that arrive out of
//! order are not buffered (they are acknowledged at the expected sequence,
//! so the peer retransmits); a timeout resends everything unacknowledged
//! (go-back-N); the receive window is a fixed 65535 bytes, since received
//! data moves straight into an unbounded buffer the caller drains; no
//! window scaling, SACK or timestamps are offered; and the connection ends
//! when both FINs are acknowledged, without TIME-WAIT: each connection uses
//! a fresh local port, so no old duplicate can reach a successor.
use super::{
    NetError,
    wire::{ACK, FIN, PSH, RST, SYN},
};
use alloc::{collections::VecDeque, vec::Vec};

pub const MSS: u16 = 1460;
const WINDOW: u16 = 65535;
/// The initial retransmission timeout (RFC 6298 2.1) and its bound.
const INITIAL_RTO_US: u64 = 1_000_000;
const MAX_RTO_US: u64 = 16_000_000;
/// Retransmissions of one segment before the connection fails.
const MAX_RETRIES: u32 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    SynSent,
    Established,
    Closed,
}

/// A segment the connection asks to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Emit {
    pub sequence: u32,
    pub acknowledgment: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
    pub payload: Vec<u8>,
}

/// A received segment, already matched to this connection's ports.
#[derive(Debug, Clone, Copy)]
pub struct Incoming<'a> {
    pub sequence: u32,
    pub acknowledgment: u32,
    pub flags: u8,
    pub window: u16,
    pub mss: Option<u16>,
    pub payload: &'a [u8],
}

/// Sequence-space comparison modulo 2^32.
fn before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

pub struct Connection {
    pub state: State,
    iss: u32,
    /// The oldest unacknowledged and the next sequence number to send.
    una: u32,
    next: u32,
    /// The peer's advertised window and segment size.
    window: u32,
    mss: usize,
    /// The next sequence number expected from the peer.
    expected: u32,
    /// Bytes from `una` onward: unacknowledged, then unsent.
    outgoing: VecDeque<u8>,
    /// Bytes received in order and not yet taken.
    pub received: Vec<u8>,
    close_requested: bool,
    fin_sent: bool,
    fin_acked: bool,
    pub peer_closed: bool,
    rto: u64,
    retransmit_at: Option<u64>,
    retries: u32,
}

impl Connection {
    /// A connection in SYN-SENT and the SYN that opens it.
    pub fn open(iss: u32, now: u64) -> (Self, Emit) {
        let mut connection = Self {
            state: State::SynSent,
            iss,
            una: iss,
            next: iss.wrapping_add(1),
            window: 0,
            mss: usize::from(MSS),
            expected: 0,
            outgoing: VecDeque::new(),
            received: Vec::new(),
            close_requested: false,
            fin_sent: false,
            fin_acked: false,
            peer_closed: false,
            rto: INITIAL_RTO_US,
            retransmit_at: None,
            retries: 0,
        };
        connection.retransmit_at = Some(now + connection.rto);
        let syn = connection.syn();
        (connection, syn)
    }

    fn syn(&self) -> Emit {
        Emit {
            sequence: self.iss,
            acknowledgment: 0,
            flags: SYN,
            window: WINDOW,
            mss: Some(MSS),
            payload: Vec::new(),
        }
    }

    fn ack(&self) -> Emit {
        Emit {
            sequence: self.next,
            acknowledgment: self.expected,
            flags: ACK,
            window: WINDOW,
            mss: None,
            payload: Vec::new(),
        }
    }

    /// Queues `data` for sending.
    pub fn send(&mut self, data: &[u8]) -> Result<(), NetError> {
        if self.close_requested || self.state == State::Closed {
            return Err(NetError::Invalid("send after close"));
        }
        self.outgoing.extend(data);
        Ok(())
    }

    /// Asks for a FIN once every queued byte is sent.
    pub fn close(&mut self) {
        self.close_requested = true;
    }

    /// Every sent byte, and the FIN if one was asked for, is acknowledged.
    pub fn drained(&self) -> bool {
        self.outgoing.is_empty() && (!self.close_requested || self.fin_acked)
    }

    /// Bytes sent but not acknowledged, FIN excluded.
    fn in_flight(&self) -> usize {
        let span = self.next.wrapping_sub(self.una) as usize;
        span - usize::from(self.fin_sent && !self.fin_acked)
    }

    /// Handles one segment of this connection's 4-tuple, returning what to
    /// send in reply.
    pub fn receive(&mut self, segment: Incoming<'_>, now: u64) -> Result<Vec<Emit>, NetError> {
        let mut replies = Vec::new();
        match self.state {
            State::Closed => return Ok(replies),
            State::SynSent => {
                let acceptable =
                    segment.flags & ACK != 0 && segment.acknowledgment == self.iss.wrapping_add(1);
                if segment.flags & RST != 0 {
                    if acceptable {
                        self.state = State::Closed;
                        return Err(NetError::Refused);
                    }
                    return Ok(replies);
                }
                if segment.flags & SYN == 0 || !acceptable {
                    return Ok(replies);
                }
                self.una = segment.acknowledgment;
                self.expected = segment.sequence.wrapping_add(1);
                self.window = u32::from(segment.window);
                if let Some(mss) = segment.mss {
                    self.mss = usize::from(mss.clamp(64, MSS));
                } else {
                    // RFC 9293 3.7.1: 536 bytes without the option.
                    self.mss = 536;
                }
                self.state = State::Established;
                self.retransmit_at = None;
                self.retries = 0;
                self.rto = INITIAL_RTO_US;
                replies.push(self.ack());
                replies.extend(self.transmit(now));
                return Ok(replies);
            }
            State::Established => {}
        }
        // RFC 9293 3.10.7.4: only an in-window RST is believed.
        if segment.flags & RST != 0 {
            if segment.sequence == self.expected {
                self.state = State::Closed;
                return Err(NetError::Reset);
            }
            return Ok(replies);
        }
        if segment.flags & ACK != 0 {
            let ack = segment.acknowledgment;
            if before(self.una, ack) && !before(self.next, ack) {
                let mut acked = ack.wrapping_sub(self.una) as usize;
                if self.fin_sent && ack == self.next {
                    self.fin_acked = true;
                    acked -= 1;
                }
                self.outgoing.drain(..acked.min(self.outgoing.len()));
                self.una = ack;
                self.retries = 0;
                self.rto = INITIAL_RTO_US;
                self.retransmit_at = (self.una != self.next).then_some(now + self.rto);
            }
            self.window = u32::from(segment.window);
        }
        let mut acknowledge = false;
        if !segment.payload.is_empty() || segment.flags & FIN != 0 {
            acknowledge = true;
            if segment.sequence == self.expected && !self.peer_closed {
                self.received.extend_from_slice(segment.payload);
                self.expected = self.expected.wrapping_add(segment.payload.len() as u32);
                if segment.flags & FIN != 0 {
                    self.expected = self.expected.wrapping_add(1);
                    self.peer_closed = true;
                }
            }
        }
        let sent = self.transmit(now);
        // Data segments carry the acknowledgment themselves.
        if acknowledge && sent.is_empty() {
            replies.push(self.ack());
        }
        replies.extend(sent);
        if self.fin_acked && self.peer_closed {
            self.state = State::Closed;
        }
        Ok(replies)
    }

    /// New data the peer's window admits, then the FIN when due.
    fn transmit(&mut self, now: u64) -> Vec<Emit> {
        let mut segments = Vec::new();
        if self.state != State::Established {
            return segments;
        }
        loop {
            let flight = self.in_flight();
            let unsent = self.outgoing.len() - flight.min(self.outgoing.len());
            let room = (self.window as usize).saturating_sub(flight);
            let length = unsent.min(room).min(self.mss);
            if length == 0 {
                break;
            }
            let payload: Vec<u8> = self
                .outgoing
                .range(flight..flight + length)
                .copied()
                .collect();
            segments.push(Emit {
                sequence: self.next,
                acknowledgment: self.expected,
                flags: ACK | PSH,
                window: WINDOW,
                mss: None,
                payload,
            });
            self.next = self.next.wrapping_add(length as u32);
        }
        if self.close_requested
            && !self.fin_sent
            && self.in_flight() == self.outgoing.len()
            && self.state == State::Established
        {
            segments.push(Emit {
                sequence: self.next,
                acknowledgment: self.expected,
                flags: FIN | ACK,
                window: WINDOW,
                mss: None,
                payload: Vec::new(),
            });
            self.next = self.next.wrapping_add(1);
            self.fin_sent = true;
        }
        if !segments.is_empty() && self.retransmit_at.is_none() {
            self.retransmit_at = Some(now + self.rto);
        }
        segments
    }

    /// Timer work at `now`: a retransmission when one is due, and data the
    /// caller queued since the last segment.
    pub fn poll(&mut self, now: u64) -> Result<Vec<Emit>, NetError> {
        if self.state == State::Closed {
            return Ok(Vec::new());
        }
        if self.retransmit_at.is_some_and(|due| now >= due) {
            self.retries += 1;
            if self.retries > MAX_RETRIES {
                let what = match self.state {
                    State::SynSent => "TCP connection",
                    _ => "TCP retransmission",
                };
                self.state = State::Closed;
                return Err(NetError::Timeout(what));
            }
            self.rto = (self.rto * 2).min(MAX_RTO_US);
            self.retransmit_at = Some(now + self.rto);
            if self.state == State::SynSent {
                return Ok(alloc::vec![self.syn()]);
            }
            // Go back to the oldest unacknowledged byte.
            self.next = self.una;
            self.fin_sent = false;
            // A zero window is probed with one byte (RFC 9293 3.8.6.1).
            let window = self.window;
            if window == 0 {
                self.window = 1;
            }
            let segments = self.transmit(now);
            self.window = window;
            return Ok(segments);
        }
        Ok(self.transmit(now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn incoming(sequence: u32, acknowledgment: u32, flags: u8, payload: &[u8]) -> Incoming<'_> {
        Incoming {
            sequence,
            acknowledgment,
            flags,
            window: 4096,
            mss: None,
            payload,
        }
    }

    fn established() -> Connection {
        let (mut c, syn) = Connection::open(1000, 0);
        assert_eq!(syn.flags, SYN);
        assert_eq!(syn.mss, Some(MSS));
        let replies = c
            .receive(
                Incoming {
                    mss: Some(1000),
                    ..incoming(5000, 1001, SYN | ACK, &[])
                },
                10,
            )
            .unwrap();
        assert_eq!(c.state, State::Established);
        assert_eq!(replies[0].flags, ACK);
        assert_eq!(replies[0].acknowledgment, 5001);
        c
    }

    #[test]
    fn data_is_segmented_by_mss_and_window_and_released_by_acks() {
        let mut c = established();
        c.send(&[7; 2500]).unwrap();
        let sent = c.poll(20).unwrap();
        // MSS 1000 and window 4096: three segments.
        assert_eq!(
            sent.iter().map(|s| s.payload.len()).collect::<Vec<_>>(),
            [1000, 1000, 500]
        );
        assert_eq!(sent[1].sequence, 2001);
        c.receive(incoming(5001, 2001, ACK, &[]), 30).unwrap();
        assert_eq!(c.outgoing.len(), 1500);
        c.receive(incoming(5001, 3501, ACK, &[]), 40).unwrap();
        assert!(c.drained());
        assert_eq!(c.retransmit_at, None);
    }

    #[test]
    fn a_lost_segment_is_resent_after_the_timeout_with_backoff() {
        let mut c = established();
        c.send(b"hello").unwrap();
        let first = c.poll(0).unwrap();
        assert_eq!(first.len(), 1);
        assert!(c.poll(INITIAL_RTO_US - 1).unwrap().is_empty());
        let again = c.poll(INITIAL_RTO_US).unwrap();
        assert_eq!(again, first);
        assert_eq!(c.retransmit_at, Some(INITIAL_RTO_US + 2 * INITIAL_RTO_US));
        let mut now = INITIAL_RTO_US;
        let mut failed = None;
        for _ in 0..10 {
            now += MAX_RTO_US;
            if let Err(error) = c.poll(now) {
                failed = Some(error);
                break;
            }
        }
        assert_eq!(failed, Some(NetError::Timeout("TCP retransmission")));
        assert_eq!(c.state, State::Closed);
    }

    #[test]
    fn in_order_data_and_fin_are_delivered_and_others_reacknowledged() {
        let mut c = established();
        let r = c
            .receive(incoming(5001, 1001, ACK | PSH, b"abc"), 1)
            .unwrap();
        assert_eq!(r[0].acknowledgment, 5004);
        // Out of order: dropped, acknowledged at the expected sequence.
        let r = c.receive(incoming(5010, 1001, ACK, b"zzz"), 2).unwrap();
        assert_eq!(r[0].acknowledgment, 5004);
        // A retransmitted old segment is acknowledged again, not duplicated.
        c.receive(incoming(5001, 1001, ACK, b"abc"), 3).unwrap();
        let r = c
            .receive(incoming(5004, 1001, ACK | FIN, b"de"), 4)
            .unwrap();
        assert_eq!(r[0].acknowledgment, 5007);
        assert_eq!(c.received, b"abcde");
        assert!(c.peer_closed);
        c.close();
        let fin = c.poll(5).unwrap();
        assert_eq!(fin[0].flags, FIN | ACK);
        assert_eq!(fin[0].sequence, 1001);
        c.receive(incoming(5007, 1002, ACK, &[]), 6).unwrap();
        assert_eq!(c.state, State::Closed);
        assert!(c.drained());
    }

    #[test]
    fn resets_refuse_or_end_the_connection() {
        let (mut c, _) = Connection::open(1, 0);
        // A RST without an acceptable ACK is ignored in SYN-SENT.
        assert!(
            c.receive(incoming(0, 9, RST | ACK, &[]), 0)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            c.receive(incoming(0, 2, RST | ACK, &[]), 0),
            Err(NetError::Refused)
        );
        let mut c = established();
        assert!(
            c.receive(incoming(9999, 0, RST, &[]), 0)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            c.receive(incoming(5001, 0, RST, &[]), 0),
            Err(NetError::Reset)
        );
        assert!(c.send(b"x").is_err());
    }

    #[test]
    fn syns_are_retried_until_the_connection_times_out() {
        let (mut c, syn) = Connection::open(1, 0);
        let mut now = 0;
        let mut retries = 0;
        let error = loop {
            now += MAX_RTO_US;
            match c.poll(now) {
                Ok(again) => {
                    assert_eq!(again, core::slice::from_ref(&syn));
                    retries += 1;
                }
                Err(error) => break error,
            }
        };
        assert_eq!(retries, MAX_RETRIES);
        assert_eq!(error, NetError::Timeout("TCP connection"));
    }
}
