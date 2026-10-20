//! restored's side of the mux, as the host's `driver::Ports`: the control
//! service on 62078 and one listening socket per DataPort the guest names.
//! Reads and writes are fragmented and sometimes backpressured, from a
//! seeded generator, so framing never relies on whole-message I/O.
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io::Cursor,
    task::Poll,
};
use stela_runtime::restore::{Error, Result, driver::Ports, session::PORT};

pub const CONTROL: u16 = PORT;

#[derive(Default)]
pub struct Socket {
    pub port: u16,
    to_host: VecDeque<u8>,
    pub from_host: Vec<u8>,
    /// Bytes of `from_host` the guest has consumed.
    pub read: usize,
    pub guest_closed: bool,
    pub host_closed: bool,
}

pub struct Wire {
    sockets: BTreeMap<u32, Socket>,
    listening: BTreeSet<u16>,
    next: u32,
    state: u64,
    /// Bytes moved in either direction, for stall detection.
    pub moved: u64,
}

impl Wire {
    pub fn new(seed: u64) -> Self {
        Self {
            sockets: BTreeMap::new(),
            listening: BTreeSet::new(),
            next: 1,
            state: seed | 1,
            moved: 0,
        }
    }
    fn random(&mut self) -> u64 {
        // xorshift64*
        self.state ^= self.state >> 12;
        self.state ^= self.state << 25;
        self.state ^= self.state >> 27;
        self.state.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    /// A fragment size: usually large, sometimes a few bytes.
    fn chunk(&mut self, available: usize) -> usize {
        let r = self.random();
        let limit = if r.is_multiple_of(5) {
            1 + (r >> 8) as usize % 13
        } else {
            1 + (r >> 8) as usize % (256 * 1024)
        };
        available.min(limit)
    }
    pub fn listen(&mut self, port: u16) {
        self.listening.insert(port);
    }
    /// The newest socket the host opened to `port`.
    pub fn socket(&mut self, port: u16) -> Option<&mut Socket> {
        self.sockets.values_mut().rev().find(|s| s.port == port)
    }
    pub fn send(&mut self, port: u16, bytes: &[u8]) -> bool {
        match self.socket(port) {
            Some(s) if !s.guest_closed => {
                s.to_host.extend(bytes);
                true
            }
            _ => false,
        }
    }
    /// Send `value` as restored frames a control message: a big-endian
    /// length and a binary plist.
    pub fn send_frame(&mut self, port: u16, value: &plist::Value) -> anyhow::Result<()> {
        let mut body = Vec::new();
        value.to_writer_binary(&mut body)?;
        let mut bytes = (body.len() as u32).to_be_bytes().to_vec();
        bytes.extend(body);
        anyhow::ensure!(self.send(port, &bytes), "no open socket on port {port}");
        Ok(())
    }
    /// The next whole frame the host wrote to `port`, decoded independently
    /// of the host's encoder.
    pub fn frame(&mut self, port: u16) -> anyhow::Result<Option<plist::Value>> {
        let Some(s) = self.socket(port) else {
            return Ok(None);
        };
        let pending = &s.from_host[s.read..];
        if pending.len() < 4 {
            return Ok(None);
        }
        let n = u32::from_be_bytes(pending[..4].try_into().unwrap()) as usize;
        if pending.len() < 4 + n {
            return Ok(None);
        }
        let value = plist::Value::from_reader(Cursor::new(&pending[4..4 + n]))
            .map_err(|e| anyhow::anyhow!("host frame on port {port} is not a plist: {e}"))?;
        s.read += 4 + n;
        Ok(Some(value))
    }
    /// Consume up to `n` raw bytes the host wrote to `port`.
    pub fn take(&mut self, port: u16, n: usize) -> Vec<u8> {
        let Some(s) = self.socket(port) else {
            return Vec::new();
        };
        let end = s.read.saturating_add(n).min(s.from_host.len());
        let out = s.from_host[s.read..end].to_vec();
        s.read = end;
        // Keep memory bounded on long streams.
        if s.read > 64 << 20 {
            s.from_host.drain(..s.read);
            s.read = 0;
        }
        out
    }
    pub fn close(&mut self, port: u16) {
        if let Some(s) = self.socket(port) {
            s.guest_closed = true;
        }
    }
}

impl Ports for Wire {
    type Handle = u32;
    fn open(&mut self, port: u16) -> Poll<Result<u32>> {
        if port != CONTROL && !self.listening.remove(&port) {
            return Poll::Pending;
        }
        let id = self.next;
        self.next += 1;
        self.sockets.insert(
            id,
            Socket {
                port,
                ..Socket::default()
            },
        );
        Poll::Ready(Ok(id))
    }
    fn read(&mut self, h: u32, bytes: &mut [u8]) -> Poll<Result<usize>> {
        let available = match self.sockets.get(&h) {
            None => return Poll::Ready(Err(Error::Invalid("read of an unknown socket"))),
            Some(s) if s.host_closed => {
                return Poll::Ready(Err(Error::Invalid("read after the host closed")));
            }
            Some(s) if s.to_host.is_empty() => {
                return if s.guest_closed {
                    Poll::Ready(Ok(0))
                } else {
                    Poll::Pending
                };
            }
            Some(s) => s.to_host.len(),
        };
        let n = self.chunk(available.min(bytes.len()));
        let s = self.sockets.get_mut(&h).unwrap();
        for (b, v) in bytes.iter_mut().zip(s.to_host.drain(..n)) {
            *b = v;
        }
        self.moved += n as u64;
        Poll::Ready(Ok(n))
    }
    fn write(&mut self, h: u32, bytes: &[u8]) -> Poll<Result<usize>> {
        match self.sockets.get(&h) {
            None => return Poll::Ready(Err(Error::Invalid("write to an unknown socket"))),
            Some(s) if s.host_closed => {
                return Poll::Ready(Err(Error::Invalid("write after the host closed")));
            }
            Some(s) if s.guest_closed => {
                return Poll::Ready(Err(Error::Transport("restored closed the socket".into())));
            }
            Some(_) => {}
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.random().is_multiple_of(9) {
            return Poll::Pending;
        }
        let n = self.chunk(bytes.len());
        self.sockets
            .get_mut(&h)
            .unwrap()
            .from_host
            .extend_from_slice(&bytes[..n]);
        self.moved += n as u64;
        Poll::Ready(Ok(n))
    }
    fn close(&mut self, h: u32) -> Poll<Result<()>> {
        match self.sockets.get_mut(&h) {
            Some(s) if !s.host_closed => {
                s.host_closed = true;
                Poll::Ready(Ok(()))
            }
            _ => Poll::Ready(Err(Error::Invalid("close of an unknown or closed socket"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_cross_fragmented_reads_and_unlisted_ports_stay_pending() {
        let mut wire = Wire::new(7);
        assert!(matches!(wire.open(5000), Poll::Pending));
        let Poll::Ready(Ok(control)) = wire.open(CONTROL) else {
            panic!()
        };
        let mut dict = plist::Dictionary::new();
        dict.insert("Request".into(), "QueryType".into());
        wire.send_frame(CONTROL, &dict.clone().into()).unwrap();
        let mut got = Vec::new();
        let mut buffer = [0; 64];
        while let Poll::Ready(Ok(n)) = wire.read(control, &mut buffer) {
            got.extend_from_slice(&buffer[..n]);
        }
        // The host echoes the bytes back; the guest decodes them whole.
        let mut at = 0;
        while at < got.len() {
            if let Poll::Ready(Ok(n)) = wire.write(control, &got[at..]) {
                at += n;
            }
        }
        assert_eq!(wire.frame(CONTROL).unwrap(), Some(dict.into()));
        wire.listen(5000);
        assert!(matches!(wire.open(5000), Poll::Ready(Ok(_))));
        assert!(matches!(wire.open(5000), Poll::Pending));
    }
}
