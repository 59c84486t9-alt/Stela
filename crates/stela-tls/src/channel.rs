//! Bounded no_std Rustls record pump; the caller owns real TCP backpressure.
use alloc::{sync::Arc, vec, vec::Vec};
use rustls::{
    ClientConfig,
    client::UnbufferedClientConnection,
    pki_types::ServerName,
    unbuffered::{ConnectionState, EncodeError, EncryptError},
};
use zeroize::Zeroize;
const BUFFER_LIMIT: usize = 64 * 1024;
const PLAIN_RECORD: usize = 16 * 1024;
#[derive(Debug)]
pub enum ChannelError {
    Tls(rustls::Error),
    Encode(EncodeError),
    Encrypt(EncryptError),
    Capacity { required: usize, maximum: usize },
    Truncated,
    TimeUnavailable,
    State,
    Consumption,
}
#[derive(Debug)]
pub enum Progress {
    Pending,
    NeedRead,
    NeedWrite,
    Ready,
    Accepted(usize),
    Received(Vec<u8>),
    PeerClosed,
    Closed,
}
pub struct Channel {
    connection: UnbufferedClientConnection,
    time: Arc<dyn rustls::time_provider::TimeProvider>,
    failed: bool,
    incoming: Vec<u8>,
    outgoing: Vec<u8>,
    sent: usize,
    encoded: bool,
    transmitted: bool,
    eof: bool,
    peer_closed: bool,
    close_requested: bool,
    local_closed: bool,
}
impl Channel {
    pub fn new(config: Arc<ClientConfig>, name: ServerName<'static>) -> Result<Self, ChannelError> {
        let time = config.time_provider.clone();
        if time.current_time().is_none() {
            return Err(ChannelError::TimeUnavailable);
        }
        Ok(Self {
            time,
            failed: false,
            connection: UnbufferedClientConnection::new(config, name).map_err(ChannelError::Tls)?,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            sent: 0,
            encoded: false,
            transmitted: false,
            eof: false,
            peer_closed: false,
            close_requested: false,
            local_closed: false,
        })
    }
    pub fn input_capacity(&self) -> usize {
        BUFFER_LIMIT - self.incoming.len()
    }
    pub fn feed(&mut self, input: &[u8], eof: bool) -> Result<(), ChannelError> {
        let required =
            self.incoming
                .len()
                .checked_add(input.len())
                .ok_or(ChannelError::Capacity {
                    required: usize::MAX,
                    maximum: BUFFER_LIMIT,
                })?;
        if required > BUFFER_LIMIT {
            return Err(ChannelError::Capacity {
                required,
                maximum: BUFFER_LIMIT,
            });
        }
        self.incoming.extend_from_slice(input);
        self.eof |= eof;
        Ok(())
    }
    pub fn output(&self) -> &[u8] {
        &self.outgoing[self.sent..]
    }
    pub fn consume_output(&mut self, bytes: usize) -> Result<(), ChannelError> {
        if bytes > self.outgoing.len() - self.sent {
            return Err(ChannelError::Consumption);
        }
        self.sent += bytes;
        if self.sent == self.outgoing.len() {
            self.outgoing.clear();
            self.sent = 0;
            if self.encoded {
                self.transmitted = true;
                self.encoded = false;
            }
        }
        Ok(())
    }
    pub fn request_close(&mut self) {
        self.close_requested = true;
    }
    pub fn protocol_version(&self) -> Option<rustls::ProtocolVersion> {
        self.connection.protocol_version()
    }
    /// Process a bounded amount of protocol work. Application bytes are accepted
    /// only in WriteTraffic, after ordinary chain/name/time verification. Early
    /// data is never enabled. The caller consumes Accepted(n) bytes exactly once.
    pub fn advance(&mut self, application: &[u8]) -> Result<Progress, ChannelError> {
        if self.failed || self.time.current_time().is_none() {
            self.failed = true;
            self.incoming.zeroize();
            self.outgoing.zeroize();
            self.sent = 0;
            return Err(ChannelError::TimeUnavailable);
        }
        if !self.output().is_empty() {
            return Ok(Progress::NeedWrite);
        }
        if self.peer_closed && self.local_closed {
            return Ok(Progress::Closed);
        }
        for _ in 0..128 {
            let status = self.connection.process_tls_records(&mut self.incoming);
            let mut discard = status.discard;
            let progress = match status.state.map_err(ChannelError::Tls)? {
                ConnectionState::EncodeTlsData(mut encoder) => {
                    let mut bytes = vec![0; 4096];
                    let length = match encoder.encode(&mut bytes) {
                        Ok(length) => length,
                        Err(EncodeError::InsufficientSize(size)) => {
                            if size.required_size > BUFFER_LIMIT {
                                return Err(ChannelError::Capacity {
                                    required: size.required_size,
                                    maximum: BUFFER_LIMIT,
                                });
                            }
                            bytes.resize(size.required_size, 0);
                            encoder.encode(&mut bytes).map_err(ChannelError::Encode)?
                        }
                        Err(error) => return Err(ChannelError::Encode(error)),
                    };
                    bytes.truncate(length);
                    self.outgoing = bytes;
                    self.encoded = true;
                    Some(Progress::NeedWrite)
                }
                ConnectionState::TransmitTlsData(transmitter) => {
                    if !self.transmitted {
                        return Err(ChannelError::State);
                    }
                    transmitter.done();
                    self.transmitted = false;
                    None
                }
                ConnectionState::ReadTraffic(mut traffic) => match traffic.next_record() {
                    Some(record) => {
                        let record = record.map_err(ChannelError::Tls)?;
                        discard += record.discard;
                        Some(Progress::Received(record.payload.to_vec()))
                    }
                    None => None,
                },
                ConnectionState::WriteTraffic(mut traffic) => {
                    if self.eof && !self.peer_closed {
                        return Err(ChannelError::Truncated);
                    }
                    if (self.close_requested || self.peer_closed) && !self.local_closed {
                        let mut bytes = vec![0; 512];
                        let length = traffic
                            .queue_close_notify(&mut bytes)
                            .map_err(ChannelError::Encrypt)?;
                        bytes.truncate(length);
                        self.outgoing = bytes;
                        self.encoded = false;
                        self.local_closed = true;
                        Some(Progress::NeedWrite)
                    } else if self.local_closed {
                        Some(Progress::NeedRead)
                    } else if application.is_empty() {
                        Some(Progress::Ready)
                    } else {
                        let count = application.len().min(PLAIN_RECORD);
                        let mut bytes = vec![0; PLAIN_RECORD + 2048];
                        let length = traffic
                            .encrypt(&application[..count], &mut bytes)
                            .map_err(ChannelError::Encrypt)?;
                        bytes.truncate(length);
                        self.outgoing = bytes;
                        self.encoded = false;
                        Some(Progress::Accepted(count))
                    }
                }
                ConnectionState::BlockedHandshake => {
                    if self.eof {
                        return Err(ChannelError::Truncated);
                    }
                    Some(Progress::NeedRead)
                }
                ConnectionState::PeerClosed => {
                    self.peer_closed = true;
                    Some(Progress::PeerClosed)
                }
                ConnectionState::Closed => {
                    self.peer_closed = true;
                    self.local_closed = true;
                    Some(Progress::Closed)
                }
                _ => return Err(ChannelError::State),
            };
            if discard > self.incoming.len() {
                return Err(ChannelError::State);
            }
            self.incoming.drain(..discard);
            if let Some(progress) = progress {
                return Ok(progress);
            }
        }
        // Yield without inventing protocol success. The next call resumes the
        // same owned Rustls state and buffers; this bound cannot drop a record.
        Ok(Progress::Pending)
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        self.incoming.zeroize();
        self.outgoing.zeroize();
    }
}
