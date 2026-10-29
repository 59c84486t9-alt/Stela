//! TLS record transport over the same owned TCP socket and partial-write path.
use super::*;
use alloc::sync::Arc;
use stela_tls::{
    ClientConfig, ServerName,
    channel::{Channel, Progress},
};
use zeroize::Zeroizing;

/// One TLS connection and its caller-owned fixed request. The TLS engine never
/// hands application bytes out before certificate/name/time verification.
pub struct SecureTransfer {
    tcp: Transfer,
    channel: Channel,
    request: Zeroizing<Vec<u8>>,
    sent: usize,
    idle_at: u64,
}

fn tls_error(error: stela_tls::channel::ChannelError) -> NetError {
    match error {
        stela_tls::channel::ChannelError::Truncated => NetError::Truncated("TLS record stream"),
        other => NetError::Tls(alloc::format!("{other:?}")),
    }
}

impl<L: Link, C: Clock> Stack<L, C> {
    /// Validate TLS inputs before opening TCP or publishing a ClientHello. The
    /// config retains its genuine provider and time source; native callers must
    /// obtain those from the admitted boot owner, never captured clock metadata.
    pub fn open_tls(
        &mut self,
        destination: http::Url<'_>,
        request: Vec<u8>,
        buffer: usize,
        config: Arc<ClientConfig>,
    ) -> Result<SecureTransfer, NetError> {
        let request = Zeroizing::new(request);
        if destination.scheme != http::Scheme::Https {
            return Err(NetError::Invalid("TLS requires an https destination"));
        }
        let peer = ServerName::try_from(String::from(destination.host))
            .map_err(|_| NetError::Invalid("TLS server name"))?;
        let channel = Channel::new(config, peer).map_err(tls_error)?;
        let tcp = self.open_raw(destination.host, destination.port, buffer)?;
        Ok(SecureTransfer {
            tcp,
            channel,
            request,
            sent: 0,
            idle_at: self.now().saturating_add(IDLE_US),
        })
    }

    /// Poll one bounded TLS/TCP turn. Output consumption follows actual TCP
    /// acceptance, and input never consumes more than the TLS record capacity.
    /// Errors leave ownership with the caller, which must close the transfer.
    pub fn read_tls(
        &mut self,
        transfer: &mut SecureTransfer,
        mut take: impl FnMut(&[u8], bool) -> Result<bool, NetError>,
    ) -> Result<bool, NetError> {
        if self.now() >= transfer.idle_at {
            return Err(NetError::Timeout("TLS transfer"));
        }
        for turn in 0..2 {
            for _ in 0..128 {
                match transfer
                    .channel
                    .advance(&transfer.request[transfer.sent..])
                    .map_err(tls_error)?
                {
                    Progress::Received(bytes) => {
                        transfer.idle_at = self.now().saturating_add(IDLE_US);
                        if take(&bytes, false)? {
                            return Ok(true);
                        }
                    }
                    Progress::Accepted(count) => {
                        transfer.sent = transfer
                            .sent
                            .checked_add(count)
                            .filter(|n| *n <= transfer.request.len())
                            .ok_or(NetError::Invalid("TLS request consumption"))?;
                    }
                    Progress::NeedWrite | Progress::Pending => {}
                    Progress::NeedRead | Progress::Ready => break,
                    Progress::PeerClosed | Progress::Closed => return take(&[], true),
                }
                if !transfer.channel.output().is_empty() {
                    let count = self.write(&mut transfer.tcp, transfer.channel.output())?;
                    transfer.channel.consume_output(count).map_err(tls_error)?;
                    if count == 0 {
                        break;
                    }
                    transfer.idle_at = self.now().saturating_add(IDLE_US);
                    if !transfer.channel.output().is_empty() {
                        break;
                    }
                }
            }
            if turn == 0 {
                let capacity = transfer.channel.input_capacity();
                self.read_bounded(&mut transfer.tcp, capacity, |bytes, eof| {
                    transfer.channel.feed(bytes, eof).map_err(tls_error)?;
                    Ok(false)
                })?;
            }
        }
        Ok(false)
    }

    /// Drop the TLS state/secret buffers and retire exactly its TCP socket.
    pub fn close_tls(&mut self, transfer: SecureTransfer) {
        self.close(transfer.tcp);
    }
}
