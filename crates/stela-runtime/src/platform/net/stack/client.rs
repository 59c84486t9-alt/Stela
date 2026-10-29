//! URL-aware request/redirect ownership over plain or authenticated TLS sockets.
use super::*;
use alloc::{boxed::Box, sync::Arc};
use core::fmt;
use stela_tls::ClientConfig;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsUnavailable {
    CorrelatedClock,
    Entropy,
    Trust,
}
impl fmt::Display for TlsUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CorrelatedClock => "a qualified continuous UTC-correlated clock is unavailable",
            Self::Entropy => "owned secure entropy is unavailable",
            Self::Trust => "the certificate trust store is unavailable",
        })
    }
}
impl core::error::Error for TlsUnavailable {}

pub struct HttpRequest(Request);
enum Request {
    Range {
        start: u64,
        end: u64,
        etag: Option<String>,
    },
    Post {
        headers: Vec<(String, String)>,
        content_type: String,
        body: Zeroizing<Vec<u8>>,
    },
}
impl HttpRequest {
    pub fn range(start: u64, end: u64, etag: Option<&str>) -> Self {
        Self(Request::Range {
            start,
            end,
            etag: etag.map(String::from),
        })
    }
    pub fn post(headers: &[(&str, &str)], content_type: &str, body: &[u8]) -> Self {
        Self(Request::Post {
            headers: headers
                .iter()
                .map(|(k, v)| (String::from(*k), String::from(*v)))
                .collect(),
            content_type: String::from(content_type),
            body: Zeroizing::new(body.to_vec()),
        })
    }
    fn method(&self) -> http::Method {
        match &self.0 {
            Request::Range { .. } => http::Method::Get,
            Request::Post { .. } => http::Method::Post,
        }
    }
    fn encode(&self, url: http::Url<'_>) -> Result<Vec<u8>, NetError> {
        match &self.0 {
            Request::Range { start, end, etag } => {
                http::get_range(url.authority, url.target, *start, *end, etag.as_deref())
            }
            Request::Post {
                headers,
                content_type,
                body,
            } => {
                let fields: Vec<_> = headers
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect();
                http::post(url.authority, url.target, &fields, content_type, body)
            }
        }
    }
}
impl Drop for HttpRequest {
    fn drop(&mut self) {
        match &mut self.0 {
            Request::Range { etag, .. } => {
                if let Some(value) = etag {
                    value.zeroize();
                }
            }
            Request::Post { headers, body, .. } => {
                for (_, value) in headers {
                    value.zeroize();
                }
                body.zeroize();
            }
        }
    }
}

enum Connection {
    Plain(Transfer),
    Secure(Box<SecureTransfer>),
}

pub struct HttpTransfer {
    connection: Option<Connection>,
    redirects: http::Redirects,
    request: Option<HttpRequest>,
    security: Result<Arc<ClientConfig>, TlsUnavailable>,
    header: Option<Vec<u8>>,
    buffer: usize,
    done: bool,
    failed: bool,
}
impl HttpTransfer {
    pub fn url(&self) -> &str {
        self.redirects.current().as_str()
    }
}

impl<L: Link, C: Clock> Stack<L, C> {
    /// The missing native capability is explicit. A plain initial URL can still
    /// configure/transfer, but redirecting it to HTTPS never falls back to HTTP.
    pub fn open_http(
        &mut self,
        url: &str,
        request: HttpRequest,
        buffer: usize,
        security: Result<Arc<ClientConfig>, TlsUnavailable>,
    ) -> Result<HttpTransfer, NetError> {
        let redirects = http::Redirects::new(url, request.method()).map_err(NetError::Url)?;
        let connection = self.connect_http(redirects.current(), &request, buffer, &security)?;
        Ok(HttpTransfer {
            connection: Some(connection),
            redirects,
            request: Some(request),
            security,
            header: Some(Vec::new()),
            buffer,
            done: false,
            failed: false,
        })
    }
    fn connect_http(
        &mut self,
        url: http::Url<'_>,
        request: &HttpRequest,
        buffer: usize,
        security: &Result<Arc<ClientConfig>, TlsUnavailable>,
    ) -> Result<Connection, NetError> {
        match url.scheme {
            http::Scheme::Http => self
                .open(url.authority, request.encode(url)?, buffer)
                .map(Connection::Plain),
            http::Scheme::Https => {
                let config = security
                    .as_ref()
                    .map_err(|e| NetError::TlsUnavailable(*e))?
                    .clone();
                self.open_tls(url, request.encode(url)?, buffer, config)
                    .map(|tls| Connection::Secure(Box::new(tls)))
            }
        }
    }
    /// Deliver only a final accepted head/body. Redirect bodies are discarded;
    /// every error retires the socket and request secrets before returning.
    pub fn read_http(
        &mut self,
        transfer: &mut HttpTransfer,
        mut take: impl FnMut(&[u8], bool) -> Result<bool, NetError>,
    ) -> Result<bool, NetError> {
        if transfer.failed {
            return Err(NetError::Invalid("HTTP transfer already failed"));
        }
        if transfer.done {
            return Ok(true);
        }
        let result = self.read_http_once(transfer, &mut take);
        if result.is_err() || matches!(result, Ok(true)) {
            if let Some(connection) = transfer.connection.take() {
                self.close_connection(connection);
            }
            transfer.request.take();
            transfer.header.take();
            transfer.failed = result.is_err();
            transfer.done = matches!(result, Ok(true));
        }
        result
    }
    fn read_http_once(
        &mut self,
        transfer: &mut HttpTransfer,
        take: &mut impl FnMut(&[u8], bool) -> Result<bool, NetError>,
    ) -> Result<bool, NetError> {
        let mut redirect = None;
        let limit = transfer.header.as_ref().map_or(usize::MAX, |head| {
            http::MAX_HEADER.saturating_sub(head.len())
        });
        if limit == 0 {
            return Err(NetError::Http(String::from("response header too large")));
        }
        let mut receive = |bytes: &[u8], closed: bool| -> Result<bool, NetError> {
            if let Some(header) = &mut transfer.header {
                header.extend_from_slice(bytes);
                let Some(head) = http::response_head(header, closed)? else {
                    return Ok(false);
                };
                match head.status {
                    407 => return Err(NetError::ProxyAuthentication),
                    511 => return Err(NetError::NetworkAuthentication),
                    301 | 302 | 303 | 307 | 308 => {
                        redirect = Some((head.status, head.location));
                        return Ok(true);
                    }
                    200..=299 => {}
                    other => return Err(NetError::Status(other)),
                }
                let bytes = transfer.header.take().expect("complete accepted head");
                take(&bytes, closed)
            } else {
                take(bytes, closed)
            }
        };
        let done = match transfer
            .connection
            .as_mut()
            .ok_or(NetError::Invalid("HTTP transfer has no socket"))?
        {
            Connection::Plain(tcp) => self.read_bounded(tcp, limit, &mut receive)?,
            Connection::Secure(tls) => self.read_tls(tls, &mut receive)?,
        };
        if let Some((status, location)) = redirect {
            transfer
                .redirects
                .follow(status, location.as_deref())
                .map_err(NetError::Redirect)?;
            if let Some(connection) = transfer.connection.take() {
                self.close_connection(connection);
            }
            transfer.connection = Some(self.connect_http(
                transfer.redirects.current(),
                transfer.request.as_ref().expect("live request"),
                transfer.buffer,
                &transfer.security,
            )?);
            transfer.header = Some(Vec::new());
            Ok(false)
        } else {
            Ok(done)
        }
    }
    fn close_connection(&mut self, connection: Connection) {
        match connection {
            Connection::Plain(tcp) => self.close(tcp),
            Connection::Secure(tls) => self.close_tls(*tls),
        }
    }
    pub fn close_http(&mut self, mut transfer: HttpTransfer) {
        if let Some(connection) = transfer.connection.take() {
            self.close_connection(connection);
        }
    }
    pub fn post_url(
        &mut self,
        url: &str,
        headers: &[(&str, &str)],
        content_type: &str,
        body: &[u8],
        security: Result<Arc<ClientConfig>, TlsUnavailable>,
    ) -> Result<Vec<u8>, NetError> {
        let deadline = self.now().saturating_add(POST_WAIT_US);
        let mut transfer = self.open_http(
            url,
            HttpRequest::post(headers, content_type, body),
            POST_BUFFER,
            security,
        )?;
        let mut reply = Zeroizing::new(Vec::new());
        let mut response = None;
        let result = loop {
            match self.read_http(&mut transfer, |bytes, closed| {
                reply.extend_from_slice(bytes);
                response = http::response(&reply, closed)?;
                Ok(response.is_some())
            }) {
                Ok(true) => break Ok(()),
                Ok(false) if self.now() >= deadline => {
                    break Err(NetError::Timeout("HTTP request"));
                }
                Ok(false) => self.wait_until(deadline),
                Err(error) => break Err(error),
            }
        };
        self.close_http(transfer);
        result?;
        Ok(response.expect("completed response").body)
    }
}
