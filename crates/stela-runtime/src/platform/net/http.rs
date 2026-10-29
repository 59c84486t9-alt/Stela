//! HTTP/1.1 requests and responses (RFC 9112): a POST with a
//! Content-Length body, and a GET of one byte range (RFC 9110 14), both
//! with `Connection: close`. httparse reads response heads; a POST's
//! response is framed by Content-Length, chunked transfer coding or the end
//! of the connection, and a range's by Content-Length alone. Interim 1xx
//! responses are skipped; any other non-2xx status is an error. Redirects
//! are exposed by `response_head` for explicit request policy; the simple
//! response reader and unsupported transfer codings refuse them.
mod url;
pub use url::{Scheme, Url, UrlError};

use super::NetError;
use alloc::{format, string::String, vec::Vec};

/// The largest response header block and POST response body accepted.
pub const MAX_HEADER: usize = 64 * 1024;
pub const MAX_BODY: usize = 8 * 1024 * 1024;
const MAX_FIELDS: usize = 64;

fn http_error(why: &str) -> NetError {
    NetError::Http(String::from(why))
}

/// A request head: its line and `headers`, refusing anything that could
/// inject a field.
fn request(
    method: &str,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<String, NetError> {
    let token = |text: &str| !text.is_empty() && text.bytes().all(|b| b > 0x20 && b != 0x7f);
    let value = |text: &str| {
        text.bytes()
            .all(|b| b == b' ' || b == b'\t' || (b > 0x20 && b != 0x7f))
    };
    if !token(host) || !path.starts_with('/') || !token(path) {
        return Err(NetError::Invalid("HTTP host or path"));
    }
    if headers
        .iter()
        .any(|(name, text)| !token(name) || name.contains(':') || !value(text))
    {
        return Err(NetError::Invalid("HTTP header"));
    }
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    for (name, text) in headers {
        head.push_str(&format!("{name}: {text}\r\n"));
    }
    head.push_str("Connection: close\r\n\r\n");
    Ok(head)
}

/// A complete POST request.
pub fn post(
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
    content_type: &str,
    body: &[u8],
) -> Result<Vec<u8>, NetError> {
    let length = format!("{}", body.len());
    let mut fields = Vec::from([("Content-Type", content_type), ("Content-Length", &*length)]);
    fields.extend_from_slice(headers);
    let mut bytes = request("POST", host, path, &fields)?.into_bytes();
    bytes.extend_from_slice(body);
    Ok(bytes)
}

/// A GET of bytes `start..=end` of `path`. With `etag`, the server sends
/// the range only while the object still has that entity tag, and the whole
/// object otherwise (RFC 9110 13.1.5), which [`Ranged`] refuses.
pub fn get_range(
    host: &str,
    path: &str,
    start: u64,
    end: u64,
    etag: Option<&str>,
) -> Result<Vec<u8>, NetError> {
    if end < start {
        return Err(NetError::Invalid("HTTP range"));
    }
    let range = format!("bytes={start}-{end}");
    let mut fields = Vec::from([("Range", &*range)]);
    fields.extend(etag.map(|etag| ("If-Range", etag)));
    Ok(request("GET", host, path, &fields)?.into_bytes())
}

/// The fields of a final response head that frame its body and redirection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub status: u16,
    pub length: Option<u64>,
    pub chunked: bool,
    /// Content-Range: the first and last byte and the whole size.
    pub range: Option<(u64, u64, u64)>,
    /// Bytes before the body, interim responses included.
    pub size: usize,
    pub location: Option<String>,
    pub etag: Option<String>,
}

/// `bytes a-b/size` (RFC 9110 14.4).
fn content_range(value: &str) -> Option<(u64, u64, u64)> {
    let (span, size) = value.strip_prefix("bytes ")?.split_once('/')?;
    let (first, last) = span.split_once('-')?;
    let (first, last, size) = (first.parse().ok()?, last.parse().ok()?, size.parse().ok()?);
    (first <= last && last < size).then_some((first, last, size))
}

/// The final response head in `bytes`, once complete. A non-2xx status is
/// an error. `closed` says the server ended the connection.
pub fn head(bytes: &[u8], closed: bool) -> Result<Option<Head>, NetError> {
    let parsed = response_head(bytes, closed)?;
    if let Some(head) = &parsed
        && !(200..300).contains(&head.status)
    {
        return Err(NetError::Status(head.status));
    }
    Ok(parsed)
}

/// Parse a final head with Location for the request owner's redirect policy.
/// Every interim head consumes the same bounded total header budget.
pub fn response_head(bytes: &[u8], closed: bool) -> Result<Option<Head>, NetError> {
    let mut start = 0;
    loop {
        let mut fields = [httparse::EMPTY_HEADER; MAX_FIELDS];
        let mut response = httparse::Response::new(&mut fields);
        let size = match response.parse(&bytes[start..]) {
            Ok(httparse::Status::Complete(size)) => size,
            Ok(httparse::Status::Partial) if bytes.len() > MAX_HEADER => {
                return Err(http_error("response header too large"));
            }
            Ok(httparse::Status::Partial) if closed => {
                return Err(http_error("connection closed inside the response header"));
            }
            Ok(httparse::Status::Partial) => return Ok(None),
            Err(error) => return Err(NetError::Http(format!("response header: {error}"))),
        };
        if start + size > MAX_HEADER {
            return Err(http_error("response header too large"));
        }
        let status = response.code.unwrap_or_default();
        if status == 101 {
            return Err(http_error("protocol switch is unsupported"));
        }
        if (100..200).contains(&status) {
            // An interim response has no body; the final one follows.
            start += size;
            continue;
        }
        let mut head = Head {
            status,
            length: None,
            chunked: false,
            range: None,
            size: start + size,
            location: None,
            etag: None,
        };
        for field in response.headers.iter() {
            let value = core::str::from_utf8(field.value)
                .map_err(|_| http_error("header field value is not text"))?
                .trim();
            if field.name.eq_ignore_ascii_case("content-length") {
                let length = value
                    .parse()
                    .map_err(|_| http_error("malformed Content-Length"))?;
                if head.length.is_some_and(|other| other != length) {
                    return Err(http_error("conflicting Content-Length"));
                }
                head.length = Some(length);
            } else if field.name.eq_ignore_ascii_case("transfer-encoding") {
                if head.chunked {
                    return Err(http_error("duplicate Transfer-Encoding"));
                }
                if !value.eq_ignore_ascii_case("chunked") {
                    return Err(NetError::Http(format!("transfer coding {value:?}")));
                }
                head.chunked = true;
            } else if field.name.eq_ignore_ascii_case("location") {
                if head.location.replace(String::from(value)).is_some() {
                    return Err(http_error("duplicate Location"));
                }
            } else if field.name.eq_ignore_ascii_case("etag") {
                if head.etag.replace(String::from(value)).is_some() {
                    return Err(http_error("duplicate ETag"));
                }
            } else if field.name.eq_ignore_ascii_case("content-range") {
                if head.range.is_some() {
                    return Err(http_error("duplicate Content-Range"));
                }
                head.range = Some(
                    content_range(value).ok_or_else(|| http_error("malformed Content-Range"))?,
                );
            }
        }
        if head.chunked && head.length.is_some() {
            return Err(http_error("Transfer-Encoding and Content-Length conflict"));
        }
        return Ok(Some(head));
    }
}

/// A complete response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// The response in `bytes`, once complete. `closed` says the server has
/// ended the connection, which completes a body without a length.
pub fn response(bytes: &[u8], closed: bool) -> Result<Option<Response>, NetError> {
    let Some(head) = head(bytes, closed)? else {
        return Ok(None);
    };
    let body = &bytes[head.size..];
    if body.len() > MAX_BODY {
        return Err(http_error("response body too large"));
    }
    let body = if head.chunked {
        match chunks(body)? {
            Some(body) => body,
            None if closed => return Err(http_error("connection closed inside a chunk")),
            None => return Ok(None),
        }
    } else if let Some(length) = head.length {
        if length > MAX_BODY as u64 {
            return Err(http_error("response body too large"));
        }
        let length = length as usize;
        if body.len() < length {
            return match closed {
                true => Err(http_error("connection closed before the body's end")),
                false => Ok(None),
            };
        }
        body[..length].to_vec()
    } else if closed {
        body.to_vec()
    } else {
        if body.len() > MAX_BODY {
            return Err(http_error("response body too large"));
        }
        return Ok(None);
    };
    Ok(Some(Response {
        status: head.status,
        body,
    }))
}

/// A chunked body (RFC 9112 7.1), once its last chunk and trailer arrive.
fn chunks(mut bytes: &[u8]) -> Result<Option<Vec<u8>>, NetError> {
    let mut body = Vec::new();
    loop {
        let (line, size) = match httparse::parse_chunk_size(bytes) {
            Ok(httparse::Status::Complete(parsed)) => parsed,
            Ok(httparse::Status::Partial) => return Ok(None),
            Err(_) => return Err(http_error("malformed chunk size")),
        };
        bytes = &bytes[line..];
        if size == 0 {
            // Trailer fields, if any, end with an empty line.
            let done = bytes.starts_with(b"\r\n") || bytes.windows(4).any(|w| w == b"\r\n\r\n");
            return Ok(done.then_some(body));
        }
        let size = usize::try_from(size)
            .ok()
            .filter(|size| body.len().checked_add(*size).is_some_and(|n| n <= MAX_BODY))
            .ok_or_else(|| http_error("response body too large"))?;
        if bytes.len() < size + 2 {
            return Ok(None);
        }
        if &bytes[size..size + 2] != b"\r\n" {
            return Err(http_error("chunk without its line end"));
        }
        body.extend_from_slice(&bytes[..size]);
        bytes = &bytes[size + 2..];
    }
}

/// A ranged GET's response as it arrives: the head is checked against the
/// requested range, then the body's bytes pass through in order.
#[derive(Debug)]
pub struct Ranged {
    start: u64,
    end: u64,
    /// Bytes of the head received so far, until it is complete.
    head: Option<Vec<u8>>,
    /// The resource's whole size, once the head named it.
    pub size: Option<u64>,
    /// Body bytes still due.
    pub left: u64,
    identity: Option<(String, u64)>,
    failed: bool,
}

impl Ranged {
    pub fn new(start: u64, end: u64) -> Self {
        Self {
            start,
            end,
            head: Some(Vec::new()),
            size: None,
            left: end
                .checked_sub(start)
                .and_then(|n| n.checked_add(1))
                .unwrap_or(0),
            identity: None,
            failed: start > end
                || end
                    .checked_sub(start)
                    .and_then(|n| n.checked_add(1))
                    .is_none(),
        }
    }

    /// Bind a resumed range to the exact strong validator and object length
    /// in its input receipt before any response body is handed to the caller.
    pub fn with_identity(start: u64, end: u64, etag: &str, bytes: u64) -> Result<Self, NetError> {
        let opaque = etag
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .ok_or_else(|| http_error("range needs a strong quoted ETag"))?;
        if opaque
            .bytes()
            .any(|b| b != 0x21 && !(0x23..=0x7e).contains(&b) && b < 0x80)
        {
            return Err(http_error("range ETag contains invalid bytes"));
        }
        if start > end || end >= bytes {
            return Err(NetError::Invalid("HTTP range identity extent"));
        }
        let mut range = Self::new(start, end);
        range.identity = Some((String::from(etag), bytes));
        Ok(range)
    }

    /// Takes `bytes` as they arrived, handing body bytes to `body`. Returns
    /// whether the range is complete. `closed` says the server ended the
    /// connection after them.
    pub fn feed(
        &mut self,
        bytes: &[u8],
        closed: bool,
        body: impl FnMut(&[u8]),
    ) -> Result<bool, NetError> {
        if self.failed {
            return Err(http_error("range already failed"));
        }
        let result = self.feed_once(bytes, closed, body);
        self.failed |= result.is_err();
        result
    }

    fn feed_once(
        &mut self,
        bytes: &[u8],
        closed: bool,
        mut body: impl FnMut(&[u8]),
    ) -> Result<bool, NetError> {
        let held;
        let mut data = bytes;
        if let Some(mut so_far) = self.head.take() {
            so_far.extend_from_slice(bytes);
            let Some(head) = head(&so_far, closed)? else {
                self.head = Some(so_far);
                return Ok(false);
            };
            if head.status != 206 {
                return Err(http_error("response is not a partial range"));
            }
            match head.range {
                Some((first, last, size))
                    if (first, last) == (self.start, self.end) && !head.chunked =>
                {
                    if let Some((etag, expected_size)) = &self.identity {
                        if head.etag.as_deref() != Some(etag.as_str()) {
                            return Err(http_error("range ETag changed or absent"));
                        }
                        if size != *expected_size {
                            return Err(http_error("range object length changed"));
                        }
                    }
                    self.size = Some(size)
                }
                _ => return Err(http_error("response is not the requested range")),
            }
            if head.length != Some(self.left) {
                return Err(http_error("range length differs from Content-Length"));
            }
            held = so_far.split_off(head.size);
            data = &held;
        }
        let take = data.len().min(self.left as usize);
        body(&data[..take]);
        self.left -= take as u64;
        if self.left > 0 && closed {
            return Err(http_error("connection closed before the range's end"));
        }
        Ok(self.left == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_frame_their_body_and_refuse_injection() {
        let bytes = post(
            "gs.apple.com",
            "/TSS/controller?action=2",
            &[("Cache-Control", "no-cache")],
            "text/xml; charset=\"utf-8\"",
            b"<plist/>",
        )
        .unwrap();
        let text = core::str::from_utf8(&bytes).unwrap();
        assert!(
            text.starts_with("POST /TSS/controller?action=2 HTTP/1.1\r\nHost: gs.apple.com\r\n")
        );
        assert!(text.contains("\r\nContent-Length: 8\r\n"));
        assert!(text.contains("\r\nConnection: close\r\n"));
        assert!(text.contains("\r\nCache-Control: no-cache\r\n"));
        assert!(text.ends_with("\r\n\r\n<plist/>"));
        assert!(post("a b", "/", &[], "x", b"").is_err());
        assert!(post("a", "x", &[], "x", b"").is_err());
        assert!(post("a", "/", &[("X", "a\r\nInjected: 1")], "x", b"").is_err());
        assert!(post("a", "/", &[("X:", "1")], "x", b"").is_err());
        let get = get_range(
            "updates-http.cdn-apple.com",
            "/a.ipsw",
            10,
            19,
            Some("\"e\""),
        )
        .unwrap();
        let get = core::str::from_utf8(&get).unwrap();
        assert!(get.starts_with("GET /a.ipsw HTTP/1.1\r\n"));
        assert!(get.contains("\r\nRange: bytes=10-19\r\nIf-Range: \"e\"\r\n"));
        assert!(get_range("a", "/", 2, 1, None).is_err());
    }

    #[test]
    fn responses_complete_by_length_chunks_or_close() {
        let fixed = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        for cut in 0..fixed.len() {
            assert_eq!(response(&fixed[..cut], false).unwrap(), None, "{cut}");
        }
        assert_eq!(
            response(fixed, false).unwrap().unwrap(),
            Response {
                status: 200,
                body: b"hello".to_vec()
            }
        );
        assert!(response(&fixed[..fixed.len() - 1], true).is_err());
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;x=y\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        for cut in 0..chunked.len() {
            assert_eq!(response(&chunked[..cut], false).unwrap(), None, "{cut}");
        }
        assert_eq!(
            response(chunked, false).unwrap().unwrap().body,
            b"hello world"
        );
        let open = b"HTTP/1.0 200 OK\r\nServer: x\r\n\r\nall of it";
        assert_eq!(response(open, false).unwrap(), None);
        assert_eq!(response(open, true).unwrap().unwrap().body, b"all of it");
        let interim =
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        assert_eq!(response(interim, false).unwrap().unwrap().body, b"ok");
    }

    #[test]
    fn errors_and_unsupported_framing_refuse() {
        assert_eq!(
            response(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
                false
            ),
            Err(NetError::Status(404))
        );
        assert_eq!(
            response(b"HTTP/1.1 301 Moved\r\nLocation: x\r\n\r\n", false),
            Err(NetError::Status(301))
        );
        assert!(response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n", false).is_err());
        assert!(
            response(
                b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
                false
            )
            .is_err()
        );
        assert!(response(b"SIP/2.0 200 OK\r\n\r\n", false).is_err());
        assert!(response(b"HTTP/1.1 200 OK\r\nbroken\r\n\r\n", false).is_err());
        assert!(
            response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXY",
                false
            )
            .is_err()
        );
    }

    #[test]
    fn a_range_passes_its_body_through_once_its_head_matches() {
        let reply = b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 10-19/100\r\nContent-Length: 10\r\n\r\n0123456789";
        // Any split of the reply gives the same body.
        for cut in 0..reply.len() {
            let mut ranged = Ranged::new(10, 19);
            let mut body = Vec::new();
            let first = ranged.feed(&reply[..cut], false, |b| body.extend_from_slice(b));
            assert!(!first.unwrap());
            let rest = ranged.feed(&reply[cut..], false, |b| body.extend_from_slice(b));
            assert!(rest.unwrap());
            assert_eq!(body, b"0123456789");
            assert_eq!(ranged.size, Some(100));
        }
        let mut ranged = Ranged::new(10, 19);
        assert!(
            ranged
                .feed(&reply[..reply.len() - 1], true, |_| ())
                .is_err()
        );
        for wrong in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n"[..],
            b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-9/100\r\nContent-Length: 10\r\n\r\n",
            b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 10-19/100\r\nContent-Length: 11\r\n\r\n",
            b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 19-10/100\r\n\r\n",
        ] {
            assert!(Ranged::new(10, 19).feed(wrong, false, |_| ()).is_err());
        }
    }
    #[test]
    fn response_head_preserves_redirects_but_refuses_ambiguous_framing() {
        let redirect =
            b"HTTP/1.1 302 Found\r\nLocation: ../next?sig=%2b\r\nContent-Length: 0\r\n\r\n";
        let parsed = response_head(redirect, false).unwrap().unwrap();
        assert_eq!(parsed.status, 302);
        assert_eq!(parsed.location.as_deref(), Some("../next?sig=%2b"));
        assert_eq!(head(redirect, false), Err(NetError::Status(302)));
        for bytes in [&b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n"[..], b"HTTP/1.1 302 Found\r\nLocation: /a\r\nLocation: /b\r\n\r\n", b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-1/2\r\nContent-Range: bytes 0-1/3\r\n\r\n",b"HTTP/1.1 101 Switching Protocols\r\n\r\n"] { assert!(response_head(bytes,false).is_err()); }
        let mut bytes = b"HTTP/1.1 100 Continue\r\n\r\n".repeat(MAX_HEADER / 20);
        bytes.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        assert!(response_head(&bytes, false).is_err());
    }
    #[test]
    fn range_identity_and_failed_state_precede_body_publication() {
        let good=b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-1/10\r\nContent-Length: 2\r\nETag: \"v1\"\r\n\r\nab";
        let mut range = Ranged::with_identity(0, 1, "\"v1\"", 10).unwrap();
        let mut body = Vec::new();
        assert!(
            range
                .feed(good, false, |b| body.extend_from_slice(b))
                .unwrap()
        );
        assert_eq!(body, b"ab");
        for wrong in [
            String::from_utf8(good.to_vec())
                .unwrap()
                .replace("v1", "v2"),
            String::from_utf8(good.to_vec())
                .unwrap()
                .replace("/10", "/11"),
            String::from_utf8(good.to_vec())
                .unwrap()
                .replace("206 Partial Content", "200 OK"),
            String::from_utf8(good.to_vec())
                .unwrap()
                .replace("ETag: \"v1\"\r\n", ""),
        ] {
            let mut range = Ranged::with_identity(0, 1, "\"v1\"", 10).unwrap();
            let mut delivered = 0;
            assert!(
                range
                    .feed(wrong.as_bytes(), false, |b| delivered += b.len())
                    .is_err()
            );
            assert_eq!(delivered, 0);
            assert!(
                range
                    .feed(b"injected body", false, |b| delivered += b.len())
                    .is_err()
            );
            assert_eq!(delivered, 0);
        }
        for etag in ["W/\"v1\"", "unquoted", "\"bad\r\nheader\""] {
            assert!(Ranged::with_identity(0, 1, etag, 10).is_err());
        }
    }
    #[test]
    fn malicious_lengths_refuse_without_arithmetic_panics_or_publication() {
        assert!(response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\nffffffffffffffff\r\n",false).is_err());
        let mut oversized = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        oversized.resize(oversized.len() + MAX_BODY + 1, b'a');
        assert!(response(&oversized, true).is_err());
        for (start, end) in [(2, 1), (0, u64::MAX)] {
            let mut range = Ranged::new(start, end);
            assert!(
                range
                    .feed(b"HTTP/1.1 206 Partial Content\r\n\r\n", false, |_| panic!(
                        "invalid extent cannot publish"
                    ))
                    .is_err()
            );
        }
    }
}
