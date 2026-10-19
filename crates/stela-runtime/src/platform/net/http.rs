//! HTTP/1.1 requests and responses (RFC 9112): a POST with a
//! Content-Length body and `Connection: close`, and a response framed by
//! Content-Length, chunked transfer coding, or the end of the connection.
//! Interim 1xx responses are skipped; any other non-2xx status is an
//! error. Redirects and other transfer codings are refused.
use super::NetError;
use alloc::{format, string::String, vec::Vec};

/// The largest response header block and body this client accepts.
pub const MAX_HEADER: usize = 64 * 1024;
pub const MAX_BODY: usize = 8 * 1024 * 1024;

/// A complete POST request.
pub fn post(
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
    content_type: &str,
    body: &[u8],
) -> Result<Vec<u8>, NetError> {
    let field = |text: &str| !text.is_empty() && text.bytes().all(|b| b > 0x20 && b != 0x7f);
    let value = |text: &str| {
        text.bytes()
            .all(|b| b == b' ' || b == b'\t' || (b > 0x20 && b != 0x7f))
    };
    if !field(host) || !path.starts_with('/') || !field(path) || !value(content_type) {
        return Err(NetError::Invalid("HTTP host, path or content type"));
    }
    if headers
        .iter()
        .any(|(name, text)| !field(name) || name.contains(':') || !value(text))
    {
        return Err(NetError::Invalid("HTTP header"));
    }
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: {content_type}\r\n\
         Content-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, text) in headers {
        request.push_str(&format!("{name}: {text}\r\n"));
    }
    request.push_str("\r\n");
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(body);
    Ok(bytes)
}

/// A complete response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

fn http_error(why: &str) -> NetError {
    NetError::Http(String::from(why))
}

/// The response in `bytes`, once complete. `closed` says the server has
/// ended the connection, which completes a body without a length.
pub fn response(bytes: &[u8], closed: bool) -> Result<Option<Response>, NetError> {
    let mut start = 0;
    loop {
        let rest = &bytes[start..];
        let Some(end) = rest.windows(4).position(|w| w == b"\r\n\r\n") else {
            if rest.len() > MAX_HEADER {
                return Err(http_error("response header too large"));
            }
            return match closed {
                true => Err(http_error("connection closed inside the response header")),
                false => Ok(None),
            };
        };
        let head = core::str::from_utf8(&rest[..end])
            .map_err(|_| http_error("response header is not text"))?;
        let mut lines = head.split("\r\n");
        let status_line = lines.next().unwrap_or_default();
        let mut parts = status_line.splitn(3, ' ');
        let version = parts.next().unwrap_or_default();
        let code = parts.next().unwrap_or_default();
        if !version.starts_with("HTTP/1.") || code.len() != 3 {
            return Err(http_error("malformed status line"));
        }
        let status: u16 = code
            .parse()
            .map_err(|_| http_error("malformed status code"))?;
        let mut length = None;
        let mut chunked = false;
        for line in lines {
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| http_error("malformed header field"))?;
            let value = value.trim();
            if name.eq_ignore_ascii_case("content-length") {
                let n: usize = value
                    .parse()
                    .map_err(|_| http_error("malformed Content-Length"))?;
                if length.is_some_and(|other| other != n) {
                    return Err(http_error("conflicting Content-Length"));
                }
                length = Some(n);
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                if !value.eq_ignore_ascii_case("chunked") {
                    return Err(NetError::Http(format!("transfer coding {value:?}")));
                }
                chunked = true;
            }
        }
        let body = &rest[end + 4..];
        if (100..200).contains(&status) {
            // An interim response has no body; the final one follows.
            start += end + 4;
            continue;
        }
        if !(200..300).contains(&status) {
            return Err(NetError::Status(status));
        }
        let body = if chunked {
            match chunks(body)? {
                Some(body) => body,
                None if closed => return Err(http_error("connection closed inside a chunk")),
                None => return Ok(None),
            }
        } else if let Some(length) = length {
            if length > MAX_BODY {
                return Err(http_error("response body too large"));
            }
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
        return Ok(Some(Response { status, body }));
    }
}

/// A chunked body (RFC 9112 7.1), once its last chunk and trailer arrive.
fn chunks(mut bytes: &[u8]) -> Result<Option<Vec<u8>>, NetError> {
    let mut body = Vec::new();
    loop {
        let Some(line) = bytes.windows(2).position(|w| w == b"\r\n") else {
            return Ok(None);
        };
        let text =
            core::str::from_utf8(&bytes[..line]).map_err(|_| http_error("malformed chunk size"))?;
        let size = text.split(';').next().unwrap_or_default().trim();
        let size =
            usize::from_str_radix(size, 16).map_err(|_| http_error("malformed chunk size"))?;
        bytes = &bytes[line + 2..];
        if size == 0 {
            // Trailer fields, if any, end with an empty line.
            let done = bytes.starts_with(b"\r\n") || bytes.windows(4).any(|w| w == b"\r\n\r\n");
            return Ok(done.then_some(body));
        }
        if body.len() + size > MAX_BODY {
            return Err(http_error("response body too large"));
        }
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
}
