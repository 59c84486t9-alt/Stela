//! HTTP destination policy over the shared RFC 3986 syntax owner.
use core::fmt;
use stela_formats::uri::{self, Reference, Uri};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlError {
    Syntax,
    Scheme,
    Host,
    Path,
    Credentials,
    Fragment,
    Port,
    HostEncoding,
    Resolution,
}
impl UrlError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::Syntax => "invalid RFC 3986 URI syntax",
            Self::Scheme => "URL scheme must be http or https",
            Self::Host => "URL without a host",
            Self::Path => "URL without a path",
            Self::Credentials => "URL credentials are not supported",
            Self::Fragment => "URL fragment is not a transport request",
            Self::Port => "URL port must be 1 to 65535",
            Self::HostEncoding => "encoded or non-IP literal host is unsupported",
            Self::Resolution => "redirect reference is not RFC 3986 resolvable",
        }
    }
}
impl fmt::Display for UrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}
impl core::error::Error for UrlError {}

/// A validated HTTP destination. Request target and permission keep their raw
/// original octets; no parse-time normalization can change a signed request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Url<'a> {
    pub scheme: Scheme,
    pub authority: &'a str,
    /// DNS name or unbracketed numeric IPv6 address; never user information.
    pub host: &'a str,
    pub port: u16,
    pub target: &'a str,
    uri: &'a Uri,
}
impl<'a> Url<'a> {
    pub fn parse(raw: &'a str) -> Result<Self, UrlError> {
        let uri = Uri::new(raw).map_err(|_| UrlError::Syntax)?;
        let scheme = match uri.scheme_str() {
            value if value.eq_ignore_ascii_case("http") => Scheme::Http,
            value if value.eq_ignore_ascii_case("https") => Scheme::Https,
            _ => return Err(UrlError::Scheme),
        };
        let authority = uri.authority_str().ok_or(UrlError::Host)?;
        let components = uri.authority_components().ok_or(UrlError::Host)?;
        if components.host().is_empty() {
            return Err(UrlError::Host);
        }
        if !uri.path_str().starts_with('/') {
            return Err(UrlError::Path);
        }
        if components.userinfo().is_some() {
            return Err(UrlError::Credentials);
        }
        if uri.fragment_str().is_some() {
            return Err(UrlError::Fragment);
        }
        let host = components.host();
        let host = if let Some(literal) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            literal
                .parse::<core::net::Ipv6Addr>()
                .map_err(|_| UrlError::HostEncoding)?;
            literal
        } else {
            if host.contains('%') {
                return Err(UrlError::HostEncoding);
            }
            host
        };
        let default = match scheme {
            Scheme::Http => 80,
            Scheme::Https => 443,
        };
        let port = components.port().map_or(Ok(default), |port| {
            port.parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or(UrlError::Port)
        })?;
        // Upstream syntax has already established the exact scheme/permission
        // boundaries. Keeping the suffix avoids re-encoding query octets.
        let prefix = uri.scheme_str().len() + 3 + authority.len();
        let target = &raw[prefix..];
        Ok(Self {
            scheme,
            authority,
            host,
            port,
            target,
            uri,
        })
    }

    pub fn as_str(self) -> &'a str {
        self.uri.as_str()
    }

    /// Resolve Location syntax here; redirect count, method, origin/credential
    /// forwarding and HTTPS downgrade decisions remain the request policy's job.
    pub fn resolve(self, location: &str) -> Result<uri::OwnedUri, UrlError> {
        let reference = Reference::new(location).map_err(|_| UrlError::Syntax)?;
        uri::resolve(self.uri, reference).map_err(|_| UrlError::Resolution)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_request_target_and_numeric_authority_remain_exact() {
        let raw = "https://CDN.example:8443/a/../b%2fc?key=%2B%20&sig=a%2fb%3D";
        let url = Url::parse(raw).unwrap();
        assert_eq!(url.as_str(), raw);
        assert_eq!(
            (url.scheme, url.host, url.authority, url.port, url.target),
            (
                Scheme::Https,
                "CDN.example",
                "CDN.example:8443",
                8443,
                "/a/../b%2fc?key=%2B%20&sig=a%2fb%3D"
            )
        );
        let ip = Url::parse("http://[2001:db8::1]:8080/?q=1").unwrap();
        assert_eq!(
            (ip.host, ip.port, ip.target),
            ("2001:db8::1", 8080, "/?q=1")
        );
        assert_eq!(Url::parse("http://h/p").unwrap().port, 80);
        assert_eq!(Url::parse("https://h/p").unwrap().port, 443);
    }
    #[test]
    fn syntax_failures_remain_distinct_from_transport_policy() {
        for raw in [
            "http://h:bad/p",
            "http://h/%GG",
            "http://h/a b",
            "http://[bad]/p",
        ] {
            assert_eq!(Url::parse(raw), Err(UrlError::Syntax), "{raw}");
        }
        for (raw, error) in [
            ("ftp://h/p", UrlError::Scheme),
            ("http:///p", UrlError::Host),
            ("http://h", UrlError::Path),
            ("http://u:p@h/p", UrlError::Credentials),
            ("http://h/p#f", UrlError::Fragment),
            ("http://h:0/p", UrlError::Port),
            ("http://h:65536/p", UrlError::Port),
            ("http://%65xample/p", UrlError::HostEncoding),
        ] {
            assert_eq!(Url::parse(raw), Err(error), "{raw}");
        }
    }
    #[test]
    fn redirect_resolution_does_not_silently_authorize_new_transport() {
        let url = Url::parse("https://h/a/b?old=1").unwrap();
        let next = url.resolve("../c?sig=%2b").unwrap();
        assert_eq!(Url::parse(next.as_str()).unwrap().target, "/c?sig=%2b");
        let downgrade = url.resolve("http://other/p").unwrap();
        assert_eq!(Url::parse(downgrade.as_str()).unwrap().scheme, Scheme::Http);
        let credential = url.resolve("https://u:p@other/p").unwrap();
        assert_eq!(Url::parse(credential.as_str()), Err(UrlError::Credentials));
        assert_eq!(url.resolve("%GG"), Err(UrlError::Syntax));
    }
}
