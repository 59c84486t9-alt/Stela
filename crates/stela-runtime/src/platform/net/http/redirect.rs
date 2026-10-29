//! Bounded redirect policy without scheme fallback or cross-origin POST replay.
use super::{Scheme, Url, UrlError};
use alloc::{borrow::ToOwned, string::String, vec::Vec};
use core::fmt;
use stela_formats::uri::{OwnedUri, Uri};

/// An automatic request chain follows at most ten server-supplied references.
const MAX_REDIRECTS: usize = 10;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedirectError {
    Status(u16),
    MissingLocation,
    Method,
    Origin,
    Downgrade,
    Loop,
    Limit,
    Url(UrlError),
}
impl fmt::Display for RedirectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status(status) => {
                write!(f, "HTTP status {status} has no automatic redirect policy")
            }
            Self::MissingLocation => f.write_str("redirect has no Location"),
            Self::Method => f.write_str("refusing to rewrite POST method or body on redirect"),
            Self::Origin => f.write_str("refusing POST body replay across origins"),
            Self::Downgrade => f.write_str("refusing HTTPS downgrade"),
            Self::Loop => f.write_str("redirect loop"),
            Self::Limit => f.write_str("redirect limit exceeded"),
            Self::Url(error) => write!(f, "redirect destination: {error}"),
        }
    }
}
impl core::error::Error for RedirectError {}

pub struct Redirects {
    current: OwnedUri,
    visited: Vec<String>,
    method: Method,
    credentials: bool,
}
impl Redirects {
    pub fn new(url: &str, method: Method) -> Result<Self, UrlError> {
        Url::parse(url)?;
        Ok(Self {
            current: Uri::new(url).map_err(|_| UrlError::Syntax)?.to_owned(),
            visited: Vec::new(),
            method,
            credentials: true,
        })
    }
    pub fn current(&self) -> Url<'_> {
        Url::parse(self.current.as_str()).expect("owned policy-validated URL")
    }
    /// Authorization/Cookie/Proxy-Authorization must stay removed after the
    /// first unrelated origin change, including a later redirect back. A
    /// same-host default-port HTTPS upgrade keeps its original credentials.
    pub fn forwards_credentials(&self) -> bool {
        self.credentials
    }
    /// Update only after the whole next destination passes transport policy.
    /// POST follows only 307/308 within its origin or HTTP80→HTTPS443 on the
    /// same host. The transport verifies TLS before sending request bytes.
    pub fn follow(&mut self, status: u16, location: Option<&str>) -> Result<(), RedirectError> {
        if !matches!(status, 301 | 302 | 303 | 307 | 308) {
            return Err(RedirectError::Status(status));
        }
        if self.method == Method::Post && !matches!(status, 307 | 308) {
            return Err(RedirectError::Method);
        }
        if self.visited.len() >= MAX_REDIRECTS {
            return Err(RedirectError::Limit);
        }
        let current = self.current();
        let resolved = current
            .resolve(location.ok_or(RedirectError::MissingLocation)?)
            .map_err(RedirectError::Url)?;
        let next = Url::parse(resolved.as_str()).map_err(RedirectError::Url)?;
        if current.scheme == Scheme::Https && next.scheme != Scheme::Https {
            return Err(RedirectError::Downgrade);
        }
        let same = same_origin(current, next);
        let upgrade = current.scheme == Scheme::Http
            && current.port == 80
            && next.scheme == Scheme::Https
            && next.port == 443
            && same_host(current, next);
        if self.method == Method::Post && !same && !upgrade {
            return Err(RedirectError::Origin);
        }
        if resolved.as_str() == self.current.as_str()
            || self.visited.iter().any(|v| v == resolved.as_str())
        {
            return Err(RedirectError::Loop);
        }
        self.visited.push(String::from(self.current.as_str()));
        self.current = resolved;
        self.credentials &= same || upgrade;
        Ok(())
    }
}
fn same_host(a: Url<'_>, b: Url<'_>) -> bool {
    match (
        a.host.parse::<core::net::IpAddr>(),
        b.host.parse::<core::net::IpAddr>(),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => a.host.eq_ignore_ascii_case(b.host),
    }
}
fn same_origin(a: Url<'_>, b: Url<'_>) -> bool {
    a.scheme == b.scheme && a.port == b.port && same_host(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn relative_signed_targets_and_same_origin_post_keep_exact_octets() {
        let mut chain = Redirects::new("https://H/a/b?old=%2b", Method::Post).unwrap();
        chain.follow(307, Some("../c?sig=%2f%3D")).unwrap();
        assert_eq!(chain.current().as_str(), "https://H/c?sig=%2f%3D");
        assert!(chain.forwards_credentials());
        chain.follow(308, Some("https://h:443/d")).unwrap();
        assert!(chain.forwards_credentials());
    }
    #[test]
    fn rejected_targets_do_not_mutate_the_admitted_chain() {
        let initial = "https://h/p";
        for (method, status, location, error) in [
            (
                Method::Get,
                302,
                Some("http://h/q"),
                RedirectError::Downgrade,
            ),
            (Method::Post, 301, Some("/q"), RedirectError::Method),
            (
                Method::Post,
                307,
                Some("https://other/q"),
                RedirectError::Origin,
            ),
            (Method::Get, 302, None, RedirectError::MissingLocation),
            (
                Method::Get,
                302,
                Some("https://u:p@h/q"),
                RedirectError::Url(UrlError::Credentials),
            ),
            (
                Method::Get,
                302,
                Some("%GG"),
                RedirectError::Url(UrlError::Syntax),
            ),
            (Method::Get, 300, Some("/q"), RedirectError::Status(300)),
        ] {
            let mut chain = Redirects::new(initial, method).unwrap();
            assert_eq!(chain.follow(status, location), Err(error));
            assert_eq!(chain.current().as_str(), initial);
            assert!(chain.forwards_credentials());
        }
    }
    #[test]
    fn credentials_never_return_after_cross_origin_get() {
        let mut chain = Redirects::new("https://first/a", Method::Get).unwrap();
        chain.follow(302, Some("https://other/b")).unwrap();
        assert!(!chain.forwards_credentials());
        chain.follow(303, Some("https://first/c")).unwrap();
        assert!(!chain.forwards_credentials());
    }
    #[test]
    fn cycles_and_nonrepeating_chains_are_both_bounded() {
        let mut chain = Redirects::new("https://h/a", Method::Get).unwrap();
        chain.follow(302, Some("/b")).unwrap();
        assert_eq!(chain.follow(302, Some("/a")), Err(RedirectError::Loop));
        let mut chain = Redirects::new("https://h/a", Method::Get).unwrap();
        for i in 0..MAX_REDIRECTS {
            chain.follow(302, Some(&alloc::format!("/hop{i}"))).unwrap();
        }
        assert_eq!(chain.follow(302, Some("/last")), Err(RedirectError::Limit));
    }
    #[test]
    fn default_port_same_host_post_upgrade_requires_https_transport() {
        let mut chain = Redirects::new("http://H:80/p", Method::Post).unwrap();
        chain
            .follow(307, Some("https://h:443/secure?sig=%2b"))
            .unwrap();
        assert_eq!(chain.current().scheme, Scheme::Https);
        assert!(chain.forwards_credentials());
        for (initial, next) in [
            ("http://h:8080/p", "https://h/q"),
            ("http://h/p", "https://h:8443/q"),
            ("http://h/p", "https://other/q"),
        ] {
            let mut chain = Redirects::new(initial, Method::Post).unwrap();
            assert_eq!(chain.follow(308, Some(next)), Err(RedirectError::Origin));
        }
    }
}
