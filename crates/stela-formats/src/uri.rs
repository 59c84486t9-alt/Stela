//! RFC 3986 URI syntax and reference resolution without transport policy.
use core::fmt;
use iri_string::format::ToDedicatedString;

pub use iri_string::types::{UriReferenceStr as Reference, UriStr as Uri, UriString as OwnedUri};
pub use iri_string::validate::Error as SyntaxError;

/// The reference cannot be represented by RFC 3986's resolution algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolutionError;
impl fmt::Display for ResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("URI reference is not RFC 3986 resolvable")
    }
}
impl core::error::Error for ResolutionError {}

/// Resolve only when a caller follows a reference. Parsing a URI leaves its
/// original octets, escape spelling and query untouched, including signatures.
/// Fragments and schemes remain syntax here; the transport decides their policy.
pub fn resolve(base: &Uri, reference: &Reference) -> Result<OwnedUri, ResolutionError> {
    let resolved = reference.resolve_against(base.to_absolute());
    resolved
        .ensure_rfc3986_normalizable()
        .map_err(|_| ResolutionError)?;
    Ok(resolved.to_dedicated_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_octets_remain_exact_when_parsed() {
        let raw = "https://CDN.example/a/../b%2fc?key=%2B%20&sig=a%2fb%3D";
        let uri = Uri::new(raw).unwrap();
        assert_eq!(uri.as_str(), raw);
        assert_eq!(uri.path_str(), "/a/../b%2fc");
        assert_eq!(uri.query_str(), Some("key=%2B%20&sig=a%2fb%3D"));
    }

    #[test]
    fn syntax_is_shared_without_http_policy() {
        for raw in [
            "http://host:bad/p",
            "http://h/a b",
            "http://h/%xz",
            "http://[broken]/p",
            "http://h/\r\nX:y",
        ] {
            assert!(Uri::new(raw).is_err(), "{raw:?}");
        }
        assert!(Uri::new("urn:example:object").is_ok());
        assert!(Uri::new("https://user:password@[2001:db8::1]:443/path?q=1#part").is_ok());
    }

    #[test]
    fn rfc_references_preserve_query_and_resolve_paths() {
        let base = Uri::new("https://h/a/b?old=1#ignored").unwrap();
        for (reference, expected) in [
            ("../c?sig=a%2fb%3D", "https://h/c?sig=a%2fb%3D"),
            ("?key=%2B", "https://h/a/b?key=%2B"),
            ("//other/p", "https://other/p"),
            ("https://h/x%2fy?z=%2b", "https://h/x%2fy?z=%2b"),
            ("#part", "https://h/a/b?old=1#part"),
        ] {
            assert_eq!(
                resolve(base, Reference::new(reference).unwrap())
                    .unwrap()
                    .as_str(),
                expected
            );
        }
    }
}
