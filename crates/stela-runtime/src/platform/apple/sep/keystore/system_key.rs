//! System-key public queries through AKS perform_operation (command 0x22).
//!
//! 26A434 kernel file 0x2d41f50: variant 0, session, handle, operation,
//! blob; reply variant 0 and one raw result blob. The public system-key
//! wrapper uses handle -1, operation 2 (constant at 0x725890); the userspace
//! perform-operation dispatch sets operation 0 (0x2d36078). Its DER
//! dictionary is a SET of SEQUENCE { UTF8 key, value } pairs, sorted by
//! complete encoded pair. `o=oskgp`, `skt=1`, `skg=1` requests the SIK.
//!
//! P-256 is Stela's system-identity policy, not a recovered Apple hardware
//! KDF or an Apple-certified identity. The genuine private scalar is derived
//! from provisioned machine roots, retained only here and zeroized on drop.
//! No attestation, key rotation, signing or other key types are advertised.
use super::{
    super::der::{self, Cursor},
    Fields,
};
use alloc::{format, string::String};
use hmac::{Hmac, Mac};
use p256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use sha2::Sha256;
use zeroize::Zeroizing;

pub(super) const PERFORM_OPERATION: u8 = 0x22;
const PUBLIC_HANDLE: u32 = u32::MAX;
const PUBLIC_OPERATIONS: [u32; 2] = [0, 2];
const IDENTITY_TYPE: u32 = 1;
const IDENTITY_GENERATION: u32 = 1;
const SCALAR_DOMAIN: &[u8] = b"Stela SEP system identity P-256 v1\0";
const MAX_SCALAR_ATTEMPTS: u32 = 256;
const PUBLIC_BYTES: usize = 65;

pub(super) enum PublicQuery {
    Identity,
}

pub(super) struct SystemKeys {
    root: Zeroizing<[u8; 32]>,
    identity: Option<(SecretKey, [u8; PUBLIC_BYTES])>,
}

impl SystemKeys {
    pub(super) fn new(root: Zeroizing<[u8; 32]>) -> Self {
        Self {
            root,
            identity: None,
        }
    }

    pub(super) fn public(&mut self, query: PublicQuery) -> Result<&[u8], &'static str> {
        match query {
            PublicQuery::Identity => {
                if self.identity.is_none() {
                    let secret = identity_secret(&self.root)?;
                    let point = secret.public_key().to_encoded_point(false);
                    let mut public = [0; PUBLIC_BYTES];
                    public.copy_from_slice(point.as_bytes());
                    self.identity = Some((secret, public));
                }
                Ok(&self.identity.as_ref().unwrap().1)
            }
        }
    }
}

fn identity_secret(root: &[u8; 32]) -> Result<SecretKey, &'static str> {
    // Rejection sampling preserves the scalar distribution, unlike reducing
    // a 256-bit digest modulo the curve order. The counter changes only on
    // an out-of-range candidate, so reopen reconstructs the identical key.
    for counter in 0..MAX_SCALAR_ATTEMPTS {
        let mut mac = Hmac::<Sha256>::new_from_slice(root).expect("HMAC accepts 256-bit roots");
        mac.update(SCALAR_DOMAIN);
        mac.update(&IDENTITY_TYPE.to_be_bytes());
        mac.update(&IDENTITY_GENERATION.to_be_bytes());
        mac.update(&counter.to_be_bytes());
        let candidate = Zeroizing::new(<[u8; 32]>::from(mac.finalize().into_bytes()));
        if let Ok(secret) = SecretKey::from_slice(candidate.as_ref()) {
            return Ok(secret);
        }
    }
    Err("SEP system identity scalar derivation exhausted")
}

pub(super) fn public_query(
    variant: u32,
    fields: &mut Fields<'_>,
) -> Result<PublicQuery, &'static str> {
    if variant != 0 {
        return Err("SEP perform-operation variant is not implemented");
    }
    // This read-only public query grants no session, bag or credential state.
    let _session = fields.lword()?;
    if fields.word()? != PUBLIC_HANDLE || !PUBLIC_OPERATIONS.contains(&fields.word()?) {
        return Err("SEP perform-operation handle or operation is not implemented");
    }
    let bytes = fields.blob()?;
    fields.end()?;
    let mut outer = Cursor(bytes);
    let set = outer.take(17)?;
    outer.end()?;
    let mut pairs = Cursor(set.value);
    let mut previous: Option<&[u8]> = None;
    let (mut operation, mut key_type, mut generation) = (false, false, false);
    while !pairs.0.is_empty() {
        let pair = pairs.take(16)?;
        if previous.is_some_and(|p| p >= pair.encoded) {
            return Err("SEP system-key dictionary is duplicated or not DER sorted");
        }
        previous = Some(pair.encoded);
        let mut entry = Cursor(pair.value);
        match entry.take(12)?.value {
            b"o" => {
                if operation || entry.take(12)?.value != b"oskgp" {
                    return Err("SEP system-key operation is not implemented");
                }
                operation = true;
            }
            b"skt" => {
                if key_type || der::unsigned(entry.take(2)?.value)? != [IDENTITY_TYPE as u8] {
                    return Err("SEP system-key type is not implemented");
                }
                key_type = true;
            }
            b"skg" => {
                if generation || der::unsigned(entry.take(2)?.value)? != [IDENTITY_GENERATION as u8]
                {
                    return Err("SEP system-key generation is not implemented");
                }
                generation = true;
            }
            _ => return Err("SEP system-key parameter is not implemented"),
        }
        entry.end()?;
    }
    if !(operation && key_type && generation) {
        return Err("SEP system-key dictionary is incomplete");
    }
    Ok(PublicQuery::Identity)
}

/// Sanitized metadata for a refused, digest-validated perform-operation.
/// Never render the session, unknown strings, parameter values or key bytes.
/// This parser only describes the request; it grants no operation or authority.
pub(super) fn diagnostic(variant: u32, fields: &mut Fields<'_>) -> String {
    let (mut handle, mut operation) = (None, None);
    let mut parameters = None;
    let parsed = (|| {
        let _session = fields.lword()?;
        handle = Some(fields.word()?);
        operation = Some(fields.word()?);
        let bytes = fields.blob()?;
        fields.end()?;
        parameters = Some(ParameterDiagnostic::parse(bytes)?);
        Ok::<_, &'static str>(())
    })()
    .is_ok();
    let parameters = parameters.unwrap_or_default();
    format!(
        "sks refused command=0x22 variant={variant} handle={handle:?} operation={operation:?} parameter_operation={} system_key_type={:?} reference_key_type={:?} generation={:?} parsed={parsed}",
        parameters.operation,
        parameters.system_key_type,
        parameters.reference_key_type,
        parameters.generation,
    )
}

struct ParameterDiagnostic {
    operation: &'static str,
    system_key_type: Option<u32>,
    reference_key_type: Option<u32>,
    generation: Option<u32>,
}

impl Default for ParameterDiagnostic {
    fn default() -> Self {
        Self {
            operation: "unknown",
            system_key_type: None,
            reference_key_type: None,
            generation: None,
        }
    }
}

impl ParameterDiagnostic {
    fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        let mut outer = Cursor(bytes);
        let set = outer.take(17)?;
        outer.end()?;
        let mut pairs = Cursor(set.value);
        let mut previous: Option<&[u8]> = None;
        let mut result = Self::default();
        let mut has_operation = false;
        // Bounded diagnostic work even for a large, otherwise valid request.
        for _ in 0..32 {
            if pairs.0.is_empty() {
                return Ok(result);
            }
            let pair = pairs.take(16)?;
            if previous.is_some_and(|p| p >= pair.encoded) {
                return Err("SEP diagnostic dictionary is duplicated or not DER sorted");
            }
            previous = Some(pair.encoded);
            let mut entry = Cursor(pair.value);
            match entry.take(12)?.value {
                b"o" => {
                    if has_operation {
                        return Err("SEP diagnostic operation is duplicated");
                    }
                    has_operation = true;
                    // Original operation names only. Unknown guest strings
                    // may contain secrets and must never enter a log line.
                    result.operation = match entry.take(12)?.value {
                        b"oskgp" => "oskgp",
                        b"oc" => "oc",
                        b"osgn" => "osgn",
                        b"osa" => "osa",
                        b"oskc" => "oskc",
                        b"oska" => "oska",
                        b"osko" => "osko",
                        _ => "unknown",
                    };
                }
                b"skt" if result.system_key_type.is_none() => {
                    result.system_key_type = Some(diagnostic_number(&mut entry)?);
                }
                b"kt" if result.reference_key_type.is_none() => {
                    result.reference_key_type = Some(diagnostic_number(&mut entry)?);
                }
                b"skg" if result.generation.is_none() => {
                    result.generation = Some(diagnostic_number(&mut entry)?);
                }
                b"skt" | b"kt" | b"skg" => {
                    return Err("SEP diagnostic number is duplicated");
                }
                _ => {
                    entry.next()?;
                }
            }
            entry.end()?;
        }
        Err("SEP diagnostic dictionary exceeds the parameter bound")
    }
}

fn diagnostic_number(entry: &mut Cursor<'_>) -> Result<u32, &'static str> {
    let bytes = der::unsigned(entry.take(2)?.value)?;
    if bytes.len() > 4 {
        return Err("SEP diagnostic integer is oversized");
    }
    Ok(bytes.iter().fold(0, |n, b| (n << 8) | u32::from(*b)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_a_real_curve_key_and_reopens_without_new_entropy() {
        let root = Zeroizing::new([1; 32]);
        let mut first = SystemKeys::new(root.clone());
        let public = first.public(PublicQuery::Identity).unwrap().to_vec();
        p256::PublicKey::from_sec1_bytes(&public).unwrap();
        assert_eq!(public.len(), PUBLIC_BYTES);
        assert_eq!(public[0], 4);
        // Independent Python HMAC + OpenSSL EC public-key derivation for
        // this test-only seed and the exact domain/type/generation/counter.
        assert_eq!(
            hex::encode(&public),
            "04c5f1cca66ff986742be7e6ccf4996fde1a031bf7697cf7fe104b23a82f98c5c3d908693dbc7b4df331a1940e69526c8417327beab5ca48fd505e2337bcdff437"
        );
        assert_eq!(public, first.public(PublicQuery::Identity).unwrap());
        let mut reopened = SystemKeys::new(root);
        assert_eq!(public, reopened.public(PublicQuery::Identity).unwrap());
        let mut other = SystemKeys::new(Zeroizing::new([2; 32]));
        assert_ne!(public, other.public(PublicQuery::Identity).unwrap());
    }
}
