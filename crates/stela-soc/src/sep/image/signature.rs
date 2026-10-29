//! Image4 cryptographic evidence, separate from boot admission.
//!
//! IM4M signs the exact DER SET containing MANB; DGST binds the complete
//! IM4P encoding (the loader's `im4m` contract). The first certificate holds
//! the manifest key. This checks RSA/SHA-384 and every supplied issuer link,
//! but grants NO trust: missing roots, certificate constraints, board/nonce
//! policy and rollback remain the admission owner's obligations. In particular
//! a key supplied by an untrusted manifest cannot authenticate itself as Apple.
use alloc::vec::Vec;
use sha2::{Digest, Sha384};
use stela_formats::{
    der::{self, Cursor, Element},
    rsa::{self, Hash, Key},
};

/// A structural or cryptographic failure, with its original parser cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    Der(der::Error),
    Rsa(rsa::Error),
    Payload(stela_formats::img4::Img4Error),
    Violation(SignatureViolation),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureViolation {
    AlgorithmParameters,
    UnusedBits,
    CertificateSignatureAlgorithm,
    CertificateVersion,
    CertificateSerial,
    CertificateAlgorithmMismatch,
    CertificateKeyAlgorithm,
    CertificateOptionalField,
    ManifestTag,
    ManifestName,
    ManifestProperties,
    ManifestBody,
    ObjectLimit,
    DuplicateObject,
    PropertyLimit,
    DuplicateProperty,
    DigestAlgorithm,
    MissingPayload,
    ManifestLimit,
    PayloadType,
    ManifestType,
    ManifestVersion,
    PayloadDigest,
    CertificateLimit,
    DuplicateCertificate,
    MissingCertificate,
    CertificateIssuer,
}
impl SignatureViolation {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::AlgorithmParameters => "SEP algorithm parameters are not NULL",
            Self::UnusedBits => "SEP signature/key BIT STRING has unused bits",
            Self::CertificateSignatureAlgorithm => {
                "SEP certificate signature algorithm is unsupported"
            }
            Self::CertificateVersion => "SEP certificate version is unsupported",
            Self::CertificateSerial => "SEP certificate version/serial is malformed",
            Self::CertificateAlgorithmMismatch => "SEP certificate signature algorithms disagree",
            Self::CertificateKeyAlgorithm => "SEP certificate key algorithm is unsupported",
            Self::CertificateOptionalField => "SEP certificate optional field is unsupported",
            Self::ManifestTag => "SEP manifest entry is not a private constructed tag",
            Self::ManifestName => "SEP manifest entry name differs from its tag",
            Self::ManifestProperties => "SEP manifest properties are not a SET",
            Self::ManifestBody => "SEP manifest has no MANB",
            Self::ObjectLimit => "SEP manifest object count exceeds the resource bound",
            Self::DuplicateObject => "SEP manifest has duplicate objects",
            Self::PropertyLimit => "SEP manifest property count exceeds the resource bound",
            Self::DuplicateProperty => "SEP manifest has duplicate properties",
            Self::DigestAlgorithm => "SEP manifest digest is not SHA-384",
            Self::MissingPayload => "SEP manifest does not cover this payload type",
            Self::ManifestLimit => "SEP manifest exceeds the resource bound",
            Self::PayloadType => "SEP payload type is unsupported",
            Self::ManifestType => "SEP firmware manifest is not an IM4M",
            Self::ManifestVersion => "SEP manifest version is unsupported",
            Self::PayloadDigest => "SEP manifest payload digest mismatch",
            Self::CertificateLimit => "SEP certificate chain exceeds the resource bound",
            Self::DuplicateCertificate => "SEP certificate chain contains a duplicate certificate",
            Self::MissingCertificate => "SEP manifest has no signing certificate",
            Self::CertificateIssuer => "SEP certificate issuer/subject mismatch",
        }
    }
}
impl SignatureError {
    /// Description for the legacy ROM protocol's static refusal vocabulary.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Der(_) => "SEP signature DER is malformed",
            Self::Rsa(_) => "SEP RSA signature verification failed",
            Self::Payload(_) => "SEP payload is not an IM4P",
            Self::Violation(reason) => reason.reason(),
        }
    }
}
impl From<der::Error> for SignatureError {
    fn from(error: der::Error) -> Self {
        Self::Der(error)
    }
}
impl From<rsa::Error> for SignatureError {
    fn from(error: rsa::Error) -> Self {
        Self::Rsa(error)
    }
}
impl core::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Der(error) => write!(f, "SEP signature: {error}"),
            Self::Rsa(error) => write!(f, "SEP signature: {error}"),
            Self::Payload(error) => write!(f, "SEP payload: {error}"),
            Self::Violation(reason) => f.write_str(reason.reason()),
        }
    }
}
impl core::error::Error for SignatureError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Der(error) => Some(error),
            Self::Rsa(error) => Some(error),
            Self::Payload(error) => Some(error),
            Self::Violation(_) => None,
        }
    }
}

const RSA_ENCRYPTION: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
const RSA_SHA256: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b";
const RSA_SHA384: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c";
const MAX_CERTIFICATES: usize = 4;
const MAX_ENTRIES: usize = 256;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;

/// A signature proof using supplied keys, NOT a trusted-boot capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEvidence {
    pub manifest_sha384: [u8; 48],
    pub leaf_certificate_sha384: [u8; 48],
    /// Number of child signatures checked against a supplied issuer key.
    /// A single leaf certificate yields zero; no root was supplied by it.
    pub issuer_links: usize,
}

/// Signature proof together with a matching SEP payload digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub signature: ManifestEvidence,
    pub payload_sha384: [u8; 48],
}

fn algorithm(encoded: &[u8]) -> Result<&[u8], SignatureError> {
    let mut fields = der::sequence(encoded)?;
    let oid = fields.take(6)?.value;
    if !fields.0.is_empty() && !fields.take(5)?.value.is_empty() {
        return Err(SignatureError::Violation(
            SignatureViolation::AlgorithmParameters,
        ));
    }
    fields.end()?;
    Ok(oid)
}

struct Certificate<'a> {
    encoded: &'a [u8],
    tbs: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    signature: &'a [u8],
    hash: Hash,
    key: Key,
}

fn bit_string(value: &[u8]) -> Result<&[u8], SignatureError> {
    if value.first() != Some(&0) {
        return Err(SignatureError::Violation(SignatureViolation::UnusedBits));
    }
    Ok(&value[1..])
}

fn certificate(encoded: &[u8]) -> Result<Certificate<'_>, SignatureError> {
    let mut outer = der::sequence(encoded)?;
    let tbs = outer.take(16)?;
    let alg = outer.take(16)?;
    let hash = match algorithm(alg.encoded)? {
        RSA_SHA256 => Hash::Sha256,
        RSA_SHA384 => Hash::Sha384,
        _ => {
            return Err(SignatureError::Violation(
                SignatureViolation::CertificateSignatureAlgorithm,
            ));
        }
    };
    let signature = bit_string(outer.take(3)?.value)?;
    outer.end()?;
    let mut fields = Cursor(tbs.value);
    let first = fields.next_element()?;
    if first.class == 2 && first.tag == 0 && first.constructed {
        if first.value != b"\x02\x01\x02" {
            return Err(SignatureError::Violation(
                SignatureViolation::CertificateVersion,
            ));
        }
        der::unsigned(fields.take(2)?.value)?;
    } else if first.class == 0 && first.tag == 2 && !first.constructed {
        der::unsigned(first.value)?; // X.509 v1 omits the DEFAULT version.
    } else {
        return Err(SignatureError::Violation(
            SignatureViolation::CertificateSerial,
        ));
    }
    if fields.take(16)?.encoded != alg.encoded {
        return Err(SignatureError::Violation(
            SignatureViolation::CertificateAlgorithmMismatch,
        ));
    }
    let issuer = fields.take(16)?.encoded;
    fields.take(16)?; // Validity is preserved in tbs, not evaluated as trust here.
    let subject = fields.take(16)?.encoded;
    let mut spki = Cursor(fields.take(16)?.value);
    if algorithm(spki.take(16)?.encoded)? != RSA_ENCRYPTION {
        return Err(SignatureError::Violation(
            SignatureViolation::CertificateKeyAlgorithm,
        ));
    }
    let key = Key::parse(bit_string(spki.take(3)?.value)?)?;
    spki.end()?;
    // Only the optional X.509 v3 extensions field is supported; never claim
    // extension/role/time validation because a signature verified.
    if !fields.0.is_empty() {
        let extensions = fields.next_element()?;
        if extensions.class != 2 || extensions.tag != 3 || !extensions.constructed {
            return Err(SignatureError::Violation(
                SignatureViolation::CertificateOptionalField,
            ));
        }
        der::sequence(extensions.value)?;
    }
    fields.end()?;
    Ok(Certificate {
        encoded,
        tbs: tbs.encoded,
        issuer,
        subject,
        signature,
        hash,
        key,
    })
}

fn named(element: Element<'_>) -> Result<([u8; 4], Element<'_>), SignatureError> {
    if element.class != 3 || !element.constructed {
        return Err(SignatureError::Violation(SignatureViolation::ManifestTag));
    }
    let name = element.tag.to_be_bytes();
    let mut fields = der::sequence(element.value)?;
    if fields.take(22)?.value != name {
        return Err(SignatureError::Violation(SignatureViolation::ManifestName));
    }
    let value = fields.next_element()?;
    fields.end()?;
    Ok((name, value))
}

fn set(element: Element<'_>) -> Result<Cursor<'_>, SignatureError> {
    if element.class != 0 || element.tag != 17 || !element.constructed {
        return Err(SignatureError::Violation(
            SignatureViolation::ManifestProperties,
        ));
    }
    Ok(Cursor(element.value))
}

fn digest_for(body: Element<'_>, payload_type: [u8; 4]) -> Result<&[u8], SignatureError> {
    let mut body = set(body)?;
    let (name, entries) = named(body.next_element()?)?;
    if name != *b"MANB" {
        return Err(SignatureError::Violation(SignatureViolation::ManifestBody));
    }
    body.end()?;
    let mut entries = set(entries)?;
    let mut names = Vec::new();
    let mut digest = None;
    while !entries.0.is_empty() {
        if names.len() == MAX_ENTRIES {
            return Err(SignatureError::Violation(SignatureViolation::ObjectLimit));
        }
        let (name, properties) = named(entries.next_element()?)?;
        if names.contains(&name) {
            return Err(SignatureError::Violation(
                SignatureViolation::DuplicateObject,
            ));
        }
        names.push(name);
        let mut properties = set(properties)?;
        let mut property_names = Vec::new();
        while !properties.0.is_empty() {
            if property_names.len() == MAX_ENTRIES {
                return Err(SignatureError::Violation(SignatureViolation::PropertyLimit));
            }
            let (property_name, value) = named(properties.next_element()?)?;
            if property_names.contains(&property_name) {
                return Err(SignatureError::Violation(
                    SignatureViolation::DuplicateProperty,
                ));
            }
            property_names.push(property_name);
            if name == payload_type && property_name == *b"DGST" {
                if value.class != 0
                    || value.tag != 4
                    || value.constructed
                    || value.value.len() != 48
                {
                    return Err(SignatureError::Violation(
                        SignatureViolation::DigestAlgorithm,
                    ));
                }
                digest = Some(value.value);
            }
        }
    }
    digest.ok_or(SignatureError::Violation(
        SignatureViolation::MissingPayload,
    ))
}

/// Verify signatures and IM4P digest binding using the supplied certificates.
/// The returned evidence has no `trusted`/`booted` flag.
pub fn inspect(payload: &[u8], manifest: &[u8]) -> Result<Evidence, SignatureError> {
    if manifest.len() > MAX_MANIFEST_BYTES {
        return Err(SignatureError::Violation(SignatureViolation::ManifestLimit));
    }
    let payload_type =
        stela_formats::img4::payload_type(payload).map_err(SignatureError::Payload)?;
    if ![*b"sepi", *b"rsep"].contains(&payload_type) {
        return Err(SignatureError::Violation(SignatureViolation::PayloadType));
    }
    let mut fields = der::sequence(manifest)?;
    if fields.take(22)?.value != b"IM4M" {
        return Err(SignatureError::Violation(SignatureViolation::ManifestType));
    }
    if fields.take(2)?.value != [0] {
        return Err(SignatureError::Violation(
            SignatureViolation::ManifestVersion,
        ));
    }
    let body = fields.take(17)?;
    let digest = digest_for(body, payload_type)?;
    let payload_sha384: [u8; 48] = Sha384::digest(payload).into();
    if digest != payload_sha384 {
        return Err(SignatureError::Violation(SignatureViolation::PayloadDigest));
    }
    // Parse the remaining fields here too, so no trailing or duplicate
    // envelope is ignored before the signature check.
    fields.take(4)?;
    fields.take(16)?;
    fields.end()?;
    Ok(Evidence {
        signature: verify_manifest(manifest)?,
        payload_sha384,
    })
}

/// Verify the manifest signature without asserting coverage of any payload.
/// Useful when an IPSW supplies a manifest that does not cover SEP at all.
pub fn verify_manifest(manifest: &[u8]) -> Result<ManifestEvidence, SignatureError> {
    if manifest.len() > MAX_MANIFEST_BYTES {
        return Err(SignatureError::Violation(SignatureViolation::ManifestLimit));
    }
    let mut fields = der::sequence(manifest)?;
    if fields.take(22)?.value != b"IM4M" {
        return Err(SignatureError::Violation(SignatureViolation::ManifestType));
    }
    if fields.take(2)?.value != [0] {
        return Err(SignatureError::Violation(
            SignatureViolation::ManifestVersion,
        ));
    }
    let body = fields.take(17)?;
    let signature = fields.take(4)?.value;
    let mut chain = Cursor(fields.take(16)?.value);
    fields.end()?;
    let mut certificates: Vec<Certificate<'_>> = Vec::new();
    while !chain.0.is_empty() {
        if certificates.len() == MAX_CERTIFICATES {
            return Err(SignatureError::Violation(
                SignatureViolation::CertificateLimit,
            ));
        }
        let encoded = chain.take(16)?.encoded;
        if certificates.iter().any(|c| c.encoded == encoded) {
            return Err(SignatureError::Violation(
                SignatureViolation::DuplicateCertificate,
            ));
        }
        certificates.push(certificate(encoded)?);
    }
    let leaf = certificates.first().ok_or(SignatureError::Violation(
        SignatureViolation::MissingCertificate,
    ))?;
    leaf.key.verify(body.encoded, signature, Hash::Sha384)?;
    for pair in certificates.windows(2) {
        let [child, issuer] = pair else {
            unreachable!()
        };
        if child.issuer != issuer.subject {
            return Err(SignatureError::Violation(
                SignatureViolation::CertificateIssuer,
            ));
        }
        issuer.key.verify(child.tbs, child.signature, child.hash)?;
    }
    Ok(ManifestEvidence {
        manifest_sha384: Sha384::digest(manifest).into(),
        leaf_certificate_sha384: Sha384::digest(leaf.encoded).into(),
        issuer_links: certificates.len() - 1,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn inputs() -> (Vec<u8>, Vec<u8>) {
        // Independent OpenSSL signature/certificate generated for this test.
        // Synthetic payload; none of this fixture comes from Apple.
        (hex::decode("302c1604494d3450160473657069160a5374656c612074657374041273796e746865746963206669726d77617265").unwrap(), hex::decode("308204451604494d344d0201003174ff84ea859c426d306b16044d414e423163ff84ea859c500a300816044d414e503100ff879b95e0694b30491604736570693141ff84a29da6543a30381604444753540430232a817a2a4b08275b2969cf0507c7268516d6c6d34f0ec9b386ba3be376dcd65ee2192a0ffb1b1cb1ad1eef2ff6cd2f048201002f3d5e4f39c9a50c7259541e2bad2f9df59c63815cc3d5cc1e2949abe6eb41058cb77bb44f9021cab50b336d3231745580e2f0a463c0060b7e4c46031032658f12e115c46d4e073fe461db5e0b010ceb8f98c08c3524f85524b1ca28d38f89899d9997a2fdc01b3f267cdf8b7155dfab180621497d9279c6b07fbe3d85dd2e3abb3eff1d09e8174641d6712221d2cc97efd64244a48a76464d10fb98580c3bb8365a6b75708042f3753851f2eb4b0929585fd16171e03921776097174b50e07968ef65d53d4497ea9edb1b35743d8206c557c37e4fa57572bd88e65efbb7534593175b3ad15497ce5ad5ffc98640c7864bbb313354d2562dba1e7f4c39a50549308202be308202ba308201a2020900ba94439adfb63958300d06092a864886f70d01010c0500301f311d301b06035504030c145374656c612d53796e7468657469632d54657374301e170d3236313031383230333130375a170d3237313031383230333130375a301f311d301b06035504030c145374656c612d53796e7468657469632d5465737430820122300d06092a864886f70d01010105000382010f003082010a0282010100ab6a5a81c1a2b0afdd4e24b554773cb83c418a9594bdc84f2e4045d690a63615fce9c9714f435419009c32feec337d472cd0a13ea6278c8a669abca6606789f3f33513d095d92a1e3df2ea12e3b2052d1ef0309e6e85858f80b501f82e84f5e303b206582e5a78832653ccb28542711a1b60af67fb5b8f13ca7a42d2acd2090c2deac96f1d3f1c33460b6d42261132bcb86a75069eb44abb156ca52c7e486a944b689b6a1aaf23403d6f2ae0427115e8a978d6a24a9c72023c6bc88a8f3d8a48d87a2a451b0cc664e868bbad175b40a329e36cc8bd5ce1c0a23c9bcb0050e69e100efb6047d2df38782c449725f64735214f1da788728f73caa01238494b97cf0203010001300d06092a864886f70d01010c05000382010100207343bd20e6c2cd8359ca0604f30c64cf4a1c2b0a3841415f8e5adb11fe529da4dad8703f7bd582ed3affd5c2c5ca4dc72fc0532271935df5075c51cf8b402524b157eae56fd07fae8a3bc3903a6ba487bd5b326433022b8de09a35fbdc171950cdcd3ed20aa3d9c8ec4c0e168b51c30292af61fdd496abcfcac3ad7ec20850f96da791f5009180934146c5f2b8b955f5af83974fa66854768033d28e8dd624307b14a669eb98a87861f5334c32ec632e8eb5f670c1d6a8d4c0f42d214855205aede6e6d4ecc364b17e66e739c819667c2a95d338f52b8fe3a5cb9ac45b3cb8426f8ca12cba2a8f7ef2271f78cb4ec391d1d865c4eda4c538070bb04815bf66").unwrap())
    }

    #[test]
    fn signed_manifest_binds_payload_but_a_supplied_leaf_is_not_a_trust_anchor() {
        let (payload, manifest) = inputs();
        let evidence = inspect(&payload, &manifest).unwrap();
        assert_eq!(evidence.signature.issuer_links, 0);
        assert_eq!(
            evidence.payload_sha384,
            <[u8; 48]>::from(Sha384::digest(&payload))
        );
        let mut altered = payload.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert_eq!(
            inspect(&altered, &manifest),
            Err(SignatureError::Violation(SignatureViolation::PayloadDigest))
        );
        for length in 0..manifest.len() {
            assert!(inspect(&payload, &manifest[..length]).is_err());
        }
        let mut fields = der::sequence(&manifest).unwrap();
        fields.take(22).unwrap();
        fields.take(2).unwrap();
        fields.take(17).unwrap();
        let signature = fields.take(4).unwrap().value;
        let offset = signature.as_ptr() as usize - manifest.as_ptr() as usize;
        let mut modified = manifest.clone();
        modified[offset] ^= 1;
        assert_eq!(
            inspect(&payload, &modified),
            Err(SignatureError::Rsa(rsa::Error::SignatureMismatch))
        );
        let mut excess = manifest.clone();
        excess.push(0);
        assert!(inspect(&payload, &excess).is_err());
        assert!(inspect(&payload, &alloc::vec![0; MAX_MANIFEST_BYTES+1]).is_err());
        // Independent synthetic issuer key, RSA/SHA-256 child certificate,
        // and SHA-384 manifest. Supplied-chain verification still grants no trust.
        let chain=hex::decode("308202b43082019c020102300d06092a864886f70d01010b05003021311f301d06035504030c165374656c612d53796e7468657469632d497373756572301e170d3236313031383230343831305a170d3237313031383230343831305a301f311d301b06035504030c145374656c612d53796e7468657469632d4c65616630820122300d06092a864886f70d01010105000382010f003082010a0282010100ab6a5a81c1a2b0afdd4e24b554773cb83c418a9594bdc84f2e4045d690a63615fce9c9714f435419009c32feec337d472cd0a13ea6278c8a669abca6606789f3f33513d095d92a1e3df2ea12e3b2052d1ef0309e6e85858f80b501f82e84f5e303b206582e5a78832653ccb28542711a1b60af67fb5b8f13ca7a42d2acd2090c2deac96f1d3f1c33460b6d42261132bcb86a75069eb44abb156ca52c7e486a944b689b6a1aaf23403d6f2ae0427115e8a978d6a24a9c72023c6bc88a8f3d8a48d87a2a451b0cc664e868bbad175b40a329e36cc8bd5ce1c0a23c9bcb0050e69e100efb6047d2df38782c449725f64735214f1da788728f73caa01238494b97cf0203010001300d06092a864886f70d01010b05000382010100849d53646701487f31fa1fa5edf4b821490e41f6debb7e241902fa0e28966afc3129e2352715e589e045a42d35daa1bbc75055f7e9ecd9f98501daacbb319fe19b4c6852713deef47c9f32213ddb36948c8c806f576878bbc27f55d5741d0b38dbf50df1b379b8a9372e563b0f85022e5f97e2a538349a9ec2427bf714bb5d43680ff1ad0a28bced2a2fffca6b98a2c2b8fde2800f6254241e1b45c4b6582b7b575910d911aabfe6dab90ba954d8dda6a9f6c447675f8e399b36cd08260d8f0fcf4b9fa9d38f45a97ec58f1ea11ade48520bb01744fe95357f77e7f28954f76407fa692f711ffffe9a679dedc7d0fc51f3e4258f2c50140e75bd133b0b989bed308202be308201a6020900ce5853631ed4493f300d06092a864886f70d01010c05003021311f301d06035504030c165374656c612d53796e7468657469632d497373756572301e170d3236313031383230343831305a170d3237313031383230343831305a3021311f301d06035504030c165374656c612d53796e7468657469632d49737375657230820122300d06092a864886f70d01010105000382010f003082010a02820101009de1e3b8d539f560b00365077cc29bf0a21093dde9e3e8cf3cd3a727af16f3519788f0fb39b967b9ca292a925c28849ef4d27a6490e4de26a40e1590a0aca35310e1029b7e1c046f1405ad3114a99cfd5572785f1e534735c6902235fdef88a2d86913f5e624ae3e781a6cb18a43d5d0c0c355c554440c95ead2bc05511f1ade3d16eb710b314fa77ba233c3f5044ca4ac594e733612a1007e5d6a67e2bbaea2543ec0762d72c21d0e86f8cbd99441209442184ada95b80ed8a0a3a09fe07ca65d4ed9913f0d7a6f0beb02155d3911593520e4586cc9ffd187754e5f151b0a705be2fb9ccb307e740e51c04843bc4e6a1ae3ab8f21e11ca0f7d04c5ff8313ac10203010001300d06092a864886f70d01010c05000382010100127b69ff085b6b7afa84c50b6b19482072f9e340db8a5f96414ee0095d8939b662d977500c091cc9d8a637accd8e08788aecb86d2985729e8aaec37f85434b927cf31c92ec0103cf62bdb4ff7efd72ee267a4068cae180a6564b335d52e9932f7601f5d943bc54ff6aff24e0fce91db74819a7a5b48e85f30cf0e3a2f440bc6af33c5d81d081276bba44dcfde2ba102515b33ff2332b3012fce8f2d733a285fe288a700481bb6d896a859b243d08607e786447360641cbf9b72aebf1bdbb606d3f3767a1cfc8a44f17f13dfaecf2f30b114b09c85deaf92d9bc3d57afa2821bbc91e6e65d23692cdbad22227747100d1648e88e4527f87f6e29b17ab078be75e").unwrap();
        let mut fields = der::sequence(&manifest).unwrap();
        let mut prefix = Vec::new();
        for _ in 0..4 {
            prefix.extend_from_slice(fields.next_element().unwrap().encoded);
        }
        let chain_manifest = stela_formats::img4::test_support::der(
            0x30,
            &[
                prefix.clone(),
                stela_formats::img4::test_support::der(0x30, &chain),
            ]
            .concat(),
        );
        assert_eq!(
            inspect(&payload, &chain_manifest)
                .unwrap()
                .signature
                .issuer_links,
            1
        );
        let mut c = Cursor(&chain);
        let child = c.take(16).unwrap().encoded;
        let duplicate = stela_formats::img4::test_support::der(
            0x30,
            &[
                prefix.clone(),
                stela_formats::img4::test_support::der(0x30, &[child, child].concat()),
            ]
            .concat(),
        );
        assert_eq!(
            inspect(&payload, &duplicate),
            Err(SignatureError::Violation(
                SignatureViolation::DuplicateCertificate
            ))
        );
        let mut broken = chain.clone();
        // Last byte of the child is its signature; the manifest's key/body
        // remain intact, so this exercises issuer verification specifically.
        broken[child.len() - 1] ^= 1;
        let broken = stela_formats::img4::test_support::der(
            0x30,
            &[
                prefix,
                stela_formats::img4::test_support::der(0x30, &broken),
            ]
            .concat(),
        );
        assert_eq!(
            inspect(&payload, &broken),
            Err(SignatureError::Rsa(rsa::Error::SignatureMismatch))
        );
    }
}
