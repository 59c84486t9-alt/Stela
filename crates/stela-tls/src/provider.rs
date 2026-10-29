//! Rustls provider over checked key exchange, signature verification and AEADs.
use crate::{Digest, Group, Key};
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};
use rustls::{
    Error, NamedGroup, SignatureScheme, SupportedCipherSuite,
    crypto::{
        self, ActiveKeyExchange, CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom,
        SharedSecret, SupportedKxGroup,
    },
};
use zeroize::Zeroizing;
/// Retained cryptographically secure entropy source. Failure leaves the output
/// unchanged; native integration supplies the actual owned entropy capability.
pub trait EntropySource: Send + Sync {
    fn fill(&self, output: &mut [u8]) -> Result<(), GetRandomFailed>;
}
pub struct ProviderOwner {
    random: Random,
    x25519: ExchangeGroup,
    p256: ExchangeGroup,
}
impl ProviderOwner {
    pub fn new(entropy: Arc<dyn EntropySource>) -> Self {
        Self {
            random: Random(entropy.clone()),
            x25519: ExchangeGroup {
                source: entropy.clone(),
                group: NamedGroup::X25519,
            },
            p256: ExchangeGroup {
                source: entropy,
                group: NamedGroup::secp256r1,
            },
        }
    }
    /// Rustls requires static group/random references. Caller retains this exact
    /// unique provider owner through the whole boot, never replaces its source.
    pub fn provider(&'static self) -> CryptoProvider {
        CryptoProvider {
            cipher_suites: SUITES.to_vec(),
            kx_groups: vec![&self.x25519, &self.p256],
            signature_verification_algorithms: crate::verification::ALGORITHMS,
            secure_random: &self.random,
            key_provider: &NoClientIdentity,
        }
    }
}
struct Random(Arc<dyn EntropySource>);
impl fmt::Debug for Random {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnedEntropy")
    }
}
impl SecureRandom for Random {
    fn fill(&self, output: &mut [u8]) -> Result<(), GetRandomFailed> {
        self.0.fill(output)
    }
}
#[derive(Debug)]
struct NoClientIdentity;
impl KeyProvider for NoClientIdentity {
    fn load_private_key(
        &self,
        _: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, Error> {
        Err(Error::General(
            "native client identity is not configured".into(),
        ))
    }
}
struct ExchangeGroup {
    source: Arc<dyn EntropySource>,
    group: NamedGroup,
}
impl fmt::Debug for ExchangeGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.group.fmt(f)
    }
}
struct SharedEntropy {
    source: Arc<dyn EntropySource>,
    failed: Arc<AtomicBool>,
}
impl crate::Entropy for SharedEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), crate::Error> {
        self.source.fill(output).map_err(|_| {
            self.failed.store(true, Ordering::Release);
            crate::Error(-1)
        })
    }
}
struct Exchange {
    key: Key<SharedEntropy>,
    group: NamedGroup,
    entropy_failed: Arc<AtomicBool>,
}
impl SupportedKxGroup for ExchangeGroup {
    fn name(&self) -> NamedGroup {
        self.group
    }
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let kind = match self.group {
            NamedGroup::X25519 => Group::X25519,
            NamedGroup::secp256r1 => Group::P256,
            _ => unreachable!("private configured groups"),
        };
        let entropy_failed = Arc::new(AtomicBool::new(false));
        let key = Key::new(
            kind,
            SharedEntropy {
                source: self.source.clone(),
                failed: entropy_failed.clone(),
            },
        )
        .map_err(|e| {
            if entropy_failed.load(Ordering::Acquire) {
                Error::FailedToGetRandomBytes
            } else {
                Error::General(alloc::format!("native key generation refused: {}", e.0))
            }
        })?;
        Ok(Box::new(Exchange {
            key,
            group: self.group,
            entropy_failed,
        }))
    }
}
impl ActiveKeyExchange for Exchange {
    fn group(&self) -> NamedGroup {
        self.group
    }
    fn pub_key(&self) -> &[u8] {
        self.key.public()
    }
    fn complete(mut self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let secret = Zeroizing::new(self.key.complete(peer).map_err(|e| {
            if self.entropy_failed.load(Ordering::Acquire) {
                Error::FailedToGetRandomBytes
            } else {
                Error::General(alloc::format!("native key agreement refused: {}", e.0))
            }
        })?);
        Ok(secret.as_slice().into())
    }
}
pub(crate) struct Hash(pub u32);
pub(crate) static SHA256: Hash = Hash(256);
pub(crate) static SHA384: Hash = Hash(384);
struct HashContext(Digest);
impl crypto::hash::Hash for Hash {
    fn start(&self) -> Box<dyn crypto::hash::Context> {
        Box::new(HashContext(
            Digest::new(self.0, None).expect("digest allocation failed before output"),
        ))
    }
    fn hash(&self, data: &[u8]) -> crypto::hash::Output {
        let mut context = self.start();
        context.update(data);
        context.finish()
    }
    fn output_len(&self) -> usize {
        (self.0 / 8) as usize
    }
    fn algorithm(&self) -> crypto::hash::HashAlgorithm {
        match self.0 {
            256 => crypto::hash::HashAlgorithm::SHA256,
            384 => crypto::hash::HashAlgorithm::SHA384,
            _ => unreachable!("private configured digests"),
        }
    }
}
impl crypto::hash::Context for HashContext {
    fn fork_finish(&self) -> crypto::hash::Output {
        crypto::hash::Output::new(
            &self
                .0
                .try_clone()
                .expect("digest clone allocation failed before output")
                .finish()
                .expect("valid digest finalization"),
        )
    }
    fn fork(&self) -> Box<dyn crypto::hash::Context> {
        Box::new(Self(
            self.0
                .try_clone()
                .expect("digest clone allocation failed before output"),
        ))
    }
    fn finish(self: Box<Self>) -> crypto::hash::Output {
        crypto::hash::Output::new(&self.0.finish().expect("valid digest finalization"))
    }
    fn update(&mut self, data: &[u8]) {
        self.0.update(data).expect("valid digest update")
    }
}
pub(crate) struct Hmac(pub u32);
pub(crate) static HMAC256: Hmac = Hmac(256);
pub(crate) static HMAC384: Hmac = Hmac(384);
struct HmacKey {
    bits: u32,
    key: Zeroizing<Vec<u8>>,
}
impl crypto::hmac::Hmac for Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(HmacKey {
            bits: self.0,
            key: Zeroizing::new(key.to_vec()),
        })
    }
    fn hash_output_len(&self) -> usize {
        (self.0 / 8) as usize
    }
}
impl crypto::hmac::Key for HmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        // Rustls' HMAC API is infallible, just like its Rust allocation paths.
        // Backend allocation failure aborts this operation before publishing a tag;
        // it never substitutes empty/zero authentication output.
        let mut context =
            Digest::new(self.bits, Some(&self.key)).expect("HMAC allocation failed before output");
        context.update(first).expect("valid HMAC input");
        for part in middle {
            context.update(part).expect("valid HMAC input")
        }
        context.update(last).expect("valid HMAC input");
        let tag = Zeroizing::new(context.finish().expect("valid HMAC finalization"));
        crypto::hmac::Tag::new(&tag)
    }
    fn tag_len(&self) -> usize {
        (self.bits / 8) as usize
    }
}
macro_rules! suite13 {
    ($name:ident,$id:ident,$hash:ident,$hmac:ident,$cipher:ident,$limit:expr) => {
        static $name: SupportedCipherSuite =
            SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
                common: crypto::CipherSuiteCommon {
                    suite: rustls::CipherSuite::$id,
                    hash_provider: &$hash,
                    confidentiality_limit: $limit,
                },
                hkdf_provider: &crypto::tls13::HkdfUsingHmac(&$hmac),
                aead_alg: &crate::aead::Algorithm::$cipher,
                quic: None,
            });
    };
}
macro_rules! suite12 {
    ($name:ident,$id:ident,$hash:ident,$hmac:ident,$cipher:ident,$sign:ident,$limit:expr) => {
        static $name: SupportedCipherSuite =
            SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
                common: crypto::CipherSuiteCommon {
                    suite: rustls::CipherSuite::$id,
                    hash_provider: &$hash,
                    confidentiality_limit: $limit,
                },
                kx: crypto::KeyExchangeAlgorithm::ECDHE,
                sign: $sign,
                prf_provider: &crypto::tls12::PrfUsingHmac(&$hmac),
                aead_alg: &crate::aead::Algorithm::$cipher,
            });
    };
}
const RSA: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA512,
];
const ECDSA: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
];
suite13!(
    AES128_13,
    TLS13_AES_128_GCM_SHA256,
    SHA256,
    HMAC256,
    Aes128,
    1 << 24
);
suite13!(
    AES256_13,
    TLS13_AES_256_GCM_SHA384,
    SHA384,
    HMAC384,
    Aes256,
    1 << 24
);
suite13!(
    CHACHA_13,
    TLS13_CHACHA20_POLY1305_SHA256,
    SHA256,
    HMAC256,
    Chacha,
    u64::MAX
);
suite12!(
    AES128_RSA,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    SHA256,
    HMAC256,
    Aes128,
    RSA,
    1 << 24
);
suite12!(
    AES256_RSA,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    SHA384,
    HMAC384,
    Aes256,
    RSA,
    1 << 24
);
suite12!(
    CHACHA_RSA,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    SHA256,
    HMAC256,
    Chacha,
    RSA,
    u64::MAX
);
suite12!(
    AES128_ECDSA,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    SHA256,
    HMAC256,
    Aes128,
    ECDSA,
    1 << 24
);
suite12!(
    AES256_ECDSA,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    SHA384,
    HMAC384,
    Aes256,
    ECDSA,
    1 << 24
);
suite12!(
    CHACHA_ECDSA,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    SHA256,
    HMAC256,
    Chacha,
    ECDSA,
    u64::MAX
);
static SUITES: &[SupportedCipherSuite] = &[
    AES128_13,
    AES256_13,
    CHACHA_13,
    AES128_RSA,
    AES256_RSA,
    CHACHA_RSA,
    AES128_ECDSA,
    AES256_ECDSA,
    CHACHA_ECDSA,
];
#[derive(Debug)]
pub enum PolicyError {
    TimeUnavailable,
    TrustUnavailable,
    Configuration(Error),
}
pub(crate) fn client_config_with_roots(
    owner: &'static ProviderOwner,
    time: Arc<dyn rustls::time_provider::TimeProvider>,
    roots: rustls::RootCertStore,
) -> Result<Arc<rustls::ClientConfig>, PolicyError> {
    if time.current_time().is_none() {
        return Err(PolicyError::TimeUnavailable);
    }
    if roots.is_empty() {
        return Err(PolicyError::TrustUnavailable);
    }
    let config = rustls::ClientConfig::builder_with_details(Arc::new(owner.provider()), time)
        .with_safe_default_protocol_versions()
        .map_err(PolicyError::Configuration)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

pub fn client_config(
    owner: &'static ProviderOwner,
    time: Arc<dyn rustls::time_provider::TimeProvider>,
) -> Result<Arc<rustls::ClientConfig>, PolicyError> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    client_config_with_roots(owner, time, roots)
}
