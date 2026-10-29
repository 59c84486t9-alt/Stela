//! WebPKI signature descriptors delegate to checked public backend APIs.
use rustls::{
    SignatureScheme,
    crypto::WebPkiSupportedAlgorithms,
    pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id},
};
#[derive(Debug)]
struct Verify {
    kind: u32,
    bits: u32,
    key: AlgorithmIdentifier,
    signature: AlgorithmIdentifier,
}
impl SignatureVerificationAlgorithm for Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        self.key
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        self.signature
    }
    fn verify_signature(
        &self,
        key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        crate::backend::verify(self.kind, self.bits, key, message, signature)
            .map_err(|_| InvalidSignature)
    }
}
macro_rules! verifier {
    ($name:ident,$kind:expr,$bits:expr,$key:ident,$signature:ident) => {
        static $name: Verify = Verify {
            kind: $kind,
            bits: $bits,
            key: alg_id::$key,
            signature: alg_id::$signature,
        };
    };
}
verifier!(P256_256, 3, 256, ECDSA_P256, ECDSA_SHA256);
verifier!(P256_384, 3, 384, ECDSA_P256, ECDSA_SHA384);
verifier!(P384_256, 4, 256, ECDSA_P384, ECDSA_SHA256);
verifier!(P384_384, 4, 384, ECDSA_P384, ECDSA_SHA384);
verifier!(RSA256, 1, 256, RSA_ENCRYPTION, RSA_PKCS1_SHA256);
verifier!(RSA384, 1, 384, RSA_ENCRYPTION, RSA_PKCS1_SHA384);
verifier!(RSA512, 1, 512, RSA_ENCRYPTION, RSA_PKCS1_SHA512);
verifier!(PSS256, 2, 256, RSA_ENCRYPTION, RSA_PSS_SHA256);
verifier!(PSS384, 2, 384, RSA_ENCRYPTION, RSA_PSS_SHA384);
verifier!(PSS512, 2, 512, RSA_ENCRYPTION, RSA_PSS_SHA512);
pub(crate) static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        &P256_256, &P256_384, &P384_256, &P384_384, &RSA256, &RSA384, &RSA512, &PSS256, &PSS384,
        &PSS512,
    ],
    mapping: &[
        (
            SignatureScheme::ECDSA_NISTP256_SHA256,
            &[&P256_256, &P384_256],
        ),
        (
            SignatureScheme::ECDSA_NISTP384_SHA384,
            &[&P384_384, &P256_384],
        ),
        (SignatureScheme::RSA_PSS_SHA256, &[&PSS256]),
        (SignatureScheme::RSA_PSS_SHA384, &[&PSS384]),
        (SignatureScheme::RSA_PSS_SHA512, &[&PSS512]),
        (SignatureScheme::RSA_PKCS1_SHA256, &[&RSA256]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[&RSA384]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[&RSA512]),
    ],
};
