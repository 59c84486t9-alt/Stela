//! The SEP side of BootPolicy (`pnon`): the LocalPolicy nonces restored and
//! the installed boot bind to, and the Stela-owned signing of the macOS
//! default LocalPolicy.
//!
//! Two distinct trust owners meet here (docs/research/restore-trust.md):
//!
//! - The **recoveryOS** LocalPolicy is verified by libbootpolicy against
//!   Apple's fixed roots, so Stela cannot sign it; the lead's restore client
//!   obtains it through an opt-in Apple TSS request. The SEP's only part is a
//!   faithful recoveryOS policy **nonce**: restored drives
//!   `bootpolicy_update_recoveryos_policy_nonce_begin`,
//!   `..._get_proposed_recoveryos_policy_nonce_digest`, `..._end` and
//!   `..._reset`, and the stored policy's `ronh` is exactly the 48-byte
//!   SHA-384 of the proposed nonce (restore-trust §5, B 0x1cab4..0x1cb08).
//! - The **macOS default** LocalPolicy (`generate_default_local_policy`) and
//!   its paired recoveryOS policy are SEP-signed with Stela's own key.
//!   [`PolicyKey`] derives it from the machine's roots and signs the
//!   [`local_policy`](stela_formats::local_policy) file; Stela's boot verifies
//!   with the public key alone, so no other machine's policy passes. Their
//!   `lpnh` is the SHA-384 of the macOS policy nonce, on the same lifecycle.
//!
//! The raw nonces are durable in the anti-replay store ([`super::store`]); the
//! proposed, not-yet-committed nonce of an in-progress update lives here in
//! RAM and is discarded by `reset` or a power cycle. These are the recovered
//! nonce lifecycle used by the native trust policy. The recovered empty-body
//! local and recoveryOS commands bind it through `boot_policy::nonces`, and
//! `boot_policy::local_policy` signs on the wire; authenticated owner-bearing
//! bodies remain unbound. `--sep-observe` can keep their requests without
//! inventing authorization.
use super::{
    Entropy,
    store::{Backend, Nonces, POLICY_NONCE_BYTES, PolicyNonce},
};
use crate::Result;
use alloc::vec::Vec;
use p384::ecdsa::{DerSignature, SigningKey, VerifyingKey, signature::Signer};
use sha2::{Digest, Sha384};
use stela_contracts::refuse;
use stela_formats::local_policy::Policy;
use zeroize::Zeroizing;

/// The LocalPolicy digest size: `ronh`, `lpnh` and `nsih` are each SHA-384.
pub const DIGEST_BYTES: usize = 48;
/// The domain of the LocalPolicy signing key's scalar.
const SCALAR_DOMAIN: &[u8] = b"Stela SEP LocalPolicy key v1\0";

/// An in-progress policy-nonce update: the proposed nonce awaiting `end`.
pub struct Update {
    which: PolicyNonce,
    proposed: Zeroizing<[u8; POLICY_NONCE_BYTES]>,
}

impl Update {
    /// `bootpolicy_get_proposed_..._nonce_digest`: the policy's `ronh`/`lpnh`,
    /// the SHA-384 of the proposed nonce.
    pub fn proposed_digest(&self) -> [u8; DIGEST_BYTES] {
        Sha384::digest(*self.proposed).into()
    }
}

/// `bootpolicy_update_..._nonce_begin`: propose a fresh nonce for `which`. The
/// durable nonce is unchanged until [`commit`].
pub fn begin(which: PolicyNonce, entropy: &mut dyn Entropy) -> Result<Update> {
    let mut proposed = Zeroizing::new([0; POLICY_NONCE_BYTES]);
    entropy.fill(&mut *proposed)?;
    Ok(Update { which, proposed })
}

/// `bootpolicy_update_..._nonce_end`: commit the proposed nonce as the durable
/// policy nonce. The old nonce is replaced only here, so a failed or reset
/// update never advances it.
pub fn commit<B: Backend>(store: &mut Nonces<B>, update: Update) -> Result<[u8; DIGEST_BYTES]> {
    let digest = update.proposed_digest();
    store.commit_policy_nonce(update.which, Some(*update.proposed))?;
    Ok(digest)
}

/// `bootpolicy_update_..._nonce_reset`: discard an in-progress update and clear
/// the durable nonce (the policy it bound to is being withdrawn).
pub fn reset<B: Backend>(store: &mut Nonces<B>, which: PolicyNonce) -> Result<()> {
    store.commit_policy_nonce(which, None)
}

/// The committed policy nonce's digest (`ronh`/`lpnh`), if one is committed.
pub fn committed_digest<B: Backend>(
    store: &Nonces<B>,
    which: PolicyNonce,
) -> Result<Option<[u8; DIGEST_BYTES]>> {
    Ok(store
        .policy_nonce(which)?
        .map(|nonce| Sha384::digest(nonce).into()))
}

/// The machine's LocalPolicy signing key: ECDSA P-384, a secret of this SEP
/// derived from its roots through [`Nonces::policy_key_seed`]. A policy
/// signed on one machine fails on another. This is Stela's own key, not a
/// claim to reproduce Apple's SEP key.
pub struct PolicyKey(SigningKey);

impl PolicyKey {
    pub fn derive(seed: &[u8; 32]) -> Result<Self> {
        // A digest out of the scalar range is astronomically unlikely, and
        // the counter steps past one.
        for counter in 0..=u8::MAX {
            let scalar = Zeroizing::new(<[u8; DIGEST_BYTES]>::from(
                Sha384::new()
                    .chain_update(SCALAR_DOMAIN)
                    .chain_update([counter])
                    .chain_update(seed)
                    .finalize(),
            ));
            if let Ok(key) = SigningKey::from_slice(&*scalar) {
                return Ok(Self(key));
            }
        }
        Err(refuse!("no LocalPolicy signing key derives from the seed"))
    }

    /// What Stela's boot verifies a policy with.
    pub fn public(&self) -> &VerifyingKey {
        self.0.verifying_key()
    }

    /// The signed policy file.
    pub fn sign(&self, policy: &Policy) -> Vec<u8> {
        let signature: DerSignature = self.0.sign(&policy.signed());
        policy.file(signature.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{keys::Roots, store::Volatile};
    use super::*;
    use alloc::boxed::Box;

    fn entropy(seed: u8) -> impl FnMut(&mut [u8]) -> Result<()> {
        let mut next = seed;
        move |bytes: &mut [u8]| {
            for b in bytes {
                next = next.wrapping_add(1);
                *b = next;
            }
            Ok(())
        }
    }

    fn roots() -> Roots {
        Roots::provisioned([7; 32], [8; 32], 0xbeef_0001).unwrap()
    }

    fn store() -> Nonces<Box<dyn Backend>> {
        let backend: Box<dyn Backend> = Box::new(Volatile::default());
        Nonces::provision(&roots(), backend).unwrap()
    }

    #[test]
    fn the_recovery_nonce_lifecycle_binds_ronh_and_only_end_advances_it() {
        let mut store = store();
        assert_eq!(committed_digest(&store, PolicyNonce::Recovery), Ok(None));
        // begin proposes; the durable nonce is still absent until end.
        let update = begin(PolicyNonce::Recovery, &mut entropy(0x10)).unwrap();
        let proposed = update.proposed_digest();
        assert_eq!(proposed.len(), DIGEST_BYTES);
        assert_eq!(committed_digest(&store, PolicyNonce::Recovery), Ok(None));
        // end commits; the committed digest matches the proposed one.
        assert_eq!(commit(&mut store, update), Ok(proposed));
        assert_eq!(
            committed_digest(&store, PolicyNonce::Recovery),
            Ok(Some(proposed))
        );
        // A second begin that is reset leaves the committed nonce in place
        // only until reset, which withdraws it.
        let _ = begin(PolicyNonce::Recovery, &mut entropy(0x40)).unwrap();
        reset(&mut store, PolicyNonce::Recovery).unwrap();
        assert_eq!(committed_digest(&store, PolicyNonce::Recovery), Ok(None));
        // The macOS nonce is a separate slot.
        let macos = begin(PolicyNonce::MacOs, &mut entropy(0x80)).unwrap();
        let macos_digest = commit(&mut store, macos).unwrap();
        assert_eq!(
            committed_digest(&store, PolicyNonce::MacOs),
            Ok(Some(macos_digest))
        );
        assert_eq!(committed_digest(&store, PolicyNonce::Recovery), Ok(None));
        // Nonces are durable across reopen.
        let store = Nonces::open(&roots(), store.into_backend()).unwrap();
        assert_eq!(
            committed_digest(&store, PolicyNonce::MacOs),
            Ok(Some(macos_digest))
        );
    }

    #[test]
    fn a_policy_verifies_only_under_its_own_machines_key() {
        use stela_formats::local_policy::{self, Security};
        let policy = Policy {
            volume_group: [1; 16],
            next_stage: [2; DIGEST_BYTES],
            nonce: [3; DIGEST_BYTES],
            splat: None,
            paired: None,
            security: Security::Full,
        };
        let key = PolicyKey::derive(&[7; 32]).unwrap();
        let file = key.sign(&policy);
        assert_eq!(local_policy::verify(&file, key.public()), Ok(policy));
        // The same seed derives the same key, and another seed another.
        let same = PolicyKey::derive(&[7; 32]).unwrap();
        assert_eq!(same.public(), key.public());
        let other = PolicyKey::derive(&[8; 32]).unwrap();
        assert_eq!(
            local_policy::verify(&file, other.public()),
            Err(local_policy::Error::Signature)
        );
    }
}
