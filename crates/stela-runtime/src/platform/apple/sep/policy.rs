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
//! - The **macOS default** LocalPolicy (`generate_default_local_policy`) is
//!   SEP-signed with Stela's own key. [`PolicyKeys`] derives that key from the
//!   machine's [`Roots`] and both signs a policy (at restore) and verifies one
//!   (at installed boot), so only this machine's SEP admits its own policy.
//!   Its `lpnh` is the SHA-384 of the macOS policy nonce, on the same
//!   lifecycle.
//!
//! The raw nonces are durable in the anti-replay store ([`super::store`]); the
//! proposed, not-yet-committed nonce of an in-progress update lives here in
//! RAM and is discarded by `reset` or a power cycle. These are the recovered
//! nonce lifecycle used by the native trust policy. The recovered empty-body
//! recoveryOS commands bind it through `boot_policy::nonces`; authenticated
//! owner-bearing bodies and macOS policy signing remain unbound to the wire.
//! `--sep-observe` can retain their requests without inventing authorization.
use super::{
    Entropy,
    keys::Roots,
    store::{Backend, Nonces, POLICY_NONCE_BYTES, PolicyNonce},
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha384};
use zeroize::Zeroizing;

/// The LocalPolicy digest size: `ronh`, `lpnh` and `nsih` are each SHA-384.
pub const DIGEST_BYTES: usize = 48;
/// The key-derivation purpose for the macOS LocalPolicy signing key.
const SIGNING_PURPOSE: &[u8] = b"bootpolicy/local-policy-signing/v1";
/// The domain that separates a LocalPolicy signature from other MACs.
const SIGNATURE_DOMAIN: &[u8] = b"Stela SEP LocalPolicy v1\0";

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

    pub fn which(&self) -> PolicyNonce {
        self.which
    }
}

/// `bootpolicy_update_..._nonce_begin`: propose a fresh nonce for `which`. The
/// durable nonce is unchanged until [`commit`].
pub fn begin(which: PolicyNonce, entropy: &mut dyn Entropy) -> Result<Update, &'static str> {
    let mut proposed = Zeroizing::new([0; POLICY_NONCE_BYTES]);
    entropy.fill(&mut *proposed)?;
    Ok(Update { which, proposed })
}

/// `bootpolicy_update_..._nonce_end`: commit the proposed nonce as the durable
/// policy nonce. The old nonce is replaced only here, so a failed or reset
/// update never advances it.
pub fn commit<B: Backend>(
    store: &mut Nonces<B>,
    update: Update,
) -> Result<[u8; DIGEST_BYTES], &'static str> {
    let digest = update.proposed_digest();
    store.commit_policy_nonce(update.which, Some(*update.proposed))?;
    Ok(digest)
}

/// `bootpolicy_update_..._nonce_reset`: discard an in-progress update and clear
/// the durable nonce (the policy it bound to is being withdrawn).
pub fn reset<B: Backend>(store: &mut Nonces<B>, which: PolicyNonce) -> Result<(), &'static str> {
    store.commit_policy_nonce(which, None)
}

/// The committed policy nonce's digest (`ronh`/`lpnh`), if one is committed.
pub fn committed_digest<B: Backend>(
    store: &Nonces<B>,
    which: PolicyNonce,
) -> Result<Option<[u8; DIGEST_BYTES]>, &'static str> {
    Ok(store
        .policy_nonce(which)?
        .map(|nonce| Sha384::digest(nonce).into()))
}

/// The machine's LocalPolicy signing key: a per-machine SEP secret only this
/// SEP holds. Signing uses an HMAC-SHA384 over the policy's authenticated
/// body, so a policy signed on one machine is rejected on another, exactly as
/// a real SEP-signed LocalPolicy is. This is Stela's own signing scheme, not a
/// claim to reproduce Apple's SEP key or its Image4 signature.
pub struct PolicyKeys {
    key: Zeroizing<[u8; 32]>,
}

impl PolicyKeys {
    pub fn derive(roots: &Roots) -> Result<Self, &'static str> {
        Ok(Self {
            key: roots.uid(SIGNING_PURPOSE)?,
        })
    }

    /// The signature over a macOS LocalPolicy's authenticated body (the bytes
    /// the host presents as the policy's signed content).
    pub fn sign(&self, body: &[u8]) -> [u8; DIGEST_BYTES] {
        self.authenticator(body).finalize().into_bytes().into()
    }

    /// Whether `signature` is this machine's SEP signature over `body`. A
    /// different machine, body or signature is rejected.
    pub fn verify(&self, body: &[u8], signature: &[u8]) -> bool {
        self.authenticator(body).verify_slice(signature).is_ok()
    }

    fn authenticator(&self, body: &[u8]) -> Hmac<Sha384> {
        let mut mac = Hmac::<Sha384>::new_from_slice(&*self.key).expect("HMAC accepts any key");
        mac.update(SIGNATURE_DOMAIN);
        mac.update(&(body.len() as u64).to_be_bytes());
        mac.update(body);
        mac
    }
}

#[cfg(test)]
mod tests {
    use super::super::store::Volatile;
    use super::*;
    use alloc::boxed::Box;

    fn entropy(seed: u8) -> impl FnMut(&mut [u8]) -> Result<(), &'static str> {
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
    fn the_macos_policy_signature_is_machine_bound() {
        let keys = PolicyKeys::derive(&roots()).unwrap();
        let body = b"lpol-authenticated-body";
        let signature = keys.sign(body);
        assert!(keys.verify(body, &signature));
        assert!(!keys.verify(b"other body", &signature));
        assert!(!keys.verify(body, &[0; DIGEST_BYTES]));
        assert!(!keys.verify(body, &signature[..DIGEST_BYTES - 1]));
        assert!(!keys.verify(body, &[0; DIGEST_BYTES + 1]));
        for byte in 0..DIGEST_BYTES {
            let mut changed = signature;
            changed[byte] ^= 1;
            assert!(!keys.verify(body, &changed));
        }
        // A different machine's SEP rejects this machine's policy.
        let other = PolicyKeys::derive(&Roots::provisioned([9; 32], [8; 32], 0xbeef_0001).unwrap())
            .unwrap();
        assert!(!other.verify(body, &signature));
        // A different ECID is a different machine too.
        let moved = PolicyKeys::derive(&Roots::provisioned([7; 32], [8; 32], 0xbeef_0002).unwrap())
            .unwrap();
        assert!(!moved.verify(body, &signature));
    }
}
