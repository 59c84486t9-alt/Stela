use super::*;
use crate::allocator::observation::*;
use alloc::{format, sync::Arc};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
fn initialize() {
    assert_eq!(OUTSTANDING.load(Ordering::Acquire), 0);
}
#[derive(Clone)]
struct Fill {
    fail: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
    byte: u8,
}
impl Fill {
    fn fixture() -> Self {
        Self {
            fail: Arc::new(AtomicBool::new(false)),
            calls: Arc::new(AtomicUsize::new(0)),
            byte: 0x42,
        }
    }
}
impl Entropy for Fill {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        if self.fail.load(Ordering::Acquire) {
            return Err(Error(-1));
        }
        output.fill(self.byte);
        Ok(())
    }
}
#[test]
fn checked_mbed_exchange_agrees_with_independent_stable_implementations() {
    let _serial = SERIAL.lock().unwrap();
    initialize();
    let mut key = Key::new(Group::X25519, Fill::fixture()).unwrap();
    let peer = x25519_dalek::StaticSecret::from([0x45; 32]);
    let public = x25519_dalek::PublicKey::from(&peer);
    let ours = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(key.public()).unwrap());
    assert_eq!(
        key.complete(public.as_bytes()).unwrap(),
        peer.diffie_hellman(&ours).to_bytes()
    );
    drop(key);
    assert_eq!(OUTSTANDING.load(Ordering::Acquire), 0);
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let mut key = Key::new(Group::P256, Fill::fixture()).unwrap();
    let peer = p256::SecretKey::from_slice(&[0x45; 32]).unwrap();
    let public = peer.public_key().to_encoded_point(false);
    let ours = p256::PublicKey::from_sec1_bytes(key.public()).unwrap();
    let expected = p256::ecdh::diffie_hellman(peer.to_nonzero_scalar(), ours.as_affine());
    assert_eq!(
        &key.complete(public.as_bytes()).unwrap(),
        &expected.raw_secret_bytes()[..]
    );
    CHECK_ZERO.store(key.key.as_ptr() as usize, Ordering::Release);
    WAS_ZERO.store(false, Ordering::Release);
    drop(key);
    assert!(WAS_ZERO.load(Ordering::Acquire));
    CHECK_ZERO.store(0, Ordering::Release);
    assert_eq!(OUTSTANDING.load(Ordering::Acquire), 0);
}
#[test]
fn malformed_and_noncontributory_peers_refuse_without_publishing_secret() {
    let _serial = SERIAL.lock().unwrap();
    initialize();
    let mut key = Key::new(Group::X25519, Fill::fixture()).unwrap();
    let mut one = [0u8; 32];
    one[0] = 1;
    for peer in [[0u8; 32], one] {
        assert!(key.complete(&peer).is_err());
    }
    assert!(key.complete(&[9u8; 31]).is_err());
    drop(key);
    let mut key = Key::new(Group::P256, Fill::fixture()).unwrap();
    let mut invalid = [0u8; 65];
    invalid[0] = 4;
    assert!(key.complete(&invalid).is_err());
    invalid.fill(0xff);
    invalid[0] = 4;
    assert!(key.complete(&invalid).is_err());
    assert!(key.complete(&[0]).is_err());
    assert!(key.complete(&[2u8; 33]).is_err());
    drop(key);
    assert_eq!(OUTSTANDING.load(Ordering::Acquire), 0);
}
#[test]
fn entropy_and_allocator_failure_leave_no_key_secret_or_live_allocation() {
    let _serial = SERIAL.lock().unwrap();
    initialize();
    for group in [Group::X25519, Group::P256] {
        let rng = Fill::fixture();
        rng.fail.store(true, Ordering::Release);
        assert!(Key::new(group, rng).is_err());
        assert_eq!(OUTSTANDING.load(Ordering::Acquire), 0);
        for fail_at in [0, 1, 2, 4, 8] {
            FAIL_AT.store(fail_at, Ordering::Release);
            assert!(Key::new(group, Fill::fixture()).is_err());
            FAIL_AT.store(-1, Ordering::Release);
            assert_eq!(OUTSTANDING.load(Ordering::Acquire), 0);
        }
        let rng = Fill::fixture();
        let failed = rng.fail.clone();
        let calls = rng.calls.clone();
        let mut key = Key::new(group, rng).unwrap();
        let peer = Key::new(group, Fill::fixture()).unwrap();
        let before = calls.load(Ordering::Acquire);
        failed.store(true, Ordering::Release);
        assert!(key.complete(peer.public()).is_err());
        assert!(calls.load(Ordering::Acquire) > before);
        let mut output = [0xa5; 32];
        // SAFETY: exclusive exact key and live concrete RNG/peer/output; this
        // failed blinding source must not publish partial bytes.
        let status = unsafe {
            stela_mbed_kx_shared(
                key.key.as_ptr(),
                peer.public().as_ptr(),
                peer.public().len(),
                random::<Fill>,
                core::ptr::from_mut(&mut key.rng).cast(),
                output.as_mut_ptr(),
                output.len(),
            )
        };
        assert_ne!(status, 0);
        assert_eq!(output, [0xa5; 32]);
        drop(key);
        drop(peer);
        assert_eq!(OUTSTANDING.load(Ordering::Acquire), 0);
    }
}
#[test]
fn failed_generation_does_not_mutate_raw_ffi_outputs() {
    let _serial = SERIAL.lock().unwrap();
    initialize();
    for group in [Group::X25519, Group::P256] {
        let mut rng = Fill::fixture();
        rng.fail.store(true, Ordering::Release);
        let mut key = core::ptr::dangling_mut::<Opaque>();
        let original = key;
        let mut public = [0xa5; 65];
        let mut length = 123;
        // SAFETY: live output slots and synchronous concrete RNG; the
        // sentinel pointer is never dereferenced and must remain unchanged.
        let status = unsafe {
            stela_mbed_kx_new(
                group as c_uint,
                random::<Fill>,
                core::ptr::from_mut(&mut rng).cast(),
                &mut key,
                public.as_mut_ptr(),
                public.len(),
                &mut length,
            )
        };
        assert_ne!(status, 0);
        assert_eq!(key, original);
        assert_eq!(length, 123);
        assert_eq!(public, [0xa5; 65]);
        assert_eq!(OUTSTANDING.load(Ordering::Acquire), 0);
    }
}

#[test]
fn checked_verification_matches_independent_openssl_signatures_and_refuses_mutations() {
    let _serial = SERIAL.lock().unwrap();
    initialize();
    let message = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/message.bin"
    ));
    {
        let public = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rsa.pub"
        ));
        let signature = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rsa-1-256.sig"
        ));
        verify(1, 256, public, message, signature).unwrap();
        assert!(verify(1, 256, public, b"wrong message", signature).is_err());
        assert!(verify(1, 256, public, message, &signature[..signature.len() - 1]).is_err());
        let mut corrupt = signature.to_vec();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(verify(1, 256, public, message, &corrupt).is_err());
        assert!(verify(1, 160, public, message, signature).is_err());
    }
    {
        let public = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rsa.pub"
        ));
        let signature = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rsa-2-256.sig"
        ));
        verify(2, 256, public, message, signature).unwrap();
        assert!(verify(2, 256, public, b"wrong message", signature).is_err());
        assert!(verify(2, 256, public, message, &signature[..signature.len() - 1]).is_err());
        let mut corrupt = signature.to_vec();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(verify(2, 256, public, message, &corrupt).is_err());
        assert!(verify(2, 160, public, message, signature).is_err());
    }
    {
        let public = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rsa.pub"
        ));
        let signature = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rsa-1-384.sig"
        ));
        verify(1, 384, public, message, signature).unwrap();
        assert!(verify(1, 384, public, b"wrong message", signature).is_err());
        assert!(verify(1, 384, public, message, &signature[..signature.len() - 1]).is_err());
        let mut corrupt = signature.to_vec();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(verify(1, 384, public, message, &corrupt).is_err());
        assert!(verify(1, 160, public, message, signature).is_err());
    }
    {
        let public = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rsa.pub"
        ));
        let signature = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rsa-2-384.sig"
        ));
        verify(2, 384, public, message, signature).unwrap();
        assert!(verify(2, 384, public, b"wrong message", signature).is_err());
        assert!(verify(2, 384, public, message, &signature[..signature.len() - 1]).is_err());
        let mut corrupt = signature.to_vec();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(verify(2, 384, public, message, &corrupt).is_err());
        assert!(verify(2, 160, public, message, signature).is_err());
    }
    {
        let public = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rsa.pub"
        ));
        let signature = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rsa-1-512.sig"
        ));
        verify(1, 512, public, message, signature).unwrap();
        assert!(verify(1, 512, public, b"wrong message", signature).is_err());
        assert!(verify(1, 512, public, message, &signature[..signature.len() - 1]).is_err());
        let mut corrupt = signature.to_vec();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(verify(1, 512, public, message, &corrupt).is_err());
        assert!(verify(1, 160, public, message, signature).is_err());
    }
    {
        let public = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rsa.pub"
        ));
        let signature = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/rsa-2-512.sig"
        ));
        verify(2, 512, public, message, signature).unwrap();
        assert!(verify(2, 512, public, b"wrong message", signature).is_err());
        assert!(verify(2, 512, public, message, &signature[..signature.len() - 1]).is_err());
        let mut corrupt = signature.to_vec();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(verify(2, 512, public, message, &corrupt).is_err());
        assert!(verify(2, 160, public, message, signature).is_err());
    }
    {
        let public = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/p256.pub"
        ));
        let signature = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/p256-3-256.sig"
        ));
        verify(3, 256, public, message, signature).unwrap();
        assert!(verify(3, 256, public, b"wrong message", signature).is_err());
        assert!(verify(3, 256, public, message, &signature[..signature.len() - 1]).is_err());
        let mut corrupt = signature.to_vec();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(verify(3, 256, public, message, &corrupt).is_err());
        assert!(verify(3, 160, public, message, signature).is_err());
    }
    {
        let public = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/p256.pub"
        ));
        let signature = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/p256-3-384.sig"
        ));
        verify(3, 384, public, message, signature).unwrap();
        assert!(verify(3, 384, public, b"wrong message", signature).is_err());
        assert!(verify(3, 384, public, message, &signature[..signature.len() - 1]).is_err());
        let mut corrupt = signature.to_vec();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(verify(3, 384, public, message, &corrupt).is_err());
        assert!(verify(3, 160, public, message, signature).is_err());
    }
    {
        let public = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/p256.pub"
        ));
        let signature = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/p256-3-512.sig"
        ));
        verify(3, 512, public, message, signature).unwrap();
        assert!(verify(3, 512, public, b"wrong message", signature).is_err());
        assert!(verify(3, 512, public, message, &signature[..signature.len() - 1]).is_err());
        let mut corrupt = signature.to_vec();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(verify(3, 512, public, message, &corrupt).is_err());
        assert!(verify(3, 160, public, message, signature).is_err());
    }
    {
        let public = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/p384.pub"
        ));
        let signature = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/p384-4-256.sig"
        ));
        verify(4, 256, public, message, signature).unwrap();
        assert!(verify(4, 256, public, b"wrong message", signature).is_err());
        assert!(verify(4, 256, public, message, &signature[..signature.len() - 1]).is_err());
        let mut corrupt = signature.to_vec();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(verify(4, 256, public, message, &corrupt).is_err());
        assert!(verify(4, 160, public, message, signature).is_err());
    }
    {
        let public = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/p384.pub"
        ));
        let signature = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/p384-4-384.sig"
        ));
        verify(4, 384, public, message, signature).unwrap();
        assert!(verify(4, 384, public, b"wrong message", signature).is_err());
        assert!(verify(4, 384, public, message, &signature[..signature.len() - 1]).is_err());
        let mut corrupt = signature.to_vec();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(verify(4, 384, public, message, &corrupt).is_err());
        assert!(verify(4, 160, public, message, signature).is_err());
    }
    {
        let public = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/p384.pub"
        ));
        let signature = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/p384-4-512.sig"
        ));
        verify(4, 512, public, message, signature).unwrap();
        assert!(verify(4, 512, public, b"wrong message", signature).is_err());
        assert!(verify(4, 512, public, message, &signature[..signature.len() - 1]).is_err());
        let mut corrupt = signature.to_vec();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(verify(4, 512, public, message, &corrupt).is_err());
        assert!(verify(4, 160, public, message, signature).is_err());
    }
    assert_eq!(OUTSTANDING.load(Ordering::Acquire), 0);
}
#[test]
fn verification_rejects_noncanonical_keys_signatures_and_allocation_failure() {
    let _serial = SERIAL.lock().unwrap();
    initialize();
    let message = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/message.bin"
    ));
    let public = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/p256.pub"
    ));
    let signature = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/p256-3-256.sig"
    ));
    let mut trailing = signature.to_vec();
    trailing.push(0);
    assert!(verify(3, 256, public, message, &trailing).is_err());
    assert!(verify(3, 256, public, message, b"\x30\x06\x02\x01\xff\x02\x01\x01").is_err());
    assert!(
        verify(
            3,
            256,
            public,
            message,
            b"\x30\x07\x02\x02\x00\x01\x02\x01\x01"
        )
        .is_err()
    );
    assert!(verify(4, 256, public, message, signature).is_err());
    assert!(verify(3, 256, &public[..64], message, signature).is_err());
    FAIL_AT.store(0, Ordering::Release);
    assert!(verify(3, 256, public, message, signature).is_err());
    FAIL_AT.store(-1, Ordering::Release);
    assert_eq!(OUTSTANDING.load(Ordering::Acquire), 0);
}

#[test]
fn digest_and_hmac_match_independent_vectors_and_wipe_all_backend_allocations() {
    let _serial = SERIAL.lock().unwrap();
    initialize();
    CHECK_ALL_FREES.store(true, Ordering::Release);
    NONZERO_FREES.store(0, Ordering::Release);
    fn hex(bytes: &[u8]) -> std::string::String {
        bytes.iter().map(|x| format!("{x:02x}")).collect()
    }
    let mut sha = Digest::new(256, None).unwrap();
    sha.update(b"a").unwrap();
    let mut fork = sha.try_clone().unwrap();
    sha.update(b"bc").unwrap();
    fork.update(b" different").unwrap();
    assert_eq!(
        hex(&sha.finish().unwrap()),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_ne!(
        hex(&fork.finish().unwrap()),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let mut sha = Digest::new(384, None).unwrap();
    sha.update(b"abc").unwrap();
    assert_eq!(
        hex(&sha.finish().unwrap()),
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    );
    // RFC4231 case1, independent published known answers.
    for (bits, expected) in [
        (
            256,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        (
            384,
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
        ),
    ] {
        let mut hmac = Digest::new(bits, Some(&[0x0b; 20])).unwrap();
        assert!(hmac.try_clone().is_err());
        hmac.update(b"Hi ").unwrap();
        hmac.update(b"There").unwrap();
        let mut sentinel = [0xa5; 64];
        assert_ne!(
            // SAFETY: live affine context and writable sentinel, mismatched
            // output length is rejected before any output write.
            unsafe { stela_mbed_md_finish(hmac.state.as_ptr(), sentinel.as_mut_ptr(), 64) },
            0
        );
        assert_eq!(sentinel, [0xa5; 64]);
        assert_eq!(hex(&hmac.finish().unwrap()), expected);
    }
    for fail in 0..4 {
        FAIL_AT.store(fail, Ordering::Release);
        let attempt = Digest::new(256, Some(b"key"));
        FAIL_AT.store(-1, Ordering::Release);
        drop(attempt);
        assert_eq!(OUTSTANDING.load(Ordering::Acquire), 0);
    }
    CHECK_ALL_FREES.store(false, Ordering::Release);
    assert_eq!(NONZERO_FREES.load(Ordering::Acquire), 0);
    assert_eq!(OUTSTANDING.load(Ordering::Acquire), 0);
}

mod channel;
