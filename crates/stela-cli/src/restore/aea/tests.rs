use super::*;

fn header(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut payload = Vec::new();
    for (key, value) in entries {
        payload.extend(((5 + key.len() + value.len()) as u32).to_le_bytes());
        payload.extend(key.as_bytes());
        payload.push(0);
        payload.extend(*value);
    }
    let mut bytes = b"AEA1".to_vec();
    bytes.extend(1u32.to_le_bytes());
    bytes.extend((payload.len() as u32).to_le_bytes());
    bytes.extend(payload);
    bytes
}

#[test]
fn metadata_redacts_wrapped_credentials_and_retains_public_endpoint() {
    let bytes = header(&[
        (
            FCS_FIELD,
            b"https://wkms-public.apple.com/fcs-keys/abc_123=",
        ),
        ("saksKey", b"do-not-print-key-material"),
    ]);
    let result = parse(PathBuf::from("own.aea"), 1000, &bytes).unwrap();
    assert_eq!(result.entries.len(), 2);
    assert!(result.public_key_url.unwrap().ends_with("abc_123="));
    let serialized = serde_json::to_string(&result.entries).unwrap();
    assert!(!serialized.contains("do-not-print-key-material"));
    assert!(serialized.contains(&sha256(b"do-not-print-key-material")));
}

#[test]
fn malformed_profile_lengths_keys_and_duplicate_entries_decline() {
    let valid = header(&[("x", b"y")]);
    for end in 0..valid.len() {
        assert!(parse(PathBuf::new(), 1000, &valid[..end]).is_err());
    }
    let mut bad = valid.clone();
    bad[4] = 2;
    assert!(parse(PathBuf::new(), 1000, &bad).is_err());
    let mut bad = valid.clone();
    bad[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(parse(PathBuf::new(), 1000, &bad).is_err());
    for entries in [
        vec![("x", b"y".as_slice()), ("x", b"z".as_slice())],
        vec![("", b"z".as_slice())],
        vec![("bad key", b"z".as_slice())],
    ] {
        assert!(parse(PathBuf::new(), 1000, &header(&entries)).is_err());
    }
    assert!(parse(PathBuf::new(), valid.len() as u64, &valid).is_err());
}

#[test]
fn only_reviewed_public_key_routes_can_be_requested_or_redirected() {
    for url in [
        "http://wkms-public.apple.com/fcs-keys/abc",
        "https://example.com/fcs-keys/abc",
        "https://wkms-public.apple.com:444/fcs-keys/abc",
        "https://wkms-public.apple.com/fcs-keys/a/b",
        "https://wkms-public.apple.com/fcs-keys/%61",
        "https://wkms-public.apple.com/fcs-keys/abc?q=1",
        "https://wkms-public.apple.com/fcs-keys/abc#x",
        "https://user@wkms-public.apple.com/fcs-keys/abc",
    ] {
        assert!(key_url(url, true).is_err(), "{url}");
    }
    let cdn = "https://fcs-keys-pub-prod.cdn-apple.com/fcs-keys/abc=";
    assert!(key_url(cdn, true).is_err());
    assert!(key_url(cdn, false).is_ok());
}

#[test]
fn key_and_receipt_publication_preserves_existing_files() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("recipient.pem");
    let receipt = serde_json::json!({"own_fixture":true});
    publish(&output, b"own-key", &receipt).unwrap();
    assert!(publish(&output, b"replacement", &receipt).is_err());
    assert_eq!(std::fs::read(&output).unwrap(), b"own-key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let other = directory.path().join("other.pem");
    std::fs::write(directory.path().join("other.pem.json"), b"existing").unwrap();
    assert!(publish(&other, b"own-key", &receipt).is_err());
    assert!(!other.exists());
}

/// A deterministic generator for the test's ephemeral HPKE key.
struct Counter(u64);

impl hpke::rand_core::RngCore for Counter {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(1);
        self.0
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        for byte in bytes {
            *byte = self.next_u64() as u8;
        }
    }
}

impl hpke::rand_core::CryptoRng for Counter {}

#[test]
fn archive_key_unwraps_an_fcs_response_sealed_to_the_recipient() -> Result<()> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use hpke::{
        Deserializable, OpModeS, Serializable, aead::AesGcm256, kdf::HkdfSha256,
        kem::DhP256HkdfSha256, single_shot_seal,
    };
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    let secret = p256::SecretKey::from_slice(&[7; 32])?;
    let pem = secret.to_pkcs8_pem(LineEnding::LF)?;
    let recipient = <DhP256HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(
        &secret.public_key().to_sec1_bytes(),
    )
    .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let archive = [0x5a; ARCHIVE_KEY_BYTES];
    let (encapsulated, wrapped) = single_shot_seal::<AesGcm256, HkdfSha256, DhP256HkdfSha256, _>(
        &OpModeS::Base,
        &recipient,
        &[],
        &archive,
        &[],
        &mut Counter(1),
    )
    .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let response = serde_json::json!({
        "enc-request": STANDARD.encode(encapsulated.to_bytes()),
        "wrapped-key": STANDARD.encode(wrapped),
    });
    let mut header = b"AEA1".to_vec();
    header.extend(1u32.to_le_bytes());
    header.extend(0u32.to_le_bytes());
    let mut metadata = parse(PathBuf::from("archive.aea"), 1 << 20, &header)?;
    metadata.fcs_response = Some(serde_json::to_vec(&response)?);
    assert_eq!(archive_key(&metadata, &pem)?.as_slice(), archive);
    let other = p256::SecretKey::from_slice(&[9; 32])?.to_pkcs8_pem(LineEnding::LF)?;
    assert!(archive_key(&metadata, &other).is_err());
    Ok(())
}
