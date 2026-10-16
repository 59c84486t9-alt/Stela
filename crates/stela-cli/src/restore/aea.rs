//! Bounded inspection of the public IPSW AEA1/profile-1 acquisition envelope.
//! Metadata is unverified until an authenticated archive decoder accepts it.
//! Key bodies and wrapped-key metadata are never part of a JSON report.
use anyhow::{Context, Result, ensure};
use reqwest::{Url, blocking::Client, redirect::Policy};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use stela_core::sha256;

const MAX_METADATA: usize = 64 * 1024;
const MAX_KEY: usize = 64 * 1024;
const FCS_FIELD: &str = "com.apple.wkms.fcs-key-url";
const FCS_RESPONSE_FIELD: &str = "com.apple.wkms.fcs-response";
const MAX_FCS_RESPONSE: usize = 4096;
/// An uncompressed SEC1 P-256 point: the HPKE encapsulated key.
const ENCAPSULATED_BYTES: usize = 65;
/// A 32-byte AES-256 archive key and its 16-byte AES-GCM tag.
const WRAPPED_BYTES: usize = 48;
const ARCHIVE_KEY_BYTES: usize = 32;
const AEA_TOOL: &str = "/usr/bin/aea";

#[derive(Debug, Serialize)]
pub struct Entry {
    pub key: String,
    pub value_bytes: usize,
    pub value_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct Metadata {
    pub kind: &'static str,
    pub schema_version: u32,
    pub source: PathBuf,
    pub source_bytes: u64,
    pub profile: u32,
    pub metadata_bytes: usize,
    pub header_sha256: String,
    pub entries: Vec<Entry>,
    pub public_key_url: Option<String>,
    pub limits: &'static str,
    /// The FCS response holding the HPKE-wrapped archive key; never reported.
    #[serde(skip)]
    fcs_response: Option<Vec<u8>>,
}

fn key_url(text: &str, initial: bool) -> Result<Url> {
    let url = Url::parse(text).context("invalid public AEA key URL")?;
    ensure!(
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.port_or_known_default() == Some(443)
            && url.query().is_none()
            && url.fragment().is_none(),
        "public AEA key URL requires ordinary HTTPS without credentials/query/fragment"
    );
    let allowed = url.host_str() == Some("wkms-public.apple.com")
        || (!initial && url.host_str() == Some("fcs-keys-pub-prod.cdn-apple.com"));
    ensure!(allowed, "unsupported public AEA key server");
    let identifier = url
        .path()
        .strip_prefix("/fcs-keys/")
        .context("unexpected public AEA key path")?;
    ensure!(
        !identifier.is_empty()
            && identifier.len() <= 256
            && identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_=".contains(&byte)),
        "invalid public AEA key identifier"
    );
    Ok(url)
}

fn parse(source: PathBuf, source_bytes: u64, bytes: &[u8]) -> Result<Metadata> {
    ensure!(
        bytes.len() >= 12 && &bytes[..4] == b"AEA1",
        "expected AEA1 header"
    );
    let profile = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    ensure!(profile == 1, "only AEA1 symmetric profile 1 is reviewed");
    let size = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    ensure!(
        size <= MAX_METADATA && bytes.len() == 12 + size,
        "AEA metadata extent/limit mismatch"
    );
    ensure!(source_bytes > bytes.len() as u64, "AEA payload is missing");
    let mut cursor = 12usize;
    let mut entries = Vec::new();
    let mut names = BTreeSet::new();
    let mut public_key_url = None;
    let mut fcs_response = None;
    while cursor < bytes.len() {
        ensure!(entries.len() < 256, "too many AEA metadata entries");
        let length = bytes
            .get(cursor..cursor + 4)
            .context("truncated AEA metadata entry")?;
        let length = u32::from_le_bytes(length.try_into().unwrap()) as usize;
        ensure!(length >= 6, "AEA metadata entry is too short");
        let end = cursor
            .checked_add(length)
            .context("AEA metadata entry overflow")?;
        let payload = bytes
            .get(cursor + 4..end)
            .context("AEA metadata entry exceeds header")?;
        let terminator = payload
            .iter()
            .position(|byte| *byte == 0)
            .context("AEA metadata key is not terminated")?;
        ensure!(
            terminator > 0 && terminator <= 256,
            "AEA metadata key length"
        );
        let key = &payload[..terminator];
        ensure!(
            key.iter().all(|byte| (0x21..0x7f).contains(byte)),
            "AEA metadata key must be printable ASCII"
        );
        let key = std::str::from_utf8(key)?.to_owned();
        ensure!(names.insert(key.clone()), "duplicate AEA metadata key");
        let value = &payload[terminator + 1..];
        if key == FCS_FIELD {
            let text = std::str::from_utf8(value).context("AEA key URL is not UTF-8")?;
            public_key_url = Some(key_url(text, true)?.to_string());
        }
        if key == FCS_RESPONSE_FIELD {
            fcs_response = Some(value.to_vec());
        }
        entries.push(Entry {
            key,
            value_bytes: value.len(),
            value_sha256: sha256(value),
        });
        cursor = end;
    }
    Ok(Metadata {
        kind: "aea1_public_ipsw_metadata",
        schema_version: 1,
        source,
        source_bytes,
        profile,
        metadata_bytes: size,
        header_sha256: sha256(bytes),
        entries,
        public_key_url,
        fcs_response,
        limits: "Bounded acquisition metadata only; wrapped keys/body omitted. Header data is unauthenticated here. No payload decryption, signing/trust-chain verification or filesystem validation.",
    })
}

pub fn inspect(path: &Path) -> Result<Metadata> {
    ensure!(
        std::fs::metadata(path)?.is_file(),
        "AEA input must be a regular file"
    );
    let mut file = File::open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "AEA input is no longer a regular file"
    );
    let length = file.metadata()?.len();
    let mut header = [0u8; 12];
    file.read_exact(&mut header)
        .context("truncated AEA1 header")?;
    ensure!(&header[..4] == b"AEA1", "expected AEA1 header");
    let size = u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize;
    ensure!(size <= MAX_METADATA, "AEA metadata exceeds 64 KiB");
    let mut bytes = header.to_vec();
    bytes.resize(12 + size, 0);
    file.read_exact(&mut bytes[12..])
        .context("truncated AEA metadata")?;
    parse(path.canonicalize()?, length, &bytes)
}

fn receipt_path(output: &Path) -> PathBuf {
    let mut path = output.as_os_str().to_owned();
    path.push(".json");
    PathBuf::from(path)
}

fn publish(output: &Path, body: &[u8], receipt: &serde_json::Value) -> Result<()> {
    let receipt_path = receipt_path(output);
    ensure!(
        !output.try_exists()? && !receipt_path.try_exists()?,
        "key output or receipt exists"
    );
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    // NamedTempFile is private (0600 on Unix). Complete files publish without
    // replacement, key first and receipt last; this is not a two-path transaction.
    let mut key = tempfile::NamedTempFile::new_in(parent)?;
    key.write_all(body)?;
    key.as_file().sync_all()?;
    let mut record = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(&mut record, receipt)?;
    record.write_all(b"\n")?;
    record.as_file().sync_all()?;
    key.persist_noclobber(output).map_err(|error| error.error)?;
    record
        .persist_noclobber(&receipt_path)
        .map_err(|error| error.error)?;
    Ok(())
}

pub fn fetch_key(input: &Path, output: &Path) -> Result<serde_json::Value> {
    ensure!(
        !output.try_exists()? && !receipt_path(output).try_exists()?,
        "key output or receipt exists"
    );
    let metadata = inspect(input)?;
    let url = key_url(
        metadata
            .public_key_url
            .as_deref()
            .context("AEA archive has no public FCS key URL")?,
        true,
    )?;
    let identifier = url.path().to_owned();
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(60))
        .redirect(Policy::custom(move |attempt| {
            if attempt.previous().len() >= 5 {
                attempt.error("too many public key redirects")
            } else if key_url(attempt.url().as_str(), false).is_err()
                || attempt.url().path() != identifier
            {
                attempt.error("public AEA key redirect changed server profile or key identity")
            } else {
                attempt.follow()
            }
        }))
        .build()?;
    let response = client.get(url.clone()).send()?.error_for_status()?;
    let final_url = response.url().to_string();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut body = Vec::new();
    response.take(MAX_KEY as u64 + 1).read_to_end(&mut body)?;
    ensure!(
        body.len() <= MAX_KEY,
        "public AEA key response exceeds 64 KiB"
    );
    let text = std::str::from_utf8(&body).context("public AEA key is not a PEM response")?;
    ensure!(
        text.starts_with("-----BEGIN PRIVATE KEY-----\n")
            && text.trim_end().ends_with("-----END PRIVATE KEY-----"),
        "unsupported public AEA key response; expected PKCS8 PEM"
    );
    ensure!(
        inspect(input)?.header_sha256 == metadata.header_sha256,
        "AEA metadata changed during key fetch"
    );
    let receipt = serde_json::json!({
        "kind":"public_apple_aea_key_fetch", "schema_version":1, "metadata":metadata,
        "request_url":url.as_str(), "final_url":final_url, "content_type":content_type,
        "key_bytes":body.len(), "key_file_sha256":sha256(&body), "key_body_omitted":true,
        "cli_executable_sha256":sha256(&std::fs::read(std::env::current_exe()?)?),
        "limits":"Verified HTTPS acquisition of a public FCS recipient key, not archive authentication or decryption. PEM shape only; the native CryptoKit decoder validates the P-256 private key. Key file publishes before its receipt without replacement; an interrupted publication can leave an unreceipted key file."
    });
    publish(output, &body, &receipt)?;
    Ok(receipt)
}

/// The FCS response's encapsulated key and wrapped archive key.
fn wrapped_key(metadata: &Metadata) -> Result<(Vec<u8>, Vec<u8>)> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let response = metadata
        .fcs_response
        .as_deref()
        .context("AEA archive has no FCS response")?;
    ensure!(
        response.len() <= MAX_FCS_RESPONSE,
        "FCS response exceeds 4 KiB"
    );
    let fields: std::collections::BTreeMap<String, String> = serde_json::from_slice(response)?;
    ensure!(
        fields
            .keys()
            .map(String::as_str)
            .eq(["enc-request", "wrapped-key"]),
        "FCS response must hold exactly enc-request and wrapped-key"
    );
    let encapsulated = STANDARD.decode(&fields["enc-request"])?;
    let wrapped = STANDARD.decode(&fields["wrapped-key"])?;
    ensure!(
        encapsulated.len() == ENCAPSULATED_BYTES && wrapped.len() == WRAPPED_BYTES,
        "expected a P-256 encapsulation and a wrapped 32-byte key"
    );
    Ok((encapsulated, wrapped))
}

/// Unwrap the archive key: HPKE base mode, DHKEM(P-256, HKDF-SHA256),
/// HKDF-SHA256 and AES-256-GCM with empty info and associated data.
fn archive_key(metadata: &Metadata, pem: &str) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    use hpke::{
        Deserializable, OpModeR, aead::AesGcm256, kdf::HkdfSha256, kem::DhP256HkdfSha256,
        single_shot_open,
    };
    use p256::pkcs8::DecodePrivateKey;
    let (encapsulated, wrapped) = wrapped_key(metadata)?;
    let secret = p256::SecretKey::from_pkcs8_pem(pem).context("invalid P-256 PKCS8 key")?;
    let private = <DhP256HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(&secret.to_bytes())
        .map_err(|error| anyhow::anyhow!("HPKE private key: {error:?}"))?;
    let encapsulated = <DhP256HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&encapsulated)
        .map_err(|error| anyhow::anyhow!("HPKE encapsulated key: {error:?}"))?;
    let key = single_shot_open::<AesGcm256, HkdfSha256, DhP256HkdfSha256>(
        &OpModeR::Base,
        &private,
        &encapsulated,
        &[],
        &wrapped,
        &[],
    )
    .map_err(|error| anyhow::anyhow!("cannot unwrap the archive key: {error:?}"))?;
    ensure!(
        key.len() == ARCHIVE_KEY_BYTES,
        "unexpected archive key length"
    );
    Ok(zeroize::Zeroizing::new(key))
}

/// Decrypt an AEA1 profile-1 archive with its fetched FCS private key.
///
/// The archive key is unwrapped here; macOS `aea` authenticates and decrypts
/// the payload. The key exists on disk only in a private temporary file.
pub fn decrypt(input: &Path, key: &Path, output: &Path) -> Result<serde_json::Value> {
    ensure!(!output.try_exists()?, "{} exists", output.display());
    let metadata = inspect(input)?;
    let pem = std::fs::read_to_string(key)?;
    ensure!(pem.len() <= MAX_KEY, "key file exceeds 64 KiB");
    let archive_key = archive_key(&metadata, &pem)?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut key_file = tempfile::NamedTempFile::new_in(parent)?;
    key_file.write_all(&archive_key)?;
    let status = std::process::Command::new(AEA_TOOL)
        .arg("decrypt")
        .arg("-key")
        .arg(key_file.path())
        .arg("-i")
        .arg(input)
        .arg("-o")
        .arg(output)
        .stdin(std::process::Stdio::null())
        .status()
        .with_context(|| format!("cannot run {AEA_TOOL}"))?;
    drop(key_file);
    ensure!(status.success(), "{AEA_TOOL} decrypt failed with {status}");
    let decrypted = File::open(output)?.metadata()?.len();
    Ok(serde_json::json!({
        "kind": "aea1_decrypt",
        "input": metadata.source,
        "input_header_sha256": metadata.header_sha256,
        "key_file_sha256": sha256(pem.as_bytes()),
        "output": output,
        "output_bytes": decrypted,
    }))
}

#[cfg(test)]
mod tests {
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
        let (encapsulated, wrapped) =
            single_shot_seal::<AesGcm256, HkdfSha256, DhP256HkdfSha256, _>(
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
}
