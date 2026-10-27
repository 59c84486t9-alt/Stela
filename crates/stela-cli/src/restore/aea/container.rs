//! The AEA1 container after its metadata, for the symmetric profile: a root
//! header, then clusters of segments, then padding. Every part is
//! authenticated with HMAC-SHA256 before it is decrypted with AES-256-CTR,
//! and each segment is optionally compressed.
//!
//! Keys come from HKDF-SHA256. The archive key and the 32-byte salt after
//! the metadata give the main key (info `AEA_AMK` and the header's profile
//! word). The main key gives the root header's key (`AEA_RHEK`), each
//! cluster's (`AEA_CK` and its index) and the padding's (`AEA_PAK`). A
//! cluster key gives its segment headers' key (`AEA_CHEK`) and each
//! segment's (`AEA_SK` and its index in the cluster). A header key is a MAC
//! key, an AES key and a counter block, in that order of one HKDF output.
//! Each cluster carries the MAC of the next one, and the last next-MAC is the
//! padding's. The layout follows blacktop/ipsw's `pkg/aea/decrypt.go` (MIT).
use anyhow::{Context, Result, bail, ensure};
use hmac::Mac;
use sha2::Digest;
use std::io::{Read, Write};
use zeroize::Zeroizing;

type HmacSha256 = hmac::Hmac<sha2::Sha256>;
type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

const SALT_BYTES: usize = 32;
const MAC_BYTES: usize = 32;
const ROOT_HEADER_BYTES: usize = 48;
/// The root header's geometry is bounded before any cluster is read, so a
/// corrupt header cannot ask for unbounded buffers.
const MAX_SEGMENT_BYTES: u32 = 64 << 20;
const MAX_SEGMENTS_PER_CLUSTER: u32 = 1 << 16;

/// Segment compression, by the root header's algorithm byte.
const STORED: u8 = b'-';
const LZFSE: u8 = b'e';
const LZVN: u8 = b'f';
/// Segment checksums, by the root header's checksum byte.
const NO_CHECKSUM: u8 = 0;
const SHA256_CHECKSUM: u8 = 2;

/// A MAC key, an AES-256 key and its initial counter block.
struct HeaderKey(Zeroizing<[u8; 80]>);

impl HeaderKey {
    fn derive(key: &[u8], info: &[u8]) -> Self {
        let mut bytes = Zeroizing::new([0u8; 80]);
        hkdf::Hkdf::<sha2::Sha256>::new(None, key)
            .expand(info, &mut *bytes)
            .expect("80 bytes is a valid HKDF-SHA256 output");
        Self(bytes)
    }

    fn mac_key(&self) -> &[u8] {
        &self.0[..32]
    }

    fn decrypt(&self, data: &mut [u8]) {
        use ctr::cipher::{KeyIvInit, StreamCipher};
        let key: &[u8; 32] = self.0[32..64].try_into().unwrap();
        let iv: &[u8; 16] = self.0[64..].try_into().unwrap();
        Aes256Ctr::new(key.into(), iv.into()).apply_keystream(data);
    }
}

fn derive_key(key: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<sha2::Sha256>::new(salt, key)
        .expand(info, &mut *bytes)
        .expect("32 bytes is a valid HKDF-SHA256 output");
    bytes
}

fn info(label: &str, index: u32) -> Vec<u8> {
    [label.as_bytes(), &index.to_le_bytes()].concat()
}

/// Whether `expected` is the MAC of `salt`, `data` and the salt's length.
fn authentic(key: &[u8], salt: &[u8], data: &[u8], expected: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(salt);
    mac.update(data);
    mac.update(&(salt.len() as u64).to_le_bytes());
    mac.verify_slice(expected).is_ok()
}

fn read<const N: usize>(input: &mut impl Read, what: &str) -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    input
        .read_exact(&mut bytes)
        .with_context(|| format!("truncated AEA1 {what}"))?;
    Ok(bytes)
}

fn read_vec(input: &mut impl Read, bytes: usize, what: &str) -> Result<Vec<u8>> {
    let mut data = vec![0u8; bytes];
    input
        .read_exact(&mut data)
        .with_context(|| format!("truncated AEA1 {what}"))?;
    Ok(data)
}

/// The decrypted root header's fields.
struct Root {
    file_bytes: u64,
    segment_bytes: u32,
    per_cluster: u32,
    compression: u8,
    checksum_bytes: usize,
}

impl Root {
    fn parse(bytes: &[u8; ROOT_HEADER_BYTES]) -> Result<Self> {
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let root = Self {
            file_bytes: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            segment_bytes: word(16),
            per_cluster: word(20),
            compression: bytes[24],
            checksum_bytes: match bytes[25] {
                NO_CHECKSUM => 0,
                SHA256_CHECKSUM => 32,
                other => bail!("UNSUPPORTED AEA1 segment checksum kind {other}"),
            },
        };
        ensure!(
            matches!(root.compression, STORED | LZFSE | LZVN),
            "UNSUPPORTED AEA1 segment compression {:?}",
            char::from(root.compression)
        );
        ensure!(
            (1..=MAX_SEGMENT_BYTES).contains(&root.segment_bytes)
                && (1..=MAX_SEGMENTS_PER_CLUSTER).contains(&root.per_cluster),
            "AEA1 root header has {} segments of {} bytes per cluster",
            root.per_cluster,
            root.segment_bytes
        );
        Ok(root)
    }

    fn decompress(&self, data: Vec<u8>, raw: usize) -> Result<Vec<u8>> {
        if data.len() == raw {
            return Ok(data);
        }
        let decoded = match self.compression {
            LZFSE => stela_runtime::lzfse::decode(&data, raw),
            LZVN if stela_runtime::lzfse::is_lzfse(&data) => {
                stela_runtime::lzfse::decode(&data, raw)
            }
            LZVN => stela_runtime::lzfse::decode_lzvn(&data, raw),
            _ => bail!(
                "an AEA1 segment of stored data is {} bytes, not {raw}",
                data.len()
            ),
        }
        .map_err(|error| anyhow::anyhow!("AEA1 segment: {error}"))?;
        ensure!(
            decoded.len() == raw,
            "an AEA1 segment decompresses to {} bytes, not {raw}",
            decoded.len()
        );
        Ok(decoded)
    }
}

/// Decrypt the AEA1 symmetric archive read from its first byte in `input`
/// with `archive_key` into `output`, and return the bytes written. The
/// header must be the one whose SHA-256 is `header_sha256`. Nothing is
/// written from a part before its MAC is checked.
pub(super) fn decrypt(
    archive_key: &[u8],
    header_sha256: &str,
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<u64> {
    let fixed: [u8; 12] = read(input, "header")?;
    ensure!(&fixed[..4] == b"AEA1", "expected AEA1 header");
    let profile = u32::from_le_bytes(fixed[4..8].try_into().unwrap());
    let auth_bytes = u32::from_le_bytes(fixed[8..12].try_into().unwrap()) as usize;
    ensure!(
        auth_bytes <= super::MAX_METADATA,
        "AEA metadata exceeds 64 KiB"
    );
    let auth = read_vec(input, auth_bytes, "metadata")?;
    ensure!(
        stela_runtime::sha256(&[&fixed[..], &auth].concat()) == header_sha256,
        "the AEA1 header differs from the one inspected"
    );
    let salt: [u8; SALT_BYTES] = read(input, "salt")?;
    let main = derive_key(archive_key, Some(&salt), &info("AEA_AMK", profile));

    let root_mac: [u8; MAC_BYTES] = read(input, "root header")?;
    let mut root: [u8; ROOT_HEADER_BYTES] = read(input, "root header")?;
    let mut expected: [u8; MAC_BYTES] = read(input, "root header")?;
    let root_key = HeaderKey::derive(&*main, b"AEA_RHEK");
    ensure!(
        authentic(
            root_key.mac_key(),
            &[&expected[..], &auth].concat(),
            &root,
            &root_mac
        ),
        "the AEA1 root header fails its MAC: the key is not this archive's"
    );
    root_key.decrypt(&mut root);
    let root = Root::parse(&root)?;

    let per_cluster = root.per_cluster as usize;
    let header_bytes = 8 + root.checksum_bytes;
    let mut written = 0u64;
    let mut cluster = 0u32;
    loop {
        let cluster_key = derive_key(&*main, None, &info("AEA_CK", cluster));
        let header_key = HeaderKey::derive(&*cluster_key, b"AEA_CHEK");
        let mut headers = read_vec(input, header_bytes * per_cluster, "segment headers")?;
        let next: [u8; MAC_BYTES] = read(input, "cluster MAC")?;
        let macs = read_vec(input, MAC_BYTES * per_cluster, "segment MACs")?;
        ensure!(
            authentic(
                header_key.mac_key(),
                &[&next[..], &macs].concat(),
                &headers,
                &expected
            ),
            "AEA1 cluster {cluster} fails its MAC"
        );
        header_key.decrypt(&mut headers);
        for (index, header) in headers.chunks_exact(header_bytes).enumerate() {
            let raw = u32::from_le_bytes(header[..4].try_into().unwrap());
            let stored = u32::from_le_bytes(header[4..8].try_into().unwrap());
            if raw == 0 {
                continue;
            }
            let position = (u64::from(cluster) * per_cluster as u64 + index as u64)
                * u64::from(root.segment_bytes);
            ensure!(
                raw <= root.segment_bytes
                    && stored <= MAX_SEGMENT_BYTES
                    && position == written
                    && written + u64::from(raw) <= root.file_bytes,
                "AEA1 segment {index} of cluster {cluster} ({raw} bytes, {stored} stored) is \
                 out of place"
            );
            let mut data = read_vec(input, stored as usize, "segment")?;
            let segment_key = HeaderKey::derive(&*cluster_key, &info("AEA_SK", index as u32));
            ensure!(
                authentic(
                    segment_key.mac_key(),
                    &[],
                    &data,
                    &macs[index * MAC_BYTES..][..MAC_BYTES]
                ),
                "AEA1 segment {index} of cluster {cluster} fails its MAC"
            );
            segment_key.decrypt(&mut data);
            let plain = root.decompress(data, raw as usize)?;
            if root.checksum_bytes == 32 {
                ensure!(
                    sha2::Sha256::digest(&plain)[..] == header[8..],
                    "AEA1 segment {index} of cluster {cluster} fails its checksum"
                );
            }
            output.write_all(&plain)?;
            written += u64::from(raw);
        }
        expected = next;
        cluster += 1;
        if written >= root.file_bytes {
            break;
        }
    }
    ensure!(
        written == root.file_bytes,
        "AEA1 archive holds {written} bytes, not {}",
        root.file_bytes
    );
    let mut padding = Vec::new();
    input.read_to_end(&mut padding)?;
    if !padding.is_empty() {
        let padding_key = HeaderKey::derive(&*main, b"AEA_PAK");
        let mut mac =
            HmacSha256::new_from_slice(padding_key.mac_key()).expect("HMAC takes any key length");
        mac.update(&padding);
        ensure!(
            mac.verify_slice(&expected).is_ok(),
            "the AEA1 archive's padding fails its MAC"
        );
    }
    output.flush()?;
    Ok(written)
}
