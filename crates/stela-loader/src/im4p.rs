//! Bounded IM4P inspection and plaintext payload decoding.
//!
//! An IM4P is the DER `SEQUENCE { IA5 "IM4P", IA5 type, IA5 description,
//! OCTET STRING payload, [SEQUENCE { INTEGER algorithm, INTEGER size }] }`
//! that restore images use for kernels, DeviceTrees, trust caches and
//! firmware ([blacktop/ipsw img4 payload](https://github.com/blacktop/ipsw/blob/master/pkg/img4/payload.go)).
//! This is not an IMG4 signature validator and never decrypts keybag payloads.
use alloc::{string::String, vec, vec::Vec};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;

/// IM4P compression algorithm 1 is LZFSE, with a `bvx*` block stream.
const COMPRESSION_LZFSE: u64 = 1;

const DER_SEQUENCE: u8 = 0x30;
const DER_IA5_STRING: u8 = 0x16;
const DER_OCTET_STRING: u8 = 0x04;
const DER_INTEGER: u8 = 0x02;
const DER_CONTEXT_0: u8 = 0xa0;

struct Der<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Der<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn next(&mut self) -> Result<(u8, &'a [u8])> {
        let tag = *self.bytes.get(self.position).context("truncated DER tag")?;
        ensure!(tag & 31 != 31, "high-number DER tags are unsupported");
        let first = *self
            .bytes
            .get(self.position + 1)
            .context("truncated DER length")?;
        self.position += 2;
        let length = if first < 128 {
            usize::from(first)
        } else {
            let width = usize::from(first & 127);
            ensure!(
                width > 0 && width <= size_of::<usize>(),
                "indefinite or oversized DER length"
            );
            let end = self
                .position
                .checked_add(width)
                .context("DER length overflow")?;
            let encoded = self
                .bytes
                .get(self.position..end)
                .context("truncated DER long length")?;
            ensure!(encoded[0] != 0, "non-minimal DER length");
            self.position = end;
            let mut length = 0usize;
            for byte in encoded {
                length = length
                    .checked_mul(256)
                    .and_then(|n| n.checked_add(usize::from(*byte)))
                    .context("DER length overflow")?;
            }
            ensure!(length >= 128, "non-minimal DER long length");
            length
        };
        let end = self
            .position
            .checked_add(length)
            .context("DER range overflow")?;
        let value = self
            .bytes
            .get(self.position..end)
            .context("DER value is out of bounds")?;
        self.position = end;
        Ok((tag, value))
    }

    fn value(&mut self, tag: u8) -> Result<&'a [u8]> {
        let (actual, value) = self.next()?;
        ensure!(
            actual == tag,
            "unexpected DER tag: {actual:#x}, expected {tag:#x}"
        );
        Ok(value)
    }

    fn done(&self) -> bool {
        self.position == self.bytes.len()
    }
}

fn text(bytes: &[u8]) -> Result<String> {
    ensure!(bytes.is_ascii(), "IM4P IA5 string is not ASCII");
    Ok(core::str::from_utf8(bytes)?.into())
}

fn integer(bytes: &[u8]) -> Result<u64> {
    ensure!(
        !bytes.is_empty() && bytes[0] & 128 == 0,
        "negative or empty DER integer"
    );
    ensure!(
        bytes.len() <= 1 || bytes[0] != 0 || bytes[1] & 128 != 0,
        "non-minimal DER integer"
    );
    let mut value = 0u64;
    for byte in bytes {
        value = value
            .checked_mul(256)
            .and_then(|n| n.checked_add(u64::from(*byte)))
            .context("DER integer overflow")?;
    }
    Ok(value)
}

/// An IM4P field this parser keeps opaque, recorded by tag and length.
#[derive(Debug, Clone, Serialize)]
pub struct Extension {
    pub tag: u8,
    pub bytes: usize,
}

#[derive(Debug)]
pub struct Im4p<'a> {
    /// The four-character payload type, such as `krnl`, `dtre` or `trst`.
    pub payload_type: String,
    pub description: String,
    pub payload: &'a [u8],
    pub compression_algorithm: Option<u64>,
    pub declared_uncompressed_bytes: Option<u64>,
    pub opaque_extensions: Vec<Extension>,
}

/// Parse a bare IM4P container, rejecting keybags and trailing bytes.
pub fn parse(bytes: &[u8]) -> Result<Im4p<'_>> {
    let mut outer = Der::new(bytes);
    let mut sequence = Der::new(outer.value(DER_SEQUENCE)?);
    ensure!(outer.done(), "trailing bytes after IM4P container");
    ensure!(
        sequence.value(DER_IA5_STRING)? == b"IM4P",
        "expected a bare IM4P container"
    );
    let payload_type = text(sequence.value(DER_IA5_STRING)?)?;
    ensure!(
        payload_type.len() == 4,
        "payload type must have four characters"
    );
    let description = text(sequence.value(DER_IA5_STRING)?)?;
    let payload = sequence.value(DER_OCTET_STRING)?;
    let mut compression_algorithm = None;
    let mut declared_uncompressed_bytes = None;
    let mut opaque_extensions = vec![];
    while !sequence.done() {
        let (tag, value) = sequence.next()?;
        match tag {
            DER_SEQUENCE => {
                ensure!(
                    compression_algorithm.is_none(),
                    "duplicate compression metadata"
                );
                let mut compression = Der::new(value);
                compression_algorithm = Some(integer(compression.value(DER_INTEGER)?)?);
                declared_uncompressed_bytes = Some(integer(compression.value(DER_INTEGER)?)?);
                ensure!(compression.done(), "unexpected compression metadata fields");
            }
            DER_OCTET_STRING => bail!(
                "IM4P keybags or trailing hashes are unsupported; encrypted payloads are not decrypted"
            ),
            DER_CONTEXT_0 => opaque_extensions.push(Extension {
                tag,
                bytes: value.len(),
            }),
            _ => bail!("unsupported IM4P extension tag {tag:#x}"),
        }
    }
    Ok(Im4p {
        payload_type,
        description,
        payload,
        compression_algorithm,
        declared_uncompressed_bytes,
        opaque_extensions,
    })
}

/// Identities of one decoded IM4P; the payload remains Apple's bytes.
#[derive(Debug, Clone, Serialize)]
pub struct DecodeReceipt {
    pub schema_version: u32,
    pub container_bytes: usize,
    pub container_sha256: String,
    pub payload_type: String,
    pub description: String,
    pub compression: String,
    pub payload_bytes: usize,
    pub payload_sha256: String,
    pub declared_uncompressed_bytes: Option<u64>,
    pub decoded_bytes: usize,
    pub decoded_sha256: String,
    pub opaque_extensions: Vec<Extension>,
    pub signature_validated: bool,
}

/// Decode a plaintext IM4P payload of any type, returning Apple's bytes.
///
/// LZFSE streams must be consumed exactly and match the declared size. Other
/// payloads are copied unchanged and must not carry compression metadata.
pub fn decode(bytes: &[u8], maximum: u64) -> Result<(Vec<u8>, DecodeReceipt)> {
    let im4p = parse(bytes)?;
    ensure!(
        im4p.declared_uncompressed_bytes
            .is_none_or(|n| n <= maximum),
        "declared output exceeds configured limit"
    );
    let mut decoded = vec![];
    let compression = if stela_formats::lzfse::is_lzfse(im4p.payload) {
        ensure!(
            im4p.compression_algorithm
                .is_none_or(|n| n == COMPRESSION_LZFSE),
            "compression record disagrees with LZFSE marker"
        );
        let limit = usize::try_from(maximum).unwrap_or(usize::MAX);
        decoded = stela_formats::lzfse::decode(im4p.payload, limit)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        "lzfse"
    } else {
        ensure!(
            im4p.compression_algorithm.is_none(),
            "unrecognized compressed payload format"
        );
        ensure!(
            im4p.payload.len() as u64 <= maximum,
            "payload exceeds configured limit"
        );
        decoded.extend_from_slice(im4p.payload);
        "none"
    };
    ensure!(!decoded.is_empty(), "decoded payload is empty");
    ensure!(
        im4p.declared_uncompressed_bytes
            .is_none_or(|n| n == decoded.len() as u64),
        "decoded size disagrees with IM4P metadata"
    );
    let receipt = DecodeReceipt {
        schema_version: 1,
        container_bytes: bytes.len(),
        container_sha256: stela_formats::sha256(bytes),
        payload_type: im4p.payload_type,
        description: im4p.description,
        compression: compression.into(),
        payload_bytes: im4p.payload.len(),
        payload_sha256: stela_formats::sha256(im4p.payload),
        declared_uncompressed_bytes: im4p.declared_uncompressed_bytes,
        decoded_bytes: decoded.len(),
        decoded_sha256: stela_formats::sha256(&decoded),
        opaque_extensions: im4p.opaque_extensions,
        signature_validated: false,
    };
    Ok((decoded, receipt))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(tag: u8, data: &[u8]) -> Vec<u8> {
        assert!(data.len() < 128);
        [vec![tag, data.len() as u8], data.to_vec()].concat()
    }

    fn fixture(payload_type: &[u8], payload: &[u8], extension: &[u8]) -> Vec<u8> {
        let fields = [
            field(DER_IA5_STRING, b"IM4P"),
            field(DER_IA5_STRING, payload_type),
            field(DER_IA5_STRING, b"original fixture"),
            field(DER_OCTET_STRING, payload),
            extension.to_vec(),
        ]
        .concat();
        field(DER_SEQUENCE, &fields)
    }

    fn stored_lzfse(raw: &[u8]) -> Vec<u8> {
        [
            b"bvx-".to_vec(),
            (raw.len() as u32).to_le_bytes().to_vec(),
            raw.to_vec(),
            b"bvx$".to_vec(),
        ]
        .concat()
    }

    #[test]
    fn decodes_lzfse_and_raw_payloads_with_limits() -> Result<()> {
        let raw = b"original kernel fixture";
        let size = field(
            DER_SEQUENCE,
            &[
                field(DER_INTEGER, &[1]),
                field(DER_INTEGER, &[raw.len() as u8]),
            ]
            .concat(),
        );
        let container = fixture(b"dtre", &stored_lzfse(raw), &size);
        let (decoded, receipt) = decode(&container, 1024)?;
        assert_eq!(decoded, raw);
        assert_eq!(receipt.payload_type, "dtre");
        assert_eq!(receipt.compression, "lzfse");
        assert_eq!(receipt.decoded_sha256, stela_formats::sha256(raw));
        assert!(!receipt.signature_validated);
        assert!(decode(&container, 2).is_err());

        let (decoded, receipt) = decode(&fixture(b"trst", b"\x02\0\0\0", &[]), 1024)?;
        assert_eq!(decoded, b"\x02\0\0\0");
        assert_eq!(receipt.compression, "none");

        let mut truncated = stored_lzfse(raw);
        truncated.pop();
        assert!(decode(&fixture(b"krnl", &truncated, &[]), 1024).is_err());
        let mut trailing = container;
        trailing.push(0);
        assert!(decode(&trailing, 1024).is_err());
        Ok(())
    }

    #[test]
    fn rejects_keybags_duplicate_and_incorrect_size_metadata() {
        let raw = [0xcf, 0xfa, 0xed, 0xfe];
        assert!(parse(&fixture(b"krnl", &raw, &field(DER_OCTET_STRING, b"keybag"))).is_err());
        let compression = field(
            DER_SEQUENCE,
            &[field(DER_INTEGER, &[1]), field(DER_INTEGER, &[5])].concat(),
        );
        assert!(
            parse(&fixture(
                b"krnl",
                &raw,
                &[compression.clone(), compression.clone()].concat()
            ))
            .is_err()
        );
        assert!(decode(&fixture(b"krnl", &stored_lzfse(&raw), &compression), 100).is_err());
        assert!(decode(&fixture(b"krnl", &raw, &compression), 100).is_err());
    }

    #[test]
    fn rejects_malformed_lengths_and_short_types() {
        for bytes in [
            vec![0x30, 0x80],
            vec![0x30, 0x81, 0x01, 0],
            vec![0x30, 0x82, 0, 128],
            vec![0x30, 0xff],
            vec![0x30, 4, 0x16, 4],
        ] {
            assert!(parse(&bytes).is_err());
        }
        assert!(parse(&fixture(b"krn", b"x", &[])).is_err());
    }
}
