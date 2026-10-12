//! Bounded IM4P inspection and plaintext kernel payload decompression.
//! This is not an IMG4 signature validator or an encrypted-payload decryptor.
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{self, Write};

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
                width > 0 && width <= std::mem::size_of::<usize>(),
                "indefinite or oversized DER length"
            );
            let encoded = self
                .bytes
                .get(
                    self.position
                        ..self
                            .position
                            .checked_add(width)
                            .context("DER length overflow")?,
                )
                .context("truncated DER long length")?;
            ensure!(encoded[0] != 0, "non-minimal DER length");
            self.position += width;
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
    Ok(std::str::from_utf8(bytes)?.into())
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

#[derive(Debug, Serialize)]
pub struct Extension {
    pub tag: u8,
    pub bytes: usize,
}

#[derive(Debug)]
pub struct Im4p<'a> {
    pub payload_type: String,
    pub description: String,
    pub payload: &'a [u8],
    pub compression_algorithm: Option<u64>,
    pub declared_uncompressed_bytes: Option<u64>,
    pub opaque_extensions: Vec<Extension>,
}

pub fn inspect(bytes: &[u8]) -> Result<Im4p<'_>> {
    let mut outer = Der::new(bytes);
    let mut sequence = Der::new(outer.value(0x30)?);
    ensure!(outer.done(), "trailing bytes after IM4P container");
    ensure!(
        sequence.value(0x16)? == b"IM4P",
        "expected a bare IM4P container"
    );
    let payload_type = text(sequence.value(0x16)?)?;
    ensure!(
        payload_type.len() == 4,
        "payload type must have four characters"
    );
    let description = text(sequence.value(0x16)?)?;
    let payload = sequence.value(0x04)?;
    let mut compression_algorithm = None;
    let mut declared_uncompressed_bytes = None;
    let mut opaque_extensions = vec![];
    while !sequence.done() {
        let (tag, value) = sequence.next()?;
        match tag {
            0x30 => {
                ensure!(
                    compression_algorithm.is_none(),
                    "duplicate compression metadata"
                );
                let mut compression = Der::new(value);
                compression_algorithm = Some(integer(compression.value(0x02)?)?);
                declared_uncompressed_bytes = Some(integer(compression.value(0x02)?)?);
                ensure!(compression.done(), "unexpected compression metadata fields");
            }
            0x04 => bail!(
                "IM4P keybags or trailing hashes are unsupported; encrypted payloads are not decrypted"
            ),
            0xa0 => opaque_extensions.push(Extension {
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

struct BoundedWriter<'a, W> {
    inner: &'a mut W,
    maximum: u64,
    written: u64,
    hash: Sha256,
}

impl<W: Write> Write for BoundedWriter<'_, W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let end = self
            .written
            .checked_add(buffer.len() as u64)
            .ok_or_else(|| io::Error::other("output length overflow"))?;
        if end > self.maximum {
            return Err(io::Error::other("decoded output exceeds configured limit"));
        }
        let written = self.inner.write(buffer)?;
        self.hash.update(&buffer[..written]);
        self.written += written as u64;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[derive(Debug, Serialize)]
pub struct DecodeReceipt {
    pub schema_version: u32,
    pub container_sha256: String,
    pub payload_type: String,
    pub description: String,
    pub compression: String,
    pub compressed_payload_bytes: usize,
    pub compressed_payload_sha256: String,
    pub declared_uncompressed_bytes: Option<u64>,
    pub decoded_bytes: u64,
    pub decoded_sha256: String,
    pub opaque_extensions: Vec<Extension>,
    pub signature_validated: bool,
}

pub fn decode_kernel(bytes: &[u8], output: &mut impl Write, maximum: u64) -> Result<DecodeReceipt> {
    let im4p = inspect(bytes)?;
    ensure!(
        matches!(im4p.payload_type.as_str(), "krnl" | "rkrn"),
        "only kernel payload types are currently supported"
    );
    ensure!(
        im4p.declared_uncompressed_bytes
            .is_none_or(|n| n <= maximum),
        "declared output exceeds configured limit"
    );
    let mut writer = BoundedWriter {
        inner: output,
        maximum,
        written: 0,
        hash: Sha256::new(),
    };
    let compression = if matches!(
        im4p.payload.get(..4),
        Some(b"bvx2" | b"bvx1" | b"bvx-" | b"bvxn")
    ) {
        ensure!(
            im4p.compression_algorithm.is_none_or(|n| n == 1),
            "compression record disagrees with LZFSE marker"
        );
        let (consumed, decoded) = lzfse_rust::LzfseRingDecoder::default()
            .decode(&mut std::io::Cursor::new(im4p.payload), &mut writer)?;
        ensure!(
            consumed == im4p.payload.len() as u64 && decoded == writer.written,
            "LZFSE stream extent mismatch"
        );
        "lzfse"
    } else if matches!(
        im4p.payload.get(..4),
        Some([0xcf, 0xfa, 0xed, 0xfe] | [0xfe, 0xed, 0xfa, 0xcf])
    ) {
        ensure!(
            im4p.compression_algorithm.is_none(),
            "raw Mach-O with compression metadata is unsupported"
        );
        writer.write_all(im4p.payload)?;
        "none"
    } else {
        bail!("unsupported or encrypted kernel payload format");
    };
    ensure!(writer.written > 0, "decoded kernel is empty");
    ensure!(
        im4p.declared_uncompressed_bytes
            .is_none_or(|n| n == writer.written),
        "decoded size disagrees with IM4P metadata"
    );
    writer.flush()?;
    Ok(DecodeReceipt {
        schema_version: 1,
        container_sha256: stela_core::sha256(bytes),
        payload_type: im4p.payload_type,
        description: im4p.description,
        compression: compression.into(),
        compressed_payload_bytes: im4p.payload.len(),
        compressed_payload_sha256: stela_core::sha256(im4p.payload),
        declared_uncompressed_bytes: im4p.declared_uncompressed_bytes,
        decoded_bytes: writer.written,
        decoded_sha256: hex::encode(writer.hash.finalize()),
        opaque_extensions: im4p.opaque_extensions,
        signature_validated: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn field(tag: u8, data: &[u8]) -> Vec<u8> {
        assert!(data.len() < 128);
        [vec![tag, data.len() as u8], data.to_vec()].concat()
    }
    fn fixture(payload: &[u8]) -> Vec<u8> {
        fixture_extension(payload, &[])
    }
    fn fixture_extension(payload: &[u8], extension: &[u8]) -> Vec<u8> {
        let fields = [
            field(0x16, b"IM4P"),
            field(0x16, b"krnl"),
            field(0x16, b"original fixture"),
            field(0x04, payload),
            extension.to_vec(),
        ]
        .concat();
        field(0x30, &fields)
    }
    #[test]
    fn decodes_independent_uncompressed_lzfse_frame_and_enforces_limits() -> Result<()> {
        let raw = b"original kernel fixture";
        let payload = [
            b"bvx-".to_vec(),
            (raw.len() as u32).to_le_bytes().to_vec(),
            raw.to_vec(),
            b"bvx$".to_vec(),
        ]
        .concat();
        let container = fixture(&payload);
        let mut output = vec![];
        let receipt = decode_kernel(&container, &mut output, 1024)?;
        assert_eq!(output, raw);
        assert_eq!(receipt.decoded_sha256, stela_core::sha256(raw));
        assert!(!receipt.signature_validated);
        assert!(decode_kernel(&container, &mut vec![], 2).is_err());
        let mut truncated = payload;
        truncated.pop();
        assert!(decode_kernel(&fixture(&truncated), &mut vec![], 1024).is_err());
        let mut trailing = container.clone();
        // DER trailing data and LZFSE trailing data are independently rejected.
        trailing.push(0);
        assert!(decode_kernel(&trailing, &mut vec![], 1024).is_err());
        Ok(())
    }
    #[test]
    fn rejects_encrypted_keybags_duplicate_and_incorrect_size_metadata() {
        let raw = [0xcf, 0xfa, 0xed, 0xfe];
        assert!(inspect(&fixture_extension(&raw, &field(0x04, b"keybag"))).is_err());
        let compression = field(0x30, &[field(0x02, &[1]), field(0x02, &[5])].concat());
        assert!(
            inspect(&fixture_extension(
                &raw,
                &[compression.clone(), compression.clone()].concat()
            ))
            .is_err()
        );
        let payload = [
            b"bvx-".to_vec(),
            4u32.to_le_bytes().to_vec(),
            raw.to_vec(),
            b"bvx$".to_vec(),
        ]
        .concat();
        assert!(
            decode_kernel(&fixture_extension(&payload, &compression), &mut vec![], 100).is_err()
        );
        let mut extra = payload;
        extra.push(0);
        assert!(decode_kernel(&fixture(&extra), &mut vec![], 100).is_err());
    }
    #[test]
    fn rejects_malformed_lengths_trailing_bytes_and_unknown_encryption() {
        for bytes in [
            vec![0x30, 0x80],
            vec![0x30, 0x81, 0x01, 0],
            vec![0x30, 0x82, 0, 128],
            vec![0x30, 0xff],
            vec![0x30, 4, 0x16, 4],
        ] {
            assert!(inspect(&bytes).is_err());
        }
        let mut trailing = fixture(b"unknown");
        trailing.push(0);
        assert!(inspect(&trailing).is_err());
        assert!(decode_kernel(&fixture(b"unknown"), &mut vec![], 1024).is_err());
    }
}
