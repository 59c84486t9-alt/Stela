//! Bounded measurement of a firmware container through dart-sep.
//!
//! `AppleSEPBooter::bootSEP`, kernel file 0x2d73d20..0x2d73d8c, sends an
//! IOVA in 4-KiB units without a length. DER supplies the container extent;
//! the caller supplies its permitted maximum. This is source-integrity
//! evidence only: measurement never authenticates Image4 or boots sepOS.
mod der;
mod rsa;
pub mod signature;

use crate::platform::dma::{DmaError, Port};
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

const SEQUENCE: u8 = 0x30;
const IA5: u8 = 0x16;
const MAGIC_BYTES: u8 = 4;
const HEADER_BYTES: usize = 2;
const MAX_LENGTH_BYTES: usize = 4;
const CHUNK: usize = 4096;
/// A Stela resource bound, not a hardware firmware-size register.
pub const MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Container {
    Img4,
    Im4p,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measurement {
    pub container: Container,
    pub bytes: u64,
    pub sha256: [u8; 32],
}

/// An owned DMA snapshot. Verification never rereads a mutable guest pointer.
pub struct Snapshot {
    pub measurement: Measurement,
    bytes: Vec<u8>,
}

impl Snapshot {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Bound the DER extent before allocating, then copy through the same DART
/// stream. A changing memory backend is refused instead of mixing evidence
/// from different versions of an image. No guest writes occur.
pub fn snapshot(port: &mut Port<'_, '_>, address: u64, maximum: u64) -> Result<Snapshot, DmaError> {
    let measurement = measure(port, address, maximum)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(measurement.bytes as usize)
        .map_err(|_| DmaError::Unsupported("SEP firmware snapshot allocation failed"))?;
    bytes.resize(measurement.bytes as usize, 0);
    port.read(address, &mut bytes)?;
    if <[u8; 32]>::from(Sha256::digest(&bytes)) != measurement.sha256 {
        return Err(DmaError::Unsupported(
            "SEP firmware changed during DMA inspection",
        ));
    }
    Ok(Snapshot { measurement, bytes })
}

/// Reads, bounds and hashes one DER container. It grants no execution or
/// authentication capability; a bare IM4P has no manifest to authenticate.
pub fn measure(
    port: &mut Port<'_, '_>,
    address: u64,
    maximum: u64,
) -> Result<Measurement, DmaError> {
    let bad = DmaError::Unsupported;
    if !(HEADER_BYTES as u64..=MAX_IMAGE_BYTES).contains(&maximum) {
        return Err(bad("SEP firmware bound is invalid"));
    }
    address
        .checked_add(maximum)
        .ok_or(bad("SEP firmware range overflows"))?;
    let mut header = [0; HEADER_BYTES];
    port.read(address, &mut header)?;
    if header[0] != SEQUENCE {
        return Err(bad("SEP firmware is not a DER sequence"));
    }
    let width = if header[1] & 0x80 == 0 {
        0
    } else {
        usize::from(header[1] & 0x7f)
    };
    if header[1] == 0x80 || width > MAX_LENGTH_BYTES {
        return Err(bad("SEP firmware DER length is indefinite or oversized"));
    }
    let header_bytes = (HEADER_BYTES + width) as u64;
    if header_bytes > maximum {
        return Err(bad("SEP firmware DER header exceeds its bound"));
    }
    let length = if width == 0 {
        u64::from(header[1])
    } else {
        let mut length = [0; MAX_LENGTH_BYTES];
        port.read(address + HEADER_BYTES as u64, &mut length[..width])?;
        if length[0] == 0 {
            return Err(bad("SEP firmware DER length is not minimal"));
        }
        let value = length[..width]
            .iter()
            .fold(0u64, |n, &b| n * 256 + u64::from(b));
        if value < 128 {
            return Err(bad("SEP firmware DER long length is not minimal"));
        }
        value
    };
    let bytes = header_bytes
        .checked_add(length)
        .filter(|&n| n <= maximum)
        .ok_or(bad("SEP firmware DER extent exceeds its bound"))?;
    let mut magic = [0; HEADER_BYTES + MAGIC_BYTES as usize];
    if length < magic.len() as u64 {
        return Err(bad("SEP firmware DER payload has no magic"));
    }
    port.read(address + header_bytes, &mut magic)?;
    if magic[..HEADER_BYTES] != [IA5, MAGIC_BYTES] {
        return Err(bad("SEP firmware magic is not an IA5 string"));
    }
    let container = match &magic[HEADER_BYTES..] {
        b"IMG4" => Container::Img4,
        b"IM4P" => Container::Im4p,
        _ => return Err(bad("SEP firmware magic is unsupported")),
    };
    let mut hash = Sha256::new();
    let mut chunk = [0; CHUNK];
    let mut done = 0;
    while done < bytes {
        let count = (bytes - done).min(CHUNK as u64) as usize;
        port.read(address + done, &mut chunk[..count])?;
        hash.update(&chunk[..count]);
        done += count as u64;
    }
    Ok(Measurement {
        container,
        bytes,
        sha256: hash.finalize().into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{
        apple::{bus::Access, interrupt::InterruptLatch},
        dma::{Iommu, Memory, tests::Ram},
    };

    struct Mapping {
        deny: Option<u64>,
        translated: usize,
    }
    impl Iommu for Mapping {
        fn page(&self) -> u64 {
            16
        }
        fn translate(
            &mut self,
            _: &mut dyn Memory,
            stream: usize,
            iova: u64,
            last: u64,
            write: bool,
            _: &mut Access<'_>,
        ) -> Result<u64, DmaError> {
            assert_eq!(stream, 0);
            assert!(!write);
            assert_eq!(iova / 16, last / 16);
            if self.deny.is_some_and(|page| iova / 16 == page) {
                return Err(DmaError::Fault(7));
            }
            self.translated += 1;
            Ok(iova + 0x1000)
        }
    }

    fn measured(bytes: &[u8], bound: u64, deny: Option<u64>) -> Result<Measurement, DmaError> {
        let mut ram = Ram::new(0x1000, bytes.len());
        ram.bytes.copy_from_slice(bytes);
        let mut iommu = Mapping {
            deny,
            translated: 0,
        };
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut port = Port {
            iommu: &mut iommu,
            stream: 0,
            memory: &mut ram,
            access: &mut access,
        };
        let result = measure(&mut port, 0, bound);
        assert!(iommu.translated > 0 || bound > MAX_IMAGE_BYTES);
        result
    }

    #[test]
    fn measurement_uses_iovas_and_hashes_exact_der_extent_not_padding() {
        let image = b"\x30\x06\x16\x04IM4P";
        let mut padded = image.to_vec();
        padded.extend_from_slice(&[0xaa; 20]);
        let result = measured(&padded, padded.len() as u64, None).unwrap();
        assert_eq!(result.container, Container::Im4p);
        assert_eq!(result.bytes, image.len() as u64);
        assert_eq!(result.sha256, <[u8; 32]>::from(Sha256::digest(image)));
        let mut long = alloc::vec![0x30, 0x81, 128, 0x16, 4];
        long.extend_from_slice(b"IMG4");
        long.resize(131, 0);
        assert_eq!(
            measured(&long, 131, None).unwrap().container,
            Container::Img4
        );
        assert_eq!(measured(&long, 131, Some(1)), Err(DmaError::Fault(7)));
    }

    #[test]
    fn malformed_truncated_and_oversized_images_never_measure_successfully() {
        for image in [
            b"\x30\x80\0\0".as_slice(),
            b"\x30\x85\x01\0\0\0\0",
            b"\x30\x81\x06\x16\x04IM4P",
            b"\x30\x82\x00\x80\x16\x04IM4P",
            b"\x30\x20\x16\x04IM4P",
            b"\x30\x06\x16\x04FAKE",
            b"\x30\x06\x04\x04IM4P",
            b"\x30\x05\x16\x04IM4",
            b"\x31\x06\x16\x04IM4P",
        ] {
            assert!(measured(image, image.len() as u64, None).is_err());
        }
        assert!(measured(b"\x30\x06\x16\x04IM4P", MAX_IMAGE_BYTES + 1, None).is_err());
    }
    #[test]
    fn snapshot_is_owned_bounded_and_refuses_changed_memory() {
        struct Changing {
            ram: Ram,
            full: usize,
            change: bool,
        }
        impl Memory for Changing {
            fn read(&mut self, pa: u64, out: &mut [u8]) -> bool {
                if !self.ram.read(pa, out) {
                    return false;
                }
                if out.len() == 8 {
                    self.full += 1;
                    if self.change && self.full == 2 {
                        out[2] ^= 1;
                    }
                }
                true
            }
            fn write(&mut self, _: u64, _: &[u8]) -> bool {
                panic!("inspection cannot write guest RAM")
            }
        }
        for change in [false, true] {
            let mut ram = Ram::new(0x1000, 28);
            ram.bytes[..8].copy_from_slice(b"\x30\x06\x16\x04IM4P");
            let mut memory = Changing {
                ram,
                full: 0,
                change,
            };
            let mut iommu = Mapping {
                deny: None,
                translated: 0,
            };
            let mut latch = InterruptLatch::new();
            let mut access = Access::new(0, 0, &mut latch);
            let result = snapshot(
                &mut Port {
                    iommu: &mut iommu,
                    stream: 0,
                    memory: &mut memory,
                    access: &mut access,
                },
                0,
                28,
            );
            if change {
                assert!(matches!(
                    result,
                    Err(DmaError::Unsupported(
                        "SEP firmware changed during DMA inspection"
                    ))
                ));
            } else {
                let snapshot = result.unwrap();
                assert_eq!(snapshot.bytes(), b"\x30\x06\x16\x04IM4P");
                assert_eq!(snapshot.measurement.bytes, 8);
            }
        }
    }
}
