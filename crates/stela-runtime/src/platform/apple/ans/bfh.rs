//! Boot-from-host (BFH) image download in the restore controller mode.
//!
//! The 26A434 kernel's `AppleANS2NVMeController::PerformBFH` (0x3dbe490)
//! sends up to three sections, 0 (the MSP loader) and then 1 and 2 (PHY
//! text and data, only when both are supplied, 0x3dbe50c..0x3dbe69c), each
//! in order from offset 0 in chunks of `GetMaxTxnSizeForFWUpdate`
//! (0x3dbe420: 0xff000 bytes for MSP types below 8). Each chunk is one
//! opcode 0x11 built by `BuildCommandBFHImageDownload` (0x3dec2ac):
//! CDW10 = bytes / 4 - 1, CDW11 = offset / 4, CDW14 = the section and
//! CDW15 = the chunk's CRC32C (the reflected Castagnoli table at kernel
//! file 0xb09000, initial value and final XOR all ones). It then sends
//! `BuildCommandFirmwareActivate(0, 1)` (0x3dec1e0): opcode 0x10 with
//! CDW10 = slot 0 | commit action 1 << 3, and fails on any nonzero status
//! (0x3dbe6d0). `UpdateMspBfhParams` (0x3dbe0f0) sends an opaque
//! parameter block with opcode 0xd1, CDW10 = bytes / 4 - 1
//! (`BuildCommandUpdateBFHParams` 0x3dec35c); the restore updater sends it
//! before the image.
//!
//! The images are the restore ramdisk's raw MSP loaders, not Image4
//! payloads, and the restore manifest has no digest for them; the chunk
//! CRC32C is their only integrity contract at this interface. Stela's
//! controller never executes them: activation records each section's
//! length, CRC32C and SHA-256 as the loaded image's identity and leaves
//! the medium unchanged. NVMe 1.4 section 5.11 discards an uncommitted
//! download on a controller-level reset, and so does the model.
use sha2::{Digest, Sha256};

pub(super) const SECTIONS: usize = 3;
/// `BuildCommandFirmwareActivate` CDW10 for slot 0, commit action 1:
/// replace the image and activate it at the next reset (NVMe 1.4 figure
/// 181). No other slot or action is ever sent.
pub(super) const ACTIVATE_SLOT0_REPLACE: u32 = 1 << 3;
pub(super) use crate::checksum::crc32c;
use crate::checksum::crc32c_update as crc_update;

/// A transferred byte string's identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub bytes: u64,
    pub crc32c: u32,
    pub sha256: [u8; 32],
}

/// The image the last activation committed, with the parameter block
/// that preceded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootImage {
    pub sections: alloc::vec::Vec<(u8, Identity)>,
    pub params: Option<Identity>,
}

#[derive(Clone)]
struct Section {
    bytes: u64,
    crc: u32,
    sha: Sha256,
}

impl Section {
    fn new() -> Self {
        Self {
            bytes: 0,
            crc: !0,
            sha: Sha256::new(),
        }
    }

    fn identity(&self) -> Identity {
        Identity {
            bytes: self.bytes,
            crc32c: !self.crc,
            sha256: self.sha.clone().finalize().into(),
        }
    }
}

/// The identity of a whole transferred byte string.
pub(super) fn identity(data: &[u8]) -> Identity {
    let mut section = Section::new();
    section.crc = crc_update(section.crc, data);
    section.sha.update(data);
    section.bytes = data.len() as u64;
    section.identity()
}

/// Uncommitted download state.
#[derive(Default)]
pub(super) struct Download {
    sections: alloc::vec::Vec<Section>,
    params: Option<Identity>,
}

impl Download {
    /// Accept one chunk: sections in the order 0, 1, 2, each contiguous
    /// from offset 0, and a CRC32C that matches the transferred bytes.
    pub fn chunk(
        &mut self,
        section: u32,
        offset: u64,
        data: &[u8],
        crc: u32,
    ) -> Result<(), &'static str> {
        if section as usize >= SECTIONS {
            return Err("ANS BFH image section is not 0, 1 or 2");
        }
        if crc32c(data) != crc {
            return Err("ANS BFH chunk CRC32C differs from CDW15");
        }
        let section = section as usize;
        let next = self.sections.len();
        if section == next && offset == 0 {
            self.sections.push(Section::new());
        } else if section + 1 != next {
            return Err("ANS BFH sections or offsets arrive out of order");
        } else if offset != self.sections[section].bytes {
            return Err("ANS BFH chunk offset is not contiguous with its section");
        }
        let staged = &mut self.sections[section];
        staged.crc = crc_update(staged.crc, data);
        staged.sha.update(data);
        staged.bytes += data.len() as u64;
        Ok(())
    }

    /// Record the parameter block for the next image. It may only arrive
    /// between images, as the restore updater sends it.
    pub fn params(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if !self.sections.is_empty() {
            return Err("ANS BFH parameters while an image download is in progress");
        }
        self.params = Some(identity(data));
        Ok(())
    }

    /// Commit the staged image: the loader alone, or with both PHY
    /// sections. The staging is consumed.
    pub fn activate(&mut self) -> Result<BootImage, &'static str> {
        if !matches!(self.sections.len(), 1 | 3) {
            return Err("ANS BFH activation without a loader, or with PHY text but no PHY data");
        }
        let image = BootImage {
            sections: (0..)
                .zip(&self.sections)
                .map(|(id, section)| (id, section.identity()))
                .collect(),
            params: self.params.take(),
        };
        self.sections.clear();
        Ok(image)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sections_are_ordered_contiguous_and_checked() {
        let mut download = Download::default();
        let data = [0x5a; 8];
        let crc = crc32c(&data);
        assert!(download.chunk(1, 0, &data, crc).is_err());
        assert!(download.chunk(0, 4, &data, crc).is_err());
        assert!(download.chunk(0, 0, &data, crc ^ 1).is_err());
        assert!(download.chunk(3, 0, &data, crc).is_err());
        download.chunk(0, 0, &data, crc).unwrap();
        assert!(download.chunk(0, 4, &data, crc).is_err());
        download.chunk(0, 8, &data, crc).unwrap();
        assert!(download.params(&data).is_err());
        assert!(download.chunk(2, 0, &data, crc).is_err());
        download.chunk(1, 0, &data, crc).unwrap();
        assert!(download.chunk(0, 16, &data, crc).is_err());
        assert!(download.activate().is_err());
        download.chunk(2, 0, &data, crc).unwrap();
        let image = download.activate().unwrap();
        let whole = identity(&[0x5a; 16]);
        assert_eq!(image.sections[0], (0, whole));
        assert_eq!(image.sections[2].1.bytes, 8);
        assert!(download.activate().is_err());
    }
}
