//! `boot prepare --disk`: the boot bundle from an installed system's Preboot
//! volume, built by `stela_loader::installed` with Stela's own APFS reader,
//! the same code `stela.efi` runs at boot.
use super::Prepare;
use crate::apfs::open_image;
use anyhow::{Result, ensure};
use std::path::Path;
use stela_loader::{boot_selection::BootVolume, installed};
use stela_runtime::apfs;

impl Prepare {
    pub(super) fn run_disk(&self, path: &Path) -> Result<()> {
        ensure!(
            !self.output.exists(),
            "output exists; choose a new --output directory"
        );
        let mut image = open_image(path)?;
        let options = self.options(None)?;
        let volume = self
            .boot_volume
            .as_deref()
            .map(|text| BootVolume::parse(text.as_bytes()))
            .transpose()?;
        let request = installed::Request {
            boot_hash: self.boot_hash.as_deref(),
            model: self.model.as_deref(),
            volume,
            authority: None,
        };
        let (offset, installed) = installed::prepare_disk(&mut image, &request, &options)?;
        let provenance = serde_json::json!({
            "disk": {
                "path": path.canonicalize()?.display().to_string(),
                "container_offset": offset,
                "preboot_volume": installed.preboot.name,
                "preboot_uuid": apfs::uuid_text(&installed.preboot.uuid),
                "boot_directory": installed.set.directory(),
                "evidence": installed.evidence,
                "objects": installed.set.objects.iter().map(|o| serde_json::json!({
                    "path": o.path,
                    "payload_type": String::from_utf8_lossy(&o.payload_type),
                    "bytes": o.bytes,
                })).collect::<Vec<_>>(),
            }
        });
        self.write(&installed.bundle, provenance)
    }
}
