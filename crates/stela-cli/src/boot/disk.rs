//! `boot prepare --disk`: the boot bundle from an installed system's Preboot
//! volume, built by `stela_loader::installed` with Stela's own APFS reader,
//! the same code `stela.efi` runs at boot; with `--upgrade` a staged
//! update's (`stela_loader::upgrade`), and with `--disk-recovery` a
//! recoveryOS's (`stela_loader::recovery`).
use super::{DiskRecovery, Prepare};
use crate::apfs::open_image;
use anyhow::{Result, ensure};
use std::path::Path;
use stela_formats::apfs;
use stela_loader::{boot_selection::BootVolume, installed, recovery, upgrade};

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
        if self.upgrade {
            return self.run_upgrade(&mut image, path, volume, &options);
        }
        if let Some(kind) = self.disk_recovery {
            let kind = match kind {
                DiskRecovery::Paired => recovery::Kind::Paired,
                DiskRecovery::System => recovery::Kind::System,
            };
            return self.run_recovery(&mut image, path, kind, volume, &options);
        }
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

    fn run_recovery(
        &self,
        image: &mut crate::apfs::Image,
        path: &Path,
        kind: recovery::Kind,
        volume: Option<BootVolume>,
        options: &stela_loader::boot_bundle::Options,
    ) -> Result<()> {
        let (offset, recovered) =
            recovery::prepare_disk(image, kind, volume.as_ref(), self.model.as_deref(), options)?;
        let provenance = serde_json::json!({
            "disk": {
                "path": path.canonicalize()?.display().to_string(),
                "container_offset": offset,
                "recovery": kind.label(),
                "recovery_volume": recovered.volume.name,
                "recovery_uuid": apfs::uuid_text(&recovered.volume.uuid),
                "boot_directory": recovered.set.directory(),
                "evidence": recovered.evidence,
                "objects": recovered.set.objects.iter().map(|o| serde_json::json!({
                    "path": o.path,
                    "payload_type": String::from_utf8_lossy(&o.payload_type),
                    "bytes": o.bytes,
                })).collect::<Vec<_>>(),
            }
        });
        self.write(&recovered.bundle, provenance)
    }

    fn run_upgrade(
        &self,
        image: &mut crate::apfs::Image,
        path: &Path,
        volume: Option<BootVolume>,
        options: &stela_loader::boot_bundle::Options,
    ) -> Result<()> {
        let mut options = options.clone();
        // The update ramdisk's boot-args and OS environment, unless the user
        // gave their own with --boot-args / --osenvironment.
        if self.boot_args.is_none() {
            options.boot_args = super::boot_args(&options.boot_args, upgrade::BOOT_ARGS);
        }
        options.osenvironment = options.osenvironment.or(Some(upgrade::ENVIRONMENT));
        let (offset, staged) = upgrade::prepare_disk(image, volume, None, &options)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let provenance = serde_json::json!({
            "disk": {
                "path": path.canonicalize()?.display().to_string(),
                "container_offset": offset,
                "update_volume": staged.volume.name,
                "staged_objects": staged.update.root.iter().map(|o| serde_json::json!({
                    "path": o.path,
                    "payload_type": o.payload_type.map(|t| String::from_utf8_lossy(&t).into_owned()),
                    "bytes": o.bytes,
                })).collect::<Vec<_>>(),
                "firmware_set_aside": staged.update.other_firmware.iter()
                    .map(|o| o.path.clone()).collect::<Vec<_>>(),
            }
        });
        self.write(&staged.bundle, provenance)
    }
}
