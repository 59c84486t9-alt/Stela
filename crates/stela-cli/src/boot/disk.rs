//! `boot prepare --disk`: the boot bundle from an installed system's Preboot
//! volume, built by `stela_loader::installed` with Stela's own APFS reader,
//! the same code `stela.efi` runs at boot.
use super::Prepare;
use crate::apfs::open_image;
use anyhow::{Result, bail, ensure};
use std::path::Path;
use stela_loader::installed;
use stela_runtime::apfs::{self, Container};

impl Prepare {
    pub(super) fn run_disk(&self, path: &Path) -> Result<()> {
        ensure!(
            !self.output.exists(),
            "output exists; choose a new --output directory"
        );
        let mut probe = open_image(path)?;
        let options = self.options(false)?;
        let mut failures = Vec::new();
        for offset in apfs::containers(&mut probe)? {
            let mut container = Container::open(open_image(path)?, offset)?;
            let installed = match installed::prepare(
                &mut container,
                self.boot_hash.as_deref(),
                self.model.as_deref(),
                &options,
            ) {
                Ok(installed) => installed,
                Err(error) => {
                    failures.push(format!("container at {offset:#x}: {error:#}"));
                    continue;
                }
            };
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
            return self.write(&installed.bundle, provenance);
        }
        bail!("no installed system to boot: {}", failures.join("; "))
    }
}
