//! `boot prepare --disk`: the boot bundle from an installed system's Preboot
//! volume, read with Stela's own APFS reader (`stela_runtime::preboot`).
//!
//! The objects are the Image4 files of the boot directory, chosen by payload
//! type; each is split into its payload, decoded unchanged, and its
//! personalized manifest. The kernel collection's manifest is the boot
//! manifest. The product version and build come from the volume group's
//! `SystemVersion.plist` on Preboot, the model and board name from the
//! DeviceTree, and chip and board identifiers from the boot manifest.
use super::{COMPONENT_LIMIT, Decoded, KERNEL_LIMIT, Prepare};
use crate::apfs::{Image, open_image};
use anyhow::{Context, Result, bail, ensure};
use plist::Value;
use std::path::Path;
use stela_loader::{
    apple_device_tree::DeviceTree,
    boot_bundle::{self, Input, Inputs, Source, Target},
    im4m,
};
use stela_runtime::{
    apfs::{self, Container, Volume},
    img4,
    preboot::{self, BootSet, SYSTEM_VERSION},
};

/// The variant recorded for a bundle read from an installed system.
const INSTALLED_SYSTEM: &str = "installed system (Preboot)";
const SEP_FIRMWARE_TYPE: &[u8; 4] = b"sepi";

struct Disk {
    container: Container<Image>,
    preboot: Volume,
    set: BootSet,
}

impl Disk {
    fn read(&mut self, object: &preboot::Object) -> Result<Vec<u8>> {
        preboot::read(&mut self.container, &self.preboot, object)
            .map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// The single object of `kind`, decoded, and its manifest.
    fn decode(&mut self, kind: &[u8; 4], limit: u64) -> Result<(Decoded, Option<Vec<u8>>)> {
        let object = self
            .set
            .require(kind)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .clone();
        let file = self.read(&object)?;
        let parts = img4::parse(&file).map_err(|e| anyhow::anyhow!("{}: {e}", object.path))?;
        let (bytes, receipt) = stela_loader::im4p::decode(parts.payload, limit)?;
        let decoded = Decoded {
            source: Source {
                component: format!("Preboot {}", String::from_utf8_lossy(kind)),
                member: object.path.clone(),
                container_sha256: stela_runtime::sha256(&file),
                payload_type: receipt.payload_type,
                description: receipt.description,
                decoded_bytes: bytes.len(),
                decoded_sha256: stela_runtime::sha256(&bytes),
            },
            bytes,
            declared_digest: None,
        };
        Ok((decoded, parts.manifest.map(<[u8]>::to_vec)))
    }

    /// An optional object kept as its encoded payload, as the SEP firmware is.
    fn opaque(&mut self, kind: &[u8; 4]) -> Result<Option<Decoded>> {
        let Some(object) = self
            .set
            .object(kind)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .cloned()
        else {
            return Ok(None);
        };
        let file = self.read(&object)?;
        let parts = img4::parse(&file).map_err(|e| anyhow::anyhow!("{}: {e}", object.path))?;
        Ok(Some(Decoded {
            source: Source {
                component: format!("Preboot {}", String::from_utf8_lossy(kind)),
                member: object.path.clone(),
                container_sha256: stela_runtime::sha256(&file),
                payload_type: "opaque".into(),
                description: String::new(),
                decoded_bytes: parts.payload.len(),
                decoded_sha256: stela_runtime::sha256(parts.payload),
            },
            bytes: parts.payload.to_vec(),
            declared_digest: None,
        }))
    }

    /// `ProductVersion` and `ProductBuildVersion` of the volume group.
    fn system_version(&mut self) -> Result<(String, String)> {
        let path = format!("{}/{SYSTEM_VERSION}", self.set.volume_group);
        let inode = self
            .preboot
            .lookup(&mut self.container.device, &path, true)
            .map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
        let bytes = self
            .preboot
            .read(&mut self.container.device, &inode)
            .map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
        let value = Value::from_reader(std::io::Cursor::new(bytes))?;
        let field = |key: &str| {
            value
                .as_dictionary()
                .and_then(|d| d.get(key))
                .and_then(Value::as_string)
                .map(str::to_owned)
                .with_context(|| format!("{path} has no {key}"))
        };
        Ok((field("ProductVersion")?, field("ProductBuildVersion")?))
    }
}

fn root_string(tree: &DeviceTree, property: &str) -> Result<String> {
    tree.property("/", property)
        .and_then(|p| p.as_str())
        .map(str::to_owned)
        .with_context(|| format!("the DeviceTree root has no {property}"))
}

fn manifest_id(manifest: Option<&im4m::Manifest>, key: &str) -> Result<Option<u32>> {
    match manifest.and_then(|m| m.property(key)) {
        Some(im4m::Value::Integer(value)) => Ok(Some(u32::try_from(*value)?)),
        Some(_) => bail!("boot manifest {key} is not an integer"),
        None => Ok(None),
    }
}

impl Prepare {
    pub(super) fn run_disk(&self, path: &Path) -> Result<()> {
        ensure!(
            !self.output.exists(),
            "output exists; choose a new --output directory"
        );
        let mut probe = open_image(path)?;
        let offsets = apfs::containers(&mut probe)?;
        let mut failures = Vec::new();
        let mut found = None;
        for offset in offsets {
            let mut container = Container::open(open_image(path)?, offset)?;
            match preboot::boot_set(&mut container, self.boot_hash.as_deref()) {
                Ok((preboot, set)) => {
                    found = Some((
                        offset,
                        Disk {
                            container,
                            preboot,
                            set,
                        },
                    ));
                    break;
                }
                Err(error) => failures.push(format!("container at {offset:#x}: {error}")),
            }
        }
        let Some((offset, mut disk)) = found else {
            bail!("no installed system to boot: {}", failures.join("; "));
        };
        let (kernel, boot_manifest) = disk.decode(b"krnl", KERNEL_LIMIT)?;
        let (sptm, _) = disk.decode(b"sptm", COMPONENT_LIMIT)?;
        let (txm, _) = disk.decode(b"trxm", COMPONENT_LIMIT)?;
        let (device_tree, _) = disk.decode(b"dtre", COMPONENT_LIMIT)?;
        let (trust_cache, _) = disk.decode(b"trst", COMPONENT_LIMIT)?;
        let sep = disk.opaque(SEP_FIRMWARE_TYPE)?;
        let (product_version, product_build) = disk.system_version()?;
        let tree = DeviceTree::parse(&device_tree.bytes)?;
        let model = root_string(&tree, "model")?;
        if let Some(wanted) = &self.model {
            ensure!(
                wanted == &model,
                "the disk's system is a {model}, not a {wanted}"
            );
        }
        let target_type = root_string(&tree, "target-type")?;
        let manifest = boot_manifest.as_deref().map(im4m::parse).transpose()?;
        let boot_manifest = boot_manifest.map(|bytes| Decoded {
            source: Source {
                component: "Boot manifest".into(),
                member: kernel.source.member.clone(),
                container_sha256: stela_runtime::sha256(&bytes),
                payload_type: "im4m".into(),
                description: "the kernel collection's personalized manifest".into(),
                decoded_bytes: bytes.len(),
                decoded_sha256: stela_runtime::sha256(&bytes),
            },
            bytes,
            declared_digest: None,
        });
        fn input(decoded: &Decoded) -> Input<'_> {
            Input {
                bytes: &decoded.bytes,
                source: decoded.source.clone(),
            }
        }
        let inputs = Inputs {
            target: Target {
                product_type: model,
                device_class: format!("{}ap", target_type.to_ascii_lowercase()),
                product_version,
                product_build,
                variant: INSTALLED_SYSTEM.into(),
                chip_id: manifest_id(manifest.as_ref(), "CHIP")?,
                board_id: manifest_id(manifest.as_ref(), "BORD")?,
            },
            kernel_collection: input(&kernel),
            sptm: input(&sptm),
            txm: input(&txm),
            device_tree: input(&device_tree),
            static_trust_cache: input(&trust_cache),
            sep_firmware: sep.as_ref().map(input),
            boot_manifest: boot_manifest.as_ref().map(input),
            cryptex1_manifest: None,
            extra_trust_caches: Vec::new(),
            ramdisk: None,
        };
        let options = self.options(false)?;
        let bundle = boot_bundle::prepare(&inputs, &options)?;
        let provenance = serde_json::json!({
            "disk": {
                "path": path.canonicalize()?.display().to_string(),
                "container_offset": offset,
                "preboot_volume": disk.preboot.name,
                "preboot_uuid": apfs::uuid_text(&disk.preboot.uuid),
                "boot_directory": disk.set.directory(),
                "objects": disk.set.objects.iter().map(|o| serde_json::json!({
                    "path": o.path,
                    "payload_type": String::from_utf8_lossy(&o.payload_type),
                    "bytes": o.bytes,
                })).collect::<Vec<_>>(),
            }
        });
        self.write(&bundle, provenance)
    }
}
