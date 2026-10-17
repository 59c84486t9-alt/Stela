//! The kernel boot bundle of an installed system, built from its APFS
//! container's Preboot volume (`stela_runtime::preboot`), in `no_std` so
//! `stela.efi` builds the same bundle `stela boot prepare --disk` writes.
//!
//! The boot objects are the Image4 files of the boot directory, chosen by
//! payload type; each is split into its payload, decoded unchanged, and its
//! personalized manifest. The kernel collection's manifest is the boot
//! manifest. The product version and build come from the volume group's
//! `SystemVersion.plist` on Preboot, the model and board name from the
//! DeviceTree, and chip and board identifiers from the boot manifest.
use crate::{
    apple_device_tree::DeviceTree,
    boot_bundle::{self, Bundle, Input, Inputs, Options, Source, Target},
    im4m, im4p,
};
use alloc::{format, string::String, vec::Vec};
use anyhow::{Context, Result, anyhow, bail, ensure};
use stela_runtime::{
    apfs::{Container, Volume},
    img4,
    payload::ReadAt,
    preboot::{self, BootSet, SYSTEM_VERSION},
    sha256,
};

/// The variant recorded for a bundle read from an installed system.
pub const INSTALLED_SYSTEM: &str = "installed system (Preboot)";
pub const KERNEL_LIMIT: u64 = 512 * 1024 * 1024;
pub const COMPONENT_LIMIT: u64 = 64 * 1024 * 1024;
const SEP_FIRMWARE_TYPE: &[u8; 4] = b"sepi";

/// A bundle and where on the container its objects came from.
pub struct Installed {
    pub bundle: Bundle,
    pub preboot: Volume,
    pub set: BootSet,
}

struct Decoded {
    bytes: Vec<u8>,
    source: Source,
}

impl Decoded {
    fn input(&self) -> Input<'_> {
        Input {
            bytes: &self.bytes,
            source: self.source.clone(),
        }
    }
}

struct Disk<'a, R: ReadAt> {
    container: &'a mut Container<R>,
    preboot: Volume,
    set: BootSet,
}

impl<R: ReadAt> Disk<'_, R> {
    fn read(&mut self, object: &preboot::Object) -> Result<Vec<u8>> {
        preboot::read(self.container, &self.preboot, object)
            .map_err(|e| anyhow!("{}: {e}", object.path))
    }

    /// The single object of `kind`, decoded, and its manifest.
    fn decode(&mut self, kind: &[u8; 4], limit: u64) -> Result<(Decoded, Option<Vec<u8>>)> {
        let object = self.set.require(kind).map_err(|e| anyhow!("{e}"))?.clone();
        let file = self.read(&object)?;
        let parts = img4::parse(&file).map_err(|e| anyhow!("{}: {e}", object.path))?;
        let (bytes, receipt) = im4p::decode(parts.payload, limit)?;
        let decoded = Decoded {
            source: Source {
                component: format!("Preboot {}", String::from_utf8_lossy(kind)),
                member: object.path.clone(),
                container_sha256: sha256(&file),
                payload_type: receipt.payload_type,
                description: receipt.description,
                decoded_bytes: bytes.len(),
                decoded_sha256: sha256(&bytes),
            },
            bytes,
        };
        Ok((decoded, parts.manifest.map(<[u8]>::to_vec)))
    }

    /// An optional object kept as its encoded payload, as the SEP firmware is.
    fn opaque(&mut self, kind: &[u8; 4]) -> Result<Option<Decoded>> {
        let Some(object) = self.set.object(kind).map_err(|e| anyhow!("{e}"))?.cloned() else {
            return Ok(None);
        };
        let file = self.read(&object)?;
        let parts = img4::parse(&file).map_err(|e| anyhow!("{}: {e}", object.path))?;
        Ok(Some(Decoded {
            source: Source {
                component: format!("Preboot {}", String::from_utf8_lossy(kind)),
                member: object.path.clone(),
                container_sha256: sha256(&file),
                payload_type: "opaque".into(),
                description: String::new(),
                decoded_bytes: parts.payload.len(),
                decoded_sha256: sha256(parts.payload),
            },
            bytes: parts.payload.to_vec(),
        }))
    }

    /// `ProductVersion` and `ProductBuildVersion` of the volume group.
    fn system_version(&mut self) -> Result<(String, String)> {
        let path = format!("{}/{SYSTEM_VERSION}", self.set.volume_group);
        let device = &mut self.container.device;
        let inode = self
            .preboot
            .lookup(device, &path, true)
            .map_err(|e| anyhow!("{path}: {e}"))?;
        let bytes = self
            .preboot
            .read(device, &inode)
            .map_err(|e| anyhow!("{path}: {e}"))?;
        let text = core::str::from_utf8(&bytes).with_context(|| format!("{path} is not UTF-8"))?;
        let field = |key: &str| -> Result<String> {
            plist_string(text, key)
                .with_context(|| path.clone())?
                .with_context(|| format!("{path} has no {key}"))
        };
        Ok((field("ProductVersion")?, field("ProductBuildVersion")?))
    }
}

/// The `<string>` value of `key` in the top-level dictionary of an XML
/// property list; `None` when the key is absent. Binary property lists are
/// refused.
fn plist_string(text: &str, key: &str) -> Result<Option<String>> {
    ensure!(
        !text.starts_with("bplist"),
        "binary property lists are unsupported"
    );
    ensure!(
        text.contains("<plist") && text.contains("<dict>"),
        "not an XML property list"
    );
    let marker = format!("<key>{key}</key>");
    let Some(at) = text.find(&marker) else {
        return Ok(None);
    };
    let rest = text[at + marker.len()..].trim_start();
    let value = rest
        .strip_prefix("<string>")
        .and_then(|rest| rest.split_once("</string>"))
        .map(|(value, _)| value)
        .with_context(|| format!("{key} is not a string"))?;
    let mut decoded = String::new();
    let mut rest = value;
    while let Some(at) = rest.find('&') {
        decoded.push_str(&rest[..at]);
        let (entity, after) = rest[at..]
            .split_once(';')
            .context("unterminated XML entity")?;
        decoded.push(match entity {
            "&amp" => '&',
            "&lt" => '<',
            "&gt" => '>',
            "&quot" => '"',
            "&apos" => '\'',
            _ => bail!("unsupported XML entity {entity};"),
        });
        rest = after;
    }
    decoded.push_str(rest);
    Ok(Some(decoded))
}

fn root_string(tree: &DeviceTree, property: &str) -> Result<String> {
    tree.property("/", property)
        .and_then(|p| p.as_str())
        .map(Into::into)
        .with_context(|| format!("the DeviceTree root has no {property}"))
}

fn manifest_id(manifest: Option<&im4m::Manifest>, key: &str) -> Result<Option<u32>> {
    match manifest.and_then(|m| m.property(key)) {
        Some(im4m::Value::Integer(value)) => Ok(Some(u32::try_from(*value)?)),
        Some(_) => bail!("boot manifest {key} is not an integer"),
        None => Ok(None),
    }
}

/// Build the boot bundle of the installed system on `container`. `boot_hash`
/// names the boot directory when there are several; `model`, when given,
/// must match the DeviceTree's.
pub fn prepare<R: ReadAt>(
    container: &mut Container<R>,
    boot_hash: Option<&str>,
    model: Option<&str>,
    options: &Options,
) -> Result<Installed> {
    let (preboot, set) = preboot::boot_set(container, boot_hash).map_err(|e| anyhow!("{e}"))?;
    let mut disk = Disk {
        container,
        preboot,
        set,
    };
    let (kernel, boot_manifest) = disk.decode(b"krnl", KERNEL_LIMIT)?;
    let (sptm, _) = disk.decode(b"sptm", COMPONENT_LIMIT)?;
    let (txm, _) = disk.decode(b"trxm", COMPONENT_LIMIT)?;
    let (device_tree, _) = disk.decode(b"dtre", COMPONENT_LIMIT)?;
    let (trust_cache, _) = disk.decode(b"trst", COMPONENT_LIMIT)?;
    let sep = disk.opaque(SEP_FIRMWARE_TYPE)?;
    let (product_version, product_build) = disk.system_version()?;
    let tree = DeviceTree::parse(&device_tree.bytes)?;
    let product_type = root_string(&tree, "model")?;
    if let Some(wanted) = model {
        ensure!(
            wanted == product_type,
            "the disk's system is a {product_type}, not a {wanted}"
        );
    }
    let target_type = root_string(&tree, "target-type")?;
    let manifest = boot_manifest.as_deref().map(im4m::parse).transpose()?;
    let boot_manifest = boot_manifest.map(|bytes| Decoded {
        source: Source {
            component: "Boot manifest".into(),
            member: kernel.source.member.clone(),
            container_sha256: sha256(&bytes),
            payload_type: "im4m".into(),
            description: "the kernel collection's personalized manifest".into(),
            decoded_bytes: bytes.len(),
            decoded_sha256: sha256(&bytes),
        },
        bytes,
    });
    let inputs = Inputs {
        target: Target {
            product_type,
            device_class: format!("{}ap", target_type.to_ascii_lowercase()),
            product_version,
            product_build,
            variant: INSTALLED_SYSTEM.into(),
            chip_id: manifest_id(manifest.as_ref(), "CHIP")?,
            board_id: manifest_id(manifest.as_ref(), "BORD")?,
        },
        kernel_collection: kernel.input(),
        sptm: sptm.input(),
        txm: txm.input(),
        device_tree: device_tree.input(),
        static_trust_cache: trust_cache.input(),
        sep_firmware: sep.as_ref().map(Decoded::input),
        boot_manifest: boot_manifest.as_ref().map(Decoded::input),
        cryptex1_manifest: None,
        extra_trust_caches: Vec::new(),
        ramdisk: None,
    };
    let bundle = boot_bundle::prepare(&inputs, options)?;
    Ok(Installed {
        bundle,
        preboot: disk.preboot,
        set: disk.set,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_strings_from_xml_property_lists() {
        let text = "<?xml version=\"1.0\"?>\n<plist version=\"1.0\">\n<dict>\n\
            \t<key>ProductBuildVersion</key>\n\t<string>26A434</string>\n\
            \t<key>ProductName</key>\n\t<string>mac&amp;OS &lt;x&gt;</string>\n\
            \t<key>Count</key>\n\t<integer>3</integer>\n</dict>\n</plist>\n";
        assert_eq!(
            plist_string(text, "ProductBuildVersion")
                .unwrap()
                .as_deref(),
            Some("26A434")
        );
        assert_eq!(
            plist_string(text, "ProductName").unwrap().as_deref(),
            Some("mac&OS <x>")
        );
        assert_eq!(plist_string(text, "ProductVersion").unwrap(), None);
        assert!(plist_string(text, "Count").is_err());
        assert!(plist_string("bplist00", "ProductVersion").is_err());
    }
}
