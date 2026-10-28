//! The boot of a staged macOS update: the objects macOS left on its
//! container's Update volume (APFS role 0xc0), built into a boot bundle in
//! `no_std`, so `stela.efi` boots it when NVRAM's `boot-command` is
//! `upgrade` and `stela-dev boot prepare --disk --upgrade` writes the same one.
//!
//! The 26A434 J473 LLB upgrade (image offset 0x448c) mounts the Update
//! volume at `/boot` and runs `/boot/iBEC`; that iBEC (iBoot 0x5634) loads
//! every file of `/boot/iboot_firmware`, then `/boot/sep-firmware`,
//! `/boot/devicetree`, `/boot/ramdisk`, `/boot/iBootData` and
//! `/boot/kernelcache`, and boots the ramdisk (`rd=md0`). Stela takes
//! iBEC's place: its object and iBootData must exist, as iBoot requires,
//! but are not run. Each object is an Image4 file identified by payload
//! type; the firmware directory holds the SPTM (`sptm`), TXM (`trxm`) and a
//! trust cache (`rtsc` or `trst`) with coprocessor firmware Stela's own
//! device models replace. One manifest covers all of them, recording each
//! by digest, as one APTicket covers a restore; its signature is checked
//! only when a SEP [`PolicyAuthority`] is given. A step that fails is named
//! as LLB and iBoot name it in `ota-result`/`ota-failure-reason`.
use crate::{
    apple_device_tree::DeviceTree,
    boot_bundle::{self, Bundle, Input, Inputs, Options, OwnedRamdisk, Source, Target},
    boot_policy::OsEnvironment,
    boot_selection::{BootVolume, VolumeType, uuid_text},
    im4m, im4p,
    installed::{COMPONENT_LIMIT, KERNEL_LIMIT},
    local_policy::PolicyAuthority,
    root_selection::Root,
};
use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use stela_runtime::{
    apfs::{self, ApfsError, Container, FileKind, Volume, volume::ROOT_DIR_INO_NUM},
    img4,
    payload::ReadAt,
    sha256,
};

/// The variant recorded for a bundle read from an Update volume.
pub const UPDATE_VARIANT: &str = "macOS update (Update volume)";
/// iBoot's boot-args for its upgrade ramdisk.
pub const BOOT_ARGS: &[&str] = &["rd=md0", "-progress", "-restore"];
pub const ENVIRONMENT: OsEnvironment = OsEnvironment::Upgrade;

/// LLB's `ota-result` when the upgrade partition or iBEC fails.
pub const LLB_FAILURE: &str = "failed to execute upgrade command from iBoot";
/// iBEC's `ota-result` when an object fails.
pub const IBEC_FAILURE: &str = "failed to execute upgrade command from new iBEC";
const FIRMWARE_DIRECTORY: &str = "iboot_firmware";
const PEEK_BYTES: usize = 64;

/// An object Stela needs, by name, Image4 type and failure step.
struct Needed {
    file: &'static str,
    payload_type: [u8; 4],
    step: &'static str,
    result: &'static str,
}

const ROOT_OBJECTS: [Needed; 6] = [
    Needed {
        file: "iBEC",
        payload_type: *b"ibec",
        step: "load upgrade iBEC",
        result: LLB_FAILURE,
    },
    Needed {
        file: "sep-firmware",
        payload_type: *b"sepi",
        step: "sepfw",
        result: IBEC_FAILURE,
    },
    Needed {
        file: "devicetree",
        payload_type: *b"dtre",
        step: "devicetree",
        result: IBEC_FAILURE,
    },
    Needed {
        file: "ramdisk",
        payload_type: *b"rdsk",
        step: "ramdisk",
        result: IBEC_FAILURE,
    },
    Needed {
        file: "iBootData",
        payload_type: *b"ibdt",
        step: "iBootData",
        result: IBEC_FAILURE,
    },
    Needed {
        file: "kernelcache",
        payload_type: *b"krnl",
        step: "kernelcache",
        result: IBEC_FAILURE,
    },
];
const SPTM_TYPE: [u8; 4] = *b"sptm";
const TXM_TYPE: [u8; 4] = *b"trxm";
const TRUST_CACHE_TYPES: [[u8; 4]; 2] = [*b"rtsc", *b"trst"];

/// Why an upgrade boot cannot run, named as LLB and iBoot record it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// `ota-result`.
    pub result: &'static str,
    /// `ota-failure-reason`: the step.
    pub step: &'static str,
    pub detail: String,
}

impl core::fmt::Display for Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {} ({})", self.result, self.step, self.detail)
    }
}

/// One file on the Update volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Staged {
    pub path: String,
    /// The Image4 payload type; `None` when the file is not one.
    pub payload_type: Option<[u8; 4]>,
    pub bytes: u64,
    pub oid: u64,
}

/// The update staged on a container's Update volume.
#[derive(Debug, Clone)]
pub struct Update {
    pub volume: Volume,
    /// The six root objects, in iBoot's order.
    pub root: Vec<Staged>,
    pub sptm: Staged,
    pub txm: Staged,
    /// Trust caches, the first the static one.
    pub trust_caches: Vec<Staged>,
    /// Coprocessor firmware iBoot loads that Stela's models replace.
    pub other_firmware: Vec<Staged>,
}

impl Update {
    /// The root object of this type.
    pub fn object(&self, payload_type: &[u8; 4]) -> &Staged {
        self.root
            .iter()
            .find(|s| s.payload_type == Some(*payload_type))
            .expect("the layout required it")
    }
}

#[derive(Debug)]
struct Parts {
    root: Vec<Staged>,
    sptm: Staged,
    txm: Staged,
    trust_caches: Vec<Staged>,
    other_firmware: Vec<Staged>,
}

fn listing<R: ReadAt>(
    volume: &Volume,
    device: &mut apfs::Device<R>,
    directory: u64,
    prefix: &str,
) -> apfs::Result<Vec<Staged>> {
    let mut staged = Vec::new();
    for entry in volume.entries(device, directory)? {
        if entry.kind != FileKind::Regular {
            continue;
        }
        let inode = volume.inode(device, entry.oid)?;
        let mut payload_type = None;
        if inode.size >= PEEK_BYTES as u64 {
            let mut bytes = [0u8; PEEK_BYTES];
            volume.read_at(device, &inode, 0, &mut bytes)?;
            payload_type = img4::peek_payload_type(&bytes).ok();
        }
        staged.push(Staged {
            path: format!("{prefix}/{}", entry.name),
            payload_type,
            bytes: inode.size,
            oid: inode.oid,
        });
    }
    Ok(staged)
}

fn firmware_failure(detail: String) -> Failure {
    Failure {
        result: IBEC_FAILURE,
        step: "firmware",
        detail,
    }
}

/// Check the files iBoot loads, in its order, naming the first that fails.
fn classify(root: &[Staged], firmware: Option<&[Staged]>) -> Result<Parts, Failure> {
    let mut found = Vec::new();
    for need in &ROOT_OBJECTS {
        let path = format!("/{}", need.file);
        let staged = root.iter().find(|s| s.path == path).ok_or(Failure {
            result: need.result,
            step: need.step,
            detail: format!("the Update volume has no {path}"),
        })?;
        match staged.payload_type {
            Some(kind) if kind == need.payload_type => found.push(staged.clone()),
            other => {
                return Err(Failure {
                    result: need.result,
                    step: need.step,
                    detail: match other {
                        Some(kind) => format!(
                            "{path} is a `{}` object, not `{}`",
                            String::from_utf8_lossy(&kind),
                            String::from_utf8_lossy(&need.payload_type)
                        ),
                        None => format!("{path} is not an Image4 object"),
                    },
                });
            }
        }
    }
    let firmware = firmware.ok_or_else(|| {
        firmware_failure(format!("the Update volume has no /{FIRMWARE_DIRECTORY}"))
    })?;
    let single = |kind: [u8; 4]| -> Result<Staged, Failure> {
        let mut it = firmware.iter().filter(|s| s.payload_type == Some(kind));
        match (it.next(), it.next()) {
            (Some(one), None) => Ok(one.clone()),
            (None, _) => Err(firmware_failure(format!(
                "/{FIRMWARE_DIRECTORY} has no `{}` object",
                String::from_utf8_lossy(&kind)
            ))),
            _ => Err(firmware_failure(format!(
                "/{FIRMWARE_DIRECTORY} has several `{}` objects",
                String::from_utf8_lossy(&kind)
            ))),
        }
    };
    let sptm = single(SPTM_TYPE)?;
    let txm = single(TXM_TYPE)?;
    let mut trust_caches = Vec::new();
    for kind in TRUST_CACHE_TYPES {
        trust_caches.extend(
            firmware
                .iter()
                .filter(|s| s.payload_type == Some(kind))
                .cloned(),
        );
    }
    if trust_caches.is_empty() {
        return Err(firmware_failure(format!(
            "/{FIRMWARE_DIRECTORY} has no trust cache (`rtsc` or `trst`)"
        )));
    }
    let mut other_firmware = Vec::new();
    for staged in firmware {
        match staged.payload_type {
            Some(kind)
                if kind == SPTM_TYPE || kind == TXM_TYPE || TRUST_CACHE_TYPES.contains(&kind) => {}
            Some(_) => other_firmware.push(staged.clone()),
            None => {
                return Err(firmware_failure(format!(
                    "{} is not an Image4 object",
                    staged.path
                )));
            }
        }
    }
    Ok(Parts {
        root: found,
        sptm,
        txm,
        trust_caches,
        other_firmware,
    })
}

/// The update staged on `container`'s Update volume, or the failure LLB and
/// iBoot would record. A missing volume, file or directory is a [`Failure`];
/// a disk that cannot be read is an error.
pub fn find<R: ReadAt>(container: &mut Container<R>) -> Result<Result<Update, Failure>, ApfsError> {
    let volume = match container.volume_with_role(apfs::volume::APFS_VOL_ROLE_UPDATE) {
        Ok(volume) => volume,
        Err(ApfsError::NotFound(_)) => {
            return Ok(Err(Failure {
                result: LLB_FAILURE,
                step: "mount upgrade partition",
                detail: "the container has no Update volume".into(),
            }));
        }
        Err(error) => return Err(error),
    };
    let device = &mut container.device;
    let root = listing(&volume, device, ROOT_DIR_INO_NUM, "")?;
    let firmware = match volume.child(device, ROOT_DIR_INO_NUM, FIRMWARE_DIRECTORY) {
        Ok(entry) if entry.kind == FileKind::Directory => Some(listing(
            &volume,
            device,
            entry.oid,
            &format!("/{FIRMWARE_DIRECTORY}"),
        )?),
        Ok(_) | Err(ApfsError::NotFound(_)) => None,
        Err(error) => return Err(error),
    };
    Ok(classify(&root, firmware.as_deref()).map(|parts| Update {
        volume,
        root: parts.root,
        sptm: parts.sptm,
        txm: parts.txm,
        trust_caches: parts.trust_caches,
        other_firmware: parts.other_firmware,
    }))
}

/// The installed boot's limits apply to an update's objects too.
const RAMDISK_LIMIT: u64 = 2 * 1024 * 1024 * 1024;

/// A boot bundle built from an Update volume, with where its objects came
/// from on the disk.
pub struct Staged2 {
    pub bundle: Bundle,
    pub volume: Volume,
    pub update: Update,
}

struct Reader<'a, R: ReadAt> {
    container: &'a mut Container<R>,
    volume: Volume,
}

struct Decoded {
    bytes: Vec<u8>,
    source: Source,
    /// SHA-384 of the object's `IM4P`, the manifest's `DGST` for it.
    im4p_sha384: [u8; 48],
}

impl Decoded {
    fn input(&self) -> Input<'_> {
        Input {
            bytes: &self.bytes,
            source: self.source.clone(),
        }
    }
}

impl<R: ReadAt> Reader<'_, R> {
    fn file(&mut self, staged: &Staged) -> Result<Vec<u8>, String> {
        let inode = self
            .volume
            .inode(&mut self.container.device, staged.oid)
            .map_err(|e| format!("{}: {e}", staged.path))?;
        self.volume
            .read(&mut self.container.device, &inode)
            .map_err(|e| format!("{}: {e}", staged.path))
    }

    /// Decode a staged object, with the SHA-384 of its `IM4P`.
    fn decode(&mut self, staged: &Staged, component: &str, limit: u64) -> Result<Decoded, String> {
        let file = self.file(staged)?;
        let parts = img4::parse(&file).map_err(|e| format!("{}: {e}", staged.path))?;
        let im4p_sha384 = im4m::sha384(parts.payload);
        let (bytes, receipt) = im4p::decode(parts.payload, limit).map_err(|e| format!("{e:#}"))?;
        Ok(Decoded {
            source: Source {
                component: component.into(),
                member: staged.path.clone(),
                container_sha256: sha256(&file),
                payload_type: receipt.payload_type,
                description: receipt.description,
                decoded_bytes: bytes.len(),
                decoded_sha256: sha256(&bytes),
            },
            bytes,
            im4p_sha384,
        })
    }

    /// Keep an object as its encoded `IM4P` (the SEP firmware), with its hash.
    fn encoded(&mut self, staged: &Staged, component: &str) -> Result<Decoded, String> {
        let file = self.file(staged)?;
        let parts = img4::parse(&file).map_err(|e| format!("{}: {e}", staged.path))?;
        Ok(Decoded {
            im4p_sha384: im4m::sha384(parts.payload),
            source: Source {
                component: component.into(),
                member: staged.path.clone(),
                container_sha256: sha256(&file),
                payload_type: "opaque".into(),
                description: String::new(),
                decoded_bytes: parts.payload.len(),
                decoded_sha256: sha256(parts.payload),
            },
            bytes: parts.payload.to_vec(),
        })
    }

    /// The manifest the objects carry (the kernel's `IMG4` tail), and its
    /// `DGST` for a payload type when present.
    fn manifest(&mut self, staged: &Staged) -> Result<Option<Vec<u8>>, String> {
        let file = self.file(staged)?;
        let parts = img4::parse(&file).map_err(|e| format!("{}: {e}", staged.path))?;
        Ok(parts.manifest.map(<[u8]>::to_vec))
    }
}

fn check_digest(
    manifest: Option<&im4m::Manifest>,
    tag: &str,
    decoded: &Decoded,
) -> Result<(), String> {
    let Some(manifest) = manifest else {
        return Ok(());
    };
    let digest = manifest
        .object(tag)
        .and_then(|o| o.properties.iter().find(|p| p.name == "DGST"))
        .map(|p| &p.value);
    match digest {
        Some(im4m::Value::Data(d)) if d.as_slice() == decoded.im4p_sha384.as_slice() => Ok(()),
        Some(im4m::Value::Data(_)) => Err(format!(
            "the update manifest's {tag} digest is not the staged object's"
        )),
        Some(_) => Err(format!("the update manifest's {tag} digest is not data")),
        None => Err(format!("the update manifest records no {tag} object")),
    }
}

/// Build the boot bundle of the update staged on `container`, as its objects
/// name, with `options`; `found` is [`find`]'s result. The manifest's
/// signature is checked only when `authority` is given.
pub fn prepare<R: ReadAt>(
    container: &mut Container<R>,
    found: Update,
    authority: Option<&dyn PolicyAuthority>,
    options: &Options,
) -> Result<Staged2, String> {
    let volume = found.volume.clone();
    let mut reader = Reader {
        container,
        volume: volume.clone(),
    };
    let kernel = reader.decode(found.object(b"krnl"), "Update KernelCache", KERNEL_LIMIT)?;
    let manifest_bytes = reader.manifest(found.object(b"krnl"))?;
    let manifest = manifest_bytes
        .as_deref()
        .map(im4m::parse)
        .transpose()
        .map_err(|e| format!("{e:#}"))?;
    if let (Some(bytes), Some(authority)) = (&manifest_bytes, authority) {
        authority.verify(bytes)?;
    }
    let sptm = reader.decode(&found.sptm, "Update SPTM", COMPONENT_LIMIT)?;
    let txm = reader.decode(&found.txm, "Update TXM", COMPONENT_LIMIT)?;
    let device_tree = reader.decode(found.object(b"dtre"), "Update DeviceTree", COMPONENT_LIMIT)?;
    let mut trust_caches = Vec::new();
    for staged in &found.trust_caches {
        trust_caches.push(reader.decode(staged, "Update TrustCache", COMPONENT_LIMIT)?);
    }
    let sep = reader.encoded(found.object(b"sepi"), "Update SEP")?;
    let ramdisk = reader.decode(found.object(b"rdsk"), "Update RamDisk", RAMDISK_LIMIT)?;
    // iBoot requires these, but Stela takes iBEC's place and runs neither.
    reader.file(found.object(b"ibec"))?;
    reader.file(found.object(b"ibdt"))?;
    for (tag, decoded) in [
        ("krnl", &kernel),
        ("sptm", &sptm),
        ("trxm", &txm),
        ("dtre", &device_tree),
    ] {
        check_digest(manifest.as_ref(), tag, decoded).map_err(|e| {
            Failure {
                result: IBEC_FAILURE,
                step: "load upgrade local policy",
                detail: e,
            }
            .to_string()
        })?;
    }
    let tree = DeviceTree::parse(&device_tree.bytes).map_err(|e| format!("{e:#}"))?;
    let product_type = tree
        .property("/", "model")
        .and_then(|p| p.as_str())
        .ok_or("the update DeviceTree has no model")?
        .to_string();
    let target_type = tree
        .property("/", "target-type")
        .and_then(|p| p.as_str())
        .ok_or("the update DeviceTree has no target-type")?
        .to_string();
    let id = |key: &str| match manifest.as_ref().and_then(|m| m.property(key)) {
        Some(im4m::Value::Integer(v)) => u32::try_from(*v).ok(),
        _ => None,
    };
    let extra: Vec<Input> = trust_caches.iter().skip(1).map(Decoded::input).collect();
    let inputs = Inputs {
        target: Target {
            product_type,
            device_class: format!("{}ap", target_type.to_ascii_lowercase()),
            product_version: String::new(),
            product_build: String::new(),
            variant: UPDATE_VARIANT.into(),
            chip_id: id("CHIP"),
            board_id: id("BORD"),
        },
        kernel_collection: kernel.input(),
        sptm: sptm.input(),
        txm: txm.input(),
        device_tree: device_tree.input(),
        static_trust_cache: trust_caches[0].input(),
        sep_firmware: Some(sep.input()),
        boot_manifest: manifest_bytes.as_ref().map(|bytes| Input {
            bytes,
            source: Source {
                component: "Update manifest".into(),
                member: found.object(b"krnl").path.clone(),
                container_sha256: sha256(bytes),
                payload_type: "im4m".into(),
                description: "the staged kernel's manifest".into(),
                decoded_bytes: bytes.len(),
                decoded_sha256: sha256(bytes),
            },
        }),
        cryptex1_manifest: None,
        extra_trust_caches: extra,
        ramdisk: None,
        root_hash: None,
        board_firmware: Vec::new(),
    };
    let mut options = options.placed_at(inputs.dram_base().map_err(|e| format!("{e:#}"))?);
    options.root = Some(Root::Ramdisk);
    // LLB's Update-volume dispatch records 3 before loading /boot/iBEC;
    // it does not use the host-received iBEC origin (7).
    options.boot_command = Some(crate::handoff::BootCommand::Upgrade);
    let owned = OwnedRamdisk {
        bytes: ramdisk.bytes,
        source: ramdisk.source,
    };
    let mut bundle =
        boot_bundle::prepare_owned(&inputs, owned, &options).map_err(|e| format!("{e:#}"))?;
    if manifest_bytes.is_none() {
        bundle
            .manifest
            .unresolved
            .push("the staged objects carry no manifest; their digests are unchecked".into());
    } else if authority.is_none() {
        bundle
            .manifest
            .unresolved
            .push("the update manifest's signature is not verified; no SEP PolicyAuthority".into());
    }
    for staged in &found.other_firmware {
        bundle.manifest.unresolved.push(format!(
            "{} is coprocessor firmware iBoot loads; Stela's own device model serves it",
            staged.path
        ));
    }
    Ok(Staged2 {
        bundle,
        volume,
        update: found,
    })
}

/// Build the update bundle on `source`, a disk or one APFS container, with
/// the boot volume's container when `volume` names one.
pub fn prepare_disk<R: ReadAt>(
    source: &mut R,
    volume: Option<BootVolume>,
    authority: Option<&dyn PolicyAuthority>,
    options: &Options,
) -> Result<(u64, Staged2), String> {
    let mut partitions = apfs::container_partitions(source).map_err(|e| format!("{e}"))?;
    if let Some(volume) = &volume {
        if volume.kind != VolumeType::Apfs {
            return Err(format!(
                "NVRAM boots a {:?} partition, not an APFS container",
                volume.kind
            ));
        }
        partitions.retain(|(_, guid)| guid.is_none_or(|g| g.0 == volume.partition));
        if partitions.is_empty() {
            return Err(format!(
                "NVRAM boots partition {}, which this disk does not have",
                uuid_text(&volume.partition)
            ));
        }
    }
    let mut found = Vec::new();
    let mut failures = Vec::new();
    for (offset, _) in partitions {
        let mut container = match Container::open(&mut *source, offset) {
            Ok(container) => container,
            Err(error) => {
                failures.push(format!("container at {offset:#x}: {error}"));
                continue;
            }
        };
        match find(&mut container).map_err(|e| format!("container at {offset:#x}: {e}"))? {
            Ok(update) => {
                let staged = prepare(&mut container, update, authority, options)?;
                found.push((offset, staged));
            }
            Err(failure) => failures.push(format!("container at {offset:#x}: {failure}")),
        }
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err(format!(
            "no Update volume holds a staged update: {}",
            failures.join("; ")
        )),
        count => Err(format!(
            "{count} containers hold a staged update; NVRAM's boot-volume must name one"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn staged(path: &str, kind: Option<&[u8; 4]>) -> Staged {
        Staged {
            path: path.into(),
            payload_type: kind.copied(),
            bytes: 1 << 20,
            oid: 1,
        }
    }

    fn full_root() -> Vec<Staged> {
        vec![
            staged("/iBEC", Some(b"ibec")),
            staged("/sep-firmware", Some(b"sepi")),
            staged("/devicetree", Some(b"dtre")),
            staged("/ramdisk", Some(b"rdsk")),
            staged("/iBootData", Some(b"ibdt")),
            staged("/kernelcache", Some(b"krnl")),
        ]
    }

    fn full_firmware() -> Vec<Staged> {
        vec![
            staged("/iboot_firmware/sptm", Some(b"sptm")),
            staged("/iboot_firmware/txm", Some(b"trxm")),
            staged("/iboot_firmware/trustcache", Some(b"trst")),
            staged("/iboot_firmware/ anef", Some(b"anef")),
        ]
    }

    #[test]
    fn a_complete_update_volume_classifies_with_firmware_set_aside() {
        let parts = classify(&full_root(), Some(&full_firmware())).unwrap();
        assert_eq!(parts.root.len(), 6);
        assert_eq!(parts.sptm.payload_type, Some(*b"sptm"));
        assert_eq!(parts.trust_caches.len(), 1);
        // The ANE firmware iBoot would load is set aside for Stela's model.
        assert_eq!(parts.other_firmware.len(), 1);
        assert_eq!(parts.other_firmware[0].payload_type, Some(*b"anef"));
    }

    #[test]
    fn classify_names_the_first_failing_step_as_iboot_does() {
        // A missing root object fails at its own step.
        let mut root = full_root();
        root.retain(|s| s.path != "/ramdisk");
        let failure = classify(&root, Some(&full_firmware())).unwrap_err();
        assert_eq!((failure.result, failure.step), (IBEC_FAILURE, "ramdisk"));

        // A root object of the wrong type fails there too.
        let mut root = full_root();
        root[0].payload_type = Some(*b"krnl");
        let failure = classify(&root, Some(&full_firmware())).unwrap_err();
        assert_eq!(
            (failure.result, failure.step),
            (LLB_FAILURE, "load upgrade iBEC")
        );

        // No firmware directory, or no trust cache in it.
        let failure = classify(&full_root(), None).unwrap_err();
        assert_eq!((failure.result, failure.step), (IBEC_FAILURE, "firmware"));
        let mut firmware = full_firmware();
        firmware.retain(|s| s.payload_type != Some(*b"trst"));
        let failure = classify(&full_root(), Some(&firmware)).unwrap_err();
        assert!(failure.detail.contains("trust cache"));
    }
}
