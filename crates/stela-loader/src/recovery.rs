//! The kernel boot bundle of a recoveryOS on the installed disk, built in
//! `no_std` so `stela.efi` boots it as iBoot does and `stela-dev boot prepare
//! --disk --disk-recovery` writes the same one.
//!
//! A Mac's internal disk holds two recoveryOS copies (Asahi Linux docs
//! `platform/stock-partition-layout.md`, commit `0d1f891`):
//!
//! - **Paired recoveryOS**: the Recovery-role volume (APFS role 0x4) of the
//!   main `Container`, paired with the volume group of its macOS. It is what
//!   `boot-command=recover` and `recovery-boot-mode` boot.
//! - **System Recovery**: the Recovery volume of the `RecoveryOSContainer`
//!   (`Apple_APFS_Recovery`, GPT type `52637672-7900-11AA-AA11-00306543ECAC`),
//!   which pairs with no installed system. `boot-command=recover-system`
//!   boots it, and so does a disk with no installed system (missing boot
//!   media).
//!
//! Both lay out a boot directory as a Preboot volume does,
//! `<group>/boot/<hash>/`, with the kernel collection under
//! `System/Library/Caches/com.apple.kernelcaches/` and iBoot, the
//! DeviceTree, `base_system_root_hash.img4`, the monitors and trust caches
//! (`FUD/`) and `arm64eBaseSystem.dmg` under `usr/standalone/firmware/`.
//! Objects are identified by Image4 payload type (`stela_formats::preboot`);
//! the J473 iBoot names the image and the BaseSystem trust cache by path
//! (`base-system-path`, `bs-tc-path`).
//!
//! The boot is iBoot's route B for recoveryOS
//! (docs/research/iboot-handoff.md, rows 14 and 17): the first root is the
//! on-disk Recovery volume, named in `/chosen` (`associated-volume-group`
//! and `boot-uuid` for the paired copy, `boot-uuid` alone for System
//! Recovery, and `boot-objects-path`), with no `rd=`, and XNU's imageboot
//! then roots from BaseSystem with `rp0=file://`. Known, from the J473
//! iBoot (0xeaa3c..0xeab7c): that argument is built as `rp0=file://` (or
//! `-rootdmg-ramdisk root-dmg=file://`), then the boot directory with its
//! mount prefix stripped (0xea8e4), then `base-system-path`; Stela writes
//! `rp0=file:///<group>/boot/<hash>/usr/standalone/firmware/arm64eBaseSystem.dmg`.
//! BaseSystem's root hash (`csys`) goes into `/chosen/secure-boot-hashes
//! base-system-volume-auth-blob` once the directory's manifest is shown to
//! sign it, and the OS environment is `recoveryos`.
//!
//! A directory checks by evidence, as `stela_loader::installed` chooses
//! a Preboot directory: its objects carry one manifest whose SHA-384 is the
//! directory's name, that manifest records the digest of every object the
//! boot loads, and the BaseSystem image exists. `<group>/boot/active`
//! narrows the choice; no LocalPolicy is read, since its signature is the
//! SEP's. The image is not read before the boot: it is a UDIF image, which
//! Stela's `no_std` reader does not open, so its seal is compared with the
//! forwarded root hash by APFS's `validate_root_hash` at the image root, and
//! the bundle lists that as unresolved.
use crate::{Result, Within};
use crate::{
    apple_device_tree::DeviceTree,
    boot_bundle::{self, Bundle, Input, Inputs, Options, RootHash, Source, Target},
    boot_policy::{IMAGE_BOOT_ARGS, OsEnvironment, SealedVolume},
    boot_selection::{BootVolume, VolumeType, uuid_text},
    im4m,
    installed::{COMPONENT_LIMIT, KERNEL_LIMIT, plist_string},
    root_selection::Root,
};
use alloc::{format, string::String, vec, vec::Vec};
use stela_contracts::{refuse, require};
use {
    stela_formats::apfs, stela_formats::apfs::ApfsError, stela_formats::apfs::Container,
    stela_formats::apfs::FileKind, stela_formats::apfs::Volume,
    stela_formats::apfs::uuid_text as apfs_uuid,
    stela_formats::apfs::volume::APFS_VOL_ROLE_RECOVERY, stela_formats::img4,
    stela_formats::payload::ReadAt, stela_formats::payload::gpt::Guid, stela_formats::preboot,
    stela_formats::preboot::BootSet, stela_formats::preboot::SYSTEM_VERSION, stela_formats::sha256,
};

/// The RecoveryOSContainer (`Apple_APFS_Recovery`) partition type.
pub const RECOVERY_PARTITION_TYPE: &str = "52637672-7900-11AA-AA11-00306543ECAC";
/// iBoot's `base-system-path`, below the boot directory.
pub const BASE_SYSTEM_IMAGE: &str = "usr/standalone/firmware/arm64eBaseSystem.dmg";
/// The OS environment iBoot enters for either copy.
pub const ENVIRONMENT: OsEnvironment = OsEnvironment::Recoveryos;
/// The objects the boot loads, by payload type: the kernel collection,
/// DeviceTree, monitors, BaseSystem trust cache (iBoot's `bs-tc-path`) and
/// BaseSystem root hash. Each must be recorded in the directory's manifest.
const REQUIRED: [&[u8; 4]; 6] = [b"krnl", b"dtre", b"sptm", b"trxm", b"bstc", b"csys"];
const SEP_FIRMWARE_TYPE: &[u8; 4] = b"sepi";

/// Which recoveryOS copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The main container's Recovery volume, paired with its macOS.
    Paired,
    /// The RecoveryOSContainer's volume.
    System,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Paired => "paired recoveryOS (Recovery volume)",
            Self::System => "System Recovery (RecoveryOSContainer)",
        }
    }
}

/// Why a recoveryOS boot directory is, or is not, bootable.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Evidence {
    pub directory: String,
    pub manifest_sha384: Option<String>,
    /// `<group>/boot/active`, when it named the directory.
    pub named_by: Option<String>,
    /// The BaseSystem image's length.
    pub image_bytes: Option<u64>,
    /// Every requirement that failed; empty when the directory checks.
    pub problems: Vec<String>,
}

/// A recoveryOS on a disk: its container, volume and boot directory.
pub struct Found {
    pub kind: Kind,
    /// The container's byte offset on the disk.
    pub offset: u64,
    pub volume: Volume,
    pub sets: Vec<BootSet>,
}

/// The Recovery-role volume of `container`; `None` when it has none.
fn recovery_volume<R: ReadAt>(container: &mut Container<R>) -> Result<Option<Volume>> {
    let volumes: Vec<Volume> = container
        .volumes()?
        .into_iter()
        .filter(|v| v.role == APFS_VOL_ROLE_RECOVERY)
        .collect();
    match volumes.len() {
        0 => Ok(None),
        1 => Ok(volumes.into_iter().next()),
        count => Err(refuse!("the container has {count} Recovery volumes", count).into()),
    }
}

/// The containers a recoveryOS of `kind` may be in, by byte offset: the
/// APFS containers for the paired copy (the boot volume's alone when NVRAM
/// names an APFS one), the RecoveryOSContainers for System Recovery (the
/// boot volume's alone when NVRAM names a recoveryOS one).
fn containers<R: ReadAt>(
    source: &mut R,
    kind: Kind,
    volume: Option<&BootVolume>,
) -> Result<Vec<u64>> {
    let wanted = |kind_of_volume: VolumeType| {
        volume
            .filter(|v| v.kind == kind_of_volume)
            .map(|v| v.partition)
    };
    let partitions: Vec<(u64, Option<[u8; 16]>)> = match kind {
        Kind::Paired => apfs::container_partitions(source)?
            .into_iter()
            .map(|(offset, guid)| (offset, guid.map(|g| g.0)))
            .collect(),
        Kind::System => {
            let recovery = Guid::parse(RECOVERY_PARTITION_TYPE).expect("constant GUID");
            match apfs::typed_partitions(source, recovery)? {
                Some(found) => found
                    .into_iter()
                    .map(|(offset, guid)| (offset, Some(guid.0)))
                    .collect(),
                None => Vec::new(),
            }
        }
    };
    let partition = wanted(match kind {
        Kind::Paired => VolumeType::Apfs,
        Kind::System => VolumeType::Recovery,
    });
    Ok(partitions
        .into_iter()
        .filter(|(_, guid)| partition.is_none_or(|p| guid.is_none_or(|g| g == p)))
        .map(|(offset, _)| offset)
        .collect())
}

/// The groups a paired Recovery volume's directories are named by: NVRAM's
/// boot volume group, else the container's System volume groups.
fn paired_groups<R: ReadAt>(
    container: &mut Container<R>,
    volume: Option<&BootVolume>,
) -> Result<Vec<String>> {
    if let Some(volume) = volume.filter(|v| v.kind == VolumeType::Apfs) {
        return Ok(vec![uuid_text(&volume.volume_group)]);
    }
    Ok(preboot::system_groups(container)?)
}

/// Every recoveryOS of `kind` on `source` (a disk with a GUID partition
/// table, or for the paired copy one APFS container) with at least one boot
/// directory; `volume` is NVRAM's boot volume. Nothing is evaluated: this
/// is the presence check `stela.efi` makes before choosing the boot.
pub fn find<R: ReadAt>(
    source: &mut R,
    kind: Kind,
    volume: Option<&BootVolume>,
) -> Result<Vec<Found>> {
    let mut found = Vec::new();
    for offset in containers(source, kind, volume)? {
        let mut container = match Container::open(&mut *source, offset) {
            Err(ApfsError::Malformed(_)) if kind == Kind::Paired => continue,
            opened => opened.within(|| refuse!("container at {offset:#x}", offset))?,
        };
        let Some(recovery) = recovery_volume(&mut container)? else {
            continue;
        };
        let groups = match kind {
            Kind::Paired => paired_groups(&mut container, volume)?,
            Kind::System => Vec::new(),
        };
        let sets = preboot::boot_sets(&mut container, &recovery, &groups)
            .within(|| refuse!("container at {offset:#x}", offset))?;
        if !sets.is_empty() {
            found.push(Found {
                kind,
                offset,
                volume: recovery,
                sets,
            });
        }
    }
    Ok(found)
}

/// The SHA-384 `DGST` the manifest records for `tag`.
fn recorded<'a>(manifest: &'a im4m::Manifest, tag: &str) -> Option<&'a [u8]> {
    manifest
        .object(tag)
        .and_then(|o| o.properties.iter().find(|p| p.name == "DGST"))
        .and_then(|p| match &p.value {
            im4m::Value::Data(digest) => Some(digest.as_slice()),
            _ => None,
        })
}

fn evaluate<R: ReadAt>(
    container: &mut Container<R>,
    volume: &Volume,
    set: &BootSet,
) -> Result<Evidence> {
    let mut evidence = Evidence {
        directory: set.directory(),
        manifest_sha384: None,
        named_by: None,
        image_bytes: None,
        problems: Vec::new(),
    };
    let mut manifests: Vec<Vec<u8>> = Vec::new();
    for object in &set.objects {
        if let Some(manifest) = preboot::manifest(container, volume, object)?
            && !manifests.contains(&manifest)
        {
            manifests.push(manifest);
        }
    }
    let manifest = match &manifests[..] {
        [manifest] => {
            let digest = hex::encode_upper(im4m::sha384(manifest));
            if !digest.eq_ignore_ascii_case(&set.boot_hash) {
                evidence.problems.push(format!(
                    "its name is not the SHA-384 of its objects' manifest ({digest})"
                ));
            }
            evidence.manifest_sha384 = Some(digest);
            match im4m::parse(manifest) {
                Ok(manifest) => Some(manifest),
                Err(error) => {
                    evidence
                        .problems
                        .push(format!("its manifest is not an IM4M: {error:#}"));
                    None
                }
            }
        }
        [] => {
            evidence
                .problems
                .push("no object carries a manifest".into());
            None
        }
        _ => {
            evidence.problems.push(format!(
                "its objects carry {} different manifests",
                manifests.len()
            ));
            None
        }
    };
    for kind in REQUIRED {
        let tag = String::from_utf8_lossy(kind);
        let object = match set.object(kind) {
            Ok(Some(object)) => object.clone(),
            Ok(None) => {
                evidence.problems.push(format!("it has no {tag} object"));
                continue;
            }
            Err(error) => {
                evidence.problems.push(format!("{error}"));
                continue;
            }
        };
        let Some(manifest) = &manifest else {
            continue;
        };
        let file = preboot::read(container, volume, &object)?;
        let parts = img4::parse(&file).within(|| refuse!("{path}", path = object.path))?;
        match recorded(manifest, &tag) {
            Some(digest) if digest == im4m::sha384(parts.payload).as_slice() => {}
            Some(_) => evidence.problems.push(format!(
                "its manifest's {tag} digest is not {}'s",
                object.path
            )),
            None => evidence
                .problems
                .push(format!("its manifest records no {tag} object")),
        }
    }
    let path = format!("{}/{BASE_SYSTEM_IMAGE}", set.directory());
    match volume.lookup(&mut container.device, &path, true) {
        Ok(inode) if inode.kind == FileKind::Regular && inode.logical_size() > 0 => {
            evidence.image_bytes = Some(inode.logical_size());
        }
        Ok(_) => evidence
            .problems
            .push(format!("{path} is not a BaseSystem image")),
        Err(ApfsError::NotFound(_)) => evidence.problems.push(format!("it has no {path}")),
        Err(error) => evidence.problems.push(format!("{path}: {error}")),
    }
    Ok(evidence)
}

/// The boot directory of `found` the evidence shows to be bootable:
/// `<group>/boot/active`'s when it names one, else the one that checks.
pub fn select<R: ReadAt>(
    container: &mut Container<R>,
    found: &Found,
) -> Result<(BootSet, Evidence)> {
    let mut chosen: Vec<(BootSet, Option<String>)> = Vec::new();
    let mut notes = Vec::new();
    let mut groups: Vec<&str> = found.sets.iter().map(|s| s.volume_group.as_str()).collect();
    groups.dedup();
    for group in groups {
        let in_group = found.sets.iter().filter(|s| s.volume_group == group);
        match preboot::active(container, &found.volume, group)? {
            Some(hash) => match in_group
                .clone()
                .find(|s| s.boot_hash.eq_ignore_ascii_case(&hash))
            {
                Some(set) => chosen.push((set.clone(), Some(format!("{group}/boot/active")))),
                None => {
                    notes.push(format!("{group}/boot/active names a missing boot/{hash}"));
                    chosen.extend(in_group.map(|s| (s.clone(), None)));
                }
            },
            None => chosen.extend(in_group.map(|s| (s.clone(), None))),
        }
    }
    let mut qualified = Vec::new();
    let mut refused = notes;
    for (set, by) in chosen {
        let mut evidence = evaluate(container, &found.volume, &set)?;
        evidence.named_by = by;
        if evidence.problems.is_empty() {
            qualified.push((set, evidence));
        } else {
            refused.push(format!(
                "{}: {}",
                evidence.directory,
                evidence.problems.join("; ")
            ));
        }
    }
    match qualified.len() {
        1 => Ok(qualified.remove(0)),
        0 => Err(refuse!(
            "the {label} holds no bootable boot directory ({refused})",
            label = found.kind.label(),
            refused = refused.join(" | ")
        )
        .into()),
        count => {
            let directories = qualified
                .iter()
                .map(|(set, _)| set.directory())
                .collect::<Vec<_>>();
            Err(refuse!("{count} boot directories of the {label} qualify ({directories}), and no boot/active names one", count, label = found.kind.label(), directories = directories.join(", ")).into())
        }
    }
}

/// The image-boot argument naming the BaseSystem image of `directory`
/// (`<group>/boot/<hash>`) from the Recovery volume's root.
pub fn image_boot_arg(directory: &str) -> String {
    format!(
        "{}=file:///{directory}/{BASE_SYSTEM_IMAGE}",
        IMAGE_BOOT_ARGS[0]
    )
}

/// `console` with the image-boot argument for `directory`. Console
/// arguments that name an image root or a memory-device root are refused:
/// the root is the boot's own.
pub fn boot_args(console: &str, directory: &str) -> Result<String> {
    for argument in console.split_whitespace() {
        let name = argument.split('=').next().unwrap_or(argument);
        require!(
            !IMAGE_BOOT_ARGS.contains(&name) && name != "rd" && name != "rootdev",
            "boot-args {argument} names a root; a recoveryOS boot roots from its Recovery \
             volume and BaseSystem image",
            ?argument
        );
    }
    let mut args: Vec<String> = console.split_whitespace().map(String::from).collect();
    args.push(image_boot_arg(directory));
    Ok(args.join(" "))
}

/// A recoveryOS bundle and where on the disk it came from.
pub struct Recovered {
    pub bundle: Bundle,
    pub kind: Kind,
    pub volume: Volume,
    pub set: BootSet,
    pub evidence: Evidence,
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

struct Reader<'a, R: ReadAt> {
    container: &'a mut Container<R>,
    volume: &'a Volume,
    set: &'a BootSet,
    kind: Kind,
}

impl<R: ReadAt> Reader<'_, R> {
    fn file(&mut self, object: &preboot::Object) -> Result<Vec<u8>> {
        preboot::read(self.container, self.volume, object)
            .within(|| refuse!("{path}", path = object.path))
    }

    fn component(&self, kind: &[u8; 4]) -> String {
        let copy = match self.kind {
            Kind::Paired => "Recovery",
            Kind::System => "System Recovery",
        };
        format!("{copy} {}", String::from_utf8_lossy(kind))
    }

    /// The single object of `kind`, decoded, and its manifest.
    fn decode(&mut self, kind: &[u8; 4], limit: u64) -> Result<(Decoded, Option<Vec<u8>>)> {
        let object = self.set.require(kind)?.clone();
        let file = self.file(&object)?;
        let parts = img4::parse(&file).within(|| refuse!("{path}", path = object.path))?;
        let im4p = crate::im4p::parse(parts.payload)?;
        let (bytes, _) = im4p.decode_payload(limit)?;
        let decoded = Decoded {
            source: Source {
                component: self.component(kind),
                member: object.path.clone(),
                container_sha256: sha256(&file),
                payload_type: im4p.payload_type,
                description: im4p.description,
                decoded_bytes: bytes.len() as u64,
                decoded_sha256: sha256(&bytes),
            },
            bytes,
        };
        Ok((decoded, parts.manifest.map(<[u8]>::to_vec)))
    }

    /// The build the boot set's iBoot names itself with.
    fn iboot_build(&mut self) -> Result<Option<String>> {
        let Some(object) = self.set.object(b"ibot")?.cloned() else {
            return Ok(None);
        };
        let file = self.file(&object)?;
        let parts = img4::parse(&file).within(|| refuse!("{path}", path = object.path))?;
        Ok(Some(crate::im4p::parse(parts.payload)?.description))
    }

    /// An object kept as its encoded `IM4P`: the SEP firmware, the root hash.
    fn opaque(&mut self, kind: &[u8; 4]) -> Result<Option<Decoded>> {
        let Some(object) = self.set.object(kind)?.cloned() else {
            return Ok(None);
        };
        let file = self.file(&object)?;
        let parts = img4::parse(&file).within(|| refuse!("{path}", path = object.path))?;
        Ok(Some(Decoded {
            source: Source {
                component: self.component(kind),
                member: object.path.clone(),
                container_sha256: sha256(&file),
                payload_type: "opaque".into(),
                description: String::new(),
                decoded_bytes: parts.payload.len() as u64,
                decoded_sha256: sha256(parts.payload),
            },
            bytes: parts.payload.to_vec(),
        }))
    }

    /// `ProductVersion` and `ProductBuildVersion` from the directory's group
    /// on the volume, when it has a `SystemVersion.plist`.
    fn system_version(&mut self) -> Result<Option<(String, String)>> {
        let path = format!("{}/{SYSTEM_VERSION}", self.set.volume_group);
        let device = &mut self.container.device;
        let inode = match self.volume.lookup(device, &path, true) {
            Err(ApfsError::NotFound(_)) => return Ok(None),
            found => found.within(|| refuse!("{path}", path))?,
        };
        let bytes = self
            .volume
            .read(device, &inode)
            .within(|| refuse!("{path}", path))?;
        let text =
            core::str::from_utf8(&bytes).map_err(|_| refuse!("{path} is not UTF-8", path))?;
        let field = |key: &str| -> Result<String> {
            plist_string(text, key)
                .within(|| refuse!("{path}", path))?
                .ok_or_else(|| refuse!("{path} has no {key}", path, key).into())
        };
        Ok(Some((
            field("ProductVersion")?,
            field("ProductBuildVersion")?,
        )))
    }
}

fn root_string(tree: &DeviceTree, property: &str) -> Result<String> {
    tree.property("/", property)
        .and_then(|p| p.as_str())
        .map(Into::into)
        .ok_or_else(|| refuse!("the DeviceTree root has no {property}", property).into())
}

fn manifest_id(manifest: Option<&im4m::Manifest>, key: &str) -> Result<Option<u32>> {
    match manifest.and_then(|m| m.property(key)) {
        Some(im4m::Value::Integer(value)) => Ok(Some(u32::try_from(*value).map_err(|_| {
            refuse!(
                "boot manifest {key} {value:#x} exceeds u32",
                key,
                value = *value
            )
        })?)),
        Some(_) => Err(refuse!("boot manifest {key} is not an integer", key).into()),
        None => Ok(None),
    }
}

/// Build the bundle of the recoveryOS `found` names, from the directory
/// [`select`] checks, with `options` (the console boot-args, ECID and
/// placement); `model`, when given, must be the DeviceTree's.
pub fn prepare<R: ReadAt>(
    container: &mut Container<R>,
    found: Found,
    model: Option<&str>,
    options: &Options,
) -> Result<Recovered> {
    let (set, evidence) = select(container, &found)?;
    let mut reader = Reader {
        container,
        volume: &found.volume,
        set: &set,
        kind: found.kind,
    };
    let (kernel, boot_manifest) = reader.decode(b"krnl", KERNEL_LIMIT)?;
    let (sptm, _) = reader.decode(b"sptm", COMPONENT_LIMIT)?;
    let (txm, _) = reader.decode(b"trxm", COMPONENT_LIMIT)?;
    let (device_tree, _) = reader.decode(b"dtre", COMPONENT_LIMIT)?;
    let (trust_cache, _) = reader.decode(b"bstc", COMPONENT_LIMIT)?;
    let sep = reader.opaque(SEP_FIRMWARE_TYPE)?;
    let root_hash = reader.opaque(b"csys")?;
    let firmware_version = reader.iboot_build()?;
    let version = reader.system_version()?;
    let tree = DeviceTree::parse(&device_tree.bytes)?;
    let product_type = root_string(&tree, "model")?;
    if let Some(wanted) = model {
        require!(
            wanted == product_type,
            "the disk's recoveryOS is a {product_type}'s, not a {wanted}'s",
            product_type,
            wanted
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
            description: "the recoveryOS kernel collection's manifest".into(),
            decoded_bytes: bytes.len() as u64,
            decoded_sha256: sha256(&bytes),
        },
        bytes,
    });
    let (product_version, product_build) = version.clone().unwrap_or_default();
    let inputs = Inputs {
        target: Target {
            product_type,
            device_class: format!("{}ap", target_type.to_ascii_lowercase()),
            product_version,
            product_build,
            variant: found.kind.label().into(),
            chip_id: manifest_id(manifest.as_ref(), "CHIP")?,
            board_id: manifest_id(manifest.as_ref(), "BORD")?,
        },
        kernel_collection: kernel.input().into(),
        auxiliary_collection: None,
        sptm: sptm.input(),
        txm: txm.input(),
        device_tree: device_tree.input(),
        static_trust_cache: trust_cache.input(),
        sep_firmware: sep.as_ref().map(Decoded::input),
        boot_manifest: boot_manifest.as_ref().map(Decoded::input),
        cryptex1_manifest: None,
        extra_trust_caches: Vec::new(),
        // The BaseSystem image stays on the disk; imageboot attaches it.
        ramdisk: None,
        // As for the installed system: the engine reads the board's flash.
        board_firmware: Vec::new(),
        root_hash: Some(RootHash {
            volume: SealedVolume::BaseSystem,
            im4p: root_hash.as_ref().map(Decoded::input),
            snapshot: None,
        }),
        pivot_root_hash: None,
        firmware_version: firmware_version.as_deref(),
    };
    let directory = set.directory();
    let mut options = options.placed_at(inputs.dram_base()?);
    options.boot_args = boot_args(&options.boot_args, &directory)?;
    options.osenvironment = Some(ENVIRONMENT);
    options.boot_command = Some(match found.kind {
        Kind::Paired => crate::handoff::BootCommand::Recover,
        Kind::System => crate::handoff::BootCommand::RecoverSystem,
    });
    let volume_uuid = apfs_uuid(&found.volume.uuid);
    options.root = Some(match found.kind {
        Kind::Paired => Root::PairedRecovery {
            volume_group: set.volume_group.clone(),
            recovery_volume: volume_uuid,
            boot_hash: set.boot_hash.clone(),
        },
        Kind::System => Root::SystemRecovery {
            volume: volume_uuid,
            directory: set.volume_group.clone(),
            boot_hash: set.boot_hash.clone(),
        },
    });
    let mut bundle = boot_bundle::prepare(&inputs, &options)?;
    let unresolved = &mut bundle.manifest.unresolved;
    unresolved.push(format!(
        "{directory}/{BASE_SYSTEM_IMAGE}: its seal is not compared with the forwarded csys root \
         hash before the boot (a UDIF image Stela's reader does not open); APFS's \
         validate_root_hash compares them at the image root"
    ));
    unresolved.push(format!(
        "no SEP-verified LocalPolicy names {directory}: it was chosen by {} and its evidence (its \
         manifest's SHA-384 and the digest of every object it loads)",
        evidence.named_by.as_deref().unwrap_or("evidence alone")
    ));
    if version.is_none() {
        unresolved.push(format!(
            "{}/{SYSTEM_VERSION} is absent on the {}: the bundle names no product version",
            set.volume_group,
            found.kind.label()
        ));
    }
    Ok(Recovered {
        bundle,
        kind: found.kind,
        volume: found.volume,
        set,
        evidence,
    })
}

/// The recoveryOS of `kind` on `source`, a disk with a GUID partition
/// table (or, for the paired copy, one APFS container), as NVRAM's boot
/// `volume` names it; exactly one must exist. Returns the container's byte
/// offset and the bundle.
pub fn prepare_disk<R: ReadAt>(
    source: &mut R,
    kind: Kind,
    volume: Option<&BootVolume>,
    model: Option<&str>,
    options: &Options,
) -> Result<(u64, Recovered)> {
    let mut found = find(source, kind, volume)?;
    let found = match found.len() {
        1 => found.remove(0),
        0 => return Err(refuse!("the disk holds no {label}", label = kind.label()).into()),
        count => {
            let offsets = found
                .iter()
                .map(|f| format!("{:#x}", f.offset))
                .collect::<Vec<_>>();
            return Err(refuse!("{count} containers hold a {label} (at {offsets}); NVRAM's boot-volume must name one", count, label = kind.label(), offsets = offsets.join(", ")).into());
        }
    };
    let offset = found.offset;
    let mut container = Container::open(&mut *source, offset)?;
    let recovered = prepare(&mut container, found, model, options)?;
    Ok((offset, recovered))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use {stela_formats::apfs::object::fletcher64, stela_formats::payload::gpt};

    const GROUP: &str = "A304C51B-D22F-4CDD-829D-3E30CB5BD87B";
    const BLOCK: usize = 4096;
    const VOLUME_MAGIC_AT: usize = 32;
    const ROLE_AT: usize = 964;

    /// The runtime's APFS fixture: one Preboot-role volume holding
    /// `<GROUP>/boot/<hash>/` with `krnl`, `dtre`, `sptm`, `trxm` and `trst`
    /// objects under one synthetic manifest.
    fn fixture() -> Vec<u8> {
        let compressed = include_bytes!("../../stela-formats/tests/fixtures/apfs/preboot.img.gz");
        assert_eq!(compressed[3], 0, "gzip -n: no optional header fields");
        miniz_oxide::inflate::decompress_to_vec(&compressed[10..compressed.len() - 8])
            .expect("gzip -n deflate stream")
    }

    /// The fixture with its volume's role changed to `role`, in every copy
    /// of the volume superblock, checksums recomputed.
    fn with_role(role: u16) -> Vec<u8> {
        let mut bytes = fixture();
        let mut patched = 0;
        for block in bytes.chunks_mut(BLOCK) {
            if &block[VOLUME_MAGIC_AT..VOLUME_MAGIC_AT + 4] == b"APSB" {
                block[ROLE_AT..ROLE_AT + 2].copy_from_slice(&role.to_le_bytes());
                let sum = fletcher64(block);
                block[..8].copy_from_slice(&sum.to_le_bytes());
                patched += 1;
            }
        }
        assert!(patched > 0, "the fixture has a volume superblock");
        bytes
    }

    struct Memory(Vec<u8>);

    impl ReadAt for Memory {
        type Error = &'static str;
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
            let start = offset as usize;
            buffer.copy_from_slice(self.0.get(start..start + buffer.len()).ok_or("past end")?);
            Ok(())
        }
    }

    /// `container` as the only partition, of `type_guid`, on a GPT disk.
    fn on_gpt(container: &[u8], type_guid: &str, unique: Guid) -> Memory {
        const SECTOR: u64 = 512;
        const FIRST: u64 = 2048;
        let used = (container.len() as u64).div_ceil(SECTOR);
        let disk = gpt::Disk {
            block_bytes: SECTOR,
            blocks: FIRST + used + FIRST,
        };
        let table = gpt::Table {
            disk_guid: Guid::from_entropy([3; 16]),
            partitions: vec![gpt::Partition {
                type_guid: Guid::parse(type_guid).unwrap(),
                unique_guid: unique,
                first_lba: FIRST,
                last_lba: FIRST + used - 1,
                attributes: 0,
                name: "RecoveryOSContainer".into(),
            }],
        };
        let mut bytes = vec![0u8; (disk.blocks * SECTOR) as usize];
        for write in gpt::encode(disk, &table).unwrap() {
            let at = (write.lba * SECTOR) as usize;
            bytes[at..at + write.bytes.len()].copy_from_slice(&write.bytes);
        }
        let at = (FIRST * SECTOR) as usize;
        bytes[at..at + container.len()].copy_from_slice(container);
        Memory(bytes)
    }

    #[test]
    fn the_paired_recovery_volume_is_found_by_role_and_refused_by_its_missing_objects() {
        // A container whose only volume is a Preboot volume has no recoveryOS.
        let mut preboot = Memory(fixture());
        assert!(find(&mut preboot, Kind::Paired, None).unwrap().is_empty());
        // As a Recovery volume, its boot directory is listed ...
        let mut disk = Memory(with_role(APFS_VOL_ROLE_RECOVERY));
        let mut found = find(&mut disk, Kind::Paired, None).unwrap();
        let [one] = &found[..] else {
            panic!("one paired recoveryOS");
        };
        assert_eq!(one.offset, 0);
        assert_eq!(one.sets.len(), 1);
        assert_eq!(one.sets[0].volume_group, GROUP);
        // ... and NVRAM's volume group narrows the listing.
        let other = BootVolume {
            kind: VolumeType::Apfs,
            partition: [0; 16],
            volume_group: [0x11; 16],
        };
        assert!(
            find(&mut disk, Kind::Paired, Some(&other))
                .unwrap()
                .is_empty()
        );
        // The directory names its manifest and carries the macOS objects, but
        // not BaseSystem's trust cache, root hash or image: refused by name.
        let found = found.remove(0);
        let mut container = Container::open(&mut disk, 0).unwrap();
        let error = select(&mut container, &found).unwrap_err().to_string();
        for missing in ["no bstc object", "no csys object", BASE_SYSTEM_IMAGE] {
            assert!(error.contains(missing), "{error}");
        }
        assert!(!error.contains("SHA-384"), "{error}");
        assert!(!error.contains("krnl"), "{error}");
        let error = prepare_disk(&mut disk, Kind::Paired, None, None, &Options::default())
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("no bootable boot directory"), "{error}");
    }

    #[test]
    fn system_recovery_is_the_recoveryos_container_s_volume() {
        let unique = Guid::parse("A1B2C3D4-0000-1111-2222-333344445555").unwrap();
        let recovery = with_role(APFS_VOL_ROLE_RECOVERY);
        // On an APFS-typed partition it is a paired copy, not System Recovery.
        let mut main = on_gpt(&recovery, apfs::PARTITION_TYPE, unique);
        assert!(find(&mut main, Kind::System, None).unwrap().is_empty());
        assert_eq!(find(&mut main, Kind::Paired, None).unwrap().len(), 1);
        let mut disk = on_gpt(&recovery, RECOVERY_PARTITION_TYPE, unique);
        assert!(find(&mut disk, Kind::Paired, None).unwrap().is_empty());
        let found = find(&mut disk, Kind::System, None).unwrap();
        let [one] = &found[..] else {
            panic!("one System Recovery");
        };
        assert_eq!(one.offset, 2048 * 512);
        // Its directory is any top-level one with a boot directory.
        assert_eq!(one.sets[0].volume_group, GROUP);
        // A boot volume naming another recoveryOS partition finds none.
        let elsewhere = BootVolume {
            kind: VolumeType::Recovery,
            partition: [0x22; 16],
            volume_group: [0; 16],
        };
        assert!(
            find(&mut disk, Kind::System, Some(&elsewhere))
                .unwrap()
                .is_empty()
        );
        let here = BootVolume {
            partition: unique.0,
            ..elsewhere
        };
        assert_eq!(find(&mut disk, Kind::System, Some(&here)).unwrap().len(), 1);
        // A disk with no RecoveryOSContainer has no System Recovery.
        assert!(
            find(&mut Memory(vec![0; 1 << 20]), Kind::System, None)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn the_image_root_names_the_base_system_image_below_the_boot_directory() {
        let directory = format!("{GROUP}/boot/{}", "AB".repeat(48));
        let args = boot_args("-v debug=0x8", &directory).unwrap();
        assert_eq!(
            args,
            format!(
                "-v debug=0x8 rp0=file:///{directory}/usr/standalone/firmware/arm64eBaseSystem.dmg"
            )
        );
        crate::boot_policy::require_image_boot(&args).unwrap();
        assert_eq!(crate::boot_policy::ramdisk_root_device(&args), None);
        for root in ["rd=md0", "rp0=file:///x.dmg", "rootdev=disk0s1"] {
            assert!(
                boot_args(&format!("-v {root}"), &directory).is_err(),
                "{root}"
            );
        }
    }
}
