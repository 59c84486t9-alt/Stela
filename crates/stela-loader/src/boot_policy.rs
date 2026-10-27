//! The boot-policy inputs iBoot hands SPTM, TXM and XNU as DeviceTree data.
//!
//! After verifying a LocalPolicy, iBoot publishes it as `/chosen/asmb`
//! `lp-*` values, summarizes the boot manifest as `/chosen`
//! `boot-manifest-hash`, the `effective-*-ap` state and
//! `/chosen/manifest-properties`, and records the SEP load decision. With
//! them go the chip's fused state (`certificate-*`, `chip-epoch`, the unit
//! flags) and the rows iBoot derives from the LocalPolicy
//! (`kernel-ctrr-to-be-enabled`, `/product allow-hactivation`); the full
//! contract is `docs/research/iboot-handoff.md`. The names
//! are those SPTM, TXM and the kernel read (their own strings); LocalPolicy
//! fields and types follow Apple Platform Security, "Contents of a LocalPolicy
//! file for a Mac with Apple silicon". Integers are 8 bytes, as m1n1 writes
//! `lp-sip0`; booleans are 4 bytes, as the template's
//! `UnusedBooleanProperty` slots are.
//!
//! Full Security needs a manifest personalized to one device, which Stela does
//! not have; Reduced Security admits Apple's global manifests in the IPSW.
use crate::apple_device_tree::DeviceTree;
use crate::im4m::{Manifest, Value};
use alloc::{borrow::ToOwned, format, string::String, vec, vec::Vec};
use anyhow::{Context, Result, ensure};
use serde::Serialize;

pub mod mcc;

const ASMB: &str = "/chosen/asmb";
const CHOSEN: &str = "/chosen";
const MANIFEST_PROPERTIES: &str = "/chosen/manifest-properties";
const PRODUCT: &str = "/product";
/// Template `UnusedStringProperty` slots hold 64 bytes. A slot takes the
/// octet string's own bytes, not padded to the slot: TXM 26A434 copies
/// `love` with a bounds check that its length is at most the length of its
/// NUL-terminated text plus one (`__text+0x3cc64`), which a padded value
/// fails.
const STRING_SLOT_BYTES: usize = 0x40;
const INTEGER_SLOT: &str = "UnusedIntegerProperty";
const BOOLEAN_SLOT: &str = "UnusedBooleanProperty";
const STRING_SLOT: &str = "UnusedStringProperty";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityMode {
    /// `smb0`: globally signed boot objects are admitted.
    Reduced,
    /// `smb0` and `smb1`: objects signed with the LocalPolicy key as well.
    Permissive,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityPolicy {
    pub mode: SecurityMode,
    /// `sip0`: System Integrity Protection bits (`csr-active-config`).
    pub sip_bits: u64,
    /// Overrides the template's `/chosen sepfw-load-at-boot`.
    pub sepfw_load_at_boot: Option<bool>,
}

/// One `/chosen` value written or deliberately kept, and why.
#[derive(Debug, Clone, Serialize)]
pub struct Decision {
    pub path: String,
    pub property: String,
    pub value_hex: String,
    pub source: String,
}

fn boolean(value: bool) -> Vec<u8> {
    u32::from(value).to_le_bytes().to_vec()
}

fn integer(value: u64) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

struct Writer<'a> {
    tree: &'a mut DeviceTree,
    decisions: Vec<Decision>,
}

impl Writer<'_> {
    fn set(&mut self, path: &str, property: &str, value: Vec<u8>, source: &str) -> Result<()> {
        self.decisions.push(Decision {
            path: path.into(),
            property: property.into(),
            value_hex: hex::encode(&value),
            source: source.into(),
        });
        self.tree.set_property(path, property, value)
    }

    /// Replace a template value, keeping the template's width.
    fn fill(&mut self, path: &str, property: &str, value: Vec<u8>, source: &str) -> Result<()> {
        let width = self
            .tree
            .property(path, property)
            .with_context(|| format!("DeviceTree has no {path} {property}"))?
            .value
            .len();
        ensure!(
            width == value.len(),
            "{path} {property} is {width} bytes; the value is {}",
            value.len()
        );
        self.set(path, property, value, source)
    }

    /// Replace a template value as [`Self::fill`] does, when the template
    /// has it: iBoot writes these in place only (`GETPROP` then store).
    fn fill_present(
        &mut self,
        path: &str,
        property: &str,
        value: Vec<u8>,
        source: &str,
    ) -> Result<()> {
        if self.tree.property(path, property).is_some() {
            self.fill(path, property, value, source)?;
        }
        Ok(())
    }

    fn keep(&mut self, path: &str, property: &str, source: &str) -> Result<()> {
        let value = self
            .tree
            .property(path, property)
            .with_context(|| format!("DeviceTree has no {path} {property}"))?
            .value
            .clone();
        self.decisions.push(Decision {
            path: path.into(),
            property: property.into(),
            value_hex: hex::encode(value),
            source: source.into(),
        });
        Ok(())
    }
}

fn manifest_flag(manifest: &Manifest, name: &str) -> Result<bool> {
    match manifest.property(name) {
        Some(Value::Boolean(value)) => Ok(*value),
        other => anyhow::bail!("boot manifest {name} is {other:?}, expected a boolean"),
    }
}

fn manifest_integer(manifest: &Manifest, name: &str) -> Result<u64> {
    match manifest.property(name) {
        Some(Value::Integer(value)) => Ok(*value),
        other => anyhow::bail!("boot manifest {name} is {other:?}, expected an integer"),
    }
}

/// Fill the template's typed `manifest-properties` slots with `MANP`.
fn manifest_properties(writer: &mut Writer, manifest: &Manifest) -> Result<()> {
    for property in &manifest.properties {
        let (slot, value) = match &property.value {
            Value::Integer(value) => (INTEGER_SLOT, integer(*value)),
            Value::Boolean(value) => (BOOLEAN_SLOT, boolean(*value)),
            Value::Data(bytes) => {
                ensure!(
                    bytes.len() <= STRING_SLOT_BYTES,
                    "manifest property {} exceeds a {STRING_SLOT_BYTES}-byte slot",
                    property.name
                );
                (STRING_SLOT, bytes.clone())
            }
        };
        let node = writer
            .tree
            .node_mut(MANIFEST_PROPERTIES)
            .context("DeviceTree has no /chosen/manifest-properties")?;
        let free = node
            .properties
            .iter()
            .find(|p| p.name().starts_with(slot))
            .map(|p| p.name().to_owned())
            .with_context(|| format!("no free {slot} slot for {}", property.name))?;
        writer.decisions.push(Decision {
            path: MANIFEST_PROPERTIES.into(),
            property: property.name.clone(),
            value_hex: hex::encode(&value),
            source: format!("boot manifest MANP, in slot {free}"),
        });
        node.replace_property(&free, &property.name, value)?;
    }
    Ok(())
}

/// The unit-class flags iBoot writes from the chip's security fuses after it
/// publishes the LocalPolicy (26A434 J473 iBoot 0x2db6c..0x2dc00): each is
/// set only on an internal, engineering or prerelease unit.
const UNIT_FLAGS: [&str; 4] = [
    "internal-use-only-unit",
    "engineering-use-only-unit",
    "factory-prerelease-global-trust",
    "sfr-internal-use-only-sw",
];

/// iBoot's `kernel-ctrr-to-be-enabled` (0x35eb4): the kernel's CTRR region
/// stays off when the LocalPolicy carries a custom kernel hash (`lp-coih`)
/// or sets `lp-sip2` or `lp-sip3`. SPTM reads a present 0 as "kernel CTRR
/// off" (26A434 SPTM `__text` 0xbd770).
fn kernel_ctrr(tree: &DeviceTree) -> (bool, &'static str) {
    let set = |name: &str| {
        tree.property(ASMB, name)
            .is_some_and(|p| p.value.iter().any(|&byte| byte != 0))
    };
    if tree.property(ASMB, "lp-coih").is_some() {
        (false, "LocalPolicy lp-coih: a custom kernel")
    } else if set("lp-sip2") || set("lp-sip3") {
        (false, "LocalPolicy lp-sip2 or lp-sip3")
    } else {
        (true, "LocalPolicy has no lp-coih, lp-sip2 or lp-sip3")
    }
}

/// Apply the policy and manifest summaries; returns the decisions and the
/// inputs that remain unknown.
pub fn apply(
    tree: &mut DeviceTree,
    policy: &SecurityPolicy,
    boot_manifest: Option<&Manifest>,
    cryptex1_manifest: Option<&Manifest>,
) -> Result<(Vec<Decision>, Vec<String>)> {
    let mut unresolved = vec![];
    tree.ensure_child(CHOSEN, "asmb")?;
    let mut writer = Writer {
        tree,
        decisions: vec![],
    };
    let mode = match policy.mode {
        SecurityMode::Reduced => "Reduced Security",
        SecurityMode::Permissive => "Permissive Security",
    };
    writer.set(ASMB, "lp-smb0", boolean(true), mode)?;
    writer.set(
        ASMB,
        "lp-smb1",
        boolean(policy.mode == SecurityMode::Permissive),
        mode,
    )?;
    writer.set(ASMB, "lp-sip0", integer(policy.sip_bits), "SIP bits")?;
    writer.set(
        ASMB,
        "lp-sip1",
        boolean(false),
        "signed system volume enforced",
    )?;
    match cryptex1_manifest {
        Some(manifest) => {
            writer.set(
                ASMB,
                "lp-spih",
                manifest.digest.to_vec(),
                "SHA-384 of the global Cryptex1 manifest",
            )?;
            writer.set(ASMB, "lp-stng", integer(0), "first spih generation")?;
        }
        None => unresolved.push("/chosen/asmb lp-spih, lp-stng: no Cryptex1 manifest".into()),
    }
    let (ctrr, why) = kernel_ctrr(writer.tree);
    writer.set(CHOSEN, "kernel-ctrr-to-be-enabled", boolean(ctrr), why)?;
    // iBoot looks up `asmb`/`hack` in the LocalPolicy's store (0x2dcc4).
    if writer.tree.node(PRODUCT).is_some() {
        writer.set(
            PRODUCT,
            "allow-hactivation",
            boolean(false),
            "LocalPolicy has no hacktivation (asmb hack) entry",
        )?;
    }
    writer.set(
        CHOSEN,
        "boot-nonce-hash-method",
        b"sha2-384\0".to_vec(),
        "iBoot's constant (0x23764)",
    )?;

    match boot_manifest {
        Some(manifest) => {
            let production = manifest_flag(manifest, "CPRO")?;
            let secure = manifest_flag(manifest, "CSEC")?;
            writer.fill(
                CHOSEN,
                "boot-manifest-hash",
                manifest.digest.to_vec(),
                "SHA-384 of the boot manifest",
            )?;
            writer.fill(
                CHOSEN,
                "effective-production-status-ap",
                boolean(production),
                "boot manifest CPRO",
            )?;
            writer.fill(
                CHOSEN,
                "effective-security-mode-ap",
                boolean(secure),
                "boot manifest CSEC",
            )?;
            // The fused values: the emulated chip is not demoted, so they
            // equal the effective ones.
            writer.fill_present(
                CHOSEN,
                "certificate-production-status",
                boolean(production),
                "the emulated chip's production fuse: boot manifest CPRO, undemoted",
            )?;
            writer.fill_present(
                CHOSEN,
                "certificate-security-mode",
                boolean(secure),
                "the emulated chip's security-mode fuse: boot manifest CSEC, undemoted",
            )?;
            match manifest.property("CEPO") {
                Some(Value::Integer(epoch)) => writer.set(
                    CHOSEN,
                    "chip-epoch",
                    u32::try_from(*epoch)?.to_le_bytes().to_vec(),
                    "the emulated chip's epoch: boot manifest CEPO",
                )?,
                _ => unresolved.push("/chosen chip-epoch: the boot manifest has no CEPO".into()),
            }
            if production {
                for flag in UNIT_FLAGS {
                    writer.set(
                        CHOSEN,
                        flag,
                        boolean(false),
                        "a production customer unit (boot manifest CPRO)",
                    )?;
                }
            } else {
                unresolved.push(format!(
                    "/chosen {}: a development chip's unit fuses are not modeled",
                    UNIT_FLAGS.join(", ")
                ));
            }
            let domain = u32::try_from(manifest_integer(manifest, "SDOM")?)?;
            writer.set(
                CHOSEN,
                "security-domain",
                domain.to_le_bytes().to_vec(),
                "boot manifest SDOM",
            )?;
            manifest_properties(&mut writer, manifest)?;
        }
        None => unresolved.push(
            "/chosen boot-manifest-hash, effective-*-ap, certificate-*, chip-epoch, security-domain, \
             unit flags, manifest-properties: no boot manifest"
                .into(),
        ),
    }

    match policy.sepfw_load_at_boot {
        Some(load) => writer.fill(CHOSEN, "sepfw-load-at-boot", boolean(load), "policy")?,
        None => writer.keep(CHOSEN, "sepfw-load-at-boot", "template value")?,
    }
    writer.keep(CHOSEN, "cs-system-policy", "template value")?;
    writer.keep(CHOSEN, "osenvironment", "template value: normal macOS boot")?;
    Ok((writer.decisions, unresolved))
}

/// iBoot forwards the root hash of the sealed volume the kernel roots from
/// as `/chosen/secure-boot-hashes` data. The 26A434 APFS kext's
/// `import_iboot_forwarded_roothash` (0xfffffe000b8302d8) copies the
/// property's bytes unchanged as its forwarded payload. Two paths import it:
/// `AppleAPFSContainer::start` imports `system-volume-auth-blob` once, and
/// `handle_basesystem_rootmount` (0xfffffe000b8a6164) imports
/// `base-system-volume-auth-blob` before `validate_root_hash`. The second runs
/// only for a root mount after an earlier APFS root mount, when the
/// container's device reports a `Virtual Interface` (a disk image attached
/// by DiskImages) and the volume's role is System
/// (`apfs_vfsop_mount`, 0xfffffe000b8a48d4..0xfffffe000b8a4904). The blob is
/// iBoot's `base_system_root_hash.img4` (its `base-system-roothash-path`),
/// authenticated against the manifest that signs it, of which iBoot forwards
/// only the payload: `validate_root_hash` (0xfffffe000b89cc28) takes a
/// forwarded payload of exactly [`ROOT_HASH_RECORD_BYTES`] and compares its
/// fields with the volume's on-disk seal (0xfffffe000b89ce00..0xb89ce48),
/// logging "root_hash size mismatch" otherwise.
const SECURE_BOOT_HASHES: &str = "/chosen/secure-boot-hashes";
/// The root-hash record a `csys`/`isys` `IM4P` carries.
const ROOT_HASH_RECORD_BYTES: usize = 0xd0;

/// The boot-args XNU's `imageboot_desired` takes as the disk image to root
/// from (xnu `bsd/kern/imageboot.c`). iBoot passes BaseSystem as
/// `rp0=file://...` (J473 iBoot string table, with
/// `/usr/standalone/firmware/arm64eBaseSystem.dmg`).
pub const IMAGE_BOOT_ARGS: [&str; 5] = ["rp0", "arp0", "rp", "root-dmg", "auth-root-dmg"];

/// A sealed BaseSystem volume roots only as a disk image. A memory device
/// (`md0`) does not answer `DKIOCISVIRTUAL`, so APFS requires a root snapshot
/// there (`apfs_find_named_root_snapshot_xid`, from `/chosen
/// root-snapshot-name` or the forwarded hash). BaseSystem has no snapshot,
/// and a sealed live root is refused ("Rooting from the live fs of a sealed
/// volume is not allowed", `apfs_vfsops.c:2952`). Without an image-boot
/// argument, refuse rather than boot into that panic.
pub fn require_image_boot(boot_args: &str) -> Result<()> {
    ensure!(
        image_boot_named(boot_args),
        "a BaseSystem root needs an image-boot argument ({}=file://...): APFS cannot root a \
         sealed volume without a snapshot from a memory device",
        IMAGE_BOOT_ARGS[0]
    );
    refuse_ramdisk_image_root(boot_args)
}

fn image_boot_named(boot_args: &str) -> bool {
    boot_args
        .split_whitespace()
        .filter_map(|argument| argument.split_once('='))
        .any(|(name, value)| IMAGE_BOOT_ARGS.contains(&name) && value.starts_with("file://"))
}

/// The first value of the boot-arg `name`, as `PE_parse_boot_argn` takes
/// the first match.
fn boot_arg<'a>(boot_args: &'a str, name: &str) -> Option<&'a str> {
    boot_args
        .split_whitespace()
        .filter_map(|argument| argument.split_once('='))
        .find(|(found, _)| *found == name)
        .map(|(_, value)| value)
}

/// The memory device APFS roots every root mount from, as the helper
/// `container_rootmount` calls first reads it (26A434 APFS
/// 0xfffffe000b8c63e8): `rd=`, or else `rootdev=`, whose value is `md` and
/// one character (it checks `m`, `d` and a NUL at the fourth byte).
pub fn ramdisk_root_device(boot_args: &str) -> Option<&str> {
    boot_arg(boot_args, "rd")
        .or_else(|| boot_arg(boot_args, "rootdev"))
        .filter(|device| device.len() == 3 && device.starts_with("md"))
}

/// An image root cannot follow a memory-device root. With `rd=mdN`,
/// `container_rootmount` (0xfffffe000b84fe6c) opens `/dev/mdN` for every
/// APFS root mount, imageboot's second `vfs_mountroot` included ("boot from
/// ramdisk"); the first root already holds that device, so the image's
/// mount fails with EBUSY and imageboot panics (`vfs_mountroot() failed`,
/// `imageboot.c:468`). A Mac never passes `rd=` for recoveryOS; a root that
/// pivots to an image is named by `/chosen` instead.
pub fn refuse_ramdisk_image_root(boot_args: &str) -> Result<()> {
    if let Some(device) = ramdisk_root_device(boot_args).filter(|_| image_boot_named(boot_args)) {
        anyhow::bail!(
            "boot-args root from memory device {device} and pivot to a disk image: APFS's \
             container_rootmount would take {device} again for the image root (EBUSY, \
             imageboot.c:468); name the first root in /chosen instead of rd=/rootdev="
        );
    }
    Ok(())
}

/// The sealed volume a boot roots from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SealedVolume {
    /// The installed System volume (`SystemVolume`, IM4P `isys`).
    System,
    /// recoveryOS's BaseSystem (`BaseSystemVolume`, IM4P `csys`).
    BaseSystem,
}

impl SealedVolume {
    pub fn payload_type(self) -> &'static str {
        match self {
            Self::System => "isys",
            Self::BaseSystem => "csys",
        }
    }

    pub fn property(self) -> &'static str {
        match self {
            Self::System => "system-volume-auth-blob",
            Self::BaseSystem => "base-system-volume-auth-blob",
        }
    }
}

/// Forward `volume`'s root hash: the payload of its root-hash `IM4P`, once
/// the boot manifest is shown to sign that `IM4P`, as iBoot authenticates
/// the image before forwarding its record.
pub fn apply_root_hash(
    tree: &mut DeviceTree,
    volume: SealedVolume,
    im4p: Option<&[u8]>,
    boot_manifest: Option<(&[u8], &Manifest)>,
) -> Result<(Vec<Decision>, Vec<String>)> {
    let property = volume.property();
    let (im4p, (_, manifest)) = match (im4p, boot_manifest) {
        (Some(im4p), Some(manifest)) => (im4p, manifest),
        (None, _) => {
            return Ok((
                vec![],
                vec![format!(
                    "{SECURE_BOOT_HASHES} {property}: no {} root-hash object",
                    volume.payload_type()
                )],
            ));
        }
        (Some(_), None) => {
            return Ok((
                vec![],
                vec![format!(
                    "{SECURE_BOOT_HASHES} {property}: no boot manifest signs the root hash"
                )],
            ));
        }
    };
    let tag = volume.payload_type();
    let kind = stela_runtime::img4::payload_type(im4p)
        .map_err(|e| anyhow::anyhow!("the {tag} root hash: {e}"))?;
    ensure!(
        kind == tag.as_bytes(),
        "the {tag} root hash is IM4P type {}",
        String::from_utf8_lossy(&kind)
    );
    let signed = manifest
        .object(tag)
        .and_then(|object| object.properties.iter().find(|p| p.name == "DGST"))
        .map(|p| &p.value);
    ensure!(
        matches!(signed, Some(Value::Data(digest)) if digest.as_slice() == crate::im4m::sha384(im4p).as_slice()),
        "the boot manifest does not sign this {tag} root hash"
    );
    let (record, _) = crate::im4p::decode(im4p, ROOT_HASH_RECORD_BYTES as u64)
        .map_err(|e| anyhow::anyhow!("the {tag} root hash payload: {e}"))?;
    ensure!(
        record.len() == ROOT_HASH_RECORD_BYTES,
        "the {tag} root hash payload is {} bytes, not the {ROOT_HASH_RECORD_BYTES}-byte record \
         APFS's validate_root_hash takes",
        record.len()
    );
    tree.ensure_child(CHOSEN, "secure-boot-hashes")?;
    let mut writer = Writer {
        tree,
        decisions: vec![],
    };
    writer.set(
        SECURE_BOOT_HASHES,
        property,
        record,
        &format!("the {tag} root-hash record, signed by the boot manifest"),
    )?;
    Ok((writer.decisions, vec![]))
}

const ENVIRONMENTS: &str = "/osenvironments";
const OSENVIRONMENT: &str = "osenvironment";

/// An OS environment iBoot boots. iBoot's setter (26A434 J473 iBoot
/// 0x24e60) writes the name as `/chosen osenvironment` and applies the
/// `/osenvironments/<name>-environment` child; its callers pass
/// `diagnostics`, `kcgen`, `recoveryos`, `upgrade` and, by darwinOS boot
/// kind, `darwinos-ramdisk` or `macos-darwinos` (table 0x170838). The
/// kernel and TXM also compare `recovery`, whose child the J473 DeviceTree
/// has, but no J473 iBoot caller passes it. macOS itself is the absence of
/// an environment: the template's empty value stays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OsEnvironment {
    /// The Mac's recoveryOS, paired or System Recovery.
    Recoveryos,
    /// `recovery-environment`: ephemeral storage, no SEP firmware load and
    /// an ephemeral data volume in `/filesystems`. No J473 iBoot caller
    /// enters it.
    Recovery,
    /// A restore ramdisk.
    DarwinosRamdisk,
    MacosDarwinos,
    /// A macOS update's ramdisk.
    Upgrade,
    Diagnostics,
    Kcgen,
}

impl OsEnvironment {
    pub const ALL: [Self; 7] = [
        Self::Recoveryos,
        Self::Recovery,
        Self::DarwinosRamdisk,
        Self::MacosDarwinos,
        Self::Upgrade,
        Self::Diagnostics,
        Self::Kcgen,
    ];

    /// The `/chosen osenvironment` value, without its NUL.
    pub fn name(self) -> &'static str {
        match self {
            Self::Recoveryos => "recoveryos",
            Self::Recovery => "recovery",
            Self::DarwinosRamdisk => "darwinos-ramdisk",
            Self::MacosDarwinos => "macos-darwinos",
            Self::Upgrade => "upgrade",
            Self::Diagnostics => "diagnostics",
            Self::Kcgen => "kcgen",
        }
    }

    /// The `/osenvironments` child iBoot applies.
    pub fn node(self) -> String {
        format!("{}-environment", self.name())
    }

    pub fn parse(name: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|e| e.name() == name)
            .with_context(|| {
                format!(
                    "{name:?} is not an OS environment ({})",
                    Self::ALL.map(Self::name).join(", ")
                )
            })
    }
}

fn text_value(bytes: &[u8]) -> Result<String> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Ok(core::str::from_utf8(&bytes[..end])?.to_owned())
}

/// Enter an OS environment as iBoot does: `/chosen osenvironment` becomes
/// its NUL-terminated name and its `/osenvironments` child applies. Each
/// entry either sets `node_path` `property_name` to `value`, or, with
/// `node`, `replacement` and `parent`, replaces the `node` child of `parent`
/// with its `replacement` sibling. An entry whose target is absent from this
/// tree is reported rather than invented.
pub fn apply_environment(
    tree: &mut DeviceTree,
    os_environment: OsEnvironment,
) -> Result<(Vec<Decision>, Vec<String>)> {
    let name = os_environment.node();
    let path = format!("{ENVIRONMENTS}/{name}");
    let environment = tree
        .node(&path)
        .with_context(|| format!("DeviceTree has no {path}"))?
        .clone();
    let mut value = os_environment.name().as_bytes().to_vec();
    value.push(0);
    let mut decisions = vec![Decision {
        path: CHOSEN.into(),
        property: OSENVIRONMENT.into(),
        value_hex: hex::encode(&value),
        source: format!("OS environment {}", os_environment.name()),
    }];
    tree.set_property(CHOSEN, OSENVIRONMENT, value)?;
    let mut unresolved = vec![];
    for entry in &environment.children {
        let label = entry.name().unwrap_or("?").to_owned();
        let field = |key: &str| entry.property(key).map(|p| p.value.clone());
        if let (Some(node_path), Some(property), Some(value)) =
            (field("node_path"), field("property_name"), field("value"))
        {
            let target = format!("/{}", text_value(&node_path)?);
            let property = text_value(&property)?;
            if tree.node(&target).is_none() {
                unresolved.push(format!("{path} {label}: no node {target}"));
                continue;
            }
            decisions.push(Decision {
                path: target.clone(),
                property: property.clone(),
                value_hex: hex::encode(&value),
                source: format!("osenvironment {name}: {label}"),
            });
            tree.set_property(&target, &property, value)?;
        } else if let (Some(node), Some(replacement), Some(parent)) =
            (field("node"), field("replacement"), field("parent"))
        {
            let (node, replacement, parent) = (
                text_value(&node)?,
                text_value(&replacement)?,
                text_value(&parent)?,
            );
            let Some(parent_node) = tree.node_mut(&parent) else {
                unresolved.push(format!("{path} {label}: no node {parent}"));
                continue;
            };
            let Some(index) = parent_node
                .children
                .iter()
                .position(|c| c.name() == Some(replacement.as_str()))
            else {
                unresolved.push(format!("{path} {label}: no node {parent}/{replacement}"));
                continue;
            };
            let mut substitute = parent_node.children.remove(index);
            let mut name_value = node.as_bytes().to_vec();
            name_value.push(0);
            substitute.set_property("name", name_value)?;
            parent_node
                .children
                .retain(|c| c.name() != Some(node.as_str()));
            parent_node.children.push(substitute);
            decisions.push(Decision {
                path: format!("{parent}/{node}"),
                property: "name".into(),
                value_hex: hex::encode(node.as_bytes()),
                source: format!("osenvironment {name}: {label} replaced by {replacement}"),
            });
        } else {
            anyhow::bail!("{path} {label} is neither a property nor a node replacement");
        }
    }
    Ok((decisions, unresolved))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apple_device_tree::Node;
    use crate::im4m;
    use crate::im4m::tests::{der, entry, manifest};

    fn tree() -> DeviceTree {
        let mut tree = DeviceTree {
            root: Node::named("device-tree").unwrap(),
        };
        tree.ensure_child("/", "chosen").unwrap();
        tree.ensure_child("/chosen", "manifest-properties").unwrap();
        tree.ensure_child("/", "product").unwrap();
        for (name, bytes) in [
            ("boot-manifest-hash", 48),
            ("effective-production-status-ap", 4),
            ("effective-security-mode-ap", 4),
            ("sepfw-load-at-boot", 4),
            ("osenvironment", 32),
            ("certificate-production-status", 4),
            ("certificate-security-mode", 4),
        ] {
            tree.set_property("/chosen", name, vec![0; bytes]).unwrap();
        }
        tree.set_property("/chosen", "cs-system-policy", b"default\0".to_vec())
            .unwrap();
        for (slot, bytes) in [(INTEGER_SLOT, 8), (BOOLEAN_SLOT, 4), (STRING_SLOT, 0x40)] {
            for index in 0..3 {
                tree.set_property(
                    MANIFEST_PROPERTIES,
                    &format!("{slot}{index}"),
                    vec![0; bytes],
                )
                .unwrap();
            }
        }
        tree
    }

    fn boot_manifest() -> Manifest {
        im4m::parse(&manifest(
            &[
                entry("CPRO", &der(&[0x01], &[0xff])),
                entry("CSEC", &der(&[0x01], &[0xff])),
                entry("SDOM", &der(&[0x02], &[1])),
                entry("CEPO", &der(&[0x02], &[1])),
                entry("love", &der(&[0x04], b"26.1.434.0.0,0")),
            ],
            &[],
        ))
        .unwrap()
    }

    #[test]
    fn reduced_security_is_expressed_as_device_tree_data() -> Result<()> {
        let mut tree = tree();
        let boot = boot_manifest();
        let cryptex = im4m::parse(&manifest(&[entry("SDOM", &der(&[0x02], &[1]))], &[]))?;
        let policy = SecurityPolicy {
            mode: SecurityMode::Reduced,
            sip_bits: 0,
            sepfw_load_at_boot: Some(false),
        };
        let (decisions, unresolved) = apply(&mut tree, &policy, Some(&boot), Some(&cryptex))?;
        assert!(unresolved.is_empty());
        let value = |path: &str, name: &str| tree.property(path, name).unwrap().value.clone();
        assert_eq!(value(ASMB, "lp-smb0"), boolean(true));
        assert_eq!(value(ASMB, "lp-smb1"), boolean(false));
        assert_eq!(value(ASMB, "lp-sip0"), integer(0));
        assert_eq!(hex::encode(value(ASMB, "lp-spih")), cryptex.sha384);
        assert_eq!(
            hex::encode(value(CHOSEN, "boot-manifest-hash")),
            boot.sha384
        );
        assert_eq!(value(CHOSEN, "effective-security-mode-ap"), boolean(true));
        assert_eq!(value(CHOSEN, "security-domain"), 1u32.to_le_bytes());
        assert_eq!(value(CHOSEN, "sepfw-load-at-boot"), boolean(false));
        assert_eq!(value(MANIFEST_PROPERTIES, "CPRO"), boolean(true));
        // The fused state and epoch of an undemoted production chip.
        assert_eq!(
            value(CHOSEN, "certificate-production-status"),
            boolean(true)
        );
        assert_eq!(value(CHOSEN, "certificate-security-mode"), boolean(true));
        assert_eq!(value(CHOSEN, "chip-epoch"), 1u32.to_le_bytes());
        for flag in UNIT_FLAGS {
            assert_eq!(value(CHOSEN, flag), boolean(false));
        }
        assert_eq!(value(CHOSEN, "kernel-ctrr-to-be-enabled"), boolean(true));
        assert_eq!(value(PRODUCT, "allow-hactivation"), boolean(false));
        assert_eq!(value(CHOSEN, "boot-nonce-hash-method"), b"sha2-384\0");
        assert_eq!(value(MANIFEST_PROPERTIES, "love"), b"26.1.434.0.0,0");
        // The slots keep their place; one of each kind remains.
        assert!(
            tree.property(MANIFEST_PROPERTIES, "UnusedIntegerProperty0")
                .is_none()
        );
        assert!(
            tree.property(MANIFEST_PROPERTIES, "UnusedIntegerProperty2")
                .is_some()
        );
        assert!(decisions.iter().any(|d| d.property == "cs-system-policy"));
        Ok(())
    }

    #[test]
    fn a_custom_kernel_or_sip2_turns_kernel_ctrr_off() {
        let mut tree = tree();
        tree.ensure_child(CHOSEN, "asmb").unwrap();
        assert!(kernel_ctrr(&tree).0);
        tree.set_property(ASMB, "lp-sip2", boolean(true)).unwrap();
        assert!(!kernel_ctrr(&tree).0);
        tree.set_property(ASMB, "lp-sip2", boolean(false)).unwrap();
        tree.set_property(ASMB, "lp-coih", vec![0; 48]).unwrap();
        assert!(!kernel_ctrr(&tree).0);
    }

    #[test]
    fn a_development_chip_leaves_its_unit_fuses_and_epoch_unresolved() -> Result<()> {
        let development = im4m::parse(&manifest(
            &[
                entry("CPRO", &der(&[0x01], &[0x00])),
                entry("CSEC", &der(&[0x01], &[0xff])),
                entry("SDOM", &der(&[0x02], &[1])),
            ],
            &[],
        ))?;
        let mut tree = tree();
        let policy = SecurityPolicy {
            mode: SecurityMode::Reduced,
            sip_bits: 0,
            sepfw_load_at_boot: None,
        };
        let (_, unresolved) = apply(&mut tree, &policy, Some(&development), None)?;
        assert!(unresolved.iter().any(|gap| gap.contains("chip-epoch")));
        assert!(
            unresolved
                .iter()
                .any(|gap| gap.contains("internal-use-only-unit"))
        );
        assert!(tree.property(CHOSEN, "internal-use-only-unit").is_none());
        assert_eq!(
            tree.property(CHOSEN, "certificate-production-status")
                .unwrap()
                .value,
            boolean(false)
        );
        Ok(())
    }

    #[test]
    fn a_base_system_root_needs_a_file_image_boot_argument() {
        let image = "rp0=file:///usr/standalone/firmware/arm64eBaseSystem.dmg";
        assert!(require_image_boot(&format!("-v {image}")).is_ok());
        assert!(require_image_boot("root-dmg=file:///a.dmg").is_ok());
        // A ramdisk root alone, another scheme or another argument is refused.
        assert!(require_image_boot("-v rd=md0").is_err());
        assert!(require_image_boot("rp0=http://host/a.dmg").is_err());
        assert!(require_image_boot("xrp0=file:///a.dmg").is_err());
    }

    #[test]
    fn a_memory_device_root_cannot_pivot_to_an_image() {
        let image = "rp0=file:///usr/standalone/firmware/arm64eBaseSystem.dmg";
        // The rec-r5 boot-args: APFS took md0 again for the image root.
        let error = require_image_boot(&format!("-v rd=md0 {image}"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("memory device md0"), "{error}");
        assert!(refuse_ramdisk_image_root(&format!("rootdev=mdf {image}")).is_err());
        assert!(refuse_ramdisk_image_root(&format!("{image} rd=md1")).is_err());
        // APFS reads `rd=` before `rootdev=`, and only `md` and one character.
        assert_eq!(ramdisk_root_device("rd=disk1s1 rootdev=md0"), None);
        assert_eq!(ramdisk_root_device("rd=md10"), None);
        assert_eq!(ramdisk_root_device("rootdev=md0"), Some("md0"));
        assert_eq!(ramdisk_root_device("rd=md0 rd=disk0"), Some("md0"));
        // A memory-device root without an image (a restore) stays allowed.
        assert!(refuse_ramdisk_image_root("-v rd=md0 -restore").is_ok());
        assert!(refuse_ramdisk_image_root(image).is_ok());
    }

    #[test]
    fn os_environments_are_named_as_iboot_names_them() {
        for environment in OsEnvironment::ALL {
            assert_eq!(
                OsEnvironment::parse(environment.name()).unwrap(),
                environment
            );
        }
        assert_eq!(OsEnvironment::Recoveryos.node(), "recoveryos-environment");
        assert!(OsEnvironment::parse("recovery-environment").is_err());
    }

    fn environment_entry(tree: &mut DeviceTree, entry: &str, values: &[(&str, &[u8])]) {
        let path = format!("{ENVIRONMENTS}/darwinos-ramdisk-environment");
        tree.ensure_child(&path, entry).unwrap();
        for (property, value) in values {
            tree.set_property(&format!("{path}/{entry}"), property, value.to_vec())
                .unwrap();
        }
    }

    #[test]
    fn environment_overlays_set_properties_and_replace_nodes() -> Result<()> {
        let mut tree = tree();
        tree.ensure_child("/", "osenvironments")?;
        tree.ensure_child(ENVIRONMENTS, "darwinos-ramdisk-environment")?;
        environment_entry(
            &mut tree,
            "no-sepfw-load-at-boot",
            &[
                ("node_path", b"chosen\0"),
                ("property_name", b"sepfw-load-at-boot\0"),
                ("value", &[0, 0, 0, 0]),
            ],
        );
        environment_entry(
            &mut tree,
            "data-volume",
            &[
                ("node", b"fstab\0"),
                ("replacement", b"fstab-ephemeral\0"),
                ("parent", b"/filesystems\0"),
            ],
        );
        environment_entry(
            &mut tree,
            "absent",
            &[
                ("node", b"fstab\0"),
                ("replacement", b"fstab-other\0"),
                ("parent", b"/nowhere\0"),
            ],
        );
        tree.ensure_child("/", "filesystems")?;
        tree.ensure_child("/filesystems", "fstab")?;
        tree.ensure_child("/filesystems", "fstab-ephemeral")?;
        tree.set_property("/filesystems/fstab-ephemeral", "marker", vec![1])?;
        tree.set_property("/chosen", "sepfw-load-at-boot", boolean(true))?;
        let (decisions, unresolved) = apply_environment(&mut tree, OsEnvironment::DarwinosRamdisk)?;
        assert_eq!(
            tree.property(CHOSEN, "sepfw-load-at-boot").unwrap().value,
            boolean(false)
        );
        assert_eq!(
            tree.property(CHOSEN, OSENVIRONMENT).unwrap().value,
            b"darwinos-ramdisk\0"
        );
        assert_eq!(
            tree.property("/filesystems/fstab", "marker").unwrap().value,
            vec![1]
        );
        assert!(tree.node("/filesystems/fstab-ephemeral").is_none());
        assert_eq!(decisions.len(), 3);
        assert_eq!(unresolved.len(), 1);
        assert!(apply_environment(&mut tree, OsEnvironment::Kcgen).is_err());
        Ok(())
    }

    #[test]
    fn missing_manifests_stay_visible_and_permissive_sets_smb1() -> Result<()> {
        let mut tree = tree();
        let policy = SecurityPolicy {
            mode: SecurityMode::Permissive,
            sip_bits: 0x7f,
            sepfw_load_at_boot: None,
        };
        let (_, unresolved) = apply(&mut tree, &policy, None, None)?;
        assert_eq!(unresolved.len(), 2);
        assert_eq!(tree.property(ASMB, "lp-smb1").unwrap().value, boolean(true));
        assert_eq!(tree.property(ASMB, "lp-sip0").unwrap().as_u64(), Some(0x7f));
        assert_eq!(
            tree.property(CHOSEN, "boot-manifest-hash").unwrap().value,
            vec![0; 48]
        );
        Ok(())
    }

    #[test]
    fn the_root_hash_record_is_forwarded_once_the_boot_manifest_signs_it() -> Result<()> {
        let im4p = der(
            &[0x30],
            &[
                der(&[0x16], b"IM4P"),
                der(&[0x16], b"csys"),
                der(&[0x16], b"root hash"),
                der(&[0x04], &[0x5a; 208]),
            ]
            .concat(),
        );
        let signed = manifest(
            &[entry("SDOM", &der(&[0x02], &[1]))],
            &[entry(
                "csys",
                &der(&[0x31], &entry("DGST", &der(&[0x04], &im4m::sha384(&im4p)))),
            )],
        );
        let parsed = im4m::parse(&signed)?;
        let mut tree = tree();
        let (decisions, unresolved) = apply_root_hash(
            &mut tree,
            SealedVolume::BaseSystem,
            Some(&im4p),
            Some((&signed, &parsed)),
        )?;
        assert!(unresolved.is_empty());
        assert_eq!(decisions.len(), 1);
        let blob = &tree
            .property(SECURE_BOOT_HASHES, "base-system-volume-auth-blob")
            .unwrap()
            .value;
        assert_eq!(blob, &[0x5a; 208]);

        // Without the object the gap is reported; a manifest that does not
        // sign it, or the wrong payload type, is refused.
        let (_, unresolved) = apply_root_hash(
            &mut tree,
            SealedVolume::System,
            None,
            Some((&signed, &parsed)),
        )?;
        assert!(unresolved[0].contains("system-volume-auth-blob"));
        let unsigned = boot_manifest();
        assert!(
            apply_root_hash(
                &mut tree,
                SealedVolume::BaseSystem,
                Some(&im4p),
                Some((&signed, &unsigned))
            )
            .is_err()
        );
        assert!(
            apply_root_hash(
                &mut tree,
                SealedVolume::System,
                Some(&im4p),
                Some((&signed, &parsed))
            )
            .is_err()
        );
        Ok(())
    }
}
