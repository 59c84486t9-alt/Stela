//! Prepare the kernel boot bundle that the UEFI mount hands to the ARM kernel.
use crate::{args::parse_address, restore};
use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Subcommand};
use std::{fs::OpenOptions, io::Write, path::PathBuf};
use stela_loader::boot_bundle::{
    self, Input, Inputs, Options, OverlayProperty, RootHash, Source, Target,
};
use stela_loader::boot_policy::{SealedVolume, SecurityMode, SecurityPolicy};
use stela_loader::im4m;

mod disk;

const MANIFEST_FILE: &str = "bundle.json";
const KERNEL_LIMIT: u64 = 512 * 1024 * 1024;
const COMPONENT_LIMIT: u64 = 64 * 1024 * 1024;
const RAMDISK_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
const INSTALLED_VARIANT: &str = "macOS Customer";
const RESTORE_VARIANT: &str = "Customer Erase Install (IPSW)";
/// The `/osenvironments` child for a restore ramdisk: it turns off the SEP
/// firmware load and protected data access and selects ephemeral storage.
const RESTORE_ENVIRONMENT: &str = "darwinos-ramdisk-environment";
const INSTALLED_BOOT_ARGS: &str = "-v";
const RESTORE_BOOT_ARGS: &str = "-v rd=md0";
/// recoveryOS from the installed-system identity: BaseSystem as the ramdisk.
const RECOVERY_ENVIRONMENT: &str = "recovery-environment";
const BASE_SYSTEM: &str = "BaseSystem";
/// The BaseSystem image's APFS partition, which becomes the ramdisk.
const BASE_SYSTEM_PARTITION: &str = "Apple_APFS";

/// The BuildManifest components, and their IM4P types, a boot mode loads.
struct Roles {
    kernel: &'static str,
    device_tree: &'static str,
    trust_cache: (&'static str, &'static str),
    sptm: &'static str,
    txm: &'static str,
    sep: &'static str,
    ramdisk: Option<Ramdisk>,
    /// The sealed volume the kernel roots from, by its root-hash component.
    root_hash: Option<(&'static str, SealedVolume)>,
}

#[derive(Clone, Copy)]
enum Ramdisk {
    /// An IM4P component and its type.
    Image4(&'static str, &'static str),
    /// The AEA-encrypted BaseSystem UDIF image's APFS partition.
    BaseSystem,
}

const INSTALLED: Roles = Roles {
    kernel: "KernelCache",
    device_tree: "DeviceTree",
    trust_cache: ("StaticTrustCache", "trst"),
    sptm: "Ap,SecurePageTableMonitor",
    txm: "Ap,TrustedExecutionMonitor",
    sep: "SEP",
    ramdisk: None,
    root_hash: Some(("SystemVolume", SealedVolume::System)),
};

const RESTORE: Roles = Roles {
    kernel: "RestoreKernelCache",
    device_tree: "RestoreDeviceTree",
    trust_cache: ("RestoreTrustCache", "rtsc"),
    sptm: "Ap,RestoreSecurePageTableMonitor",
    txm: "Ap,RestoreTrustedExecutionMonitor",
    sep: "RestoreSEP",
    ramdisk: Some(Ramdisk::Image4("RestoreRamDisk", "rdsk")),
    root_hash: None,
};

/// recoveryOS: the installed system's kernel, monitors and DeviceTree, the
/// BaseSystem trust cache, and BaseSystem as the ramdisk root.
const RECOVERY: Roles = Roles {
    kernel: "KernelCache",
    device_tree: "DeviceTree",
    trust_cache: ("Ap,BaseSystemTrustCache", "bstc"),
    sptm: "Ap,SecurePageTableMonitor",
    txm: "Ap,TrustedExecutionMonitor",
    sep: "SEP",
    ramdisk: Some(Ramdisk::BaseSystem),
    root_hash: Some(("BaseSystemVolume", SealedVolume::BaseSystem)),
};

#[derive(Subcommand)]
pub(crate) enum BootCommand {
    /// Lay out a model's kernel collection, SPTM, TXM, DeviceTree and trust
    /// cache in guest physical memory for `stela.efi`.
    Prepare(Prepare),
}

#[derive(Args)]
pub(crate) struct Prepare {
    #[arg(long, required_unless_present = "disk", conflicts_with = "disk")]
    ipsw: Option<PathBuf>,
    /// The `Ap,ProductType`, such as Mac14,3.
    #[arg(long, required_unless_present = "disk")]
    model: Option<String>,
    /// Build the bundle from an installed system's Preboot volume on this
    /// disk image instead of an IPSW.
    #[arg(long, conflicts_with_all = ["restore", "recovery", "variant", "cryptex_trust_caches"])]
    disk: Option<PathBuf>,
    /// The `boot/<hash>` directory to use when the Preboot volume has several.
    #[arg(long, requires = "disk")]
    boot_hash: Option<String>,
    /// A new directory for the bundle.
    #[arg(long)]
    output: PathBuf,
    /// Boot the restore ramdisk with the identity's restore objects instead
    /// of the installed system.
    #[arg(long, conflicts_with = "recovery")]
    restore: bool,
    /// Boot recoveryOS: BaseSystem as a ramdisk with the installed system's
    /// kernel. Needs `/usr/bin/aea` to decrypt BaseSystem.
    #[arg(long)]
    recovery: bool,
    /// The public AEA key (PKCS8 PEM) for BaseSystem; fetched from Apple's
    /// key server when omitted.
    #[arg(long, requires = "recovery")]
    aea_key: Option<PathBuf>,
    /// The restore identity variant: `macOS Customer` for the installed
    /// system, `Customer Erase Install (IPSW)` with `--restore`.
    #[arg(long)]
    variant: Option<String>,
    /// The `/osenvironments` child to apply; `darwinos-ramdisk-environment`
    /// with `--restore`.
    #[arg(long)]
    osenvironment: Option<String>,
    /// Guest DRAM base; the target SoC's by default (0x800000000 on the M1
    /// and M2, 0x10000000000 on their Pro and Max).
    #[arg(long, value_parser = parse_address)]
    dram_base: Option<u64>,
    /// Guest DRAM size assumed until the mount patches it at boot.
    #[arg(long, value_parser = parse_address, default_value = "0x200000000")]
    dram_size: u64,
    /// Lowest address handed to the kernel; the DRAM base by default, and
    /// always past iBoot's carveouts.
    #[arg(long, value_parser = parse_address)]
    phys_base: Option<u64>,
    /// Distance of the first region above the physical base.
    #[arg(long, value_parser = parse_address, default_value = "0")]
    load_offset: u64,
    /// The kernel command line; `-v`, or `-v rd=md0` with `--restore`.
    #[arg(long)]
    boot_args: Option<String>,
    /// The boot policy expressed to SPTM, TXM and the kernel.
    #[arg(long, value_enum, default_value = "reduced")]
    security: Security,
    /// System Integrity Protection bits (`lp-sip0`).
    #[arg(long, value_parser = parse_address, default_value = "0")]
    sip_bits: u64,
    /// Override the template's `/chosen sepfw-load-at-boot`.
    #[arg(long)]
    sepfw_load_at_boot: Option<bool>,
    /// Also place the identity's Cryptex1 trust caches in the boot
    /// `TrustCache` region after the static one.
    #[arg(long)]
    cryptex_trust_caches: bool,
    /// JSON list of DeviceTree values from device models, such as
    /// `[{"path": "/chosen/lock-regs/amcc", "property": "aperture-count", "u32": 1}]`.
    #[arg(long)]
    dt_overlay: Option<PathBuf>,
    /// The `/cpus` node of the boot CPU.
    #[arg(long, default_value = "cpu0")]
    boot_cpu: String,
    /// The generic timer rate the machine presents, in Hz.
    #[arg(long, value_parser = parse_address, default_value = "24000000")]
    timebase_frequency: u64,
    /// A board configuration value for DeviceTree fill-ins, as KEY=HEX
    /// (for example SrNm=...); repeat for each key.
    #[arg(long = "syscfg", value_parser = parse_keyed_bytes)]
    syscfg: Vec<(String, Vec<u8>)>,
    /// A MAC address for DeviceTree fill-ins, as NAME=HEX with optional
    /// colons (for example ethaddr=02:00:00:00:00:01); repeat for each.
    #[arg(long = "macaddr", value_parser = parse_keyed_bytes)]
    mac_addresses: Vec<(String, Vec<u8>)>,
    /// A firmware image the board's own devices run, kept under its guest
    /// file name (such as `USB-C_HPM,47.bin` from `extract-guest-files`);
    /// repeat for each image.
    #[arg(long, conflicts_with = "disk")]
    board_firmware: Vec<PathBuf>,
}

fn parse_keyed_bytes(value: &str) -> Result<(String, Vec<u8>), String> {
    let (key, bytes) = value.split_once('=').ok_or("expected KEY=HEX")?;
    if key.is_empty() {
        return Err("empty key".into());
    }
    let bytes = hex::decode(bytes.replace(':', "")).map_err(|error| error.to_string())?;
    Ok((key.to_owned(), bytes))
}

/// Run `boot prepare` with these arguments, exactly as the command line
/// parses them, so callers get the same defaults.
pub(crate) fn prepare(arguments: &[String]) -> Result<()> {
    #[derive(clap::Parser)]
    struct Line {
        #[command(flatten)]
        prepare: Prepare,
    }
    let line = <Line as clap::Parser>::try_parse_from(
        std::iter::once("prepare".to_owned()).chain(arguments.iter().cloned()),
    )?;
    line.prepare.run()
}

impl BootCommand {
    pub(crate) fn run(self) -> Result<()> {
        match self {
            Self::Prepare(command) => command.run(),
        }
    }
}

struct Decoded {
    bytes: Vec<u8>,
    source: Source,
    /// The BuildManifest digest of the component, as a hex string.
    declared_digest: Option<String>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Security {
    Reduced,
    Permissive,
}

/// One `--dt-overlay` entry; exactly one value field is present.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OverlayEntry {
    path: String,
    property: String,
    u32: Option<u32>,
    u64: Option<u64>,
    hex: Option<String>,
    string: Option<String>,
}

fn read_overlay(path: &std::path::Path) -> Result<Vec<OverlayProperty>> {
    let entries: Vec<OverlayEntry> = stela_runtime::read_json(path)?;
    entries
        .into_iter()
        .map(|entry| {
            let mut values = [
                entry.u32.map(|v| v.to_le_bytes().to_vec()),
                entry.u64.map(|v| v.to_le_bytes().to_vec()),
                entry.hex.map(hex::decode).transpose()?,
                entry.string.map(|v| [v.as_bytes(), &[0]].concat()),
            ]
            .into_iter()
            .flatten();
            let value = values.next().with_context(|| {
                format!("overlay {} {} has no value", entry.path, entry.property)
            })?;
            ensure!(
                values.next().is_none(),
                "overlay {} {} has several values",
                entry.path,
                entry.property
            );
            Ok(OverlayProperty {
                path: entry.path,
                property: entry.property,
                value,
            })
        })
        .collect()
}

/// The identity's global manifests sit at `Firmware/Manifests/restore/[cryptex1/]VARIANT/apticket.CLASS.im4m`.
fn manifest_member(cryptex1: bool, variant: &str, device_class: &str) -> String {
    let scope = if cryptex1 { "cryptex1/" } else { "" };
    format!("Firmware/Manifests/restore/{scope}{variant}/apticket.{device_class}.im4m")
}

/// Every boot object the manifest admits must carry the BuildManifest digest.
fn check_digests(manifest: &im4m::Manifest, decoded: &[&Decoded]) -> Result<()> {
    for item in decoded {
        let (Some(object), Some(declared)) = (
            manifest.object(&item.source.payload_type),
            &item.declared_digest,
        ) else {
            continue;
        };
        let digest = object
            .properties
            .iter()
            .find(|p| p.name == "DGST")
            .with_context(|| format!("manifest {} has no DGST", object.tag))?;
        ensure!(
            digest.value == im4m::Value::Data(hex::decode(declared)?),
            "manifest {} digest differs from the BuildManifest {}",
            object.tag,
            item.source.component
        );
    }
    Ok(())
}

/// BaseSystem's APFS partition: the AEA member is copied out, decrypted
/// with the public key, and its UDIF image's `Apple_APFS` partition read.
fn base_system(
    ipsw: &std::path::Path,
    member: &str,
    key: Option<&std::path::Path>,
    declared_digest: Option<String>,
) -> Result<Decoded> {
    let work = tempfile::tempdir()?;
    let encrypted = work.path().join("BaseSystem.dmg.aea");
    let receipt = restore::archive::extract(ipsw, member, &encrypted, RAMDISK_LIMIT)?;
    let container_sha256 = receipt["sha256"]
        .as_str()
        .context("extraction receipt has no SHA-256")?
        .to_owned();
    let key = match key {
        Some(key) => key.to_path_buf(),
        None => {
            let fetched = restore::aea::fetch_public_key(&restore::aea::inspect(&encrypted)?)?;
            let path = work.path().join("BaseSystem.pem");
            std::fs::write(&path, &fetched.body)?;
            path
        }
    };
    let image = work.path().join("BaseSystem.dmg");
    restore::aea::decrypt(&encrypted, &key, &image)?;
    let bytes = restore::udif::partition(&image, BASE_SYSTEM_PARTITION, RAMDISK_LIMIT)?;
    Ok(Decoded {
        source: Source {
            component: BASE_SYSTEM.into(),
            member: member.into(),
            container_sha256,
            payload_type: "apfs".into(),
            description: format!("{BASE_SYSTEM_PARTITION} partition of the decrypted UDIF image"),
            decoded_bytes: bytes.len(),
            decoded_sha256: stela_runtime::sha256(&bytes),
        },
        bytes,
        declared_digest,
    })
}

fn parse_id(value: Option<&str>) -> Result<Option<u32>> {
    value
        .map(|v| {
            u32::from_str_radix(v.trim_start_matches("0x").trim_start_matches("0X"), 16)
                .with_context(|| format!("bad restore identity value {v}"))
        })
        .transpose()
}

impl Prepare {
    fn run(self) -> Result<()> {
        ensure!(
            !self.output.exists(),
            "output exists; choose a new --output directory"
        );
        if let Some(disk) = &self.disk {
            return self.run_disk(disk);
        }
        let ipsw = self.ipsw.clone().context("--ipsw is required")?;
        let model = self.model.clone().context("--model is required")?;
        let report = restore::archive::manifest(&ipsw, Some(&model), false)?;
        let (roles, default_variant) = match (self.restore, self.recovery) {
            (true, _) => (RESTORE, RESTORE_VARIANT),
            (false, true) => (RECOVERY, INSTALLED_VARIANT),
            (false, false) => (INSTALLED, INSTALLED_VARIANT),
        };
        let variant = self.variant.as_deref().unwrap_or(default_variant);
        let identity = report
            .identities
            .iter()
            .find(|i| i.variant == variant)
            .with_context(|| {
                let variants: Vec<_> = report.identities.iter().map(|i| &i.variant).collect();
                format!("no {} identity {:?}; found {variants:?}", model, variant)
            })?;
        let component = |name: &str, payload_type: Option<&str>, limit: u64| -> Result<Decoded> {
            // A component absent from the selected identity is taken from
            // another identity of the same model, and named with its variant.
            let (owner, entry) = std::iter::once(identity)
                .chain(report.identities.iter())
                .find_map(|i| i.components.get(name).map(|c| (i, c)))
                .with_context(|| format!("no {model} identity lists {name}"))?;
            let container = restore::archive::read_member(&ipsw, &entry.path, limit)?;
            let label = if owner.variant == identity.variant {
                name.to_owned()
            } else {
                format!("{name} ({})", owner.variant)
            };
            let (bytes, receipt) = match payload_type {
                Some(expected) => {
                    let (bytes, receipt) = stela_loader::im4p::decode(&container, limit)?;
                    if receipt.payload_type != expected {
                        bail!(
                            "{name} is IM4P type {}, expected {expected}",
                            receipt.payload_type
                        );
                    }
                    (bytes, Some(receipt))
                }
                None => (container.clone(), None),
            };
            let source = Source {
                component: label,
                member: entry.path.clone(),
                container_sha256: stela_runtime::sha256(&container),
                payload_type: receipt
                    .as_ref()
                    .map_or_else(|| "opaque".into(), |r| r.payload_type.clone()),
                description: receipt.map(|r| r.description).unwrap_or_default(),
                decoded_bytes: bytes.len(),
                decoded_sha256: stela_runtime::sha256(&bytes),
            };
            Ok(Decoded {
                bytes,
                source,
                declared_digest: entry.declared_digest_hex.clone(),
            })
        };
        let kernel = component(roles.kernel, Some("krnl"), KERNEL_LIMIT)?;
        let sptm = component(roles.sptm, Some("sptm"), COMPONENT_LIMIT)?;
        let txm = component(roles.txm, Some("trxm"), COMPONENT_LIMIT)?;
        let device_tree = component(roles.device_tree, Some("dtre"), COMPONENT_LIMIT)?;
        let (trust_cache_name, trust_cache_type) = roles.trust_cache;
        let trust_cache = component(trust_cache_name, Some(trust_cache_type), COMPONENT_LIMIT)?;
        let ramdisk = match roles.ramdisk {
            None => None,
            Some(Ramdisk::Image4(name, payload_type)) => {
                Some(component(name, Some(payload_type), RAMDISK_LIMIT)?)
            }
            Some(Ramdisk::BaseSystem) => {
                let entry = identity
                    .components
                    .get(BASE_SYSTEM)
                    .with_context(|| format!("{} lists no {BASE_SYSTEM}", identity.variant))?;
                Some(base_system(
                    &ipsw,
                    &entry.path,
                    self.aea_key.as_deref(),
                    entry.declared_digest_hex.clone(),
                )?)
            }
        };
        // The root hash stays an IM4P: iBoot forwards it with its manifest.
        let root_hash = match roles.root_hash {
            None => None,
            Some((name, volume)) => Some((
                volume,
                report
                    .identities
                    .iter()
                    .any(|i| i.components.contains_key(name))
                    .then(|| component(name, None, COMPONENT_LIMIT))
                    .transpose()?,
            )),
        };
        let sep = report
            .identities
            .iter()
            .any(|i| i.components.contains_key(roles.sep))
            .then(|| component(roles.sep, None, COMPONENT_LIMIT))
            .transpose()?;
        let global_manifest = |cryptex1: bool| -> Result<Option<Decoded>> {
            let member = manifest_member(cryptex1, &identity.variant, &identity.device_class);
            if !restore::archive::has_member(&ipsw, &member)? {
                return Ok(None);
            }
            let bytes = restore::archive::read_member(&ipsw, &member, COMPONENT_LIMIT)?;
            let source = Source {
                component: if cryptex1 {
                    "Cryptex1 manifest"
                } else {
                    "Boot manifest"
                }
                .into(),
                member,
                container_sha256: stela_runtime::sha256(&bytes),
                payload_type: "im4m".into(),
                description: String::new(),
                decoded_bytes: bytes.len(),
                decoded_sha256: stela_runtime::sha256(&bytes),
            };
            Ok(Some(Decoded {
                bytes,
                source,
                declared_digest: None,
            }))
        };
        let boot_manifest = global_manifest(false)?;
        let cryptex1_manifest = global_manifest(true)?;
        let mut cryptex_trust_caches = vec![];
        if self.cryptex_trust_caches {
            for name in identity.components.keys() {
                if name.starts_with("Cryptex1,") && name.ends_with("TrustCache") {
                    cryptex_trust_caches.push(component(name, None, COMPONENT_LIMIT).and_then(
                        |raw| {
                            let (bytes, receipt) =
                                stela_loader::im4p::decode(&raw.bytes, COMPONENT_LIMIT)?;
                            Ok(Decoded {
                                source: Source {
                                    payload_type: receipt.payload_type,
                                    description: receipt.description,
                                    decoded_bytes: bytes.len(),
                                    decoded_sha256: stela_runtime::sha256(&bytes),
                                    ..raw.source
                                },
                                bytes,
                                declared_digest: raw.declared_digest,
                            })
                        },
                    )?);
                }
            }
        }
        if let Some(manifest) = &boot_manifest {
            check_digests(
                &im4m::parse(&manifest.bytes)?,
                &[&kernel, &sptm, &txm, &device_tree, &trust_cache],
            )?;
        }
        if let Some(manifest) = &cryptex1_manifest {
            let decoded: Vec<_> = cryptex_trust_caches.iter().collect();
            check_digests(&im4m::parse(&manifest.bytes)?, &decoded)?;
        }
        fn input(decoded: &Decoded) -> Input<'_> {
            Input {
                bytes: &decoded.bytes,
                source: decoded.source.clone(),
            }
        }
        let board_firmware = self
            .board_firmware
            .iter()
            .map(|path| {
                let bytes = std::fs::read(path)
                    .with_context(|| format!("cannot read {}", path.display()))?;
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .with_context(|| format!("{} has no UTF-8 file name", path.display()))?
                    .to_owned();
                let digest = stela_runtime::sha256(&bytes);
                let source = Source {
                    component: "BoardFirmware".into(),
                    member: path.canonicalize()?.display().to_string(),
                    container_sha256: digest.clone(),
                    payload_type: "raw".into(),
                    description: format!("board device firmware {name}"),
                    decoded_bytes: bytes.len(),
                    decoded_sha256: digest,
                };
                Ok((
                    name,
                    Decoded {
                        bytes,
                        source,
                        declared_digest: None,
                    },
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let inputs = Inputs {
            target: Target {
                product_type: model.clone(),
                device_class: identity.device_class.clone(),
                product_version: report.product_version.clone(),
                product_build: report.product_build.clone(),
                variant: identity.variant.clone(),
                chip_id: parse_id(identity.ap_chip_id.as_deref())?,
                board_id: parse_id(identity.ap_board_id.as_deref())?,
            },
            kernel_collection: input(&kernel),
            sptm: input(&sptm),
            txm: input(&txm),
            device_tree: input(&device_tree),
            static_trust_cache: input(&trust_cache),
            sep_firmware: sep.as_ref().map(input),
            boot_manifest: boot_manifest.as_ref().map(input),
            cryptex1_manifest: cryptex1_manifest.as_ref().map(input),
            extra_trust_caches: cryptex_trust_caches.iter().map(input).collect(),
            ramdisk: ramdisk.as_ref().map(input),
            root_hash: root_hash.as_ref().map(|(volume, decoded)| RootHash {
                volume: *volume,
                im4p: decoded.as_ref().map(input),
            }),
            board_firmware: board_firmware
                .iter()
                .map(|(name, decoded)| (name.clone(), input(decoded)))
                .collect(),
        };
        let options = self.options(self.restore || self.recovery, inputs.dram_base()?)?;
        let bundle = boot_bundle::prepare(&inputs, &options)?;
        let provenance = serde_json::json!({
            "archive": {
                "path": ipsw.canonicalize()?.display().to_string(),
                "build_manifest_sha256": report.manifest_sha256,
            }
        });
        self.write(&bundle, provenance)?;
        Ok(())
    }

    /// The bundle options from the command line; `ramdisk_boot` picks the
    /// restore defaults for boot-args and the OS environment.
    fn options(&self, ramdisk_boot: bool, board_dram_base: Option<u64>) -> Result<Options> {
        let dram_base = self
            .dram_base
            .or(board_dram_base)
            .unwrap_or(Options::default().dram_base);
        Ok(Options {
            dram_base,
            dram_size: self.dram_size,
            phys_base: self.phys_base.unwrap_or(dram_base),
            load_offset: self.load_offset,
            boot_args: self.boot_args.clone().unwrap_or_else(|| {
                match ramdisk_boot {
                    true => RESTORE_BOOT_ARGS,
                    false => INSTALLED_BOOT_ARGS,
                }
                .into()
            }),
            osenvironment: self.osenvironment.clone().or_else(|| {
                match (self.restore, self.recovery) {
                    (true, _) => Some(RESTORE_ENVIRONMENT),
                    (false, true) => Some(RECOVERY_ENVIRONMENT),
                    (false, false) => None,
                }
                .map(Into::into)
            }),
            boot_cpu: self.boot_cpu.clone(),
            timebase_frequency: self.timebase_frequency,
            syscfg: self.syscfg.iter().cloned().collect(),
            mac_addresses: self.mac_addresses.iter().cloned().collect(),
            security: SecurityPolicy {
                mode: match self.security {
                    Security::Reduced => SecurityMode::Reduced,
                    Security::Permissive => SecurityMode::Permissive,
                },
                sip_bits: self.sip_bits,
                sepfw_load_at_boot: self.sepfw_load_at_boot,
            },
            overlay: self
                .dt_overlay
                .as_deref()
                .map(read_overlay)
                .transpose()?
                .unwrap_or_default(),
        })
    }

    /// Write the bundle files and `bundle.json`, with `provenance` naming
    /// where the inputs came from.
    fn write(&self, bundle: &boot_bundle::Bundle, provenance: serde_json::Value) -> Result<()> {
        std::fs::create_dir_all(&self.output)?;
        for (name, bytes) in &bundle.files {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.output.join(name))?
                .write_all(bytes)?;
        }
        let mut written = serde_json::to_value(&bundle.manifest)?;
        if let (Some(object), serde_json::Value::Object(extra)) =
            (written.as_object_mut(), provenance)
        {
            object.extend(extra);
        }
        stela_runtime::write_json(&self.output.join(MANIFEST_FILE), &written)?;
        let manifest = &bundle.manifest;
        eprintln!(
            "{} {} {}: {} regions to {:#x}; entry {} at {:#x}, x0 {:#x}; {}",
            manifest.target.product_type,
            manifest.target.product_build,
            manifest.target.variant,
            manifest.regions.len(),
            manifest.top_of_kernel_data,
            manifest.entry.image,
            manifest.entry.physical_address,
            manifest.entry_x0,
            self.output.join(MANIFEST_FILE).display()
        );
        Ok(())
    }
}
