//! Prepare the kernel boot bundle that the UEFI mount hands to the ARM kernel.
use crate::{args::parse_address, restore};
use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Subcommand};
use serde::Serialize;
use std::{fs::OpenOptions, io::Write, path::PathBuf};
use stela_loader::boot_bundle::{
    self, Input, Inputs, Manifest, Options, OverlayProperty, Source, Target,
};
use stela_loader::boot_policy::{SecurityMode, SecurityPolicy};
use stela_loader::im4m;

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

/// The BuildManifest components, and their IM4P types, a boot mode loads.
struct Roles {
    kernel: &'static str,
    device_tree: &'static str,
    trust_cache: (&'static str, &'static str),
    sptm: &'static str,
    txm: &'static str,
    sep: &'static str,
    ramdisk: Option<(&'static str, &'static str)>,
}

const INSTALLED: Roles = Roles {
    kernel: "KernelCache",
    device_tree: "DeviceTree",
    trust_cache: ("StaticTrustCache", "trst"),
    sptm: "Ap,SecurePageTableMonitor",
    txm: "Ap,TrustedExecutionMonitor",
    sep: "SEP",
    ramdisk: None,
};

const RESTORE: Roles = Roles {
    kernel: "RestoreKernelCache",
    device_tree: "RestoreDeviceTree",
    trust_cache: ("RestoreTrustCache", "rtsc"),
    sptm: "Ap,RestoreSecurePageTableMonitor",
    txm: "Ap,RestoreTrustedExecutionMonitor",
    sep: "RestoreSEP",
    ramdisk: Some(("RestoreRamDisk", "rdsk")),
};

#[derive(Subcommand)]
pub(crate) enum BootCommand {
    /// Lay out a model's kernel collection, SPTM, TXM, DeviceTree and trust
    /// cache in guest physical memory for `stela.efi`.
    Prepare(Prepare),
}

#[derive(Args)]
pub(crate) struct Prepare {
    #[arg(long)]
    ipsw: PathBuf,
    /// The `Ap,ProductType`, such as Mac14,3.
    #[arg(long)]
    model: String,
    /// A new directory for the bundle.
    #[arg(long)]
    output: PathBuf,
    /// Boot the restore ramdisk with the identity's restore objects instead
    /// of the installed system.
    #[arg(long)]
    restore: bool,
    /// The restore identity variant: `macOS Customer` for the installed
    /// system, `Customer Erase Install (IPSW)` with `--restore`.
    #[arg(long)]
    variant: Option<String>,
    /// The `/osenvironments` child to apply; `darwinos-ramdisk-environment`
    /// with `--restore`.
    #[arg(long)]
    osenvironment: Option<String>,
    /// Guest DRAM base; Apple M1/M2 place DRAM at 0x800000000.
    #[arg(long, value_parser = parse_address, default_value = "0x800000000")]
    dram_base: u64,
    /// Guest DRAM size assumed until the mount patches it at boot.
    #[arg(long, value_parser = parse_address, default_value = "0x200000000")]
    dram_size: u64,
    /// Lowest address handed to the kernel; the DRAM base by default.
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
}

fn parse_keyed_bytes(value: &str) -> Result<(String, Vec<u8>), String> {
    let (key, bytes) = value.split_once('=').ok_or("expected KEY=HEX")?;
    if key.is_empty() {
        return Err("empty key".into());
    }
    let bytes = hex::decode(bytes.replace(':', "")).map_err(|error| error.to_string())?;
    Ok((key.to_owned(), bytes))
}

impl BootCommand {
    pub(crate) fn run(self) -> Result<()> {
        match self {
            Self::Prepare(command) => command.run(),
        }
    }
}

#[derive(Serialize)]
struct ArchiveIdentity {
    path: String,
    build_manifest_sha256: String,
}

#[derive(Serialize)]
struct Written<'a> {
    archive: ArchiveIdentity,
    #[serde(flatten)]
    bundle: &'a Manifest,
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
        let report = restore::archive::manifest(&self.ipsw, Some(&self.model), false)?;
        let (roles, default_variant) = match self.restore {
            true => (RESTORE, RESTORE_VARIANT),
            false => (INSTALLED, INSTALLED_VARIANT),
        };
        let variant = self.variant.as_deref().unwrap_or(default_variant);
        let identity = report
            .identities
            .iter()
            .find(|i| i.variant == variant)
            .with_context(|| {
                let variants: Vec<_> = report.identities.iter().map(|i| &i.variant).collect();
                format!(
                    "no {} identity {:?}; found {variants:?}",
                    self.model, variant
                )
            })?;
        let component = |name: &str, payload_type: Option<&str>, limit: u64| -> Result<Decoded> {
            // A component absent from the selected identity is taken from
            // another identity of the same model, and named with its variant.
            let (owner, entry) = std::iter::once(identity)
                .chain(report.identities.iter())
                .find_map(|i| i.components.get(name).map(|c| (i, c)))
                .with_context(|| format!("no {} identity lists {name}", self.model))?;
            let container = restore::archive::read_member(&self.ipsw, &entry.path, limit)?;
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
        let ramdisk = roles
            .ramdisk
            .map(|(name, payload_type)| component(name, Some(payload_type), RAMDISK_LIMIT))
            .transpose()?;
        let sep = report
            .identities
            .iter()
            .any(|i| i.components.contains_key(roles.sep))
            .then(|| component(roles.sep, None, COMPONENT_LIMIT))
            .transpose()?;
        let global_manifest = |cryptex1: bool| -> Result<Option<Decoded>> {
            let member = manifest_member(cryptex1, &identity.variant, &identity.device_class);
            if !restore::archive::has_member(&self.ipsw, &member)? {
                return Ok(None);
            }
            let bytes = restore::archive::read_member(&self.ipsw, &member, COMPONENT_LIMIT)?;
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
        let inputs = Inputs {
            target: Target {
                product_type: self.model.clone(),
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
        };
        let options = Options {
            dram_base: self.dram_base,
            dram_size: self.dram_size,
            phys_base: self.phys_base.unwrap_or(self.dram_base),
            load_offset: self.load_offset,
            boot_args: self.boot_args.unwrap_or_else(|| {
                match self.restore {
                    true => RESTORE_BOOT_ARGS,
                    false => INSTALLED_BOOT_ARGS,
                }
                .into()
            }),
            osenvironment: self
                .osenvironment
                .or_else(|| self.restore.then(|| RESTORE_ENVIRONMENT.into())),
            boot_cpu: self.boot_cpu,
            timebase_frequency: self.timebase_frequency,
            syscfg: self.syscfg.into_iter().collect(),
            mac_addresses: self.mac_addresses.into_iter().collect(),
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
        };
        let bundle = boot_bundle::prepare(&inputs, &options)?;
        std::fs::create_dir_all(&self.output)?;
        for (name, bytes) in &bundle.files {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.output.join(name))?
                .write_all(bytes)?;
        }
        let written = Written {
            archive: ArchiveIdentity {
                path: self.ipsw.canonicalize()?.display().to_string(),
                build_manifest_sha256: report.manifest_sha256.clone(),
            },
            bundle: &bundle.manifest,
        };
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
