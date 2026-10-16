//! Prepare the kernel boot bundle that the UEFI mount hands to the ARM kernel.
use crate::{args::parse_address, restore};
use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Subcommand};
use serde::Serialize;
use std::{fs::OpenOptions, io::Write, path::PathBuf};
use stela_loader::boot_bundle::{self, Input, Inputs, Manifest, Options, Source, Target};

const MANIFEST_FILE: &str = "bundle.json";
const KERNEL_LIMIT: u64 = 512 * 1024 * 1024;
const COMPONENT_LIMIT: u64 = 64 * 1024 * 1024;

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
    /// The restore identity variant; the installed-system identity by default.
    #[arg(long, default_value = "macOS Customer")]
    variant: String,
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
    #[arg(long, default_value = "-v")]
    boot_args: String,
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
        let identity = report
            .identities
            .iter()
            .find(|i| i.variant == self.variant)
            .with_context(|| {
                let variants: Vec<_> = report.identities.iter().map(|i| &i.variant).collect();
                format!(
                    "no {} identity {:?}; found {variants:?}",
                    self.model, self.variant
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
            Ok(Decoded { bytes, source })
        };
        let kernel = component("KernelCache", Some("krnl"), KERNEL_LIMIT)?;
        let sptm = component("Ap,SecurePageTableMonitor", Some("sptm"), COMPONENT_LIMIT)?;
        let txm = component("Ap,TrustedExecutionMonitor", Some("trxm"), COMPONENT_LIMIT)?;
        let device_tree = component("DeviceTree", Some("dtre"), COMPONENT_LIMIT)?;
        let trust_cache = component("StaticTrustCache", Some("trst"), COMPONENT_LIMIT)?;
        let sep = report
            .identities
            .iter()
            .any(|i| i.components.contains_key("SEP"))
            .then(|| component("SEP", None, COMPONENT_LIMIT))
            .transpose()?;
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
        };
        let options = Options {
            dram_base: self.dram_base,
            dram_size: self.dram_size,
            phys_base: self.phys_base.unwrap_or(self.dram_base),
            load_offset: self.load_offset,
            boot_args: self.boot_args,
            boot_cpu: self.boot_cpu,
            timebase_frequency: self.timebase_frequency,
            syscfg: self.syscfg.into_iter().collect(),
            mac_addresses: self.mac_addresses.into_iter().collect(),
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
