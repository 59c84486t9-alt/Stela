//! Prepare the kernel boot bundle that the UEFI mount hands to the ARM kernel.
use crate::{
    args::parse_address,
    restore::{self, components},
};
use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Subcommand};
use std::{fs::OpenOptions, io::Write, path::PathBuf};
use stela_loader::boot_bundle::{
    self, Input, Inputs, Options, OverlayProperty, RootHash, Source, Target,
};
use stela_loader::boot_policy::{OsEnvironment, SealedVolume, SecurityMode, SecurityPolicy};
use stela_loader::im4m;
use stela_loader::root_selection::Root;
use stela_runtime::{apfs::btree::Seal, payload::Purpose};

mod board_firmware;
mod disk;
mod recovery_volume;

const MANIFEST_FILE: &str = "bundle.json";
const KERNEL_LIMIT: u64 = 512 * 1024 * 1024;
const COMPONENT_LIMIT: u64 = 64 * 1024 * 1024;
const RAMDISK_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
/// The recoveryOS volume holds the whole BaseSystem UDIF image (2.3 GB for
/// 26A434) and its APFS metadata.
const RECOVERY_VOLUME_LIMIT: u64 = 3 * 1024 * 1024 * 1024;
/// The OS environment of a restore ramdisk: its `/osenvironments` child
/// turns off the SEP firmware load and protected data access and selects
/// ephemeral storage.
const RESTORE_ENVIRONMENT: OsEnvironment = OsEnvironment::DarwinosRamdisk;
/// The console boot-args when `--boot-args` gives none.
const DEFAULT_BOOT_ARGS: &str = "-v";
/// The boot-args a restore host has iBoot pass to the restore ramdisk
/// (idevicerestore `restore.c`): the ramdisk root, NAND reformat permission,
/// the progress UI and restore mode. `-restore` is read by the kernel and
/// about twenty kexts; IOUSBDeviceConfigurator, for one, leaves the USB
/// device controllers to restored only in restore mode.
const RESTORE_MODE_ARGS: &[&str] = &[
    "rd=md0",
    "nand-enable-reformat=0x1",
    "-progress",
    "-restore",
];
/// recoveryOS first roots from the ramdisk, the volume that holds BaseSystem
/// (`recovery_volume`), then from BaseSystem as a disk image.
const RECOVERY_MODE_ARGS: &[&str] = &["rd=md0", recovery_volume::IMAGE_BOOT_ARG];
/// The environment J473 iBoot enters for recoveryOS (its table 0x170838).
/// The kernel's APFS reads it (`apfs_is_booted_for_recovery`, which accepts
/// only `recoveryos` and `diagnostics`). The DeviceTree's `recovery` child is
/// one no J473 iBoot caller passes, and its data-volume entry needs a
/// `/filesystems` node this DeviceTree lacks.
const RECOVERY_ENVIRONMENT: OsEnvironment = OsEnvironment::Recoveryos;
const BASE_SYSTEM: &str = "BaseSystem";
/// The BaseSystem image's APFS partition, whose seal the forwarded root hash
/// must name.
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
    /// Whether the identity's global manifest admits every boot object of
    /// the mode. The restore objects sit outside it: that manifest is the
    /// installed system's root ticket, which the restore host answers with.
    manifest_admits_all: bool,
}

#[derive(Clone, Copy)]
enum Ramdisk {
    /// An IM4P component and its type.
    Image4(&'static str, &'static str),
    /// The AEA-encrypted BaseSystem UDIF image, decrypted, on the volume
    /// recoveryOS first roots from.
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
    manifest_admits_all: true,
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
    manifest_admits_all: false,
};

/// recoveryOS: the installed system's kernel, monitors and DeviceTree, the
/// BaseSystem trust cache, and the volume holding the BaseSystem image as the
/// ramdisk root.
const RECOVERY: Roles = Roles {
    kernel: "KernelCache",
    device_tree: "DeviceTree",
    trust_cache: ("Ap,BaseSystemTrustCache", "bstc"),
    sptm: "Ap,SecurePageTableMonitor",
    txm: "Ap,TrustedExecutionMonitor",
    sep: "SEP",
    ramdisk: Some(Ramdisk::BaseSystem),
    root_hash: Some(("BaseSystemVolume", SealedVolume::BaseSystem)),
    manifest_admits_all: true,
};

#[derive(Subcommand)]
pub(crate) enum BootCommand {
    /// Lay out a model's kernel collection, SPTM, TXM, DeviceTree and trust
    /// cache in guest physical memory for `stela.efi`.
    Prepare(Box<Prepare>),
    /// Check a prepared bundle's DeviceTree against the engine's board
    /// models (`machine::soc::board`), as `stela.efi` does before entry, and
    /// print the board the engine would run or the reason it refuses.
    Check(Check),
}

#[derive(Args)]
pub(crate) struct Check {
    /// A directory `boot prepare` wrote.
    bundle: PathBuf,
}

impl Check {
    fn run(self) -> Result<()> {
        let tree = std::fs::read(
            self.bundle
                .join(stela_loader::boot_bundle::DEVICE_TREE_FILE),
        )
        .with_context(|| format!("{} has no DeviceTree", self.bundle.display()))?;
        let board = stela_runtime::machine::soc::board(&tree)
            .map_err(|reason| anyhow::anyhow!("the engine refuses this board: {reason}"))?;
        let hex = |value: u64| format!("{value:#x}");
        let report = serde_json::json!({
            "chip": board.cpus.chip.name(),
            "processors": board.cpus.processors.iter().map(|pe| serde_json::json!({
                "midr": hex(pe.midr),
                "mpidr": hex(pe.mpidr),
                "clock_hz": pe.clock,
                "caches": pe.caches.is_some(),
            })).collect::<Vec<_>>(),
            "aic": { "physical": hex(board.aic.physical), "inputs": board.aic.inputs },
            "lockdown": board.lockdown.iter().map(|block| serde_json::json!({
                "block": block.name,
                "physical": hex(block.physical),
                "control": hex(block.control),
            })).collect::<Vec<_>>(),
            "cpu_start": board.cpu_start.map(|(physical, clusters)| serde_json::json!({
                "physical": hex(physical),
                "clusters": clusters,
            })),
            "power_states": board.power_states.as_ref().map(|states| states.registers.len()),
            "clusters": board.clusters.len(),
            "memory_cache": board.memory_cache.is_some(),
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
        Ok(())
    }
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
    /// The NVRAM `boot-volume` to boot, `TYPE:PARTITION:GROUP`, choosing the
    /// disk's container and volume group as LLB does.
    #[arg(long, requires = "disk")]
    boot_volume: Option<String>,
    /// Boot the macOS update staged on the disk's Update volume
    /// (`stela_loader::upgrade`) instead of its installed system.
    #[arg(long, requires = "disk", conflicts_with_all = ["boot_hash"])]
    upgrade: bool,
    /// A new directory for the bundle.
    #[arg(long)]
    output: PathBuf,
    /// Boot the restore ramdisk with the identity's restore objects instead
    /// of the installed system.
    #[arg(long, conflicts_with = "recovery")]
    restore: bool,
    /// Boot recoveryOS with the installed system's kernel: the ramdisk is a
    /// volume holding the BaseSystem image, which the kernel then roots
    /// from. Needs `/usr/bin/aea` to decrypt BaseSystem and
    /// `/usr/bin/hdiutil` to make the volume.
    #[arg(long)]
    recovery: bool,
    /// The public AEA key (PKCS8 PEM) for BaseSystem; fetched from Apple's
    /// key server when omitted.
    #[arg(long, requires = "recovery")]
    aea_key: Option<PathBuf>,
    /// The restore identity by its variant, such as `Customer Upgrade
    /// Install (IPSW)`; by default the model's erase restore identity with
    /// `--restore`, and its installed system's otherwise.
    #[arg(long)]
    variant: Option<String>,
    /// The OS environment iBoot enters (`/chosen osenvironment` and its
    /// `/osenvironments` child): `darwinos-ramdisk` with `--restore`,
    /// `recoveryos` with `--recovery`, none (macOS) otherwise.
    #[arg(long, value_parser = |name: &str| OsEnvironment::parse(name).map_err(|e| e.to_string()))]
    osenvironment: Option<OsEnvironment>,
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
    /// The kernel command line, `-v` by default. `--restore` and
    /// `--recovery` add the arguments their boot mode needs.
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
    /// The machine's ECID, as hex: a nonzero per-machine value the install
    /// tooling generates and keeps (`/chosen unique-chip-id`, `die-id`,
    /// `unique-device-id`). Without it those rows stay unresolved.
    #[arg(long, value_parser = parse_ecid)]
    ecid: Option<u64>,
    /// A firmware image the board's own devices run, kept under its guest
    /// file name (such as `USB-C_HPM,47.bin`); repeat for each image. These
    /// replace the images the DeviceTree's board names, which are otherwise
    /// taken from the IPSW's restore ramdisk.
    #[arg(long, conflicts_with = "disk")]
    board_firmware: Vec<PathBuf>,
}

fn parse_ecid(value: &str) -> Result<u64, String> {
    let digits = value.strip_prefix("0x").unwrap_or(value);
    match u64::from_str_radix(digits, 16) {
        Ok(0) => Err("an ECID is nonzero".into()),
        Ok(ecid) => Ok(ecid),
        Err(error) => Err(error.to_string()),
    }
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
            Self::Prepare(command) => (*command).run(),
            Self::Check(command) => command.run(),
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

/// The identity's global manifests sit at `Firmware/Manifests/restore/[cryptex1/]VARIANT/apticket.CLASS.im4m`,
/// with `Info.MacOSVariant` as VARIANT when the identity has one, as the
/// restore host's RootTicket answer chooses it: restored's `update_ticket`
/// compares that ticket's SHA-384 with `/chosen/boot-manifest-hash`.
fn manifest_member(cryptex1: bool, variant: &str, device_class: &str) -> String {
    let scope = if cryptex1 { "cryptex1/" } else { "" };
    format!("Firmware/Manifests/restore/{scope}{variant}/apticket.{device_class}.im4m")
}

/// The boot objects the manifest does not admit, by component. A manifest
/// admits an object when one of its entries' `DGST` is the object's
/// BuildManifest digest. When `admits_all`, an object it does not admit
/// fails, naming the entry of the object's IM4P type when there is one.
fn check_digests(
    manifest: &im4m::Manifest,
    decoded: &[&Decoded],
    admits_all: bool,
) -> Result<Vec<String>> {
    let digest = |object: &im4m::Object| {
        object
            .properties
            .iter()
            .find(|p| p.name == "DGST")
            .map(|p| p.value.clone())
    };
    let mut outside = vec![];
    for item in decoded {
        let Some(declared) = &item.declared_digest else {
            continue;
        };
        let declared = im4m::Value::Data(hex::decode(declared)?);
        if manifest
            .objects
            .iter()
            .any(|object| digest(object).as_ref() == Some(&declared))
        {
            continue;
        }
        ensure!(
            !admits_all,
            "{}",
            match manifest.object(&item.source.payload_type) {
                Some(object) => format!(
                    "manifest {} digest differs from the BuildManifest {}",
                    object.tag, item.source.component
                ),
                None => format!("the manifest does not admit {}", item.source.component),
            }
        );
        outside.push(item.source.component.clone());
    }
    Ok(outside)
}

/// The volume recoveryOS first roots from, and the seal of BaseSystem's file
/// system. The AEA member is copied out and decrypted with the public key.
/// Its UDIF image's `Apple_APFS` partition gives the seal, and the image itself
/// goes unchanged onto the volume (`recovery_volume`).
fn base_system(
    ipsw: &std::path::Path,
    member: &str,
    key: Option<&std::path::Path>,
    declared_digest: Option<String>,
) -> Result<(Decoded, Seal)> {
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
    std::fs::remove_file(&encrypted)?;
    let seal = recovery_volume::base_system_seal(restore::udif::partition(
        &image,
        BASE_SYSTEM_PARTITION,
        RAMDISK_LIMIT,
    )?)?;
    let (_, image_sha256) = restore::payload::file_sha256(&image)?;
    let bytes = recovery_volume::build(&image, work.path(), RECOVERY_VOLUME_LIMIT)?;
    let source = Source {
        component: BASE_SYSTEM.into(),
        member: member.into(),
        container_sha256,
        payload_type: "apfs".into(),
        description: format!(
            "unsealed APFS volume holding the decrypted UDIF image (SHA-256 {image_sha256}) at /{}",
            recovery_volume::IMAGE_PATH
        ),
        decoded_bytes: bytes.len(),
        decoded_sha256: stela_runtime::sha256(&bytes),
    };
    let volume = Decoded {
        source,
        bytes,
        declared_digest,
    };
    Ok((volume, seal))
}

fn parse_id(value: Option<&str>) -> Result<Option<u32>> {
    value
        .map(|v| {
            u32::from_str_radix(v.trim_start_matches("0x").trim_start_matches("0X"), 16)
                .with_context(|| format!("bad restore identity value {v}"))
        })
        .transpose()
}

/// `console` followed by each of the boot mode's arguments whose name it does
/// not already give, so an explicit `name=value` keeps its value.
pub(super) fn boot_args(console: &str, mode: &[&str]) -> String {
    let name = |argument: &str| argument.split('=').next().unwrap_or(argument).to_owned();
    let given: Vec<String> = console.split_whitespace().map(name).collect();
    let mut line = console.trim().to_owned();
    for argument in mode.iter().filter(|a| !given.contains(&name(a))) {
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(argument);
    }
    line
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
        // The profile's identities and components, as setup chooses them.
        let profile = components::Profile::of(&model)?;
        let report = restore::archive::manifest(&ipsw, None, false)?;
        let (roles, purpose) = match (self.restore, self.recovery) {
            (true, _) => (RESTORE, Purpose::Erase),
            (false, true) => (RECOVERY, Purpose::Installed),
            (false, false) => (INSTALLED, Purpose::Installed),
        };
        let identity = match self.variant.as_deref() {
            Some(variant) => components::variant(&report, &profile, variant)?,
            None => components::identity(&report, &profile, purpose)?,
        };
        let owned = components::identities(&report, &profile);
        let component = |name: &str, payload_type: Option<&str>, limit: u64| -> Result<Decoded> {
            // A component absent from the selected identity is taken from
            // another identity of the same profile, and named with its
            // variant.
            let (owner, entry) = components::component(&report, &profile, identity, name)?;
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
        let (ramdisk, base_system_seal) = match roles.ramdisk {
            None => (None, None),
            Some(Ramdisk::Image4(name, payload_type)) => (
                Some(component(name, Some(payload_type), RAMDISK_LIMIT)?),
                None,
            ),
            Some(Ramdisk::BaseSystem) => {
                let entry = identity
                    .components
                    .get(BASE_SYSTEM)
                    .with_context(|| format!("{} lists no {BASE_SYSTEM}", identity.variant))?;
                let (volume, seal) = base_system(
                    &ipsw,
                    &entry.path,
                    self.aea_key.as_deref(),
                    entry.declared_digest_hex.clone(),
                )?;
                (Some(volume), Some(seal))
            }
        };
        // The root hash stays an IM4P: iBoot forwards it with its manifest.
        let root_hash = match roles.root_hash {
            None => None,
            Some((name, volume)) => Some((
                volume,
                owned
                    .iter()
                    .any(|i| i.components.contains_key(name))
                    .then(|| component(name, None, COMPONENT_LIMIT))
                    .transpose()?,
            )),
        };
        if let (Some(seal), Some((_, Some(root_hash)))) = (&base_system_seal, &root_hash) {
            recovery_volume::check_root_hash(seal, &root_hash.bytes)?;
        }
        let sep = owned
            .iter()
            .any(|i| i.components.contains_key(roles.sep))
            .then(|| component(roles.sep, None, COMPONENT_LIMIT))
            .transpose()?;
        let global_manifest = |cryptex1: bool| -> Result<Option<Decoded>> {
            let variant = identity.macos_variant.as_ref().unwrap_or(&identity.variant);
            let member = manifest_member(cryptex1, variant, &identity.device_class);
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
        let mut outside_manifest = vec![];
        if let Some(manifest) = &boot_manifest {
            outside_manifest = check_digests(
                &im4m::parse(&manifest.bytes)?,
                &[&kernel, &sptm, &txm, &device_tree, &trust_cache],
                roles.manifest_admits_all,
            )?;
        }
        if let Some(manifest) = &cryptex1_manifest {
            let decoded: Vec<_> = cryptex_trust_caches.iter().collect();
            check_digests(&im4m::parse(&manifest.bytes)?, &decoded, true)?;
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
        // Set below when the images come from the restore ramdisk.
        let sourced: Vec<(String, Decoded)>;
        let ramdisk_component: Decoded;
        let mut inputs = Inputs {
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
        let options = self.options(inputs.dram_base()?)?;
        let mut bundle = boot_bundle::prepare(&inputs, &options)?;
        let mut unresolved = vec![];
        if self.board_firmware.is_empty() {
            // The board the bundle's DeviceTree describes names its images;
            // the same IPSW's restore ramdisk holds them.
            match board_firmware::needed(&bundle) {
                Ok(names) if names.is_empty() => {}
                Ok(names) => {
                    let ramdisk = match &ramdisk {
                        Some(ramdisk)
                            if ramdisk.source.component == components::RESTORE_RAMDISK =>
                        {
                            ramdisk
                        }
                        _ => {
                            ramdisk_component = component(
                                components::RESTORE_RAMDISK,
                                Some("rdsk"),
                                RAMDISK_LIMIT,
                            )?;
                            &ramdisk_component
                        }
                    };
                    sourced =
                        board_firmware::from_ramdisk(ramdisk, board_firmware::DIRECTORY, &names)?;
                    inputs.board_firmware = sourced
                        .iter()
                        .map(|(name, decoded)| (name.clone(), input(decoded)))
                        .collect();
                    bundle = boot_bundle::prepare(&inputs, &options)?;
                }
                Err(error) => unresolved.push(format!(
                    "board firmware: the DeviceTree is not a board the engine models ({error})"
                )),
            }
        }
        bundle.manifest.unresolved.extend(unresolved);
        bundle
            .manifest
            .unresolved
            .extend(outside_manifest.iter().map(|component| {
                format!("{component}: outside the boot manifest, which is the installed system's")
            }));
        let provenance = serde_json::json!({
            "archive": {
                "path": ipsw.canonicalize()?.display().to_string(),
                "build_manifest_sha256": report.manifest_sha256,
            }
        });
        self.write(&bundle, provenance)?;
        Ok(())
    }

    /// The bundle options from the command line, with the boot-args and OS
    /// environment of the selected boot mode.
    fn options(&self, board_dram_base: Option<u64>) -> Result<Options> {
        let dram_base = self
            .dram_base
            .or(board_dram_base)
            .unwrap_or(Options::default().dram_base);
        Ok(Options {
            dram_base,
            dram_size: self.dram_size,
            phys_base: self.phys_base.unwrap_or(dram_base),
            load_offset: self.load_offset,
            boot_args: boot_args(
                self.boot_args.as_deref().unwrap_or(DEFAULT_BOOT_ARGS),
                match (self.restore, self.recovery) {
                    (true, _) => RESTORE_MODE_ARGS,
                    (false, true) => RECOVERY_MODE_ARGS,
                    (false, false) => &[],
                },
            ),
            osenvironment: self.osenvironment.or(match (self.restore, self.recovery) {
                (true, _) => Some(RESTORE_ENVIRONMENT),
                (false, true) => Some(RECOVERY_ENVIRONMENT),
                (false, false) => None,
            }),
            // A ramdisk roots from itself; an installed system's root is
            // named from its disk (`stela_loader::installed`).
            root: (self.restore || self.recovery).then_some(Root::Ramdisk),
            ecid: self.ecid,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ecid_is_nonzero_hex() {
        assert_eq!(parse_ecid("0x1a2b3c4d5e6f7081"), Ok(0x1a2b_3c4d_5e6f_7081));
        assert_eq!(parse_ecid("ABCDEF"), Ok(0xab_cdef));
        assert!(parse_ecid("0").is_err());
        assert!(parse_ecid("0x").is_err());
        assert!(parse_ecid("12345678901234567").is_err());
    }

    #[test]
    fn a_manifest_admits_objects_by_digest_and_restore_objects_may_sit_outside() {
        let object = |tag: &str, digest: u8| im4m::Object {
            tag: tag.into(),
            properties: vec![im4m::Property {
                name: "DGST".into(),
                value: im4m::Value::Data(vec![digest; 48]),
            }],
        };
        let manifest = im4m::Manifest {
            version: 0,
            properties: vec![],
            objects: vec![object("krnl", 1), object("rdtr", 2)],
            sha384: String::new(),
            digest: [0; 48],
            signature_validated: false,
        };
        let decoded = |component: &str, payload_type: &str, digest: u8| Decoded {
            bytes: vec![],
            source: Source {
                component: component.into(),
                member: String::new(),
                container_sha256: String::new(),
                payload_type: payload_type.into(),
                description: String::new(),
                decoded_bytes: 0,
                decoded_sha256: String::new(),
            },
            declared_digest: Some(hex::encode([digest; 48])),
        };
        let kernel = decoded("KernelCache", "krnl", 1);
        let restore_kernel = decoded("RestoreKernelCache", "krnl", 3);
        let restore_tree = decoded("RestoreDeviceTree", "dtre", 2);
        assert!(
            check_digests(&manifest, &[&kernel], true)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            check_digests(&manifest, &[&restore_kernel, &restore_tree], false).unwrap(),
            ["RestoreKernelCache"]
        );
        let error = check_digests(&manifest, &[&restore_kernel], true).unwrap_err();
        assert!(error.to_string().contains("manifest krnl digest differs"));
    }

    #[test]
    fn boot_modes_add_their_arguments_after_the_console_arguments() {
        assert_eq!(boot_args(DEFAULT_BOOT_ARGS, &[]), "-v");
        assert_eq!(
            boot_args(DEFAULT_BOOT_ARGS, RESTORE_MODE_ARGS),
            "-v rd=md0 nand-enable-reformat=0x1 -progress -restore"
        );
        assert_eq!(
            boot_args("-v debug=0x8", RECOVERY_MODE_ARGS),
            format!("-v debug=0x8 rd=md0 {}", recovery_volume::IMAGE_BOOT_ARG)
        );
    }

    #[test]
    fn an_explicit_argument_keeps_its_value() {
        assert_eq!(
            boot_args("serial=3 rd=md1 -restore", RESTORE_MODE_ARGS),
            "serial=3 rd=md1 -restore nand-enable-reformat=0x1 -progress"
        );
        assert_eq!(
            boot_args("", RECOVERY_MODE_ARGS),
            format!("rd=md0 {}", recovery_volume::IMAGE_BOOT_ARG)
        );
    }
}
