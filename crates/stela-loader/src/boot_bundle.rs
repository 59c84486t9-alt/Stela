//! The kernel boot bundle: Apple's boot images laid out in guest physical
//! memory, with every value a loader computes already applied, so the UEFI
//! mount only copies regions and patches a few fixed-size fields.
//!
//! The region order, names and auxiliary `/chosen/memory-map` entries follow
//! Asahi m1n1 `proxyclient/m1n1/hv/__init__.py` `load_macos_sptm` (commit
//! `c6a89b908ac4bf1f7b495f20531f3ea029148adb`), which boots unchanged SPTM
//! kernels: the monitors and the kernel collection are split by segment and
//! placed in the order SPTM requires, and execution starts at SPTM's entry
//! with x0 holding the `boot_args` address. `boot_args` values follow m1n1
//! `_write_boot_args`. The format is specified in
//! `docs/design/runtime.md#kernel-boot-bundle`.
use crate::aic;
use crate::apple_device_tree::{DeviceTree, Placeholder};
use crate::boot_args::{self, BootArgs, Video};
use crate::boot_manifests;
use crate::boot_policy::{self, Decision, SealedVolume, SecurityPolicy};
use crate::carveouts::{self, Placed};
use crate::darts;
use crate::devices;
use crate::dvfs;
use crate::gpu_dvfs;
use crate::handoff;
use crate::im4m::{self, Value};
use crate::kernel_collection::{KernelCollection, PAGE_BYTES};
use crate::lock_regs::{self, Programmed};
use crate::nvram;
use crate::root_selection;
use crate::soc_variant;
use crate::trust_cache;
use alloc::collections::BTreeMap;
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use stela_runtime::machine::{ctrr, identification, soc, tag_storage};
use stela_runtime::sha256;

/// The format `stela.efi` reads (`stela_runtime::boot_bundle`).
/// Schema3 requires the boot reader's selected target/source/original ADT
/// provenance intake. Schema2 never qualified those previously ignored fields.
pub const SCHEMA_VERSION: u32 = 3;
/// The revision of what [`prepare`] writes within its schema: bump it in the
/// commit that changes the content of a prepared bundle (a DeviceTree
/// property, a region, a patch, a boot argument) without changing its
/// format, and name the change here. `stela setup --update-stela` prepares a
/// setup's bundles again when theirs are of another revision. Revision 0:
/// the bundles of every loader before revisions were recorded; a
/// `bundle.json` without `revision` is one. Revision 1: `/pram` `reg` and
/// `/chosen` `embedded-panic-log-size` give XNU its panic buffer
/// (`carveouts`). Revision 2: retain the original boot IM4M in the
/// read-only boot run and publish its object range and secure hash.
/// Revision 3: publish the explicit previous-stage boot command in `/chosen`
/// and `/chosen/handoff`, independently of the OS environment.
/// Revision 4: restrict name-matched peripherals with unavailable required
/// platform-function providers through `AAPL,ignore`.
/// Revision 5: keep retained manifests before SPTM's contiguous image run
/// and validate the complete image-adjacency contract before output.
/// Revision 6: close required service dependencies for AMFM-managed WLAN.
/// Revision 7: retire unavailable physical display service identities.
/// Revision 8: preserve qualified native legacy DART families and their
/// mapper/client dependencies with generation-aware admission and mounting.
/// Revision 9: reserve and publish T6000's source-qualified ordinary fixed
/// carveouts, including the four SGX bootstrap ranges.
/// Revision 10: publish independently numbered ECPU/PCPU domain tables;
/// validate the complete carveout reservation against supplied guest DRAM.
/// Revision 11: publish original T6000 AMCC and IOA lockdown maps.
/// Revision 12: retain the qualified T6000 AP GPIO/SPI chip-select owner;
/// auxiliary GPIO wake/restoration ownership remains unqualified.
/// Revision 13: bind selected external-pipe framebuffer geometry to the
/// actual GOP framebuffer at load. Schema 2 adds these required named fields.
/// Revision 14: retain the unchanged input ADT beside its prepared output so
/// runtime resource qualification can compare both complete source graphs.
/// Schema3 consumes this provenance at the reader; revision14 is unchanged.
/// Revision 15: on the M4 and later, place `CL4-dummypage` and state the
/// core lock registers iBoot leaves (`core_locks`, which `stela.efi` reads
/// when present).
/// Revision 16: on the chips with memory tagging, state TAG_OFFSET_EL2 in
/// `core_locks`.
/// Revision 17: give a CPU node whose template carries per-variant L2 sizes
/// its SoC's own `l2-cache-size` (J700AP's P cores).
/// Revision 18: reserve and publish every SoC's ordinary fixed carveouts from
/// its iBoot table, and name each table's special-attribute carveouts.
/// Revision 19: publish every SoC's iBoot AMCC and IOA lock-register maps,
/// into the template's nodes only.
/// Revision 20: select the T6050 variant the board's fuses give, merge its
/// template overlays, keep its dies' CPUs and size its lock maps by it.
/// Revision 21: publish `/arm-io` `die-count` on every SoC whose iBoot
/// writes it, with that iBoot's value.
/// Revision 22: truncate oversized syscfg fill-in values to the recipe's
/// requested length, as iBoot does, while zero-padding shorter values.
/// Revision 23: retire unused SPMI bus compatibles after target and
/// platform-function admission, preserving their original metadata.
pub const REVISION: u32 = 23;
/// m1n1 `_write_boot_args`: the physical aperture base XNU expects, offset
/// by `phys_base` modulo 32 MiB.
const VIRT_BASE: u64 = 0xfffffe0010000000;
const VIRT_BASE_ALIGNMENT: u64 = 32 << 20;
/// m1n1 reserves 16 KiB for `boot_args`.
const BOOT_ARGS_REGION_BYTES: u64 = 0x4000;
const MEMORY_MAP: &str = "/chosen/memory-map";
const RESERVED_ENTRY_PREFIX: &str = "MemoryMapReserved-";
/// iBoot fill-in recipe sources: `macaddr/NAME`, `syscfg/KEY[/LEN]`,
/// `syscfg-mismatch/KEY[/LEN]`, `zeroes/LEN` and `hex/BYTES[/LEN]`, tried in
/// order within a comma-separated recipe (26A434 `iBoot.j473` resolver
/// 0xd41cc..0xd42bc, names at 0x1cce79; its `string/` source no template
/// uses).
const MACADDR_RECIPE: &str = "macaddr/";
const SYSCFG_RECIPE: &str = "syscfg/";
/// The same key read from the syscfg keybag providers instead of the syscfg
/// store (`iBoot.j473` 0xd68e4 with its mismatch flag set calls 0x10991c,
/// which asks each provider in turn, instead of 0x1096bc). No keybag provider
/// is modelled, so the source yields nothing.
const SYSCFG_MISMATCH_RECIPE: &str = "syscfg-mismatch/";
const ZERO_FILL_RECIPE: &str = "zeroes/";
/// Literal bytes as hex digits, zero-extended to LEN when given
/// (`iBoot.j473` 0xd442c..0xd4570; an odd digit count or a LEN below the
/// byte count panics, 0xd46ec and 0xd46e0).
const HEX_RECIPE: &str = "hex/";
const MAC_ADDRESS_BYTES: usize = 6;
/// Clock properties XNU `pexpert/arm/pe_identify_machine.c` reads from the
/// running CPU node; absent ones fall back to its defaults.
const CPU_FREQUENCY_PROPERTIES: [&str; 3] = [
    "timebase-frequency",
    "fixed-frequency",
    "peripheral-frequency",
];
const MEMORY_MAP_ENTRY_BYTES: usize = 16;
const HIBERNATION_KEY_BYTES: usize = 0x30;

/// One Apple input, kept with the identity of the restore member it came from.
#[derive(Debug, Clone, Serialize)]
pub struct Source {
    pub component: String,
    pub member: String,
    pub container_sha256: String,
    pub payload_type: String,
    pub description: String,
    pub decoded_bytes: usize,
    pub decoded_sha256: String,
}

pub struct Input<'a> {
    pub bytes: &'a [u8],
    pub source: Source,
}

/// Board facts taken from the selected restore identity.
#[derive(Debug, Clone, Serialize)]
pub struct Target {
    pub product_type: String,
    pub device_class: String,
    pub product_version: String,
    pub product_build: String,
    pub variant: String,
    pub chip_id: Option<u32>,
    pub board_id: Option<u32>,
}

pub struct Inputs<'a> {
    pub target: Target,
    pub kernel_collection: Input<'a>,
    pub sptm: Input<'a>,
    pub txm: Input<'a>,
    pub device_tree: Input<'a>,
    pub static_trust_cache: Input<'a>,
    /// Copied unchanged: SEP firmware stays an encrypted IM4P.
    pub sep_firmware: Option<Input<'a>>,
    /// The identity's global (non-personalized) IM4M for the boot objects.
    pub boot_manifest: Option<Input<'a>>,
    /// The identity's global Cryptex1 IM4M.
    pub cryptex1_manifest: Option<Input<'a>>,
    /// Trust cache modules placed after the static one in `TrustCache`.
    pub extra_trust_caches: Vec<Input<'a>>,
    /// A ramdisk, placed as the `RAMDisk` region: a restore ramdisk the
    /// kernel roots from as `md0`, or the disk image of a
    /// [`root_selection::Root::RamImage`] root.
    pub ramdisk: Option<Input<'a>>,
    /// The sealed volume the boot roots from, and its root-hash `IM4P` when
    /// one is available; `None` when it roots from no sealed volume.
    pub root_hash: Option<RootHash<'a>>,
    /// Firmware images the board's own devices run, copied unchanged as
    /// bundle files named by their guest file names (such as
    /// `USB-C_HPM,47.bin`); device models read their identity from them.
    pub board_firmware: Vec<(String, Input<'a>)>,
}

impl Inputs<'_> {
    /// The guest DRAM base of the target board, from its DeviceTree or its
    /// SoC (`soc::board_dram_base`); `None` when the target names no chip.
    pub fn dram_base(&self) -> Result<Option<u64>> {
        self.target
            .chip_id
            .map(|chip_id| {
                stela_runtime::machine::soc::board_dram_base(self.device_tree.bytes, chip_id)
                    .map_err(anyhow::Error::msg)
            })
            .transpose()
    }
}

/// A sealed root volume and its root-hash `IM4P`.
pub struct RootHash<'a> {
    pub volume: SealedVolume,
    pub im4p: Option<Input<'a>>,
}

/// One DeviceTree value supplied from outside the restore image, such as a
/// device model's register map; nodes along `path` are created as needed.
#[derive(Debug, Clone, Serialize)]
pub struct OverlayProperty {
    pub path: String,
    pub property: String,
    #[serde(serialize_with = "hex_bytes")]
    pub value: Vec<u8>,
}

fn hex_bytes<S: serde::Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&hex::encode(bytes))
}

#[derive(Debug, Clone, Serialize)]
pub struct Options {
    pub dram_base: u64,
    pub dram_size: u64,
    /// Lowest physical address handed to the kernel (`boot_args.physBase`);
    /// a bundle raises it past iBoot's carveouts (`carveouts`).
    pub phys_base: u64,
    /// First region's distance above `phys_base`.
    pub load_offset: u64,
    pub boot_args: String,
    /// The DeviceTree `/cpus` child marked `running` for the boot CPU.
    pub boot_cpu: String,
    /// The generic timer rate (`CNTFRQ_EL0`) the machine presents.
    pub timebase_frequency: u64,
    /// Board configuration values by syscfg key, such as `SrNm` or `WMac`.
    pub syscfg: BTreeMap<String, Vec<u8>>,
    /// MAC addresses by provider name, such as `wifiaddr` or `ethaddr`.
    pub mac_addresses: BTreeMap<String, Vec<u8>>,
    pub security: SecurityPolicy,
    /// The OS environment iBoot enters, such as `darwinos-ramdisk` for a
    /// restore ramdisk; `None` is macOS.
    pub osenvironment: Option<boot_policy::OsEnvironment>,
    /// The actual previous-stage entry origin; independent of the OS
    /// environment. `None` leaves the boot-command handoff unresolved.
    pub boot_command: Option<handoff::BootCommand>,
    /// The volume the kernel roots from (`/chosen apfs-preboot-uuid`,
    /// `boot-uuid`, `associated-volume-group`, `boot-objects-path`); `None`
    /// keeps the template's values.
    pub root: Option<root_selection::Root>,
    /// The machine's ECID, nonzero and unique per machine, for `/chosen`
    /// `unique-chip-id`, `die-id` and `unique-device-id`; `None` keeps the
    /// template's zeros and lists the rows as unresolved.
    pub ecid: Option<u64>,
    /// Applied after every other DeviceTree change.
    pub overlay: Vec<OverlayProperty>,
}

/// The defaults of `stela boot prepare` for an installed system: 8 GiB of
/// DRAM at 0x8_0000_0000, verbose boot, `cpu0` booting with a 24 MHz
/// generic timer, and Reduced Security with SIP enabled.
impl Options {
    /// These options with guest DRAM, and the physical base at the same
    /// distance into it, at `base` (a board's [`Inputs::dram_base`]); `None`
    /// keeps them.
    pub fn placed_at(&self, base: Option<u64>) -> Self {
        let Some(base) = base else {
            return self.clone();
        };
        Self {
            dram_base: base,
            phys_base: base + (self.phys_base - self.dram_base),
            ..self.clone()
        }
    }
}

impl Default for Options {
    fn default() -> Self {
        const DRAM_BASE: u64 = 0x8_0000_0000;
        Self {
            dram_base: DRAM_BASE,
            dram_size: 0x2_0000_0000,
            phys_base: DRAM_BASE,
            load_offset: 0,
            boot_args: "-v".into(),
            boot_cpu: "cpu0".into(),
            timebase_frequency: 24_000_000,
            syscfg: BTreeMap::new(),
            mac_addresses: BTreeMap::new(),
            security: SecurityPolicy {
                mode: boot_policy::SecurityMode::Reduced,
                sip_bits: 0,
                sepfw_load_at_boot: None,
            },
            osenvironment: None,
            boot_command: None,
            root: None,
            ecid: None,
            overlay: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct File {
    pub name: String,
    pub bytes: usize,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Region {
    /// The `/chosen/memory-map` entry naming this region.
    pub name: String,
    pub file: String,
    pub file_offset: u64,
    /// Bytes copied from the file.
    pub bytes: u64,
    pub guest_pa: u64,
    /// Bytes reserved at `guest_pa`; those after `bytes` are zeroed.
    pub memory_bytes: u64,
    pub sha256: String,
    /// Link-time address of the region's first byte, for image regions.
    pub virtual_address: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub image: String,
    pub virtual_address: u64,
    pub physical_address: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Image {
    pub name: String,
    pub file: String,
    pub uuid: Option<String>,
    pub vm_base: u64,
    pub vm_bytes: u64,
    pub entry: Entry,
    pub fileset_entries: usize,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PatchSource {
    /// Guest RAM size chosen at boot.
    DramSize,
    /// The firmware framebuffer the kernel console draws on.
    Framebuffer,
    /// Fresh random bytes for every boot.
    Entropy,
    /// The kernel command line.
    BootArgs,
    /// The generic timer rate the machine presents.
    Timebase,
    /// The current bank of the machine's persistent NOR, when it has one.
    Nvram,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Encoding {
    U64Le,
    Bytes,
    /// NUL-terminated within the field; the rest of the field is zero.
    CString,
}

/// One fixed-size field the UEFI mount may rewrite before entry.
#[derive(Debug, Clone, Serialize)]
pub struct Patch {
    pub source: PatchSource,
    pub required: bool,
    pub region: String,
    pub file: String,
    pub file_offset: u64,
    pub bytes: u64,
    pub encoding: Encoding,
    /// The DeviceTree path and property, or the `boot_args` field.
    pub field: String,
    pub prepared_hex: String,
    pub rule: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlaceholderDecision {
    #[serde(flatten)]
    pub placeholder: Placeholder,
    pub resolution: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Manifest {
    pub schema_version: u32,
    /// [`REVISION`].
    pub revision: u32,
    pub target: Target,
    pub options: Options,
    pub sources: Vec<Source>,
    pub files: Vec<File>,
    pub regions: Vec<Region>,
    /// Where execution starts: SPTM's entry, at EL2-equivalent privilege.
    pub entry: Entry,
    /// x0 on entry: the physical address of `boot_args`.
    pub entry_x0: u64,
    pub images: Vec<Image>,
    pub boot_args: BootArgs,
    pub device_tree_bytes: usize,
    pub top_of_kernel_data: u64,
    /// iBoot's carveouts, below the managed range.
    pub carveouts: Vec<Placed>,
    /// The region iBoot programs into the AMCC's CTRR-A lock group, from
    /// the first region through `SPTM-rx` (`lock_regs`).
    pub read_only_region: Option<Programmed>,
    /// What iBoot leaves in the cores' lock registers on the M4 and later
    /// (`lock_regs::core_handoff`).
    pub core_locks: Option<ctrr::Handoff>,
    /// The DeviceTree nodes whose `compatible` names no modeled device and
    /// was removed (`devices`).
    pub hidden_devices: Vec<String>,
    pub patches: Vec<Patch>,
    pub placeholders: Vec<PlaceholderDecision>,
    /// Boot-policy and manifest values written into `/chosen`.
    pub security: Vec<Decision>,
    pub unresolved: Vec<String>,
}

pub struct Bundle {
    /// Output files in manifest order, as `(name, bytes)`.
    pub files: Vec<(String, Vec<u8>)>,
    pub manifest: Manifest,
}

/// Where a split region begins or ends within an image.
#[derive(Clone, Copy)]
enum Mark {
    ImageStart,
    ImageEnd,
    SegmentStart(&'static str),
    SegmentEnd(&'static str),
}

struct Split {
    suffix: &'static str,
    start: Mark,
    end: Mark,
}

const fn split(suffix: &'static str, start: Mark, end: Mark) -> Split {
    Split { suffix, start, end }
}

use Mark::{ImageEnd, ImageStart, SegmentEnd, SegmentStart};
use alloc::{borrow::ToOwned, format, string::String, vec, vec::Vec};

/// m1n1 `load_macos_sptm` image splits.
const KERNEL_SPLITS: &[Split] = &[
    split("ro", ImageStart, SegmentStart("__DATA_SPTM")),
    split("rs", SegmentStart("__DATA_SPTM"), SegmentEnd("__DATA_SPTM")),
    split("rx", SegmentStart("__TEXT_EXEC"), SegmentEnd("__TEXT_EXEC")),
    split(
        "bx",
        SegmentStart("__TEXT_BOOT_EXEC"),
        SegmentEnd("__TEXT_BOOT_EXEC"),
    ),
    split("rw", SegmentStart("__PRELINK_INFO"), SegmentEnd("__DATA")),
    split("le", SegmentStart("__LINKEDIT"), ImageEnd),
];
const SPTM_SPLITS: &[Split] = &[
    split("ro", ImageStart, SegmentStart("__TEXT_EXEC")),
    split("rx", SegmentStart("__TEXT_EXEC"), SegmentEnd("__TEXT_EXEC")),
    split("rw", SegmentEnd("__TEXT_EXEC"), SegmentStart("__LINKEDIT")),
    split("le", SegmentStart("__LINKEDIT"), ImageEnd),
];
const TXM_SPLITS: &[Split] = &[
    split("ro", ImageStart, SegmentStart("__TEXT_EXEC")),
    split("rx", SegmentStart("__TEXT_EXEC"), SegmentEnd("__TEXT_EXEC")),
    split(
        "bx",
        SegmentStart("__TEXT_BOOT_EXEC"),
        SegmentEnd("__TEXT_BOOT_EXEC"),
    ),
    split(
        "rw",
        SegmentEnd("__TEXT_BOOT_EXEC"),
        SegmentStart("__LINKEDIT"),
    ),
    split("le", SegmentStart("__LINKEDIT"), ImageEnd),
];

/// The physical order SPTM requires (m1n1: "Required by SPTM in this order"),
/// as `(image, split)` or a standalone region name.
const REGION_ORDER: &[&str] = &[
    // Outside SPTM's contiguous image sequence, inside the CTRR-A run.
    "BootManifest",
    "TXM-ro",
    "TXM-rx",
    "TXM-bx",
    "TrustCache",
    "BootKC-rx",
    "BootKC-bx",
    "BootKC-ro",
    "BootKC-rs",
    "DeviceTree",
    "SPTM-ro",
    "SPTM-rx",
    "SPTM-rw",
    "SPTM-le",
    "TXM-rw",
    "TXM-le",
    "BootKC-rw",
    "BootKC-le",
    // M4 and later, without a CL4 image (`lock_regs::CL4_DUMMY_PAGE`).
    lock_regs::CL4_DUMMY_PAGE,
    "RAMDisk",
    "SEPFW",
    "BootArgs",
];

/// Independent handoff contract: SPTM's validate_region_order table, raw
/// 0x18728 (16 records), consumed at 0xb9a80..0xb9b74. The boolean marks an
/// optional image. Standalone payloads must not interrupt this sequence.
const SPTM_REGION_ORDER: &[(&str, bool)] = &[
    ("TXM-ro", false),
    ("TXM-rx", false),
    ("TXM-bx", false),
    ("TrustCache", false),
    ("AuxKC-ro", true),
    ("AuxKC-rx", true),
    ("BootKC-rx", false),
    ("BootKC-bx", false),
    ("BootKC-ro", false),
    ("BootKC-rs", false),
    ("CL4-rx", true),
    ("CL4-ro", true),
    ("DeviceTree", false),
    ("SPTM-ro", false),
    ("SPTM-rx", false),
    ("SPTM-rw", false),
];

fn validate_sptm_region_order(regions: &[Region]) -> Result<()> {
    let mut previous: Option<(&str, u64)> = None;
    for &(name, optional) in SPTM_REGION_ORDER {
        let Some(region) = regions.iter().find(|region| region.name == name) else {
            ensure!(
                optional,
                "SPTM region order: missing required region {name}"
            );
            continue;
        };
        let start = region.guest_pa;
        let end = start
            .checked_add(region.memory_bytes)
            .with_context(|| format!("SPTM region order: {name} range overflows"))?;
        // The original CMN/CCMN checks reject null/sentinel endpoints.
        ensure!(
            start > 0 && start < u64::MAX - 1 && end > 0 && end < u64::MAX,
            "SPTM region order: {name} has invalid range {start:#x}..{end:#x}"
        );
        if let Some((previous_name, previous_end)) = previous {
            ensure!(
                start == previous_end,
                "SPTM region order: {name} starts at {start:#x}, not immediately after \
                 {previous_name} ending at {previous_end:#x}"
            );
        }
        previous = Some((name, end));
    }
    Ok(())
}

/// `SPTM-rm` describes one complete loaded image, including its link-edit
/// split beyond the ordered-region table. SPTM consumes its start/end at
/// raw 0xe076c..0xe0790 and 0xe09f8..0xe0a2c during memory setup.
fn sptm_image_span(regions: &[Region]) -> Result<core::ops::Range<u64>> {
    let mut span = None;
    for name in ["SPTM-ro", "SPTM-rx", "SPTM-rw", "SPTM-le"] {
        let region = regions
            .iter()
            .find(|region| region.name == name)
            .with_context(|| format!("SPTM image span: missing region {name}"))?;
        let end = region
            .guest_pa
            .checked_add(region.memory_bytes)
            .with_context(|| format!("SPTM image span: {name} range overflows"))?;
        match &mut span {
            None => span = Some(region.guest_pa..end),
            Some(span) => {
                ensure!(
                    region.guest_pa == span.end,
                    "SPTM image span: {name} starts at {:#x}, expected {:#x}",
                    region.guest_pa,
                    span.end
                );
                span.end = end;
            }
        }
    }
    span.context("SPTM image span is empty")
}

/// The secure kernel's entries, unset: the board has no exclave image
/// (its identity lists no CL4 component). SPTM 26A434 requires `CL4-entry`,
/// `CL4-rx` and `CL4-virt` (`init_get_image_region`) and starts the secure
/// kernel only when `rx + entry - virt` is not `~0`; with every value the
/// template's unset `(~0, ~0)` it is `~0`, and the `CL4-rx` range it types
/// rounds to no pages.
const ABSENT_SECURE_KERNEL: [&str; 3] = ["CL4-entry", "CL4-rx", "CL4-virt"];

const KERNEL_FILE: &str = "kernelcache.img";
const SPTM_FILE: &str = "sptm.img";
const TXM_FILE: &str = "txm.img";
/// The bundle file holding the prepared DeviceTree.
pub const DEVICE_TREE_FILE: &str = "devicetree.adt";
/// Immutable source metadata, verified as a whole file and never loaded as a region.
pub const ORIGINAL_DEVICE_TREE_FILE: &str = "original-devicetree.adt";
const TRUST_CACHE_FILE: &str = "trustcache.bin";
const BOOT_MANIFEST_FILE: &str = "boot-manifest.im4m";
const SEP_FILE: &str = "sepfw.im4p";
const RAMDISK_FILE: &str = "ramdisk.img";
/// The engine handoff's file-name capacity (`stela-boot` `handoff::MAX_NAME`).
const MAX_FILE_NAME: usize = 48;
const BOOT_ARGS_FILE: &str = "bootargs.bin";
const CL4_DUMMY_PAGE_FILE: &str = "cl4-dummypage.bin";

struct LoadedImage {
    name: &'static str,
    file: &'static str,
    collection: KernelCollection,
    memory: Vec<u8>,
    /// `(region name, image offset range)` in split order.
    pieces: Vec<(String, core::ops::Range<u64>)>,
}

fn resolve(collection: &KernelCollection, mark: Mark) -> Result<u64> {
    let segment = |name: &str| {
        collection
            .segment(name)
            .with_context(|| format!("image has no segment {name}"))
    };
    Ok(match mark {
        ImageStart => 0,
        ImageEnd => collection.image_bytes(),
        SegmentStart(name) => segment(name)?.vm_address - collection.vm_base,
        SegmentEnd(name) => segment(name)?.vm_end() - collection.vm_base,
    })
}

impl LoadedImage {
    fn new(
        name: &'static str,
        file: &'static str,
        collection: KernelCollection,
        bytes: &[u8],
        splits: &[Split],
    ) -> Result<Self> {
        let memory = collection.memory_image(bytes)?;
        let mut pieces = vec![];
        for split in splits {
            let start = resolve(&collection, split.start)?;
            let end = resolve(&collection, split.end)?;
            ensure!(
                start < end && start.is_multiple_of(PAGE_BYTES) && end.is_multiple_of(PAGE_BYTES),
                "{name}-{} is not a non-empty page-aligned range",
                split.suffix
            );
            pieces.push((format!("{name}-{}", split.suffix), start..end));
        }
        // The pieces must tile the image so that nothing is dropped.
        let mut sorted: Vec<_> = pieces.iter().map(|(_, r)| r.clone()).collect();
        sorted.sort_by_key(|r| r.start);
        let mut cursor = 0;
        for range in sorted {
            ensure!(
                range.start == cursor,
                "{name} regions leave a gap or overlap at image offset {cursor:#x}"
            );
            cursor = range.end;
        }
        ensure!(
            cursor == collection.image_bytes(),
            "{name} regions do not reach the image end"
        );
        Ok(Self {
            name,
            file,
            collection,
            memory,
            pieces,
        })
    }
}

/// Pending region content before placement.
struct Content {
    name: String,
    file: String,
    file_offset: u64,
    bytes: u64,
    memory_bytes: u64,
    virtual_address: Option<u64>,
}

fn page_round(bytes: u64) -> u64 {
    bytes.next_multiple_of(PAGE_BYTES)
}

/// The SEPFW staging bytes for a SEP image: its `IMG4` container, the form
/// the restore host delivers to `seputil` and the largest form `seputil`
/// can pass to `AppleSEPManager::setFirmwareBytes`.
fn sep_firmware_region_bytes(image: &[u8]) -> u64 {
    stela_runtime::img4::container_bytes(image.len()) as u64
}

fn range_value(base: u64, length: u64) -> Vec<u8> {
    [base.to_le_bytes(), length.to_le_bytes()].concat()
}

fn parse_size(text: &str, recipe: &str) -> Result<usize> {
    let digits = text.trim_start_matches("0x");
    usize::from_str_radix(digits, 16).with_context(|| format!("bad size {text} in {recipe}"))
}

/// The value one recipe alternative yields from the supplied board data.
fn alternative_value(
    alternative: &str,
    recipe: &str,
    options: &Options,
) -> Result<Option<Vec<u8>>> {
    if let Some(name) = alternative.strip_prefix(MACADDR_RECIPE) {
        let Some(value) = options.mac_addresses.get(name) else {
            return Ok(None);
        };
        ensure!(
            value.len() == MAC_ADDRESS_BYTES,
            "MAC address {name} must be {MAC_ADDRESS_BYTES} bytes"
        );
        return Ok(Some(value.clone()));
    }
    if let Some(spec) = alternative.strip_prefix(SYSCFG_RECIPE) {
        let (key, size) = match spec.split_once('/') {
            Some((key, size)) => (key, Some(parse_size(size, recipe)?)),
            None => (spec, None),
        };
        let Some(value) = options.syscfg.get(key) else {
            return Ok(None);
        };
        let mut value = value.clone();
        if let Some(size) = size {
            // iBoot's syscfg resolver copies min(source bytes, recipe size)
            // and zero-fills the remainder (26A434 J473 0xd6a10..0xd6a54).
            value.resize(size, 0);
        }
        return Ok(Some(value));
    }
    if alternative.starts_with(SYSCFG_MISMATCH_RECIPE) {
        return Ok(None);
    }
    if let Some(size) = alternative.strip_prefix(ZERO_FILL_RECIPE) {
        return Ok(Some(vec![0; parse_size(size, recipe)?]));
    }
    if let Some(spec) = alternative.strip_prefix(HEX_RECIPE) {
        let (digits, size) = match spec.split_once('/') {
            Some((digits, size)) => (digits, Some(parse_size(size, recipe)?)),
            None => (spec, None),
        };
        ensure!(
            digits.len().is_multiple_of(2) && digits.bytes().all(|b| b.is_ascii_hexdigit()),
            "{recipe} does not hold whole hex bytes"
        );
        let mut value: Vec<u8> = digits
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&[high, low]| {
                let digit = |b: u8| (b as char).to_digit(16).unwrap_or(0) as u8;
                digit(high) << 4 | digit(low)
            })
            .collect();
        if let Some(size) = size {
            ensure!(
                value.len() <= size,
                "{recipe} holds {} bytes; it allows {size}",
                value.len()
            );
            value.resize(size, 0);
        }
        return Ok(Some(value));
    }
    bail!("unknown fill-in source {alternative} in {recipe}")
}

/// Resolve every template placeholder as iBoot does: the first recipe
/// alternative with a value wins, from the supplied MAC addresses and syscfg
/// values or a `zeroes/N` fill. A property with no source is removed. Each
/// decision is recorded in the manifest.
fn resolve_placeholders(
    tree: &mut DeviceTree,
    options: &Options,
) -> Result<Vec<PlaceholderDecision>> {
    let mut decisions = vec![];
    for placeholder in tree.placeholders() {
        let mut chosen = None;
        for alternative in placeholder.recipe.split(',') {
            if let Some(value) = alternative_value(alternative, &placeholder.recipe, options)? {
                chosen = Some((alternative.to_owned(), value));
                break;
            }
        }
        let node = tree
            .node_mut(&placeholder.path)
            .context("placeholder node disappeared")?;
        let resolution = match chosen {
            Some((alternative, value)) => {
                let bytes = value.len();
                node.set_property(&placeholder.property, value)?;
                format!("{alternative}: {bytes} bytes")
            }
            None if placeholder.recipe.contains(SYSCFG_MISMATCH_RECIPE) => {
                node.remove_property(&placeholder.property);
                "removed: no listed source was supplied, and no syscfg keybag provider is \
                 modelled for syscfg-mismatch"
                    .into()
            }
            None => {
                node.remove_property(&placeholder.property);
                "removed: no listed source was supplied".into()
            }
        };
        decisions.push(PlaceholderDecision {
            placeholder,
            resolution,
        });
    }
    Ok(decisions)
}

fn source_of(input: &Input) -> Source {
    input.source.clone()
}

/// A ramdisk the bundle takes ownership of, so its file is the caller's
/// buffer rather than a copy: an update ramdisk of hundreds of megabytes
/// then needs no second copy in `stela.efi`'s heap.
pub struct OwnedRamdisk {
    pub bytes: Vec<u8>,
    pub source: Source,
}

pub fn prepare(inputs: &Inputs, options: &Options) -> Result<Bundle> {
    assemble(inputs, options, None)
}

/// [`prepare`], with `ramdisk` moved into the bundle; `inputs` must name no
/// ramdisk of its own.
pub fn prepare_owned(inputs: &Inputs, ramdisk: OwnedRamdisk, options: &Options) -> Result<Bundle> {
    ensure!(
        inputs.ramdisk.is_none(),
        "a bundle has one ramdisk, given both borrowed and owned"
    );
    assemble(inputs, options, Some(ramdisk))
}

fn assemble(inputs: &Inputs, options: &Options, owned: Option<OwnedRamdisk>) -> Result<Bundle> {
    let ramdisk_bytes = owned
        .as_ref()
        .map(|ramdisk| ramdisk.bytes.len())
        .or_else(|| inputs.ramdisk.as_ref().map(|ramdisk| ramdisk.bytes.len()));
    // iBoot's carveouts sit below the managed range, which starts past them.
    let table = inputs
        .target
        .chip_id
        .map(carveouts::for_chip)
        .unwrap_or_default();
    let reservation = carveouts::reserve(&table, options.dram_base, options.dram_size)?;
    let dram_end = options
        .dram_base
        .checked_add(options.dram_size)
        .context("DRAM end overflows")?;
    let options = &Options {
        phys_base: options.phys_base.max(reservation.managed_floor()),
        ..options.clone()
    };
    let carveouts = reservation.into_regions();
    // The M4 and later lock their CTRR-C/D and CTXR-A..D copies at handoff.
    let chip = inputs.target.chip_id.and_then(soc::chip);
    let core_locks_handed_off =
        chip.is_some_and(|chip| ctrr::generation(chip) == ctrr::Generation::Ctrr3);
    if let (Some(chip_id), Some(base)) = (inputs.target.chip_id, inputs.dram_base()?) {
        ensure!(
            options.dram_base == base,
            "guest DRAM base {:#x} is not ApChipID {chip_id:#x}'s {base:#x}",
            options.dram_base
        );
    }
    ensure!(
        options.phys_base >= options.dram_base
            && options.phys_base < dram_end
            && options.phys_base.is_multiple_of(PAGE_BYTES)
            && options.load_offset.is_multiple_of(PAGE_BYTES),
        "phys_base must be a page-aligned address inside DRAM"
    );
    let kernel = LoadedImage::new(
        "BootKC",
        KERNEL_FILE,
        KernelCollection::parse(inputs.kernel_collection.bytes)?,
        inputs.kernel_collection.bytes,
        KERNEL_SPLITS,
    )?;
    let sptm = LoadedImage::new(
        "SPTM",
        SPTM_FILE,
        KernelCollection::parse_executable(inputs.sptm.bytes)?,
        inputs.sptm.bytes,
        SPTM_SPLITS,
    )?;
    let txm = LoadedImage::new(
        "TXM",
        TXM_FILE,
        KernelCollection::parse_executable(inputs.txm.bytes)?,
        inputs.txm.bytes,
        TXM_SPLITS,
    )?;
    let modules: Vec<&[u8]> = core::iter::once(inputs.static_trust_cache.bytes)
        .chain(inputs.extra_trust_caches.iter().map(|input| input.bytes))
        .collect();
    let trust_cache = trust_cache::compose(&modules)?;
    let boot_manifest = inputs
        .boot_manifest
        .as_ref()
        .map(|input| im4m::parse(input.bytes))
        .transpose()?;
    let cryptex1_manifest = inputs
        .cryptex1_manifest
        .as_ref()
        .map(|input| im4m::parse(input.bytes))
        .transpose()?;
    for manifest in boot_manifest.iter().chain(&cryptex1_manifest) {
        check_board(manifest, &inputs.target)?;
    }

    let mut tree = DeviceTree::parse(inputs.device_tree.bytes)?;
    // iBoot merges the fused variant's overlays as it loads the tree.
    let (variant, variant_decisions) =
        soc_variant::apply(&mut tree, inputs.target.chip_id, inputs.target.board_id)?
            .map_or((None, vec![]), |(variant, decisions)| {
                (Some(variant), decisions)
            });
    let placeholders = resolve_placeholders(&mut tree, options)?;
    let mut unresolved = shape_device_tree(&mut tree, &inputs.target, options)?;
    let (security, policy_unresolved) = boot_policy::apply(
        &mut tree,
        &options.security,
        boot_manifest.as_ref(),
        cryptex1_manifest.as_ref(),
    )?;
    unresolved.extend(policy_unresolved);
    let mut security = security;
    security.extend(variant_decisions);
    if let Some(root_hash) = &inputs.root_hash {
        if root_hash.volume == boot_policy::SealedVolume::BaseSystem {
            boot_policy::require_image_boot(&options.boot_args)?;
        }
        let manifest = inputs
            .boot_manifest
            .as_ref()
            .zip(boot_manifest.as_ref())
            .map(|(input, manifest)| (input.bytes, manifest));
        let (decisions, gaps) = boot_policy::apply_root_hash(
            &mut tree,
            root_hash.volume,
            root_hash.im4p.as_ref().map(|input| input.bytes),
            manifest,
        )?;
        security.extend(decisions);
        unresolved.extend(gaps);
    }
    if let Some(environment) = options.osenvironment {
        let (decisions, gaps) = boot_policy::apply_environment(&mut tree, environment)?;
        security.extend(decisions);
        unresolved.extend(gaps);
    }
    // iBoot deletes the environments once one is applied.
    security.extend(handoff::remove_environments(&mut tree));
    let (decisions, gaps) = handoff::apply(&mut tree, inputs.target.chip_id)?;
    security.extend(decisions);
    unresolved.extend(gaps);
    let (decisions, gaps) = handoff::apply_boot_command(&mut tree, options.boot_command)?;
    security.extend(decisions);
    unresolved.extend(gaps);
    let (decisions, gaps) =
        handoff::apply_identity(&mut tree, options.ecid, inputs.target.chip_id)?;
    security.extend(decisions);
    unresolved.extend(gaps);
    match &options.root {
        Some(root) => security.extend(root_selection::apply(&mut tree, root)?),
        None => unresolved.push(
            "/chosen apfs-preboot-uuid, boot-uuid, boot-objects-path: no root volume was named; \
             template values kept"
                .into(),
        ),
    }
    boot_policy::refuse_ramdisk_image_root(&options.boot_args)?;
    let ram_image = matches!(options.root, Some(root_selection::Root::RamImage { .. }));
    if ram_image {
        let bytes =
            ramdisk_bytes.context("a RAM disk image root needs the image as the ramdisk")?;
        // A memory-device root wins over `boot-uuid` in `IOFindBSDRoot`, and
        // iBoot names the root in /chosen only without `rd=`.
        ensure!(
            !options
                .boot_args
                .split_whitespace()
                .any(|argument| argument.starts_with("rd=") || argument.starts_with("rootdev=")),
            "a RAM disk image root is named by /chosen boot-uuid; boot-args must not name rd= \
             or rootdev="
        );
        // The physical address follows placement; the length is fixed.
        root_selection::ram_image(&mut tree, 0, bytes as u64)?;
    }
    carveouts::publish(&mut tree, &carveouts)?;
    if let Some(chip_id) = inputs.target.chip_id {
        aic::publish(&mut tree, chip_id)?;
    }
    let nvram_published = nvram::publish(&mut tree)?;
    let fused = variant.map(|variant| variant.name);
    let memory_controller = match inputs
        .target
        .chip_id
        .and_then(|chip| lock_regs::table(chip, fused))
    {
        Some(controller) if lock_regs::publish(&mut tree, controller)? => Some(controller),
        Some(_) => {
            unresolved.push(format!(
                "{}: the template has no node for iBoot's AMCC map; SPTM's CTRR setup stops",
                lock_regs::AMCC
            ));
            None
        }
        None if tree.node(lock_regs::AMCC).is_some() => {
            unresolved.push(format!(
                "{}: no iBoot AMCC map for this SoC; the template stays empty and SPTM's CTRR \
                 setup stops on it",
                lock_regs::AMCC
            ));
            None
        }
        None => None,
    };
    if let Some(controller) = inputs
        .target
        .chip_id
        .and_then(|chip| lock_regs::ioa_table(chip, fused))
    {
        lock_regs::publish_ioa(&mut tree, controller)?;
    }
    darts::publish(&mut tree)?;
    if let Some(chip_id) = inputs.target.chip_id {
        for table in dvfs::publish(&mut tree, chip_id)? {
            let (name, domain) = (&table.name, &table.domain);
            unresolved.push(match table.contents {
                dvfs::Contents::OperatingPoints => format!(
                    "/arm-io/pmgr {name}: {domain} operating points without calibrated voltages (0)"
                ),
                dvfs::Contents::SingleState => {
                    format!("/arm-io/pmgr {name}: {domain} has one state; its clock is not modeled")
                }
                dvfs::Contents::Unpublished => format!(
                    "/arm-io/pmgr {name}: ApChipID {chip_id:#x} has no {domain} operating points; \
                     the table is left out and ApplePMGR stops on it"
                ),
            });
        }
    }
    let hidden_devices = devices::hide_unmodeled(&mut tree);
    if !hidden_devices.is_empty() {
        unresolved.push(format!(
            "{} device admissions are restricted by missing models or providers (hidden_devices)",
            hidden_devices.len()
        ));
    }
    if let Some(chip_id) = inputs.target.chip_id
        && let Some(tables) = gpu_dvfs::publish(&mut tree, chip_id)?
    {
        unresolved.push(format!(
            "/arm-io/sgx perf-states, perf-states-sram: {} GPU operating points in {} table \
             without calibrated voltages (0)",
            tables.states, tables.tables
        ));
    }
    apply_overlay(&mut tree, &options.overlay)?;
    unresolved.extend(platform_gaps(&tree, inputs));

    // Preserve the actual IM4M selected by boot policy. The payload tag
    // belongs to the source input, not a guessed iBoot identity or name.
    let boot_manifest_object = inputs
        .boot_manifest
        .as_ref()
        .map(|manifest| {
            boot_manifests::Object::new(
                &tree,
                &inputs.kernel_collection.source.payload_type,
                manifest.bytes,
            )
        })
        .transpose()?;
    if let Some(object) = &boot_manifest_object {
        object.reserve(&mut tree)?;
        unresolved.push(
            "/chosen/secure-boot-hashes state: iBoot's loaded-object authentication flags are \
             not reproduced; only the supplied original kernel manifest is forwarded"
                .into(),
        );
    }

    // Lay the memory map out with zero values first: its size is fixed by
    // the entry count, so the DeviceTree size is known before placement.
    let mut contents = vec![];
    for name in REGION_ORDER {
        let content = match *name {
            "TrustCache" => Content {
                name: (*name).into(),
                file: TRUST_CACHE_FILE.into(),
                file_offset: 0,
                bytes: trust_cache.len() as u64,
                memory_bytes: page_round(trust_cache.len() as u64),
                virtual_address: None,
            },
            "BootManifest" => match &inputs.boot_manifest {
                Some(manifest) => Content {
                    name: (*name).into(),
                    file: BOOT_MANIFEST_FILE.into(),
                    file_offset: 0,
                    bytes: manifest.bytes.len() as u64,
                    memory_bytes: page_round(manifest.bytes.len() as u64),
                    virtual_address: None,
                },
                None => continue,
            },
            "DeviceTree" => Content {
                name: (*name).into(),
                file: DEVICE_TREE_FILE.into(),
                file_offset: 0,
                bytes: 0,
                memory_bytes: 0,
                virtual_address: None,
            },
            "RAMDisk" => match ramdisk_bytes {
                Some(bytes) => Content {
                    name: (*name).into(),
                    file: RAMDISK_FILE.into(),
                    file_offset: 0,
                    bytes: bytes as u64,
                    memory_bytes: page_round(bytes as u64),
                    virtual_address: None,
                },
                None => continue,
            },
            // iBoot adds the SEPFW entry whether or not it loaded SEP firmware
            // (0x29dd8, before its loaded test at 0x29df4); only
            // `sepfw-loaded`/`sepfw-booted`/`sep-boot-slot` depend on a load.
            // The run-time load needs the region: `seputil --restore` reaches
            // `AppleSEPFirmware::_initFromMemory`, whose
            // `_setupSepFirmwareMemoryRegion` panics without SEPFW and whose
            // `_copyInData` copies the delivered image into it, refusing an
            // image longer than the region. Stela's SEP has no `fromPreload`
            // path, so the region is reserved (zero-filled), large enough for
            // the SEP image in the `IMG4` container the restore host delivers,
            // and `sepfw-loaded` stays unpublished.
            "SEPFW" => match &inputs.sep_firmware {
                Some(sep) => Content {
                    name: (*name).into(),
                    file: SEP_FILE.into(),
                    file_offset: 0,
                    bytes: 0,
                    memory_bytes: page_round(sep_firmware_region_bytes(sep.bytes)),
                    virtual_address: None,
                },
                None => {
                    unresolved.push("SEPFW: no SEP firmware input; the region is absent".into());
                    continue;
                }
            },
            lock_regs::CL4_DUMMY_PAGE if core_locks_handed_off => Content {
                name: (*name).into(),
                file: CL4_DUMMY_PAGE_FILE.into(),
                file_offset: 0,
                bytes: lock_regs::CL4_DUMMY_PAGE_BYTES as u64,
                memory_bytes: lock_regs::CL4_DUMMY_PAGE_BYTES as u64,
                virtual_address: None,
            },
            lock_regs::CL4_DUMMY_PAGE => continue,
            "BootArgs" => Content {
                name: (*name).into(),
                file: BOOT_ARGS_FILE.into(),
                file_offset: 0,
                bytes: boot_args::BYTES as u64,
                memory_bytes: BOOT_ARGS_REGION_BYTES,
                virtual_address: None,
            },
            piece => {
                let image = [&kernel, &sptm, &txm]
                    .into_iter()
                    .find(|image| piece.starts_with(image.name))
                    .with_context(|| format!("no image provides {piece}"))?;
                let range = image
                    .pieces
                    .iter()
                    .find(|(n, _)| n == piece)
                    .map(|(_, r)| r.clone())
                    .with_context(|| format!("{} has no split {piece}", image.name))?;
                Content {
                    name: piece.into(),
                    file: image.file.into(),
                    file_offset: range.start,
                    bytes: range.end - range.start,
                    memory_bytes: range.end - range.start,
                    virtual_address: Some(image.collection.vm_base + range.start),
                }
            }
        };
        contents.push(content);
    }
    unresolved.push(
        "RTBuddySeg: iBoot-provided RTKit buddy segment; content unknown, the region is absent"
            .into(),
    );

    let memory_map = tree
        .node_mut(MEMORY_MAP)
        .context("DeviceTree has no /chosen/memory-map")?;
    memory_map
        .properties
        .retain(|p| !p.name().starts_with(RESERVED_ENTRY_PREFIX));
    let extra_entries = [
        "slide",
        "TXM-entry",
        "TXM-virt",
        "BootKC-entry",
        "BootKC-virt",
        "SPTM-rm",
    ]
    .into_iter()
    .chain(ABSENT_SECURE_KERNEL);
    for name in contents
        .iter()
        .map(|c| c.name.as_str())
        .chain(extra_entries)
    {
        memory_map.set_property(name, vec![0; MEMORY_MAP_ENTRY_BYTES])?;
    }
    let device_tree_bytes = tree.encoded_bytes() as u64;
    for content in &mut contents {
        if content.name == "DeviceTree" {
            content.bytes = device_tree_bytes;
            content.memory_bytes = page_round(device_tree_bytes);
        }
    }

    // Place every region back to back from the load base.
    let load_base = options
        .phys_base
        .checked_add(options.load_offset)
        .context("load base overflows")?;
    let mut cursor = load_base;
    let mut regions = vec![];
    for content in contents {
        regions.push(Region {
            name: content.name,
            file: content.file,
            file_offset: content.file_offset,
            bytes: content.bytes,
            guest_pa: cursor,
            memory_bytes: content.memory_bytes,
            sha256: String::new(),
            virtual_address: content.virtual_address,
        });
        cursor = cursor
            .checked_add(page_round(content.memory_bytes))
            .context("loaded region end overflows")?;
    }
    validate_sptm_region_order(&regions)?;
    let top_of_kernel_data = cursor;
    ensure!(
        top_of_kernel_data <= dram_end,
        "regions end at {top_of_kernel_data:#x}, past DRAM end {dram_end:#x}"
    );
    let region = |name: &str| {
        regions
            .iter()
            .find(|r| r.name == name)
            .with_context(|| format!("no region {name}"))
    };
    let memory_map = tree.node_mut(MEMORY_MAP).context("memory-map")?;
    for region in &regions {
        memory_map.set_property(
            &region.name,
            range_value(region.guest_pa, region.memory_bytes),
        )?;
    }
    let read_only_region = memory_controller
        .map(|controller| {
            let sptm_rx = region("SPTM-rx")?;
            lock_regs::ctrr_a(
                controller,
                options.dram_base,
                load_base,
                sptm_rx.guest_pa + page_round(sptm_rx.memory_bytes),
            )
        })
        .transpose()?;
    let sptm_span = sptm_image_span(&regions)?;
    for (name, value) in [
        (
            "slide",
            range_value(options.phys_base, load_base - options.phys_base),
        ),
        ("TXM-entry", range_value(txm.collection.entry_offset(), 0)),
        ("TXM-virt", range_value(0, 0)),
        (
            "BootKC-entry",
            range_value(kernel.collection.entry_offset(), 0),
        ),
        ("BootKC-virt", range_value(0, 0)),
        (
            "SPTM-rm",
            range_value(sptm_span.start, sptm_span.end - sptm_span.start),
        ),
    ]
    .into_iter()
    .chain(ABSENT_SECURE_KERNEL.map(|name| (name, range_value(u64::MAX, u64::MAX))))
    {
        memory_map.set_property(name, value)?;
    }
    let core_locks = core_locks_handed_off
        .then(|| {
            // SPTM programs CTRR-D unless the property is a present 0.
            let kernel_ctrr = tree
                .property("/chosen", "kernel-ctrr-to-be-enabled")
                .is_none_or(|p| p.value.iter().any(|&byte| byte != 0));
            lock_regs::core_handoff(
                |name| {
                    let region = regions.iter().find(|r| r.name == name)?;
                    Some(region.guest_pa..region.guest_pa + region.memory_bytes)
                },
                kernel_ctrr,
                tag_offset(chip, options, dram_end, top_of_kernel_data)?,
            )
        })
        .transpose()?;
    if ram_image {
        // The image keeps the `RAMDisk` region, a name SPTM types (its
        // region table, `sptm.t8112` file offset 0x28a3); XNU also makes
        // `md0` of it, which nothing roots from without `rd=`.
        let image = region("RAMDisk")?;
        security.extend(root_selection::ram_image(
            &mut tree,
            image.guest_pa,
            image.bytes,
        )?);
    }
    if let Some(object) = &boot_manifest_object {
        let manifest = region("BootManifest")?;
        let protected = read_only_region
            .as_ref()
            .context("boot manifest publication requires a read-only boot region")?;
        ensure!(
            manifest.guest_pa >= protected.base
                && manifest.guest_pa + manifest.memory_bytes <= protected.base + protected.bytes,
            "boot manifest lies outside the read-only boot region"
        );
        security.extend(object.place(&mut tree, manifest.guest_pa)?);
    }
    let device_tree = tree.serialize();
    ensure!(
        device_tree.len() as u64 == device_tree_bytes,
        "DeviceTree size changed after placement"
    );

    let virt_base = VIRT_BASE + (options.phys_base % VIRT_BASE_ALIGNMENT);
    let device_tree_region = region("DeviceTree")?;
    let boot_args_region = region("BootArgs")?;
    let boot_args = BootArgs {
        revision: boot_args::REVISION,
        version: boot_args::VERSION,
        virt_base,
        phys_base: options.phys_base,
        mem_size: dram_end - options.phys_base,
        top_of_kernel_data,
        video: Video::default(),
        machine_type: 0,
        device_tree: device_tree_region.guest_pa - options.phys_base + virt_base,
        device_tree_length: u32::try_from(device_tree.len())?,
        command_line: options.boot_args.clone(),
        boot_flags: 0,
        mem_size_actual: options.dram_size,
    };
    let boot_args_bytes = boot_args.encode()?.to_vec();
    let boot_args_pa = boot_args_region.guest_pa;

    let mut patches = device_tree_patches(&tree, device_tree_region)?;
    patches.extend(cpu_frequency_patches(&tree, device_tree_region)?);
    if nvram_published {
        patches.extend(nvram_patches(&tree, device_tree_region)?);
    }
    patches.extend(boot_args_patches(boot_args_region, &boot_args_bytes));

    let entry_point = |image: &LoadedImage| -> Result<Entry> {
        let offset = image.collection.entry_offset();
        let (name, range) = image
            .pieces
            .iter()
            .find(|(_, r)| r.contains(&offset))
            .context("entry lies outside every region")?;
        Ok(Entry {
            image: image.name.into(),
            virtual_address: image.collection.thread.pc,
            physical_address: region(name)?.guest_pa + (offset - range.start),
        })
    };
    let images = [&sptm, &txm, &kernel]
        .into_iter()
        .map(|image| {
            Ok(Image {
                name: image.name.into(),
                file: image.file.into(),
                uuid: image.collection.uuid.clone(),
                vm_base: image.collection.vm_base,
                vm_bytes: image.collection.image_bytes(),
                entry: entry_point(image)?,
                fileset_entries: image.collection.fileset_entries.len(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let entry = images[0].entry.clone();

    let mut files = vec![
        (KERNEL_FILE.to_owned(), kernel.memory),
        (SPTM_FILE.to_owned(), sptm.memory),
        (TXM_FILE.to_owned(), txm.memory),
        (DEVICE_TREE_FILE.to_owned(), device_tree),
        (
            ORIGINAL_DEVICE_TREE_FILE.to_owned(),
            inputs.device_tree.bytes.to_vec(),
        ),
        (TRUST_CACHE_FILE.to_owned(), trust_cache),
        (BOOT_ARGS_FILE.to_owned(), boot_args_bytes),
    ];
    if let Some(manifest) = &inputs.boot_manifest {
        files.push((BOOT_MANIFEST_FILE.to_owned(), manifest.bytes.to_vec()));
    }
    if core_locks_handed_off {
        files.push((CL4_DUMMY_PAGE_FILE.to_owned(), lock_regs::cl4_dummy_page()));
    }
    if let Some(sep) = &inputs.sep_firmware {
        files.push((SEP_FILE.to_owned(), sep.bytes.to_vec()));
    }
    let ramdisk_source = match owned {
        Some(ramdisk) => {
            files.push((RAMDISK_FILE.to_owned(), ramdisk.bytes));
            Some(ramdisk.source)
        }
        None => inputs.ramdisk.as_ref().map(|ramdisk| {
            files.push((RAMDISK_FILE.to_owned(), ramdisk.bytes.to_vec()));
            source_of(ramdisk)
        }),
    };
    for (name, image) in &inputs.board_firmware {
        // The manifest admits only simple names; these checks keep the name
        // within the engine handoff and distinct from the bundle's own files.
        ensure!(
            name.len() <= MAX_FILE_NAME && !files.iter().any(|(file, _)| file == name),
            "board firmware name {name:?} is too long or already a bundle file"
        );
        files.push((name.clone(), image.bytes.to_vec()));
    }
    for region in &mut regions {
        let (_, bytes) = files
            .iter()
            .find(|(name, _)| *name == region.file)
            .with_context(|| format!("no file {}", region.file))?;
        let start = usize::try_from(region.file_offset)?;
        let end = start + usize::try_from(region.bytes)?;
        ensure!(
            end <= bytes.len(),
            "region {} exceeds its file",
            region.name
        );
        region.sha256 = sha256(&bytes[start..end]);
    }
    let mut sources = vec![
        source_of(&inputs.kernel_collection),
        source_of(&inputs.sptm),
        source_of(&inputs.txm),
        source_of(&inputs.device_tree),
        source_of(&inputs.static_trust_cache),
    ];
    sources.extend(
        inputs
            .sep_firmware
            .iter()
            .chain(&inputs.boot_manifest)
            .chain(&inputs.cryptex1_manifest)
            .chain(&inputs.extra_trust_caches)
            .map(source_of),
    );
    sources.extend(ramdisk_source);
    sources.extend(
        inputs
            .root_hash
            .iter()
            .filter_map(|r| r.im4p.as_ref())
            .chain(inputs.board_firmware.iter().map(|(_, image)| image))
            .map(source_of),
    );
    let manifest = Manifest {
        schema_version: SCHEMA_VERSION,
        revision: REVISION,
        target: inputs.target.clone(),
        options: options.clone(),
        sources,
        files: files
            .iter()
            .map(|(name, bytes)| File {
                name: name.clone(),
                bytes: bytes.len(),
                sha256: sha256(bytes),
            })
            .collect(),
        regions,
        entry,
        entry_x0: boot_args_pa,
        images,
        boot_args,
        device_tree_bytes: device_tree_bytes as usize,
        top_of_kernel_data,
        carveouts,
        read_only_region,
        core_locks,
        hidden_devices,
        patches,
        placeholders,
        security,
        unresolved,
    };
    Ok(Bundle { files, manifest })
}

/// TAG_OFFSET_EL2 as iBoot locks it on a chip with memory tagging, 0
/// elsewhere: the tag storage at the top of the managed range
/// (`stela_runtime::machine::tag_storage`), which must lie above every
/// placed region.
fn tag_offset(
    chip: Option<stela_runtime::machine::Chip>,
    options: &Options,
    dram_end: u64,
    top_of_kernel_data: u64,
) -> Result<u64> {
    if !chip.is_some_and(identification::memory_tagging) {
        return Ok(0);
    }
    let value = tag_storage::hand_off(
        options.phys_base,
        dram_end - options.phys_base,
        options.dram_size,
    )
    .context("the tag storage's base does not fit TAG_OFFSET_EL2")?;
    ensure!(
        tag_storage::base(value) >= top_of_kernel_data,
        "the tag storage at {:#x} overlaps the regions ending at {top_of_kernel_data:#x}",
        tag_storage::base(value)
    );
    Ok(value)
}

/// A global manifest must name the selected board.
fn check_board(manifest: &im4m::Manifest, target: &Target) -> Result<()> {
    for (name, expected) in [("CHIP", target.chip_id), ("BORD", target.board_id)] {
        if let (Some(Value::Integer(found)), Some(expected)) = (manifest.property(name), expected) {
            ensure!(
                *found == u64::from(expected),
                "manifest {name} {found:#x} differs from the identity's {expected:#x}"
            );
        }
    }
    Ok(())
}

fn apply_overlay(tree: &mut DeviceTree, overlay: &[OverlayProperty]) -> Result<()> {
    for entry in overlay {
        let mut parent = String::from("/");
        for component in entry.path.split('/').filter(|c| !c.is_empty()) {
            tree.ensure_child(&parent, component)?;
            parent = format!("{}/{component}", parent.trim_end_matches('/'));
        }
        tree.set_property(&entry.path, &entry.property, entry.value.clone())?;
    }
    Ok(())
}

/// Bootloader-provided inputs SPTM reads that no restore member supplies.
fn platform_gaps(tree: &DeviceTree, inputs: &Inputs) -> Vec<String> {
    let mut gaps = vec![];
    if tree.property(lock_regs::AMCC, "aperture-count").is_none() {
        gaps.extend(lock_regs::gaps(None));
    }
    gaps.extend(carveouts::gaps(tree, inputs.target.chip_id));
    if inputs.extra_trust_caches.is_empty() {
        gaps.push(
            "TrustCache: static module only; Cryptex1 trust caches load later through their manifest"
                .into(),
        );
    }
    gaps.push("ExclaveOSTrustCache: the identity lists no Ap,ExclaveOS component".into());
    gaps.push("SEPPatches: iBoot's SEP patch region is not in the restore image".into());
    gaps
}

/// Board facts and boot-time slots that iBoot adds to its template tree.
fn shape_device_tree(
    tree: &mut DeviceTree,
    target: &Target,
    options: &Options,
) -> Result<Vec<String>> {
    let mut unresolved = vec![];
    let chosen = "/chosen";
    tree.set_property(
        chosen,
        "dram-base",
        options.dram_base.to_le_bytes().to_vec(),
    )?;
    tree.set_property(
        chosen,
        "dram-size",
        options.dram_size.to_le_bytes().to_vec(),
    )?;
    for (name, value) in [("chip-id", target.chip_id), ("board-id", target.board_id)] {
        match value {
            Some(value) => tree.set_property(chosen, name, value.to_le_bytes().to_vec())?,
            None => unresolved.push(format!("/chosen {name}: absent from the restore identity")),
        }
    }
    // m1n1 load_macos_sptm creates these keys for every boot.
    tree.ensure_child(chosen, "hibernation")?;
    for key in ["key-sptm-ctrr", "key-xnu-ctrr"] {
        tree.set_property("/chosen/hibernation", key, vec![0; HIBERNATION_KEY_BYTES])?;
    }
    let cpu = format!("/cpus/{}", options.boot_cpu);
    let state = tree
        .property(&cpu, "state")
        .with_context(|| format!("DeviceTree has no {cpu} state"))?;
    let running = b"running\0".to_vec();
    ensure!(
        state.value.len() == running.len(),
        "{cpu} state field is not eight bytes"
    );
    tree.set_property(&cpu, "state", running)?;
    // iBoot adds the clock rates at hand-off; every CPU node carries them.
    for cpu in cpu_nodes(tree)? {
        for property in CPU_FREQUENCY_PROPERTIES {
            tree.set_property(
                &cpu,
                property,
                options.timebase_frequency.to_le_bytes().to_vec(),
            )?;
        }
    }
    unresolved.push(
        "/cpus fixed-frequency and peripheral-frequency take the timebase rate; Apple's values are unobserved"
            .into(),
    );
    unresolved.extend(set_die_count(tree, target.chip_id)?);
    unresolved.push(
        "/chosen/boot-object-manifests: no signed LocalPolicy or personalized manifest objects; \
         a supplied original global boot manifest is forwarded separately"
            .into(),
    );
    unresolved.push("preoslog: iBoot log region omitted".into());
    unresolved.push(
        "other rows iBoot writes stay as the template ships them or absent \
         (docs/research/iboot-handoff.md lists each with its reason)"
            .into(),
    );
    Ok(unresolved)
}

/// The ApChipIDs whose 26A434 iBoots carry no `die-count` row: every T8103
/// (J274, J293, J313, J456, J457), T8112 (J413, J415, J473, J493) and T8140
/// (J700) iBoot lacks the string. Every other board's iBoot writes it.
const NO_DIE_COUNT: [u32; 3] = [0x8103, 0x8112, 0x8140];
/// The Ultras, for which iBoot writes 2: J375D/J314C/J375C compute
/// `chip == 0x6002 ? 2 : 1` (J375D 0x36454, compare 0x3c1d0), J575D/J514C/
/// J514M `chip == 0x6032 ? 2 : 1` (J575D 0x3a66c, compare 0x41a00), and the
/// T6022 boards' builds store 2 (J180D 0x39c1c, J475D 0x39bf0) where the
/// T6020/T6021 builds store 1 (J414C 0x3a634).
const ULTRAS: [u32; 3] = [0x6002, 0x6022, 0x6032];
/// The M5 Pro, Max and Ultra share one ApChipID; their iBoot counts two dies
/// only when the die-configuration fuses at 0x2_8837_4010 read
/// `0xa050_c030`, `0xa55a_c33c` (J775D 0x520d8, J714C 0x50a5c), which is the
/// `h17d` variant whose CPUs the variant pass keeps on both dies.
const FUSED_DIES: u32 = 0x6050;

/// iBoot's `/arm-io` `die-count` (J180D writes it beside `usbphy-frequency`
/// on the `arm-io` node, file 0x39d84..0x39d98, creating the property).
/// `ApplePMGR::start` reads it from its provider's provider's provider, the
/// `arm-io` device (mac14j KC VA 0xfffffe0009b35804..0xfffffe0009b358e0),
/// defaulting to one die (0xfffffe0009b357fc). The value is the chip's rule
/// above; the CPU nodes' dies (`die-id`, which the runtime's PMGR reader
/// counts) must agree, and give the fused count on the T6050.
fn set_die_count(tree: &mut DeviceTree, chip_id: Option<u32>) -> Result<Option<String>> {
    let Some(chip) = chip_id else {
        return Ok(Some(
            "/arm-io die-count: no ApChipID selects iBoot's row".into(),
        ));
    };
    if NO_DIE_COUNT.contains(&chip) {
        return Ok(None);
    }
    let dies = cpu_dies(tree)?;
    let count = if chip == FUSED_DIES {
        dies
    } else {
        let count = if ULTRAS.contains(&chip) { 2 } else { 1 };
        ensure!(
            dies == count,
            "ApChipID {chip:#x}'s iBoot writes die-count {count}, but its CPUs are on {dies} dies"
        );
        count
    };
    ensure!(tree.node("/arm-io").is_some(), "DeviceTree has no /arm-io");
    tree.set_property("/arm-io", "die-count", count.to_le_bytes().to_vec())?;
    Ok(None)
}

/// The dies the CPU nodes name: their highest `die-id` plus one.
fn cpu_dies(tree: &DeviceTree) -> Result<u32> {
    let mut highest = 0u32;
    for cpu in cpu_nodes(tree)? {
        if let Some(die) = tree.property(&cpu, "die-id") {
            let word = die
                .value
                .first_chunk::<4>()
                .with_context(|| format!("{cpu} die-id is not a u32"))?;
            highest = highest.max(u32::from_le_bytes(*word));
        }
    }
    highest
        .checked_add(1)
        .context("CPU die-id exceeds the die count")
}

/// Paths of the `/cpus` children that describe processors.
fn cpu_nodes(tree: &DeviceTree) -> Result<Vec<String>> {
    let cpus = tree.node("/cpus").context("DeviceTree has no /cpus")?;
    Ok(cpus
        .children
        .iter()
        .filter(|cpu| cpu.property("state").is_some())
        .filter_map(|cpu| cpu.name().map(|name| format!("/cpus/{name}")))
        .collect())
}

fn cpu_frequency_patches(tree: &DeviceTree, region: &Region) -> Result<Vec<Patch>> {
    let bytes = tree.serialize();
    let mut patches = vec![];
    for cpu in cpu_nodes(tree)? {
        for property in CPU_FREQUENCY_PROPERTIES {
            let at = tree.locate(&cpu, property)?;
            patches.push(Patch {
                source: PatchSource::Timebase,
                required: false,
                region: region.name.clone(),
                file: region.file.clone(),
                file_offset: at.value_offset as u64,
                bytes: at.value_bytes as u64,
                encoding: Encoding::U64Le,
                field: format!("{cpu} {property}"),
                prepared_hex: hex::encode(
                    &bytes[at.value_offset..at.value_offset + at.value_bytes],
                ),
                rule: "CNTFRQ_EL0 the machine presents, in Hz".into(),
            });
        }
    }
    Ok(patches)
}

fn device_tree_patches(tree: &DeviceTree, region: &Region) -> Result<Vec<Patch>> {
    let mut patches = vec![];
    let slots: &[(&str, &str, PatchSource, bool, Encoding, &str)] = &[
        (
            "/chosen",
            "dram-size",
            PatchSource::DramSize,
            false,
            Encoding::U64Le,
            "installed guest DRAM bytes",
        ),
        (
            "/chosen",
            "random-seed",
            PatchSource::Entropy,
            true,
            Encoding::Bytes,
            "random bytes",
        ),
        (
            "/chosen",
            "cl4-entropy",
            PatchSource::Entropy,
            true,
            Encoding::Bytes,
            "random bytes",
        ),
        (
            "/chosen/hibernation",
            "key-sptm-ctrr",
            PatchSource::Entropy,
            true,
            Encoding::Bytes,
            "random bytes",
        ),
        (
            "/chosen/hibernation",
            "key-xnu-ctrr",
            PatchSource::Entropy,
            true,
            Encoding::Bytes,
            "random bytes",
        ),
        (
            "/vram",
            "reg",
            PatchSource::Framebuffer,
            false,
            Encoding::Bytes,
            "u64 framebuffer base, u64 framebuffer bytes",
        ),
    ];
    let bytes = tree.serialize();
    for &(path, property, source, required, encoding, rule) in slots {
        let Ok(at) = tree.locate(path, property) else {
            bail!("DeviceTree has no patch slot {path} {property}");
        };
        patches.push(Patch {
            source,
            required,
            region: region.name.clone(),
            file: region.file.clone(),
            file_offset: at.value_offset as u64,
            bytes: at.value_bytes as u64,
            encoding,
            field: format!("{path} {property}"),
            prepared_hex: hex::encode(&bytes[at.value_offset..at.value_offset + at.value_bytes]),
            rule: rule.into(),
        });
    }
    // Native IOMobileFramebufferAP::allocate_carveout reads these capacities
    // (original mac13j VA 0xfffffe000ad95600..ad95638).
    // The same runtime Framebuffer supplies Video and these scalar slots;
    // never retain the physical board's 4096x2160 capacity for another GOP.
    for profile in stela_runtime::machine::soc::EXTERNAL_OUTPUTS
        .iter()
        .filter(|p| p.admitted)
    {
        let path = format!("/arm-io/{}", profile.pipe);
        let Some(pipe) = tree.node(&path).filter(|node| {
            node.property("compatible").is_some_and(|p| {
                p.value
                    .split(|&b| b == 0)
                    .any(|name| name == profile.compatible.as_bytes())
            })
        }) else {
            continue;
        };
        let geometry = ["framebuffer-width", "framebuffer-height"];
        if geometry.iter().all(|name| pipe.property(name).is_none()) {
            continue;
        }
        for property in geometry {
            let at = tree.locate(&path, property)?;
            ensure!(
                at.value_bytes == 4,
                "{path} {property} is not one native u32"
            );
            patches.push(Patch {
                source: PatchSource::Framebuffer,
                required: true,
                region: region.name.clone(),
                file: region.file.clone(),
                file_offset: at.value_offset as u64,
                bytes: 4,
                encoding: Encoding::Bytes,
                field: format!("{path} {property}"),
                prepared_hex: hex::encode(&bytes[at.value_offset..at.value_offset + 4]),
                rule: "the actual single native GOP scanout dimensions, also used by boot_args.Video and the DCP".into(),
            });
        }
    }
    Ok(patches)
}

/// iBoot's NOR hand-off: the machine replaces the prepared empty bank with
/// its persistent NOR's current bank; without one the prepared bank stands
/// and variables last one boot.
fn nvram_patches(tree: &DeviceTree, region: &Region) -> Result<Vec<Patch>> {
    let bytes = tree.serialize();
    ["nvram-proxy-data", "nvram-current-bank"]
        .into_iter()
        .map(|property| {
            let at = tree.locate("/chosen", property)?;
            Ok(Patch {
                source: PatchSource::Nvram,
                required: false,
                region: region.name.clone(),
                file: region.file.clone(),
                file_offset: at.value_offset as u64,
                bytes: at.value_bytes as u64,
                encoding: Encoding::Bytes,
                field: format!("/chosen {property}"),
                prepared_hex: hex::encode(
                    &bytes[at.value_offset..at.value_offset + at.value_bytes],
                ),
                rule: "the persistent NOR's newest valid NVRAM bank and its index".into(),
            })
        })
        .collect()
}

fn boot_args_patches(region: &Region, bytes: &[u8]) -> Vec<Patch> {
    use boot_args::offset;
    let fields: &[(&str, usize, usize, PatchSource, Encoding, &str)] = &[
        (
            "memSize",
            offset::MEM_SIZE,
            8,
            PatchSource::DramSize,
            Encoding::U64Le,
            "dram-base + guest DRAM bytes - physBase",
        ),
        (
            "memSizeActual",
            offset::MEM_SIZE_ACTUAL,
            8,
            PatchSource::DramSize,
            Encoding::U64Le,
            "guest DRAM bytes",
        ),
        (
            "Video.v_baseAddr",
            offset::VIDEO_BASE,
            8,
            PatchSource::Framebuffer,
            Encoding::U64Le,
            "framebuffer guest physical address",
        ),
        (
            "Video.v_display",
            offset::VIDEO_DISPLAY,
            8,
            PatchSource::Framebuffer,
            Encoding::U64Le,
            "1 for a graphical boot, 0 with -v (m1n1 set_bootargs)",
        ),
        (
            "Video.v_rowBytes",
            offset::VIDEO_ROW_BYTES,
            8,
            PatchSource::Framebuffer,
            Encoding::U64Le,
            "bytes per scanline",
        ),
        (
            "Video.v_width",
            offset::VIDEO_WIDTH,
            8,
            PatchSource::Framebuffer,
            Encoding::U64Le,
            "pixels",
        ),
        (
            "Video.v_height",
            offset::VIDEO_HEIGHT,
            8,
            PatchSource::Framebuffer,
            Encoding::U64Le,
            "pixels",
        ),
        (
            "Video.v_depth",
            offset::VIDEO_DEPTH,
            8,
            PatchSource::Framebuffer,
            Encoding::U64Le,
            "bits per pixel in bits 0..8",
        ),
        (
            "CommandLine",
            offset::COMMAND_LINE,
            boot_args::BOOT_LINE_LENGTH,
            PatchSource::BootArgs,
            Encoding::CString,
            "kernel boot-args",
        ),
    ];
    fields
        .iter()
        .map(|&(field, at, length, source, encoding, rule)| Patch {
            source,
            required: false,
            region: region.name.clone(),
            file: region.file.clone(),
            file_offset: at as u64,
            bytes: length as u64,
            encoding,
            field: format!("boot_args.{field}"),
            prepared_hex: hex::encode(&bytes[at..at + length]),
            rule: rule.into(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel_collection::tests::{BASE, Builder};
    use object::macho;

    const PAGE: u64 = PAGE_BYTES;

    fn ordered_region_fixture(optional_images: bool) -> Vec<Region> {
        // Spell the ABI fixture independently of the preparer's placement list.
        let names = [
            "TXM-ro",
            "TXM-rx",
            "TXM-bx",
            "TrustCache",
            "AuxKC-ro",
            "AuxKC-rx",
            "BootKC-rx",
            "BootKC-bx",
            "BootKC-ro",
            "BootKC-rs",
            "CL4-rx",
            "CL4-ro",
            "DeviceTree",
            "SPTM-ro",
            "SPTM-rx",
            "SPTM-rw",
        ];
        names
            .into_iter()
            .filter(|name| {
                optional_images || !(name.starts_with("AuxKC") || name.starts_with("CL4"))
            })
            .enumerate()
            .map(|(index, name)| Region {
                name: name.into(),
                file: "fixture".into(),
                file_offset: 0,
                bytes: PAGE,
                guest_pa: 0x8_0000_0000 + index as u64 * PAGE,
                memory_bytes: PAGE,
                sha256: String::new(),
                virtual_address: None,
            })
            .collect()
    }

    #[test]
    fn sptm_order_accepts_optional_images_and_an_arbitrary_prefix() -> Result<()> {
        for optional_images in [false, true] {
            let mut regions = ordered_region_fixture(optional_images);
            validate_sptm_region_order(&regions)?;
            // A retained manifest precedes the first constrained image. SPTM
            // constrains adjacency, not the first image's absolute address.
            for region in &mut regions {
                region.guest_pa += 7 * PAGE;
            }
            let mut prefix = regions[0].clone();
            prefix.name = "BootManifest".into();
            prefix.guest_pa -= PAGE;
            regions.insert(0, prefix);
            validate_sptm_region_order(&regions)?;
        }
        Ok(())
    }

    #[test]
    fn sptm_order_rejects_a_payload_inserted_inside_the_image_sequence() {
        let mut regions = ordered_region_fixture(false);
        let index = regions.iter().position(|r| r.name == "DeviceTree").unwrap();
        let mut inserted = regions[index].clone();
        inserted.name = "BootManifest".into();
        for region in &mut regions[index..] {
            region.guest_pa += PAGE;
        }
        regions.insert(index, inserted);
        let error = validate_sptm_region_order(&regions)
            .unwrap_err()
            .to_string();
        assert!(error.contains("DeviceTree"), "{error}");
        assert!(error.contains("BootKC-rs"), "{error}");
        assert!(error.contains("not immediately after"), "{error}");
    }

    #[test]
    fn sptm_order_rejects_missing_images_overlap_and_invalid_endpoints() {
        let mut regions = ordered_region_fixture(false);
        regions.retain(|r| r.name != "TrustCache");
        assert!(
            validate_sptm_region_order(&regions)
                .unwrap_err()
                .to_string()
                .contains("missing required region TrustCache")
        );
        let mut regions = ordered_region_fixture(true);
        regions[1].guest_pa -= PAGE;
        assert!(validate_sptm_region_order(&regions).is_err());
        for (start, length) in [(0, PAGE), (u64::MAX, 0), (u64::MAX - 2, PAGE)] {
            let mut regions = ordered_region_fixture(false);
            regions[0].guest_pa = start;
            regions[0].memory_bytes = length;
            assert!(validate_sptm_region_order(&regions).is_err());
        }
    }

    #[test]
    fn sptm_image_span_includes_link_edit_and_rejects_an_intervening_payload() -> Result<()> {
        let mut regions = ordered_region_fixture(false);
        let last = regions.last().unwrap();
        let mut link_edit = last.clone();
        link_edit.name = "SPTM-le".into();
        link_edit.guest_pa += link_edit.memory_bytes;
        regions.push(link_edit);
        let span = sptm_image_span(&regions)?;
        assert_eq!(span.end - span.start, 4 * PAGE);
        assert_eq!(span.end, regions.last().unwrap().guest_pa + PAGE);

        // The original 16-record table ends at SPTM-rw. A later payload
        // before link-edit passes that check but invalidates SPTM-rm.
        for adjustment in [PAGE, 0_u64.wrapping_sub(PAGE)] {
            let mut bad = regions.clone();
            let link_edit = bad.last_mut().unwrap();
            link_edit.guest_pa = link_edit.guest_pa.wrapping_add(adjustment);
            validate_sptm_region_order(&bad)?;
            let error = sptm_image_span(&bad).unwrap_err().to_string();
            assert!(error.contains("SPTM-le"), "{error}");
        }
        regions.pop();
        assert!(
            sptm_image_span(&regions)
                .unwrap_err()
                .to_string()
                .contains("missing region SPTM-le")
        );
        let mut link_edit = regions.last().unwrap().clone();
        link_edit.name = "SPTM-le".into();
        link_edit.guest_pa = u64::MAX - PAGE + 1;
        regions.push(link_edit);
        assert!(
            sptm_image_span(&regions)
                .unwrap_err()
                .to_string()
                .contains("range overflows")
        );
        Ok(())
    }

    fn source(component: &str) -> Source {
        Source {
            component: component.into(),
            member: format!("{component}.im4p"),
            container_sha256: "0".repeat(64),
            payload_type: "test".into(),
            description: "synthetic".into(),
            decoded_bytes: 0,
            decoded_sha256: "0".repeat(64),
        }
    }

    fn page(fill: u8) -> Vec<u8> {
        vec![fill; PAGE as usize]
    }

    fn kernel() -> Vec<u8> {
        Builder::new(macho::MH_FILESET)
            .segment("__TEXT", PAGE, &page(0))
            .segment("__DATA_SPTM", PAGE, &page(1))
            .segment("__TEXT_EXEC", PAGE, &page(2))
            .segment("__TEXT_BOOT_EXEC", PAGE, &page(3))
            .segment("__PRELINK_INFO", PAGE, &page(4))
            .segment("__DATA", PAGE, &page(5))
            .segment("__LINKEDIT", PAGE, &page(6))
            .fileset("com.apple.kernel", BASE)
            .thread(BASE + 3 * PAGE)
            .build()
    }

    fn sptm() -> Vec<u8> {
        Builder::new(macho::MH_EXECUTE)
            .segment("__TEXT", PAGE, &page(0))
            .segment("__TEXT_EXEC", PAGE, &page(7))
            .segment("__DATA", PAGE, &page(8))
            .segment("__LINKEDIT", PAGE, &[9; 0x20])
            .thread(BASE + PAGE + 0x388)
            .build()
    }

    fn txm() -> Vec<u8> {
        Builder::new(macho::MH_EXECUTE)
            .segment("__TEXT", PAGE, &page(0))
            .segment("__TEXT_EXEC", PAGE, &page(10))
            .segment("__TEXT_BOOT_EXEC", PAGE, &page(11))
            .segment("__DATA", PAGE, &page(12))
            .segment("__LINKEDIT", PAGE, &[13; 0x20])
            .thread(BASE + 2 * PAGE)
            .build()
    }

    fn device_tree() -> Vec<u8> {
        let mut tree = DeviceTree {
            root: crate::apple_device_tree::Node::named("device-tree").unwrap(),
        };
        for child in ["chosen", "cpus", "vram", "pram"] {
            tree.ensure_child("/", child).unwrap();
        }
        tree.ensure_child("/chosen", "memory-map").unwrap();
        lock_regs::tests::template(&mut tree, false).unwrap();
        tree.ensure_child("/cpus", "cpu0").unwrap();
        tree.set_property("/cpus/cpu0", "state", b"waiting\0".to_vec())
            .unwrap();
        tree.set_property("/vram", "reg", vec![0; 16]).unwrap();
        tree.set_property("/pram", "reg", vec![0; 16]).unwrap();
        tree.set_property("/chosen", "random-seed", vec![0; 0x100])
            .unwrap();
        tree.set_property("/chosen", "cl4-entropy", vec![0; 0xc0])
            .unwrap();
        for index in 0..17 {
            tree.set_property(
                "/chosen/memory-map",
                &format!("MemoryMapReserved-{index}"),
                vec![0; 16],
            )
            .unwrap();
        }
        let chosen = tree.node_mut("/chosen").unwrap();
        chosen
            .set_property(
                "software-behavior",
                b"syscfg/SwBh/0x10,zeroes/0x10\0".to_vec(),
            )
            .unwrap();
        chosen
            .set_property(
                "mac-address-wifi0",
                b"macaddr/wifiaddr,syscfg/WMac/6\0".to_vec(),
            )
            .unwrap();
        chosen
            .set_property("repair-status", b"syscfg/rpcp\0".to_vec())
            .unwrap();
        for property in &mut chosen.properties[3..] {
            property.placeholder = true;
        }
        // Security inputs the template carries, with typed manifest slots.
        for (name, bytes) in [
            ("boot-manifest-hash", 48),
            ("effective-production-status-ap", 4),
            ("effective-security-mode-ap", 4),
            ("sepfw-load-at-boot", 4),
            ("osenvironment", 32),
        ] {
            tree.set_property("/chosen", name, vec![0; bytes]).unwrap();
        }
        tree.set_property("/chosen", "cs-system-policy", b"default\0".to_vec())
            .unwrap();
        tree.ensure_child("/chosen", "manifest-properties").unwrap();
        for (slot, bytes) in [
            ("UnusedIntegerProperty0", 8),
            ("UnusedIntegerProperty1", 8),
            ("UnusedBooleanProperty0", 4),
            ("UnusedBooleanProperty1", 4),
        ] {
            tree.set_property("/chosen/manifest-properties", slot, vec![0; bytes])
                .unwrap();
        }
        tree.serialize()
    }

    fn boot_manifest() -> Vec<u8> {
        use crate::im4m::tests::{der, entry, manifest};
        manifest(
            &[
                entry("BORD", &der(&[0x02], &[0x2e])),
                entry("CPRO", &der(&[0x01], &[0xff])),
                entry("CSEC", &der(&[0x01], &[0xff])),
                entry("SDOM", &der(&[0x02], &[1])),
            ],
            &[entry("test", &der(&[0x31], &[]))],
        )
    }

    #[test]
    fn die_count_follows_each_chips_iboot_rule() -> Result<()> {
        let tree = |dies: &[Option<u32>]| -> Result<DeviceTree> {
            let mut tree = DeviceTree {
                root: crate::apple_device_tree::Node::named("device-tree")?,
            };
            tree.ensure_child("/", "cpus")?;
            tree.ensure_child("/", "arm-io")?;
            for (index, die) in dies.iter().enumerate() {
                let cpu = format!("cpu{index}");
                tree.ensure_child("/cpus", &cpu)?;
                let path = format!("/cpus/{cpu}");
                tree.set_property(&path, "state", b"waiting\0".to_vec())?;
                if let Some(die) = die {
                    // The templates carry die-id as a 64-bit cell pair.
                    tree.set_property(&path, "die-id", u64::from(*die).to_le_bytes().to_vec())?;
                }
            }
            Ok(tree)
        };
        let two = [Some(0), Some(0), Some(1), Some(1)];
        let one = [Some(0), Some(0)];
        let count = |dies: &[Option<u32>], chip| -> Result<Option<u32>> {
            let mut tree = tree(dies)?;
            assert_eq!(set_die_count(&mut tree, Some(chip))?, None);
            Ok(tree
                .property("/arm-io", "die-count")
                .map(|p| u32::from_le_bytes(p.value[..].try_into().unwrap())))
        };
        // The iBoots without the row, and the chip rules of those with it.
        for chip in NO_DIE_COUNT {
            assert_eq!(count(&one, chip)?, None);
        }
        for chip in ULTRAS {
            assert_eq!(count(&two, chip)?, Some(2));
            assert!(count(&one, chip).is_err());
        }
        for chip in [0x6000, 0x6021, 0x6031, 0x8122, 0x8152] {
            assert_eq!(count(&one, chip)?, Some(1));
            assert_eq!(count(&[None, None], chip)?, Some(1));
            assert!(count(&two, chip).is_err());
        }
        // The T6050's fused count is the variant's remaining CPU dies.
        assert_eq!(count(&two, FUSED_DIES)?, Some(2));
        assert_eq!(count(&one, FUSED_DIES)?, Some(1));
        let mut unknown = tree(&one)?;
        assert!(set_die_count(&mut unknown, None)?.is_some());
        assert!(unknown.property("/arm-io", "die-count").is_none());
        let mut malformed = tree(&[Some(1)])?;
        malformed.set_property("/cpus/cpu0", "die-id", vec![1])?;
        assert!(set_die_count(&mut malformed, Some(0x6002)).is_err());
        Ok(())
    }

    #[test]
    fn fill_in_sources_follow_iboots_resolver() -> Result<()> {
        let options = Options {
            syscfg: BTreeMap::from([("ARXN".to_owned(), vec![9; 2])]),
            ..Options::default()
        };
        let value = |alternative: &str| alternative_value(alternative, alternative, &options);
        assert_eq!(value("hex/0200fA")?, Some(vec![2, 0, 0xfa]));
        assert_eq!(value("hex/0102/0x4")?, Some(vec![1, 2, 0, 0]));
        for refused in [
            "hex/012",
            "hex/0x12",
            "hex/+1",
            "hex/010203/0x2",
            "string/x",
        ] {
            assert!(value(refused).is_err(), "{refused}");
        }
        // No keybag provider is modelled: the source yields nothing.
        assert_eq!(value("syscfg-mismatch/ARXN")?, None);
        assert_eq!(value("syscfg/ARXN")?, Some(vec![9; 2]));
        Ok(())
    }

    #[test]
    fn syscfg_recipe_lengths_truncate_pad_and_preserve_the_source() -> Result<()> {
        let options = Options {
            syscfg: BTreeMap::from([("Test".to_owned(), vec![1, 2, 3, 4])]),
            ..Options::default()
        };
        let value = |recipe: &str| alternative_value(recipe, recipe, &options);
        assert_eq!(value("syscfg/Test")?, Some(vec![1, 2, 3, 4]));
        assert_eq!(value("syscfg/Test/0x2")?, Some(vec![1, 2]));
        assert_eq!(value("syscfg/Test/4")?, Some(vec![1, 2, 3, 4]));
        assert_eq!(value("syscfg/Test/0x6")?, Some(vec![1, 2, 3, 4, 0, 0]));
        assert_eq!(value("syscfg/Test/0")?, Some(vec![]));
        assert_eq!(value("syscfg/None/0x2")?, None);
        assert!(value("syscfg/Test/no-size").is_err());
        assert_eq!(options.syscfg["Test"], [1, 2, 3, 4]);
        Ok(())
    }

    fn trust_cache() -> Vec<u8> {
        let mut module = 2u32.to_le_bytes().to_vec();
        module.extend([0; 16]);
        module.extend(1u32.to_le_bytes());
        module.extend([0xee; 24]);
        module
    }

    #[test]
    fn lays_out_sptm_regions_and_patch_slots() -> Result<()> {
        let (kernel, sptm, txm, tree, tc) = (kernel(), sptm(), txm(), device_tree(), trust_cache());
        let input = |bytes: &'static [u8], name: &str| Input {
            bytes,
            source: source(name),
        };
        let leak = |v: Vec<u8>| -> &'static [u8] { Box::leak(v.into_boxed_slice()) };
        let mut inputs = Inputs {
            target: Target {
                product_type: "Mac14,3".into(),
                device_class: "j473ap".into(),
                product_version: "27.0.1".into(),
                product_build: "26A434".into(),
                variant: "Customer Erase Install (IPSW)".into(),
                chip_id: Some(0x8112),
                board_id: Some(0x2e),
            },
            kernel_collection: input(leak(kernel), "KernelCache"),
            sptm: input(leak(sptm), "Ap,SecurePageTableMonitor"),
            txm: input(leak(txm), "Ap,TrustedExecutionMonitor"),
            device_tree: input(leak(tree), "DeviceTree"),
            static_trust_cache: input(leak(tc), "StaticTrustCache"),
            sep_firmware: None,
            boot_manifest: Some(input(leak(boot_manifest()), "BootManifest")),
            cryptex1_manifest: None,
            extra_trust_caches: vec![],
            board_firmware: vec![(
                "USB-C_HPM,47.bin".into(),
                input(leak(vec![1, 2, 3]), "BoardFirmware"),
            )],
            ramdisk: Some(input(leak(vec![0x5a; 100]), "RestoreRamDisk")),
            root_hash: None,
        };
        let options = Options {
            dram_base: 0x8_0000_0000,
            dram_size: 0x2_0000_0000,
            phys_base: 0x8_0000_0000,
            load_offset: 0,
            boot_args: "-v".into(),
            boot_cpu: "cpu0".into(),
            osenvironment: None,
            boot_command: None,
            root: None,
            ecid: None,
            timebase_frequency: 24_000_000,
            syscfg: BTreeMap::from([("SwBh".to_owned(), vec![7; 4])]),
            mac_addresses: BTreeMap::from([("wifiaddr".to_owned(), vec![2, 0, 0, 0, 0, 1])]),
            security: SecurityPolicy {
                mode: boot_policy::SecurityMode::Reduced,
                sip_bits: 0,
                sepfw_load_at_boot: None,
            },
            overlay: vec![OverlayProperty {
                path: "/chosen/lock-regs/amcc".into(),
                property: "aperture-count".into(),
                value: 1u32.to_le_bytes().to_vec(),
            }],
        };
        // DRAM must sit at the target board's base: an M2 Pro's placement is
        // refused for the M2, whose own base `placed_at` restores.
        let elsewhere = options.placed_at(Some(0x100_0000_0000));
        assert_eq!(
            (elsewhere.dram_base, elsewhere.phys_base),
            (0x100_0000_0000, 0x100_0000_0000)
        );
        let refusal = prepare(&inputs, &elsewhere).err().unwrap().to_string();
        assert!(
            refusal.contains("is not ApChipID 0x8112's 0x800000000"),
            "{refusal}"
        );
        assert_eq!(
            elsewhere.placed_at(inputs.dram_base()?).dram_base,
            options.dram_base
        );
        let bundle = prepare(&inputs, &options)?;
        let original = bundle
            .files
            .iter()
            .find(|(name, _)| name == ORIGINAL_DEVICE_TREE_FILE)
            .unwrap();
        assert_eq!(original.1, inputs.device_tree.bytes);
        assert!(
            !bundle
                .manifest
                .regions
                .iter()
                .any(|r| r.file == ORIGINAL_DEVICE_TREE_FILE)
        );
        // Origin is an independent loader input, not inferred from these
        // fixtures' OS environment or verbose-only command line.
        let origin_options = Options {
            boot_command: Some(handoff::BootCommand::TetheredRestore),
            ..options.clone()
        };
        let originated = prepare(&inputs, &origin_options)?;
        let origin_tree = DeviceTree::parse(
            &originated
                .files
                .iter()
                .find(|(name, _)| name == DEVICE_TREE_FILE)
                .unwrap()
                .1,
        )?;
        for (path, name) in [
            ("/chosen", "boot-command"),
            ("/chosen/handoff", "boot_type"),
        ] {
            assert_eq!(origin_tree.property(path, name).unwrap().as_u32(), Some(7));
        }
        assert!(
            !originated
                .manifest
                .unresolved
                .iter()
                .any(|gap| gap.starts_with("/chosen boot-command"))
        );
        // An owned ramdisk moves into the same bundle.
        let borrowed = inputs.ramdisk.take().expect("a ramdisk");
        let owned = OwnedRamdisk {
            bytes: borrowed.bytes.to_vec(),
            source: borrowed.source.clone(),
        };
        let moved = prepare_owned(&inputs, owned, &options)?;
        assert_eq!(
            serde_json::to_string(&moved.manifest)?,
            serde_json::to_string(&bundle.manifest)?
        );
        inputs.ramdisk = Some(borrowed);
        let twice = OwnedRamdisk {
            bytes: vec![1],
            source: source("RestoreRamDisk"),
        };
        assert!(prepare_owned(&inputs, twice, &options).is_err());
        // Board firmware travels unchanged under its guest file name, which
        // must not replace a bundle file.
        let firmware = bundle.files.iter().find(|(n, _)| n == "USB-C_HPM,47.bin");
        assert_eq!(firmware.map(|(_, b)| b.as_slice()), Some(&[1u8, 2, 3][..]));
        let supplied = core::mem::take(&mut inputs.board_firmware);
        inputs.board_firmware = vec![(KERNEL_FILE.into(), input(leak(vec![1]), "BoardFirmware"))];
        assert!(prepare(&inputs, &options).is_err());
        inputs.board_firmware = supplied;
        let manifest = &bundle.manifest;
        let names: Vec<_> = manifest.regions.iter().map(|r| r.name.as_str()).collect();
        let expected: Vec<_> = REGION_ORDER
            .iter()
            .copied()
            .filter(|n| !["SEPFW", lock_regs::CL4_DUMMY_PAGE].contains(n))
            .collect();
        assert_eq!(names, expected);
        // The M1 to M3 hand off no core lock registers.
        assert!(manifest.core_locks.is_none());
        // The original input manifest is retained byte for byte in the
        // read-only boot run, with an exact (not page-rounded) guest length.
        let manifest_region = manifest
            .regions
            .iter()
            .find(|r| r.name == "BootManifest")
            .unwrap();
        let original_manifest = inputs.boot_manifest.as_ref().unwrap().bytes;
        assert_eq!(
            bundle
                .files
                .iter()
                .find(|(n, _)| n == BOOT_MANIFEST_FILE)
                .unwrap()
                .1,
            original_manifest
        );
        let prepared_tree = DeviceTree::parse(
            &bundle
                .files
                .iter()
                .find(|(n, _)| n == DEVICE_TREE_FILE)
                .unwrap()
                .1,
        )?;
        assert_eq!(
            prepared_tree
                .property("/chosen/boot-object-manifests", "test")
                .unwrap()
                .value,
            range_value(manifest_region.guest_pa, original_manifest.len() as u64),
        );
        assert_eq!(
            prepared_tree
                .property("/chosen/secure-boot-hashes", "test")
                .unwrap()
                .value,
            im4m::sha384(original_manifest),
        );
        let protected = manifest.read_only_region.as_ref().unwrap();
        assert!(manifest_region.guest_pa >= protected.base);
        assert!(
            manifest_region.guest_pa + manifest_region.memory_bytes
                <= protected.base + protected.bytes
        );
        // Regions are page-aligned, ascending and non-overlapping.
        for pair in manifest.regions.windows(2) {
            assert!(pair[0].guest_pa + pair[0].memory_bytes <= pair[1].guest_pa);
            assert_eq!(pair[1].guest_pa % PAGE, 0);
        }
        let region = |name: &str| manifest.regions.iter().find(|r| r.name == name).unwrap();
        assert_eq!(manifest.entry.image, "SPTM");
        assert_eq!(
            manifest.entry.physical_address,
            region("SPTM-rx").guest_pa + 0x388
        );
        assert_eq!(manifest.entry_x0, region("BootArgs").guest_pa);
        let kc = manifest.images.iter().find(|i| i.name == "BootKC").unwrap();
        assert_eq!(kc.entry.physical_address, region("BootKC-bx").guest_pa);
        assert_eq!(region("SPTM-le").memory_bytes, PAGE);
        // iBoot's carveouts sit below physBase, which starts past them.
        let phys_base = manifest.options.phys_base;
        assert_eq!(phys_base, 0x8_0200_0000);
        assert_eq!(manifest.boot_args.phys_base, phys_base);
        assert_eq!(manifest.boot_args.mem_size, 0xa_0000_0000 - phys_base);
        assert!(manifest.regions[0].guest_pa >= phys_base);
        assert!(
            manifest
                .carveouts
                .iter()
                .all(|c| c.base >= 0x8_0000_0000 && c.base + c.bytes <= phys_base)
        );
        // CTRR-A covers the read-only run, ending where SPTM's data starts.
        let ctrr = manifest.read_only_region.unwrap();
        assert_eq!(ctrr.base, manifest.regions[0].guest_pa);
        assert_eq!(ctrr.base + ctrr.bytes, region("SPTM-rw").guest_pa);

        let file = |name: &str| &bundle.files.iter().find(|(n, _)| n == name).unwrap().1;
        let tree = DeviceTree::parse(file(DEVICE_TREE_FILE))?;
        let map = tree.node(MEMORY_MAP).unwrap();
        assert!(
            map.properties
                .iter()
                .all(|p| !p.name().starts_with(RESERVED_ENTRY_PREFIX))
        );
        let entry = |name: &str| map.property(name).unwrap().value.clone();
        let nvme = manifest.carveouts.iter().find(|c| c.id == 0x37).unwrap();
        assert_eq!(
            tree.property(carveouts::MEMORY_MAP, "region-id-55")
                .unwrap()
                .value,
            range_value(nvme.base, nvme.bytes)
        );
        // The panic region is XNU's panic buffer, below physBase.
        let panic = manifest.carveouts.iter().find(|c| c.id == 98).unwrap();
        assert_eq!(panic.bytes, 0x18_8000);
        assert_eq!(
            tree.property(carveouts::PRAM, "reg").unwrap().value,
            range_value(panic.base, panic.bytes)
        );
        assert_eq!(
            tree.property("/chosen", carveouts::PANIC_LOG_SIZE)
                .unwrap()
                .as_u32(),
            Some(0x18_8000)
        );
        assert_eq!(
            entry("TrustCache"),
            range_value(region("TrustCache").guest_pa, PAGE)
        );
        assert_eq!(entry("BootKC-entry"), range_value(3 * PAGE, 0));
        for name in ABSENT_SECURE_KERNEL {
            assert_eq!(entry(name), range_value(u64::MAX, u64::MAX));
        }
        assert_eq!(
            entry("SPTM-rm"),
            range_value(region("SPTM-ro").guest_pa, 4 * PAGE)
        );
        assert!(tree.placeholders().is_empty());
        assert_eq!(
            tree.property("/chosen", "mac-address-wifi0").unwrap().value,
            vec![2, 0, 0, 0, 0, 1]
        );
        let mut behavior = vec![7; 4];
        behavior.resize(16, 0);
        assert_eq!(
            tree.property("/chosen", "software-behavior").unwrap().value,
            behavior
        );
        assert!(tree.property("/chosen", "repair-status").is_none());
        for property in CPU_FREQUENCY_PROPERTIES {
            assert_eq!(
                tree.property("/cpus/cpu0", property).unwrap().as_u64(),
                Some(24_000_000)
            );
        }
        assert!(
            manifest
                .patches
                .iter()
                .any(|p| p.field == "/cpus/cpu0 timebase-frequency")
        );
        assert_eq!(
            tree.property("/cpus/cpu0", "state").unwrap().as_str(),
            Some("running")
        );
        assert_eq!(
            tree.property("/chosen", "chip-id").unwrap().as_u32(),
            Some(0x8112)
        );

        let args = BootArgs::decode(file(BOOT_ARGS_FILE))?;
        assert_eq!(
            args.device_tree,
            region("DeviceTree").guest_pa - args.phys_base + args.virt_base
        );
        assert_eq!(
            args.device_tree_length as usize,
            file(DEVICE_TREE_FILE).len()
        );
        assert_eq!(args.top_of_kernel_data, region("BootArgs").guest_pa + PAGE);
        assert_eq!(args.command_line, "-v");

        // Every patch addresses its prepared bytes in its file.
        for patch in &manifest.patches {
            let bytes = file(&patch.file);
            let at = patch.file_offset as usize;
            assert_eq!(
                hex::encode(&bytes[at..at + patch.bytes as usize]),
                patch.prepared_hex,
                "{}",
                patch.field
            );
        }
        // Every region hash covers its file bytes.
        for region in &manifest.regions {
            let at = region.file_offset as usize;
            assert_eq!(
                sha256(&file(&region.file)[at..at + region.bytes as usize]),
                region.sha256
            );
        }
        assert!(manifest.unresolved.iter().any(|u| u.starts_with("SEPFW")));
        let ramdisk = region("RAMDisk");
        assert_eq!((ramdisk.bytes, ramdisk.memory_bytes), (100, PAGE));
        assert_eq!(
            map.property("RAMDisk").unwrap().value,
            range_value(ramdisk.guest_pa, PAGE)
        );
        assert!(!manifest.unresolved.iter().any(|u| u.contains("lock-regs")));
        assert!(manifest.unresolved.iter().any(|u| u.contains("lp-spih")));
        assert_eq!(
            tree.property("/chosen/asmb", "lp-smb0").unwrap().as_u32(),
            Some(1)
        );
        assert_eq!(
            tree.property("/chosen/lock-regs/amcc", "aperture-count")
                .unwrap()
                .as_u32(),
            Some(1)
        );
        assert_eq!(
            tree.property("/chosen/manifest-properties", "BORD")
                .unwrap()
                .as_u64(),
            Some(0x2e)
        );
        assert!(
            manifest
                .security
                .iter()
                .any(|d| d.property == "boot-manifest-hash")
        );
        // The mount's reader accepts the manifest, revision and all, and
        // reproduces the layout.
        assert_eq!(manifest.revision, REVISION);
        let json = serde_json::to_vec(manifest)?;
        let consumed = stela_runtime::boot_bundle::Manifest::parse(&json)?;
        let mut changed_source = file(ORIGINAL_DEVICE_TREE_FILE).clone();
        changed_source[0] ^= 1;
        assert!(
            consumed
                .verify(&|name| {
                    Some(if name == ORIGINAL_DEVICE_TREE_FILE {
                        changed_source.as_slice()
                    } else {
                        file(name).as_slice()
                    })
                })
                .is_err()
        );
        let verified = consumed.verify(&|name| Some(file(name).as_slice()))?;
        let span = (manifest.top_of_kernel_data - options.dram_base) as usize;
        let mut ram = vec![0u8; span];
        let machine = stela_runtime::boot_bundle::Machine {
            dram_base: options.dram_base,
            ram_bytes: span as u64,
            timebase_hz: 24_000_000,
            framebuffer: None,
            boot_args: None,
            nvram: None,
        };
        let image = verified.load(
            &machine,
            &mut |b| {
                b.fill(7);
                Ok(())
            },
            &mut |pa, bytes| {
                let at = (pa - options.dram_base) as usize;
                ram[at..at + bytes.len()].copy_from_slice(bytes);
                true
            },
        )?;
        assert_eq!(image.entry_pa, manifest.entry.physical_address);
        assert_eq!(image.x0, manifest.entry_x0);
        let tc = region("TrustCache");
        let at = (tc.guest_pa - options.dram_base) as usize;
        assert_eq!(
            &ram[at..at + tc.bytes as usize],
            file(TRUST_CACHE_FILE).as_slice()
        );
        assert!(image.kept.iter().all(|field| field.contains("Video")
            || field.contains("vram")
            || field.contains("CommandLine")));

        // An M4 bundle places iBoot's dummy CL4 page and states the core
        // lock registers SPTM checks, which the mount's reader takes.
        let m2 = (inputs.target.clone(), inputs.device_tree.bytes);
        let m2_manifest = inputs.boot_manifest.take();
        let mut m4_tree = DeviceTree::parse(inputs.device_tree.bytes)?;
        m4_tree.ensure_child("/", "arm-io")?;
        m4_tree.ensure_child("/arm-io", "mcc")?;
        m4_tree.set_property(
            "/arm-io/mcc",
            "dram-base",
            0x100_0000_0000u64.to_le_bytes().to_vec(),
        )?;
        inputs.device_tree.bytes = leak(m4_tree.serialize());
        inputs.target.chip_id = Some(0x8132);
        let m4_options = options.placed_at(inputs.dram_base()?);
        let m4_bundle = prepare(&inputs, &m4_options)?;
        inputs.target.chip_id = Some(0x8142);
        let m5_bundle = prepare(&inputs, &m4_options)?;
        (inputs.target, inputs.device_tree.bytes) = m2;
        inputs.boot_manifest = m2_manifest;
        let m4_manifest = &m4_bundle.manifest;
        let page = m4_manifest
            .regions
            .iter()
            .find(|r| r.name == lock_regs::CL4_DUMMY_PAGE)
            .unwrap();
        assert_eq!(page.memory_bytes, lock_regs::CL4_DUMMY_PAGE_BYTES as u64);
        let core_locks = m4_manifest.core_locks.as_ref().unwrap();
        let ctxr_b = core_locks
            .locked
            .iter()
            .find(|locked| locked.region == ctrr::Region::CtxrB)
            .unwrap();
        assert_eq!(
            (ctxr_b.first, ctxr_b.last),
            (page.guest_pa, page.guest_pa + page.memory_bytes - 1)
        );
        // The policy enables kernel CTRR, so CTRR-D is locked too.
        assert_eq!(core_locks.locked.len(), 6);
        let consumed =
            stela_runtime::boot_bundle::Manifest::parse(&serde_json::to_vec(m4_manifest)?)?;
        assert_eq!(consumed.core_locks.as_ref(), Some(core_locks));
        assert_eq!(core_locks.tag_offset, 0);
        // An M5 bundle also locks TAG_OFFSET_EL2 at the top of the managed
        // range, which ends at DRAM's end.
        let dram_end = m4_options.dram_base + m4_options.dram_size;
        assert_eq!(
            m5_bundle.manifest.core_locks.unwrap().tag_offset,
            tag_storage::LOCK | (dram_end - tag_storage::bytes(m4_options.dram_size))
        );

        // A RAM disk image root: DiskImages gets the placed region from
        // /chosen, and boot-uuid names the volume.
        const VOLUME: &str = "11111111-2222-3333-4444-555555555555";
        let image_root = Options {
            boot_args: "-v rp0=file:///a.dmg".into(),
            root: Some(root_selection::Root::RamImage {
                volume: VOLUME.into(),
            }),
            ..options.clone()
        };
        let imaged = prepare(&inputs, &image_root)?;
        let file = |name: &str| &imaged.files.iter().find(|(n, _)| n == name).unwrap().1;
        let tree = DeviceTree::parse(file(DEVICE_TREE_FILE))?;
        let ramdisk = imaged
            .manifest
            .regions
            .iter()
            .find(|r| r.name == "RAMDisk")
            .unwrap();
        let chosen = |name: &str| tree.property("/chosen", name).map(|p| p.value.clone());
        assert_eq!(
            chosen(root_selection::BOOT_RAMDMG_SIZE),
            Some(100u64.to_le_bytes().to_vec())
        );
        let mut extent = ramdisk.guest_pa.to_le_bytes().to_vec();
        extent.extend(100u64.to_le_bytes());
        assert_eq!(chosen(root_selection::BOOT_RAMDMG_EXTENTS), Some(extent));
        assert_eq!(
            chosen(root_selection::BOOT_UUID),
            Some(format!("{VOLUME}\0").into_bytes())
        );
        // A memory-device root argument contradicts it, and rd=md0 with an
        // image root is refused on any root.
        let with_rd = Options {
            boot_args: "-v rd=md0 rp0=file:///a.dmg".into(),
            ..image_root.clone()
        };
        let refusal = prepare(&inputs, &with_rd).err().unwrap().to_string();
        assert!(refusal.contains("memory device md0"), "{refusal}");
        let rootdev = Options {
            boot_args: "-v rootdev=disk1s1".into(),
            ..image_root.clone()
        };
        assert!(prepare(&inputs, &rootdev).is_err());
        let ramdisk_pivot = Options {
            boot_args: "-v rd=md0 rp0=file:///a.dmg".into(),
            root: Some(root_selection::Root::Ramdisk),
            ..options.clone()
        };
        assert!(prepare(&inputs, &ramdisk_pivot).is_err());
        let ramdisk = inputs.ramdisk.take();
        assert!(prepare(&inputs, &image_root).is_err());
        inputs.ramdisk = ramdisk;

        // With SEP firmware, SEPFW is a reserved, zero-filled staging region
        // between RAMDisk and BootArgs that holds the image's IMG4 container;
        // the image itself travels as a bundle file for the run-time load.
        let sep = vec![0x5e; 3 * PAGE as usize];
        inputs.sep_firmware = Some(input(leak(sep.clone()), "RestoreSEP"));
        let staged = prepare(&inputs, &options)?;
        inputs.sep_firmware = None;
        let names: Vec<_> = staged.manifest.regions.iter().map(|r| &*r.name).collect();
        let expected: Vec<_> = REGION_ORDER
            .iter()
            .copied()
            .filter(|n| *n != lock_regs::CL4_DUMMY_PAGE)
            .collect();
        assert_eq!(names, expected);
        let sepfw = staged
            .manifest
            .regions
            .iter()
            .find(|r| r.name == "SEPFW")
            .unwrap();
        assert_eq!(sepfw.bytes, 0);
        assert_eq!(sepfw.memory_bytes, 4 * PAGE);
        assert!(sepfw.memory_bytes >= stela_runtime::img4::container(&sep).len() as u64);
        let file = |name: &str| &staged.files.iter().find(|(n, _)| n == name).unwrap().1;
        assert_eq!(file(SEP_FILE), &sep);
        let tree = DeviceTree::parse(file(DEVICE_TREE_FILE))?;
        assert_eq!(
            tree.property(MEMORY_MAP, "SEPFW").unwrap().value,
            range_value(sepfw.guest_pa, sepfw.memory_bytes)
        );
        assert!(
            !staged
                .manifest
                .unresolved
                .iter()
                .any(|u| u.starts_with("SEPFW"))
        );

        // A manifest for another board is refused.
        let mut other = Inputs { ..inputs };
        other.target.board_id = Some(0x24);
        assert!(prepare(&other, &options).is_err());
        Ok(())
    }
}
