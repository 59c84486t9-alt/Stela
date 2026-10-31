//! `bundle.json`, as `stela-dev boot prepare` writes it and the UEFI mount reads
//! it (`docs/design/runtime.md#kernel-boot-bundle`). Fields that only the
//! preparation report uses default when absent, so hand-authored bundles
//! need only what the mount reads.
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use serde::{Deserialize, Serialize};

/// Schema4 binds the selected boot CPU to the original and prepared ADTs.
pub const SCHEMA_VERSION: u32 = 4;

/// One Apple input, kept with the identity of the restore member it came
/// from. File verification alone does not authenticate its container or an
/// Apple signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    pub component: String,
    pub member: String,
    pub container_sha256: String,
    pub payload_type: String,
    pub description: String,
    pub decoded_bytes: u64,
    pub decoded_sha256: String,
}

/// Board facts taken from the selected restore identity, never inferred
/// from template DeviceTree IDs or from a source filename.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub product_type: String,
    pub device_class: String,
    pub product_version: String,
    pub product_build: String,
    pub variant: String,
    pub chip_id: Option<u32>,
    pub board_id: Option<u32>,
}

/// One DeviceTree value supplied from outside the restore image, such as a
/// device model's register map; nodes along `path` are created as needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayProperty {
    pub path: String,
    pub property: String,
    #[serde(with = "hex_bytes")]
    pub value: Vec<u8>,
}

/// Bytes as lowercase hex digits.
mod hex_bytes {
    use alloc::{string::String, vec::Vec};
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        let text: String = bytes
            .iter()
            .flat_map(|byte| {
                [
                    DIGITS[usize::from(byte >> 4)],
                    DIGITS[usize::from(byte & 15)],
                ]
            })
            .map(char::from)
            .collect();
        serializer.serialize_str(&text)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        let digit = |c: u8| {
            char::from(c)
                .to_digit(16)
                .and_then(|d| u8::try_from(d).ok())
                .ok_or_else(|| D::Error::custom("not a hex digit"))
        };
        let (pairs, rest) = text.as_bytes().as_chunks::<2>();
        if !rest.is_empty() {
            return Err(D::Error::custom("odd hex digit count"));
        }
        pairs
            .iter()
            .map(|&[high, low]| Ok((digit(high)? << 4) | digit(low)?))
            .collect()
    }
}

/// How the boot policy admits boot objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityMode {
    /// `smb0`: globally signed boot objects are admitted.
    Reduced,
    /// `smb0` and `smb1`: objects signed with the LocalPolicy key as well.
    Permissive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub mode: SecurityMode,
    /// `sip0`: System Integrity Protection bits (`csr-active-config`).
    pub sip_bits: u64,
    /// Overrides the template's `/chosen sepfw-load-at-boot`.
    pub sepfw_load_at_boot: Option<bool>,
    /// The auxiliary kernel collection this boot admits.
    pub kexts: Option<KextGrant>,
}

/// What a LocalPolicy's kext grant (`local_policy::Kexts`) names, as
/// hexadecimal SHA-384 digests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KextGrant {
    pub approved: String,
    pub collection: String,
    pub receipt: String,
}

/// Reduced Security with SIP enabled.
impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            mode: SecurityMode::Reduced,
            sip_bits: 0,
            sepfw_load_at_boot: None,
            kexts: None,
        }
    }
}

/// An OS environment iBoot boots. iBoot's setter (26A434 J473 iBoot
/// 0x24e60) writes the name as `/chosen osenvironment` and applies the
/// `/osenvironments/<name>-environment` child; its callers pass
/// `diagnostics`, `kcgen`, `recoveryos`, `upgrade` and, by darwinOS boot
/// kind, `darwinos-ramdisk` or `macos-darwinos` (table 0x170838). The
/// kernel and TXM also compare `recovery`, whose child the J473 DeviceTree
/// has, but no J473 iBoot caller passes it. macOS itself is the absence of
/// an environment: the template's empty value stays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
        alloc::format!("{}-environment", self.name())
    }

    /// The environment whose [`Self::name`] is `name`.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.name() == name)
    }
}

/// The previous boot stage's command, not the OS environment or root
/// device. Known codes come from 26A434 J473 LLB's dispatch table at raw
/// 0x1544e8 (0x38-byte entries, command at +0x30), or its received-iBEC path
/// at 0x132c/0x2075c. The setter at 0xc76c0 records the byte at handoff
/// +0xc; iBoot imports that byte at 0xea4c8 and publishes it without
/// remapping. Values whose origin is unknown remain unrepresentable here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum BootCommand {
    Fsboot = 1,
    Kcgen = 2,
    Upgrade = 3,
    RecoverSystem = 4,
    TetheredRestore = 7,
    FieldDiags = 8,
    FsbootSafe = 9,
    Recover = 11,
    FieldDiagsPaired = 13,
    PostUpgrade = 14,
}

impl TryFrom<u8> for BootCommand {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Fsboot),
            2 => Ok(Self::Kcgen),
            3 => Ok(Self::Upgrade),
            4 => Ok(Self::RecoverSystem),
            7 => Ok(Self::TetheredRestore),
            8 => Ok(Self::FieldDiags),
            9 => Ok(Self::FsbootSafe),
            11 => Ok(Self::Recover),
            13 => Ok(Self::FieldDiagsPaired),
            14 => Ok(Self::PostUpgrade),
            _ => Err("boot command has no modeled previous-stage origin"),
        }
    }
}

/// The volume the kernel roots from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum Root {
    /// The System volume of `volume_group`, booting from its Preboot
    /// directory `boot_hash`.
    System {
        volume_group: String,
        boot_hash: String,
    },
    /// The Recovery volume paired with `volume_group`, booting from its
    /// directory `<volume_group>/boot/<boot_hash>`.
    PairedRecovery {
        volume_group: String,
        recovery_volume: String,
        boot_hash: String,
    },
    /// System Recovery: the RecoveryOSContainer's volume `volume`, booting
    /// from its directory `<directory>/boot/<boot_hash>`. It pairs with no
    /// installed system, so only `boot-uuid` names the root (Inferred:
    /// without `apfs-preboot-uuid` and `associated-volume-group`,
    /// AppleFileSystemDriver roots from the volume `boot-uuid` names).
    SystemRecovery {
        volume: String,
        directory: String,
        boot_hash: String,
    },
    /// A ramdisk; no installed volume.
    Ramdisk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Options {
    pub dram_base: u64,
    pub dram_size: u64,
    /// Lowest physical address handed to the kernel (`boot_args.physBase`);
    /// a bundle raises it past iBoot's carveouts.
    pub phys_base: u64,
    /// First region's distance above `phys_base`.
    #[serde(default)]
    pub load_offset: u64,
    #[serde(default)]
    pub boot_args: String,
    /// Explicit `/cpus` child name; absent selects the first CPU in the
    /// original DeviceTree order.
    #[serde(default)]
    pub boot_cpu: Option<String>,
    /// The generic timer rate (`CNTFRQ_EL0`) the machine presents.
    #[serde(default)]
    pub timebase_frequency: u64,
    /// Board configuration values by syscfg key, such as `SrNm` or `WMac`.
    #[serde(default)]
    pub syscfg: BTreeMap<String, Vec<u8>>,
    /// MAC addresses by provider name, such as `wifiaddr` or `ethaddr`.
    #[serde(default)]
    pub mac_addresses: BTreeMap<String, Vec<u8>>,
    #[serde(default)]
    pub security: SecurityPolicy,
    /// The OS environment iBoot enters, such as `darwinos-ramdisk` for a
    /// restore ramdisk; `None` is macOS.
    #[serde(default)]
    pub osenvironment: Option<OsEnvironment>,
    /// The previous-stage entry origin; independent of the OS environment.
    /// `None` leaves the boot-command handoff unresolved.
    #[serde(default)]
    pub boot_command: Option<BootCommand>,
    /// The volume the kernel roots from (`/chosen apfs-preboot-uuid`,
    /// `boot-uuid`, `associated-volume-group`, `boot-objects-path`); `None`
    /// keeps the template's values.
    #[serde(default)]
    pub root: Option<Root>,
    /// The machine's ECID, nonzero and unique per machine, for `/chosen`
    /// `unique-chip-id`, `die-id` and `unique-device-id`; `None` keeps the
    /// template's zeros and lists the rows as unresolved.
    #[serde(default)]
    pub ecid: Option<u64>,
    /// Applied after every other DeviceTree change.
    #[serde(default)]
    pub overlay: Vec<OverlayProperty>,
}

/// The defaults of `stela-dev boot prepare` for an installed system: 8 GiB of
/// DRAM at 0x8_0000_0000, verbose boot, the first CPU booting with a 24 MHz
/// generic timer, and Reduced Security with SIP enabled.
impl Default for Options {
    fn default() -> Self {
        const DRAM_BASE: u64 = 0x8_0000_0000;
        Self {
            dram_base: DRAM_BASE,
            dram_size: 0x2_0000_0000,
            phys_base: DRAM_BASE,
            load_offset: 0,
            boot_args: "-v".into(),
            boot_cpu: None,
            timebase_frequency: 24_000_000,
            syscfg: BTreeMap::new(),
            mac_addresses: BTreeMap::new(),
            security: SecurityPolicy::default(),
            osenvironment: None,
            boot_command: None,
            root: None,
            ecid: None,
            overlay: Vec::new(),
        }
    }
}

impl Options {
    /// These options with guest DRAM, and the physical base at the same
    /// distance into it, at `base` (a board's DRAM base); `None` keeps them.
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct File {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(default)]
    pub virtual_address: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub image: String,
    pub virtual_address: u64,
    pub physical_address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Image {
    pub name: String,
    pub file: String,
    pub uuid: Option<String>,
    pub vm_base: u64,
    pub vm_bytes: u64,
    pub entry: Entry,
    pub fileset_entries: usize,
}

/// What the running machine supplies for a patch slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Encoding {
    U64Le,
    Bytes,
    /// NUL-terminated within the field; the rest of the field is zero.
    CString,
}

/// One fixed-size field the UEFI mount may rewrite before entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(default)]
    pub prepared_hex: String,
    #[serde(default)]
    pub rule: String,
}

/// A template property that still carries iBoot's fill-in recipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Placeholder {
    pub path: String,
    pub property: String,
    pub recipe: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaceholderDecision {
    #[serde(flatten)]
    pub placeholder: Placeholder,
    pub resolution: String,
}

/// Why preparation selected this original CPU node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BootCpuSelection {
    /// The original first `/cpus` child, the PE whose position the kernel's
    /// per-CPU tables assume for the boot processor.
    First,
    /// The first original P-core, the automatic policy of earlier bundles.
    FirstPerformance,
    Explicit,
}

/// Selected boot PE provenance, tied to the immutable input DeviceTree.
/// The original index is a source coordinate, never a runtime logical PE ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootCpu {
    pub path: String,
    /// Original u32 `reg`, with its die/cluster/core affinity bits.
    pub affinity: u32,
    pub cluster_type: u8,
    pub original_index: usize,
    pub selection: BootCpuSelection,
}

/// `Boot_Video`: the framebuffer XNU draws its console on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Video {
    pub base: u64,
    pub display: u64,
    pub row_bytes: u64,
    pub width: u64,
    pub height: u64,
    pub depth: u64,
}

/// XNU's `boot_args`, as preparation encodes it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootArgs {
    #[serde(default)]
    pub revision: u16,
    #[serde(default)]
    pub version: u16,
    /// Kernel virtual address of `phys_base` in XNU's physical aperture.
    #[serde(default)]
    pub virt_base: u64,
    #[serde(default)]
    pub phys_base: u64,
    /// Bytes of memory from `phys_base` that the kernel may manage.
    #[serde(default)]
    pub mem_size: u64,
    #[serde(default)]
    pub top_of_kernel_data: u64,
    #[serde(default)]
    pub video: Video,
    #[serde(default)]
    pub machine_type: u32,
    /// Kernel virtual address of the flattened DeviceTree.
    #[serde(default)]
    pub device_tree: u64,
    #[serde(default)]
    pub device_tree_length: u32,
    pub command_line: String,
    #[serde(default)]
    pub boot_flags: u64,
    /// Installed DRAM, including memory below `phys_base`.
    #[serde(default)]
    pub mem_size_actual: u64,
}

/// A carveout at its guest physical address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Placed {
    pub id: u16,
    pub base: u64,
    pub bytes: u64,
}

/// A physical range iBoot programs into a memory-controller lock group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Programmed {
    #[serde(default)]
    pub group: String,
    pub base: u64,
    pub bytes: u64,
}

/// The regions of the M4 and later core lock register file, in register
/// order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LockRegion {
    CtrrC,
    CtrrD,
    CtxrA,
    CtxrB,
    CtxrC,
    CtxrD,
}

/// A region iBoot locked into the per-cluster copies: its first and last
/// byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Locked {
    pub region: LockRegion,
    pub first: u64,
    pub last: u64,
}

/// What iBoot leaves in the core lock registers before SPTM starts. Empty
/// on the chips and bundles without one: every register then resets to 0.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreLocks {
    /// The regions locked into every cluster's `ACC_*_EL2` copy, each with
    /// its handoff control.
    #[serde(default)]
    pub locked: Vec<Locked>,
    /// CTRR-A's and CTRR-B's per-core and per-cluster controls are locked
    /// and enabled.
    #[serde(default)]
    pub legacy_locked: bool,
    /// TAG_OFFSET_EL2 as iBoot locks it, 0 where it leaves it unprogrammed,
    /// its reset value.
    #[serde(default)]
    pub tag_offset: u64,
}

/// One `/chosen` value written or kept, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub path: String,
    pub property: String,
    pub value_hex: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    /// The revision of the content preparation writes within its schema.
    #[serde(default)]
    pub revision: u32,
    /// Generic authored images may omit Apple provenance. The Apple boot
    /// mount requires complete selected target/source/original ADT before
    /// loading.
    #[serde(default)]
    pub target: Option<Target>,
    pub options: Options,
    /// Authored diagnostics may omit this; Apple intake requires and
    /// verifies it against immutable source and prepared/live CPU
    /// identities.
    #[serde(default)]
    pub boot_cpu: Option<BootCpu>,
    /// The PEs of the prepared `/cpus`, which setup passes on as
    /// `--guest-pes`.
    #[serde(default)]
    pub processors: usize,
    #[serde(default)]
    pub sources: Vec<Source>,
    pub files: Vec<File>,
    pub regions: Vec<Region>,
    /// Where execution starts: SPTM's entry, at EL2-equivalent privilege.
    pub entry: Entry,
    /// x0 on entry: the physical address of `boot_args`.
    pub entry_x0: u64,
    #[serde(default)]
    pub images: Vec<Image>,
    pub boot_args: BootArgs,
    #[serde(default)]
    pub device_tree_bytes: u64,
    pub top_of_kernel_data: u64,
    /// iBoot's carveouts, below the managed range.
    #[serde(default)]
    pub carveouts: Vec<Placed>,
    /// The region iBoot programs into the AMCC's CTRR-A lock group, from
    /// the first region through `SPTM-rx`.
    #[serde(default)]
    pub read_only_region: Option<Programmed>,
    /// What iBoot leaves in the cores' lock registers on the M4 and later.
    #[serde(default)]
    pub core_locks: Option<CoreLocks>,
    /// The DeviceTree nodes whose `compatible` names no modeled device and
    /// were removed.
    #[serde(default)]
    pub hidden_devices: Vec<String>,
    pub patches: Vec<Patch>,
    #[serde(default)]
    pub placeholders: Vec<PlaceholderDecision>,
    /// Boot-policy and manifest values written into `/chosen`.
    #[serde(default)]
    pub security: Vec<Decision>,
    #[serde(default)]
    pub unresolved: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_hex_round_trips() {
        let overlay = OverlayProperty {
            path: "/arm-io".into(),
            property: "reg".into(),
            value: alloc::vec![0x0a, 0xff, 0x00],
        };
        let json = serde_json::to_string(&overlay).unwrap();
        assert!(json.contains("\"0aff00\""));
        assert_eq!(
            serde_json::from_str::<OverlayProperty>(&json).unwrap(),
            overlay
        );
        for wrong in ["\"0af\"", "\"0g\""] {
            let text = json.replace("\"0aff00\"", wrong);
            assert!(serde_json::from_str::<OverlayProperty>(&text).is_err());
        }
    }
}
