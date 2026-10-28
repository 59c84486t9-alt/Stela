//! The kernel boot bundle as the UEFI mount consumes it.
//!
//! `stela-dev boot prepare` writes `bundle.json` and the files it lists; the
//! format is in `docs/design/runtime.md#kernel-boot-bundle`. Before boot
//! services end the mount reads every file and [`Manifest::verify`]s each
//! file and region hash. [`Verified::load`] then writes the regions into
//! guest DRAM through the caller's writer, fills the patch slots only the
//! running machine knows, and returns a plain [`GuestImage`] for the engine.
//! Nothing here parses Mach-O, IM4P or the DeviceTree: every value the host
//! could compute is already in the files.
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::fmt;

pub mod schema;
pub use schema::{
    BootCpu, BootCpuSelection, CoreLocks, Encoding, Manifest, Options, Patch, PatchSource,
    SCHEMA_VERSION, Source, Target,
};
use schema::{File, Region};
pub const MANIFEST_FILE: &str = "bundle.json";
const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
/// Guest DRAM is backed by 2 MiB host frames.
pub const FRAME_BYTES: u64 = 2 * 1024 * 1024;
const U64_BYTES: usize = 8;
/// The verbose-boot flag, under which `Boot_Video.v_display` is 0 (m1n1
/// `set_bootargs`).
const VERBOSE_FLAG: &str = "-v";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    Manifest(String),
    File {
        name: String,
        reason: String,
    },
    Region {
        name: String,
        reason: String,
    },
    Patch {
        field: String,
        reason: String,
    },
    /// The running machine cannot host the bundle.
    Machine(String),
    /// No entropy source; the bundle requires fresh random bytes.
    Entropy(&'static str),
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(what) => write!(f, "bundle.json: {what}"),
            Self::File { name, reason } => write!(f, "bundle file {name}: {reason}"),
            Self::Region { name, reason } => write!(f, "region {name}: {reason}"),
            Self::Patch { field, reason } => write!(f, "patch {field}: {reason}"),
            Self::Machine(what) => write!(f, "machine: {what}"),
            Self::Entropy(what) => write!(f, "entropy: {what}"),
        }
    }
}

impl core::error::Error for BundleError {}

/// The firmware framebuffer as the guest sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Framebuffer {
    /// Guest physical address the machine maps the framebuffer at.
    pub guest_pa: u64,
    pub bytes: u64,
    pub row_bytes: u64,
    pub width: u64,
    pub height: u64,
    pub bits_per_pixel: u64,
}

/// What the running machine provides for the patch slots.
#[derive(Debug, Clone)]
pub struct Machine {
    pub dram_base: u64,
    /// Guest DRAM bytes actually backed from `dram_base`.
    pub ram_bytes: u64,
    /// The DRAM the Mac reports (`/chosen dram-size`, `memSizeActual`):
    /// the backed bytes and, above them, the host memory Stela and the
    /// firmware keep, which the kernel never manages, as with iBoot's
    /// carveouts.
    pub dram_bytes: u64,
    /// The counter rate `CNTFRQ_EL0` reports.
    pub timebase_hz: u64,
    pub framebuffer: Option<Framebuffer>,
    /// Replaces the prepared kernel command line.
    pub boot_args: Option<String>,
    /// The persistent NOR's current NVRAM bank, replacing the prepared
    /// empty one.
    pub nvram: Option<Nvram>,
}

/// The NVRAM bank iBoot hands the kernel in `/chosen`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nvram {
    /// `nvram-current-bank`.
    pub bank: u32,
    /// `nvram-proxy-data`: the bank's bytes.
    pub proxy: Vec<u8>,
}

impl Machine {
    /// The end of the range the kernel manages: the DRAM end, or the
    /// framebuffer's base, which must then end the backed RAM. iBoot keeps
    /// `/vram` out of the kernel's memory; where it puts it is not
    /// established, so the machine places it at the top (inference).
    fn managed_end(&self) -> Result<u64, &'static str> {
        let end = self.dram_base + self.ram_bytes;
        match self.framebuffer {
            None => Ok(end),
            Some(screen) if screen.guest_pa.checked_add(screen.bytes) == Some(end) => {
                Ok(screen.guest_pa)
            }
            Some(_) => Err("the framebuffer does not end the backed RAM"),
        }
    }
}

impl Manifest {
    /// The cores' lock registers iBoot leaves on `machine`. Where the chip
    /// keeps memory tags, SPTM requires TAG_OFFSET_EL2 at the top of the
    /// managed range, sized for `/chosen dram-size`
    /// ([`stela_contracts::tag_storage`]), so its value follows the machine's
    /// DRAM rather than the prepared one.
    pub fn core_locks(&self, machine: &Machine) -> Result<Option<CoreLocks>, BundleError> {
        let Some(mut locks) = self.core_locks.clone() else {
            return Ok(None);
        };
        if locks.tag_offset != 0 {
            let fail = |reason: &str| BundleError::Machine(format!("tag storage: {reason}"));
            let phys_base = self.options.phys_base;
            let managed = machine.managed_end().map_err(fail)? - phys_base;
            locks.tag_offset =
                stela_contracts::tag_storage::hand_off(phys_base, managed, machine.dram_bytes)
                    .ok_or_else(|| fail("its base does not fit TAG_OFFSET_EL2"))?;
            if stela_contracts::tag_storage::base(locks.tag_offset) < self.top_of_kernel_data {
                return Err(fail("it overlaps the loaded regions"));
            }
        }
        Ok(Some(locks))
    }
}

/// A contiguous guest RAM range the engine must back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RamExtent {
    pub guest_pa: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedRegion {
    pub name: String,
    pub guest_pa: u64,
    pub bytes: u64,
    pub memory_bytes: u64,
}

/// A patch slot and the bytes now in guest RAM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedPatch {
    pub field: String,
    pub source: PatchSource,
    pub guest_pa: u64,
    pub value: Vec<u8>,
}

/// Plain data the engine starts from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestImage {
    /// The image entered first: SPTM.
    pub entry_image: String,
    pub entry_pa: u64,
    pub entry_va: u64,
    /// x0 on entry: the `boot_args` physical address.
    pub x0: u64,
    pub ram: Vec<RamExtent>,
    pub regions: Vec<LoadedRegion>,
    pub patches: Vec<AppliedPatch>,
    /// Slots left with their prepared bytes, such as the framebuffer when
    /// the machine has none.
    pub kept: Vec<String>,
}

fn manifest_error(what: impl ToString) -> BundleError {
    BundleError::Manifest(what.to_string())
}

impl Manifest {
    pub fn parse(json: &[u8]) -> Result<Self, BundleError> {
        if json.len() > MAX_MANIFEST_BYTES {
            return Err(manifest_error("exceeds 16 MiB"));
        }
        let manifest: Self = serde_json::from_slice(json).map_err(manifest_error)?;
        if manifest.schema_version != SCHEMA_VERSION {
            return Err(manifest_error(format!(
                "schema {} is not {SCHEMA_VERSION}",
                manifest.schema_version
            )));
        }
        for file in &manifest.files {
            let simple = !file.name.is_empty()
                && file
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_,".contains(&b));
            if !simple {
                return Err(manifest_error(format!("unsafe file name {:?}", file.name)));
            }
        }
        Ok(manifest)
    }

    fn file(&self, name: &str) -> Result<&File, BundleError> {
        self.files
            .iter()
            .find(|f| f.name == name)
            .ok_or_else(|| manifest_error(format!("no file {name}")))
    }

    /// Whether the regions cover `file` exactly once, end to end.
    fn tiled(&self, file: &File) -> bool {
        let mut ranges: Vec<(u64, u64)> = self
            .regions
            .iter()
            .filter(|r| r.file == file.name)
            .map(|r| (r.file_offset, r.file_offset.saturating_add(r.bytes)))
            .collect();
        ranges.sort_unstable();
        let mut cursor = 0;
        for (start, end) in ranges {
            if start != cursor {
                return false;
            }
            cursor = end;
        }
        cursor == file.bytes
    }

    /// Check every file's size and every region's extent and SHA-256. A
    /// file the regions do not tile exactly is also checked against its own
    /// SHA-256; a tiled file's region hashes already cover every byte.
    /// `contents` returns a file's bytes by name.
    pub fn verify<'a>(
        &'a self,
        contents: &dyn Fn(&str) -> Option<&'a [u8]>,
    ) -> Result<Verified<'a>, BundleError> {
        let mut files = Vec::with_capacity(self.files.len());
        for file in &self.files {
            let bytes = contents(&file.name).ok_or_else(|| BundleError::File {
                name: file.name.clone(),
                reason: "was not read".into(),
            })?;
            if bytes.len() as u64 != file.bytes {
                return Err(BundleError::File {
                    name: file.name.clone(),
                    reason: format!("is {} bytes, not {}", bytes.len(), file.bytes),
                });
            }
            if !self.tiled(file) && crate::sha256(bytes) != file.sha256 {
                return Err(BundleError::File {
                    name: file.name.clone(),
                    reason: "SHA-256 differs from bundle.json".into(),
                });
            }
            files.push((file.name.as_str(), bytes));
        }
        let verified = Verified {
            manifest: self,
            files,
        };
        for region in &self.regions {
            let bytes = verified.region_bytes(region)?;
            if crate::sha256(bytes) != region.sha256 {
                return Err(BundleError::Region {
                    name: region.name.clone(),
                    reason: "SHA-256 differs from bundle.json".into(),
                });
            }
        }
        Ok(verified)
    }
}

/// A manifest whose files and regions matched their hashes.
pub struct Verified<'a> {
    pub manifest: &'a Manifest,
    files: Vec<(&'a str, &'a [u8])>,
}

fn u64_value(value: u64) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

/// The low 32 bits of `value`, for a u32 DeviceTree property.
fn u32_value(value: u64) -> Vec<u8> {
    (value as u32).to_le_bytes().to_vec()
}

impl<'a> Verified<'a> {
    fn file_bytes(&self, name: &str) -> Result<&'a [u8], BundleError> {
        self.manifest.file(name)?;
        self.files
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, bytes)| *bytes)
            .ok_or_else(|| manifest_error(format!("no file {name}")))
    }

    fn region_bytes(&self, region: &Region) -> Result<&'a [u8], BundleError> {
        let file = self.file_bytes(&region.file)?;
        let start = usize::try_from(region.file_offset).ok();
        let end = start.and_then(|s| s.checked_add(usize::try_from(region.bytes).ok()?));
        match (start, end) {
            (Some(start), Some(end))
                if end <= file.len() && region.bytes <= region.memory_bytes =>
            {
                Ok(&file[start..end])
            }
            _ => Err(BundleError::Region {
                name: region.name.clone(),
                reason: format!("lies outside {}", region.file),
            }),
        }
    }

    /// The bytes a patch slot takes on `machine`; `None` keeps the prepared
    /// bytes.
    fn patch_value(
        &self,
        patch: &Patch,
        machine: &Machine,
        entropy: &mut dyn FnMut(&mut [u8]) -> Result<(), &'static str>,
    ) -> Result<Option<Vec<u8>>, BundleError> {
        let error = |reason: &str| BundleError::Patch {
            field: patch.field.clone(),
            reason: reason.into(),
        };
        let bytes = usize::try_from(patch.bytes).map_err(|_| error("size overflows"))?;
        let options = &self.manifest.options;
        let value = match (patch.source, patch.field.as_str()) {
            (PatchSource::DramSize, "/chosen dram-size" | "boot_args.memSizeActual") => {
                Some(u64_value(machine.dram_bytes))
            }
            (PatchSource::DramSize, "boot_args.memSize") => Some(u64_value(
                machine.managed_end().map_err(error)? - options.phys_base,
            )),
            (PatchSource::Entropy, _) => {
                let mut random = vec![0; bytes];
                entropy(&mut random).map_err(BundleError::Entropy)?;
                Some(random)
            }
            (PatchSource::Timebase, _) => Some(u64_value(machine.timebase_hz)),
            (PatchSource::Framebuffer, field) => match machine.framebuffer {
                None => None,
                Some(screen) => {
                    let command_line = machine
                        .boot_args
                        .as_deref()
                        .unwrap_or(&self.manifest.boot_args.command_line);
                    let verbose = command_line
                        .split_ascii_whitespace()
                        .any(|w| w == VERBOSE_FLAG);
                    Some(match field {
                        "/vram reg" => {
                            [screen.guest_pa.to_le_bytes(), screen.bytes.to_le_bytes()].concat()
                        }
                        "boot_args.Video.v_baseAddr" => u64_value(screen.guest_pa),
                        "boot_args.Video.v_display" => u64_value(u64::from(!verbose)),
                        "boot_args.Video.v_rowBytes" => u64_value(screen.row_bytes),
                        "boot_args.Video.v_width" => u64_value(screen.width),
                        "boot_args.Video.v_height" => u64_value(screen.height),
                        "boot_args.Video.v_depth" => u64_value(screen.bits_per_pixel),
                        // iBoot derives these from v_depth (file 0x24148..
                        // 0x2425c): bits 8..15 rotation and 24..31 boot
                        // rotation in quarter turns, bits 16..23 the scale
                        // less one. Stela's depth has neither, so the scale
                        // is 1, never the template's 0.
                        "/chosen display-rotation" => {
                            u32_value((screen.bits_per_pixel >> 8 & 0xff) * 90)
                        }
                        "/chosen display-scale" => {
                            u32_value((screen.bits_per_pixel >> 16 & 0xff) + 1)
                        }
                        "/chosen display-boot-rotation" => {
                            u32_value((screen.bits_per_pixel >> 24 & 0xff) * 90)
                        }
                        "/arm-io/dispext0 framebuffer-width" => u32::try_from(screen.width)
                            .map_err(|_| error("external framebuffer width exceeds u32"))?
                            .to_le_bytes()
                            .to_vec(),
                        "/arm-io/dispext0 framebuffer-height" => u32::try_from(screen.height)
                            .map_err(|_| error("external framebuffer height exceeds u32"))?
                            .to_le_bytes()
                            .to_vec(),
                        _ => return Err(error("unknown framebuffer field")),
                    })
                }
            },
            (PatchSource::Nvram, "/chosen nvram-proxy-data") => {
                machine.nvram.as_ref().map(|nvram| nvram.proxy.clone())
            }
            (PatchSource::Nvram, "/chosen nvram-current-bank") => machine
                .nvram
                .as_ref()
                .map(|nvram| nvram.bank.to_le_bytes().to_vec()),
            (PatchSource::BootArgs, _) => match &machine.boot_args {
                None => None,
                Some(line) => {
                    if line.len() >= bytes || line.contains('\0') {
                        return Err(error("boot-args do not fit the command line"));
                    }
                    let mut value = line.as_bytes().to_vec();
                    value.resize(bytes, 0);
                    Some(value)
                }
            },
            _ => return Err(error("unknown field for its source")),
        };
        if let Some(value) = &value {
            let width = match patch.encoding {
                Encoding::U64Le => U64_BYTES,
                Encoding::Bytes | Encoding::CString => value.len(),
            };
            if value.len() != bytes || value.len() != width {
                return Err(error("value does not fill the slot"));
            }
        }
        Ok(value)
    }

    /// Write every region into guest DRAM and fill the patch slots.
    ///
    /// `write(guest_pa, bytes)` stores into guest RAM and returns false when
    /// any byte is not backed; regions are written in manifest order, then
    /// their zero tails, then the patches. `entropy` fills a buffer with
    /// fresh random bytes or refuses.
    pub fn load(
        &self,
        machine: &Machine,
        entropy: &mut dyn FnMut(&mut [u8]) -> Result<(), &'static str>,
        write: &mut dyn FnMut(u64, &[u8]) -> bool,
    ) -> Result<GuestImage, BundleError> {
        let options = &self.manifest.options;
        if options.dram_base != machine.dram_base {
            return Err(BundleError::Machine(format!(
                "bundle DRAM base {:#x} differs from the machine's {:#x}",
                options.dram_base, machine.dram_base
            )));
        }
        let ram_end = machine
            .dram_base
            .checked_add(machine.ram_bytes)
            .ok_or_else(|| BundleError::Machine("DRAM range overflows".into()))?;
        if machine.dram_bytes < machine.ram_bytes {
            return Err(BundleError::Machine(format!(
                "the Mac's {:#x} bytes of DRAM hold fewer than the {:#x} backed",
                machine.dram_bytes, machine.ram_bytes
            )));
        }
        if self.manifest.top_of_kernel_data > ram_end || options.phys_base < machine.dram_base {
            return Err(BundleError::Machine(format!(
                "the bundle needs DRAM up to {:#x}; {:#x} bytes are backed",
                self.manifest.top_of_kernel_data, machine.ram_bytes
            )));
        }
        let mut regions = Vec::with_capacity(self.manifest.regions.len());
        for region in &self.manifest.regions {
            let fail = |reason: &str| BundleError::Region {
                name: region.name.clone(),
                reason: reason.into(),
            };
            let bytes = self.region_bytes(region)?;
            let end = region
                .guest_pa
                .checked_add(region.memory_bytes)
                .ok_or_else(|| fail("guest range overflows"))?;
            if region.guest_pa < machine.dram_base || end > ram_end {
                return Err(fail("lies outside backed guest DRAM"));
            }
            let tail = vec![0u8; (region.memory_bytes - region.bytes) as usize];
            if !write(region.guest_pa, bytes) || !write(region.guest_pa + region.bytes, &tail) {
                return Err(fail("guest RAM write failed"));
            }
            regions.push(LoadedRegion {
                name: region.name.clone(),
                guest_pa: region.guest_pa,
                bytes: region.bytes,
                memory_bytes: region.memory_bytes,
            });
        }
        let mut patches = Vec::new();
        let mut kept = Vec::new();
        for patch in &self.manifest.patches {
            let Some(value) = self.patch_value(patch, machine, entropy)? else {
                if patch.required {
                    return Err(BundleError::Patch {
                        field: patch.field.clone(),
                        reason: "is required and has no value".into(),
                    });
                }
                kept.push(patch.field.clone());
                continue;
            };
            let region = self
                .manifest
                .regions
                .iter()
                .find(|r| r.name == patch.region)
                .ok_or_else(|| BundleError::Patch {
                    field: patch.field.clone(),
                    reason: format!("names missing region {}", patch.region),
                })?;
            let inside = region.file == patch.file
                && patch.file_offset >= region.file_offset
                && patch.file_offset + patch.bytes <= region.file_offset + region.bytes;
            if !inside {
                return Err(BundleError::Patch {
                    field: patch.field.clone(),
                    reason: format!("lies outside region {}", region.name),
                });
            }
            let guest_pa = region.guest_pa + (patch.file_offset - region.file_offset);
            if !write(guest_pa, &value) {
                return Err(BundleError::Patch {
                    field: patch.field.clone(),
                    reason: "guest RAM write failed".into(),
                });
            }
            patches.push(AppliedPatch {
                field: patch.field.clone(),
                source: patch.source,
                guest_pa,
                value,
            });
        }
        Ok(GuestImage {
            entry_image: self.manifest.entry.image.clone(),
            entry_pa: self.manifest.entry.physical_address,
            entry_va: self.manifest.entry.virtual_address,
            x0: self.manifest.entry_x0,
            ram: vec![RamExtent {
                guest_pa: machine.dram_base,
                bytes: machine.ram_bytes,
            }],
            regions,
            patches,
            kept,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    const BASE: u64 = 0x8_0000_0000;

    const PATCHES: &str = r#"
    {"source": "dram-size", "required": false, "region": "DeviceTree", "file": "devicetree.adt", "file_offset": 0, "bytes": 8, "encoding": "u64-le", "field": "/chosen dram-size", "prepared_hex": ""},
    {"source": "entropy", "required": true, "region": "DeviceTree", "file": "devicetree.adt", "file_offset": 8, "bytes": 4, "encoding": "bytes", "field": "/chosen random-seed", "prepared_hex": ""},
    {"source": "framebuffer", "required": false, "region": "DeviceTree", "file": "devicetree.adt", "file_offset": 12, "bytes": 8, "encoding": "u64-le", "field": "boot_args.Video.v_display", "prepared_hex": ""}"#;

    fn manifest_json(kernel: &[u8], tree: &[u8]) -> String {
        manifest_with(kernel, tree, PATCHES)
    }

    fn manifest_with(kernel: &[u8], tree: &[u8], patches: &str) -> String {
        let sha = crate::sha256;
        format!(
            r#"{{
  "schema_version": 4, "unknown_field": true,
  "options": {{"dram_base": {BASE}, "dram_size": 1073741824, "phys_base": {BASE}}},
  "files": [
    {{"name": "kernel.img", "bytes": {kb}, "sha256": "{ks}"}},
    {{"name": "devicetree.adt", "bytes": {tb}, "sha256": "{ts}"}}
  ],
  "regions": [
    {{"name": "BootKC", "file": "kernel.img", "file_offset": 0, "bytes": {kb}, "guest_pa": {BASE}, "memory_bytes": 16384, "sha256": "{ks}"}},
    {{"name": "DeviceTree", "file": "devicetree.adt", "file_offset": 0, "bytes": {tb}, "guest_pa": {dt}, "memory_bytes": 16384, "sha256": "{ts}"}}
  ],
  "entry": {{"image": "SPTM", "virtual_address": 18446744005645091720, "physical_address": {BASE}}},
  "entry_x0": {dt},
  "boot_args": {{"command_line": "-v"}},
  "top_of_kernel_data": {top},
  "patches": [{patches}
  ]
}}"#,
            kb = kernel.len(),
            ks = sha(kernel),
            tb = tree.len(),
            ts = sha(tree),
            dt = BASE + 0x4000,
            top = BASE + 0x8000,
        )
    }

    fn write_into(ram: &mut [u8], pa: u64, bytes: &[u8]) -> bool {
        let Some(offset) = pa.checked_sub(BASE).map(|o| o as usize) else {
            return false;
        };
        match ram.get_mut(offset..offset + bytes.len()) {
            Some(slot) => {
                slot.copy_from_slice(bytes);
                true
            }
            None => false,
        }
    }

    fn machine() -> Machine {
        Machine {
            dram_base: BASE,
            ram_bytes: FRAME_BYTES,
            dram_bytes: FRAME_BYTES,
            timebase_hz: 24_000_000,
            framebuffer: None,
            boot_args: None,
            nvram: None,
        }
    }

    #[test]
    fn admission_ledger_defaults_conservatively_and_preserves_exact_evidence() {
        let json = manifest_json(&[0xaa; 100], &[0x11; 20]);
        assert!(
            Manifest::parse(json.as_bytes())
                .unwrap()
                .hidden_devices
                .is_empty()
        );
        let supplied = json.replacen("\"schema_version\": 4", "\"hidden_devices\": [\"/arm-io/ave\", \"/ secure-root-prefix\"], \"schema_version\": 4", 1);
        assert_eq!(
            Manifest::parse(supplied.as_bytes()).unwrap().hidden_devices,
            ["/arm-io/ave", "/ secure-root-prefix"]
        );
        let malformed = json.replacen(
            "\"schema_version\": 4",
            "\"hidden_devices\": [17], \"schema_version\": 4",
            1,
        );
        assert!(Manifest::parse(malformed.as_bytes()).is_err());
    }

    #[test]
    fn selected_source_metadata_is_typed_and_duplicate_fields_refuse() {
        let json = manifest_json(&[1; 32], &[2; 32]);
        let authored = Manifest::parse(json.as_bytes()).unwrap();
        assert!(authored.target.is_none());
        assert!(authored.sources.is_empty());
        let target = r#"{"product_type":"test","device_class":"test","product_version":"test","product_build":"test","variant":"test","chip_id":24576,"board_id":8}"#;
        let source = r#"{"component":"RestoreDeviceTree","member":"Firmware/test.im4p","container_sha256":"container retained verbatim","payload_type":"dtre","description":"","decoded_bytes":32,"decoded_sha256":"decoded retained verbatim"}"#;
        let metadata = format!(r#""target":{target},"sources":[{source}],"#);
        let typed = json.replacen(
            "\"schema_version\"",
            &format!("{metadata}\"schema_version\""),
            1,
        );
        let parsed = Manifest::parse(typed.as_bytes()).unwrap();
        assert_eq!(parsed.target.as_ref().unwrap().board_id, Some(8));
        assert_eq!(parsed.sources[0].member, "Firmware/test.im4p");
        assert_eq!(
            parsed.sources[0].decoded_sha256,
            "decoded retained verbatim"
        );
        // Typed parsing preserves metadata; the Apple Entry intake separately
        // validates digests, selected IDs and actual original file contents.
        for repeated in [
            format!(r#""target":{target},"#),
            format!(r#""sources":[{source}],"#),
        ] {
            let wrong = typed.replacen(
                "\"schema_version\"",
                &format!("{repeated}\"schema_version\""),
                1,
            );
            assert!(Manifest::parse(wrong.as_bytes()).is_err());
        }
        for wrong in [
            typed.replace("\"chip_id\":24576", "\"chip_id\":24576,\"chip_id\":24576"),
            typed.replace("\"board_id\":8", "\"board_id\":4294967296"),
            typed.replace("\"decoded_bytes\":32", "\"decoded_bytes\":-1"),
        ] {
            assert!(Manifest::parse(wrong.as_bytes()).is_err());
        }
    }

    #[test]
    fn boot_cpu_schema4_preserves_typed_source_identity_and_rejects_ambiguity() {
        let json = manifest_json(&[1; 32], &[2; 32]);
        assert!(Manifest::parse(json.as_bytes()).unwrap().boot_cpu.is_none());
        let record = r#"{"path":"/cpus/cpu4","affinity":256,"cluster_type":80,"original_index":4,"selection":"first-performance"}"#;
        let with_cpu = json.replacen(
            "\"schema_version\"",
            &format!("\"boot_cpu\":{record},\"schema_version\""),
            1,
        );
        let selected = Manifest::parse(with_cpu.as_bytes())
            .unwrap()
            .boot_cpu
            .unwrap();
        assert_eq!(selected.path, "/cpus/cpu4");
        assert_eq!(selected.affinity, 256);
        assert_eq!(selected.cluster_type, b'P');
        assert_eq!(selected.original_index, 4);
        assert_eq!(selected.selection, BootCpuSelection::FirstPerformance);
        let first = with_cpu.replace("first-performance", "first");
        assert_eq!(
            Manifest::parse(first.as_bytes())
                .unwrap()
                .boot_cpu
                .unwrap()
                .selection,
            BootCpuSelection::First
        );
        let explicit = with_cpu.replace("first-performance", "explicit");
        assert_eq!(
            Manifest::parse(explicit.as_bytes())
                .unwrap()
                .boot_cpu
                .unwrap()
                .selection,
            BootCpuSelection::Explicit
        );
        for wrong in [
            with_cpu.replace("first-performance", "cpu0"),
            with_cpu.replace("\"affinity\":256", "\"affinity\":4294967296"),
            with_cpu.replace("\"cluster_type\":80", "\"cluster_type\":256"),
            with_cpu.replace("\"original_index\":4", "\"original_index\":-1"),
            with_cpu.replace(
                "\"original_index\":4",
                "\"original_index\":4,\"original_index\":4",
            ),
            with_cpu.replacen(
                "\"schema_version\"",
                &format!("\"boot_cpu\":{record},\"schema_version\""),
                1,
            ),
        ] {
            assert!(Manifest::parse(wrong.as_bytes()).is_err());
        }
        for old in 0..4 {
            assert!(
                Manifest::parse(
                    json.replace(
                        "\"schema_version\": 4",
                        &format!("\"schema_version\": {old}")
                    )
                    .as_bytes()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn the_mac_reports_the_installed_dram_above_the_backed_range() -> Result<(), BundleError> {
        let kernel = [0xaa; 100];
        let tree = [0x11; 20];
        let json = manifest_json(&kernel, &tree);
        let manifest = Manifest::parse(json.as_bytes())?;
        let files: BTreeMap<&str, &[u8]> =
            BTreeMap::from([("kernel.img", &kernel[..]), ("devicetree.adt", &tree[..])]);
        let verified = manifest.verify(&|name| files.get(name).copied())?;
        let mut ram = vec![0xffu8; FRAME_BYTES as usize];
        let mut entropy = |buffer: &mut [u8]| {
            buffer.fill(0x42);
            Ok(())
        };
        // Host memory Stela keeps shows as DRAM the kernel does not manage.
        let kept = Machine {
            dram_bytes: 3 * FRAME_BYTES,
            ..machine()
        };
        verified.load(&kept, &mut entropy, &mut |pa, bytes| {
            write_into(&mut ram, pa, bytes)
        })?;
        assert_eq!(&ram[0x4000..0x4008], &(3 * FRAME_BYTES).to_le_bytes());
        let short = Machine {
            dram_bytes: FRAME_BYTES - 0x4000,
            ..machine()
        };
        assert!(matches!(
            verified.load(&short, &mut entropy, &mut |_, _| true),
            Err(BundleError::Machine(_))
        ));
        Ok(())
    }

    #[test]
    fn verifies_loads_and_patches_into_guest_ram() -> Result<(), BundleError> {
        let kernel = [0xaa; 100];
        let tree = [0x11; 20];
        let json = manifest_json(&kernel, &tree);
        let manifest = Manifest::parse(json.as_bytes())?;
        let files: BTreeMap<&str, &[u8]> =
            BTreeMap::from([("kernel.img", &kernel[..]), ("devicetree.adt", &tree[..])]);
        let verified = manifest.verify(&|name| files.get(name).copied())?;
        let mut ram = vec![0xffu8; FRAME_BYTES as usize];
        let mut entropy = |buffer: &mut [u8]| {
            buffer.fill(0x42);
            Ok(())
        };
        let image = verified.load(&machine(), &mut entropy, &mut |pa, bytes| {
            write_into(&mut ram, pa, bytes)
        })?;
        assert_eq!(image.x0, BASE + 0x4000);
        assert_eq!(image.kept, vec!["boot_args.Video.v_display".to_string()]);
        assert_eq!(&ram[..100], &kernel);
        assert!(ram[100..0x4000].iter().all(|&b| b == 0));
        let dt = 0x4000;
        assert_eq!(&ram[dt..dt + 8], &FRAME_BYTES.to_le_bytes());
        assert_eq!(&ram[dt + 8..dt + 12], &[0x42; 4]);
        assert_eq!(&ram[dt + 12..dt + 20], &[0x11; 8]);

        // With a framebuffer and verbose boot-args, v_display is 0.
        let screen = Machine {
            framebuffer: Some(Framebuffer {
                guest_pa: 0xc000_0000,
                bytes: 0x80_0000,
                row_bytes: 7680,
                width: 1920,
                height: 1080,
                bits_per_pixel: 32,
            }),
            ..machine()
        };
        let image = verified.load(&screen, &mut entropy, &mut |pa, bytes| {
            write_into(&mut ram, pa, bytes)
        })?;
        assert!(image.kept.is_empty());
        assert_eq!(&ram[dt + 12..dt + 20], &0u64.to_le_bytes());
        Ok(())
    }

    #[test]
    fn external_pipe_geometry_uses_the_same_actual_framebuffer() -> Result<(), BundleError> {
        let kernel = [0xaa; 100];
        let tree = [0x11; 28];
        let patches = format!(
            r#"{PATCHES},
        {{"source":"framebuffer","required":true,"region":"DeviceTree","file":"devicetree.adt","file_offset":20,"bytes":4,"encoding":"bytes","field":"/arm-io/dispext0 framebuffer-width","prepared_hex":""}},
        {{"source":"framebuffer","required":true,"region":"DeviceTree","file":"devicetree.adt","file_offset":24,"bytes":4,"encoding":"bytes","field":"/arm-io/dispext0 framebuffer-height","prepared_hex":""}}"#
        );
        let manifest = Manifest::parse(manifest_with(&kernel, &tree, &patches).as_bytes())?;
        let files: BTreeMap<&str, &[u8]> =
            BTreeMap::from([("kernel.img", &kernel[..]), ("devicetree.adt", &tree[..])]);
        let verified = manifest.verify(&|name| files.get(name).copied())?;
        let mut ram = vec![0xff; FRAME_BYTES as usize];
        let mut entropy = |bytes: &mut [u8]| {
            bytes.fill(0x42);
            Ok(())
        };
        // A visible display cannot retain physical-board geometry without a
        // real backing resource when the native GOP is unavailable.
        assert!(
            verified
                .load(&machine(), &mut entropy, &mut |pa, bytes| write_into(
                    &mut ram, pa, bytes
                ))
                .is_err()
        );
        let screen = Machine {
            framebuffer: Some(Framebuffer {
                guest_pa: 0xc000_0000,
                bytes: 0x80_0000,
                row_bytes: 7680,
                width: 1920,
                height: 1080,
                bits_per_pixel: 32,
            }),
            ..machine()
        };
        verified.load(&screen, &mut entropy, &mut |pa, bytes| {
            write_into(&mut ram, pa, bytes)
        })?;
        assert_eq!(&ram[0x4014..0x4018], &1920u32.to_le_bytes());
        assert_eq!(&ram[0x4018..0x401c], &1080u32.to_le_bytes());
        Ok(())
    }

    #[test]
    fn display_scale_and_rotation_follow_the_video_depth() -> Result<(), BundleError> {
        let kernel = [0xaa; 100];
        let tree = [0x11; 32];
        let patches = format!(
            r#"{PATCHES},
        {{"source":"framebuffer","required":false,"region":"DeviceTree","file":"devicetree.adt","file_offset":20,"bytes":4,"encoding":"bytes","field":"/chosen display-rotation","prepared_hex":""}},
        {{"source":"framebuffer","required":false,"region":"DeviceTree","file":"devicetree.adt","file_offset":24,"bytes":4,"encoding":"bytes","field":"/chosen display-scale","prepared_hex":""}},
        {{"source":"framebuffer","required":false,"region":"DeviceTree","file":"devicetree.adt","file_offset":28,"bytes":4,"encoding":"bytes","field":"/chosen display-boot-rotation","prepared_hex":""}}"#
        );
        let manifest = Manifest::parse(manifest_with(&kernel, &tree, &patches).as_bytes())?;
        let files: BTreeMap<&str, &[u8]> =
            BTreeMap::from([("kernel.img", &kernel[..]), ("devicetree.adt", &tree[..])]);
        let verified = manifest.verify(&|name| files.get(name).copied())?;
        let mut ram = vec![0xff; FRAME_BYTES as usize];
        let mut entropy = |bytes: &mut [u8]| {
            bytes.fill(0x42);
            Ok(())
        };
        // Without a display the template stands, as iBoot leaves it.
        verified.load(&machine(), &mut entropy, &mut |pa, bytes| {
            write_into(&mut ram, pa, bytes)
        })?;
        assert_eq!(&ram[0x4014..0x4020], &[0x11; 12]);
        let screen = Machine {
            framebuffer: Some(Framebuffer {
                guest_pa: 0xc000_0000,
                bytes: 0x80_0000,
                row_bytes: 5120,
                width: 1280,
                height: 800,
                bits_per_pixel: 32,
            }),
            ..machine()
        };
        verified.load(&screen, &mut entropy, &mut |pa, bytes| {
            write_into(&mut ram, pa, bytes)
        })?;
        assert_eq!(&ram[0x4014..0x4018], &0u32.to_le_bytes());
        assert_eq!(&ram[0x4018..0x401c], &1u32.to_le_bytes());
        assert_eq!(&ram[0x401c..0x4020], &0u32.to_le_bytes());
        Ok(())
    }

    #[test]
    fn a_persistent_nor_hands_off_its_current_bank() -> Result<(), BundleError> {
        let kernel = [0xaa; 100];
        let tree = [0x11; 20];
        let json = manifest_with(
            &kernel,
            &tree,
            r#"
    {"source": "nvram", "required": false, "region": "DeviceTree", "file": "devicetree.adt", "file_offset": 0, "bytes": 16, "encoding": "bytes", "field": "/chosen nvram-proxy-data", "prepared_hex": ""},
    {"source": "nvram", "required": false, "region": "DeviceTree", "file": "devicetree.adt", "file_offset": 16, "bytes": 4, "encoding": "bytes", "field": "/chosen nvram-current-bank", "prepared_hex": ""}"#,
        );
        let manifest = Manifest::parse(json.as_bytes())?;
        let files: BTreeMap<&str, &[u8]> =
            BTreeMap::from([("kernel.img", &kernel[..]), ("devicetree.adt", &tree[..])]);
        let verified = manifest.verify(&|name| files.get(name).copied())?;
        let mut ram = vec![0u8; FRAME_BYTES as usize];
        let mut entropy = |_: &mut [u8]| Err("unused");
        // Without a persistent NOR the prepared bank stands.
        let image = verified.load(&machine(), &mut entropy, &mut |pa, bytes| {
            write_into(&mut ram, pa, bytes)
        })?;
        assert_eq!(image.kept.len(), 2);
        assert_eq!(&ram[0x4000..0x4014], &[0x11; 20]);
        let persistent = Machine {
            nvram: Some(Nvram {
                bank: 1,
                proxy: vec![7; 16],
            }),
            ..machine()
        };
        verified.load(&persistent, &mut entropy, &mut |pa, bytes| {
            write_into(&mut ram, pa, bytes)
        })?;
        assert_eq!(&ram[0x4000..0x4010], &[7; 16]);
        assert_eq!(&ram[0x4010..0x4014], &1u32.to_le_bytes());
        let short = Machine {
            nvram: Some(Nvram {
                bank: 0,
                proxy: vec![7; 4],
            }),
            ..machine()
        };
        assert!(
            verified
                .load(&short, &mut entropy, &mut |_, _| true)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn the_framebuffer_ends_the_managed_range() {
        let screen = |guest_pa| Machine {
            framebuffer: Some(Framebuffer {
                guest_pa,
                bytes: 0x4000,
                row_bytes: 64,
                width: 16,
                height: 16,
                bits_per_pixel: 32,
            }),
            ..machine()
        };
        let end = BASE + FRAME_BYTES;
        assert_eq!(machine().managed_end(), Ok(end));
        assert_eq!(screen(end - 0x4000).managed_end(), Ok(end - 0x4000));
        assert!(screen(BASE).managed_end().is_err());
    }

    #[test]
    fn refuses_tampered_files_small_ram_and_missing_entropy() -> Result<(), BundleError> {
        let kernel = [0xaa; 100];
        let tree = [0x11; 20];
        let json = manifest_json(&kernel, &tree);
        let manifest = Manifest::parse(json.as_bytes())?;
        let tampered = [0xab; 100];
        let files: BTreeMap<&str, &[u8]> =
            BTreeMap::from([("kernel.img", &tampered[..]), ("devicetree.adt", &tree[..])]);
        // The kernel is tiled by its region, whose hash catches the change.
        assert!(matches!(
            manifest.verify(&|name| files.get(name).copied()),
            Err(BundleError::Region { .. })
        ));
        let files: BTreeMap<&str, &[u8]> =
            BTreeMap::from([("kernel.img", &kernel[..]), ("devicetree.adt", &tree[..])]);
        let verified = manifest.verify(&|name| files.get(name).copied())?;
        let mut write = |_: u64, _: &[u8]| true;
        let mut no_entropy = |_: &mut [u8]| Err("no RDSEED or RDRAND");
        assert_eq!(
            verified.load(&machine(), &mut no_entropy, &mut write).err(),
            Some(BundleError::Entropy("no RDSEED or RDRAND"))
        );
        let small = Machine {
            ram_bytes: 0x4000,
            ..machine()
        };
        let mut entropy = |_: &mut [u8]| Ok(());
        assert!(matches!(
            verified.load(&small, &mut entropy, &mut write),
            Err(BundleError::Machine(_))
        ));
        // A file no region covers is checked by its own hash.
        let extra = json.replace(
            r#"  ],
  "regions""#,
            &format!(
                r#",    {{"name": "extra.bin", "bytes": 3, "sha256": "{}"}}
  ],
  "regions""#,
                crate::sha256(b"abc")
            ),
        );
        let extra = Manifest::parse(extra.as_bytes())?;
        let files: BTreeMap<&str, &[u8]> = BTreeMap::from([
            ("kernel.img", &kernel[..]),
            ("devicetree.adt", &tree[..]),
            ("extra.bin", &b"abd"[..]),
        ]);
        assert!(matches!(
            extra.verify(&|name| files.get(name).copied()),
            Err(BundleError::File { .. })
        ));
        let unsafe_name = json.replace("\"kernel.img\"", "\"../kernel.img\"");
        assert!(Manifest::parse(unsafe_name.as_bytes()).is_err());
        assert!(
            Manifest::parse(
                json.replace("\"schema_version\": 4", "\"schema_version\": 2")
                    .as_bytes()
            )
            .is_err()
        );
        Ok(())
    }
}
