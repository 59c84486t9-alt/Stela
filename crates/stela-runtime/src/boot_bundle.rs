//! The kernel boot bundle as the UEFI mount consumes it.
//!
//! `stela boot prepare` writes `bundle.json` and the files it lists; the
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
use serde::Deserialize;

pub const SCHEMA_VERSION: u32 = 1;
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

#[derive(Debug, Clone, Deserialize)]
pub struct Options {
    pub dram_base: u64,
    pub dram_size: u64,
    pub phys_base: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct File {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Region {
    pub name: String,
    pub file: String,
    pub file_offset: u64,
    pub bytes: u64,
    pub guest_pa: u64,
    pub memory_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Patch {
    pub source: String,
    pub required: bool,
    pub region: String,
    pub file: String,
    pub file_offset: u64,
    pub bytes: u64,
    pub encoding: String,
    pub field: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Entry {
    pub image: String,
    pub virtual_address: u64,
    pub physical_address: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BootArgs {
    pub command_line: String,
}

/// The fields of `bundle.json` the mount uses; others are ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub options: Options,
    pub files: Vec<File>,
    pub regions: Vec<Region>,
    pub entry: Entry,
    pub entry_x0: u64,
    pub boot_args: BootArgs,
    pub top_of_kernel_data: u64,
    pub patches: Vec<Patch>,
}

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
    /// The counter rate `CNTFRQ_EL0` reports.
    pub timebase_hz: u64,
    pub framebuffer: Option<Framebuffer>,
    /// Replaces the prepared kernel command line.
    pub boot_args: Option<String>,
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
    pub source: String,
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
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_');
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
        let value = match (patch.source.as_str(), patch.field.as_str()) {
            ("dram-size", "/chosen dram-size" | "boot_args.memSizeActual") => {
                Some(u64_value(machine.ram_bytes))
            }
            ("dram-size", "boot_args.memSize") => Some(u64_value(
                machine.dram_base + machine.ram_bytes - options.phys_base,
            )),
            ("entropy", _) => {
                let mut random = vec![0; bytes];
                entropy(&mut random).map_err(BundleError::Entropy)?;
                Some(random)
            }
            ("timebase", _) => Some(u64_value(machine.timebase_hz)),
            ("framebuffer", field) => match machine.framebuffer {
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
                        _ => return Err(error("unknown framebuffer field")),
                    })
                }
            },
            ("boot-args", _) => match &machine.boot_args {
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
            _ => return Err(error("unknown patch source or field")),
        };
        if let Some(value) = &value {
            let width = match patch.encoding.as_str() {
                "u64-le" => U64_BYTES,
                "bytes" | "c-string" => value.len(),
                _ => return Err(error("unknown encoding")),
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
                source: patch.source.clone(),
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

    fn manifest_json(kernel: &[u8], tree: &[u8]) -> String {
        let sha = crate::sha256;
        format!(
            r#"{{
  "schema_version": 1, "unknown_field": true,
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
  "patches": [
    {{"source": "dram-size", "required": false, "region": "DeviceTree", "file": "devicetree.adt", "file_offset": 0, "bytes": 8, "encoding": "u64-le", "field": "/chosen dram-size", "prepared_hex": ""}},
    {{"source": "entropy", "required": true, "region": "DeviceTree", "file": "devicetree.adt", "file_offset": 8, "bytes": 4, "encoding": "bytes", "field": "/chosen random-seed", "prepared_hex": ""}},
    {{"source": "framebuffer", "required": false, "region": "DeviceTree", "file": "devicetree.adt", "file_offset": 12, "bytes": 8, "encoding": "u64-le", "field": "boot_args.Video.v_display", "prepared_hex": ""}}
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
            timebase_hz: 24_000_000,
            framebuffer: None,
            boot_args: None,
        }
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
                json.replace("\"schema_version\": 1", "\"schema_version\": 2")
                    .as_bytes()
            )
            .is_err()
        );
        Ok(())
    }
}
