//! `cargo xtask census --ipsw PATH [--keys DIR]` writes
//! `crates/stela-runtime/src/hosted/requirements/census.rs`: every
//! `SVC #0x80` in a macOS build's arm64e shared cache and in its
//! `/usr/lib/dyld`, with the call number its stub loads into X16 and the
//! stub's symbol. The images come from the IPSW's SystemOS cryptex and OS
//! volume, decrypted with the AEA readers `stela guest-system install` uses
//! and copied out with `hdiutil`, so it runs on macOS. Only numbers and
//! symbol names reach the output.
use crate::tools::root;
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use object::read::macho::{DyldCache, FatArch, MachOFatFile32, MachOFatFile64};
use object::{Endianness, FileKind, Object, ObjectSection, ObjectSymbol};
use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs::{self, File},
    path::{Path, PathBuf},
    process::Command,
};
use stela_cli::restore::{aea, archive, disk};

const GENERATED: &str = "crates/stela-runtime/src/hosted/requirements/census.rs";
/// The arm64e shared cache inside the system volume.
const SHARED_CACHE: &str = "System/Library/dyld/dyld_shared_cache_arm64e";
const DYLD: &str = "/usr/lib/dyld";
/// The BuildManifest components holding the shared cache and dyld.
const CRYPTEX: &str = "Cryptex1,SystemOS";
const OS: &str = "OS";

/// `SVC #0x80`.
const SVC_0X80: u32 = 0xd400_1001;
/// X16 = `0x80000000` selects a platform call, whose operation is in X3.
const PLATFORM: i64 = 0x8000_0000;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;

/// The images that issue calls, with the census flag of each.
const IMAGES: [(&str, Image); 3] = [
    (
        "/usr/lib/system/libsystem_kernel.dylib",
        Image::LibsystemKernel,
    ),
    (
        "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit",
        Image::Iokit,
    ),
    (DYLD, Image::Dyld),
];

#[derive(Args)]
pub struct Census {
    /// The macOS restore image.
    #[arg(long)]
    ipsw: PathBuf,
    /// A directory of AEA recipient keys, each named `<header SHA-256>.pem`;
    /// without it each key comes from Apple's public key server.
    #[arg(long)]
    keys: Option<PathBuf>,
}

impl Census {
    pub fn run(&self) -> Result<()> {
        let manifest = archive::manifest(&self.ipsw, None, false)
            .with_context(|| format!("{} is not a macOS restore image", self.ipsw.display()))?;
        let identity = manifest
            .identities
            .iter()
            .find(|identity| {
                identity.restore_behavior.as_deref() == Some("Erase")
                    && [CRYPTEX, OS]
                        .iter()
                        .all(|name| identity.components.contains_key(*name))
            })
            .context("no erase identity names the SystemOS cryptex and the OS volume")?;
        // The decrypted OS volume is several GB: work next to the IPSW.
        let work = tempfile::tempdir_in(
            self.ipsw
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?;
        let root = work.path().join("root");
        let mut zip = zip::ZipArchive::new(File::open(&self.ipsw)?)?;
        for (component, selection) in [
            (CRYPTEX, selection(&[], true)),
            (OS, selection(&[DYLD], false)),
        ] {
            let member = &identity.components[component].path;
            let bytes = zip
                .by_name(member)
                .with_context(|| format!("the IPSW has no member {member}"))?
                .size();
            let metadata =
                aea::inspect_stream(self.ipsw.join(member), bytes, &mut zip.by_name(member)?)
                    .with_context(|| format!("{member} is not an AEA archive"))?;
            let pem = match &self.keys {
                Some(directory) => {
                    let path = directory.join(format!("{}.pem", metadata.header_sha256));
                    fs::read_to_string(&path).with_context(|| {
                        format!("no key for {member} in {}", directory.display())
                    })?
                }
                None => String::from_utf8(aea::fetch_public_key(&metadata)?.body)?,
            };
            let image = work
                .path()
                .join(format!("{}.dmg", component.replace(',', "-")));
            println!("decrypting {component} ({member})");
            aea::decrypt_reader(&metadata, &pem, &mut zip.by_name(member)?, &image)
                .with_context(|| format!("cannot decrypt {member}"))?;
            disk::copy_into(&image, &root, &selection)?;
            fs::remove_file(&image)?;
        }
        let calls = scan_root(&root)?;
        let generated = root_path();
        fs::write(&generated, render(&manifest.product_build, &calls)?)?;
        let status = Command::new("rustfmt")
            .args(["--edition", "2024"])
            .arg(&generated)
            .status()?;
        ensure!(status.success(), "rustfmt failed on {GENERATED}");
        println!("wrote {GENERATED}");
        Ok(())
    }
}

fn root_path() -> PathBuf {
    root().join(GENERATED)
}

fn selection(required: &[&str], shared_cache: bool) -> disk::Selection {
    disk::Selection {
        required: required.iter().map(|path| path.to_string()).collect(),
        optional: vec![],
        shared_cache,
        volume: None,
    }
}

/// An image that issues calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Image {
    LibsystemKernel,
    Iokit,
    Dyld,
}

impl Image {
    fn of(path: &str) -> Option<Self> {
        IMAGES
            .iter()
            .find(|(name, _)| *name == path)
            .map(|(_, image)| *image)
    }

    fn flag(self) -> u8 {
        match self {
            Self::LibsystemKernel => 1 << 0,
            Self::Dyld => 1 << 1,
            Self::Iokit => 1 << 2,
        }
    }
}

/// The table a call belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Area {
    Bsd,
    Mach,
    Platform,
}

/// One call: the stub symbol that names it and the images that issue it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Call {
    stub: String,
    /// The image whose stub names the call: libsystem_kernel's before
    /// IOKit's before dyld's, and the first one in an image.
    named_by: Image,
    images: u8,
}

/// Every call, and how many images and sites were read.
#[derive(Debug, Default)]
struct Calls {
    calls: BTreeMap<(Area, u32), Call>,
    images: usize,
    sites: usize,
}

impl Calls {
    fn add(&mut self, area: Area, number: u32, stub: &str, image: Image) {
        self.sites += 1;
        let call = self.calls.entry((area, number)).or_insert_with(|| Call {
            stub: stub.to_owned(),
            named_by: image,
            images: 0,
        });
        call.images |= image.flag();
        if image < call.named_by {
            call.stub = stub.to_owned();
            call.named_by = image;
        }
    }
}

/// The calls of the shared cache below `root` and of its dyld.
fn scan_root(root: &Path) -> Result<Calls> {
    let mut calls = Calls::default();
    let main = root.join(SHARED_CACHE);
    let data = fs::read(&main).with_context(|| format!("cannot read {}", main.display()))?;
    let suffixes = DyldCache::<Endianness>::subcache_suffixes(data.as_slice())?;
    let subcaches = suffixes
        .iter()
        .map(|suffix| {
            let path = PathBuf::from(format!("{}{suffix}", main.display()));
            fs::read(&path).with_context(|| format!("cannot read {}", path.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    let subcaches: Vec<&[u8]> = subcaches.iter().map(Vec::as_slice).collect();
    let cache = DyldCache::<Endianness>::parse(data.as_slice(), &subcaches)?;
    for image in cache.images() {
        let path = image.path()?;
        scan(path, &image.parse_object()?, &mut calls)?;
        calls.images += 1;
    }
    let dyld = root.join(DYLD.trim_start_matches('/'));
    let data = fs::read(&dyld).with_context(|| format!("cannot read {}", dyld.display()))?;
    scan(DYLD, &object::File::parse(arm64_slice(&data)?)?, &mut calls)?;
    Ok(calls)
}

/// The arm64 Mach-O of `data`, which may be a universal binary.
fn arm64_slice(data: &[u8]) -> Result<&[u8]> {
    fn arm64<'d, A: FatArch>(arches: &[A], data: &'d [u8]) -> Result<&'d [u8]> {
        let arch = arches
            .iter()
            .find(|arch| arch.cputype() == CPU_TYPE_ARM64)
            .context("the universal binary has no arm64 slice")?;
        Ok(arch.data(data)?)
    }
    match FileKind::parse(data)? {
        FileKind::MachOFat32 => arm64(MachOFatFile32::parse(data)?.arches(), data),
        FileKind::MachOFat64 => arm64(MachOFatFile64::parse(data)?.arches(), data),
        _ => Ok(data),
    }
}

/// Add every `SVC #0x80` in the `__text` of `file`, the image at `path`.
fn scan(path: &str, file: &object::File<'_>, calls: &mut Calls) -> Result<()> {
    let Some(text) = file.sections().find(|section| {
        section.name() == Ok("__text") && section.segment_name() == Ok(Some("__TEXT"))
    }) else {
        return Ok(());
    };
    let data = text.data()?;
    let words: Vec<u32> = data
        .as_chunks::<4>()
        .0
        .iter()
        .map(|word| u32::from_le_bytes(*word))
        .collect();
    let sites: Vec<usize> = (0..words.len()).filter(|&i| words[i] == SVC_0X80).collect();
    if sites.is_empty() {
        return Ok(());
    }
    let image = Image::of(path).with_context(|| format!("{path} issues SVC #0x80"))?;
    let mut symbols: Vec<(u64, &str)> = file
        .symbols()
        .filter(|symbol| symbol.section_index() == Some(text.index()) && symbol.is_definition())
        .filter_map(|symbol| Some((symbol.address(), symbol.name().ok()?)))
        .collect();
    symbols.sort();
    for site in sites {
        let address = text.address() + 4 * site as u64;
        let &(start, stub) = symbols
            .iter()
            .rev()
            .find(|(start, _)| *start <= address)
            .with_context(|| format!("{path}: SVC at {address:#x} has no stub symbol"))?;
        let first = ((start.max(text.address()) - text.address()) / 4) as usize;
        let stub_words = &words[first..site];
        let x16 = immediate(stub_words, 16)
            .with_context(|| format!("{path}: {stub} does not load X16 with an immediate"))?;
        let (area, number) = match x16 {
            PLATFORM => {
                let operation = immediate(stub_words, 3).with_context(|| {
                    format!("{path}: {stub} does not load X3 with an immediate")
                })?;
                (Area::Platform, u32::try_from(operation)?)
            }
            0.. => (Area::Bsd, u32::try_from(x16)?),
            _ => (Area::Mach, u32::try_from(-x16)?),
        };
        calls.add(area, number, stub, image);
    }
    Ok(())
}

/// The value the last write of register `rd` in `words` gives it, when that
/// write is a `MOVZ` or `MOVN` immediate; `None` when another instruction
/// form writes it last or nothing writes it.
fn immediate(words: &[u32], rd: u32) -> Option<i64> {
    for &word in words.iter().rev() {
        if word & 0x1f != rd {
            continue;
        }
        let wide = word >> 31 != 0;
        let imm = i64::from((word >> 5) & 0xffff);
        let shift = 16 * ((word >> 21) & 3);
        match word & 0x7f80_0000 {
            // MOVZ
            0x5280_0000 => return Some(imm << shift),
            // MOVN
            0x1280_0000 if wide => return Some(!(imm << shift)),
            0x1280_0000 => return Some(i64::from(!((imm << shift) as u32) as i32)),
            // Any other write of the register, e.g. MOVK or a register move.
            _ if writes(word, rd) => return None,
            _ => {}
        }
    }
    None
}

/// Whether `word`, whose Rd field is `rd`, writes it: data-processing,
/// load and move forms; stores, branches and compares do not.
fn writes(word: u32, rd: u32) -> bool {
    let op0 = (word >> 25) & 0xf;
    let store = op0 & 0b0101 == 0b0100 && (word >> 22) & 1 == 0;
    let branch = op0 & 0b1110 == 0b1010;
    let compare = rd == 31;
    !(store || branch || compare)
}

/// `n` with thousands separators.
fn grouped(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// The census module for `build`, before rustfmt.
fn render(build: &str, calls: &Calls) -> Result<String> {
    let mut out = String::new();
    writeln!(
        out,
        "//! The {build} call-site census: every `SVC #0x80` in the guest shared\n\
         //! cache and in dyld, with the call number its stub loads into X16 and\n\
         //! the stub's symbol, from the IPSW's images (the `__text` of all\n\
         //! {} cached images and of `/usr/lib/dyld`); each X16 is a\n\
         //! `MOVZ`/`MOVN` immediate within the stub, and no site sets it from a\n\
         //! register. {} sites name {} distinct calls. Numbers and symbol names\n\
         //! only; no Apple bytes. Regenerate with `cargo xtask census --ipsw PATH`.\n\
         use super::{{DYLD, IOKIT, LIBSYSTEM_KERNEL, Site}};\n",
        grouped(calls.images),
        grouped(calls.sites),
        grouped(calls.calls.len()),
    )?;
    for (area, comment, name) in [
        (Area::Bsd, "BSD system calls (X16 >= 0), by number.", "BSD"),
        (Area::Mach, "Mach traps (X16 = -index), by index.", "MACH"),
        (
            Area::Platform,
            "Platform calls (X16 = `0x80000000`, operation in X3).",
            "PLATFORM",
        ),
    ] {
        writeln!(out, "/// {comment}\npub const {name}: &[Site] = &[")?;
        for ((_, number), call) in calls.calls.range((area, 0)..=(area, u32::MAX)) {
            let flags: Vec<&str> = [
                (1 << 1, "DYLD"),
                (1 << 2, "IOKIT"),
                (1 << 0, "LIBSYSTEM_KERNEL"),
            ]
            .iter()
            .filter(|(flag, _)| call.images & flag != 0)
            .map(|(_, name)| *name)
            .collect();
            ensure!(!flags.is_empty(), "call {number} has no image");
            writeln!(
                out,
                "    Site::new({number}, {:?}, {}),",
                call.stub,
                flags.join(" | ")
            )?;
        }
        writeln!(out, "];\n")?;
    }
    if calls.calls.is_empty() {
        bail!("the images issue no SVC #0x80");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOVZ_X16: u32 = 0xd280_0010;
    const MOVN_X16: u32 = 0x9280_0010;
    const MOVZ_X3: u32 = 0xd280_0003;
    const RET: u32 = 0xd65f_03c0;

    fn movz(base: u32, imm: u32, hw: u32) -> u32 {
        base | hw << 21 | imm << 5
    }

    /// A minimal arm64 Mach-O dylib whose `__TEXT,__text` holds `stubs`,
    /// each a symbol and its words.
    fn image(stubs: &[(&str, &[u32])]) -> Vec<u8> {
        const TEXT_ADDRESS: u64 = 0x1000;
        let mut text = Vec::new();
        let mut symbols = Vec::new();
        for (name, words) in stubs {
            symbols.push((*name, TEXT_ADDRESS + text.len() as u64));
            for word in *words {
                text.extend(word.to_le_bytes());
            }
        }
        let commands = 72 + 80 + 24;
        let text_offset = 32 + commands;
        let symbol_offset = text_offset + text.len();
        let strings_offset = symbol_offset + 16 * symbols.len();
        let mut strings = vec![0u8];
        let mut nlists = Vec::new();
        for (name, address) in &symbols {
            nlists.extend((strings.len() as u32).to_le_bytes());
            nlists.extend([0x0f, 1]);
            nlists.extend(0u16.to_le_bytes());
            nlists.extend(address.to_le_bytes());
            strings.extend(name.as_bytes());
            strings.push(0);
        }
        let name16 = |name: &str| {
            let mut field = [0u8; 16];
            field[..name.len()].copy_from_slice(name.as_bytes());
            field
        };
        let mut out = Vec::new();
        for word in [
            0xfeed_facfu32,
            CPU_TYPE_ARM64,
            0,
            6,
            2,
            commands as u32,
            0,
            0,
        ] {
            out.extend(word.to_le_bytes());
        }
        // LC_SEGMENT_64 __TEXT with one section.
        out.extend(0x19u32.to_le_bytes());
        out.extend(152u32.to_le_bytes());
        out.extend(name16("__TEXT"));
        let file_bytes = (strings_offset + strings.len()) as u64;
        for value in [TEXT_ADDRESS - text_offset as u64, file_bytes, 0, file_bytes] {
            out.extend(value.to_le_bytes());
        }
        for value in [5u32, 5, 1, 0] {
            out.extend(value.to_le_bytes());
        }
        out.extend(name16("__text"));
        out.extend(name16("__TEXT"));
        out.extend(TEXT_ADDRESS.to_le_bytes());
        out.extend((text.len() as u64).to_le_bytes());
        for value in [text_offset as u32, 2, 0, 0, 0x8000_0400, 0, 0, 0] {
            out.extend(value.to_le_bytes());
        }
        // LC_SYMTAB.
        for value in [
            2u32,
            24,
            symbol_offset as u32,
            symbols.len() as u32,
            strings_offset as u32,
            strings.len() as u32,
        ] {
            out.extend(value.to_le_bytes());
        }
        assert_eq!(out.len(), text_offset);
        out.extend(text);
        out.extend(nlists);
        out.extend(strings);
        out
    }

    fn scanned(path: &str, data: &[u8], calls: &mut Calls) -> Result<()> {
        scan(path, &object::File::parse(data).unwrap(), calls)
    }

    #[test]
    fn stubs_name_bsd_mach_and_platform_calls() {
        let kernel = image(&[
            ("_read", &[movz(MOVZ_X16, 3, 0), SVC_0X80, RET]),
            (
                "_mach_absolute_time",
                &[movz(MOVN_X16, 2, 0), SVC_0X80, RET],
            ),
            (
                "__thread_set_tsd_base",
                &[
                    movz(MOVZ_X3, 2, 0),
                    movz(MOVZ_X16, 0x8000, 1),
                    SVC_0X80,
                    RET,
                ],
            ),
        ]);
        let dyld = image(&[("_read", &[movz(MOVZ_X16, 3, 0), SVC_0X80])]);
        let mut calls = Calls::default();
        scanned(DYLD, &dyld, &mut calls).unwrap();
        scanned(IMAGES[0].0, &kernel, &mut calls).unwrap();
        calls.images = 4088;
        assert_eq!(calls.sites, 4);
        let text = render("26A434", &calls).unwrap();
        assert!(text.contains("all\n//! 4,088 cached images"), "{text}");
        assert!(text.contains("4 sites name 3 distinct calls"), "{text}");
        assert!(text.contains("    Site::new(3, \"_read\", DYLD | LIBSYSTEM_KERNEL),\n"));
        assert!(text.contains(
            "pub const MACH: &[Site] = &[\n    Site::new(3, \"_mach_absolute_time\", LIBSYSTEM_KERNEL),\n];"
        ));
        assert!(text.contains(
            "pub const PLATFORM: &[Site] = &[\n    Site::new(2, \"__thread_set_tsd_base\", LIBSYSTEM_KERNEL),\n];"
        ));
    }

    #[test]
    fn libsystem_kernel_names_a_call_dyld_also_issues() {
        let mut calls = Calls::default();
        let dyld = image(&[("_dyld_read", &[movz(MOVZ_X16, 3, 0), SVC_0X80])]);
        let kernel = image(&[("_read", &[movz(MOVZ_X16, 3, 0), SVC_0X80])]);
        scanned(DYLD, &dyld, &mut calls).unwrap();
        scanned(IMAGES[0].0, &kernel, &mut calls).unwrap();
        assert_eq!(calls.calls[&(Area::Bsd, 3)].stub, "_read");
    }

    #[test]
    fn census_rejects_dynamic_x16_and_unknown_image() {
        let mut calls = Calls::default();
        // MOV X16, X0 (ORR X16, XZR, X0) after the immediate.
        let moved = image(&[("_indirect", &[movz(MOVZ_X16, 3, 0), 0xaa00_03f0, SVC_0X80])]);
        assert!(scanned(IMAGES[0].0, &moved, &mut calls).is_err());
        let other = image(&[("_read", &[movz(MOVZ_X16, 3, 0), SVC_0X80])]);
        let error = scanned("/usr/lib/libother.dylib", &other, &mut calls).unwrap_err();
        assert!(error.to_string().contains("libother"), "{error}");
        // An image without SVC #0x80 needs no classification.
        let quiet = image(&[("_f", &[RET])]);
        scanned("/usr/lib/libother.dylib", &quiet, &mut calls).unwrap();
        assert_eq!(calls.sites, 0);
    }

    #[test]
    fn immediates_decode_like_movz_and_movn() {
        assert_eq!(immediate(&[movz(MOVZ_X16, 0x8000, 1)], 16), Some(PLATFORM));
        assert_eq!(immediate(&[movz(MOVN_X16, 30, 0)], 16), Some(-31));
        // MOVN W16 zero-extends the 32-bit result's bits; the kernel reads
        // the call number as an int.
        assert_eq!(immediate(&[movz(0x1280_0010, 30, 0)], 16), Some(-31));
        // A later MOVK replaces the immediate.
        assert_eq!(immediate(&[movz(MOVZ_X16, 1, 0), 0xf2a0_0010], 16), None);
        // A store of X16 leaves it.
        assert_eq!(immediate(&[movz(MOVZ_X16, 1, 0), 0xf900_0010], 16), Some(1));
        assert_eq!(immediate(&[RET], 16), None);
        assert_eq!(grouped(4088), "4,088");
        assert_eq!(grouped(530), "530");
    }
}
