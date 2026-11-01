//! nouveau: the `nouveau-y` composite of its own Kbuild, compiled unchanged in
//! Stela's Linux environment, and the kernel services it imports that the
//! environment does not yet supply.
use super::initcalls::{self, Captured, Unit};
use super::kbuild::{Config, Kbuild};
use super::native::{self, Linux, Module};
use object::{Object, ObjectSymbol, read::archive::ArchiveFile};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::Path,
    thread,
};

const NOUVEAU: &str = "../../third_party/linux/drivers/gpu/drm/nouveau";
const AUTOCONF: &str = "src/compat/linux/generated/autoconf.h";
const KERNEL: &str = "src/compat/linux/kernel";
const MODULE: Module = Module {
    name: "nouveau",
    file: "drivers/gpu/drm/nouveau/nouveau",
};
/// Kbuild's composite: nouveau's DRM layer over NVIF and NVKM.
const COMPOSITES: [&str; 1] = ["nouveau"];

/// What the compiler itself calls, which every platform's runtime supplies.
const RUNTIME: [&str; 4] = ["memcpy", "memmove", "memset", "memcmp"];
/// The prefix of what Stela's Rust side exports to the environment.
const PLATFORM: &str = "stela_linux_";

/// The kernel services the composites import that Stela's Linux environment
/// lacks, or defines only as a trap, by service. Building fails when the
/// imports change, so each supplied service leaves this list with its change.
const OPEN: &[(&str, &[&str])] = &[
    // Traps nothing nouveau runs reaches. Shmem-backed pages: TTM allocates
    // from its own pool and Stela never swaps it out.
    (
        "shmem and page cache",
        &[
            "__folio_batch_release",
            "__folio_lock",
            "check_move_unevictable_folios",
            "folio_clear_dirty_for_io",
            "folio_mark_accessed",
            "folio_mark_dirty",
            "folio_unlock",
            "mark_page_accessed",
            "mm_get_unmapped_area",
            "set_page_dirty",
            "shmem_read_folio_gfp",
            "shmem_read_mapping_page_gfp",
            "shmem_truncate_range",
            "shmem_writeout",
        ],
    ),
    // Nothing tears a pseudo filesystem's superblock down.
    ("pseudo filesystems", &["kill_anon_super"]),
    ("DRM leases", &["dentry_open"]),
    (
        "HDMI audio",
        &["device_link_add", "platform_device_unregister"],
    ),
];

/// The unit of nouveau's own `module_init`.
const INITCALLS: Unit = Unit {
    source: "drivers/gpu/drm/nouveau/nouveau_drm",
    module: MODULE.name,
    file: MODULE.file,
};

pub fn port(linux: &mut Linux) {
    let config = Config::parse(&fs::read_to_string(AUTOCONF).expect("read Stela's Kconfig header"))
        .unwrap_or_else(|error| panic!("{AUTOCONF}: {error}"));
    let kbuild =
        Kbuild::read(Path::new(NOUVEAU), &config).unwrap_or_else(|error| panic!("{error}"));
    for file in &kbuild.files {
        println!("cargo:rerun-if-changed={}", file.display());
    }
    let mut sources = Vec::new();
    for composite in COMPOSITES {
        let objects = kbuild
            .objects(composite)
            .unwrap_or_else(|error| panic!("{error}"));
        sources.extend(
            objects
                .iter()
                .map(|object| Path::new(NOUVEAU).join(object).with_extension("c")),
        );
    }
    let includes = kbuild
        .includes
        .iter()
        .map(|directory| {
            let relative = directory
                .strip_prefix(NOUVEAU)
                .expect("Kbuild includes lie in nouveau's tree");
            Path::new("nouveau").join(relative).display().to_string()
        })
        .collect::<Vec<_>>();
    let includes = includes.iter().map(String::as_str).collect::<Vec<_>>();
    // Compiled below, with its registrations captured.
    sources.retain(|source| *source != INITCALLS.path());
    let mut build = stela_c_build::native::configure();
    linux.apply(&mut build, None, &includes, Some(&MODULE));
    native::upstream_warnings(&mut build);
    // As Kbuild builds every profile: Linux relies on the optimizer to drop
    // the calls its configuration disables.
    build.opt_level(2).cargo_metadata(false);
    let jobs = env::var("NUM_JOBS")
        .ok()
        .and_then(|jobs| jobs.parse().ok())
        .unwrap_or(1)
        .max(1);
    let objects = thread::scope(|scope| {
        sources
            .chunks(sources.len().div_ceil(jobs))
            .map(|chunk| {
                let build = &build;
                scope.spawn(move || build.clone().files(chunk).compile_intermediates())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .flat_map(|compiling| compiling.join().expect("a compiling thread"))
            .collect::<Vec<_>>()
    });
    let mut captured = linux.take_captured();
    captured.push(initcalls::compile(
        &build,
        INITCALLS,
        captured.len() as u32 + 1,
    ));
    let image = initcalls::image(&captured);
    build
        .objects(objects)
        .objects(captured.iter().map(Captured::object))
        .file(image)
        .compile("stela-nouveau-nvkm");
    let archive = native::out_dir().join("libstela-nouveau-nvkm.a");
    check_imports(&archive, &linux.archive);
    // Hosted programs test the environment and link no driver.
    if env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "uefi") {
        println!("cargo:rustc-link-lib=static=stela-nouveau-nvkm");
    }
}

/// Compare the services the composites reach when linked, directly or through
/// the environment's objects, and that nothing supplies, with [`OPEN`].
fn check_imports(port: &Path, environment: &Path) {
    let port = members(port);
    let environment = members(environment);
    let definers = environment
        .iter()
        .flat_map(|member| member.defined.iter().map(move |symbol| (symbol, member)))
        .collect::<BTreeMap<_, _>>();
    let defined = port
        .iter()
        .flat_map(|member| &member.defined)
        .collect::<BTreeSet<_>>();
    let traps = traps();
    let mut reached = port
        .iter()
        .flat_map(|member| &member.imported)
        .filter(|symbol| !defined.contains(symbol))
        .collect::<Vec<_>>();
    let mut seen = reached.iter().copied().collect::<BTreeSet<_>>();
    let mut open = BTreeSet::new();
    while let Some(symbol) = reached.pop() {
        if traps.contains(symbol) {
            open.insert(symbol.clone());
        }
        match definers.get(symbol) {
            Some(member) => reached.extend(
                member
                    .imported
                    .iter()
                    .filter(|&import| !defined.contains(import) && seen.insert(import)),
            ),
            None if RUNTIME.contains(&symbol.as_str()) || symbol.starts_with(PLATFORM) => {}
            None => {
                open.insert(symbol.clone());
            }
        }
    }
    let mut stale = Vec::new();
    for symbol in OPEN.iter().flat_map(|(_, symbols)| symbols.iter()) {
        if !open.remove(*symbol) {
            stale.push(*symbol);
        }
    }
    assert!(
        open.is_empty() && stale.is_empty(),
        "nouveau's imports changed: newly open {open:?}; now supplied {stale:?}"
    );
}

/// What one archive member defines and imports.
struct Member {
    defined: BTreeSet<String>,
    imported: BTreeSet<String>,
}

fn members(archive: &Path) -> Vec<Member> {
    let data = fs::read(archive).unwrap_or_else(|error| panic!("{}: {error}", archive.display()));
    let archive = ArchiveFile::parse(&*data).expect("an archive");
    archive
        .members()
        .map(|member| {
            let member = member.expect("an archive member");
            let object = object::File::parse(member.data(&*data).expect("member data"))
                .expect("an object file");
            let (mut defined, mut imported) = (BTreeSet::new(), BTreeSet::new());
            for symbol in object.symbols() {
                let Ok(name) = symbol.name() else {
                    continue;
                };
                if symbol.is_undefined() {
                    imported.insert(name.to_owned());
                } else if symbol.is_global() {
                    defined.insert(name.to_owned());
                }
            }
            Member { defined, imported }
        })
        .collect()
}

/// What the environment defines without serving: functions that trap
/// (`STELA_UNSUPPORTED`), placeholder objects (`STELA_UNSUPPORTED_OBJECT`)
/// and functions that report themselves unsupported and fail.
fn traps() -> BTreeSet<String> {
    let mut traps = BTreeSet::new();
    for source in native::sources(KERNEL) {
        let text = fs::read_to_string(&source).expect("read a kernel-API source");
        for (marker, field) in [
            ("STELA_UNSUPPORTED(", 1),
            ("STELA_UNSUPPORTED_OBJECT(", 1),
            ("stela_linux_unsupported(\"", 0),
        ] {
            for definition in text.split(marker).skip(1) {
                let end = definition.find([')', '"']).unwrap_or(definition.len());
                if let Some(name) = definition[..end].split(',').nth(field) {
                    traps.insert(name.trim().to_owned());
                }
            }
        }
    }
    traps
}
