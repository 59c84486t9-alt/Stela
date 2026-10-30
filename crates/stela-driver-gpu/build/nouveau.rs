//! nouveau's hardware resource manager: the `nvif-y` and `nvkm-y` composites
//! of nouveau's own Kbuild, compiled unchanged in Stela's Linux environment,
//! and the kernel services they import that the environment does not yet
//! supply. The DRM layer (`nouveau-y`'s own objects) needs Linux's DRM core,
//! TTM, scheduler and GPUVM first, and is not built.
use super::kbuild::{Config, Kbuild};
use super::native::{self, Linux, Module};
use object::{Object, ObjectSymbol, read::archive::ArchiveFile};
use std::{collections::BTreeSet, env, fs, path::Path, thread};

const NOUVEAU: &str = "../../third_party/linux/drivers/gpu/drm/nouveau";
const AUTOCONF: &str = "src/compat/linux/generated/autoconf.h";
const KERNEL: &str = "src/compat/linux/kernel";
const MODULE: Module = Module {
    name: "nouveau",
    file: "drivers/gpu/drm/nouveau/nouveau",
};
/// Kbuild's composites, in its link order.
const COMPOSITES: [&str; 2] = ["nvif", "nvkm"];

/// What the compiler itself calls, which every platform's runtime supplies.
const RUNTIME: [&str; 4] = ["memcpy", "memmove", "memset", "memcmp"];

/// The kernel services the composites import that Stela's Linux environment
/// lacks, or defines only as a trap, by service. Building fails when the
/// imports change, so each supplied service leaves this list with its change.
const OPEN: &[(&str, &[&str])] = &[
    (
        "mm/vmalloc.c",
        &[
            "__kvmalloc_node_noprof",
            "vfree",
            "vmalloc_noprof",
            "vmalloc_to_page",
            "vmap",
            "vunmap",
            "vzalloc_noprof",
        ],
    ),
    ("device memory mappings", &["ioremap", "iounmap"]),
    ("DMA pages", &["dma_alloc_pages", "dma_free_pages"]),
    (
        "PCI device control and configuration",
        &[
            "pci_dev_put",
            "pci_disable_device",
            "pci_enable_device",
            "pci_find_capability",
            "pci_get_domain_bus_and_slot",
            "pci_read_config_dword",
            "pci_set_master",
            "pci_write_config_byte",
        ],
    ),
    (
        "PCI option ROMs",
        &[
            "pci_disable_rom",
            "pci_enable_rom",
            "pci_map_rom",
            "pci_unmap_rom",
        ],
    ),
    ("device model references", &["put_device"]),
    ("interrupts", &["free_irq", "request_threaded_irq"]),
    (
        "workqueues",
        &[
            "alloc_workqueue_noprof",
            "destroy_workqueue",
            "flush_work",
            "queue_work_on",
            "system_percpu_wq",
        ],
    ),
    (
        "the I2C core and its bit-banging algorithm",
        &[
            "i2c_add_adapter",
            "i2c_bit_add_bus",
            "i2c_bit_algo",
            "i2c_del_adapter",
            "i2c_new_client_device",
            "i2c_transfer",
            "i2c_unregister_device",
        ],
    ),
    ("orderly shutdown", &["orderly_poweroff"]),
    // NVKM's client driver, defined by nouveau's DRM layer.
    ("nouveau_nvif.c", &["nvif_driver_nvkm"]),
];

pub fn port(linux: &Linux) {
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
    let mut build = native::configure();
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
    build.objects(objects).compile("stela-nouveau-nvkm");
    let archive = native::out_dir().join("libstela-nouveau-nvkm.a");
    check_imports(&archive, &linux.archive);
}

/// Compare the services the composites import, and that neither they, the
/// environment nor the platform runtime supply, with [`OPEN`].
fn check_imports(port: &Path, environment: &Path) {
    let (defined, imported) = symbols(port);
    let (supplied, _) = symbols(environment);
    let traps = traps();
    let mut open = imported
        .difference(&defined)
        .filter(|symbol| !RUNTIME.contains(&symbol.as_str()))
        .filter(|symbol| !supplied.contains(*symbol) || traps.contains(*symbol))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut stale = Vec::new();
    for symbol in OPEN.iter().flat_map(|(_, symbols)| symbols.iter()) {
        if !open.remove(*symbol) {
            stale.push(*symbol);
        }
    }
    assert!(
        open.is_empty() && stale.is_empty(),
        "nouveau's NVKM imports changed: newly open {open:?}; now supplied {stale:?}"
    );
}

/// The symbols an archive's objects define and import.
fn symbols(archive: &Path) -> (BTreeSet<String>, BTreeSet<String>) {
    let data = fs::read(archive).unwrap_or_else(|error| panic!("{}: {error}", archive.display()));
    let archive = ArchiveFile::parse(&*data).expect("an archive");
    let (mut defined, mut imported) = (BTreeSet::new(), BTreeSet::new());
    for member in archive.members() {
        let member = member.expect("an archive member");
        let object =
            object::File::parse(member.data(&*data).expect("member data")).expect("an object file");
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
    }
    (defined, imported)
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
