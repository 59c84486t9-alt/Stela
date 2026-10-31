//! The Linux units that register initcalls and exits, compiled with
//! `stela/registration.h` so a generated image names their records. Linux finds
//! its initcalls in linker sections, which COFF and a static link do not offer;
//! `linux_registry` reads the objects instead, and `stela_linux_start` runs the
//! image at boot.
use super::inputs::{Hash, Limits};
use super::linux_registry::{
    self, Group, Input, InputRoot, Plan, RoleLimits, TargetAbi, Unit as PlanUnit,
};
use super::native::{self, NATIVE_TARGET, out_dir, run};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

const LINUX: &str = "../../third_party/linux";
const REGISTRATION: &str = "src/compat/linux/stela/registration.h";
const DOMAIN: &str = "Stela";
const IMAGE: &str = "stela_linux_nouveau_image";

/// One unit, by its path in Linux's tree, and the module Kbuild builds it into.
#[derive(Clone, Copy)]
pub struct Unit {
    pub source: &'static str,
    pub module: &'static str,
    pub file: &'static str,
}

impl Unit {
    pub fn path(self) -> PathBuf {
        PathBuf::from(format!("{LINUX}/{}.c", self.source))
    }
}

/// The environment's units that register anything nouveau needs run.
pub const ENVIRONMENT: [Unit; 5] = [
    Unit {
        source: "drivers/dma-buf/dma-buf",
        module: "dma_buf",
        file: "drivers/dma-buf/dma-buf",
    },
    Unit {
        source: "drivers/dma-buf/dma-fence",
        module: "dma_fence",
        file: "drivers/dma-buf/dma-fence",
    },
    Unit {
        source: "drivers/gpu/drm/drm_drv",
        module: "drm",
        file: "drivers/gpu/drm/drm",
    },
    Unit {
        source: "drivers/gpu/drm/scheduler/sched_fence",
        module: "gpu_sched",
        file: "drivers/gpu/drm/scheduler/gpu-sched",
    },
    Unit {
        source: "drivers/gpu/drm/display/drm_display_helper_mod",
        module: "drm_display_helper",
        file: "drivers/gpu/drm/display/drm_display_helper",
    },
];

/// The unit a module's registrations came from, compiled.
pub struct Captured {
    unit: Unit,
    token: String,
    object: PathBuf,
    compiler: PathBuf,
    options: Vec<String>,
    dependencies: Vec<PathBuf>,
}

impl Captured {
    pub fn object(&self) -> &Path {
        &self.object
    }
}

/// What registry identifiers admit: letters and digits.
fn token(name: &str) -> String {
    name.chars().filter(char::is_ascii_alphanumeric).collect()
}

fn group_symbol(module: &str) -> String {
    format!("stela_linux_group__{DOMAIN}__{}", token(module))
}

/// The compiler on `PATH`, as the registry records what built each object.
fn resolved(program: &Path) -> PathBuf {
    let found = env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| env::split_paths(&paths).collect::<Vec<_>>())
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| program.to_path_buf());
    fs::canonicalize(&found).unwrap_or_else(|error| panic!("{}: {error}", found.display()))
}

/// Compile `unit` as `ordinal` with its registrations captured. `build` carries
/// the unit's module definitions when its whole port shares them.
pub fn compile(build: &cc::Build, unit: Unit, ordinal: u32) -> Captured {
    let token = token(unit.source.rsplit('/').next().expect("a unit name"));
    let mut build = build.clone();
    build
        .define("STELA_LINUX_CAPTURE_REGISTRATIONS", None)
        .define("STELA_LINUX_REG_DOMAIN", DOMAIN)
        .define("STELA_LINUX_REG_UNIT", token.as_str())
        .define("STELA_LINUX_REG_UNIT_ORDINAL", ordinal.to_string().as_str())
        .define(
            "STELA_LINUX_REG_GROUP_SYMBOL",
            group_symbol(unit.module).as_str(),
        )
        .flag("-include")
        .flag(REGISTRATION);
    if !defines(&build, "-DKBUILD_MODNAME=") {
        build
            .define("KBUILD_MODNAME", format!("\"{}\"", unit.module).as_str())
            .define("KBUILD_MODFILE", format!("\"{}\"", unit.file).as_str());
    }
    let compiler = build.get_compiler();
    let options: Vec<String> = compiler
        .args()
        .iter()
        .map(|option| option.to_string_lossy().into_owned())
        .collect();
    let object = out_dir().join(format!("captured-{token}.o"));
    let depfile = object.with_extension("d");
    run(compiler
        .to_command()
        .arg("-c")
        .arg(unit.path())
        .arg("-o")
        .arg(&object)
        .arg("-MD")
        .arg("-MF")
        .arg(&depfile));
    let dependencies = fs::read_to_string(&depfile)
        .unwrap_or_else(|error| panic!("{}: {error}", depfile.display()))
        .replace("\\\n", " ")
        .split_whitespace()
        .skip(1)
        .map(PathBuf::from)
        .collect();
    Captured {
        unit,
        token,
        object,
        compiler: resolved(compiler.path()),
        options,
        dependencies,
    }
}

fn defines(build: &cc::Build, prefix: &str) -> bool {
    build
        .get_compiler()
        .args()
        .iter()
        .any(|option| option.to_string_lossy().starts_with(prefix))
}

/// An input under one of `roots`, with the hash the registry will recheck.
fn input(path: &Path, roots: &[PathBuf]) -> Input {
    let path = fs::canonicalize(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let (root, relative) = roots
        .iter()
        .enumerate()
        .find_map(|(index, root)| Some((index, path.strip_prefix(root).ok()?.to_path_buf())))
        .unwrap_or_else(|| panic!("{} is outside the build's roots", path.display()));
    let bytes = fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let sha256: Hash = Sha256::digest(bytes).into();
    Input {
        root,
        relative,
        sha256,
    }
}

/// The generated source naming every captured unit's records.
pub fn image(captured: &[Captured]) -> PathBuf {
    let compiler = captured.first().expect("a captured unit").compiler.clone();
    let roots = [
        fs::canonicalize("../..").expect("the workspace root"),
        fs::canonicalize(out_dir()).expect("Cargo's output directory"),
        compiler
            .parent()
            .expect("a compiler directory")
            .to_path_buf(),
    ];
    let cohort = out_dir().join("initcall-units.txt");
    let listing = captured
        .iter()
        .map(|unit| format!("{} {}\n", unit.unit.module, unit.unit.source))
        .collect::<String>();
    fs::write(&cohort, listing).expect("write the initcall units");
    let mut groups: Vec<Group> = Vec::new();
    for unit in captured {
        let name = token(unit.unit.module);
        if groups.iter().all(|group| group.token != name) {
            groups.push(Group {
                ordinal: groups.len() as u32 + 1,
                token: name,
                module_name: unit.unit.module.into(),
                module_file: unit.unit.file.into(),
                provenance: format!("Kbuild's {}", unit.unit.file),
            });
        }
    }
    let units = captured
        .iter()
        .enumerate()
        .map(|(index, unit)| PlanUnit {
            token: unit.token.clone(),
            ordinal: index as u32 + 1,
            group_token: token(unit.unit.module),
            source: input(&unit.unit.path(), &roots),
            source_label: unit.unit.source.into(),
            provenance: format!("Linux's {}", unit.unit.source),
            object: input(&unit.object, &roots),
            compiler: input(&unit.compiler, &roots),
            options: unit.options.clone(),
            dependencies: unit
                .dependencies
                .iter()
                .map(|path| input(path, &roots))
                .collect(),
        })
        .collect();
    let os = env::var("CARGO_CFG_TARGET_OS").expect("Cargo supplies the target OS");
    let plan = Plan {
        roots: roots
            .iter()
            .map(|root| InputRoot {
                label: root.display().to_string(),
                selected: root.clone(),
            })
            .collect(),
        input_limits: Limits {
            max_unique_files: 16 * 1024,
            max_unique_bytes: 4 << 30,
            max_roots: roots.len(),
        },
        role_limits: RoleLimits {
            cohort_bytes: 64 << 10,
            source_bytes: 4 << 20,
            compiler_bytes: 1 << 30,
            dependency_bytes: 64 << 20,
            object_bytes: 64 << 20,
        },
        domain_token: DOMAIN.into(),
        domain_ordinal: 1,
        target: match os.as_str() {
            "uefi" => TargetAbi::CoffWin64Lp64,
            "macos" => TargetAbi::MachOSysv,
            _ => TargetAbi::ElfSysv,
        },
        target_triple: if os == "uefi" {
            NATIVE_TARGET.into()
        } else {
            env::var("TARGET").expect("Cargo supplies TARGET")
        },
        image_symbol: IMAGE.into(),
        cohort: input(&cohort, &roots),
        groups,
        units,
    };
    let manifest = linux_registry::generate(&plan).unwrap_or_else(|error| panic!("{error}"));
    assert!(manifest.records > 0, "no unit registered anything");
    let source = out_dir().join("initcall-image.c");
    fs::write(&source, manifest.c_source).expect("write the initcall image");
    let receipt = source.with_extension("receipt");
    fs::write(receipt, manifest.receipt).expect("write the initcall receipt");
    native::rerun_on(&cohort);
    source
}
