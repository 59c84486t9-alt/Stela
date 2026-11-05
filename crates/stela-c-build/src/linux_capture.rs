//! The Linux units that register initcalls and exits, compiled with
//! `stela/registration.h` so a generated image names their records. Linux finds
//! its initcalls in linker sections, which COFF and a static link do not offer;
//! `linux_registry` reads the objects instead, and `stela_linux_start` runs the
//! image at boot.
use crate::inputs::{Hash, Inputs, Limits, Request, RootId};
use crate::linux_build::{out_dir, rerun_on, run};
use crate::linux_registry::{
    self, Group, Input, InputRoot, Plan, RoleLimits, TargetAbi, Unit as PlanUnit,
};
use crate::native::NATIVE_TARGET;
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt, fs,
    path::{Path, PathBuf},
};

const LINUX: &str = "../../third_party/linux";
const DOMAIN: &str = "Stela";
// Source-owned image limits; imports cannot enlarge the selected policy.
const MAX_IMAGE_UNITS: usize = 2048;
const MAX_COHORT_BYTES: u64 = 256 << 10;

/// One unit, by its path in Linux's tree, and the module Kbuild builds it into.
#[derive(Clone, Debug)]
pub struct Unit {
    pub source: String,
    pub module: String,
    pub file: String,
}

impl Unit {
    pub fn path(&self) -> PathBuf {
        PathBuf::from(format!("{LINUX}/{}.c", self.source))
    }
}

/// A build owner's reviewed source/module identity, independent of artifacts.
#[derive(Clone, Copy, Debug)]
pub struct UnitSpec {
    pub scope: Scope,
    pub source: &'static str,
    pub module: &'static str,
    pub file: &'static str,
}

/// Stable source-owned occurrence identity, independent of artifact paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scope {
    pub slice: &'static str,
    pub group: &'static str,
    pub group_ordinal: u32,
    pub unit_ordinal: u32,
    pub global_ordinal: u32,
}
impl Scope {
    fn token(self) -> String {
        format!(
            "s{}g{}u{}n{}",
            self.slice, self.group, self.unit_ordinal, self.global_ordinal
        )
    }
}

/// Caller-selected placement. Artifact bytes never provide source/output roots.
#[derive(Clone, Debug)]
pub struct Placement {
    source: PathBuf,
    output: PathBuf,
    roots: Vec<PathBuf>,
}
// Normalize only lexical components before choosing an explicit input root.
// Below-root names remain intact for descriptor-relative no-follow access.
fn absolute_lexical(path: &Path) -> Result<PathBuf, ImportError> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        env::current_dir()
            .map_err(|error| ImportError::Input(error.to_string()))?
            .join(path)
    };
    let mut result = PathBuf::new();
    for part in path.components() {
        match part {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if result.file_name().is_none() || !result.pop() {
                    return Err(ImportError::Schema(
                        "input path escapes its absolute prefix",
                    ));
                }
            }
            part => result.push(part.as_os_str()),
        }
    }
    Ok(result)
}

impl Placement {
    pub fn new(source: &Path, output: &Path, roots: &[&Path]) -> Result<Self, ImportError> {
        let canonical = |path: &Path| {
            fs::canonicalize(path).map_err(|error| ImportError::Input(error.to_string()))
        };
        let source = absolute_lexical(source)?;
        let output_root = output;
        let output = canonical(output)?;
        let mut selected = roots.to_vec();
        selected.push(output_root);
        let mut actual_roots = Vec::new();
        let mut actual_source = None;
        for selected in selected {
            let lexical = absolute_lexical(selected)?;
            let root = canonical(selected)?;
            if root.parent().is_none() {
                return Err(ImportError::Schema(
                    "filesystem-wide placement input root refused",
                ));
            }
            if actual_source.is_none() {
                let relative = source
                    .strip_prefix(&lexical)
                    .or_else(|_| source.strip_prefix(&root));
                if let Ok(relative) = relative {
                    crate::inputs::validate_relative(relative).map_err(ImportError::Input)?;
                    let mut owner = Inputs::new(Limits {
                        max_unique_files: 1,
                        max_unique_bytes: 4 << 20,
                        max_roots: 1,
                    })
                    .map_err(ImportError::Input)?;
                    let id = owner.add_root(&root).map_err(ImportError::Input)?;
                    let key = owner
                        .prepare(&[Request {
                            root: id,
                            relative,
                            expected_sha256: None,
                            max_bytes: 4 << 20,
                        }])
                        .map_err(ImportError::Input)?[0];
                    owner.verify(key).map_err(ImportError::Input)?;
                    owner.finish().map_err(ImportError::Input)?;
                    actual_source = Some(root.join(relative));
                }
            }
            if !actual_roots.contains(&root) {
                actual_roots.push(root);
            }
        }
        Ok(Self {
            source: actual_source.ok_or(ImportError::Schema(
                "source leaves caller-owned placement roots",
            ))?,
            output,
            roots: actual_roots,
        })
    }
}

pub fn validate_units(units: &[UnitSpec]) -> Result<(), ImportError> {
    if units.is_empty() || units.len() > MAX_IMAGE_UNITS {
        return Err(ImportError::Schema(
            "explicit cohort must fit the source-owned image unit limit",
        ));
    }
    let mut globals = BTreeSet::new();
    let mut occurrences = BTreeSet::new();
    let mut tokens = BTreeSet::new();
    let mut groups = BTreeMap::new();
    let mut group_ordinals = BTreeMap::new();
    let mut previous = 0;
    for spec in units {
        let scope = spec.scope;
        let valid = |s: &str| {
            !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric())
        };
        crate::inputs::validate_relative(Path::new(&format!("{}.c", spec.source)))
            .map_err(ImportError::Input)?;
        if !valid(scope.slice)
            || !valid(scope.group)
            || scope.group_ordinal == 0
            || scope.group_ordinal > 65536
            || scope.unit_ordinal == 0
            || scope.unit_ordinal > 65536
            || scope.global_ordinal > 65536
            || scope.global_ordinal <= previous
            || !globals.insert(scope.global_ordinal)
            || !occurrences.insert((scope.group, scope.unit_ordinal))
            || !tokens.insert(scope.token())
        {
            return Err(ImportError::Schema(
                "invalid or duplicate scoped occurrence/ordinal",
            ));
        }
        previous = scope.global_ordinal;
        let group = (scope.group_ordinal, spec.module, spec.file);
        if groups
            .insert(scope.group, group)
            .is_some_and(|old| old != group)
            || group_ordinals
                .insert(scope.group_ordinal, scope.group)
                .is_some_and(|old| old != scope.group)
        {
            return Err(ImportError::Schema(
                "inconsistent source-owned group identity",
            ));
        }
    }
    Ok(())
}

/// The common runtime's fixed prefix in every class image.
pub const COMMON: &[UnitSpec] = &[
    UnitSpec {
        scope: Scope {
            slice: "common",
            group: "rtmutexapi",
            group_ordinal: 1,
            unit_ordinal: 1,
            global_ordinal: 1,
        },
        source: "kernel/locking/rtmutex_api",
        module: "rtmutex_api",
        file: "kernel/locking/rtmutex_api",
    },
    UnitSpec {
        scope: Scope {
            slice: "common",
            group: "dmabuf",
            group_ordinal: 2,
            unit_ordinal: 1,
            global_ordinal: 2,
        },
        source: "drivers/dma-buf/dma-buf",
        module: "dma_buf",
        file: "drivers/dma-buf/dma-buf",
    },
    UnitSpec {
        scope: Scope {
            slice: "common",
            group: "dmafence",
            group_ordinal: 3,
            unit_ordinal: 1,
            global_ordinal: 3,
        },
        source: "drivers/dma-buf/dma-fence",
        module: "dma_fence",
        file: "drivers/dma-buf/dma-fence",
    },
    UnitSpec {
        scope: Scope {
            slice: "common",
            group: "softirq",
            group_ordinal: 4,
            unit_ordinal: 1,
            global_ordinal: 4,
        },
        source: "kernel/softirq",
        module: "softirq",
        file: "kernel/softirq",
    },
];

impl From<UnitSpec> for Unit {
    fn from(spec: UnitSpec) -> Self {
        Self {
            source: spec.source.into(),
            module: spec.module.into(),
            file: spec.file.into(),
        }
    }
}

/// The unit a module's registrations came from, compiled.
#[derive(Clone, Debug)]
pub struct Captured {
    unit: Unit,
    scope: Scope,
    source: PathBuf,
    /// Established by the local compiler or caller policy, never decoded.
    reviewed_roots: Vec<PathBuf>,
    ordinal: u32,
    token: String,
    object: PathBuf,
    compiler: PathBuf,
    options: Vec<String>,
    directory: PathBuf,
    dependencies: Vec<PathBuf>,
    pins: BTreeMap<PathBuf, Hash>,
}

impl Captured {
    fn pin(&self, path: &Path) -> Option<Hash> {
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            fs::canonicalize(path).expect("captured input")
        };
        self.pins.get(&path).copied()
    }
    pub fn object(&self) -> &Path {
        &self.object
    }
}

/// What registry identifiers admit: letters and digits.
pub fn token(name: &str) -> String {
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
        .map(|directory| {
            let mut candidate = directory.join(program).into_os_string();
            candidate.push(env::consts::EXE_SUFFIX);
            PathBuf::from(candidate)
        })
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| program.to_path_buf());
    fs::canonicalize(&found).unwrap_or_else(|error| panic!("{}: {error}", found.display()))
}

/// The exact command context the source owner permits importing. Relative
/// options are meaningful only under this independently selected directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Profile {
    pub directory: PathBuf,
    pub options: Vec<String>,
}

/// Derive a producer command from source-owned flags and occurrence identity.
/// This executes no C compilation and never reads artifact options.
pub fn profile(
    build: &cc::Build,
    registration: &Path,
    spec: UnitSpec,
    directory: &Path,
) -> Profile {
    let prepared = prepared(build, registration, spec);
    Profile {
        directory: fs::canonicalize(directory).expect("producer working directory"),
        options: prepared
            .get_compiler()
            .args()
            .iter()
            .map(|option| {
                option
                    .to_str()
                    .expect("compiler options must be UTF-8")
                    .to_owned()
            })
            .collect(),
    }
}

fn prepared(build: &cc::Build, registration: &Path, spec: UnitSpec) -> cc::Build {
    validate_units(&[spec]).expect("source-owned unit identity");
    let unit = Unit::from(spec);
    let token = spec.scope.token();
    let ordinal = spec.scope.global_ordinal;
    let mut build = build.clone();
    assert!(
        !build.get_compiler().args().iter().any(|a| {
            let a = a.to_str().expect("compiler options must be UTF-8");
            a == "-DMODULE" || a.starts_with("-DMODULE=")
        }),
        "selected scoped profile requires built-in translation units"
    );
    build
        .define("STELA_LINUX_CAPTURE_REGISTRATIONS", None)
        .define("STELA_LINUX_REG_DOMAIN", DOMAIN)
        .define("STELA_LINUX_REG_UNIT", token.as_str())
        .define("STELA_LINUX_REG_UNIT_ORDINAL", ordinal.to_string().as_str())
        .define(
            "STELA_LINUX_REG_GROUP_SYMBOL",
            group_symbol(spec.scope.group).as_str(),
        )
        .flag("-include")
        .flag(registration);
    if !defines(&build, "-DKBUILD_MODNAME=") {
        build
            .define("KBUILD_MODNAME", format!("\"{}\"", unit.module).as_str())
            .define("KBUILD_MODFILE", format!("\"{}\"", unit.file).as_str());
    }
    if !defines(&build, "-D__KBUILD_MODNAME=") {
        build.define("__KBUILD_MODNAME", spec.module);
    }
    if !defines(&build, "-DKBUILD_BASENAME=") {
        let base = spec
            .source
            .rsplit('/')
            .next()
            .expect("reviewed source name")
            .replace(['-', ','], "_");
        build.define("KBUILD_BASENAME", format!("\"{base}\"").as_str());
    }
    build
}

/// Compile one declared scoped occurrence at its caller-owned placement.
/// `build` carries the reviewed native and original per-unit Kbuild flags.
pub fn compile(
    build: &cc::Build,
    registration: &Path,
    spec: UnitSpec,
    placement: &Placement,
) -> Captured {
    let build = prepared(build, registration, spec);
    let unit = Unit::from(spec);
    let token = spec.scope.token();
    let ordinal = spec.scope.global_ordinal;
    let directory = fs::canonicalize(env::current_dir().expect("compiler working directory"))
        .expect("canonical compiler working directory");
    let compiler = build.get_compiler();
    let options = compiler
        .args()
        .iter()
        .map(|option| {
            option
                .to_str()
                .expect("compiler options must be UTF-8")
                .to_owned()
        })
        .collect();
    // System-header diagnostics are normally suppressed. Keep the original
    // function prototypes checked before producing an object for any class.
    crate::linux_build::check_declarations(&build, std::slice::from_ref(&placement.source));
    let object = placement.output.join(format!("captured-{token}.o"));
    let depfile = object.with_extension("d");
    run(compiler
        .to_command()
        .arg("-c")
        .arg(&placement.source)
        .arg("-o")
        .arg(&object)
        .arg("-MD")
        .arg("-MF")
        .arg(&depfile));
    let dependencies = fs::read_to_string(&depfile)
        .unwrap_or_else(|error| panic!("{}: {error}", depfile.display()))
        .lines()
        .flat_map(|line| line.trim_end_matches('\\').split_whitespace())
        .skip(1)
        .map(|path| fs::canonicalize(path).expect("captured dependency"))
        .collect();
    let compiler = resolved(compiler.path());
    let reviewed_roots = placement.roots.clone();
    let source = placement.source.clone();
    Captured {
        unit,
        scope: spec.scope,
        source,
        reviewed_roots,
        ordinal,
        token,
        object,
        compiler,
        options,
        directory,
        dependencies,
        pins: BTreeMap::new(),
    }
}

fn defines(build: &cc::Build, prefix: &str) -> bool {
    build.get_compiler().args().iter().any(|option| {
        option
            .to_str()
            .expect("compiler options must be UTF-8")
            .starts_with(prefix)
    })
}

/// Bounded hash-only snapshots over the explicitly reviewed build roots.
struct Snapshot {
    owner: Inputs,
    roots: Vec<(PathBuf, RootId)>,
}
impl Snapshot {
    fn new(roots: &[PathBuf]) -> Self {
        let mut owner = Inputs::new(Limits {
            max_unique_files: 16 * 1024,
            max_unique_bytes: 4 << 30,
            max_roots: roots.len(),
        })
        .expect("snapshot limits");
        let roots = roots
            .iter()
            .map(|root| {
                (
                    root.clone(),
                    owner.add_root(root).expect("reviewed input root"),
                )
            })
            .collect();
        Self { owner, roots }
    }
    fn input(&mut self, path: &Path, expected: Option<Hash>, max_bytes: u64) -> Input {
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            fs::canonicalize(path).expect("selected build input")
        };
        let (index, root, relative) = self
            .roots
            .iter()
            .enumerate()
            .find_map(|(index, (root, id))| {
                Some((index, *id, path.strip_prefix(root).ok()?.to_path_buf()))
            })
            .unwrap_or_else(|| panic!("{} is outside reviewed build roots", path.display()));
        let key = self
            .owner
            .prepare(&[Request {
                root,
                relative: &relative,
                expected_sha256: expected,
                max_bytes,
            }])
            .expect("prepare build snapshot")[0];
        let binding = self.owner.verify(key).expect("verify build snapshot");
        Input {
            root: index,
            relative,
            sha256: binding.sha256,
        }
    }
    fn finish(self) {
        self.owner
            .finish()
            .expect("build inputs changed during snapshot");
    }
}

/// Resolve the configured compiler before importing any artifact.
pub fn compiler(build: &cc::Build) -> PathBuf {
    resolved(build.get_compiler().path())
}

fn roots(captured: &[Captured]) -> Vec<PathBuf> {
    let mut roots = vec![fs::canonicalize(out_dir()).expect("Cargo output directory")];
    for unit in captured {
        for root in &unit.reviewed_roots {
            if !roots.contains(root) {
                roots.push(root.clone());
            }
        }
    }
    roots
}

/// The only roots and source identities a dependent build permits importing.
pub struct Import<'a> {
    pub output: &'a Path,
    pub compiler: &'a Path,
    pub units: &'a [UnitSpec],
    pub placements: &'a [Placement],
    pub profiles: &'a [Profile],
    /// Digest published by the producer build through Cargo metadata.
    pub sha256: &'a str,
}

#[derive(Debug)]
pub enum ImportError {
    Input(String),
    Schema(&'static str),
    Identity { index: usize, field: &'static str },
    Path { index: usize, field: &'static str },
}
impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => write!(f, "captured input: {error}"),
            Self::Schema(error) => write!(f, "captured cohort schema: {error}"),
            Self::Identity { index, field } => {
                write!(f, "captured unit {index} differs from reviewed {field}")
            }
            Self::Path { index, field } => {
                write!(f, "captured unit {index} leaves reviewed {field}")
            }
        }
    }
}
impl std::error::Error for ImportError {}

fn identity(unit: &Captured, spec: UnitSpec, index: usize) -> Result<(), ImportError> {
    for (field, selected, expected) in [
        ("source", unit.unit.source.as_str(), spec.source),
        ("module", unit.unit.module.as_str(), spec.module),
        ("module file", unit.unit.file.as_str(), spec.file),
    ] {
        if selected != expected {
            return Err(ImportError::Identity { index, field });
        }
    }
    if unit.scope != spec.scope || unit.ordinal != spec.scope.global_ordinal {
        return Err(ImportError::Identity {
            index,
            field: "ordinal",
        });
    }
    let expected = spec.scope.token();
    if unit.token != expected {
        return Err(ImportError::Identity {
            index,
            field: "token",
        });
    }
    Ok(())
}

/// The descriptor owner and imported prefix for one registry composition.
pub struct Projection<'a> {
    pub symbol: &'a str,
    pub expected: &'a [UnitSpec],
    pub imported_units: usize,
    pub descriptors_only: bool,
}

/// Generate either an archive's descriptors or the final canonical image.
pub fn source(captured: &[Captured], projection: Projection<'_>) -> PathBuf {
    let Projection {
        symbol,
        expected,
        imported_units: shared_count,
        descriptors_only,
    } = projection;
    assert_eq!(
        captured.len(),
        expected.len(),
        "reviewed source cohort count"
    );
    validate_units(expected).expect("source-owned projection policy");
    for (index, (unit, spec)) in captured.iter().zip(expected).enumerate() {
        identity(unit, *spec, index).unwrap_or_else(|error| panic!("{error}"));
    }
    assert!(
        shared_count <= captured.len(),
        "imported prefix exceeds reviewed cohort"
    );
    let roots = roots(captured);
    let mut snapshot = Snapshot::new(&roots);
    let listing = captured
        .iter()
        .map(|unit| {
            format!(
                "{} {} {} {} {} {} {}\n",
                unit.scope.slice,
                unit.scope.group,
                unit.scope.group_ordinal,
                unit.scope.unit_ordinal,
                unit.scope.global_ordinal,
                unit.unit.module,
                unit.unit.source
            )
        })
        .collect::<String>();
    let cohort = write_cohort(&out_dir(), symbol, &listing);
    let mut groups: Vec<Group> = Vec::new();
    for unit in captured {
        let name = unit.scope.group.to_string();
        if groups.iter().all(|group| group.token != name) {
            groups.push(Group {
                ordinal: unit.scope.group_ordinal,
                token: name,
                module_name: unit.unit.module.clone(),
                module_file: unit.unit.file.clone(),
                provenance: format!("Kbuild's {}", unit.unit.file),
            });
        }
    }
    let units = captured
        .iter()
        .map(|unit| PlanUnit {
            token: unit.token.clone(),
            ordinal: unit.ordinal,
            group_token: unit.scope.group.into(),
            source: snapshot.input(&unit.source, unit.pin(&unit.source), 4 << 20),
            source_label: unit.unit.source.clone(),
            provenance: format!("Linux's {}", unit.unit.source),
            object: snapshot.input(&unit.object, unit.pin(&unit.object), 64 << 20),
            compiler: snapshot.input(&unit.compiler, unit.pin(&unit.compiler), 1 << 30),
            options: unit.options.clone(),
            working_directory: unit.directory.clone(),
            dependencies: unit
                .dependencies
                .iter()
                .map(|path| snapshot.input(path, unit.pin(path), 64 << 20))
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
            cohort_bytes: MAX_COHORT_BYTES,
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
        image_symbol: symbol.into(),
        cohort: snapshot.input(&cohort, None, MAX_COHORT_BYTES),
        groups,
        units,
    };
    snapshot.finish();
    let shared_groups = captured[..shared_count]
        .iter()
        .map(|unit| unit.scope.group.into())
        .collect::<Vec<_>>();
    let shared_units = captured[..shared_count]
        .iter()
        .map(|unit| unit.token.clone())
        .collect::<Vec<_>>();
    let manifest = linux_registry::generate_with_imports(&plan, &shared_groups, &shared_units)
        .unwrap_or_else(|error| panic!("{error}"));
    // A selected helper slice may legitimately contain zero registration records.
    let suffix = if descriptors_only {
        "descriptors"
    } else {
        "image"
    };
    let source = out_dir().join(format!("{symbol}-{suffix}.c"));
    let generated = if descriptors_only {
        manifest.descriptor_source
    } else {
        manifest.c_source
    };
    fs::write(&source, generated).expect("write the registry projection");
    let receipt = source.with_extension("receipt");
    use sha2::{Digest, Sha256};
    let bytes = fs::read(&source).expect("generated registry source");
    let hash = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let receipt_text = format!(
        r#"{}{{"projection":"{suffix}","projection_sha256":"{hash}"}}"#,
        manifest.receipt
    ) + "\n";
    fs::write(receipt, receipt_text).expect("write the initcall receipt");
    rerun_on(&cohort);
    source
}

// Only the caller-owned output directory is resolved, never an imported file.
// Snapshot still opens the generated leaf through its no-follow input boundary.
fn write_cohort(directory: &Path, symbol: &str, listing: &str) -> PathBuf {
    let cohort = fs::canonicalize(directory)
        .expect("Cargo output directory")
        .join(format!("{symbol}-units.txt"));
    // The cohort is a watched integrity input. Preserve its timestamp when
    // unchanged, or Cargo would invalidate this build as soon as it finishes.
    if fs::read(&cohort).ok().as_deref() != Some(listing.as_bytes()) {
        fs::write(&cohort, listing).expect("write the initcall units");
    }
    cohort
}

/// Export a captured cohort for a dependent Cargo build. Paths are absolute;
/// every consumed source/object/header/compiler digest is pinned at publication.
pub fn write(path: &Path, captured: &[Captured]) -> String {
    fn field(output: &mut Vec<u8>, value: &str) {
        output.extend_from_slice(&(value.len() as u32).to_le_bytes());
        output.extend_from_slice(value.as_bytes());
    }
    fn file(output: &mut Vec<u8>, snapshot: &mut Snapshot, path: &Path, limit: u64) {
        field(output, path.to_str().expect("UTF-8 captured path"));
        output.extend_from_slice(&snapshot.input(path, None, limit).sha256);
    }
    let mut snapshot = Snapshot::new(&roots(captured));
    let mut output = b"STELA-LINUX-CAPTURE-3\0".to_vec();
    output.extend_from_slice(&(captured.len() as u32).to_le_bytes());
    for unit in captured {
        field(&mut output, unit.scope.slice);
        field(&mut output, unit.scope.group);
        for ordinal in [
            unit.scope.group_ordinal,
            unit.scope.unit_ordinal,
            unit.scope.global_ordinal,
        ] {
            output.extend_from_slice(&ordinal.to_le_bytes());
        }
        for value in [
            &unit.unit.source,
            &unit.unit.module,
            &unit.unit.file,
            &unit.token,
        ] {
            field(&mut output, value);
        }
        output.extend_from_slice(&unit.ordinal.to_le_bytes());
        file(&mut output, &mut snapshot, &unit.object, 64 << 20);
        file(&mut output, &mut snapshot, &unit.compiler, 1 << 30);
        file(&mut output, &mut snapshot, &unit.source, 4 << 20);
        field(
            &mut output,
            unit.directory
                .to_str()
                .expect("compiler directory is UTF-8"),
        );
        output.extend_from_slice(&(unit.options.len() as u32).to_le_bytes());
        for option in &unit.options {
            field(&mut output, option);
        }
        output.extend_from_slice(&(unit.dependencies.len() as u32).to_le_bytes());
        for dependency in &unit.dependencies {
            file(&mut output, &mut snapshot, dependency, 64 << 20);
        }
    }
    snapshot.finish();
    let sha256 = cohort_digest(&output);
    write_export(path, &output);
    sha256
}

// This producer owns the generated metadata leaf. Identical complete bytes
// must not manufacture a change for downstream Cargo watchers. All source,
// object/header/compiler hashing and Snapshot.finish still precede this step.
fn write_export(path: &Path, bytes: &[u8]) {
    assert!(
        !fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()),
        "owned captured metadata leaf must not be a symlink"
    );
    let same_size = fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.len() == u64::try_from(bytes.len()).expect("bounded serialized metadata size")
    });
    if !same_size || fs::read(path).ok().as_deref() != Some(bytes) {
        fs::write(path, bytes).expect("write captured cohort");
    }
}

fn cohort_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn expected_digest(value: &str) -> Result<Hash, ImportError> {
    if value.len() != 64 {
        return Err(ImportError::Schema(
            "producer SHA-256 must have 64 hex digits",
        ));
    }
    let mut digest = [0; 32];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = char::from(pair[0])
            .to_digit(16)
            .ok_or(ImportError::Schema("producer SHA-256 is not hexadecimal"))?;
        let low = char::from(pair[1])
            .to_digit(16)
            .ok_or(ImportError::Schema("producer SHA-256 is not hexadecimal"))?;
        digest[index] = (high * 16 + low) as u8;
    }
    Ok(digest)
}

/// Import only the caller's reviewed cohort. Artifact contents cannot choose
/// source identities, compiler identity, object locations or additional roots.
pub fn read(policy: Import<'_>) -> Result<Vec<Captured>, ImportError> {
    validate_units(policy.units)?;
    if policy.placements.len() != policy.units.len() {
        return Err(ImportError::Schema("declared placement count differs"));
    }
    if policy.profiles.len() != policy.units.len() {
        return Err(ImportError::Schema(
            "declared compiler profile count differs",
        ));
    }
    for profile in policy.profiles {
        if !profile.directory.is_absolute()
            || fs::canonicalize(&profile.directory).ok().as_ref() != Some(&profile.directory)
        {
            return Err(ImportError::Schema(
                "expected compiler directory must be canonical",
            ));
        }
    }
    let sha256 = expected_digest(policy.sha256)?;
    let canonical =
        |path: &Path| fs::canonicalize(path).map_err(|error| ImportError::Input(error.to_string()));
    let output = canonical(policy.output)?;
    let compiler = canonical(policy.compiler)?;
    let selected = Boundary {
        output,
        compiler,
        units: policy.units,
        placements: policy.placements.to_vec(),
        profiles: policy.profiles.to_vec(),
    };
    const LIMIT: u64 = 16 << 20;
    let mut owner = Inputs::new(Limits {
        max_unique_files: 1,
        max_unique_bytes: LIMIT,
        max_roots: 1,
    })
    .map_err(ImportError::Input)?;
    let root = owner
        .add_root(&selected.output)
        .map_err(ImportError::Input)?;
    let key = owner
        .prepare(&[Request {
            root,
            relative: Path::new("captured-units.bin"),
            expected_sha256: Some(sha256),
            max_bytes: LIMIT,
        }])
        .map_err(ImportError::Input)?[0];
    let bytes = owner.read(key).map_err(ImportError::Input)?;
    let captured = decode(&bytes, &selected)?;
    owner.finish().map_err(ImportError::Input)?;
    rerun_on(&selected.output.join("captured-units.bin"));
    Ok(captured)
}

/// Compose only explicitly configured producer slices in global ordinal order.
pub fn compose(
    expected: &[UnitSpec],
    slices: &[&[Captured]],
) -> Result<Vec<Captured>, ImportError> {
    validate_units(expected)?;
    if slices.is_empty() || slices.iter().any(|slice| slice.is_empty()) {
        return Err(ImportError::Schema("configured slices must be nonempty"));
    }
    let count = slices.iter().try_fold(0usize, |n, slice| {
        n.checked_add(slice.len())
            .ok_or(ImportError::Schema("slice count overflow"))
    })?;
    if count != expected.len() {
        return Err(ImportError::Schema("configured slice/unit count differs"));
    }
    let captured = slices
        .iter()
        .flat_map(|slice| slice.iter().cloned())
        .collect::<Vec<_>>();
    let mut objects = BTreeSet::new();
    for (index, (unit, spec)) in captured.iter().zip(expected).enumerate() {
        identity(unit, *spec, index)?;
        if unit.pins.is_empty() || !objects.insert(unit.object.clone()) {
            return Err(ImportError::Identity {
                index,
                field: "unique pinned producer object",
            });
        }
    }
    Ok(captured)
}

/// Require every imported unit to pin the same independently selected header.
///
/// Actual bytes for all dependencies are verified again by source generation.
pub fn require_header_pin(
    captured: &[Captured],
    header: &Path,
    expected_sha256: &str,
) -> Result<(), ImportError> {
    if captured.is_empty() {
        return Err(ImportError::Schema(
            "shared header requires a nonempty cohort",
        ));
    }
    let expected = expected_digest(expected_sha256)?;
    let header = fs::canonicalize(header).map_err(|error| ImportError::Input(error.to_string()))?;
    for (index, unit) in captured.iter().enumerate() {
        if !unit.dependencies.contains(&header) || unit.pin(&header) != Some(expected) {
            return Err(ImportError::Identity {
                index,
                field: "shared configuration header pin",
            });
        }
    }
    Ok(())
}

/// Require independently configured source pins in the already reviewed order.
pub fn require_source_pins(
    captured: &[Captured],
    expected_sha256: &[&str],
) -> Result<(), ImportError> {
    if captured.is_empty() || captured.len() != expected_sha256.len() {
        return Err(ImportError::Schema("reviewed source pin count differs"));
    }
    for (index, (unit, expected)) in captured.iter().zip(expected_sha256).enumerate() {
        if unit.pin(&unit.source) != Some(expected_digest(expected)?) {
            return Err(ImportError::Identity {
                index,
                field: "reviewed source pin",
            });
        }
    }
    Ok(())
}

struct Boundary<'a> {
    output: PathBuf,
    compiler: PathBuf,
    units: &'a [UnitSpec],
    placements: Vec<Placement>,
    profiles: Vec<Profile>,
}
impl Boundary<'_> {
    fn roots(&self) -> Vec<PathBuf> {
        let mut roots = Vec::new();
        if !roots.contains(&self.output) {
            roots.push(self.output.clone());
        }
        for placement in &self.placements {
            for root in &placement.roots {
                if !roots.contains(root) {
                    roots.push(root.clone());
                }
            }
        }
        roots
    }
    fn contains(&self, index: usize, path: &Path) -> bool {
        self.placements[index].roots.iter().any(|root| {
            path.strip_prefix(root)
                .ok()
                .is_some_and(|relative| crate::inputs::validate_relative(relative).is_ok())
        })
    }
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn bytes(&mut self, count: usize) -> Result<&'a [u8], ImportError> {
        if count > self.0.len() {
            return Err(ImportError::Schema("truncated cohort"));
        }
        let (value, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(value)
    }
    fn count(&mut self) -> Result<usize, ImportError> {
        let count = u32::from_le_bytes(self.bytes(4)?.try_into().expect("four bytes")) as usize;
        if count > 64 * 1024 {
            return Err(ImportError::Schema("field/count exceeds limit"));
        }
        Ok(count)
    }
    fn string(&mut self) -> Result<String, ImportError> {
        let count = self.count()?;
        let value = std::str::from_utf8(self.bytes(count)?)
            .map_err(|_| ImportError::Schema("non-UTF-8 field"))?;
        if value.contains('\0') {
            return Err(ImportError::Schema("NUL field"));
        }
        Ok(value.into())
    }
    fn file(&mut self, pins: &mut BTreeMap<PathBuf, Hash>) -> Result<PathBuf, ImportError> {
        let path = PathBuf::from(self.string()?);
        let expected = self.bytes(32)?.try_into().expect("SHA-256 pin");
        if pins
            .insert(path.clone(), expected)
            .is_some_and(|previous| previous != expected)
        {
            return Err(ImportError::Schema("conflicting input pins"));
        }
        Ok(path)
    }
}

fn decode(bytes: &[u8], selected: &Boundary<'_>) -> Result<Vec<Captured>, ImportError> {
    if bytes.len() > 16 << 20 {
        return Err(ImportError::Schema("cohort exceeds limit"));
    }
    validate_units(selected.units)?;
    if selected.placements.len() != selected.units.len() {
        return Err(ImportError::Schema("declared placement count differs"));
    }
    if selected.profiles.len() != selected.units.len() {
        return Err(ImportError::Schema(
            "declared compiler profile count differs",
        ));
    }
    for spec in selected.units {
        crate::inputs::validate_relative(Path::new(&format!("{}.c", spec.source)))
            .map_err(ImportError::Input)?;
    }
    let mut reader = Reader(bytes);
    if reader.bytes(22)? != b"STELA-LINUX-CAPTURE-3\0" {
        return Err(ImportError::Schema("unsupported cohort version"));
    }
    let count = reader.count()?;
    if count != selected.units.len() {
        return Err(ImportError::Schema("reviewed cohort count differs"));
    }
    let mut captured = Vec::new();
    for (index, spec) in selected.units.iter().enumerate() {
        let slice = reader.string()?;
        let group = reader.string()?;
        let group_ordinal = reader.count()? as u32;
        let unit_ordinal = reader.count()? as u32;
        let global_ordinal = reader.count()? as u32;
        if slice != spec.scope.slice
            || group != spec.scope.group
            || group_ordinal != spec.scope.group_ordinal
            || unit_ordinal != spec.scope.unit_ordinal
            || global_ordinal != spec.scope.global_ordinal
        {
            return Err(ImportError::Identity {
                index,
                field: "scope/group/slice/global ordinal",
            });
        }
        let unit = Unit {
            source: reader.string()?,
            module: reader.string()?,
            file: reader.string()?,
        };
        let token = reader.string()?;
        let ordinal = reader.count()? as u32;
        let mut pins = BTreeMap::new();
        let object = reader.file(&mut pins)?;
        let compiler = reader.file(&mut pins)?;
        let source = reader.file(&mut pins)?;
        let directory = PathBuf::from(reader.string()?);
        let options = (0..reader.count()?)
            .map(|_| reader.string())
            .collect::<Result<Vec<_>, _>>()?;
        let dependencies = (0..reader.count()?)
            .map(|_| reader.file(&mut pins))
            .collect::<Result<Vec<_>, _>>()?;
        let unit = Captured {
            unit,
            scope: spec.scope,
            source,
            ordinal,
            token,
            object,
            compiler,
            options,
            directory,
            dependencies,
            pins,
            reviewed_roots: selected.roots(),
        };
        identity(&unit, *spec, index)?;
        let profile = &selected.profiles[index];
        if unit.directory != profile.directory || unit.options != profile.options {
            return Err(ImportError::Identity {
                index,
                field: "compiler command profile",
            });
        }
        if unit
            .options
            .iter()
            .any(|a| a == "-DMODULE" || a.starts_with("-DMODULE="))
        {
            return Err(ImportError::Identity {
                index,
                field: "built-in compiler profile",
            });
        }
        let expected_source = selected.placements[index].source.clone();
        if unit.source != expected_source {
            return Err(ImportError::Path {
                index,
                field: "Linux source",
            });
        }
        let output = &selected.placements[index].output;
        let expected_object = output.join(format!("captured-{}.o", unit.token));
        if unit.object != expected_object {
            return Err(ImportError::Path {
                index,
                field: "shared output",
            });
        }
        if unit.compiler != selected.compiler {
            return Err(ImportError::Path {
                index,
                field: "compiler",
            });
        }
        if unit.dependencies.is_empty()
            || unit
                .dependencies
                .iter()
                .any(|path| !selected.contains(index, path))
        {
            return Err(ImportError::Path {
                index,
                field: "dependency roots",
            });
        }
        captured.push(unit);
    }
    if !reader.0.is_empty() {
        return Err(ImportError::Schema("trailing cohort bytes"));
    }
    Ok(captured)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "linux_capture/export_tests.rs"]
mod export_tests;
