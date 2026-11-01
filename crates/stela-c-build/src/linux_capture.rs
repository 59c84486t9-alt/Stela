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
    collections::BTreeMap,
    env, fmt, fs,
    path::{Path, PathBuf},
};

const LINUX: &str = "../../third_party/linux";
const DOMAIN: &str = "Stela";

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
    pub source: &'static str,
    pub module: &'static str,
    pub file: &'static str,
}

/// The common runtime's fixed prefix in every class image.
pub const COMMON: &[UnitSpec] = &[
    UnitSpec {
        source: "kernel/locking/rtmutex_api",
        module: "rtmutex",
        file: "kernel/locking/rtmutex",
    },
    UnitSpec {
        source: "drivers/dma-buf/dma-buf",
        module: "dma_buf",
        file: "drivers/dma-buf/dma-buf",
    },
    UnitSpec {
        source: "drivers/dma-buf/dma-fence",
        module: "dma_fence",
        file: "drivers/dma-buf/dma-fence",
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
    source: PathBuf,
    /// Established by the local compiler or caller policy, never decoded.
    reviewed_roots: Vec<PathBuf>,
    ordinal: u32,
    token: String,
    object: PathBuf,
    compiler: PathBuf,
    options: Vec<String>,
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

/// Compile `unit` as `ordinal` with its registrations captured. `build` carries
/// the unit's module definitions when its whole port shares them.
pub fn compile(build: &cc::Build, registration: &Path, unit: Unit, ordinal: u32) -> Captured {
    let token = token(unit.source.rsplit('/').next().expect("a unit name"));
    let mut build = build.clone();
    build
        .define("STELA_LINUX_CAPTURE_REGISTRATIONS", None)
        .define("STELA_LINUX_REG_DOMAIN", DOMAIN)
        .define("STELA_LINUX_REG_UNIT", token.as_str())
        .define("STELA_LINUX_REG_UNIT_ORDINAL", ordinal.to_string().as_str())
        .define(
            "STELA_LINUX_REG_GROUP_SYMBOL",
            group_symbol(&unit.module).as_str(),
        )
        .flag("-include")
        .flag(registration);
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
    let object = fs::canonicalize(out_dir())
        .expect("build output")
        .join(format!("captured-{token}.o"));
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
        .lines()
        .flat_map(|line| line.trim_end_matches('\\').split_whitespace())
        .skip(1)
        .map(|path| fs::canonicalize(path).expect("captured dependency"))
        .collect();
    let compiler = resolved(compiler.path());
    let reviewed_roots = build_roots(&compiler);
    let source = fs::canonicalize(unit.path()).expect("selected Linux source");
    Captured {
        unit,
        source,
        reviewed_roots,
        ordinal,
        token,
        object,
        compiler,
        options,
        dependencies,
        pins: BTreeMap::new(),
    }
}

fn defines(build: &cc::Build, prefix: &str) -> bool {
    build
        .get_compiler()
        .args()
        .iter()
        .any(|option| option.to_string_lossy().starts_with(prefix))
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

fn build_roots(compiler: &Path) -> Vec<PathBuf> {
    vec![
        fs::canonicalize("../..").expect("workspace root"),
        fs::canonicalize(out_dir()).expect("Cargo output directory"),
        compiler.parent().expect("compiler directory").to_path_buf(),
    ]
}

/// Resolve the independently configured compiler before admitting metadata.
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
    pub workspace: &'a Path,
    pub linux: &'a Path,
    pub output: &'a Path,
    pub compiler: &'a Path,
    pub units: &'a [UnitSpec],
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
    if unit.ordinal as usize != index + 1 {
        return Err(ImportError::Identity {
            index,
            field: "ordinal",
        });
    }
    let expected = token(spec.source.rsplit('/').next().expect("reviewed unit name"));
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
        .map(|unit| format!("{} {}\n", unit.unit.module, unit.unit.source))
        .collect::<String>();
    let cohort = write_cohort(&out_dir(), symbol, &listing);
    let mut groups: Vec<Group> = Vec::new();
    for unit in captured {
        let name = token(&unit.unit.module);
        if groups.iter().all(|group| group.token != name) {
            groups.push(Group {
                ordinal: groups.len() as u32 + 1,
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
            group_token: token(&unit.unit.module),
            source: snapshot.input(&unit.source, unit.pin(&unit.source), 4 << 20),
            source_label: unit.unit.source.clone(),
            provenance: format!("Linux's {}", unit.unit.source),
            object: snapshot.input(&unit.object, unit.pin(&unit.object), 64 << 20),
            compiler: snapshot.input(&unit.compiler, unit.pin(&unit.compiler), 1 << 30),
            options: unit.options.clone(),
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
        image_symbol: symbol.into(),
        cohort: snapshot.input(&cohort, None, 64 << 10),
        groups,
        units,
    };
    snapshot.finish();
    let shared_groups = captured[..shared_count]
        .iter()
        .map(|unit| token(&unit.unit.module))
        .collect::<Vec<_>>();
    let shared_units = captured[..shared_count]
        .iter()
        .map(|unit| unit.token.clone())
        .collect::<Vec<_>>();
    let manifest = linux_registry::generate_with_imports(&plan, &shared_groups, &shared_units)
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(manifest.records > 0, "no unit registered anything");
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
    let mut output = b"STELA-LINUX-CAPTURE-1\0".to_vec();
    output.extend_from_slice(&(captured.len() as u32).to_le_bytes());
    for unit in captured {
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
    fs::write(path, output).expect("write captured cohort");
    sha256
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
    let sha256 = expected_digest(policy.sha256)?;
    let canonical =
        |path: &Path| fs::canonicalize(path).map_err(|error| ImportError::Input(error.to_string()));
    let workspace = canonical(policy.workspace)?;
    let linux = canonical(policy.linux)?;
    let output = canonical(policy.output)?;
    let compiler = canonical(policy.compiler)?;
    let compiler_root = compiler
        .parent()
        .ok_or(ImportError::Schema("compiler has no parent"))?
        .to_path_buf();
    if linux
        .strip_prefix(&workspace)
        .ok()
        .is_none_or(|relative| crate::inputs::validate_relative(relative).is_err())
    {
        return Err(ImportError::Schema(
            "Linux source root is outside workspace",
        ));
    }
    let selected = Boundary {
        linux,
        output,
        compiler,
        units: policy.units,
        roots: vec![workspace, compiler_root],
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

struct Boundary<'a> {
    linux: PathBuf,
    output: PathBuf,
    compiler: PathBuf,
    units: &'a [UnitSpec],
    roots: Vec<PathBuf>,
}
impl Boundary<'_> {
    fn roots(&self) -> Vec<PathBuf> {
        let mut roots = self.roots.clone();
        if !roots.contains(&self.output) {
            roots.push(self.output.clone());
        }
        roots
    }
    fn contains(&self, path: &Path) -> bool {
        self.roots
            .iter()
            .chain(std::iter::once(&self.output))
            .any(|root| {
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
    for spec in selected.units {
        crate::inputs::validate_relative(Path::new(&format!("{}.c", spec.source)))
            .map_err(ImportError::Input)?;
    }
    let mut reader = Reader(bytes);
    if reader.bytes(22)? != b"STELA-LINUX-CAPTURE-1\0" {
        return Err(ImportError::Schema("unsupported cohort version"));
    }
    let count = reader.count()?;
    if count != selected.units.len() {
        return Err(ImportError::Schema("reviewed cohort count differs"));
    }
    let mut captured = Vec::new();
    for (index, spec) in selected.units.iter().enumerate() {
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
        let options = (0..reader.count()?)
            .map(|_| reader.string())
            .collect::<Result<Vec<_>, _>>()?;
        let dependencies = (0..reader.count()?)
            .map(|_| reader.file(&mut pins))
            .collect::<Result<Vec<_>, _>>()?;
        let unit = Captured {
            unit,
            source,
            ordinal,
            token,
            object,
            compiler,
            options,
            dependencies,
            pins,
            reviewed_roots: selected.roots(),
        };
        identity(&unit, *spec, index)?;
        let expected_source = selected.linux.join(format!("{}.c", spec.source));
        if unit.source != expected_source {
            return Err(ImportError::Path {
                index,
                field: "Linux source",
            });
        }
        let expected_object = selected.output.join(format!("captured-{}.o", unit.token));
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
                .any(|path| !selected.contains(path))
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
mod tests {
    //! Imported artifacts cannot grant new roots or alter the reviewed cohort.
    use super::*;
    use tempfile::TempDir;

    struct Fixture {
        _temporary: TempDir,
        boundary: Boundary<'static>,
        captured: Vec<Captured>,
    }
    fn fixture() -> Fixture {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let workspace = root.join("workspace");
        let linux = workspace.join("linux");
        let output = root.join("shared-output");
        let tools = root.join("toolchain");
        for directory in [&linux, &output, &tools] {
            fs::create_dir_all(directory).unwrap();
        }
        let compiler = tools.join("clang");
        fs::write(&compiler, b"fixture compiler identity").unwrap();
        let boundary = Boundary {
            linux,
            output,
            compiler,
            units: COMMON,
            roots: vec![workspace, tools],
        };
        let captured = COMMON
            .iter()
            .enumerate()
            .map(|(index, spec)| {
                let source = boundary.linux.join(format!("{}.c", spec.source));
                let token = token(spec.source.rsplit('/').next().unwrap());
                Captured {
                    unit: (*spec).into(),
                    source: source.clone(),
                    reviewed_roots: boundary.roots(),
                    ordinal: index as u32 + 1,
                    object: boundary.output.join(format!("captured-{token}.o")),
                    compiler: boundary.compiler.clone(),
                    token,
                    options: vec!["-Dfixture=1".into()],
                    dependencies: vec![source],
                    pins: BTreeMap::new(),
                }
            })
            .collect();
        Fixture {
            _temporary: temporary,
            boundary,
            captured,
        }
    }
    fn encode(captured: &[Captured]) -> Vec<u8> {
        fn field(bytes: &mut Vec<u8>, value: &str) {
            bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
        fn file(bytes: &mut Vec<u8>, path: &Path) {
            field(bytes, path.to_str().unwrap());
            bytes.extend_from_slice(&[1; 32]);
        }
        let mut bytes = b"STELA-LINUX-CAPTURE-1\0".to_vec();
        bytes.extend_from_slice(&(captured.len() as u32).to_le_bytes());
        for unit in captured {
            for value in [
                &unit.unit.source,
                &unit.unit.module,
                &unit.unit.file,
                &unit.token,
            ] {
                field(&mut bytes, value);
            }
            bytes.extend_from_slice(&unit.ordinal.to_le_bytes());
            file(&mut bytes, &unit.object);
            file(&mut bytes, &unit.compiler);
            file(&mut bytes, &unit.source);
            bytes.extend_from_slice(&(unit.options.len() as u32).to_le_bytes());
            for option in &unit.options {
                field(&mut bytes, option);
            }
            bytes.extend_from_slice(&(unit.dependencies.len() as u32).to_le_bytes());
            for dependency in &unit.dependencies {
                file(&mut bytes, dependency);
            }
        }
        bytes
    }

    #[test]
    fn reviewed_common_cohort_retains_pins_and_only_caller_owned_roots() {
        let fixture = fixture();
        let observed = decode(&encode(&fixture.captured), &fixture.boundary).unwrap();
        assert_eq!(observed.len(), 3);
        for (index, unit) in observed.iter().enumerate() {
            identity(unit, COMMON[index], index).unwrap();
            assert_eq!(unit.reviewed_roots, fixture.boundary.roots());
            assert_eq!(unit.pin(&unit.object), Some([1; 32]));
            assert_eq!(unit.pin(&unit.compiler), Some([1; 32]));
            assert_eq!(unit.pin(&unit.source), Some([1; 32]));
        }
    }

    #[test]
    fn imported_cohort_identity_order_and_count_are_exact() {
        let fixture = fixture();
        for field in ["source", "module", "module file", "token", "ordinal"] {
            let mut changed = fixture.captured.clone();
            match field {
                "source" => changed[0].unit.source = "lib/sort".into(),
                "module" => changed[0].unit.module = "other".into(),
                "module file" => changed[0].unit.file = "lib/other".into(),
                "token" => changed[0].token = "other".into(),
                "ordinal" => changed[0].ordinal = 2,
                _ => unreachable!(),
            }
            assert!(matches!(decode(&encode(&changed), &fixture.boundary),
                Err(ImportError::Identity { index: 0, field: rejected }) if rejected == field));
        }
        let mut changed = fixture.captured.clone();
        changed.swap(0, 1);
        assert!(matches!(
            decode(&encode(&changed), &fixture.boundary),
            Err(ImportError::Identity { index: 0, .. })
        ));
        for count in [2, 4] {
            let mut changed = fixture.captured.clone();
            changed.resize(count, fixture.captured[0].clone());
            assert!(matches!(
                decode(&encode(&changed), &fixture.boundary),
                Err(ImportError::Schema("reviewed cohort count differs"))
            ));
        }
    }

    #[test]
    fn metadata_cannot_select_object_source_compiler_or_dependency_roots() {
        let fixture = fixture();
        let unrelated = fixture._temporary.path().join("unreviewed");
        for (field, path) in [
            ("shared output", unrelated.join("captured-rtmutexapi.o")),
            (
                "shared output",
                fixture.boundary.output.join("../captured-rtmutexapi.o"),
            ),
            ("Linux source", unrelated.join("rtmutex_api.c")),
            (
                "Linux source",
                fixture.boundary.linux.join("kernel/locking/other.c"),
            ),
            (
                "compiler",
                fixture.boundary.compiler.with_file_name("other-clang"),
            ),
            ("dependency roots", unrelated.join("header.h")),
            (
                "dependency roots",
                fixture.boundary.output.join("../header.h"),
            ),
        ] {
            let mut changed = fixture.captured.clone();
            match field {
                "shared output" => changed[0].object = path,
                "Linux source" => changed[0].source = path,
                "compiler" => changed[0].compiler = path,
                "dependency roots" => changed[0].dependencies = vec![path],
                _ => unreachable!(),
            }
            assert!(
                matches!(decode(&encode(&changed), &fixture.boundary),
                Err(ImportError::Path { index: 0, field: rejected }) if rejected == field),
                "{field}"
            );
        }
    }

    #[test]
    fn malformed_versions_lengths_truncation_and_trailing_bytes_refuse() {
        for bad in ["", "ff", &"x".repeat(64)] {
            assert!(matches!(expected_digest(bad), Err(ImportError::Schema(_))));
        }
        let fixture = fixture();
        let bytes = encode(&fixture.captured);
        for length in [0, 21, 25, bytes.len() - 1] {
            assert!(matches!(
                decode(&bytes[..length], &fixture.boundary),
                Err(ImportError::Schema(_))
            ));
        }
        let mut changed = bytes.clone();
        changed[20] = b'2';
        assert!(matches!(
            decode(&changed, &fixture.boundary),
            Err(ImportError::Schema("unsupported cohort version"))
        ));
        let mut changed = bytes.clone();
        changed[26..30].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            decode(&changed, &fixture.boundary),
            Err(ImportError::Schema("field/count exceeds limit"))
        ));
        let mut changed = bytes;
        changed.push(0);
        assert!(matches!(
            decode(&changed, &fixture.boundary),
            Err(ImportError::Schema("trailing cohort bytes"))
        ));
    }

    #[test]
    fn duplicate_paths_with_conflicting_pins_refuse() {
        let fixture = fixture();
        let mut bytes = encode(&fixture.captured);
        let source = fixture.captured[0].source.to_str().unwrap().as_bytes();
        let position = bytes
            .windows(source.len())
            .rposition(|window| window == source)
            .unwrap();
        bytes[position + source.len()] = 2;
        assert!(matches!(
            decode(&bytes, &fixture.boundary),
            Err(ImportError::Schema("conflicting input pins"))
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn bounded_import_reads_only_the_caller_selected_output_and_rejects_symlinks() {
        let fixture = fixture();
        let bytes = encode(&fixture.captured);
        let digest = cohort_digest(&bytes);
        let selected = || Import {
            workspace: &fixture.boundary.roots[0],
            linux: &fixture.boundary.linux,
            output: &fixture.boundary.output,
            compiler: &fixture.boundary.compiler,
            units: COMMON,
            sha256: &digest,
        };
        let path = fixture.boundary.output.join("captured-units.bin");
        fs::write(&path, &bytes).unwrap();
        assert_eq!(read(selected()).unwrap().len(), 3);
        let mut tampered = bytes.clone();
        tampered.push(0);
        fs::write(&path, tampered).unwrap();
        assert!(matches!(read(selected()), Err(ImportError::Input(_))));
        fs::remove_file(&path).unwrap();
        let external = fixture._temporary.path().join("outside-cohort.bin");
        fs::write(&external, encode(&fixture.captured)).unwrap();
        std::os::unix::fs::symlink(&external, &path).unwrap();
        assert!(matches!(read(selected()), Err(ImportError::Input(_))));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn owned_cohort_resolves_output_alias_without_admitting_foreign_inputs() {
        let fixture = fixture();
        let output = &fixture.boundary.output;
        let alias = fixture._temporary.path().join("output-alias");
        std::os::unix::fs::symlink(output, &alias).unwrap();
        let listing = "rtmutex kernel/locking/rtmutex_api\n";
        let path = write_cohort(&alias, "fixture", listing);
        assert_eq!(path, output.join("fixture-units.txt"));
        let past = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_234_567_890);
        fs::File::open(&path).unwrap().set_modified(past).unwrap();
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(write_cohort(&alias, "fixture", listing), path);
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);
        let mut snapshot = Snapshot::new(std::slice::from_ref(output));
        let input = snapshot.input(&path, None, 64 << 10);
        assert_eq!(input.relative, Path::new("fixture-units.txt"));
        snapshot.finish();
        let mut foreign = Snapshot::new(&fixture.boundary.roots[..1]);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                foreign.input(&path, None, 64 << 10);
            }))
            .is_err()
        );
        let external = fixture._temporary.path().join("foreign-units.txt");
        fs::write(&external, listing).unwrap();
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&external, &path).unwrap();
        let mut snapshot = Snapshot::new(std::slice::from_ref(output));
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                snapshot.input(&path, None, 64 << 10);
            }))
            .is_err()
        );
    }
}
