//! Exact-profile original radio compilation and bounded scoped imports.
//!
//! This produces descriptors and archives, never an active image or a device
//! owner. The shared runtime/terminal caller supplies its independently owned
//! whole-image UnitSpecs; this class assigns no global or group ordinals.
use crate::{
    inputs::{Hash, Inputs, Key, Limits, Request},
    linux::{Environment, Module, Roots},
    linux_build::{archive, out_dir, upstream_build, upstream_warnings},
    linux_capture::{
        self as capture, Captured, Import, ImportError, Placement, Projection, UnitSpec,
    },
    native,
};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

mod policy;
use policy::GROUPS;

type Result<T> = std::result::Result<T, ImportError>;
const CONFIG: &str = "55d974270f61468b7cb153ddd2ee227ea2176358d6a0e13108a1a55a617013ae";
const HEADER: &str = "24a6f9d4e1cbdd04b38fe238a038d2b4c9585549131393490219389d72af17bf";
const CERTS: &[(&str, &str)] = &[
    (
        "net/wireless/certs/sforshee.hex",
        "ca3dd4d10995168507e0b7b44621917c7e1e77e73e882f85afa92df86daae77a",
    ),
    (
        "net/wireless/certs/wens.hex",
        "6485f5ddecbecbf73113dc669fe23da07f1a5ab60fb1ad932b0062f9d7fe8753",
    ),
];

/// Producer-owned paths and its explicitly reviewed input roots. Relative
/// compiler paths retain their original meaning under `directory`.
pub struct Layout<'a> {
    pub directory: &'a Path,
    pub linux: &'a Path,
    pub compat: &'a Path,
    pub output: &'a Path,
    pub input_roots: &'a [&'a Path],
}
impl Layout<'_> {
    fn resolve(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_owned()
        } else {
            self.directory.join(path)
        }
    }
    fn environment(&self) -> Environment {
        Environment::from_existing(Roots {
            linux: self.linux.to_owned(),
            compat: self.compat.to_owned(),
            output: self.output.to_owned(),
        })
    }
    fn generated(&self) -> PathBuf {
        self.resolve(self.output).join("radio-generated")
    }
    fn roots(&self) -> Vec<PathBuf> {
        let mut roots = self
            .input_roots
            .iter()
            .map(|path| self.resolve(path))
            .collect::<Vec<_>>();
        let output = self.resolve(self.output);
        if !roots.contains(&output) {
            roots.push(output);
        }
        roots
    }
}

#[derive(Clone, Copy)]
enum Flag {
    Literal(&'static str),
    Include(&'static str),
}
struct Source {
    source: &'static str,
    sha256: &'static str,
    flags: &'static [Flag],
    generated: bool,
}
struct Group {
    slice: &'static str,
    key: &'static str,
    module: &'static str,
    file: &'static str,
    directory: &'static str,
    flags: &'static [Flag],
    sources: &'static [Source],
}

/// Class identity comes from original Kbuild and this source policy. Ordinals
/// remain the shared whole-image caller's decision, independent of artifacts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub slice: &'static str,
    pub group: &'static str,
    pub module: &'static str,
    pub file: &'static str,
    pub source: &'static str,
    pub unit_ordinal: u32,
}
pub fn identities() -> impl Iterator<Item = Identity> {
    GROUPS.iter().flat_map(|group| {
        group
            .sources
            .iter()
            .enumerate()
            .map(move |(index, source)| Identity {
                slice: group.slice,
                group: group.key,
                module: group.module,
                file: group.file,
                source: source.source,
                unit_ordinal: u32::try_from(index + 1).expect("bounded source policy"),
            })
    })
}
pub fn slice_names() -> impl ExactSizeIterator<Item = &'static str> {
    GROUPS.iter().map(|group| group.slice)
}
fn validate_selection(selected: &[UnitSpec]) -> Result<()> {
    capture::validate_units(selected)?;
    if selected.len() != identities().count() {
        return Err(ImportError::Schema(
            "complete exact294 radio cohort required",
        ));
    }
    for (index, (unit, expected)) in selected.iter().zip(identities()).enumerate() {
        if unit.source != expected.source
            || unit.module != expected.module
            || unit.file != expected.file
            || unit.scope.slice != expected.slice
            || unit.scope.group != expected.group
            || unit.scope.unit_ordinal != expected.unit_ordinal
        {
            return Err(ImportError::Identity {
                index,
                field: "source-owned radio selection",
            });
        }
    }
    Ok(())
}
fn input_error(error: impl std::fmt::Display) -> ImportError {
    ImportError::Input(error.to_string())
}
fn hash(text: &str) -> Result<Hash> {
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ImportError::Schema("invalid source-owned radio pin"));
    }
    let mut hash = [0; 32];
    for (index, value) in hash.iter_mut().enumerate() {
        *value = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).map_err(input_error)?;
    }
    Ok(hash)
}
struct Pinned {
    owner: Inputs,
    generated: Key,
    certs: Vec<Key>,
}
fn pinned(layout: &Layout<'_>, generated_exists: bool) -> Result<Pinned> {
    let mut owner = Inputs::new(Limits {
        max_unique_files: 512,
        max_unique_bytes: 128 << 20,
        max_roots: 3,
    })
    .map_err(input_error)?;
    let linux = owner
        .add_root(&layout.resolve(layout.linux))
        .map_err(input_error)?;
    let compat = owner
        .add_root(&layout.resolve(layout.compat))
        .map_err(input_error)?;
    let output = owner
        .add_root(&layout.resolve(layout.output))
        .map_err(input_error)?;
    let mut planned = vec![
        (
            compat,
            PathBuf::from("generated/stela.config"),
            CONFIG,
            64 << 10,
        ),
        (
            compat,
            PathBuf::from("generated/autoconf.h"),
            HEADER,
            64 << 10,
        ),
        (
            linux,
            PathBuf::from("net/wireless/Makefile"),
            "a0fd870352487f084584c1ed24191592d538ee212182c2fe3d709d3a395d24c5",
            32 << 10,
        ),
    ];
    let cert_start = planned.len();
    planned.extend(
        CERTS
            .iter()
            .map(|(path, pin)| (linux, PathBuf::from(*path), *pin, 16 << 10)),
    );
    for group in GROUPS {
        for source in group.sources.iter().filter(|source| !source.generated) {
            planned.push((
                linux,
                PathBuf::from(format!("{}.c", source.source)),
                source.sha256,
                4 << 20,
            ));
        }
    }
    let generated_source = GROUPS
        .iter()
        .flat_map(|group| group.sources)
        .find(|source| source.generated)
        .ok_or(ImportError::Schema(
            "missing selected original generated cert source",
        ))?;
    let generated_index = planned.len();
    planned.push((
        output,
        PathBuf::from(format!("radio-generated/{}.c", generated_source.source)),
        generated_source.sha256,
        32 << 10,
    ));
    let requests = planned
        .iter()
        .map(|(root, path, pin, max_bytes)| {
            Ok(Request {
                root: *root,
                relative: path,
                expected_sha256: Some(hash(pin)?),
                max_bytes: *max_bytes,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let keys = owner.prepare(&requests).map_err(input_error)?;
    for (index, key) in keys.iter().enumerate() {
        if index != generated_index || generated_exists {
            owner.verify(*key).map_err(input_error)?;
        }
    }
    let certificate_directory = layout.resolve(layout.linux).join("net/wireless/certs");
    let mut present = fs::read_dir(&certificate_directory)
        .map_err(input_error)?
        .map(|entry| entry.map(|entry| entry.file_name()).map_err(input_error))
        .collect::<Result<Vec<_>>>()?;
    present.retain(|name| Path::new(name).extension().is_some_and(|ext| ext == "hex"));
    present.sort();
    let expected = CERTS
        .iter()
        .map(|(path, _)| {
            Path::new(path)
                .file_name()
                .expect("source policy leaf")
                .to_os_string()
        })
        .collect::<Vec<_>>();
    if present != expected {
        return Err(ImportError::Schema(
            "original regdb certificate input set changed",
        ));
    }
    Ok(Pinned {
        generated: keys[generated_index],
        certs: keys[cert_start..cert_start + CERTS.len()].to_vec(),
        owner,
    })
}
fn generate_cert_source(layout: &Layout<'_>, pinned: &mut Pinned) -> Result<()> {
    // Original net/wireless/Makefile's sorted .hex concatenation, retaining
    // its initial blank line and exact final declarations. No trust fallback.
    let mut source = b"#include \"reg.h\"\nconst u8 shipped_regdb_certs[] = {\n\n".to_vec();
    for key in &pinned.certs {
        source.extend(pinned.owner.read(*key).map_err(input_error)?);
    }
    source.extend(b"};\nunsigned int shipped_regdb_certs_len = sizeof(shipped_regdb_certs);\n");
    let target = layout.generated().join("net/wireless/shipped-certs.c");
    fs::create_dir_all(target.parent().expect("generated source parent")).map_err(input_error)?;
    if fs::symlink_metadata(&target).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return Err(ImportError::Schema(
            "generated radio source leaf is a symlink",
        ));
    }
    if fs::read(&target).ok().as_deref() != Some(source.as_slice()) {
        fs::write(&target, source).map_err(input_error)?;
    }
    pinned.owner.verify(pinned.generated).map_err(input_error)?;
    Ok(())
}
fn include(build: &mut cc::Build, path: &Path) {
    let mut option = std::ffi::OsString::from("-I");
    option.push(path);
    build.flag(option);
}
fn build(
    layout: &Layout<'_>,
    environment: &Environment,
    group: &Group,
    source: &Source,
) -> cc::Build {
    let mut build = native::configure();
    environment.profile(
        &mut build,
        None,
        &[],
        Some(&Module {
            name: group.module,
            file: group.file,
        }),
    );
    let mut build = upstream_build(&build, layout.compat);
    upstream_warnings(&mut build);
    for flag in group.flags.iter().chain(source.flags) {
        match flag {
            Flag::Literal(flag) => {
                build.flag(flag);
            }
            Flag::Include(path) => {
                include(&mut build, &layout.linux.join(path));
            }
        }
    }
    // Original scripts/Makefile.lib's building_out_of_srctree rule, after
    // per-source flags and before module/capture definitions.
    include(&mut build, &layout.linux.join(group.directory));
    include(
        &mut build,
        &layout.output.join("radio-generated").join(group.directory),
    );
    build
}
fn placements(layout: &Layout<'_>, group: &Group) -> Result<Vec<Placement>> {
    let roots = layout.roots();
    let roots = roots.iter().map(PathBuf::as_path).collect::<Vec<_>>();
    let output = layout
        .resolve(layout.output)
        .join(format!("capture-{}", group.slice));
    group
        .sources
        .iter()
        .map(|source| {
            let source = if source.generated {
                layout.generated()
            } else {
                layout.resolve(layout.linux)
            }
            .join(format!("{}.c", source.source));
            Placement::new(&source, &output, &roots)
        })
        .collect()
}
fn profiles(
    layout: &Layout<'_>,
    environment: &Environment,
    group: &Group,
    selected: &[UnitSpec],
) -> Vec<capture::Profile> {
    let registration = layout.compat.join("stela/registration.h");
    group
        .sources
        .iter()
        .zip(selected)
        .map(|(source, spec)| {
            capture::profile(
                &build(layout, environment, group, source),
                &registration,
                *spec,
                layout.directory,
            )
        })
        .collect()
}
fn check_pins(layout: &Layout<'_>, group: &Group, captured: &[Captured]) -> Result<()> {
    capture::require_source_pins(
        captured,
        &group
            .sources
            .iter()
            .map(|source| source.sha256)
            .collect::<Vec<_>>(),
    )?;
    capture::require_header_pin(
        captured,
        &layout.resolve(layout.compat).join("generated/autoconf.h"),
        HEADER,
    )
}

/// Completed compiler artifacts only. No original radio has registered or
/// acquired a native function; those are separate runtime/ownership gates.
pub struct RadioCapture {
    pub captured: Vec<Captured>,
    pub archives: Vec<PathBuf>,
    pub digests: Vec<String>,
}

pub fn compile(layout: Layout<'_>, selected: &[UnitSpec]) -> Result<RadioCapture> {
    validate_selection(selected)?;
    if fs::canonicalize(env::current_dir().map_err(input_error)?).map_err(input_error)?
        != fs::canonicalize(layout.directory).map_err(input_error)?
        || fs::canonicalize(out_dir()).map_err(input_error)?
            != fs::canonicalize(layout.resolve(layout.output)).map_err(input_error)?
    {
        return Err(ImportError::Schema(
            "radio compilation must run in its actual producer context",
        ));
    }
    let mut pinned = pinned(&layout, false)?;
    generate_cert_source(&layout, &mut pinned)?;
    // The actual producer validates supplemental headers and owns generation.
    // Read-only import reconstruction below never calls this constructor.
    let environment = Environment::new(Roots {
        linux: layout.linux.to_owned(),
        compat: layout.compat.to_owned(),
        output: layout.output.to_owned(),
    });
    let registration = layout.compat.join("stela/registration.h");
    let mut result = RadioCapture {
        captured: Vec::new(),
        archives: Vec::new(),
        digests: Vec::new(),
    };
    let mut offset = 0;
    for group in GROUPS {
        let end = offset + group.sources.len();
        let specs = &selected[offset..end];
        let output = layout
            .resolve(layout.output)
            .join(format!("capture-{}", group.slice));
        fs::create_dir_all(&output).map_err(input_error)?;
        let placements = placements(&layout, group)?;
        let original = group
            .sources
            .iter()
            .zip(specs)
            .zip(&placements)
            .map(|((source, spec), place)| {
                capture::compile(
                    &build(&layout, &environment, group, source),
                    &registration,
                    *spec,
                    place,
                )
            })
            .collect::<Vec<_>>();
        let digest = capture::write(&output.join("captured-units.bin"), &original);
        let profiles = profiles(&layout, &environment, group, specs);
        let compiler = capture::compiler(&build(&layout, &environment, group, &group.sources[0]));
        let captured = capture::read(Import {
            output: &output,
            compiler: &compiler,
            units: specs,
            placements: &placements,
            profiles: &profiles,
            sha256: &digest,
        })?;
        check_pins(&layout, group, &captured)?;
        let symbol = format!("stela_linux_{}_descriptors", group.slice);
        let descriptors = capture::source(
            &captured,
            Projection {
                symbol: &symbol,
                expected: specs,
                imported_units: 0,
                descriptors_only: true,
            },
        );
        let mut archive_build = native::configure();
        environment.profile(&mut archive_build, None, &[], None);
        archive_build
            .cargo_metadata(false)
            .objects(captured.iter().map(Captured::object));
        result.archives.push(archive(
            &archive_build,
            &format!("stela-{}", group.slice),
            &[descriptors],
        ));
        result.digests.push(digest);
        result.captured.extend(captured);
        offset = end;
    }
    pinned.owner.finish().map_err(input_error)?;
    Ok(result)
}

/// Read exactly the class slices declared by source, independently reconstruct
/// producer commands, and retain every source/header/object/compiler pin.
/// Producer metadata supplies locations/digests, never entries or ordinals.
pub fn read(layout: Layout<'_>, selected: &[UnitSpec], digests: &[&str]) -> Result<Vec<Captured>> {
    validate_selection(selected)?;
    if digests.len() != GROUPS.len() {
        return Err(ImportError::Schema(
            "exact radio slice digest count required",
        ));
    }
    let pinned = pinned(&layout, true)?;
    let environment = layout.environment();
    let mut captured = Vec::new();
    let mut offset = 0;
    for (group, digest) in GROUPS.iter().zip(digests) {
        let end = offset + group.sources.len();
        let specs = &selected[offset..end];
        let output = layout
            .resolve(layout.output)
            .join(format!("capture-{}", group.slice));
        let placements = placements(&layout, group)?;
        let profiles = profiles(&layout, &environment, group, specs);
        let compiler = capture::compiler(&build(&layout, &environment, group, &group.sources[0]));
        let units = capture::read(Import {
            output: &output,
            compiler: &compiler,
            units: specs,
            placements: &placements,
            profiles: &profiles,
            sha256: digest,
        })?;
        check_pins(&layout, group, &units)?;
        captured.extend(units);
        offset = end;
    }
    pinned.owner.finish().map_err(input_error)?;
    Ok(captured)
}

#[cfg(test)]
mod tests;
