//! The plan a run executes: its cases, the libraries they name and their
//! inputs. The runner on the Mac and in the guest reads `plan.json`; each
//! input is a file named by its digest, so cases that share inputs share
//! one file.
use super::values::Dtype;
use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    path::Path,
};

/// Each MSL language version with the oldest macOS that compiles it, which
/// sets the AIR version Apple's compiler emits (AIR 1.8 to 2.9), and its
/// `__METAL_VERSION__`.
pub const VERSIONS: [(&str, &str, &str, u32); 12] = [
    ("1.1", "macos-metal1.1", "10.11", 110),
    ("1.2", "macos-metal1.2", "10.12", 120),
    ("2.0", "macos-metal2.0", "10.13", 200),
    ("2.1", "macos-metal2.1", "10.14", 210),
    ("2.2", "macos-metal2.2", "10.15", 220),
    ("2.3", "macos-metal2.3", "11.0", 230),
    ("2.4", "macos-metal2.4", "12.0", 240),
    ("3.0", "metal3.0", "13.0", 300),
    ("3.1", "metal3.1", "14.0", 310),
    ("3.2", "metal3.2", "15.0", 320),
    ("4.0", "metal4.0", "26.0", 400),
    ("4.1", "metal4.1", "27.0", 410),
];
pub const LATEST: &str = "4.1";

pub fn version_flags(version: &str) -> Vec<String> {
    let (_, std, target, _) = VERSIONS
        .iter()
        .find(|v| v.0 == version)
        .unwrap_or_else(|| panic!("unknown MSL version {version}"));
    vec![
        format!("-std={std}"),
        format!("-mmacosx-version-min={target}"),
    ]
}

pub fn metal_version(version: &str) -> u32 {
    VERSIONS
        .iter()
        .find(|v| v.0 == version)
        .map(|v| v.3)
        .unwrap_or_else(|| panic!("{version}"))
}

/// A case name's suffix for an MSL version: none for the latest.
pub fn suffix(version: &str) -> String {
    if version == LATEST {
        String::new()
    } else {
        format!("@{version}")
    }
}

/// How far a result may be from its reference.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Tolerance {
    pub ulp: Option<f64>,
    pub abs: Option<f64>,
    pub rel: Option<f64>,
    /// Integer elements: the largest difference.
    pub units: Option<f64>,
    /// Flush subnormal floats on both sides first (the default).
    pub ftz: Option<bool>,
    /// Distinguish -0 from +0.
    pub signed_zero: Option<bool>,
    /// Accept any value where the reference is NaN or the result is.
    pub nan_ignore: bool,
}

impl Tolerance {
    pub fn exact() -> Self {
        Self::default()
    }

    pub fn ulp(n: f64) -> Self {
        Self {
            ulp: Some(n),
            ..Self::default()
        }
    }

    pub fn abs(x: f64) -> Self {
        Self {
            abs: Some(x),
            ..Self::default()
        }
    }

    pub fn units(n: f64) -> Self {
        Self {
            units: Some(n),
            ..Self::default()
        }
    }

    pub fn with_ulp(mut self, n: f64) -> Self {
        self.ulp = Some(n);
        self
    }

    pub fn with_abs(mut self, x: f64) -> Self {
        self.abs = Some(x);
        self
    }

    pub fn with_rel(mut self, x: f64) -> Self {
        self.rel = Some(x);
        self
    }

    pub fn with_ftz(mut self, ftz: bool) -> Self {
        self.ftz = Some(ftz);
        self
    }

    #[cfg(test)]
    pub fn with_signed_zero(mut self, signed: bool) -> Self {
        self.signed_zero = Some(signed);
        self
    }

    /// The tolerance between two implementations each within this one.
    pub fn doubled(&self) -> Self {
        Self {
            ulp: self.ulp.map(|v| v * 2.0),
            abs: self.abs.map(|v| v * 2.0),
            rel: self.rel.map(|v| v * 2.0),
            ..self.clone()
        }
    }

    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        for (key, value) in [
            ("ulp", self.ulp),
            ("abs", self.abs),
            ("rel", self.rel),
            ("units", self.units),
        ] {
            if let Some(v) = value {
                m.insert(key.into(), number(v));
            }
        }
        if let Some(v) = self.ftz {
            m.insert("ftz".into(), v.into());
        }
        if let Some(v) = self.signed_zero {
            m.insert("signed_zero".into(), v.into());
        }
        if self.nan_ignore {
            m.insert("nan".into(), "ignore".into());
        }
        Value::Object(m)
    }

    pub fn from_json(value: Option<&Value>) -> Self {
        let get = |key: &str| value.and_then(|v| v.get(key)).and_then(Value::as_f64);
        let flag = |key: &str| value.and_then(|v| v.get(key)).and_then(Value::as_bool);
        Self {
            ulp: get("ulp"),
            abs: get("abs"),
            rel: get("rel"),
            units: get("units"),
            ftz: flag("ftz"),
            signed_zero: flag("signed_zero"),
            nan_ignore: value.and_then(|v| v.get("nan")).and_then(Value::as_str) == Some("ignore"),
        }
    }
}

/// A JSON number, integral values written as integers.
pub fn number(v: f64) -> Value {
    if v.fract() == 0.0 && v.abs() < 9e15 {
        json!(v as i64)
    } else {
        json!(v)
    }
}

/// One step of a sequence case. Its bindings name the case's resources:
/// `bind` lists (name, index) for buffers, `bind_textures` for textures and
/// `bind_samplers` for samplers, each optionally with a render stage.
pub struct Step(Map<String, Value>);

impl Step {
    fn new(kind: &str) -> Self {
        let mut json = Map::new();
        json.insert("kind".into(), kind.into());
        Self(json)
    }

    /// A dispatch of `grid` threads in groups of `group`.
    pub fn compute(function: &str, grid: [u32; 3], group: [u32; 3]) -> Self {
        Self::new("compute")
            .set("function", function)
            .set("grid", json!(grid))
            .set("threadgroup", json!(group))
            .set("dispatch", "threads")
    }

    /// A render pass: `state` as for `Case::render`.
    pub fn render(vertex: &str, fragment: &str, state: Value) -> Self {
        Self::new("render")
            .set("vertex", vertex)
            .set("fragment", fragment)
            .set("render", state)
    }

    pub fn blit(commands: Value) -> Self {
        Self::new("blit").set("blits", commands)
    }

    fn bindings(mut self, key: &str, bindings: &[(&str, u32)], stage: Option<&str>) -> Self {
        let list = self.0.entry(key).or_insert_with(|| json!([]));
        for (name, index) in bindings {
            let mut b = json!({"name": name, "index": index});
            if let Some(stage) = stage {
                b["stage"] = stage.into();
            }
            list.as_array_mut().unwrap().push(b);
        }
        self
    }

    pub fn bind(self, buffers: &[(&str, u32)]) -> Self {
        self.bindings("buffers", buffers, None)
    }

    /// Buffers bound to a render stage: vertex, fragment or both.
    pub fn bind_stage(self, stage: &str, buffers: &[(&str, u32)]) -> Self {
        self.bindings("buffers", buffers, Some(stage))
    }

    pub fn bind_textures(self, textures: &[(&str, u32)]) -> Self {
        self.bindings("textures", textures, None)
    }

    /// Dispatches the threadgroup counts a buffer holds at an offset.
    pub fn indirect(self, buffer: &str, offset: u32) -> Self {
        self.set("indirect", json!({"buffer": buffer, "offset": offset}))
    }

    /// Continues the previous step's compute encoder.
    pub fn continues(self) -> Self {
        self.set("continue", true)
    }

    /// Commits the command buffer so far and starts another.
    pub fn new_command_buffer(self) -> Self {
        self.set("new_command_buffer", true)
    }

    pub fn wait_fences(self, fences: &[&str]) -> Self {
        self.set("wait_fences", json!(fences))
    }

    pub fn update_fences(self, fences: &[&str]) -> Self {
        self.set("update_fences", json!(fences))
    }

    /// Before the step, the command buffer waits for each event's value.
    pub fn wait_events(self, events: &[(&str, u64)]) -> Self {
        self.set("wait_events", json!(events))
    }

    /// After the step, the command buffer signals each event's value.
    pub fn signal_events(self, events: &[(&str, u64)]) -> Self {
        self.set("signal_events", json!(events))
    }

    pub fn set(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.0.insert(key.into(), value.into());
        self
    }
}

/// A buffer a case binds, or allocates for an output.
#[derive(Clone)]
pub struct Buffer {
    json: Map<String, Value>,
    data: Option<Vec<u8>>,
}

impl Buffer {
    /// A buffer at an argument index holding these bytes.
    pub fn data(name: &str, index: u32, data: Vec<u8>) -> Self {
        let mut json = Map::new();
        json.insert("name".into(), name.into());
        json.insert("index".into(), index.into());
        Self {
            json,
            data: Some(data),
        }
    }

    /// A zero-filled buffer of a length.
    pub fn zeroed(name: &str, index: u32, length: usize) -> Self {
        let mut json = Map::new();
        json.insert("name".into(), name.into());
        json.insert("index".into(), index.into());
        json.insert("length".into(), length.into());
        Self { json, data: None }
    }

    /// Bound to no argument: storage for a texture buffer or an argument
    /// buffer's pointer.
    pub fn unbound(mut self) -> Self {
        self.json.remove("index");
        self
    }

    /// The render stage it binds to: vertex, fragment or both.
    pub fn stage(self, stage: &str) -> Self {
        self.set("stage", stage)
    }

    pub fn set(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.json.insert(key.into(), value.into());
        self
    }
}

/// A texture a case uploads, binds or renders to.
#[derive(Clone)]
pub struct Texture {
    json: Map<String, Value>,
    data: Option<Vec<u8>>,
    stencil: Option<Vec<u8>>,
}

impl Texture {
    /// A texture of a format and type ("2d", "3d", "cube", ...), bound to
    /// no argument until `index`.
    pub fn new(name: &str, format: &str, kind: &str, size: [u32; 3]) -> Self {
        let mut json = Map::new();
        json.insert("name".into(), name.into());
        json.insert("format".into(), format.into());
        json.insert("type".into(), kind.into());
        json.insert("width".into(), size[0].into());
        json.insert("height".into(), size[1].into());
        json.insert("depth".into(), size[2].into());
        json.insert("usage".into(), json!(["read"]));
        Self {
            json,
            data: None,
            stencil: None,
        }
    }

    pub fn d2(name: &str, format: &str, width: u32, height: u32) -> Self {
        Self::new(name, format, "2d", [width, height, 1])
    }

    pub fn index(self, index: u32) -> Self {
        self.set("index", index)
    }

    pub fn array(self, length: u32) -> Self {
        self.set("array", length)
    }

    pub fn mipmaps(self, levels: u32) -> Self {
        self.set("mipmaps", levels)
    }

    pub fn samples(self, count: u32) -> Self {
        self.set("samples", count)
    }

    pub fn usage(self, usage: &[&str]) -> Self {
        self.set("usage", json!(usage))
    }

    pub fn data(mut self, data: Vec<u8>) -> Self {
        self.data = Some(data);
        self
    }

    /// The stencil aspect's bytes of a combined depth-stencil texture.
    pub fn stencil(mut self, data: Vec<u8>) -> Self {
        self.stencil = Some(data);
        self
    }

    pub fn set(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.json.insert(key.into(), value.into());
        self
    }
}

/// A buffer or texture a case reads back, and what it is checked against.
#[derive(Clone)]
pub struct Output {
    json: Map<String, Value>,
    expect: Option<Vec<u8>>,
    alternatives: Vec<Vec<u8>>,
}

impl Output {
    /// An output compared with the reference device within a tolerance.
    pub fn new(name: &str, dtype: Dtype, tolerance: Tolerance) -> Self {
        let mut json = Map::new();
        json.insert("name".into(), name.into());
        json.insert("dtype".into(), dtype.name().into());
        json.insert("tolerance".into(), tolerance.to_json());
        Self {
            json,
            expect: None,
            alternatives: vec![],
        }
    }

    /// The expected bytes, asserted within a tolerance.
    pub fn expect(mut self, data: Vec<u8>, tolerance: Tolerance) -> Self {
        self.expect = Some(data);
        self.json
            .insert("expect_tolerance".into(), tolerance.to_json());
        self
    }

    /// An output expected bit for bit.
    pub fn exact(name: &str, dtype: Dtype, data: Vec<u8>) -> Self {
        Self::new(name, dtype, Tolerance::exact()).expect_same(data)
    }

    /// The expected bytes within the comparison's tolerance.
    pub fn expect_same(self, data: Vec<u8>) -> Self {
        let tolerance = Tolerance::from_json(self.json.get("tolerance"));
        self.expect(data, tolerance)
    }

    /// Another result Metal allows: each element may match the
    /// expectation or any alternative, within the same tolerance.
    pub fn expect_alternative(mut self, data: Vec<u8>) -> Self {
        self.alternatives.push(data);
        self
    }

    /// Which elements (cycling, `stride` apart) the expectation covers.
    pub fn expect_mask(self, mask: Vec<u8>) -> Self {
        self.set("expect_mask", json!(mask))
    }

    /// Holds every device to the expectation and its alternatives, which
    /// bound a result Metal leaves open, rather than to a reference run.
    pub fn judged_by_expectation(self) -> Self {
        self.set("judge", "expectation")
    }

    /// Which elements (cycling, `stride` apart) any comparison covers.
    pub fn mask(self, mask: Vec<u8>) -> Self {
        self.set("mask", json!(mask))
    }

    pub fn set(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.json.insert(key.into(), value.into());
        self
    }
}

/// One dispatch, draw, blit sequence or device query.
pub struct Case {
    json: Map<String, Value>,
    buffers: Vec<Buffer>,
    textures: Vec<Texture>,
    samplers: Vec<Value>,
    outputs: Vec<Output>,
    render: bool,
}

impl Case {
    fn new(name: &str, kind: &str, library: Option<&str>) -> Self {
        let mut json = Map::new();
        json.insert("name".into(), name.into());
        json.insert("kind".into(), kind.into());
        if let Some(library) = library {
            json.insert("library".into(), library.into());
        }
        Self {
            json,
            buffers: vec![],
            textures: vec![],
            samplers: vec![],
            outputs: vec![],
            render: false,
        }
    }

    /// A compute dispatch of `grid` threadgroups (or threads, with
    /// `dispatch_threads`) of `group` threads.
    pub fn compute(
        name: &str,
        library: &str,
        function: &str,
        grid: [u32; 3],
        group: [u32; 3],
    ) -> Self {
        let mut case = Self::new(name, "compute", Some(library));
        case.json.insert("function".into(), function.into());
        case.json.insert("grid".into(), json!(grid));
        case.json.insert("threadgroup".into(), json!(group));
        case
    }

    /// A 1D dispatch of `count` threads in groups of 64.
    pub fn compute1(name: &str, library: &str, function: &str, count: u32) -> Self {
        Self::compute(name, library, function, [count, 1, 1], [64, 1, 1])
    }

    /// A render pass: `state` holds its attachments, pipeline state and draw.
    pub fn render(
        name: &str,
        library: &str,
        vertex: &str,
        fragment: Option<&str>,
        state: Value,
    ) -> Self {
        let mut case = Self::new(name, "render", Some(library));
        case.json.insert("vertex".into(), vertex.into());
        if let Some(fragment) = fragment {
            case.json.insert("fragment".into(), fragment.into());
        }
        case.json.insert("render".into(), state);
        case.render = true;
        case
    }

    /// A sequence of blit commands.
    pub fn blit(name: &str, commands: Value) -> Self {
        let mut case = Self::new(name, "blit", None);
        case.json.insert("blits".into(), commands);
        case
    }

    /// Steps of compute, render and blit work over the case's resources,
    /// in one command buffer unless a step starts another (see `Step`).
    pub fn sequence(name: &str, library: &str, steps: Vec<Step>) -> Self {
        let mut case = Self::new(name, "sequence", Some(library));
        let steps: Vec<Value> = steps.into_iter().map(|s| Value::Object(s.0)).collect();
        case.json.insert("steps".into(), steps.into());
        case.render = true;
        case
    }

    /// Work one of Apple's frameworks encodes with its own shaders over
    /// the case's resources: `framework` names it and its parameters.
    pub fn framework(name: &str, framework: Value) -> Self {
        let mut case = Self::new(name, "framework", None);
        case.json.insert("framework".into(), framework);
        case.render = true;
        case
    }

    /// Host work around the device over the case's buffers: `host` names
    /// it and its parameters, and the runner records what it observes.
    pub fn host(name: &str, library: &str, host: Value) -> Self {
        let mut case = Self::new(name, "host", Some(library));
        case.json.insert("host".into(), host);
        case
    }

    /// The device's families, features and limits.
    pub fn device(name: &str) -> Self {
        Self::new(name, "device", None)
    }

    /// Dispatches threads rather than threadgroups, for non-uniform grids.
    pub fn dispatch_threads(self) -> Self {
        self.set("dispatch", "threads")
    }

    pub fn buffer(mut self, buffer: Buffer) -> Self {
        self.buffers.push(buffer);
        self
    }

    pub fn buffers(mut self, buffers: impl IntoIterator<Item = Buffer>) -> Self {
        self.buffers.extend(buffers);
        self
    }

    pub fn texture(mut self, texture: Texture) -> Self {
        self.textures.push(texture);
        self
    }

    pub fn sampler(mut self, sampler: Value) -> Self {
        self.samplers.push(sampler);
        self
    }

    pub fn output(mut self, output: Output) -> Self {
        self.outputs.push(output);
        self
    }

    /// Differences from the reference are reported, never failures: the
    /// result is the implementation's choice.
    pub fn informational(self) -> Self {
        self.set("informational", true)
    }

    pub fn note(self, note: &str) -> Self {
        self.set("note", note)
    }

    /// Unsupported unless the device has these families and features.
    pub fn requires(self, families: &[&str], features: &[&str]) -> Self {
        let mut r = Map::new();
        if !families.is_empty() {
            r.insert("families".into(), json!(families));
        }
        if !features.is_empty() {
            r.insert("features".into(), json!(features));
        }
        self.set("requires", Value::Object(r))
    }

    pub fn set(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.json.insert(key.into(), value.into());
        self
    }

    pub fn get(&self, key: &str) -> &Value {
        self.json.get(key).unwrap_or(&Value::Null)
    }

    /// Sets a key of a nested object, such as `["render", "mesh", "x"]`.
    pub fn set_at(mut self, path: &[&str], value: impl Into<Value>) -> Self {
        let (last, parents) = path.split_last().expect("a path");
        let mut at = &mut self.json;
        for key in parents {
            at = at
                .entry(key.to_string())
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .expect("an object on the path");
        }
        at.insert(last.to_string(), value.into());
        self
    }

    /// Sets a key of the named entry of a list the case already holds
    /// (`buffers`, `textures` or `samplers`), as when varying a case.
    pub fn edit(mut self, list: &str, name: &str, key: &str, value: impl Into<Value>) -> Self {
        let entry = self.json[list]
            .as_array_mut()
            .and_then(|l| l.iter_mut().find(|e| e["name"] == name))
            .unwrap_or_else(|| panic!("no {list} entry {name}"));
        entry[key] = value.into();
        self
    }

    pub fn name(&self) -> &str {
        self.json["name"].as_str().unwrap()
    }
}

/// The `stela_air__NAME` placeholder functions a corpus source calls for
/// AIR builtins no public header declares, which the Mac's build renames
/// in the library's IR ([`air_name`]).
pub fn air_placeholders(text: &str) -> Vec<String> {
    let mut names: Vec<String> = text
        .match_indices("stela_air__")
        .map(|(at, _)| {
            let name: String = text[at..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            name
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

/// The AIR builtin a placeholder names: `stela_air__a__b` is `air.a.b`.
pub fn air_name(placeholder: &str) -> String {
    let rest = placeholder
        .strip_prefix("stela_air__")
        .unwrap_or(placeholder);
    format!("air.{}", rest.replace("__", "."))
}

/// A corpus source the Mac compiles at an MSL version with flags.
#[derive(Clone)]
pub struct Library {
    pub source: String,
    pub version: String,
    pub flags: Vec<String>,
    /// A dynamic library, installed as `@loader_path/NAME.metallib`.
    pub dynamic: bool,
    /// The dynamic libraries it links against.
    pub links: Vec<String>,
    /// The runner's bundle ships it as its default library.
    pub default: bool,
    /// Compiled by the device at run time from source, with these
    /// `MTLCompileOptions`, in place of a metallib the Mac builds.
    pub runtime: Option<Value>,
}

/// Which functions of each guarded corpus source Apple's compiler refuses
/// at each MSL version, as `probe` found.
pub type Availability = BTreeMap<String, BTreeMap<String, Vec<String>>>;

pub struct Plan {
    cases: Vec<Value>,
    names: HashSet<String>,
    libraries: BTreeMap<String, Library>,
    sources: BTreeMap<String, String>,
    inputs: BTreeMap<String, Vec<u8>>,
    availability: Availability,
}

impl Plan {
    pub fn new(availability: Availability) -> Self {
        Self {
            cases: vec![],
            names: HashSet::new(),
            libraries: BTreeMap::new(),
            sources: BTreeMap::new(),
            inputs: BTreeMap::new(),
            availability,
        }
    }

    /// A metallib compiled from a corpus source (a file in corpus/ or
    /// generated text) with Apple's `metal` for an MSL version and its
    /// oldest macOS, and these flags. Functions the toolchain cannot
    /// compile at that version are left out by their SKIP_ macros.
    pub fn library(&mut self, name: &str, source: &str, flags: &[&str], version: &str) -> String {
        if !self.libraries.contains_key(name) {
            let mut all = version_flags(version);
            all.extend(flags.iter().map(|f| f.to_string()));
            all.extend(
                self.unavailable(source, version)
                    .iter()
                    .map(|k| format!("-DSKIP_{k}")),
            );
            self.libraries.insert(
                name.into(),
                Library {
                    source: source.into(),
                    version: version.into(),
                    flags: all,
                    dynamic: false,
                    links: vec![],
                    default: false,
                    runtime: None,
                },
            );
        }
        name.into()
    }

    /// Marks `name` as the library the runner's bundle ships as
    /// `default.metallib`, which `newDefaultLibrary` loads.
    pub fn default_library(&mut self, name: &str) {
        self.libraries.get_mut(name).unwrap().default = true;
    }

    /// A dynamic library of a corpus source, which other libraries link
    /// against and pipelines may preload.
    pub fn dynamic_library(&mut self, name: &str, source: &str, version: &str) -> String {
        let name = self.library(name, source, &[], version);
        self.libraries.get_mut(&name).unwrap().dynamic = true;
        name
    }

    /// A library the device compiles from a corpus source at run time with
    /// `options` as `MTLCompileOptions` takes them: `language` (any MSL
    /// version, the latest by default), `math_mode` (safe, relaxed, fast),
    /// `math_functions` (precise, fast), the older `fast_math`, `macros`,
    /// `preserve_invariance`, `optimization` (size), `libraries` (dynamic
    /// libraries to link), `allow_undefined`, `symbol_visibility`
    /// (default, hidden), `logging`, `required_threads`,
    /// `conversion_rounding` (nearest_even, toward_zero) and
    /// `install_name`, which makes it a dynamic library installed there.
    pub fn runtime_library(&mut self, name: &str, source: &str, mut options: Value) -> String {
        let version = options["language"].as_str().unwrap_or(LATEST).to_string();
        let name = self.library(name, source, &[], &version);
        // The functions the toolchain refuses at that version, left out
        // by the same macros an offline build defines.
        let skipped = self.unavailable(source, &version);
        if !skipped.is_empty() {
            let mut macros = options["macros"].as_object().cloned().unwrap_or_default();
            for k in skipped {
                macros.insert(format!("SKIP_{k}"), "1".into());
            }
            options["macros"] = macros.into();
        }
        let library = self.libraries.get_mut(&name).unwrap();
        library.dynamic = options["install_name"].is_string();
        // The dynamic libraries it links as it compiles go with it.
        library.links = options["libraries"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        library.runtime = Some(options);
        name
    }

    /// Links `name` against the dynamic libraries `dependencies`.
    pub fn link(&mut self, name: &str, dependencies: &[&str]) {
        self.libraries.get_mut(name).unwrap().links =
            dependencies.iter().map(|d| d.to_string()).collect();
    }

    /// The functions of a source that `probe` found Apple's compiler
    /// refuses at an MSL version.
    pub fn unavailable(&self, source: &str, version: &str) -> BTreeSet<String> {
        let base = Path::new(source).file_name().unwrap().to_string_lossy();
        self.availability
            .get(base.as_ref())
            .and_then(|v| v.get(version))
            .map(|v| v.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Whether a guarded function compiles at the latest MSL version.
    pub fn has(&self, source: &str, function: &str) -> bool {
        !self.unavailable(source, LATEST).contains(function)
    }

    /// A corpus source the generator writes.
    pub fn generated(&mut self, filename: &str, text: String) -> String {
        self.sources.insert(filename.into(), text);
        filename.into()
    }

    pub fn libraries(&self) -> &BTreeMap<String, Library> {
        &self.libraries
    }

    pub fn source_text(&self, source: &str, corpus: &Path) -> Result<String> {
        match self.sources.get(source) {
            Some(text) => Ok(text.clone()),
            None => fs::read_to_string(corpus.join(source))
                .with_context(|| format!("corpus source {source}")),
        }
    }

    /// Stores an input's bytes, named by their digest, and returns the
    /// path the plan names.
    fn input(&mut self, data: Vec<u8>) -> String {
        let digest = hex(&Sha256::digest(&data))[..24].to_string();
        let path = format!("inputs/{}/{digest}.bin", &digest[..2]);
        self.inputs.entry(path.clone()).or_insert(data);
        path
    }

    /// Stores a case's inline bytes as inputs and adds it.
    pub fn add(&mut self, case: Case) {
        let name = case.name().to_string();
        assert!(self.names.insert(name.clone()), "duplicate case {name}");
        let json = self.materialize(case);
        self.cases.push(Value::Object(json));
    }

    /// A copy of the case `name` as `name.suffix`, changed by `change`:
    /// the same inputs and expectations through another path of the API,
    /// with any buffers, textures, samplers and outputs `change` adds.
    pub fn vary(&mut self, name: &str, suffix: &str, change: impl FnOnce(Case) -> Case) {
        let json = self
            .cases
            .iter()
            .find(|c| name_of(c) == name)
            .unwrap_or_else(|| panic!("no case {name} to vary"))
            .as_object()
            .unwrap()
            .clone();
        let case = Case {
            json,
            buffers: vec![],
            textures: vec![],
            samplers: vec![],
            outputs: vec![],
            render: false,
        };
        self.add(change(case.set("name", format!("{name}.{suffix}"))));
    }

    /// A case's JSON with its buffers', textures' and outputs' bytes
    /// stored as inputs, appended to the lists it already holds.
    fn materialize(&mut self, case: Case) -> Map<String, Value> {
        let mut json = case.json;
        let name = json
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let lengths: BTreeMap<String, usize> = case
            .buffers
            .iter()
            .map(|b| {
                let declared = b.json.get("length").and_then(Value::as_u64).unwrap_or(0) as usize;
                let length = declared.max(b.data.as_ref().map_or(0, Vec::len));
                let name = b.json.get("name").and_then(Value::as_str);
                (name.unwrap_or_default().to_string(), length)
            })
            .collect();
        // A derived output's expectation holds one u32 property per
        // element the output reads back.
        for o in &case.outputs {
            let (Some(_), Some(expect)) = (o.json.get("derive"), &o.expect) else {
                continue;
            };
            let output = o
                .json
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let dtype = o
                .json
                .get("dtype")
                .and_then(Value::as_str)
                .and_then(Dtype::parse);
            let bytes = o
                .json
                .get("length")
                .and_then(Value::as_u64)
                .map(|l| l as usize)
                .or_else(|| lengths.get(output).copied());
            if let (Some(dtype), Some(bytes)) = (dtype, bytes) {
                assert_eq!(
                    expect.len() / 4,
                    bytes / dtype.size(),
                    "{name}: derived output {output} expects one u32 per element"
                );
            }
        }
        let mut buffers = vec![];
        for b in case.buffers {
            let mut m = b.json;
            if let Some(data) = b.data {
                m.insert("file".into(), self.input(data).into());
                m.entry("length").or_insert(0.into());
            }
            buffers.push(Value::Object(m));
        }
        let mut textures = vec![];
        for t in case.textures {
            let mut m = t.json;
            if let Some(data) = t.data {
                m.insert("file".into(), self.input(data).into());
            }
            if let Some(data) = t.stencil {
                m.insert("stencil_file".into(), self.input(data).into());
            }
            textures.push(Value::Object(m));
        }
        let mut outputs = vec![];
        for o in case.outputs {
            let mut m = o.json;
            // A buffer output is read back at the length the case gives
            // it, not at the larger size the runner may allocate.
            if let Some(&length) = m
                .get("name")
                .and_then(Value::as_str)
                .and_then(|n| lengths.get(n))
            {
                m.entry("length").or_insert(length.into());
            }
            if let Some(data) = o.expect {
                m.insert("expect".into(), self.input(data).into());
            }
            if !o.alternatives.is_empty() {
                let files: Vec<Value> = o
                    .alternatives
                    .into_iter()
                    .map(|d| self.input(d).into())
                    .collect();
                m.insert("expect_alternatives".into(), files.into());
            }
            outputs.push(Value::Object(m));
        }
        let mut extend = |key: &str, items: Vec<Value>, always: bool| {
            if items.is_empty() && !always && !json.contains_key(key) {
                return;
            }
            if let Value::Array(list) = json.entry(key).or_insert_with(|| Value::Array(vec![])) {
                list.extend(items);
            }
        };
        extend("buffers", buffers, true);
        extend("outputs", outputs, true);
        extend("textures", textures, case.render);
        extend("samplers", case.samplers, case.render);
        json
    }

    #[cfg(test)]
    pub fn cases(&self) -> &[Value] {
        &self.cases
    }

    /// Writes DIR/plan.json with the cases `only` selects (all when
    /// empty), every input and the sources of the libraries they use.
    pub fn write(&self, dir: &Path, corpus: &Path, only: &[String]) -> Result<Value> {
        for sub in ["inputs", "sources"] {
            let path = dir.join(sub);
            if path.exists() {
                fs::remove_dir_all(&path)?;
            }
        }
        let selected: Vec<&Value> = self
            .cases
            .iter()
            .filter(|c| selects(only, name_of(c)))
            .collect();
        let mut used: BTreeSet<&str> = selected
            .iter()
            .flat_map(|c| {
                let steps = c["steps"].as_array().into_iter().flatten();
                let preloads = c["preload"].as_array().into_iter().flatten();
                // Libraries a case's pipelines link functions from.
                let uses = c["uses"].as_array().into_iter().flatten();
                std::iter::once(&c["library"])
                    .chain(steps.map(|s| &s["library"]))
                    .chain(preloads)
                    .chain(uses)
            })
            .filter_map(Value::as_str)
            .collect();
        // A used library's dynamic libraries are used too.
        let linked: Vec<&str> = used
            .iter()
            .filter_map(|n| self.libraries.get(*n))
            .flat_map(|l| l.links.iter().map(String::as_str))
            .collect();
        used.extend(linked);
        let mut libraries = Map::new();
        let mut builds = Map::new();
        let mut runtime_sources = vec![];
        for (name, library) in &self.libraries {
            if !used.contains(name.as_str()) {
                continue;
            }
            let Library {
                source,
                version,
                flags,
                dynamic,
                links,
                default,
                runtime,
            } = library;
            let base = Path::new(source).file_name().unwrap().to_string_lossy();
            if let Some(options) = runtime {
                let mut entry = options.as_object().cloned().unwrap_or_default();
                entry.insert("source".into(), format!("sources/{base}").into());
                libraries.insert(name.clone(), entry.into());
                runtime_sources.push(source.as_str());
                continue;
            }
            libraries.insert(name.clone(), format!("lib/{name}.metallib").into());
            let air_names = air_placeholders(&self.source_text(source, corpus)?);
            builds.insert(
                name.clone(),
                json!({"source": source, "version": version, "flags": flags, "dynamic": dynamic, "links": links,
                       "default": default, "air_names": air_names}),
            );
        }
        let body = serde_json::to_string(&json!({"libraries": libraries, "cases": selected}))?;
        let digest = hex(&Sha256::digest(body.as_bytes()))[..16].to_string();
        for (path, data) in &self.inputs {
            let path = dir.join(path);
            fs::create_dir_all(path.parent().unwrap())?;
            fs::write(&path, data)?;
        }
        let sources = dir.join("sources");
        fs::create_dir_all(&sources)?;
        let built = builds.values().map(|b| b["source"].as_str().unwrap());
        for source in built.chain(runtime_sources) {
            let base = Path::new(source).file_name().unwrap();
            fs::write(sources.join(base), self.source_text(source, corpus)?)?;
        }
        let plan =
            json!({"libraries": libraries, "builds": builds, "cases": selected, "digest": digest});
        fs::write(dir.join("plan.json"), serde_json::to_string_pretty(&plan)?)?;
        Ok(plan)
    }
}

pub fn name_of(case: &Value) -> &str {
    case["name"].as_str().unwrap_or_default()
}

/// Whether a case name contains one of the selections, or there are none.
pub fn selects(only: &[String], name: &str) -> bool {
    only.is_empty() || only.iter().any(|o| name.contains(o.as_str()))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn load(dir: &Path) -> Result<Value> {
    let path = dir.join("plan.json");
    let text = fs::read_to_string(&path)
        .with_context(|| format!("{} (run `plan` or `mac` first)", path.display()))?;
    let plan: Value = serde_json::from_str(&text)?;
    if !plan["cases"].is_array() {
        bail!("{} has no cases", path.display());
    }
    Ok(plan)
}
