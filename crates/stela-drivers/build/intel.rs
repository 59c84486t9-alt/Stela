//! Stela's Xe and i915 port, its dispatch packers and their hosted tests.
//! Linux's and Mesa's original generators supply the workaround table and the
//! packet headers, run by a selected Python interpreter.
use super::native::{self, Linux, Module, Tests};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

const SOURCE: &str = "src/gpu/intel";
const XE_DRIVER: &str = "../../third_party/linux/drivers/gpu/drm/xe";
const GENXML: &str = "../../third_party/mesa/src/intel/genxml";
const LEGACY: &str = "GPGPU_WALKER,MEDIA_STATE_FLUSH";
const COMPUTE: &str = "COMPUTE_WALKER,COMPUTE_WALKER_BODY,INTERFACE_DESCRIPTOR_DATA,POSTSYNC_DATA,PREF_SLM_ALLOCATION_SIZE";

const XE: Module = Module {
    name: "xe",
    file: "drivers/gpu/drm/xe/xe",
};
const I915: Module = Module {
    name: "i915",
    file: "drivers/gpu/drm/i915/i915",
};
/// The adapters over i915's sources; the others are over Xe's, except the
/// packet encoders, which run Mesa's packers rather than Linux code.
const I915_ADAPTERS: [&str; 1] = ["i915_commands.c"];
const ENCODERS: [&str; 2] = ["dispatch.c", "compute_dispatch.c"];

/// Packet generations: GFX_VERx10, Mesa's XML name, and the dispatch unit
/// built over each one's selected packets.
const DISPATCH: [(u32, &str, &str, &str); 10] = [
    (70, "gen70", "gen", LEGACY),
    (75, "gen75", "gen", LEGACY),
    (80, "gen80", "gen", LEGACY),
    (90, "gen90", "gen", LEGACY),
    (110, "gen110", "gen", LEGACY),
    (120, "gen120", "gen", LEGACY),
    (125, "gen125", "compute", COMPUTE),
    (200, "xe2", "compute", COMPUTE),
    (300, "xe3", "compute", COMPUTE),
    (350, "xe3p", "compute", COMPUTE),
];

/// Each encoder's comparison against Mesa's complete packers, by generation.
const PACKERS: [(&str, &[u32]); 4] = [
    ("commands", &[120, 125, 200, 300, 350]),
    ("i915_commands", &[60, 70, 75, 80, 90, 110]),
    ("dispatch", &[70, 75, 80, 90, 110, 120]),
    ("compute_dispatch", &[125, 200, 300, 350]),
];

/// Hosted tests of the adapters, which run in Stela's Linux environment, and
/// of the encoders and packet adapters, which use the host's C library.
const LINUX_TESTS: [&str; 9] = [
    "activation",
    "firmware",
    "ggtt_probe",
    "guc_reset",
    "huc_firmware",
    "pat",
    "pt_walk",
    "wopcm",
    "wopcm_owned",
];
const HOST_TESTS: [&str; 5] = [
    "commands",
    "compute_dispatch",
    "ct",
    "dispatch",
    "i915_commands",
];

/// The port's three builds: adapters in Stela's Linux environment as Xe's
/// and i915's Kbuild build them, and the packet encoders over Mesa's packers.
struct Builds {
    xe: cc::Build,
    i915: cc::Build,
    encoders: cc::Build,
}

impl Builds {
    fn new(linux: &Linux, base: &cc::Build, generated: &Path, dispatch: &Path) -> Self {
        let mut xe = base.clone();
        linux.apply(&mut xe, Some(generated), &["xe"], Some(&XE));
        xe.include(SOURCE);
        let mut i915 = base.clone();
        linux.apply(&mut i915, None, &["i915"], Some(&I915));
        i915.define("I915", None).include(SOURCE);
        let mut encoders = base.clone();
        encoders
            .include(dispatch)
            .include(SOURCE)
            .include(format!("{}/include", native::MESA))
            .include(format!("{}/src", native::MESA))
            .include(GENXML);
        Self { xe, i915, encoders }
    }
}

pub fn port(linux: &Linux, tests: &mut Tests) {
    let output = native::out_dir();
    let python = python();
    let generated = output.join("intel-generated");
    workarounds(&generated);
    let dispatch = output.join("intel-dispatch");
    let (mut encoders, adapters): (Vec<_>, Vec<_>) = native::sources(SOURCE)
        .into_iter()
        .partition(|path| named(path, &ENCODERS));
    let (i915, xe): (Vec<_>, Vec<_>) = adapters
        .into_iter()
        .partition(|path| named(path, &I915_ADAPTERS));
    encoders.extend(packets(&python, &dispatch));
    let mut port = Builds::new(linux, &native::configure(), &generated, &dispatch);
    // Mesa's packing helpers include a few C library headers, which the
    // freestanding encoders take from Stela.
    port.encoders
        .include("src/gpu/compat/freestanding")
        .define("HAVE_ENDIAN_H", None);
    native::check_declarations(&port.xe, &xe);
    native::check_declarations(&port.i915, &i915);
    port.xe.clone().files(&xe).compile("stela-intel-xe");
    port.i915.clone().files(&i915).compile("stela-intel-i915");
    port.encoders
        .clone()
        .files(&encoders)
        .compile("stela-intel-encoders");
    let Some(base) = native::hosted() else {
        return;
    };
    let mut hosted = Builds::new(linux, &base, &generated, &dispatch);
    native::mesa_hosted(&mut hosted.encoders);
    let mut archives = vec![
        native::archive(&hosted.xe, "intel-xe-hosted", &xe),
        native::archive(&hosted.i915, "intel-i915-hosted", &i915),
        native::archive(&hosted.encoders, "intel-encoders-hosted", &encoders),
    ];
    archives.extend(linux.hosted.iter().cloned());
    let archives = archives.iter().map(PathBuf::as_path).collect::<Vec<_>>();
    let mut host = base.clone();
    host.include(SOURCE);
    for (build, names) in [(&hosted.xe, &LINUX_TESTS[..]), (&host, &HOST_TESTS[..])] {
        for name in names {
            let source = format!("{SOURCE}/tests/{name}.c");
            tests.add(build, &format!("intel_{name}"), &source, &archives);
        }
    }
    let genxml = output.join("intel-genxml");
    let mut generations = PACKERS
        .iter()
        .flat_map(|(_, generations)| generations.iter().copied())
        .collect::<Vec<_>>();
    generations.sort_unstable();
    generations.dedup();
    for generation in generations {
        complete_packets(&python, generation, &genxml.join("genxml"));
    }
    // Mesa's headers keep their own warning profile, as Linux's do.
    let mut mesa = base;
    native::mesa_hosted(&mut mesa);
    let (include, src) = (
        format!("{}/include", native::MESA),
        format!("{}/src", native::MESA),
    );
    for directory in [
        Path::new(&include),
        Path::new(&src),
        Path::new(GENXML),
        &genxml,
    ] {
        mesa.flag("-isystem").flag(directory);
    }
    for (name, generations) in PACKERS {
        for generation in generations {
            let source = format!("{SOURCE}/tests/{name}_mesa.c");
            let test = format!("intel_{name}_mesa_{generation}");
            let mut build = mesa.clone();
            build.define("GFX_VERx10", generation.to_string().as_str());
            tests.add(&build, &test, &source, &archives);
        }
    }
}

/// Whether `path` names one of `files`.
fn named(path: &Path, files: &[&str]) -> bool {
    files.iter().any(|file| path.ends_with(file))
}

fn python() -> PathBuf {
    println!("cargo:rerun-if-env-changed=STELA_GPU_PYTHON");
    env::var_os("STELA_GPU_PYTHON").map_or_else(|| "python3".into(), PathBuf::from)
}

/// Xe's workaround table, generated as Kbuild does by Linux's unchanged
/// generator from its rules, as <generated/xe_wa_oob.h>.
fn workarounds(generated: &Path) {
    let source = XE_DRIVER;
    let output = generated.join("generated");
    fs::create_dir_all(&output).expect("create the generated Xe header directory");
    let host = env::var("HOST").expect("Cargo supplies HOST");
    let generator = native::out_dir().join(format!("xe_gen_wa_oob{}", env::consts::EXE_SUFFIX));
    native::run(
        cc::Build::new()
            .host(&host)
            .target(&host)
            .cargo_metadata(false)
            .get_compiler()
            .to_command()
            .args(["-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror"])
            .arg(format!("{source}/xe_gen_wa_oob.c"))
            .arg("-o")
            .arg(&generator),
    );
    native::run(
        Command::new(&generator)
            .arg(format!("{source}/xe_wa_oob.rules"))
            .arg(native::out_dir().join("xe_wa_oob.c"))
            .arg(output.join("xe_wa_oob.h")),
    );
}

/// The selected packets of each dispatch generation, and its unit's source.
fn packets(python: &Path, output: &Path) -> Vec<PathBuf> {
    fs::create_dir_all(output).expect("create the Intel packet header directory");
    println!("cargo:rerun-if-changed={GENXML}");
    DISPATCH
        .iter()
        .map(|&(generation, xml, unit, symbols)| {
            let family = if unit == "gen" { "dispatch" } else { unit };
            generate(
                Command::new(python)
                    .arg(format!("{GENXML}/gen_pack_header.py"))
                    .arg(format!("{GENXML}/{xml}.xml"))
                    .args(["--include-symbols", symbols]),
                &output.join(format!("gen{generation}_{family}_pack.h")),
            );
            PathBuf::from(format!("{SOURCE}/dispatch/{unit}{generation}.c"))
        })
        .collect()
}

/// One generation's complete packers, as Mesa's build generates them.
fn complete_packets(python: &Path, generation: u32, output: &Path) {
    fs::create_dir_all(output).expect("create the Mesa packet header directory");
    let xml = match generation {
        200 => "xe2".into(),
        300 => "xe3".into(),
        350 => "xe3p".into(),
        _ => format!("gen{generation}"),
    };
    generate(
        Command::new(python)
            .arg(format!("{GENXML}/gen_pack_header.py"))
            .arg(format!("{GENXML}/{xml}.xml"))
            .arg("--engines=render,blitter,compute"),
        &output.join(format!("{xml}_pack.h")),
    );
}

fn generate(command: &mut Command, header: &Path) {
    let output = command
        .output()
        .expect("Mesa's Intel XML generator requires Python 3; select STELA_GPU_PYTHON");
    assert!(
        output.status.success(),
        "{command:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::write(header, output.stdout).expect("write a generated Intel packet header");
}
