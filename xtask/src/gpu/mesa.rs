//! Native host compiler builds. Device access and Metal are separate ports.
use super::support::{capture, evidence_directory, source_binding};
use crate::tools;
use anyhow::{Context, Result, ensure};
use object::{Object, read::archive::ArchiveFile};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    env,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const LIBRARIES: &[&str] = &[
    "src/compiler/nir/libnir.a",
    "src/nouveau/compiler/libnak.a",
    "src/nouveau/compiler/libnak_rs.a",
    "src/nouveau/nil/libnil.a",
    "src/amd/compiler/libaco.a",
    "src/intel/compiler/gen/libintel_compiler_gen.a",
    "src/intel/compiler/brw/libintel_compiler.a",
    "src/intel/compiler/elk/libintel_compiler_elk.a",
    "src/intel/compiler/jay/libintel_compiler_jay.a",
];

fn tool(name: &str, local: &str) -> Result<PathBuf> {
    tools::which(name)
        .or_else(|| {
            let path = tools::root().join(".tools/gpu").join(local).join(name);
            path.is_file().then_some(path)
        })
        .with_context(|| format!("install {name} and put it in PATH"))
}

fn run(command: &mut Command, evidence: &Path, stage: &str) -> Result<()> {
    let path = evidence.join(format!("{stage}.log"));
    let log = File::create_new(&path)?;
    println!("GPU compilers {stage}: {}", path.display());
    let status = command
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .status()
        .with_context(|| format!("cannot execute {command:?}"))?;
    ensure!(status.success(), "{stage} failed; see {}", path.display());
    Ok(())
}

fn inspect_archive(path: &Path) -> Result<Value> {
    let data = fs::read(path)?;
    let archive = ArchiveFile::parse(&*data)?;
    let mut formats = BTreeSet::new();
    let mut architectures = BTreeSet::new();
    let mut count = 0;
    for member in archive.members() {
        let member = member?;
        let object = object::File::parse(member.data(&*data)?)
            .with_context(|| format!("non-object member in {}", path.display()))?;
        ensure!(
            object.kind() == object::ObjectKind::Relocatable,
            "non-relocatable member in {}",
            path.display()
        );
        formats.insert(format!("{:?}", object.format()));
        architectures.insert(format!("{:?}", object.architecture()));
        count += 1;
    }
    ensure!(count > 0, "{} contains no objects", path.display());
    Ok(json!({
        "binding": tools::binding(path)?, "objects": count,
        "formats": formats, "architectures": architectures,
    }))
}

pub fn build(jobs: u16) -> Result<()> {
    let meson = tool("meson", "generators/bin")?;
    let ninja = tool("ninja", "generators/bin")?;
    let bindgen = tool("bindgen", "rust/bin")?;
    let cbindgen = tool("cbindgen", "rust/bin")?;
    let paths = [&meson, &ninja, &bindgen, &cbindgen]
        .iter()
        .filter_map(|path| path.parent())
        .map(Path::to_owned)
        .chain(env::split_paths(&env::var_os("PATH").unwrap_or_default()))
        .collect::<Vec<_>>();
    let path = env::join_paths(paths)?;
    let gpu = tools::root().join("crates/stela-drivers/src/gpu");
    let source = gpu.join("common/mesa");
    let build = tools::root().join(".stela/gpu/build/mesa-host");
    let evidence = evidence_directory()?;
    let hash = source_binding(&source)?;
    let mut setup = Command::new(&meson);
    setup
        .current_dir(tools::root())
        .env("PATH", &path)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .args(["setup", "--wrap-mode=nodownload"])
        .arg(&build)
        .arg(&source)
        .args([
            "-Dstela-compilers=nvidia,amd,intel",
            "-Dplatforms=[]",
            "-Dgallium-drivers=[]",
            "-Dvulkan-drivers=[]",
            "-Dopengl=false",
            "-Dgles1=disabled",
            "-Dgles2=disabled",
            "-Degl=disabled",
            "-Dgbm=disabled",
            "-Dglx=disabled",
            "-Dllvm=disabled",
            "-Dvideo-codecs=",
            "-Dbuild-tests=false",
            "-Dintel-elk=true",
        ]);
    if build.join("meson-private/coredata.dat").is_file() {
        setup.arg("--reconfigure");
    }
    run(&mut setup, &evidence, "setup")?;
    let mut compile = Command::new(&ninja);
    compile
        .env("PATH", &path)
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg("-C")
        .arg(&build)
        .arg(format!("-j{jobs}"))
        .args(LIBRARIES)
        .arg("src/stela/stela_nak_probe");
    run(&mut compile, &evidence, "compile")?;
    let mut probe = Command::new(build.join("src/stela/stela_nak_probe"));
    run(&mut probe, &evidence, "nak-codegen")?;
    let libraries = LIBRARIES
        .iter()
        .map(|name| inspect_archive(&build.join(name)))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        source_binding(&source)? == hash,
        "compiler source changed during the build; rerun against a stable tree"
    );
    let receipt = json!({
        "schema": 1, "stage": "native-host-shader-compiler-build",
        "stela_platform_port": false, "hardware_executed": false,
        "metal_frontend": false,
        "source_tree_sha256": hash,
        "origin": serde_json::from_slice::<Value>(&fs::read(gpu.join("sources.json"))?)?,
        "host": {"os": env::consts::OS, "arch": env::consts::ARCH},
        "meson": capture(Command::new(&meson).arg("--version"))?,
        "setup": format!("{setup:?}"), "compile": format!("{compile:?}"),
        "libraries": libraries,
        "nvidia_codegen_probe": tools::binding(&evidence.join("nak-codegen.log"))?,
        "probe_binary": tools::binding(&build.join("src/stela/stela_nak_probe"))?,
    });
    File::create_new(evidence.join("compilers.json"))?
        .write_all(&serde_json::to_vec_pretty(&receipt)?)?;
    println!("Built NVIDIA/AMD/Intel shader libraries; NVIDIA codegen probe passed.");
    Ok(())
}
