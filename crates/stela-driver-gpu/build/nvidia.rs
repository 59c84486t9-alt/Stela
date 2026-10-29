//! Stela's NVIDIA OS hooks over NVIDIA's unchanged interface headers, in the
//! vendor's FreeBSD configuration as `cargo xtask gpu nvidia` builds the cores.
use super::native;
use std::fs;

pub fn port() {
    native::require_sources();
    let source = native::NVIDIA;
    let port = "src/nvidia";
    let version_mk = format!("{source}/version.mk");
    let version = fs::read_to_string(&version_mk).expect("read NVIDIA version.mk");
    let version = version
        .lines()
        .find_map(|line| line.strip_prefix("NVIDIA_VERSION = "))
        .expect("NVIDIA_VERSION in retained version.mk");
    assert!(
        version
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    );
    let generated = native::out_dir().join("nvidia-include");
    fs::create_dir_all(&generated).expect("create NVIDIA generated include");
    fs::write(
        generated.join("version.h"),
        format!("#define NVIDIA_VERSION \"{version}\"\n"),
    )
    .expect("generate NVIDIA version.h");
    println!("cargo:rerun-if-changed={version_mk}");
    let mut build = native::configure();
    // NVIDIA's Unix resource manager for an OS with its own interface layer.
    // Its headers take a predefined __linux__ for Linux's kernel layer, which
    // a Linux host's compiler defines even for this freestanding build.
    build
        .flag("-U__linux__")
        .flag("-U__linux")
        .flag("-Ulinux")
        .define("NV_BSD", None)
        // cpuopsys.h must not also select the hosted compiler's Linux OS.
        .flag("-U__linux__")
        .include(&generated)
        .include(port)
        // FreeBSD headers NVIDIA's interface layer includes, where none exist.
        .flag("-idirafter")
        .flag("src/compat/freebsd");
    for directory in [
        "src/common/sdk/nvidia/inc",
        "src/nvidia/arch/nvalloc/unix/include",
        "src/nvidia/arch/nvalloc/common/inc",
        "src/nvidia/inc/kernel",
        "src/common/inc",
        "src/common/inc/swref",
        "src/common/uproc/os/common/include",
        "src/common/nvlink/interface",
        "src/common/nvswitch/interface",
        "src/common/unix/common/inc",
        "src/nvidia-modeset/os-interface/include",
        "src/nvidia-modeset/kapi/interface",
        "src/nvidia-modeset/interface",
    ] {
        // NVIDIA's headers keep their own warning profile.
        build.flag("-isystem").flag(format!("{source}/{directory}"));
        println!("cargo:rerun-if-changed={source}/{directory}");
    }
    build
        .files(native::sources(port))
        .compile("stela-nvidia-port");
}
