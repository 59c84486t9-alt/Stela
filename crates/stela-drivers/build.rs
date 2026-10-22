#[cfg(feature = "native-acpi")]
#[path = "build/acpi.rs"]
mod acpi;
#[cfg(feature = "amd-commands")]
#[path = "build/amd.rs"]
mod amd;
#[cfg(feature = "intel-port")]
#[path = "build/intel.rs"]
mod intel;
#[cfg(any(feature = "nvidia-port", feature = "intel-port", feature = "amd-port"))]
#[path = "build/native.rs"]
mod native;

fn main() {
    #[cfg(feature = "native-acpi")]
    acpi::build();
    // Active ports declare their native source inputs below. Without this
    // baseline Cargo watches every vendored file even when no C port is used.
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(feature = "amd-port")]
    {
        // amdgpu's probe admission and IP discovery, from the unchanged
        // amdgpu_drv.c and amdgpu_discovery.c, and Stela's BAR policy, all in
        // Stela's Linux environment.
        let linux = || {
            let mut build = native::configure();
            native::linux_environment(
                &mut build,
                None,
                &[
                    "amd/include/asic_reg",
                    "amd/include",
                    "amd/amdgpu",
                    "amd/pm/inc",
                    "amd/ras/ras_mgr",
                    "amd/amdxcp",
                ],
            );
            build
        };
        linux()
            .file("src/gpu/amd/stela/pci_match.c")
            .file("src/gpu/amd/stela/ip_discovery.c")
            .file("src/gpu/amd/stela/native_bar.c")
            .compile("stela-amd-port");
        // Fixtures for the integration test, which links them itself.
        linux()
            .file("src/gpu/amd/tests/fixtures.c")
            .cargo_metadata(false)
            .compile("stela-amd-test-fixtures");
        for path in [
            "src/gpu/amd/stela",
            "src/gpu/amd/amdgpu",
            "src/gpu/amd/include",
            "src/gpu/amd/pm/inc",
            "src/gpu/amd/ras/ras_mgr",
            "src/gpu/amd/amdxcp",
            "src/gpu/amd/tests/fixtures.c",
            "src/gpu/amd/tests/fixtures.h",
        ] {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    #[cfg(feature = "amd-commands")]
    amd::build();
    #[cfg(feature = "nvidia-port")]
    nvidia();
    #[cfg(feature = "intel-port")]
    {
        let mut build = native::configure();
        intel::configure(&mut build);
        build.compile("stela-intel-port");
    }
}

#[cfg(feature = "nvidia-port")]
fn nvidia() {
    let source = "src/gpu/nvidia";
    let version_mk = format!("{source}/version.mk");
    let version = std::fs::read_to_string(&version_mk).expect("read NVIDIA version.mk");
    let version = version
        .lines()
        .find_map(|line| line.strip_prefix("NVIDIA_VERSION = "))
        .expect("NVIDIA_VERSION in retained version.mk");
    assert!(
        version
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    );
    let generated =
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("nvidia-include");
    std::fs::create_dir_all(&generated).expect("create NVIDIA generated include");
    std::fs::write(
        generated.join("version.h"),
        format!("#define NVIDIA_VERSION \"{version}\"\n"),
    )
    .expect("generate NVIDIA version.h");
    println!("cargo:rerun-if-changed={version_mk}");
    let mut build = native::configure();
    build
        // NVIDIA's FreeBSD configuration, as `cargo xtask gpu nvidia` builds the
        // cores: its Unix resource manager for an OS with its own interface layer.
        .define("NV_BSD", None)
        .file(format!("{source}/stela/pci.c"))
        .file(format!("{source}/stela/memory.c"))
        .file(format!("{source}/stela/stela_ram_mapping.c"))
        .file(format!("{source}/stela/stela_pages.c"))
        .file(format!("{source}/stela/stela_page_geometry.c"))
        .file(format!("{source}/stela/stela_ordering.c"))
        .file(format!("{source}/stela/stela_device.c"))
        .file(format!("{source}/stela/stela_mmio.c"))
        .file(format!("{source}/stela/stela_firmware.c"))
        .file(format!("{source}/stela/stela_primitives.c"))
        .file(format!("{source}/stela/stela_nvlink_primitives.c"))
        .file(format!("{source}/stela/stela_nvswitch_primitives.c"))
        .file(format!("{source}/stela/stela_nvlink_memory.c"))
        .file(format!("{source}/stela/stela_nvkms_primitives.c"))
        .file(format!("{source}/stela/stela_nvkms_memory.c"))
        .include(&generated)
        .include(format!("{source}/stela"))
        // FreeBSD headers NVIDIA's interface layer includes, where none exist.
        .flag("-idirafter")
        .flag(format!("{source}/stela/compat"))
        .include(format!("{source}/src/common/sdk/nvidia/inc"))
        .include(format!("{source}/src/nvidia/arch/nvalloc/unix/include"))
        .include(format!("{source}/src/nvidia/arch/nvalloc/common/inc"))
        .include(format!("{source}/src/nvidia/inc/kernel"))
        .include(format!("{source}/src/common/inc"))
        .include(format!("{source}/src/common/inc/swref"))
        .include(format!("{source}/src/common/uproc/os/common/include"))
        .include(format!("{source}/src/common/nvlink/interface"))
        .include(format!("{source}/src/common/unix/common/inc"))
        .include(format!("{source}/src/nvidia-modeset/os-interface/include"))
        .include(format!("{source}/src/nvidia-modeset/kapi/interface"))
        .include(format!("{source}/src/nvidia-modeset/interface"));
    println!("cargo:rerun-if-changed={source}/stela");
    println!("cargo:rerun-if-changed={source}/src/common/sdk/nvidia/inc");
    println!("cargo:rerun-if-changed={source}/src/nvidia/arch/nvalloc/unix/include");
    println!("cargo:rerun-if-changed={source}/src/nvidia/arch/nvalloc/common/inc");
    println!("cargo:rerun-if-changed={source}/src/nvidia/inc/kernel/os");
    println!("cargo:rerun-if-changed={source}/src/common/inc/nvctassert.h");
    println!("cargo:rerun-if-changed={source}/src/common/inc/swref/published/nv_arch.h");
    println!("cargo:rerun-if-changed={source}/src/common/uproc/os/common/include/libelf.h");
    for directory in [
        "src/common/nvlink/interface",
        "src/common/unix/common/inc",
        "src/nvidia-modeset/os-interface/include",
        "src/nvidia-modeset/kapi/interface",
        "src/nvidia-modeset/interface",
    ] {
        println!("cargo:rerun-if-changed={source}/{directory}");
    }
    build.compile("stela-nvidia-port");
}
