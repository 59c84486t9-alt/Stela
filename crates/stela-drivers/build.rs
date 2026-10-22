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
        let mut build = native::configure();
        build
            .file("src/gpu/amd/stela/vm_cpu.c")
            .file("src/gpu/amd/stela/native_bar.c")
            .file("src/gpu/amd/stela/discovery_binary.c")
            .file("src/gpu/amd/stela/discovery_file.c")
            .file("src/gpu/amd/stela/discovery_tmr.c")
            .file("src/gpu/amd/stela/vram_mm.c")
            .include("src/gpu/common/linux/include")
            .std("c11");
        // Preserve the original IP walk's signed counter semantics locally.
        native::configure()
            .file("src/gpu/amd/stela/discovery_ip.c")
            .include("src/gpu/common/linux/include")
            .flag("-fwrapv")
            .std("c11")
            .compile("stela-amd-ip");
        // Only the original PCI table's shorthand initializers and ARRAY_SIZE
        // comparison need these warning exceptions; other native TUs keep them.
        native::configure()
            .file("src/gpu/amd/stela/pci_match.c")
            .include("src/gpu/common/linux/include")
            .flag("-Wno-missing-field-initializers")
            .flag("-Wno-sign-compare")
            .std("c11")
            .compile("stela-amd-pci");
        // Build the pure C ABI/original-value test helper separately. Only the
        // cfg(test) Rust link attribute selects it; production links the port.
        let mut model = native::configure();
        model
            .file("src/gpu/amd/tests/vm_ram_test.c")
            .std("c11")
            .cargo_metadata(false)
            .compile("stela-amd-vm-test");
        // The donor model uses hosted assertions/stdio; production policy is
        // freestanding and builds above for both the host and UEFI targets.
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("uefi") {
            let mut bars = native::configure();
            bars.file("src/gpu/amd/tests/native_bar_test.c")
                .include("src/gpu/common/linux/include")
                .define("STELA_AMD_BAR_TEST_LIBRARY", None)
                .flag("-Wno-unused-function")
                .std("c11")
                .cargo_metadata(false)
                .compile("stela-amd-bar-test");
        }
        for path in [
            "src/gpu/amd/stela",
            "src/gpu/amd/amdgpu/amdgpu_vm_cpu_entries.h",
            "src/gpu/amd/amdgpu/amdgpu_gmc_pte.h",
            "src/gpu/amd/amdgpu/amdgpu_mm_access_core.h",
            "src/gpu/amd/amdgpu/amdgpu_discovery_tmr_core.h",
            "src/gpu/amd/amdgpu/amdgpu_discovery_tmr_limits.h",
            "src/gpu/amd/amdgpu/amdgpu_discovery_ip_core.h",
            "src/gpu/amd/amdgpu/amdgpu_discovery_file_core.h",
            "src/gpu/amd/amdgpu/amdgpu_ip_types.h",
            "src/gpu/amd/amdgpu/amdgpu_ip_instance_limits.h",
            "src/gpu/amd/amdgpu/amdgpu_virt_bootstrap_core.h",
            "src/gpu/amd/amdgpu/amdgpu_pci_match_core.h",
            "src/gpu/amd/amdgpu/amdgpu_apu_flags_core.h",
            "src/gpu/amd/amdgpu/amdgpu_discovery_source_core.h",
            "src/gpu/amd/include/amd_chip_flags.h",
            "src/gpu/amd/include/asic_reg/bif/bif_4_1_d.h",
            "src/gpu/amd/tests/vm_ram_test.c",
            "src/gpu/amd/tests/native_bar_test.c",
            "src/gpu/common/linux/include/drm/amd_asic_type.h",
            "src/gpu/amd/include/discovery.h",
            "src/gpu/amd/include/soc15_hw_ip.h",
            "src/gpu/amd/amdgpu/amdgpu_ip_limits.h",
            "src/gpu/common/linux/include/uapi/linux/stddef.h",
            "src/gpu/common/linux/include/linux/device-id/pci.h",
            "src/gpu/common/linux/include/linux/pci_ids.h",
        ] {
            println!("cargo:rerun-if-changed={path}");
        }
        build.compile("stela-amd-port");
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
        .define("NV_STELA", None)
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
