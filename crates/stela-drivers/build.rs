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
    // Active ports declare their native source inputs below. Without this
    // baseline Cargo watches every vendored file even when no C port is used.
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(feature = "amd-port")]
    {
        let mut build = native::configure();
        build.file("src/gpu/amd/stela/vm_cpu.c").std("c11");
        // Build the pure C ABI/original-value test helper separately. Only the
        // cfg(test) Rust link attribute selects it; production links the port.
        let mut model = native::configure();
        model
            .file("src/gpu/amd/tests/vm_ram_test.c")
            .std("c11")
            .cargo_metadata(false)
            .compile("stela-amd-vm-test");
        for path in [
            "src/gpu/amd/stela",
            "src/gpu/amd/amdgpu/amdgpu_vm_cpu_entries.h",
            "src/gpu/amd/amdgpu/amdgpu_gmc_pte.h",
            "src/gpu/amd/tests/vm_ram_test.c",
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
    let mut build = native::configure();
    build
        .define("NV_STELA", None)
        .file(format!("{source}/stela/pci.c"))
        .file(format!("{source}/stela/memory.c"))
        .file(format!("{source}/stela/stela_ram_mapping.c"))
        .file(format!("{source}/stela/stela_pages.c"))
        .include(format!("{source}/stela"))
        .include(format!("{source}/src/common/sdk/nvidia/inc"))
        .include(format!("{source}/src/nvidia/arch/nvalloc/unix/include"))
        .include(format!("{source}/src/nvidia/arch/nvalloc/common/inc"))
        .include(format!("{source}/src/nvidia/inc/kernel"));
    println!("cargo:rerun-if-changed={source}/stela");
    println!("cargo:rerun-if-changed={source}/src/common/sdk/nvidia/inc");
    println!("cargo:rerun-if-changed={source}/src/nvidia/arch/nvalloc/unix/include");
    println!("cargo:rerun-if-changed={source}/src/nvidia/arch/nvalloc/common/inc");
    println!("cargo:rerun-if-changed={source}/src/nvidia/inc/kernel/os");
    build.compile("stela-nvidia-port");
}
