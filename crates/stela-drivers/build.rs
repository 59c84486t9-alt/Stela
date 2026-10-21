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
    #[cfg(feature = "amd-port")]
    {
        let mut build = native::configure();
        build.file("src/gpu/amd/stela/vm_cpu.c").std("c11");
        for path in [
            "src/gpu/amd/stela",
            "src/gpu/amd/amdgpu/amdgpu_vm_cpu_entries.h",
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
        .include(format!("{source}/stela"))
        .include(format!("{source}/src/common/sdk/nvidia/inc"))
        .include(format!("{source}/src/nvidia/arch/nvalloc/unix/include"))
        .include(format!("{source}/src/nvidia/inc/kernel"));
    println!("cargo:rerun-if-changed={source}/stela");
    println!("cargo:rerun-if-changed={source}/src/common/sdk/nvidia/inc");
    println!("cargo:rerun-if-changed={source}/src/nvidia/arch/nvalloc/unix/include");
    println!("cargo:rerun-if-changed={source}/src/nvidia/inc/kernel/os");
    build.compile("stela-nvidia-port");
}
