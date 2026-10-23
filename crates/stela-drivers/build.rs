#[cfg(feature = "native-acpi")]
#[path = "build/acpi.rs"]
mod acpi;
#[cfg(feature = "amd-port")]
#[path = "build/amd.rs"]
mod amd;
#[cfg(feature = "amd-commands")]
#[path = "build/amd_commands.rs"]
mod amd_commands;
#[cfg(feature = "intel-port")]
#[path = "build/intel.rs"]
mod intel;
#[cfg(any(feature = "nvidia-port", feature = "intel-port", feature = "amd-port"))]
#[path = "build/native.rs"]
mod native;
#[cfg(feature = "nvidia-port")]
#[path = "build/nvidia.rs"]
mod nvidia;

fn main() {
    #[cfg(feature = "native-acpi")]
    acpi::build();
    // Active ports declare their native source inputs below. Without this
    // baseline Cargo watches every vendored file even when no C port is used.
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(any(feature = "amd-port", feature = "intel-port"))]
    let (linux, mut tests) = (native::Linux::new(), native::Tests::default());
    #[cfg(any(feature = "amd-port", feature = "intel-port"))]
    linux.tests(&mut tests);
    #[cfg(feature = "amd-port")]
    amd::port(&linux, &mut tests);
    #[cfg(feature = "amd-commands")]
    amd_commands::build();
    #[cfg(feature = "nvidia-port")]
    nvidia::port();
    #[cfg(feature = "intel-port")]
    intel::port(&linux, &mut tests);
    #[cfg(any(feature = "amd-port", feature = "intel-port"))]
    tests.write();
}
