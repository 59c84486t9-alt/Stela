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
#[cfg(any(feature = "nvidia-port", feature = "linux-kernel"))]
#[path = "build/native.rs"]
mod native;
#[path = "build/nouveau_firmware.rs"]
mod nouveau_firmware;
#[cfg(feature = "nvidia-port")]
#[path = "build/nvidia.rs"]
mod nvidia;
#[cfg(any(
    feature = "native-acpi",
    feature = "nvidia-port",
    feature = "linux-kernel"
))]
#[path = "build/tools.rs"]
mod tools;

fn main() {
    nouveau_firmware::validate();
    #[cfg(feature = "native-acpi")]
    acpi::build();
    // Active ports declare their native source inputs below. Without this
    // baseline Cargo watches every vendored file even when no C port is used.
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(feature = "linux-kernel")]
    let (linux, mut tests) = (native::Linux::new(), native::Tests::default());
    #[cfg(feature = "linux-kernel")]
    linux.tests(&mut tests);
    #[cfg(feature = "amd-port")]
    amd::port(&linux, &mut tests);
    #[cfg(feature = "amd-commands")]
    amd_commands::build();
    #[cfg(feature = "nvidia-port")]
    nvidia::port();
    #[cfg(feature = "intel-port")]
    intel::port(&linux, &mut tests);
    #[cfg(feature = "linux-kernel")]
    tests.write();
}
