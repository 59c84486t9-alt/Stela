#[cfg(feature = "amd-port")]
#[path = "build/amd.rs"]
mod amd;
#[cfg(feature = "amd-commands")]
#[path = "build/amd_commands.rs"]
mod amd_commands;
#[cfg(feature = "nouveau-port")]
#[path = "build/initcalls.rs"]
mod initcalls;
#[cfg(feature = "nouveau-port")]
#[path = "build/inputs.rs"]
mod inputs;
#[cfg(feature = "intel-port")]
#[path = "build/intel.rs"]
mod intel;
#[cfg(feature = "nouveau-port")]
#[path = "build/kbuild.rs"]
mod kbuild;
#[cfg(feature = "nouveau-port")]
#[path = "build/linux_registry.rs"]
mod linux_registry;
#[cfg(any(feature = "nvidia-port", feature = "linux-kernel"))]
#[path = "build/native.rs"]
mod native;
#[cfg(feature = "nouveau-port")]
#[path = "build/nouveau.rs"]
mod nouveau;
#[path = "build/nouveau_firmware.rs"]
mod nouveau_firmware;
#[cfg(feature = "nvidia-port")]
#[path = "build/nvidia.rs"]
mod nvidia;

fn main() {
    nouveau_firmware::validate();
    // Active ports declare their native source inputs below. Without this
    // baseline Cargo watches every vendored file even when no C port is used.
    println!("cargo:rerun-if-changed=build.rs");
    // Clippy reads Rust and links nothing, so it needs no C objects.
    println!("cargo:rerun-if-env-changed=CLIPPY_ARGS");
    #[cfg(feature = "linux-kernel")]
    if std::env::var_os("CLIPPY_ARGS").is_some() {
        let mut tests = native::Tests::default();
        tests.rust_children();
        tests.write();
        return;
    }
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
    #[cfg(feature = "nouveau-port")]
    let mut linux = linux;
    #[cfg(feature = "nouveau-port")]
    nouveau::port(&mut linux);
    #[cfg(feature = "linux-kernel")]
    tests.write();
}
