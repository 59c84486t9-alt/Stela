//! Build the single shared Linux runtime only when explicitly enabled.
#[cfg(feature = "kernel")]
#[path = "build/native.rs"]
mod native;

#[cfg(feature = "kernel")]
fn task_fixtures() -> bool {
    cfg!(feature = "hosted-test-support")
        && std::env::var("TARGET").ok() == std::env::var("HOST").ok()
        && std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64")
        && matches!(
            std::env::var("CARGO_CFG_TARGET_OS").as_deref(),
            Ok("linux" | "macos")
        )
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CLIPPY_ARGS");
    #[cfg(feature = "kernel")]
    {
        use stela_c_build::linux_build::{Tests, out_dir};
        println!("cargo:output={}", out_dir().display());
        let mut tests = Tests::default();
        if std::env::var_os("CLIPPY_ARGS").is_some() {
            if task_fixtures() {
                tests.rust_children();
            }
        } else {
            let linux = native::Linux::new();
            if cfg!(feature = "hosted-test-support") {
                linux.tests(&mut tests);
            }
        }
        tests.write();
    }
}
