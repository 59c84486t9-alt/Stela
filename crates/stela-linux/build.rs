//! Build the single shared Linux runtime only when explicitly enabled.
#[cfg(feature = "kernel")]
#[path = "build/native.rs"]
mod native;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CLIPPY_ARGS");
    #[cfg(feature = "kernel")]
    {
        use stela_c_build::linux_build::{Tests, out_dir};
        println!("cargo:output={}", out_dir().display());
        let mut tests = Tests::default();
        if std::env::var_os("CLIPPY_ARGS").is_some() {
            tests.rust_children();
        } else {
            let linux = native::Linux::new();
            linux.tests(&mut tests);
        }
        tests.write();
    }
}
