//! Assemble the AArch64 harness into a flat image with the host's clang.
use object::{Object, ObjectSection};
use std::{env, fs, path::PathBuf, process::Command};

const SOURCE: &str = "src/harness.S";
const TARGET: &str = "--target=aarch64-none-elf";
const ARCHITECTURE: &str = "-march=armv9.4-a+sme2+memtag";

fn main() {
    println!("cargo:rerun-if-changed={SOURCE}");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let object_path = out.join("harness.o");
    let clang = env::var_os("CLANG").unwrap_or_else(|| "clang".into());
    let status = Command::new(&clang)
        .args([TARGET, ARCHITECTURE, "-c", SOURCE, "-o"])
        .arg(&object_path)
        .status()
        .expect("run clang to assemble the AArch64 harness");
    assert!(status.success(), "clang failed to assemble {SOURCE}");
    let data = fs::read(&object_path).expect("read assembled harness");
    let file = object::File::parse(&*data).expect("parse assembled harness");
    let text = file.section_by_name(".text").expect("harness .text");
    assert!(
        text.relocations().next().is_none(),
        "the harness must be position-independent"
    );
    fs::write(out.join("harness.bin"), text.data().expect("harness bytes"))
        .expect("write harness image");
}
