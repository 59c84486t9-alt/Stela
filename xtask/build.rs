//! Assemble the AArch64 fixtures into flat images with the host's clang: the
//! system-mode test kernel.
use object::{Object, ObjectSection};
use std::{env, fs, path::PathBuf, process::Command};

const TARGET: &str = "--target=aarch64-none-elf";
/// (source, image, architecture)
const FIXTURES: [(&str, &str, &str); 1] = [("src/boot/kernel.S", "kernel.bin", "-march=armv8.6-a")];

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let clang = env::var_os("CLANG").unwrap_or_else(|| "clang".into());
    for (source, image, architecture) in FIXTURES {
        println!("cargo:rerun-if-changed={source}");
        let object_path = out.join(image).with_extension("o");
        let status = Command::new(&clang)
            .args([TARGET, architecture, "-c", source, "-o"])
            .arg(&object_path)
            .status()
            .expect("run clang to assemble an AArch64 fixture");
        assert!(status.success(), "clang failed to assemble {source}");
        let data = fs::read(&object_path).expect("read assembled fixture");
        let file = object::File::parse(&*data).expect("parse assembled fixture");
        let text = file.section_by_name(".text").expect("fixture .text");
        assert!(
            text.relocations().next().is_none(),
            "{source} must be position-independent"
        );
        fs::write(out.join(image), text.data().expect("fixture bytes"))
            .expect("write fixture image");
    }
}
