//! The whole upstream I801 translation unit, as the GPU ports include theirs.
use super::native::{self, Linux, Module};

pub fn port(linux: &Linux) {
    let source = "src/bus/smbus/linux_i801/driver.c";
    let module = Module {
        name: "i2c_i801",
        file: "drivers/i2c/busses/i2c-i801",
    };
    let mut build = native::configure();
    linux.apply(&mut build, None, &[], Some(&module));
    build.define("CONFIG_I2C", "1");
    build
        .flag("-isystem")
        .flag("../../third_party/linux/drivers/i2c/busses");
    native::check_declarations(&build, &[source.into()]);
    build.file(source).compile("stela-linux-i801");
    println!("cargo:rerun-if-changed=src/bus/smbus/linux_i801");
    println!("cargo:rerun-if-changed=../../third_party/linux/drivers/i2c/busses/i2c-i801.c");
}
