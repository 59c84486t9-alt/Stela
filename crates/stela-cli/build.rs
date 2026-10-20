//! The hosted main thread runs on the `stela` process's main thread
//! (`stela_runtime::hosted`), which needs the stack every guest host thread
//! gets (16 MiB) rather than the linker's 8 MiB default.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg-bin=stela=-Wl,-stack_size,0x1000000");
    }
}
