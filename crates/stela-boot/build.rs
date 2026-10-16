fn main() {
    // The Multiboot address-fields image has one fixed physical load address.
    println!("cargo:rustc-link-arg=--no-pie");
    let directory = std::env::var("CARGO_MANIFEST_DIR").expect("Cargo manifest path");
    println!("cargo:rerun-if-changed=link.ld");
    println!("cargo:rerun-if-changed=src/entry.S");
    println!("cargo:rustc-link-arg=-T{directory}/link.ld");
    println!("cargo:rustc-link-arg=--build-id=none");
}
