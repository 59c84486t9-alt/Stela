#[cfg(feature = "native-acpi")]
#[path = "build/acpi.rs"]
mod acpi;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(feature = "native-acpi")]
    acpi::build();
}
