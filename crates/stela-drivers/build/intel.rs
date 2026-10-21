//! Source list for the native Intel support library; the caller owns target,
//! compiler, archiver, freestanding flags, and the final library name.
pub fn configure(build: &mut cc::Build) {
    let source = "src/gpu/intel";
    build
        .define("STELA_NATIVE", None)
        .include(format!("{source}/xe"))
        .file(format!("{source}/xe/xe_pt_walk.c"))
        .file(format!("{source}/stela/pt_walk.c"))
        .file(format!("{source}/stela/commands.c"));
    for path in [
        "stela",
        "xe/xe_pt_walk.h",
        "xe/xe_ring_emit.h",
        "xe/instructions",
    ] {
        println!("cargo:rerun-if-changed={source}/{path}");
    }
}
