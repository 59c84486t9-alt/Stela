//! Stela's amdgpu port and its hosted tests.
use super::native::{self, Linux, Module, Tests};

const AMDGPU: Module = Module {
    name: "amdgpu",
    file: "drivers/gpu/drm/amd/amdgpu/amdgpu",
};

/// amdgpu's probe admission and IP discovery, from the unchanged
/// `amdgpu_drv.c` and `amdgpu_discovery.c`, and Stela's BAR policy, all in
/// Stela's Linux environment with amdgpu's Kbuild include directories.
pub fn port(linux: &Linux, tests: &mut Tests) {
    const FIXTURES: &str = "src/amd/tests/fixtures.c";
    let configure = |mut build: cc::Build| {
        linux.apply(
            &mut build,
            None,
            &[
                "amd/include/asic_reg",
                "amd/include",
                "amd/amdgpu",
                "amd/pm/inc",
                "amd/acp/include",
                "amd/display",
                "amd/display/include",
                "amd/display/modules/inc",
                "amd/display/dc",
                "amd/display/amdgpu_dm",
                "amd/amdkfd",
                "amd/ras/rascore",
                "amd/ras/ras_mgr",
            ],
            Some(&AMDGPU),
        );
        build
    };
    let adapters = native::sources("src/amd");
    let port = configure(stela_c_build::native::configure());
    native::check_declarations(&port, &adapters);
    port.clone().files(&adapters).compile("stela-amd-port");
    // Fixtures for the integration test, which links them itself.
    port.clone()
        .file(FIXTURES)
        .cargo_metadata(false)
        .compile("stela-amd-test-fixtures");
    println!("cargo:rerun-if-changed=src/amd/tests");
    let Some(hosted) = stela_c_build::native::hosted() else {
        return;
    };
    let hosted = configure(hosted);
    let fixtures = native::archive(&hosted, "amd-fixtures-hosted", &[FIXTURES.into()]);
    let adapters = native::archive(&hosted, "amd-adapters-hosted", &adapters);
    let mut archives = vec![adapters.as_path(), fixtures.as_path()];
    archives.extend(linux.hosted.iter().map(|archive| archive.as_path()));
    for name in ["ip_discovery", "native_bar", "pci_match"] {
        let source = format!("src/amd/tests/{name}.c");
        tests.add(&hosted, &format!("amd_{name}"), &source, &archives);
    }
}
