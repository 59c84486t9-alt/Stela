//! Native C for the physical GPU ports: target and tool selection, Stela's
//! Linux environment for unchanged Linux sources, and the hosted C test
//! programs that `cargo test` runs when Cargo builds for this machine.
use std::{
    env, fs,
    path::{Path, PathBuf},
};

#[cfg(feature = "linux-kernel")]
use stela_c_build::native::configure;
#[cfg(feature = "linux-kernel")]
use stela_c_build::native::hosted;

#[cfg(feature = "linux-kernel")]
#[path = "linux_crc.rs"]
mod linux_crc;

/// The upstream sources: submodules that `cargo xtask gpu fetch` checks out.
#[cfg(feature = "linux-kernel")]
pub const LINUX: &str = "../../third_party/linux";
#[cfg(feature = "intel-port")]
pub const MESA: &str = "../../third_party/mesa";
#[cfg(feature = "nvidia-port")]
pub const NVIDIA: &str = "../../third_party/nvidia";

pub fn require_sources() {
    #[cfg(feature = "linux-kernel")]
    require_source(LINUX);
    #[cfg(feature = "intel-port")]
    require_source(MESA);
    #[cfg(feature = "nvidia-port")]
    require_source(NVIDIA);
}

fn require_source(source: &str) {
    assert!(
        Path::new(source).join(".git").exists(),
        "{source} is missing; run `cargo xtask gpu fetch`"
    );
}

/// Stela's Linux environment for unchanged Linux sources, and the kernel-API
/// in `compat/linux/kernel` that they call, built once for every port.
#[cfg(feature = "linux-kernel")]
pub struct Linux {
    /// Shared Kbuild flags and generated architecture header layout.
    pub environment: stela_c_build::linux::Environment,
    /// The kernel-API archive for Cargo's target.
    pub archive: PathBuf,
    /// The environment's units whose registrations nouveau's image names.
    #[cfg(feature = "nouveau-port")]
    pub captured: Vec<crate::initcalls::Captured>,
    /// What hosted programs running Linux code link: the kernel-API and the
    /// host's platform services.
    pub hosted: Vec<PathBuf>,
}

#[cfg(feature = "linux-kernel")]
const DRM: &str = "../../third_party/linux/drivers/gpu/drm";
/// DRM's core and the helpers nouveau selects, as Linux's `drm-y`,
/// `drm_kms_helper-y`, `ttm-y`, `gpu-sched-y` and `drm_display_helper-y`
/// compose them under Stela's Kconfig.
#[cfg(any(feature = "nouveau-port", feature = "amd-port"))]
const DRM_SOURCES: &[&str] = &[
    "drm_atomic",
    "drm_atomic_uapi",
    "drm_auth",
    "drm_blend",
    "drm_bridge",
    "drm_cache",
    "drm_color_mgmt",
    "drm_colorop",
    "drm_connector",
    "drm_crtc",
    "drm_displayid",
    "drm_drv",
    "drm_dumb_buffers",
    "drm_edid",
    "drm_eld",
    "drm_encoder",
    "drm_file",
    "drm_framebuffer",
    "drm_gem",
    "drm_ioctl",
    "drm_lease",
    "drm_managed",
    "drm_mode_config",
    "drm_mode_object",
    "drm_modes",
    "drm_modeset_lock",
    "drm_panel_orientation_quirks",
    "drm_pci",
    "drm_plane",
    "drm_prime",
    "drm_print",
    "drm_property",
    "drm_rect",
    "drm_syncobj",
    "drm_sysfs",
    "drm_vblank",
    "drm_vblank_work",
    "drm_writeback",
    "drm_exec",
    "drm_gpuvm",
    "drm_gem_ttm_helper",
    "drm_atomic_helper",
    "drm_atomic_state_helper",
    "drm_bridge_helper",
    "drm_crtc_helper",
    "drm_damage_helper",
    "drm_flip_work",
    "drm_format_helper",
    "drm_gem_atomic_helper",
    "drm_gem_framebuffer_helper",
    "drm_kms_helper_common",
    "drm_modeset_helper",
    "drm_plane_helper",
    "drm_probe_helper",
    "drm_self_refresh_helper",
    "drm_simple_kms_helper",
    "drm_vblank_helper",
    "ttm/ttm_tt",
    "ttm/ttm_bo",
    "ttm/ttm_bo_util",
    "ttm/ttm_bo_vm",
    "ttm/ttm_module",
    "ttm/ttm_execbuf_util",
    "ttm/ttm_range_manager",
    "ttm/ttm_resource",
    "ttm/ttm_pool",
    "ttm/ttm_device",
    "ttm/ttm_sys_manager",
    "ttm/ttm_backup",
    "scheduler/sched_main",
    "scheduler/sched_fence",
    "scheduler/sched_entity",
    "scheduler/sched_rq",
    "display/drm_display_helper_mod",
    "display/drm_dp_dual_mode_helper",
    "display/drm_dp_helper",
    "display/drm_dp_mst_topology",
    "display/drm_hdmi_helper",
    "display/drm_scdc_helper",
];

/// Linux's fences, reservation objects and shared buffers.
#[cfg(any(feature = "nouveau-port", feature = "amd-port"))]
const DMA_BUF_SOURCES: &[&str] = &[
    "dma-buf",
    "dma-buf-mapping",
    "dma-fence",
    "dma-fence-array",
    "dma-fence-chain",
    "dma-fence-unwrap",
    "dma-resv",
    "sync_file",
];
#[cfg(feature = "linux-kernel")]
const COMPAT: &str = "src/compat/linux";

#[cfg(feature = "linux-kernel")]
impl Linux {
    pub fn new() -> Self {
        require_sources();
        let environment = stela_c_build::linux::Environment::new(stela_c_build::linux::Roots {
            linux: LINUX.into(),
            compat: COMPAT.into(),
            output: out_dir(),
        });
        let mut linux = Self {
            environment,
            archive: PathBuf::new(),
            hosted: Vec::new(),
            #[cfg(feature = "nouveau-port")]
            captured: Vec::new(),
        };
        let kernel = sources(&format!("{COMPAT}/kernel"));
        let crc_tables = linux_crc::tables();
        // Unchanged shared helpers use Linux's arithmetic types. Stela's
        // extra conversion diagnostics remain confined to its own source.
        let upstream = vec![
            PathBuf::from(format!("{LINUX}/lib/string.c")),
            PathBuf::from(format!("{LINUX}/lib/hexdump.c")),
            PathBuf::from(format!("{LINUX}/lib/ratelimit.c")),
            PathBuf::from(format!("{LINUX}/drivers/i2c/algos/i2c-algo-bit.c")),
            PathBuf::from(format!("{LINUX}/lib/scatterlist.c")),
            PathBuf::from(format!("{LINUX}/lib/find_bit.c")),
            PathBuf::from(format!("{LINUX}/lib/bitmap.c")),
            PathBuf::from(format!("{LINUX}/lib/idr.c")),
            PathBuf::from(format!("{LINUX}/lib/radix-tree.c")),
            PathBuf::from(format!("{LINUX}/lib/xarray.c")),
            PathBuf::from(format!("{LINUX}/lib/rbtree.c")),
            PathBuf::from(format!("{LINUX}/lib/timerqueue.c")),
            PathBuf::from(format!("{LINUX}/lib/kobject.c")),
            PathBuf::from(format!("{LINUX}/lib/kobject_uevent.c")),
            PathBuf::from(format!("{LINUX}/lib/ctype.c")),
            PathBuf::from(format!("{LINUX}/lib/refcount_lock.c")),
            PathBuf::from(format!("{LINUX}/kernel/user.c")),
            PathBuf::from(format!("{LINUX}/kernel/exec_state.c")),
            PathBuf::from(format!("{LINUX}/kernel/locking/mutex.c")),
            PathBuf::from(format!("{LINUX}/kernel/locking/rtmutex_api.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/wait_support.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/wait.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/swait.c")),
            PathBuf::from(format!("{LINUX}/kernel/sched/completion.c")),
            PathBuf::from(format!("{LINUX}/kernel/rcuwait_wake.c")),
            PathBuf::from(format!("{LINUX}/kernel/rcu/rcuwait_finish.c")),
            PathBuf::from(format!("{LINUX}/fs/seq_output.c")),
            PathBuf::from(format!("{LINUX}/lib/maple_tree.c")),
            PathBuf::from(format!("{LINUX}/drivers/video/hdmi.c")),
            PathBuf::from(format!("{DRM}/drm_fourcc.c")),
            PathBuf::from(format!("{DRM}/drm_mm.c")),
            PathBuf::from(format!("{DRM}/drm_vma_manager.c")),
        ];
        let mut hosted_upstream = upstream.clone();
        #[cfg(any(feature = "nouveau-port", feature = "amd-port"))]
        let mut upstream = upstream;
        #[cfg(any(feature = "nouveau-port", feature = "amd-port"))]
        {
            upstream.extend(
                DMA_BUF_SOURCES
                    .iter()
                    .map(|source| PathBuf::from(format!("{LINUX}/drivers/dma-buf/{source}.c"))),
            );
            upstream.extend(
                DRM_SOURCES
                    .iter()
                    .map(|source| PathBuf::from(format!("{DRM}/{source}.c"))),
            );
        }
        // Hosted programs link what they test, and only amdgpu's reach these.
        if cfg!(feature = "amd-port") {
            hosted_upstream.clone_from(&upstream);
        }
        // Compiled below, with their registrations captured.
        #[cfg(feature = "nouveau-port")]
        upstream.retain(|source| {
            !crate::initcalls::ENVIRONMENT
                .iter()
                .any(|unit| unit.path() == *source)
        });
        for source in &upstream {
            println!("cargo:rerun-if-changed={}", source.display());
        }
        let mut build = configure();
        linux.environment.apply(&mut build, None, &[], None);
        let crc_objects = linux_crc::objects(&build, &crc_tables);
        build.objects(crc_objects);
        #[cfg(feature = "nouveau-port")]
        {
            let mut captured_build = upstream_build(&build);
            upstream_warnings(&mut captured_build);
            for (index, unit) in crate::initcalls::ENVIRONMENT.iter().enumerate() {
                linux.captured.push(crate::initcalls::compile(
                    &captured_build,
                    *unit,
                    index as u32 + 1,
                ));
            }
            build.objects(linux.captured.iter().map(|unit| unit.object()));
        }
        linux.archive = linux_archive(&build, "stela-linux", &kernel, &upstream);
        // A callable target-ABI fixture plus host helpers only. It links the
        // SAME production common archive/Rust heap as the unit binary;
        // never mix duplicate native/hosted common archives. The standalone
        // C suites below keep their separate sanitizer-linked programs.
        if env::var("TARGET").ok() == env::var("HOST").ok()
            && matches!(
                env::var("CARGO_CFG_TARGET_OS").as_deref(),
                Ok("linux" | "macos")
            )
        {
            let mut helper = stela_c_build::native::compiler();
            helper.define("STELA_TEST_CANONICAL_RUST_HEAP", None);
            helper.file(format!("{COMPAT}/stela/test.c"));
            let helper_objects = helper.compile_intermediates();
            let mut fixture = configure();
            linux.environment.apply(&mut fixture, None, &[], None);
            fixture
                .define("STELA_LINUX_TREES_TEST", None)
                .define("STELA_LINUX_TREES_CALLABLE", None)
                .define("STELA_LINUX_PERCPU_TEST", None)
                .files([
                    format!("{COMPAT}/kernel/trees.c"),
                    format!("{COMPAT}/kernel/percpu.c"),
                    format!("{COMPAT}/stela/task_test.c"),
                    format!("{COMPAT}/stela/atomic_callback_test.c"),
                    format!("{COMPAT}/stela/mutex_test.c"),
                    format!("{COMPAT}/stela/rtmutex_test.c"),
                    format!("{COMPAT}/stela/resource_test.c"),
                    format!("{COMPAT}/stela/service_test.c"),
                    format!("{COMPAT}/stela/timer_test.c"),
                    format!("{COMPAT}/stela/workqueue_test.c"),
                    format!("{COMPAT}/stela/i2c_test.c"),
                    format!("{COMPAT}/stela/sync_test.c"),
                ])
                .objects(helper_objects)
                .compile("linux-task-fixture");
        }
        if let Some(host) = hosted() {
            let services = [
                PathBuf::from(format!("{COMPAT}/stela/test.c")),
                PathBuf::from(format!("{COMPAT}/stela/registry_test_host.c")),
                PathBuf::from(format!("{COMPAT}/stela/taint_test_host.c")),
                PathBuf::from(format!("{COMPAT}/stela/rodata_test_host.c")),
            ];
            let services = archive(&host, "linux-host", &services);
            let mut kernel_build = host;
            linux.environment.apply(&mut kernel_build, None, &[], None);
            let crc_objects = linux_crc::objects(&kernel_build, &crc_tables);
            kernel_build.objects(crc_objects);
            linux.hosted = vec![
                linux_archive(&kernel_build, "linux-hosted", &kernel, &hosted_upstream),
                services,
            ];
        }
        linux
    }

    /// The environment's captured units, for the image that names them.
    #[cfg(feature = "nouveau-port")]
    pub fn take_captured(&mut self) -> Vec<crate::initcalls::Captured> {
        std::mem::take(&mut self.captured)
    }

    pub fn tests(&self, tests: &mut Tests) {
        super::nouveau_firmware::tests(self, tests);
        if env::var("TARGET").ok() == env::var("HOST").ok()
            && matches!(
                env::var("CARGO_CFG_TARGET_OS").as_deref(),
                Ok("linux" | "macos")
            )
        {
            tests.rust_children();
        }
        let Some(mut build) = hosted() else {
            return;
        };
        self.environment.apply(&mut build, None, &[], None);
        let archives = self.hosted.iter().map(PathBuf::as_path).collect::<Vec<_>>();
        // Dedicated lifecycle fixture: unchanged original kobject/uevent APIs.
        tests.add(
            &build,
            "linux_kobjects",
            &format!("{COMPAT}/stela/kobject_test.c"),
            &archives,
        );
        for (name, source) in [
            ("linux_compiler_abi", "abi_test.c"),
            ("linux_thread_initializers", "thread_initializers_test.c"),
            ("linux_acpi_client", "acpi_client_test.c"),
            ("linux_acpi_dsm", "acpi_dsm_test.c"),
            ("linux_random", "random_test.c"),
            ("linux_resources", "resources_test.c"),
            ("linux_seq_output", "seq_output_test.c"),
            ("linux_drm_mm", "drm_mm_test.c"),
            ("linux_drm_vma", "drm_vma_test.c"),
        ] {
            tests.add(&build, name, &format!("{COMPAT}/stela/{source}"), &archives);
        }
        // This fixture observes calls with the ELF linker's --wrap.
        if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
            let mut deferred = build.clone();
            for symbol in [
                "stela_linux_heap_alloc",
                "stela_linux_heap_free",
                "call_rcu",
            ] {
                deferred.flag(format!("-Wl,--wrap={symbol}"));
            }
            tests.add(
                &deferred,
                "linux_deferred_free",
                &format!("{COMPAT}/stela/deferred_free_test.c"),
                &archives,
            );
        }
        for (name, source, define) in [
            ("linux_printk", "printk.c", "STELA_LINUX_PRINTK_TEST"),
            ("linux_panic", "panic.c", "STELA_LINUX_PANIC_TEST"),
            ("linux_drm_formats", "drm.c", "STELA_LINUX_DRM_FORMAT_TEST"),
            ("linux_rcu", "rcu.c", "STELA_LINUX_RCU_TEST"),
            ("linux_pages", "page.c", "STELA_LINUX_PAGE_TEST"),
            ("linux_slab", "slab.c", "STELA_LINUX_SLAB_TEST"),
            ("linux_cache", "cache.c", "STELA_LINUX_CACHE_TEST"),
            ("linux_params", "params.c", "STELA_LINUX_PARAMS_TEST"),
            (
                "linux_params_parser",
                "params.c",
                "STELA_LINUX_PARAMS_PARSER_TEST",
            ),
            ("linux_registry", "registry.c", "STELA_LINUX_REGISTRY_TEST"),
            ("linux_taint", "taint.c", "STELA_LINUX_TAINT_TEST"),
            (
                "linux_entry_generation",
                "linux.c",
                "STELA_LINUX_ENTRY_GENERATION_TEST",
            ),
            ("linux_firmware", "firmware.c", "STELA_LINUX_FIRMWARE_TEST"),
            ("linux_crc", "crc.c", "STELA_LINUX_CRC_TEST"),
            ("linux_find_bit", "find_bit.c", "STELA_LINUX_FIND_BIT_TEST"),
            ("linux_cpuhotplug", "cpuhotplug.c", "STELA_LINUX_CPUHP_TEST"),
            (
                "linux_string_helpers",
                "string_helpers.c",
                "STELA_LINUX_STRING_HELPERS_TEST",
            ),
            ("linux_printf", "printf.c", "STELA_LINUX_PRINTF_TEST"),
            ("linux_uuid", "uuid.c", "STELA_LINUX_UUID_TEST"),
            ("linux_kstrtox", "kstrtox.c", "STELA_LINUX_KSTRTOX_TEST"),
            ("linux_jiffies", "jiffies.c", "STELA_LINUX_JIFFIES_TEST"),
            ("linux_device", "device.c", "STELA_LINUX_DEVICE_TEST"),
            ("linux_file", "file.c", "STELA_LINUX_FILE_TEST"),
            ("linux_mapping", "mapping.c", "STELA_LINUX_MAPPING_TEST"),
            ("linux_reclaim", "reclaim.c", "STELA_LINUX_RECLAIM_TEST"),
            ("linux_sort", "sort.c", "STELA_LINUX_SORT_TEST"),
            ("linux_usercopy", "usercopy.c", "STELA_LINUX_USERCOPY_TEST"),
            ("linux_dma", "dma.c", "STELA_LINUX_DMA_TEST"),
            ("linux_pci", "pci.c", "STELA_LINUX_PCI_TEST"),
            ("linux_pci_host", "pci_host.c", "STELA_LINUX_PCI_HOST_TEST"),
            ("linux_service", "service.c", "STELA_LINUX_SERVICE_TEST"),
            ("linux_vmalloc", "vmalloc.c", "STELA_LINUX_VMALLOC_TEST"),
            ("linux_refcount", "refcount.c", "STELA_LINUX_REFCOUNT_TEST"),
            (
                "linux_const_string",
                "const_string.c",
                "STELA_LINUX_CONST_STRING_TEST",
            ),
        ] {
            let mut build = build.clone();
            build.define(define, None);
            tests.add(
                &build,
                name,
                &format!("{COMPAT}/kernel/{source}"),
                &archives,
            );
        }
    }
}

/// Include directories below the GPU framework's source root.
#[cfg(feature = "linux-kernel")]
pub fn drm_includes(directories: &[&str]) -> Vec<PathBuf> {
    directories
        .iter()
        .map(|directory| Path::new(DRM).join(directory))
        .collect()
}

/// Compile unchanged helpers with the common ABI and baseline diagnostics,
/// then archive them with the strictly checked owned objects. One archive
/// preserves dependency resolution between Linux helpers and host services.
#[cfg(feature = "linux-kernel")]
fn linux_archive(
    build: &cc::Build,
    name: &str,
    kernel: &[PathBuf],
    upstream: &[PathBuf],
) -> PathBuf {
    check_declarations(build, kernel);
    let mut upstream_build = upstream_build(build);
    check_declarations(&upstream_build, upstream);
    upstream_warnings(&mut upstream_build);
    upstream_build.files(upstream);
    let objects = upstream_build.compile_intermediates();
    let mut combined = build.clone();
    combined.objects(&objects);
    archive(&combined, name, kernel)
}

/// `build` for unchanged Linux sources.
#[cfg(feature = "linux-kernel")]
fn upstream_build(build: &cc::Build) -> cc::Build {
    let mut build = build.clone();
    // The scheduler's shared units include its internal header as "sched.h";
    // Stela's scheduler supplies what they take from it. As Kbuild builds
    // every profile: Linux relies on the optimizer to drop the calls its
    // configuration disables.
    build
        .flag(format!("-iquote{COMPAT}/kernel/sched"))
        .opt_level(2);
    build
}

/// Linux's own warning profile for unchanged sources, in place of Stela's.
#[cfg(feature = "linux-kernel")]
pub fn upstream_warnings(build: &mut cc::Build) {
    build
        .remove_flag("-Wconversion")
        .remove_flag("-Wsign-conversion")
        // Linux scripts/Makefile.warn disables these outside W=3. Unchanged
        // helpers compare signed counts and keep unused public parameters.
        .flag("-Wno-sign-compare")
        .flag("-Wno-unused-parameter")
        // Linux's top-level Makefile builds every file with -Wno-pointer-sign:
        // mutex.c passes its unsigned owner word to the long atomic helpers.
        .flag("-Wno-pointer-sign");
    // The rest of scripts/Makefile.warn's default (no W=) clang profile.
    for warning in [
        "format-security",
        "trigraphs",
        "frame-address",
        "address-of-packed-member",
        "type-limits",
        "unused-but-set-variable",
        "unused-const-variable",
        "initializer-overrides",
        "pointer-to-enum-cast",
        "tautological-constant-out-of-range-compare",
        "unaligned-access",
        "enum-compare-conditional",
        "missing-field-initializers",
        "shift-negative-value",
        "enum-enum-conversion",
    ] {
        build.flag(format!("-Wno-{warning}"));
    }
}

/// Clang reports nothing from system headers, not even a call to a service no
/// header declares, so check each adapter for those before it links.
#[cfg(feature = "linux-kernel")]
pub fn check_declarations(build: &cc::Build, sources: &[PathBuf]) {
    for source in sources {
        run(build
            .get_compiler()
            .to_command()
            .args(["-Wsystem-headers", "-Wno-everything"])
            .args([
                "-Werror=implicit-function-declaration",
                "-Werror=implicit-int",
            ])
            .arg("-fsyntax-only")
            .arg(source));
    }
}

/// The C files directly in `directory`, in a stable order.
pub fn sources(directory: &str) -> Vec<PathBuf> {
    let mut sources = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("cannot read {directory}: {error}"))
        .map(|entry| entry.expect("readable directory entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "c"))
        .collect::<Vec<_>>();
    sources.sort();
    println!("cargo:rerun-if-changed={directory}");
    sources
}

/// Hosted C test programs, each run by its own Rust test.
#[cfg(feature = "linux-kernel")]
#[derive(Default)]
pub struct Tests {
    programs: Vec<(String, PathBuf)>,
    rust: Vec<(&'static str, &'static str)>,
}

#[cfg(feature = "linux-kernel")]
impl Tests {
    /// Link `source` with `archives` into a program named `name`. A source may
    /// include the adapter it tests; the archives supply the others it calls.
    pub fn add(&mut self, build: &cc::Build, name: &str, source: &str, archives: &[&Path]) {
        let program = out_dir().join(format!("c-test-{name}"));
        let mut command = build.get_compiler().to_command();
        command.arg(source).args(archives).arg("-o").arg(&program);
        run(command.args(["-lpthread", "-lm"]));
        println!("cargo:rerun-if-changed={source}");
        self.programs.push((name.replace('-', "_"), program));
    }

    /// The Rust-hosted fixtures, each with its own exact child selector.
    pub fn rust_children(&mut self) {
        self.rust.extend([
            (
                "linux_trees",
                "crate::linux::task::tests::run_trees_child()",
            ),
            (
                "linux_mutex_wait",
                "crate::linux::task::tests::run_mutex_child()",
            ),
        ]);
    }

    /// The Rust tests `src/lib.rs` includes, one per program/child wrapper.
    pub fn write(&self) {
        let mut tests = self
            .programs
            .iter()
            .map(|(name, program)| {
                format!("#[test]\nfn {name}() {{\n    run({:?});\n}}\n", program)
            })
            .collect::<String>();
        for (name, body) in &self.rust {
            tests.push_str(&format!("#[test]\nfn {name}() {{\n    {body};\n}}\n"));
        }
        fs::write(out_dir().join("c_tests.rs"), tests).expect("write the C test list");
    }
}

/// Compile `sources` with `build` into an archive outside Cargo's link line.
#[cfg(feature = "linux-kernel")]
pub fn archive(build: &cc::Build, name: &str, sources: &[PathBuf]) -> PathBuf {
    build.clone().files(sources).compile(name);
    out_dir().join(format!("lib{name}.a"))
}

/// Rebuild when `path` changes.
#[cfg(feature = "nouveau-port")]
pub fn rerun_on(path: &Path) {
    println!("cargo:rerun-if-changed={}", path.display());
}

pub fn out_dir() -> PathBuf {
    PathBuf::from(env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"))
}

#[cfg(feature = "linux-kernel")]
pub fn run(command: &mut std::process::Command) {
    let line = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|part| part.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("cannot run {line}: {error}"));
    assert!(
        output.status.success(),
        "{line} failed ({}):\n{}{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
