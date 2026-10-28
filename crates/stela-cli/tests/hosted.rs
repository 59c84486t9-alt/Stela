//! End to end: after `stela install-system` into a fresh home directory,
//! `stela PROGRAM` runs an arm64 program, a `#!` script and an app bundle
//! with no options, explains what it cannot run, and `stela apps` makes and
//! removes a launcher.
//!
//! It needs the 26A434 guest roots ([`support::guest`]) and `xcrun clang`;
//! without them it says so and checks nothing.
#![cfg(all(target_os = "macos", target_arch = "x86_64"))]

mod support {
    pub mod guest;
}

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use support::guest::guest_roots;
const HELLO: &str = r#"#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    printf("hello from arm64:");
    for (int i = 1; i < argc; i++) printf(" %s", argv[i]);
    const char *bundle = getenv("__CFBundleIdentifier");
    if (bundle) printf(" (bundle %s)", bundle);
    printf("\n");
    return 3;
}
"#;

/// A program that runs another by the path it is given, as `execv` does.
const EXEC: &str = r#"#include <unistd.h>
int main(int argc, char **argv) { execv(argv[1], argv + 1); return 127; }
"#;

fn compile(directory: &Path, name: &str, flags: &[&str]) -> Option<PathBuf> {
    compile_source(directory, name, HELLO, flags)
}

fn compile_source(directory: &Path, name: &str, text: &str, flags: &[&str]) -> Option<PathBuf> {
    let source = directory.join(format!("{name}.c"));
    std::fs::write(&source, text).ok()?;
    let output = directory.join(name);
    Command::new("xcrun")
        .arg("clang")
        .args(flags)
        .arg(&source)
        .arg("-o")
        .arg(&output)
        .status()
        .ok()?
        .success()
        .then_some(output)
}

/// `stela ARGS` with `home` as the home directory, in `directory`.
fn stela(home: &Path, directory: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_stela"))
        .args(arguments)
        .current_dir(directory)
        .env("HOME", home)
        .env_remove("STELA_GUEST_ROOT")
        .env_remove("__CFBundleIdentifier")
        .output()
        .unwrap()
}

/// Whether a run's standard error ends with the summary of unsupported
/// operations it answered degraded.
fn answered_degraded(error: &str) -> bool {
    error.contains("unsupported operations answered")
}

/// A program asking for what the hosted runtime lacks, and for what
/// macOS itself refuses: an unassigned call number with SIGSYS ignored
/// (`nosys`), an unsupported `fcntl` command twice, and an UNDEFINED
/// encoding under a SIGILL handler.
const UNSUPPORTED: &str = r#"#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
static sigjmp_buf back;
static void caught(int signal) { printf("caught %d\n", signal); siglongjmp(back, 1); }
int main(int argc, char **argv) {
    (void)argc;
    signal(SIGSYS, SIG_IGN);
    register long x16 __asm__("x16") = 560;
    register long x0 __asm__("x0") = 0;
    __asm__ volatile("svc #0x80" : "+r"(x0) : "r"(x16) : "memory", "cc");
    printf("nosys %ld\n", x0);
    int fd = open(argv[0], O_RDONLY);
    for (int i = 0; i < 2; i++) {
        int result = fcntl(fd, 59 /* F_ADDSIGS */, 0);
        printf("fcntl %d %d\n", result, errno);
    }
    signal(SIGILL, caught);
    if (sigsetjmp(back, 1) == 0) __asm__ volatile(".inst 0x00000000");
    return 0;
}
"#;

fn text(output: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn installed_system_runs_arm64_programs() {
    let Some(roots) = guest_roots() else {
        eprintln!("skipped: no 26A434 guest roots (see this test's documentation)");
        return;
    };
    let work = tempfile::tempdir().unwrap();
    let home = work.path().join("home");
    let programs = work.path().join("programs");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&programs).unwrap();
    let Some(hello) = compile(&programs, "hello", &["-arch", "arm64e", "-O1"]) else {
        eprintln!("skipped: xcrun clang cannot build arm64e programs here");
        return;
    };
    compile(&programs, "intel", &["-arch", "x86_64"]).unwrap();
    compile(
        &programs,
        "unsigned",
        &["-arch", "arm64", "-Wl,-no_adhoc_codesign"],
    )
    .unwrap();

    // Nothing installed: the error names the one command that installs it.
    let output = stela(&home, &programs, &["./hello"]);
    let (_, error) = text(&output);
    assert!(!output.status.success());
    assert!(error.contains("stela install-system --ipsw"), "{error}");

    let mut install = vec!["install-system"];
    for root in &roots {
        install.extend(["--import", root.to_str().unwrap()]);
    }
    let output = stela(&home, &programs, &install);
    assert!(output.status.success(), "{:?}", text(&output));
    let installed = home.join("Library/Application Support/Stela/26A434");
    assert!(installed.join("receipt.json").is_file());
    // stelad's agent, written but not loaded: this home is not launchd's.
    let agent = home.join("Library/LaunchAgents/local.stela.stelad.plist");
    assert!(agent.is_file());
    let output = stela(&home, &programs, &["install-system"]);
    assert!(
        text(&output).0.contains("are installed"),
        "{:?}",
        text(&output)
    );

    // A path, with its own arguments and exit status.
    let output = stela(&home, &programs, &["./hello", "a", "--help"]);
    assert_eq!(
        text(&output).0,
        "hello from arm64: a --help\n",
        "{:?}",
        text(&output)
    );
    assert_eq!(output.status.code(), Some(3));
    let output = stela(&home, &programs, &["run", hello.to_str().unwrap(), "b"]);
    assert_eq!(
        text(&output).0,
        "hello from arm64: b\n",
        "{:?}",
        text(&output)
    );

    // The first program argument may be an option Stela recognizes too.
    let output = stela(
        &home,
        &programs,
        &["run", "./hello", "--help", "--model", "guest"],
    );
    assert_eq!(
        text(&output).0,
        "hello from arm64: --help --model guest\n",
        "{:?}",
        text(&output)
    );
    assert_eq!(output.status.code(), Some(3));

    // A #! script runs its interpreter (/bin/echo's arm64e slice).
    let script = programs.join("script");
    std::fs::write(&script, "#!/bin/echo from\n").unwrap();
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let output = stela(&home, &programs, &["./script", "x"]);
    assert_eq!(text(&output).0, "from ./script x\n", "{:?}", text(&output));

    // An app bundle starts as LaunchServices starts it.
    let app = programs.join("Hello.app");
    std::fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
    std::fs::copy(&hello, app.join("Contents/MacOS/hello")).unwrap();
    std::fs::write(
        app.join("Contents/Info.plist"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\
         <key>CFBundleExecutable</key><string>hello</string>\
         <key>CFBundleIdentifier</key><string>com.example.hello</string>\
         <key>CFBundlePackageType</key><string>APPL</string>\
         </dict></plist>\n",
    )
    .unwrap();
    let output = stela(&home, &programs, &["Hello.app", "doc.txt"]);
    assert_eq!(
        text(&output).0,
        "hello from arm64: doc.txt (bundle com.example.hello)\n",
        "{:?}",
        text(&output)
    );

    // What Stela cannot run is explained before anything runs.
    let output = stela(&home, &programs, &["./intel"]);
    assert!(
        text(&output).1.contains("Intel program (x86_64)"),
        "{:?}",
        text(&output)
    );
    let output = stela(&home, &programs, &["./unsigned"]);
    assert!(
        text(&output).1.contains("not code-signed"),
        "{:?}",
        text(&output)
    );
    let output = stela(&home, &programs, &["hello"]);
    assert!(
        text(&output).1.contains("use ./hello"),
        "{:?}",
        text(&output)
    );

    // The guest's own execve of a relative name stays relative: no PATH
    // lookup.
    compile_source(&programs, "exec", EXEC, &["-arch", "arm64e"]).unwrap();
    let output = stela(&home, &programs, &["./exec", "hello", "y"]);
    assert_eq!(
        text(&output).0,
        "hello from arm64: y\n",
        "{:?}",
        text(&output)
    );

    // A launcher for the arm64-only app, then nothing left after uninstall.
    let scan = [
        "apps",
        "--scan",
        programs.to_str().unwrap(),
        "--no-register",
    ];
    let output = stela(&home, &programs, &scan);
    assert!(output.status.success(), "{:?}", text(&output));
    let launcher = home.join("Applications/Stela/Hello.app");
    assert!(
        text(&output).0.contains("Added launcher"),
        "{:?}",
        text(&output)
    );
    assert!(launcher.join("Contents/MacOS/hello").is_file());
    let verified = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict"])
        .arg(&launcher)
        .status()
        .unwrap();
    assert!(verified.success());
    let output = stela(&home, &programs, &["apps", "--list"]);
    assert!(text(&output).0.contains("opens"), "{:?}", text(&output));
    let output = stela(&home, &programs, &["apps", "--uninstall", "--no-register"]);
    assert!(output.status.success(), "{:?}", text(&output));
    assert!(!home.join("Applications/Stela").exists());
    assert!(
        app.join("Contents/MacOS/hello").is_file(),
        "the original is kept"
    );

    let output = stela(&home, &programs, &["install-system", "--remove"]);
    assert!(output.status.success());
    assert!(!installed.exists() && !agent.exists());
}

#[test]
fn unsupported_operations_fail_as_macos_does() {
    let Some(roots) = guest_roots() else {
        eprintln!("skipped: no 26A434 guest roots (see this test's documentation)");
        return;
    };
    let work = tempfile::tempdir().unwrap();
    let home = work.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let Some(program) = compile_source(
        work.path(),
        "unsupported",
        UNSUPPORTED,
        &["-arch", "arm64e"],
    ) else {
        eprintln!("skipped: xcrun clang cannot build arm64e programs here");
        return;
    };
    let mut command = Command::new(env!("CARGO_BIN_EXE_stela"));
    command.arg("run");
    for root in &roots {
        command.arg("--root").arg(root);
    }
    let output = command.arg(&program).env("HOME", &home).output().unwrap();
    let (out, error) = text(&output);
    assert!(output.status.success(), "{out}{error}");
    assert_eq!(
        out, "nosys 78\nfcntl -1 22\nfcntl -1 22\ncaught 4\n",
        "{error}"
    );
    // Reported once, on standard error and in the log.
    assert_eq!(
        error
            .matches("stela: unsupported BSD system call: fcntl F_ADDSIGS")
            .count(),
        1,
        "{error}"
    );
    let log = std::fs::read_to_string(home.join("Library/Logs/Stela/unsupported.log")).unwrap();
    assert!(log.contains("fcntl F_ADDSIGS"), "{log}");
    assert!(answered_degraded(&error), "{error}");
}

/// A JIT: MAP_JIT's refusals, a write faulting while the thread's view
/// is executable, the region's RWX protection, code written and run through
/// `pthread_jit_write_protect_np`, a second thread starting with its own
/// executable view while the first stays writable, and a second JIT
/// region.
const JIT: &str = r#"#include <errno.h>
#include <libkern/OSCacheControl.h>
#include <libproc.h>
#include <pthread.h>
#include <ptrauth.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
static sigjmp_buf back;
static void faulted(int signal) { printf("fault %d\n", signal); siglongjmp(back, 1); }
static void store(uint32_t *code, uint32_t value) {
    if (sigsetjmp(back, 1) == 0) { code[0] = value; printf("stored\n"); }
}
static void emit(uint32_t *code, uint16_t value) {
    code[0] = 0x52800000 | ((uint32_t)value << 5); // mov w0, #value
    code[1] = 0xd65f03c0;                          // ret
}
static int call(uint32_t *code) {
    return ((int (*)(void))ptrauth_sign_unauthenticated(code, ptrauth_key_function_pointer, 0))();
}
static void execute(uint32_t *code) {
    if (sigsetjmp(back, 1) == 0) printf("executed %d\n", call(code));
}
static void *other(void *code) {
    printf("thread runs %d\n", call(code));
    store(code, 0);
    return NULL;
}
int main(void) {
    signal(SIGBUS, faulted);
    int flags = MAP_ANON | MAP_PRIVATE | MAP_JIT, all = PROT_READ | PROT_WRITE | PROT_EXEC;
    printf("supported %d\n", pthread_jit_write_protect_supported_np());
    printf("fixed %d\n", mmap((void *)0x300000000, 0x4000, all, flags | MAP_FIXED, -1, 0) == MAP_FAILED ? errno : 0);
    printf("shared %d\n", mmap(NULL, 0x4000, all, MAP_ANON | MAP_SHARED | MAP_JIT, -1, 0) == MAP_FAILED ? errno : 0);
    // Directly above a read-only anonymous neighbor, which the host's
    // region coalesces with the JIT mapping and the arm64 kernel does not.
    char *below = mmap(NULL, 0x8000, PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
    munmap(below + 0x4000, 0x4000);
    uint32_t *code = mmap(below + 0x4000, 0x4000, all, flags, -1, 0);
    if (code == MAP_FAILED) { printf("jit %d\n", errno); return 0; }
    store(code, 0);
    struct proc_regioninfo region;
    int size = proc_pidinfo(getpid(), PROC_PIDREGIONINFO, (uint64_t)code, &region, sizeof region);
    printf("region %d %d %d\n", size == sizeof region ? (int)region.pri_protection : -1,
           (char *)code == below + 0x4000, region.pri_address == (uint64_t)code);
    pthread_jit_write_protect_np(0);
    emit(code, 42);
    pthread_jit_write_protect_np(1);
    sys_icache_invalidate(code, 8);
    printf("runs %d\n", call(code));
    pthread_jit_write_protect_np(0);
    emit(code, 7);
    execute(code);
    sys_icache_invalidate(code, 8);
    pthread_t thread;
    pthread_create(&thread, NULL, other, code);
    pthread_join(thread, NULL);
    store(code, code[0]);
    pthread_jit_write_protect_np(1);
    sys_icache_invalidate(code, 8);
    printf("runs %d\n", call(code));
    printf("second %d\n", mmap(NULL, 0x4000, all, flags, -1, 0) == MAP_FAILED ? errno : 0);
    return 0;
}
"#;

#[test]
fn map_jit_regions_follow_each_threads_write_protection() {
    let Some(roots) = guest_roots() else {
        eprintln!("skipped: no 26A434 guest roots (see this test's documentation)");
        return;
    };
    let work = tempfile::tempdir().unwrap();
    let Some(program) = compile_source(work.path(), "jit", JIT, &["-arch", "arm64e", "-O1"]) else {
        eprintln!("skipped: xcrun clang cannot build arm64e programs here");
        return;
    };
    // The same program signed ad hoc with the hardened runtime and the
    // entitlements given.
    let signed = |name: &str, runtime: bool, entitlements: &[&str]| {
        let copy = work.path().join(name);
        std::fs::copy(&program, &copy).unwrap();
        let mut command = Command::new("/usr/bin/codesign");
        command.args(["-f", "-s", "-"]);
        if runtime {
            command.args(["-o", "runtime"]);
        }
        if !entitlements.is_empty() {
            let keys: String = entitlements
                .iter()
                .map(|key| format!("<key>{key}</key><true/>"))
                .collect();
            let plist = work.path().join(format!("{name}.plist"));
            std::fs::write(
                &plist,
                format!("<plist version=\"1.0\"><dict>{keys}</dict></plist>"),
            )
            .unwrap();
            command.arg("--entitlements").arg(plist);
        }
        assert!(command.arg(&copy).output().unwrap().status.success());
        copy
    };
    let run = |program: &Path| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_stela"));
        command.arg("run");
        for root in &roots {
            command.arg("--root").arg(root);
        }
        let output = command
            .arg(program)
            .env("HOME", work.path())
            .output()
            .unwrap();
        let (out, error) = text(&output);
        assert!(output.status.success(), "{out}{error}");
        assert!(!answered_degraded(&error), "{error}");
        out
    };
    let refusals = "supported 1\nfixed 22\nshared 22\n";
    let jit = |second: i32| {
        format!(
            "{refusals}fault 10\nregion 7 1 1\nruns 42\nfault 10\nthread runs 7\nfault 10\nstored\nruns 7\nsecond \
             {second}\n"
        )
    };
    assert_eq!(run(&program), jit(0));
    assert_eq!(
        run(&signed("hardened", true, &[])),
        format!("{refusals}jit 22\n")
    );
    assert_eq!(
        run(&signed(
            "allowed",
            true,
            &["com.apple.security.cs.allow-jit"]
        )),
        jit(0)
    );
    assert_eq!(
        run(&signed(
            "single",
            false,
            &["com.apple.security.cs.single-jit"]
        )),
        jit(22)
    );
}

/// A JIT writer's toggles, timed: each round makes the region writable,
/// writes 64 bytes of code, makes it executable, invalidates and calls it;
/// then bare toggle pairs, toggle pairs around one store, and invalidations
/// with calls alone.
const JIT_BENCHMARK: &str = r#"#include <libkern/OSCacheControl.h>
#include <pthread.h>
#include <ptrauth.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>
static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}
int main(int argc, char **argv) {
    int rounds = argc > 1 ? atoi(argv[1]) : 100000;
    uint32_t *code = mmap(NULL, 1 << 20, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);
    if (code == MAP_FAILED) return 1;
    int (*function)(void) =
        (int (*)(void))ptrauth_sign_unauthenticated(code, ptrauth_key_function_pointer, 0);
    long sum = 0;
    double start = now();
    for (int i = 0; i < rounds; i++) {
        pthread_jit_write_protect_np(0);
        code[0] = 0x52800000 | ((uint32_t)(i & 0xffff) << 5);
        code[1] = 0xd65f03c0;
        for (int j = 2; j < 16; j++) code[j] = 0xd503201f;
        pthread_jit_write_protect_np(1);
        sys_icache_invalidate(code, 64);
        sum += function();
    }
    double round = now() - start;
    start = now();
    for (int i = 0; i < rounds; i++) {
        pthread_jit_write_protect_np(0);
        pthread_jit_write_protect_np(1);
    }
    double bare = now() - start;
    start = now();
    for (int i = 0; i < rounds; i++) {
        pthread_jit_write_protect_np(0);
        code[64] = i;
        pthread_jit_write_protect_np(1);
    }
    double written = now() - start;
    start = now();
    for (int i = 0; i < rounds; i++) {
        sys_icache_invalidate(code, 64);
        sum += function();
    }
    double called = now() - start;
    printf("%d rounds (sum %ld), us each: round %.2f, bare toggle pair %.2f, toggle pair with a "
           "store %.2f, invalidate and call %.2f\n", rounds, sum, round / rounds * 1e6,
           bare / rounds * 1e6, written / rounds * 1e6, called / rounds * 1e6);
    return 0;
}
"#;

/// The JIT toggle microbenchmark, headless, for comparing write-protection
/// designs: `cargo test --release -p stela-cli --test hosted --
/// --ignored --nocapture map_jit_toggles_benchmark`, with `STELA_JIT_ROUNDS`
/// rounds (100000 by default).
#[test]
#[ignore = "a benchmark, run on request"]
fn map_jit_toggles_benchmark() {
    let Some(roots) = guest_roots() else {
        eprintln!("skipped: no 26A434 guest roots (see this test's documentation)");
        return;
    };
    let work = tempfile::tempdir().unwrap();
    let flags = ["-arch", "arm64e", "-O1"];
    let Some(program) = compile_source(work.path(), "jit_benchmark", JIT_BENCHMARK, &flags) else {
        eprintln!("skipped: xcrun clang cannot build arm64e programs here");
        return;
    };
    let rounds = std::env::var("STELA_JIT_ROUNDS").unwrap_or_else(|_| "100000".into());
    let mut command = Command::new(env!("CARGO_BIN_EXE_stela"));
    command.arg("run");
    for root in &roots {
        command.arg("--root").arg(root);
    }
    let output = command
        .arg(&program)
        .arg(&rounds)
        .env("HOME", work.path())
        .output()
        .unwrap();
    let (out, error) = text(&output);
    assert!(output.status.success(), "{out}{error}");
    println!("{out}");
}

#[test]
fn guest_tools_run_on_each_chosen_mac() {
    let Some(roots) = guest_roots() else {
        eprintln!("skipped: no 26A434 guest roots (see this test's documentation)");
        return;
    };
    let work = tempfile::tempdir().unwrap();
    let run = |model: Option<&str>, environment: Option<&str>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_stela"));
        command.arg("run");
        for root in &roots {
            command.arg("--root").arg(root);
        }
        if let Some(model) = model {
            command.args(["--model", model]);
        }
        command.args([
            "/usr/sbin/sysctl",
            "-n",
            "hw.model",
            "machdep.cpu.brand_string",
        ]);
        command.env("HOME", work.path()).env_remove("STELA_MODEL");
        if let Some(model) = environment {
            command.env("STELA_MODEL", model);
        }
        command.output().unwrap()
    };
    // The default, an explicit model, the environment's, and an explicit
    // model over the environment's.
    for (model, environment, expected) in [
        (None, None, "MacBookPro18,3\nApple M1 Pro\n"),
        (Some("Macmini9,1"), None, "Macmini9,1\nApple M1\n"),
        (None, Some("Mac15,10"), "Mac15,10\nApple M3 Max\n"),
        (Some("Mac16,10"), Some("Mac15,10"), "Mac16,10\nApple M4\n"),
    ] {
        let output = run(model, environment);
        assert!(output.status.success(), "{:?}", text(&output));
        assert_eq!(text(&output).0, expected, "{:?}", text(&output));
        assert!(!answered_degraded(&text(&output).1), "{:?}", text(&output));
    }
    let output = run(Some("Mac0,0"), None);
    assert!(!output.status.success());
    assert!(text(&output).1.contains("Mac14,3"), "{:?}", text(&output));
}
