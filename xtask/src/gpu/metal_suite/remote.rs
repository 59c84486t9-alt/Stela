//! Running the plan on the Mac over ssh, finding which functions each MSL
//! version compiles, and compiling the AIR offline with Stela's compiler.
use super::plan::{self, metal_version, version_flags};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

const REMOTE_DIR: &str = "stela-metal-suite";
const DEVELOPER_DIR: &str = "/Applications/Xcode.app/Contents/Developer";

pub fn run(command: &mut Command) -> Result<()> {
    println!("+ {command:?}");
    crate::tools::exec(command)
}

fn ssh(host: &str, script: &str) -> Command {
    let mut c = Command::new("ssh");
    c.arg(host).arg(script);
    c
}

/// Pipes `tar` output into `into`'s standard input.
pub(super) fn pipe(mut tar: Command, mut into: Command) -> Result<()> {
    println!("+ {tar:?} | {into:?}");
    let mut source = tar.stdout(Stdio::piped()).spawn().context("tar")?;
    let status = into.stdin(source.stdout.take().unwrap()).status()?;
    let tar_status = source.wait()?;
    if !status.success() || !tar_status.success() {
        bail!("{tar:?} | {into:?} failed: {tar_status}, {status}");
    }
    Ok(())
}

/// The shell commands that build every library and the runner on the Mac.
fn mac_script(plan: &Value) -> String {
    let mut lines = vec![
        "set -e".to_string(),
        format!("export DEVELOPER_DIR={DEVELOPER_DIR}"),
        "cd \"$(dirname \"$0\")\"".into(),
        "mkdir -p lib".into(),
    ];
    // Dynamic libraries first: the libraries linking them need them built.
    let mut builds: Vec<(&String, &Value)> =
        plan["builds"].as_object().into_iter().flatten().collect();
    builds.sort_by_key(|(_, b)| b["dynamic"].as_bool() != Some(true));
    for (name, build) in builds {
        let source = Path::new(build["source"].as_str().unwrap())
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        let flags: Vec<&str> = build["flags"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let placeholders: Vec<&str> = build["air_names"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        if placeholders.is_empty() {
            lines.push(format!(
                "xcrun -sdk macosx metal {} -c sources/{source} -o lib/{name}.air",
                flags.join(" ")
            ));
        } else {
            // Apple's compiler takes no AIR names in source: its IR calls
            // placeholders, which take the names before it compiles that IR.
            lines.push(format!(
                "xcrun -sdk macosx metal {} -S -emit-llvm -c sources/{source} -o lib/{name}.ll",
                flags.join(" ")
            ));
            let renames: String = placeholders
                .iter()
                .map(|p| {
                    format!(
                        " -e 's/@_Z[0-9]*{p}[A-Za-z0-9_]*/@{}/g'",
                        super::plan::air_name(p)
                    )
                })
                .collect();
            lines.push(format!("sed{renames} lib/{name}.ll > lib/{name}.named.ll"));
            lines.push(format!(
                "xcrun -sdk macosx metal -c -x ir lib/{name}.named.ll -o lib/{name}.air"
            ));
        }
        let links: String = build["links"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(|l| format!(" lib/{l}.metallib"))
            .collect();
        // Linked by the `metal` driver, which keeps the functions'
        // reflection that `metallib` alone drops.
        lines.push(if build["dynamic"].as_bool() == Some(true) {
            format!(
                "xcrun -sdk macosx metal -dynamiclib -install_name @loader_path/{name}.metallib lib/{name}.air -o lib/{name}.metallib"
            )
        } else {
            format!("xcrun -sdk macosx metal lib/{name}.air{links} -o lib/{name}.metallib")
        });
    }
    lines.push(
        "clang -fobjc-arc -arch arm64 -mmacosx-version-min=14.0 -O1 -Wall -Wextra -Wno-unused-parameter \
         -framework Foundation -framework Metal -framework MetalFX -framework MetalPerformanceShaders -framework CoreImage \
         -framework CoreGraphics -framework QuartzCore -framework IOSurface runner.m -o runner.bin"
            .into(),
    );
    let default = plan["builds"]
        .as_object()
        .into_iter()
        .flatten()
        .find(|(_, b)| b["default"].as_bool() == Some(true))
        .map(|(name, _)| name.as_str());
    lines.extend(bundle_script(default));
    lines.join("\n") + "\n"
}

/// Puts the runner in `Runner.app`, with the same binary as its embedded
/// `Share.xpc` service, signs both and leaves `runner` as a script that
/// starts the bundled binary. `host` cases sharing a texture and an event
/// across processes reach the service by its bundle identifier. The
/// bundle's resources hold the plan's default library, if it has one, as
/// an application ships `default.metallib`.
fn bundle_script(default: Option<&str>) -> Vec<String> {
    let plist = |id: &str, executable: &str, package: &str, extra: &str| {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\
             <key>CFBundleIdentifier</key><string>{id}</string>\
             <key>CFBundleExecutable</key><string>{executable}</string>\
             <key>CFBundleName</key><string>{executable}</string>\
             <key>CFBundlePackageType</key><string>{package}</string>\
             <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>\
             <key>CFBundleVersion</key><string>1</string>{extra}</dict></plist>"
        )
    };
    let app = "Runner.app/Contents";
    let service = format!("{app}/XPCServices/Share.xpc/Contents");
    let mut lines: Vec<String> = vec![
        "rm -rf Runner.app runner".into(),
        format!("mkdir -p {app}/MacOS {app}/Resources {service}/MacOS"),
        format!("cp runner.bin {app}/MacOS/runner"),
        format!("mv runner.bin {service}/MacOS/share"),
        format!(
            "cat > {app}/Info.plist <<'PLIST'\n{}\nPLIST",
            plist("com.stela.metal-suite", "runner", "APPL", "")
        ),
        format!(
            "cat > {service}/Info.plist <<'PLIST'\n{}\nPLIST",
            plist(
                "com.stela.metal-suite.share",
                "share",
                "XPC!",
                "<key>XPCService</key><dict><key>ServiceType</key><string>Application</string></dict>"
            )
        ),
    ];
    if let Some(name) = default {
        lines.push(format!(
            "cp lib/{name}.metallib {app}/Resources/default.metallib"
        ));
    }
    lines.extend([
        "codesign -s - -f Runner.app/Contents/XPCServices/Share.xpc && codesign -s - -f Runner.app".into(),
        "printf '#!/bin/sh\\nexec \"$(dirname \"$0\")/Runner.app/Contents/MacOS/runner\" \"$@\"\\n' > runner".into(),
        "chmod +x runner".into(),
    ]);
    lines
}

/// Copies DIR/plan to the Mac, builds it there, runs every case and brings
/// back the AIR, metallibs, runner and DIR/results/mac.
pub fn mac(out: &Path, plan: &Value, host: &str) -> Result<()> {
    let dir = out.join("plan");
    fs::copy(super::assets().join("runner.m"), dir.join("runner.m"))?;
    fs::write(dir.join("build.sh"), mac_script(plan))?;
    let mut tar = Command::new("tar");
    tar.arg("-C").arg(out).args(["-cf", "-", "plan"]);
    pipe(
        tar,
        ssh(
            host,
            &format!("rm -rf {REMOTE_DIR} && mkdir -p {REMOTE_DIR} && tar -C {REMOTE_DIR} -xf -"),
        ),
    )?;
    run(&mut ssh(host, &format!("sh {REMOTE_DIR}/plan/build.sh")))?;
    let status = ssh(
        host,
        &format!("cd {REMOTE_DIR} && plan/runner plan results/mac"),
    )
    .status()?;
    if !status.success() {
        eprintln!("runner exited with {status}");
    }
    let results = out.join("results/mac");
    if results.exists() {
        fs::remove_dir_all(&results)?;
    }
    let mut extract = Command::new("tar");
    extract.arg("-C").arg(out).arg("-xf").arg("-");
    pipe(
        ssh(
            host,
            &format!("tar -C {REMOTE_DIR} -cf - plan/lib plan/runner plan/Runner.app results/mac"),
        ),
        extract,
    )
}

/// Each source line's enclosing function, for naming compile errors.
fn kernel_lines(text: &str) -> Vec<Option<String>> {
    let mut current = None;
    text.split('\n')
        .map(|line| {
            for word in ["kernel void ", "vertex ", "fragment "] {
                if let Some(at) = line.find(word)
                    && let Some(paren) = line[at..].find('(')
                    && let Some(name) = line[at..at + paren].split_whitespace().last()
                {
                    current = Some(name.to_string());
                }
            }
            current.clone()
        })
        .collect()
}

/// Finds, for every guarded corpus source and MSL version, the functions
/// Apple's compiler refuses, and records them in availability.json with
/// the functions the toolchain's headers declare.
pub fn probe(out: &Path, host: &str) -> Result<()> {
    let mut full = plan::Plan::new(Default::default());
    super::build(&mut full);
    let corpus = super::assets().join("corpus");
    let mut sources: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for library in full.libraries().values() {
        sources
            .entry(library.source.clone())
            .or_default()
            .insert(library.version.clone());
    }
    let mut result: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
    for (source, versions) in sources {
        let text = full.source_text(&source, &corpus)?;
        if !text.contains("#ifndef SKIP_") {
            continue;
        }
        let lines = kernel_lines(&text);
        let name = Path::new(&source)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        run(&mut ssh(host, &format!("mkdir -p {REMOTE_DIR}/probe")))?;
        let mut upload = ssh(host, &format!("cat > {REMOTE_DIR}/probe/{name}"))
            .stdin(Stdio::piped())
            .spawn()?;
        upload.stdin.take().unwrap().write_all(text.as_bytes())?;
        if !upload.wait()?.success() {
            bail!("uploading {name}");
        }
        let mut versions: Vec<String> = versions.into_iter().collect();
        versions.sort_by_key(|v| metal_version(v));
        for version in versions {
            let mut skipped = BTreeSet::new();
            loop {
                let mut flags = version_flags(&version);
                flags.extend(skipped.iter().map(|k| format!("-DSKIP_{k}")));
                let command = format!(
                    "export DEVELOPER_DIR={DEVELOPER_DIR}; cd {REMOTE_DIR}/probe && \
                     xcrun -sdk macosx metal {} -ferror-limit=0 -c {name} -o /dev/null",
                    flags.join(" ")
                );
                let p = ssh(host, &command).output()?;
                if p.status.success() {
                    break;
                }
                let stderr = String::from_utf8_lossy(&p.stderr);
                let mut found = BTreeSet::new();
                for line in stderr.lines() {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() > 3
                        && parts[0].ends_with(&name)
                        && parts[3].contains("error")
                        && let Some(Some(kernel)) = parts[1]
                            .parse::<usize>()
                            .ok()
                            .and_then(|l| l.checked_sub(1))
                            .and_then(|l| lines.get(l))
                    {
                        found.insert(kernel.clone());
                    }
                }
                if found.is_subset(&skipped) {
                    let tail = &stderr[stderr.len().saturating_sub(2000)..];
                    bail!("{name} at {version} fails outside any function:\n{tail}");
                }
                skipped.extend(found);
            }
            println!("{name} {version}: {} unavailable", skipped.len());
            if !skipped.is_empty() {
                result
                    .entry(name.clone())
                    .or_default()
                    .insert(version, skipped.into_iter().collect());
            }
        }
    }
    let toolchain = ssh(
        host,
        &format!("DEVELOPER_DIR={DEVELOPER_DIR} xcrun -sdk macosx metal --version"),
    )
    .output()?;
    let toolchain = String::from_utf8_lossy(&toolchain.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    // The toolchain's own headers, from beside its compiler.
    let headers = out.join("headers");
    if headers.exists() {
        fs::remove_dir_all(&headers)?;
    }
    fs::create_dir_all(&headers)?;
    let mut extract = Command::new("tar");
    // macOS tar records file flags GNU tar does not know.
    extract
        .arg("-C")
        .arg(&headers)
        .args(["--warning=no-unknown-keyword", "-xf", "-"]);
    pipe(
        ssh(
            host,
            &format!(
                "export DEVELOPER_DIR={DEVELOPER_DIR}; root=$(dirname \"$(dirname \"$(xcrun -sdk macosx -f metal)\")\")/metal; \
                 tar -C \"$(find \"$root\" -type d -path '*/include/metal' | head -1)\" -cf - ."
            ),
        ),
        extract,
    )?;
    let functions = super::inventory::inventory(&headers)?;
    println!(
        "{} functions in {} headers",
        functions.values().map(BTreeSet::len).sum::<usize>(),
        functions.len()
    );
    // The SDK's Metal.framework headers.
    let framework = out.join("framework");
    if framework.exists() {
        fs::remove_dir_all(&framework)?;
    }
    fs::create_dir_all(&framework)?;
    let mut extract = Command::new("tar");
    extract
        .arg("-C")
        .arg(&framework)
        .args(["--warning=no-unknown-keyword", "-xf", "-"]);
    pipe(
        ssh(
            host,
            &format!(
                "export DEVELOPER_DIR={DEVELOPER_DIR}; \
                 tar -C \"$(xcrun -sdk macosx --show-sdk-path)/System/Library/Frameworks/Metal.framework/Headers\" -cf - ."
            ),
        ),
        extract,
    )?;
    let api = super::inventory::framework(&framework)?;
    println!(
        "{} framework entries in {} headers",
        api.values()
            .flat_map(|classes| classes.values())
            .map(BTreeSet::len)
            .sum::<usize>(),
        api.len()
    );
    let path = super::assets().join("availability.json");
    fs::write(
        &path,
        serde_json::to_string_pretty(
            &json!({"toolchain": toolchain, "sources": result, "functions": functions, "api": api}),
        )? + "\n",
    )?;
    println!("{}", path.display());
    Ok(())
}

/// Compiles each case's functions with Stela's compiler from the AIR the
/// Mac produced, recording acceptance and NIR in DIR/offline.
pub fn offline(out: &Path, compiler: &Path, only: &[String]) -> Result<()> {
    let plan = plan::load(&out.join("plan"))?;
    let lib = out.join("plan/lib");
    let dir = out.join("offline");
    fs::create_dir_all(&dir)?;
    let mut seen: BTreeMap<(String, String), Value> = BTreeMap::new();
    for case in plan["cases"].as_array().unwrap() {
        if !plan::selects(only, plan::name_of(case)) {
            continue;
        }
        // A sequence's steps name their functions, and may their library;
        // a mesh pipeline names its object and mesh functions.
        let units = std::iter::once(case).chain(case["steps"].as_array().into_iter().flatten());
        let entries = units.flat_map(|u| {
            [
                &u["function"],
                &u["vertex"],
                &u["fragment"],
                &u["render"]["mesh"]["object"],
                &u["render"]["mesh"]["mesh"],
            ]
            .map(|v| (u, v))
        });
        for (unit, value) in entries {
            let Some(library) = unit["library"].as_str().or(case["library"].as_str()) else {
                continue;
            };
            let air = lib.join(format!("{library}.air"));
            let Some(entry) = value.as_str() else {
                continue;
            };
            if !air.exists() {
                continue;
            }
            let id = (library.to_string(), entry.to_string());
            if seen.contains_key(&id) {
                continue;
            }
            let mut command = Command::new(compiler);
            command
                .args(["--entry", entry, "--nir"])
                .arg(dir.join(format!("{library}.{entry}.nir")));
            if !unit["constants"].is_null() || !case["constants"].is_null() {
                command.args(["--fill", "0"]);
            }
            let p = command
                .arg(&air)
                .output()
                .with_context(|| compiler.display().to_string())?;
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&p.stdout),
                String::from_utf8_lossy(&p.stderr)
            );
            let text = text.trim();
            println!(
                "{} {library}.{entry}",
                if p.status.success() {
                    "ok     "
                } else {
                    "REFUSED"
                }
            );
            seen.insert(
                id,
                json!({"library": library, "entry": entry, "accepted": p.status.success(),
                       "output": &text[text.len().saturating_sub(2000)..]}),
            );
        }
    }
    let refused = seen.values().filter(|s| s["accepted"] == false).count();
    fs::write(
        dir.join("offline.json"),
        serde_json::to_string_pretty(&seen.values().collect::<Vec<_>>())?,
    )?;
    println!("{} accepted, {refused} refused", seen.len() - refused);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_lines_name_enclosing_functions() {
        let lines = kernel_lines("x\nkernel void a(int i)\n{\n}\nvertex V b(\n");
        assert_eq!(lines[0], None);
        assert_eq!(lines[2].as_deref(), Some("a"));
        assert_eq!(lines[4].as_deref(), Some("b"));
    }

    #[test]
    fn mac_script_builds_each_library() {
        let plan = json!({"builds": {"m": {"source": "x/m.metal", "flags": ["-std=metal4.1"]}}});
        let script = mac_script(&plan);
        assert!(script.contains("metal -std=metal4.1 -c sources/m.metal -o lib/m.air"));
        assert!(script.contains("runner.m -o runner.bin"));
        assert!(script.contains("<string>com.stela.metal-suite.share</string>"));
        assert!(script.contains("exec \"$(dirname \"$0\")/Runner.app/Contents/MacOS/runner\""));
    }

    /// A library calling AIR builtins through placeholders compiles its
    /// IR with the placeholders' mangled names replaced by AIR's.
    #[test]
    fn mac_script_names_air_builtins_in_ir() {
        let source =
            "void stela_air__wait_simdgroup_events(int);\nstela_air__wait_simdgroup_events(1);";
        let names = super::super::plan::air_placeholders(source);
        assert_eq!(names, ["stela_air__wait_simdgroup_events"]);
        let plan = json!({"builds": {"b": {"source": "b.metal", "flags": [], "air_names": names}}});
        let script = mac_script(&plan);
        assert!(script.contains("metal  -S -emit-llvm -c sources/b.metal -o lib/b.ll"));
        assert!(script.contains(
            "sed -e 's/@_Z[0-9]*stela_air__wait_simdgroup_events[A-Za-z0-9_]*/@air.wait_simdgroup_events/g'"
        ));
        assert!(script.contains("metal -c -x ir lib/b.named.ll -o lib/b.air"));
        assert_eq!(
            super::super::plan::air_name("stela_air__simdgroup_async_copy_2d__p3i8__p1i8"),
            "air.simdgroup_async_copy_2d.p3i8.p1i8"
        );
    }
}
