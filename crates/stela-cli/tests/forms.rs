//! Every reviewed instruction form still compiles from its registry samples, and
//! every recorded out-of-scope sample is still refused with its stated reason.
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use std::{fs, path::Path};
use stela_cli::compile::{Compiled, compile};

const RET: u32 = 0xd65f_03c0;
/// Guest base for every non-leaf probe; leaf probes use the CLI default.
const GUEST_BASE: u64 = 0x1000_0000;
const BASELINE: &str = "x86_64-baseline";
/// System profiles compile a bare exit: `movabs rax, pc; mov edx, kind; ret`.
const SYSTEM_EXIT_KIND: u32 = 11;
const X86_MOVABS_RAX: [u8; 2] = [0x48, 0xb8];
const X86_MOV_EDX: u8 = 0xba;
const X86_RET: u8 = 0xc3;
const DEFAULT_SOURCE_BYTES: u64 = 4;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Leaf,
    Block,
    Service,
    Scalable,
}

fn registry(name: &str) -> Result<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../isa")
        .join(name);
    Ok(serde_json::from_str(&fs::read_to_string(&path)?)?)
}

fn hex(value: &Value) -> Result<u32> {
    let text = value.as_str().context("expected a hex word")?;
    Ok(u32::from_str_radix(text.trim_start_matches("0x"), 16)?)
}

/// Command-line flags that select a service profile, as `stela compile-block` takes them.
fn service_flags(profile: &str) -> Result<&'static [&'static str]> {
    Ok(match profile {
        "apple-arm64e-software-pauth-clock-v1" => &["--software-pauth", "--software-clock"],
        "system-v1" => &["--system-boundaries", "--cpu-target", BASELINE],
        "el1-platform-v1" => &["--el1-platform", "--cpu-target", BASELINE],
        "checked-gpr-memory-sa0-off-normal-wb-v3" => {
            &["--checked-memory-sa0-off", "--cpu-target", BASELINE]
        }
        "checked-gpr-memory-sa0-off-normal-wb-pauth-clock-thread-v1" => {
            &["--checked-process-sa0-off", "--cpu-target", BASELINE]
        }
        "checked-pointer-memory-el0-v1" => &[
            "--checked-process-sa0-off",
            "--checked-pointer-mode",
            "addition-multiplication",
            "--cpu-target",
            BASELINE,
        ],
        other => bail!("unknown service profile {other}"),
    })
}

/// Flags for one scalable sample under its execution-profile contract.
fn scalable_flags(contract: &Value, sample: &Value) -> Result<Vec<String>> {
    let number = |key: &str| -> Result<String> {
        Ok(sample[key]
            .as_u64()
            .with_context(|| format!("scalable sample needs {key}"))?
            .to_string())
    };
    let mut flags = vec![
        "--guest-base".into(),
        GUEST_BASE.to_string(),
        "--guest-profile".into(),
        contract["id"].as_str().context("profile id")?.into(),
        "--svl-bytes".into(),
        number("svl_bytes")?,
        "--svcr".into(),
        number("svcr")?,
        "--cpu-target".into(),
        sample["cpu_target"].as_str().unwrap_or(BASELINE).into(),
    ];
    if let Some(features) = contract["features"].as_array() {
        for feature in features {
            flags.extend([
                "--guest-feature".into(),
                feature.as_str().context("feature")?.into(),
            ]);
        }
        flags.extend([
            "--max-svl-bytes".into(),
            contract["max_svl_bytes"].to_string(),
            "--zt0-enabled".into(),
            contract["zt0_enabled"].to_string(),
        ]);
        if let Some(fpmr) = contract["fpmr_enabled"].as_bool() {
            flags.extend(["--fpmr-enabled".into(), fpmr.to_string()]);
        }
    }
    if let Some(numerical) = contract["numerical_features"].as_object() {
        for (key, value) in numerical {
            flags.extend([format!("--{}", key.replace('_', "-")), value.to_string()]);
        }
    }
    Ok(flags)
}

struct Probe {
    command: &'static str,
    flags: Vec<String>,
    abi: Option<String>,
    profile: String,
}

fn probe(mode: Mode, registry: &Value, form: &Value, sample: &Value) -> Result<Probe> {
    let profile = form["profile"].as_str().context("form profile")?.to_owned();
    let contract = |profiles: &Value| -> Result<Value> {
        if profile == registry["profile"]["id"] {
            return Ok(registry["profile"].clone());
        }
        let contract = &profiles[&profile];
        ensure!(
            contract.is_object(),
            "undeclared execution profile {profile}"
        );
        Ok(contract.clone())
    };
    let base = || vec!["--guest-base".to_owned(), GUEST_BASE.to_string()];
    Ok(match mode {
        Mode::Leaf => Probe {
            command: "compile-leaf",
            flags: vec![],
            abi: None,
            profile,
        },
        Mode::Block => Probe {
            command: "compile-block",
            flags: base(),
            abi: registry["profile"]["abi"].as_str().map(str::to_owned),
            profile,
        },
        Mode::Service => {
            let contract = contract(&registry["execution_profiles"])?;
            let mut flags = base();
            flags.extend(service_flags(&profile)?.iter().map(|flag| flag.to_string()));
            Probe {
                command: "compile-block",
                flags,
                abi: contract["abi"].as_str().map(str::to_owned),
                profile,
            }
        }
        Mode::Scalable => {
            let contract = contract(&registry["execution_profiles"])?;
            let block = contract["compiler_command"] == "compile-block";
            Probe {
                command: if block {
                    "compile-block"
                } else {
                    "compile-leaf"
                },
                flags: scalable_flags(&contract, sample)?,
                abi: block
                    .then(|| contract["abi"].as_str().map(str::to_owned))
                    .flatten(),
                profile,
            }
        }
    })
}

fn run(probe: &Probe, words: &[u32]) -> Result<Compiled> {
    let source: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let mut arguments = vec!["stela", probe.command, "source", "--output-dir", "native"];
    arguments.extend(probe.flags.iter().map(String::as_str));
    compile(&arguments, &source)
}

fn check(mode: Mode, name: &str) -> Result<()> {
    let registry = registry(name)?;
    let mut failures = vec![];
    let mut probes = 0;
    for form in registry["forms"].as_array().context("forms")? {
        let id = form["id"].as_str().context("form id")?;
        let supported = form["status"] != "unsupported";
        let samples = form["smoke_samples"].as_array().map(Vec::as_slice);
        for sample in samples.filter(|_| supported).unwrap_or_default() {
            probes += 1;
            let word = hex(&sample["word"])?;
            let mut words = vec![word];
            for following in sample["following_words"].as_array().into_iter().flatten() {
                words.push(hex(following)?);
            }
            words.push(RET);
            let probe = probe(mode, &registry, form, sample)?;
            let result = run(&probe, &words).and_then(|compiled| {
                verify(&probe, sample, word, &compiled)?;
                Ok(())
            });
            if let Err(error) = result {
                failures.push(format!("{id} {word:#010x}: {error:#}"));
            }
        }
        for sample in form["rejected_samples"].as_array().into_iter().flatten() {
            probes += 1;
            let word = hex(&sample["word"])?;
            let reason = sample["reason"].as_str().context("rejection reason")?;
            let probe = probe(mode, &registry, form, sample)?;
            match run(&probe, &[word, RET]) {
                Ok(_) => failures.push(format!("{id} {word:#010x}: compiled but must be refused")),
                Err(error) if !format!("{error:#}").contains(reason) => failures.push(format!(
                    "{id} {word:#010x}: refused without {reason:?}: {error:#}"
                )),
                Err(_) => {}
            }
        }
    }
    ensure!(probes > 0, "{name} has no samples");
    ensure!(
        failures.is_empty(),
        "{} of {probes} probes failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    Ok(())
}

fn verify(probe: &Probe, sample: &Value, word: u32, compiled: &Compiled) -> Result<()> {
    ensure!(!compiled.native.is_empty(), "empty native code");
    let manifest = &compiled.manifest;
    if let Some(abi) = &probe.abi {
        ensure!(
            manifest["abi"] == abi.as_str(),
            "ABI {} differs from {abi}",
            manifest["abi"]
        );
        let expected = sample["consumed_source_bytes"]
            .as_u64()
            .unwrap_or(DEFAULT_SOURCE_BYTES);
        ensure!(
            manifest["source_bytes"] == expected,
            "consumed {} source bytes, expected {expected}",
            manifest["source_bytes"]
        );
    }
    if matches!(probe.profile.as_str(), "system-v1" | "el1-platform-v1") {
        let mut exit = X86_MOVABS_RAX.to_vec();
        exit.extend(GUEST_BASE.to_le_bytes());
        exit.push(X86_MOV_EDX);
        exit.extend(SYSTEM_EXIT_KIND.to_le_bytes());
        exit.push(X86_RET);
        ensure!(
            compiled.native == exit,
            "{word:#x} must compile to the bare System exit"
        );
    }
    Ok(())
}

#[test]
fn leaf_forms() -> Result<()> {
    check(Mode::Leaf, "apple-silicon-reviewed-forms.json")
}

#[test]
fn block_forms() -> Result<()> {
    check(Mode::Block, "apple-silicon-block-forms.json")
}

#[test]
fn service_forms() -> Result<()> {
    check(Mode::Service, "a64-service-forms.json")
}

#[test]
fn scalable_forms() -> Result<()> {
    check(Mode::Scalable, "apple-silicon-scalable-forms.json")
}
