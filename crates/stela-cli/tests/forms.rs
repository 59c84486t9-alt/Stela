//! Every registered instruction form compiles from its samples, and every
//! out-of-scope sample is refused with its recorded reason.
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::path::Path;
use stela_cli::{
    compile::Compiled,
    registry::{self, Mode, Probe, hex},
};

const RET: u32 = 0xd65f_03c0;
const GUEST_BASE: u64 = 0x1000_0000;
const DEFAULT_SOURCE_BYTES: u64 = 4;
/// System profiles compile a bare exit: `movabs rax, pc; mov edx, kind; ret`.
const SYSTEM_EXIT_KIND: u32 = 11;
const X86_MOVABS_RAX: [u8; 2] = [0x48, 0xb8];
const X86_MOV_EDX: u8 = 0xba;
const X86_RET: u8 = 0xc3;

fn check(mode: Mode) -> Result<()> {
    let (name, _) = registry::REGISTRIES
        .into_iter()
        .find(|(_, registry_mode)| *registry_mode == mode)
        .context("registry")?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let registry = registry::load(&root, name)?;
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
            let probe = Probe::new(mode, &registry, form, sample, GUEST_BASE)?;
            if let Err(error) = probe
                .compile(&words)
                .and_then(|compiled| verify(&probe, sample, word, &compiled))
            {
                failures.push(format!("{id} {word:#010x}: {error:#}"));
            }
        }
        for sample in form["rejected_samples"].as_array().into_iter().flatten() {
            probes += 1;
            let word = hex(&sample["word"])?;
            let reason = sample["reason"].as_str().context("rejection reason")?;
            let probe = Probe::new(mode, &registry, form, sample, GUEST_BASE)?;
            match probe.compile(&[word, RET]) {
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
    check(Mode::Leaf)
}

#[test]
fn block_forms() -> Result<()> {
    check(Mode::Block)
}

#[test]
fn service_forms() -> Result<()> {
    check(Mode::Service)
}

#[test]
fn scalable_forms() -> Result<()> {
    check(Mode::Scalable)
}
