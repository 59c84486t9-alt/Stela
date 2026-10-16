//! Reviewed instruction registries: compile one form sample under the execution
//! profile its registry declares.
use crate::compile::{Compiled, compile};
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use std::path::Path;
use stela_compiler::extended::{ScalableProfile, block::ExtendedBlockProfile};

/// How a registry's forms compile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Leaf,
    Block,
    Service,
    Scalable,
}

/// Every reviewed registry under `isa/`, with how its forms compile.
pub const REGISTRIES: [(&str, Mode); 4] = [
    ("apple-silicon-reviewed-forms.json", Mode::Leaf),
    ("apple-silicon-block-forms.json", Mode::Block),
    ("a64-service-forms.json", Mode::Service),
    ("apple-silicon-scalable-forms.json", Mode::Scalable),
];

const BASELINE: &str = "x86_64-baseline";

/// Read the registry `name` from the repository's `isa/` directory.
pub fn load(root: &Path, name: &str) -> Result<Value> {
    let path = root.join("isa").join(name);
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    Ok(serde_json::from_str(&text)?)
}

/// A registry hex word such as `"0x8b020020"`.
pub fn hex(value: &Value) -> Result<u32> {
    let text = value.as_str().context("expected a hex word")?;
    Ok(u32::from_str_radix(text.trim_start_matches("0x"), 16)?)
}

/// The compile command line for one form sample.
pub struct Probe {
    pub command: &'static str,
    pub flags: Vec<String>,
    /// The block ABI the manifest must declare; leaves declare none.
    pub abi: Option<String>,
    pub profile: String,
    /// The execution-profile contract of scalable and service forms.
    pub contract: Value,
}

impl Probe {
    /// The compile command for `sample` of `form` at guest address `base`.
    pub fn new(
        mode: Mode,
        registry: &Value,
        form: &Value,
        sample: &Value,
        base: u64,
    ) -> Result<Self> {
        let profile = form["profile"].as_str().context("form profile")?.to_owned();
        let contract = if profile == registry["profile"]["id"] {
            registry["profile"].clone()
        } else {
            let contract = registry["execution_profiles"][&profile].clone();
            ensure!(
                contract.is_object(),
                "undeclared execution profile {profile}"
            );
            contract
        };
        let mut flags = vec!["--guest-base".to_owned(), base.to_string()];
        let (command, abi) = match mode {
            Mode::Leaf => ("compile-leaf", None),
            Mode::Block => ("compile-block", contract["abi"].as_str().map(str::to_owned)),
            Mode::Service => {
                flags.extend(service_flags(&profile)?.iter().map(|flag| flag.to_string()));
                ("compile-block", contract["abi"].as_str().map(str::to_owned))
            }
            Mode::Scalable => {
                flags.extend(scalable_flags(&contract, sample)?);
                if contract["compiler_command"] == "compile-block" {
                    ("compile-block", contract["abi"].as_str().map(str::to_owned))
                } else {
                    ("compile-leaf", None)
                }
            }
        };
        Ok(Self {
            command,
            flags,
            abi,
            profile,
            contract,
        })
    }

    /// Compile `words` with this probe's command line.
    pub fn compile(&self, words: &[u32]) -> Result<Compiled> {
        let source: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        compile(&self.arguments(), &source)
    }

    /// The contextual block profile of a scalable `compile-block` probe; `None`
    /// for leaves and service blocks.
    pub fn context_block_profile_if_block(&self) -> Result<Option<ExtendedBlockProfile>> {
        if self.command != "compile-block" {
            return Ok(None);
        }
        crate::compile::context_block_profile(&self.arguments())
    }

    /// The scalable guest profile of a scalable `compile-leaf` probe.
    pub fn context_leaf_profile(&self) -> Result<Option<ScalableProfile>> {
        if self.command != "compile-leaf" {
            return Ok(None);
        }
        crate::compile::context_leaf_profile(&self.arguments())
    }

    fn arguments(&self) -> Vec<&str> {
        let mut arguments = vec!["stela", self.command, "source", "--output-dir", "native"];
        arguments.extend(self.flags.iter().map(String::as_str));
        arguments
    }
}

/// Flags that select a service profile for `compile-block`.
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
