//! Instruction progress: merge the registries into the Arm checklist and render
//! the README table. Each encoding form counts once, at its best status across
//! execution profiles; aliases and partial forms are not counted.
use crate::tools::root;
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, to_string as json};
use std::{collections::BTreeMap, fs};

const CHECKLIST: &str = "isa/a64-documented-checklist.json";
const APPLE_PROFILES: &str = "isa/apple-codegen-profiles.json";
const APPLE_EXTENSIONS: &str = "isa/apple-specific-extensions.json";
const REGISTRIES: [&str; 4] = [
    "isa/apple-silicon-reviewed-forms.json",
    "isa/apple-silicon-block-forms.json",
    "isa/a64-service-forms.json",
    "isa/apple-silicon-scalable-forms.json",
];
const README: &str = "README.md";
const README_START: &str = "<!-- stela-instruction-progress:start -->";
const README_END: &str = "<!-- stela-instruction-progress:end -->";
/// Best first; a form takes the best status of any reviewed profile.
const STATUSES: [&str; 3] = ["implemented", "partial", "unsupported"];
/// Checklist form fields in their published order.
const FACT_FIELDS: [&str; 8] = [
    "id",
    "instruction_id",
    "mnemonic",
    "category",
    "source_file",
    "encoding_mask",
    "encoding_value",
    "features",
];
const FORMS_START: &str = "\n  \"forms\": [\n";
const ASSESSMENT_START: &str = "\n  \"assessment\": {";

#[derive(Default)]
struct Counts([usize; 3]);

impl Counts {
    fn add(&mut self, status: usize) {
        self.0[status] += 1;
    }
    fn total(&self) -> usize {
        self.0.iter().sum()
    }
    fn percentage(&self) -> f64 {
        100.0 * self.0[0] as f64 / self.total() as f64
    }
}

/// Update the checklist and README, or with `check` fail if either is stale.
pub fn run(check: bool) -> Result<()> {
    let checklist_path = root().join(CHECKLIST);
    let readme_path = root().join(README);
    let checklist_text = fs::read_to_string(&checklist_path)?;
    let readme_text = fs::read_to_string(&readme_path)?;

    let mut forms = checklist_forms(&checklist_text)?;
    assess(&mut forms)?;
    let checklist = render_checklist(&checklist_text, &forms)?;
    let readme = render_readme(&readme_text, &forms)?;

    for (path, old, new) in [
        (&checklist_path, &checklist_text, &checklist),
        (&readme_path, &readme_text, &readme),
    ] {
        if old == new {
            continue;
        }
        if check {
            bail!("{} is stale; run `cargo xtask progress`", path.display());
        }
        fs::write(path, new)?;
        println!("updated {}", path.display());
    }
    Ok(())
}

fn read_json(path: &str) -> Result<Value> {
    let text =
        fs::read_to_string(root().join(path)).with_context(|| format!("cannot read {path}"))?;
    serde_json::from_str(&text).with_context(|| format!("invalid JSON in {path}"))
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .with_context(|| format!("missing string field {key}"))
}

fn status_index(status: &str) -> Result<usize> {
    STATUSES
        .iter()
        .position(|candidate| *candidate == status)
        .with_context(|| format!("unknown status {status}"))
}

/// One checklist form per line, keyed by form id.
fn checklist_forms(checklist: &str) -> Result<BTreeMap<String, Value>> {
    let (_, lines) = checklist
        .split_once(FORMS_START)
        .context("checklist has no forms array")?;
    let mut forms = BTreeMap::new();
    for line in lines.lines().take_while(|line| line.starts_with("    {")) {
        let form: Value = serde_json::from_str(line.trim().trim_end_matches(','))?;
        let id = text(&form, "id")?.to_owned();
        ensure!(
            forms.insert(id.clone(), form).is_none(),
            "duplicate form {id}"
        );
    }
    Ok(forms)
}

fn assess(forms: &mut BTreeMap<String, Value>) -> Result<()> {
    for form in forms.values_mut() {
        form["status"] = "unsupported".into();
        form["profiles"] = Value::Array(vec![]);
    }
    for registry in REGISTRIES {
        let reviewed = read_json(registry)?;
        for entry in reviewed["forms"]
            .as_array()
            .context("registry has no forms")?
        {
            let id = text(entry, "id")?;
            let form = forms
                .get_mut(id)
                .with_context(|| format!("{registry}: {id} is not an Arm checklist form"))?;
            for key in ["encoding_mask", "encoding_value", "source_file"] {
                ensure!(
                    form[key] == entry[key],
                    "{registry}: {id} {key} differs from the checklist"
                );
            }
            let status = text(entry, "status")?;
            if status_index(status)? < status_index(text(form, "status")?)? {
                form["status"] = status.into();
            }
            form["profiles"]
                .as_array_mut()
                .expect("profiles were reset to an array")
                .push(serde_json::json!({
                    "profile": entry["profile"],
                    "status": status,
                    "scope": entry["scope"],
                }));
        }
    }
    Ok(())
}

fn render_checklist(checklist: &str, forms: &BTreeMap<String, Value>) -> Result<String> {
    let (header, _) = checklist
        .split_once(ASSESSMENT_START)
        .context("checklist has no assessment")?;
    let mut overall = Counts::default();
    let mut categories: BTreeMap<&str, Counts> = BTreeMap::new();
    for form in forms.values() {
        let status = status_index(text(form, "status")?)?;
        overall.add(status);
        categories
            .entry(text(form, "category")?)
            .or_default()
            .add(status);
    }
    let category_rows: Vec<String> = categories
        .iter()
        .map(|(name, counts)| {
            let fields: Vec<String> = STATUSES
                .iter()
                .zip(counts.0)
                .filter(|(_, count)| *count != 0)
                .map(|(status, count)| format!("        \"{status}\": {count}"))
                .collect();
            format!("      \"{name}\": {{\n{}\n      }}", fields.join(",\n"))
        })
        .collect();
    let lines: Vec<String> = forms
        .values()
        .map(|form| {
            let mut fields: Vec<String> = FACT_FIELDS
                .iter()
                .chain(&["status"])
                .map(|key| Ok(format!("\"{key}\":{}", json(&form[*key])?)))
                .collect::<Result<_>>()?;
            let profiles: Vec<String> = form["profiles"]
                .as_array()
                .expect("assessed forms have profiles")
                .iter()
                .map(|profile| {
                    Ok(format!(
                        "{{\"profile\":{},\"status\":{},\"scope\":{}}}",
                        json(&profile["profile"])?,
                        json(&profile["status"])?,
                        json(&profile["scope"])?
                    ))
                })
                .collect::<Result<_>>()?;
            fields.push(format!("\"profiles\":[{}]", profiles.join(",")));
            Ok(format!("    {{{}}}", fields.join(",")))
        })
        .collect::<Result<_>>()?;
    Ok(format!(
        "{header}{ASSESSMENT_START}\n    \"implemented\": {},\n    \"partial\": {},\n    \
         \"unsupported\": {},\n    \"total\": {},\n    \"implementation_percentage\": {},\n    \
         \"categories\": {{\n{}\n    }}\n  }},\n  \"compiler_source_sha256\": \"{}\",{FORMS_START}{}\n  ]\n}}\n",
        overall.0[0],
        overall.0[1],
        overall.0[2],
        overall.total(),
        overall.percentage(),
        category_rows.join(",\n"),
        stela_compiler::SOURCE_SHA256,
        lines.join(",\n"),
    ))
}

fn render_readme(readme: &str, forms: &BTreeMap<String, Value>) -> Result<String> {
    let profiles = read_json(APPLE_PROFILES)?;
    let mut apple = Counts::default();
    for candidate in profiles["forms"].as_array().context("no Apple forms")? {
        let id = text(candidate, "id")?;
        let form = forms
            .get(id)
            .with_context(|| format!("Apple candidate {id} is not an Arm checklist form"))?;
        apple.add(status_index(text(form, "status")?)?);
    }
    let extensions = read_json(APPLE_EXTENSIONS)?;
    let extensions = extensions["extensions"]
        .as_array()
        .context("no Apple extensions")?;
    let implemented_extensions = extensions
        .iter()
        .filter(|extension| extension["status"] == "implemented")
        .count();
    let clang = text(&profiles["compiler"], "version")?;
    let compiler = &stela_compiler::SOURCE_SHA256[..12];

    let table = format!(
        "| Measurement | Current |\n| --- | --- |\n\
         | Apple M1–M6 candidate forms implemented | **{} / {} ({:.2}%)** |\n\
         | Partially implemented | {} |\n\
         | Unimplemented | {} |\n\
         | Apple-specific extension groups | {implemented_extensions} / {} tracked |\n\n\
         Candidates are the {clang} CPU features for M1–M6 mapped to Arm A64 2026-06; \
         compiler `{compiler}`. Each canonical form counts once at its best reviewed status; \
         aliases are excluded and partial forms earn no credit.\n\n\
         [Apple candidates]({APPLE_PROFILES}) · [Arm checklist]({CHECKLIST}) · \
         [Apple extensions]({APPLE_EXTENSIONS})\n",
        group(apple.0[0]),
        group(apple.total()),
        apple.percentage(),
        group(apple.0[1]),
        group(apple.0[2]),
        extensions.len(),
    );
    let (before, rest) = readme
        .split_once(README_START)
        .context("README has no progress start marker")?;
    let (_, after) = rest
        .split_once(README_END)
        .context("README has no progress end marker")?;
    Ok(format!(
        "{before}{README_START}\n{table}{README_END}{after}"
    ))
}

/// Thousands separators, as in `3,201`.
fn group(value: usize) -> String {
    let digits = value.to_string();
    let mut grouped = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

#[cfg(test)]
mod tests;
