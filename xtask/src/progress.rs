//! Instruction progress: merge the registries into the Arm checklist and render
//! the README table. Each encoding form counts once, at its best status across
//! execution profiles; aliases and partial forms are not counted.
use crate::tools::{preserve_newlines, root};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, to_string as json};
use std::{collections::BTreeMap, fs};

mod forms;

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
/// Best first; a form takes the best status across its profiles.
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
    let absent_path = root().join(forms::GENERATED);
    let absent_text = fs::read_to_string(&absent_path).unwrap_or_default();
    let features = forms::Features::from_matrix(&read_json(crate::system_matrix::MATRIX)?)?;
    let absent = preserve_newlines(
        &absent_text,
        &forms::render(&forms, &read_json(APPLE_PROFILES)?, &features)?,
    );

    for (path, old, new) in [
        (&checklist_path, &checklist_text, &checklist),
        (&readme_path, &readme_text, &readme),
        (&absent_path, &absent_text, &absent),
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

/// Split a published section marker without changing the input text.
fn split_marker<'a>(text: &'a str, marker: &str) -> Option<(&'a str, &'a str)> {
    let crlf = marker.replace('\n', "\r\n");
    let (start, bytes) = text
        .find(marker)
        .map(|start| (start, marker.len()))
        .into_iter()
        .chain(text.find(crlf.as_str()).map(|start| (start, crlf.len())))
        .min_by_key(|&(start, _)| start)?;
    Some((&text[..start], &text[start + bytes..]))
}

/// One checklist form per line, keyed by form id.
fn checklist_forms(checklist: &str) -> Result<BTreeMap<String, Value>> {
    let (_, lines) =
        split_marker(checklist, FORMS_START).context("checklist has no forms array")?;
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
            let mut profile = serde_json::json!({
                "profile": entry["profile"],
                "status": status,
                "scope": entry["scope"],
            });
            if let Some(excluded) = exclusion(entry)? {
                profile["excluded"] = excluded.into();
            }
            form["profiles"]
                .as_array_mut()
                .expect("profiles were reset to an array")
                .push(profile);
        }
    }
    Ok(())
}

/// The part of a form or extension group the exclusion policy (no source
/// gives a reasonably certain implementation, and no user workload reaches
/// it) leaves out, with the reason: its `excluded` field, when present.
fn exclusion(entry: &Value) -> Result<Option<&str>> {
    match &entry["excluded"] {
        Value::Null => Ok(None),
        Value::String(reason) if !reason.trim().is_empty() => Ok(Some(reason)),
        _ => bail!(
            "{}: excluded must name the excluded part and its reason",
            entry["id"]
        ),
    }
}

fn render_checklist(checklist: &str, forms: &BTreeMap<String, Value>) -> Result<String> {
    let (header, _) =
        split_marker(checklist, ASSESSMENT_START).context("checklist has no assessment")?;
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
                    let excluded = match &profile["excluded"] {
                        Value::Null => String::new(),
                        reason => format!(",\"excluded\":{}", json(reason)?),
                    };
                    Ok(format!(
                        "{{\"profile\":{},\"status\":{},\"scope\":{}{excluded}}}",
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
    let body = format!(
        "{ASSESSMENT_START}\n    \"implemented\": {},\n    \"partial\": {},\n    \
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
    );
    let previous = &checklist[header.len()..];
    Ok(format!("{header}{}", preserve_newlines(previous, &body)))
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
    // An excluded group carries its reason and is outside the tracked count.
    let mut excluded_extensions = 0;
    for extension in extensions {
        let excluded = exclusion(extension)?;
        ensure!(
            excluded.is_some() == (extension["status"] == "excluded"),
            "{}: an excluded group needs status excluded and its reason",
            extension["id"]
        );
        excluded_extensions += usize::from(excluded.is_some());
    }
    let clang = text(&profiles["compiler"], "version")?;
    let compiler = &stela_compiler::SOURCE_SHA256[..12];

    let table = format!(
        "| Measurement | Current |\n| --- | --- |\n\
         | Apple M1–M6 candidate forms implemented | **{} / {} ({:.2}%)** |\n\
         | Partially implemented | {} |\n\
         | Unimplemented | {} |\n\
         | Apple-specific extension groups | {implemented_extensions} / {} tracked ({excluded_extensions} excluded) |\n\n\
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
        extensions.len() - excluded_extensions,
    );
    let (before, rest) = readme
        .split_once(README_START)
        .context("README has no progress start marker")?;
    let (previous, after) = rest
        .split_once(README_END)
        .context("README has no progress end marker")?;
    let template = if previous.contains('\n') {
        previous
    } else {
        readme
    };
    let body = preserve_newlines(template, &format!("\n{table}"));
    Ok(format!("{before}{README_START}{body}{README_END}{after}"))
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
mod tests {
    use super::*;

    #[test]
    fn exclusions_carry_their_reason() {
        let excluded = serde_json::json!({"id": "x", "excluded": "debug only"});
        assert_eq!(exclusion(&excluded).unwrap(), Some("debug only"));
        assert_eq!(exclusion(&serde_json::json!({"id": "x"})).unwrap(), None);
        assert!(exclusion(&serde_json::json!({"id": "x", "excluded": " "})).is_err());
        assert!(exclusion(&serde_json::json!({"id": "x", "excluded": true})).is_err());
    }

    #[test]
    fn groups_thousands() {
        assert_eq!(group(7), "7");
        assert_eq!(group(3201), "3,201");
        assert_eq!(group(1_234_567), "1,234,567");
    }

    #[test]
    fn checklist_has_every_documented_form() -> Result<()> {
        let checklist = fs::read_to_string(root().join(CHECKLIST))?;
        assert_eq!(checklist_forms(&checklist)?.len(), 4332);
        Ok(())
    }

    #[test]
    fn line_endings_preserve_checklist_parse_and_round_trip() -> Result<()> {
        let form = serde_json::json!({
            "id": "test", "instruction_id": "instruction", "mnemonic": "TEST",
            "category": "test", "source_file": "test.xml", "encoding_mask": "ffffffff",
            "encoding_value": "00000000", "features": [], "status": "unsupported", "profiles": [],
        });
        let seed = format!(
            "{{\n  \"source\": {{\"sha256\": \"immutable source bytes\"}},\n  \"assessment\": {{}},{FORMS_START}    {}\n  ]\n}}\n",
            json(&form)?
        );
        let forms = checklist_forms(&seed)?;
        let canonical = render_checklist(&seed, &forms)?;
        let mut changed_forms = forms.clone();
        changed_forms.get_mut("test").unwrap()["status"] = "implemented".into();
        let changed = render_checklist(&canonical, &changed_forms)?;
        let expected: Value = serde_json::from_str(&changed)?;
        for newline in ["\n", "\r\n"] {
            let original = canonical.replace('\n', newline);
            let parsed = checklist_forms(&original)?;
            assert_eq!(parsed, forms);
            assert_eq!(render_checklist(&original, &parsed)?, original);
            let updated = render_checklist(&original, &changed_forms)?;
            assert_eq!(updated, changed.replace('\n', newline));
            assert_eq!(serde_json::from_str::<Value>(&updated)?, expected);
            let (header, _) = split_marker(&original, ASSESSMENT_START).unwrap();
            assert!(updated.starts_with(header));
            assert_eq!(expected["source"]["sha256"], "immutable source bytes");
            assert!(!updated.replace(newline, "").contains(['\r', '\n']));
        }
        Ok(())
    }

    #[test]
    fn line_endings_preserve_readme_progress_and_surrounding_bytes() -> Result<()> {
        let forms = checklist_forms(&fs::read_to_string(root().join(CHECKLIST))?)?;
        for newline in ["\n", "\r\n"] {
            let before = format!("unchanged prefix{newline}");
            let after = format!("{newline}unchanged suffix{newline}");
            let original =
                format!("{before}{README_START}{newline}old{newline}{README_END}{after}");
            let rendered = render_readme(&original, &forms)?;
            assert!(rendered.starts_with(&before) && rendered.ends_with(&after));
            assert!(!rendered.replace(newline, "").contains(['\r', '\n']));
            assert_eq!(render_readme(&rendered, &forms)?, rendered);
        }
        Ok(())
    }
}
