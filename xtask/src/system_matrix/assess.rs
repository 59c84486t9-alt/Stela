//! Merge the status registry into the system requirement matrix and render
//! the README line. Registry entries apply in order, the last matching entry
//! winning; a row no entry matches is `open` and owned by the system engine.
use super::{MATRIX, Matrix, REGISTRY};
use crate::tools::root;
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Map, Value, to_string as json};
use std::{collections::BTreeMap, fs};

/// Best first.
pub const STATUSES: [&str; 5] = ["implemented", "partial", "refused", "paused", "open"];
const DEFAULT_OWNER: &str = "system-engine";
const HEADER_KEYS: [&str; 9] = [
    "schema_version",
    "kind",
    "version",
    "source",
    "unit",
    "applicability",
    "profile",
    "assessment",
    "registry",
];
const ROW_KEYS: [&str; 16] = [
    "id",
    "kind",
    "name",
    "register",
    "bits",
    "type",
    "encoding",
    "instances",
    "accessors",
    "condition",
    "applicability",
    "status",
    "owner",
    "tests",
    "note",
    "evidence",
];
const ROWS_START: &str = "\n  \"rows\": [\n";
const README: &str = "README.md";
const README_START: &str = "<!-- stela-system-progress:start -->";
const README_END: &str = "<!-- stela-system-progress:end -->";
const INSTRUCTION_END: &str = "<!-- stela-instruction-progress:end -->";
/// Row kinds in README order.
const KINDS: [(&str, &str); 7] = [
    ("register", "System registers"),
    ("field", "Register fields"),
    ("access", "Register and instruction accessors"),
    ("instruction", "System instructions"),
    ("exception", "Exception classes"),
    ("feature", "Profile features"),
    ("form", "System-semantic A64 forms"),
];

pub struct Entry {
    pattern: String,
    status: String,
    owner: String,
    tests: Vec<String>,
    note: Value,
}

pub fn registry() -> Result<Vec<Entry>> {
    let text = fs::read_to_string(root().join(REGISTRY))
        .with_context(|| format!("cannot read {REGISTRY}"))?;
    let value: Value = serde_json::from_str(&text)?;
    let mut entries = Vec::new();
    for entry in value["entries"]
        .as_array()
        .context("registry has no entries")?
    {
        let status = entry["status"].as_str().context("entry without status")?;
        ensure!(STATUSES.contains(&status), "unknown status {status}");
        entries.push(Entry {
            pattern: entry["rows"]
                .as_str()
                .context("entry without rows")?
                .to_owned(),
            status: status.to_owned(),
            owner: entry["owner"].as_str().unwrap_or(DEFAULT_OWNER).to_owned(),
            tests: entry["tests"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|test| test.as_str().map(str::to_owned))
                .collect(),
            note: entry["note"].clone(),
        });
    }
    Ok(entries)
}

/// `*` matches any run of characters.
fn matches(pattern: &str, text: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or("");
    let Some(mut rest) = text.strip_prefix(first) else {
        return false;
    };
    let parts: Vec<&str> = parts.collect();
    for (index, part) in parts.iter().enumerate() {
        if index + 1 == parts.len() {
            return rest.ends_with(part);
        }
        match rest.find(part) {
            Some(position) => rest = &rest[position + part.len()..],
            None => return false,
        }
    }
    rest.is_empty()
}

/// A cited test is `path#function`: the function must exist in that file.
fn check_test(test: &str) -> Result<()> {
    let (path, function) = test
        .split_once('#')
        .with_context(|| format!("test {test} is not path#function"))?;
    let source = fs::read_to_string(root().join(path))
        .with_context(|| format!("test file {path} does not exist"))?;
    ensure!(
        source.contains(&format!("fn {function}(")),
        "{path} has no test {function}"
    );
    Ok(())
}

pub fn render(matrix: &Matrix, registry: &[Entry], _previous: &str) -> Result<String> {
    let mut rows = matrix.rows.clone();
    for row in rows.values_mut() {
        row["status"] = "open".into();
        row["owner"] = DEFAULT_OWNER.into();
    }
    for entry in registry {
        for test in &entry.tests {
            check_test(test)?;
        }
        let mut matched = 0;
        for (id, row) in rows.iter_mut() {
            if !matches(&entry.pattern, id) {
                continue;
            }
            matched += 1;
            row["status"] = entry.status.clone().into();
            row["owner"] = entry.owner.clone().into();
            row["tests"] = entry.tests.clone().into();
            row["note"] = entry.note.clone();
        }
        ensure!(matched > 0, "{REGISTRY}: {} matches no row", entry.pattern);
    }
    let mut header = matrix.header.clone();
    header.insert("assessment".into(), assessment(&rows));
    header.insert(
        "registry".into(),
        format!("{REGISTRY}; entries apply in order, the last match winning").into(),
    );
    let mut text = String::from("{\n");
    for key in HEADER_KEYS {
        let value = header
            .get(key)
            .with_context(|| format!("no header {key}"))?;
        text.push_str(&format!(
            "  \"{key}\": {},\n",
            indent(&serde_json::to_string_pretty(value)?)
        ));
    }
    text.push_str(ROWS_START.trim_start_matches('\n'));
    let lines: Vec<String> = rows.values().map(row_line).collect::<Result<_>>()?;
    text.push_str(&lines.join(",\n"));
    text.push_str("\n  ]\n}\n");
    Ok(text)
}

fn indent(text: &str) -> String {
    text.replace('\n', "\n  ")
}

fn row_line(row: &Value) -> Result<String> {
    let object = row.as_object().context("row is not an object")?;
    for key in object.keys() {
        ensure!(ROW_KEYS.contains(&key.as_str()), "unknown row key {key}");
    }
    let fields: Vec<String> = ROW_KEYS
        .iter()
        .filter_map(|key| object.get(*key).map(|value| (key, value)))
        .filter(|(_, value)| !value.is_null() && *value != &Value::Array(vec![]))
        .map(|(key, value)| Ok(format!("\"{key}\":{}", json(value)?)))
        .collect::<Result<_>>()?;
    Ok(format!("    {{{}}}", fields.join(",")))
}

fn assessment(rows: &BTreeMap<String, Value>) -> Value {
    let mut kinds: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    let mut total: Map<String, Value> = Map::new();
    for row in rows.values() {
        let kind = row["kind"].as_str().unwrap_or("?").to_owned();
        let status = row["status"].as_str().unwrap_or("open").to_owned();
        for counts in [kinds.entry(kind).or_default(), &mut total] {
            let count = counts.entry(status.clone()).or_insert(0.into());
            *count = (count.as_u64().unwrap_or(0) + 1).into();
            let all = counts.entry("total".to_owned()).or_insert(0.into());
            *all = (all.as_u64().unwrap_or(0) + 1).into();
        }
    }
    let mut out = Map::new();
    out.insert("total".into(), sorted(total));
    for (kind, counts) in kinds {
        out.insert(kind, sorted(counts));
    }
    Value::Object(out)
}

fn sorted(counts: Map<String, Value>) -> Value {
    let mut out = Map::new();
    for status in STATUSES.iter().chain(&["total"]) {
        if let Some(value) = counts.get(*status) {
            out.insert((*status).to_owned(), value.clone());
        }
    }
    Value::Object(out)
}

/// Parse the committed matrix back into facts.
fn parse(text: &str) -> Result<Matrix> {
    let value: Value = serde_json::from_str(text).with_context(|| format!("invalid {MATRIX}"))?;
    let mut header = value
        .as_object()
        .context("matrix is not an object")?
        .clone();
    let rows_value = header.remove("rows").context("matrix has no rows")?;
    header.remove("assessment");
    header.remove("registry");
    let mut rows = BTreeMap::new();
    for row in rows_value.as_array().context("rows is not a list")? {
        let mut row = row.clone();
        let object = row.as_object_mut().context("row is not an object")?;
        for key in ["status", "owner", "tests", "note"] {
            object.remove(key);
        }
        let id = row["id"].as_str().context("row without id")?.to_owned();
        rows.insert(id, row);
    }
    Ok(Matrix { header, rows })
}

/// Re-merge the registry into the committed matrix and the README, or with
/// `check` fail when either is stale.
pub fn run(check: bool) -> Result<()> {
    let matrix_path = root().join(MATRIX);
    let readme_path = root().join(README);
    let matrix_text = fs::read_to_string(&matrix_path)?;
    let readme_text = fs::read_to_string(&readme_path)?;
    let matrix = parse(&matrix_text)?;
    let rendered = render(&matrix, &registry()?, &matrix_text)?;
    let readme = render_readme(&readme_text, &serde_json::from_str(&rendered)?)?;
    for (path, old, new) in [
        (&matrix_path, &matrix_text, &rendered),
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

fn render_readme(readme: &str, matrix: &Value) -> Result<String> {
    let assessment = &matrix["assessment"];
    let count = |kind: &str, status: &str| assessment[kind][status].as_u64().unwrap_or(0);
    let mut table = String::from(
        "| System platform requirement | Implemented | Open, refused or paused | Total |\n\
         | --- | --- | --- | --- |\n",
    );
    for (kind, title) in KINDS {
        let total = count(kind, "total");
        if total == 0 {
            continue;
        }
        let done = count(kind, "implemented");
        table.push_str(&format!(
            "| {title} | {done} | {} | {total} |\n",
            total - done
        ));
    }
    let total = count("total", "total");
    let done = count("total", "implemented");
    table.push_str(&format!(
        "| **All** | **{done} / {total} ({:.1}%)** | {} | {total} |\n\n\
         Rows are the AArch64 requirements of the declared Mac14,3 profile in Arm \
         AARCHMRS {}, partial rows earning no credit. [System matrix]({MATRIX})\n",
        100.0 * done as f64 / total.max(1) as f64,
        total - done,
        matrix["source"]["release"].as_str().unwrap_or("?"),
    ));
    let block = format!("{README_START}\n{table}{README_END}");
    if let Some((before, rest)) = readme.split_once(README_START) {
        let (_, after) = rest
            .split_once(README_END)
            .context("README has no system progress end marker")?;
        return Ok(format!("{before}{block}{after}"));
    }
    let (before, after) = readme
        .split_once(INSTRUCTION_END)
        .context("README has no instruction progress end marker")?;
    Ok(format!("{before}{INSTRUCTION_END}\n\n{block}{after}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs_match_whole_ids() {
        assert!(matches("access:TLBI *", "access:TLBI VAE1"));
        assert!(matches("field:HCR_EL2.*", "field:HCR_EL2.TGE"));
        assert!(matches("register:HCR_EL2", "register:HCR_EL2"));
        assert!(!matches("register:HCR_EL2", "register:HCR_EL22"));
        assert!(matches("*_EL12", "register:SCTLR_EL12"));
        assert!(!matches("*_EL12", "register:SCTLR_EL1"));
        assert!(matches("a*b*c", "a-b-c"));
    }

    #[test]
    fn matrix_and_readme_are_current() -> Result<()> {
        let text = fs::read_to_string(root().join(MATRIX))?;
        let rendered = render(&parse(&text)?, &registry()?, &text)?;
        assert!(
            rendered == text,
            "{MATRIX} is stale; run `cargo xtask progress`"
        );
        Ok(())
    }
}
