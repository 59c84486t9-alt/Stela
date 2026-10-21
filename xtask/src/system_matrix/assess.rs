//! Merge the status registry into the system requirement matrix and render
//! the README line. Registry entries apply in order, the last matching entry
//! winning on each chip it names. An entry that names no chips holds on the
//! historical M2 baseline, and on another chip for the rows the M2 shares
//! when every cited test passed there after consulting that chip (`runs`). A row no entry
//! matches on a chip is `open` there and owned by the system engine.
use super::{
    CHIPS, DEFAULT_CHIP, MATRIX, Matrix, REGISTRY, REGISTRY_BASE_CHIP,
    runs::{self, LEDGER, Runs},
    set_primary_profile,
};
use crate::tools::root;
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Map, Value, to_string as json};
use std::{collections::BTreeMap, fs};

/// Best first; `excluded` rows are not requirements of the chip.
pub const STATUSES: [&str; 6] = [
    "implemented",
    "partial",
    "refused",
    "paused",
    "open",
    "excluded",
];
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
const ROW_KEYS: [&str; 18] = [
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
    "chips",
    "applicability",
    "status",
    "statuses",
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
    /// The chips the entry's tests establish it on.
    chips: Vec<String>,
    /// Whether the entry names its chips; one that does not also holds where
    /// the per-chip runs credit its tests.
    explicit: bool,
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
            explicit: entry["chips"].is_array(),
            chips: match entry["chips"].as_array() {
                Some(chips) => chips
                    .iter()
                    .map(|chip| {
                        let chip = chip.as_str().context("chip is not a string")?;
                        ensure!(
                            CHIPS.iter().any(|known| known.name == chip),
                            "unknown chip {chip}"
                        );
                        Ok(chip.to_owned())
                    })
                    .collect::<Result<_>>()?,
                None => vec![REGISTRY_BASE_CHIP.to_owned()],
            },
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

/// The chips a row applies to: its `chips`, or every chip.
fn row_chips(row: &Value) -> Vec<String> {
    match row["chips"].as_array() {
        Some(chips) => chips
            .iter()
            .filter_map(|chip| chip.as_str().map(str::to_owned))
            .collect(),
        None => CHIPS.iter().map(|chip| chip.name.to_owned()).collect(),
    }
}

pub fn render(matrix: &Matrix, registry: &[Entry], runs: &Runs, _previous: &str) -> Result<String> {
    for entry in registry {
        for test in &entry.tests {
            check_test(test)?;
        }
    }
    // Whether an implicit entry's every test was credited on each other
    // chip.
    let credited: Vec<BTreeMap<&str, bool>> = registry
        .iter()
        .map(|entry| {
            CHIPS
                .iter()
                .map(|chip| chip.name)
                .filter(|chip| *chip != REGISTRY_BASE_CHIP && !entry.explicit)
                .map(|chip| {
                    let holds = !entry.tests.is_empty()
                        && entry.tests.iter().all(|test| runs.credits(chip, test));
                    (chip, holds)
                })
                .collect()
        })
        .collect();
    // Per row, per chip it applies to: the winning entry, if any.
    let mut winners: BTreeMap<String, BTreeMap<String, Option<&Entry>>> = matrix
        .rows
        .iter()
        .map(|(id, row)| {
            let chips = row_chips(row)
                .into_iter()
                .map(|chip| (chip, None))
                .collect();
            (id.clone(), chips)
        })
        .collect();
    for (entry, credited) in registry.iter().zip(&credited) {
        let mut matched = 0;
        for (id, chips) in winners.iter_mut() {
            if !matches(&entry.pattern, id) {
                continue;
            }
            matched += 1;
            for chip in &entry.chips {
                if let Some(winner) = chips.get_mut(chip) {
                    *winner = Some(entry);
                }
            }
            // On a row the M2 shares, an implicit entry speaks for every
            // chip, as the last match: an implemented one only where its
            // tests were credited, leaving the row open elsewhere, and any
            // other status, which claims nothing, everywhere.
            if chips.contains_key(REGISTRY_BASE_CHIP) {
                for (chip, holds) in credited {
                    if let Some(winner) = chips.get_mut(*chip) {
                        *winner = (*holds || entry.status != "implemented").then_some(entry);
                    }
                }
            }
        }
        ensure!(matched > 0, "{REGISTRY}: {} matches no row", entry.pattern);
    }
    let mut rows = matrix.rows.clone();
    for (id, row) in rows.iter_mut() {
        let chips = &winners[id];
        fn status<'a>(entry: &Option<&'a Entry>) -> &'a str {
            entry.map_or("open", |entry| entry.status.as_str())
        }
        // The row speaks for the default chip when it applies there.
        let (_, shown) = chips
            .iter()
            .find(|(chip, _)| chip.as_str() == DEFAULT_CHIP)
            .or_else(|| chips.iter().next())
            .context("row on no chip")?;
        row["status"] = status(shown).into();
        row["owner"] = shown
            .map_or(DEFAULT_OWNER, |entry| entry.owner.as_str())
            .into();
        row["tests"] = shown.map_or(Vec::new(), |entry| entry.tests.clone()).into();
        row["note"] = shown.map_or(Value::Null, |entry| entry.note.clone());
        if chips.values().any(|entry| status(entry) != status(shown)) {
            let statuses: Map<String, Value> = chips
                .iter()
                .map(|(chip, entry)| (chip.clone(), status(entry).into()))
                .collect();
            row["statuses"] = Value::Object(statuses);
        } else {
            row.as_object_mut()
                .context("row is not an object")?
                .remove("statuses");
        }
    }
    let mut header = matrix.header.clone();
    set_primary_profile(header.get_mut("profile").context("no profile header")?)?;
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

/// A row's status on `chip`, or `None` when it does not apply there.
fn status_on(row: &Value, chip: &str) -> Option<String> {
    if !row_chips(row).iter().any(|name| name == chip) {
        return None;
    }
    Some(
        row["statuses"][chip]
            .as_str()
            .or_else(|| row["status"].as_str())
            .unwrap_or("open")
            .to_owned(),
    )
}

/// Per-kind counts on the default chip, and each chip's totals.
fn assessment(rows: &BTreeMap<String, Value>) -> Value {
    let mut kinds: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    let mut total: Map<String, Value> = Map::new();
    let mut chips: Map<String, Value> = Map::new();
    for chip in &CHIPS {
        let mut counts = Map::new();
        for status in rows.values().filter_map(|row| status_on(row, chip.name)) {
            for key in [status.as_str(), "total"] {
                let count = counts.entry(key.to_owned()).or_insert(0.into());
                *count = (count.as_u64().unwrap_or(0) + 1).into();
            }
        }
        chips.insert(chip.name.to_owned(), sorted(counts));
    }
    for row in rows.values() {
        let kind = row["kind"].as_str().unwrap_or("?").to_owned();
        let Some(status) = status_on(row, DEFAULT_CHIP) else {
            continue;
        };
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
    out.insert("chips".into(), Value::Object(chips));
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
        for key in ["status", "statuses", "owner", "tests", "note"] {
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
    if !check {
        let ledger_path = root().join(runs::LEDGER);
        let ledger = runs::run()?;
        if fs::read_to_string(&ledger_path).unwrap_or_default() != ledger {
            fs::write(&ledger_path, ledger)?;
            println!("updated {}", ledger_path.display());
        }
    }
    let rendered = render(&matrix, &registry()?, &runs::read()?, &matrix_text)?;
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
    // Excluded rows are listed but are not requirements: the totals and
    // percentages leave them out.
    let mut table = String::from(
        "| System platform requirement | Implemented | Partial | Open, refused or paused | Total | Excluded |\n\
         | --- | --- | --- | --- | --- | --- |\n",
    );
    for (kind, title) in KINDS {
        let excluded = count(kind, "excluded");
        let total = count(kind, "total") - excluded;
        if total + excluded == 0 {
            continue;
        }
        let done = count(kind, "implemented");
        let partial = count(kind, "partial");
        table.push_str(&format!(
            "| {title} | {done} | {partial} | {} | {total} | {excluded} |\n",
            total - done - partial
        ));
    }
    let excluded = count("total", "excluded");
    let total = count("total", "total") - excluded;
    let done = count("total", "implemented");
    let partial = count("total", "partial");
    table.push_str(&format!(
        "| **All** | **{done} / {total} ({:.1}%)** | {partial} | {} | {total} | {excluded} |\n\n",
        100.0 * done as f64 / total.max(1) as f64,
        total - done - partial,
    ));
    table.push_str(
        "| Apple CPU profile | Implemented | Partial | Open, refused or paused | Total | Excluded |\n\
         | --- | --- | --- | --- | --- | --- |\n",
    );
    for chip in &CHIPS {
        let counts = &assessment["chips"][chip.name];
        let count = |status: &str| counts[status].as_u64().unwrap_or(0);
        let (done, partial, excluded) = (count("implemented"), count("partial"), count("excluded"));
        let total = count("total") - excluded;
        let name = chip.name.replace("apple-m", "Apple M");
        let marker = if chip.name == DEFAULT_CHIP {
            " (M1 Pro MacBookPro18,3, above)"
        } else {
            ""
        };
        table.push_str(&format!(
            "| {name}{marker} | {done} / {total} ({:.1}%) | {partial} | {} | {total} | {excluded} |\n",
            100.0 * done as f64 / total.max(1) as f64,
            total - done - partial,
        ));
    }
    table.push_str(&format!(
        "\nRows are the AArch64 requirements of each Apple CPU profile in Arm AARCHMRS \
         {}; the first table uses the M1 CPU family for M1 Pro MacBookPro18,3 (J314sAP). A row counts on a chip only \
         when its tests have run on that chip: the historical M2 registry baseline's tests rerun on every other chip \
         ([runs]({LEDGER})) and a chip's own rows need tests of their own. Partial \
         rows earn no credit. Excluded rows are outside the chip's \
         requirements: the feature their condition names is absent from its \
         identification, as each row's note gives. [System matrix]({MATRIX})\n",
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
        let rendered = render(&parse(&text)?, &registry()?, &runs::read()?, &text)?;
        assert!(
            rendered == text,
            "{MATRIX} is stale; run `cargo xtask progress`"
        );
        Ok(())
    }

    fn entry(pattern: &str, chips: &[&str], status: &str) -> Entry {
        Entry {
            pattern: pattern.into(),
            chips: chips.iter().map(|chip| String::from(*chip)).collect(),
            explicit: true,
            status: status.into(),
            owner: DEFAULT_OWNER.into(),
            tests: Vec::new(),
            note: Value::Null,
        }
    }

    /// A real engine test, for the registry's existence check.
    const TEST: &str = "crates/stela-runtime/src/machine/engine.rs#compiles_blocks_through_the_page_and_reports_unsupported_words";

    /// Runs that credit [`TEST`] on the M3 alone.
    fn m3_runs() -> Result<Runs> {
        runs::parse(
            r#"{"sources":{"sha256":"d"},"chips":{"apple-m3":{"credited":
                ["machine::engine::tests::compiles_blocks_through_the_page_and_reports_unsupported_words"]}}}"#,
            "d",
        )
    }

    #[test]
    fn primary_target_does_not_reassign_historical_registry_evidence() -> Result<()> {
        assert_ne!(DEFAULT_CHIP, REGISTRY_BASE_CHIP);
        let entries = registry()?;
        let implicit: Vec<_> = entries.iter().filter(|entry| !entry.explicit).collect();
        assert!(!implicit.is_empty());
        for entry in implicit {
            assert_eq!(entry.chips, [REGISTRY_BASE_CHIP]);
        }
        let text = fs::read_to_string(root().join(MATRIX))?;
        let mut matrix = parse(&text)?;
        matrix.rows.retain(|id, _| id == "register:HCR_EL2");
        let mut implicit = entry("register:*", &[REGISTRY_BASE_CHIP], "implemented");
        implicit.explicit = false;
        implicit.tests = vec![TEST.into()];
        // An uncredited primary family remains open even for an implicit entry.
        let uncredited: Value = serde_json::from_str(&render(
            &matrix,
            std::slice::from_ref(&implicit),
            &m3_runs()?,
            "",
        )?)?;
        assert_eq!(uncredited["rows"][0]["status"], "open");
        assert_eq!(uncredited["assessment"]["total"]["open"], 1);
        assert_eq!(uncredited["profile"]["default"], DEFAULT_CHIP);
        assert_eq!(
            uncredited["profile"]["registry_base_chip"],
            REGISTRY_BASE_CHIP
        );
        assert_eq!(
            uncredited["profile"]["primary_platform"]["variant"],
            "M1 Pro"
        );
        assert_eq!(
            uncredited["profile"]["primary_platform"]["cpu_family"],
            "apple-m1"
        );
        let m1 = runs::parse(
            r#"{"sources":{"sha256":"d"},"chips":{"apple-m1":{"credited":
                ["machine::engine::tests::compiles_blocks_through_the_page_and_reports_unsupported_words"]}}}"#,
            "d",
        )?;
        let qualified: Value = serde_json::from_str(&render(&matrix, &[implicit], &m1, "")?)?;
        assert_eq!(qualified["rows"][0]["status"], "implemented");
        assert_eq!(
            qualified["rows"][0]["statuses"][REGISTRY_BASE_CHIP],
            "implemented"
        );
        assert_eq!(qualified["rows"][0]["statuses"]["apple-m3"], "open");
        let readme = render_readme(INSTRUCTION_END, &qualified)?;
        assert!(readme.contains("M1 Pro MacBookPro18,3"));
        assert!(readme.contains("historical M2 registry baseline"));
        Ok(())
    }

    #[test]
    fn uniform_reassessment_discards_historical_per_chip_statuses() -> Result<()> {
        let text = fs::read_to_string(root().join(MATRIX))?;
        let mut matrix = parse(&text)?;
        matrix.rows.retain(|id, _| id == "register:HCR_EL2");
        let row = matrix.rows.get_mut("register:HCR_EL2").context("HCR row")?;
        row["statuses"] = serde_json::json!({"apple-m1":"implemented", "apple-m2":"partial"});
        let rendered: Value = serde_json::from_str(&render(&matrix, &[], &m3_runs()?, "")?)?;
        assert!(rendered["rows"][0]["statuses"].is_null());
        for chip in &CHIPS {
            assert_eq!(rendered["assessment"]["chips"][chip.name]["open"], 1);
        }
        Ok(())
    }

    #[test]
    fn an_entry_holds_only_on_the_chips_it_names() -> Result<()> {
        let text = fs::read_to_string(root().join(MATRIX))?;
        let mut matrix = parse(&text)?;
        matrix
            .rows
            .retain(|id, _| id == "register:HCR_EL2" || id == "register:HCRX_EL2");
        let registry = [
            entry("register:*", &[REGISTRY_BASE_CHIP], "implemented"),
            entry("register:HCR_EL2", &["apple-m1"], "partial"),
        ];
        let rendered: Value = serde_json::from_str(&render(&matrix, &registry, &m3_runs()?, "")?)?;
        let rows = rendered["rows"].as_array().context("rows")?;
        let row = |id: &str| rows.iter().find(|row| row["id"] == id).cloned().unwrap();
        // HCR_EL2 is on every chip: implemented on the M2, partial on the M1
        // and open on the chips no entry names.
        let hcr = row("register:HCR_EL2");
        assert_eq!(hcr["status"], "partial");
        assert_eq!(hcr["statuses"]["apple-m2"], "implemented");
        assert_eq!(hcr["statuses"]["apple-m1"], "partial");
        assert_eq!(hcr["statuses"]["apple-m3"], "open");
        // HCRX_EL2 needs FEAT_HCX (M3 on): the M2 entry cannot reach it.
        let hcrx = row("register:HCRX_EL2");
        assert_eq!(hcrx["status"], "open");
        assert!(hcrx["statuses"].is_null());
        let chips = &rendered["assessment"]["chips"];
        assert_eq!(chips["apple-m2"]["implemented"], 1);
        assert_eq!(chips["apple-m3"]["open"], 2);
        Ok(())
    }

    #[test]
    fn an_implicit_entry_holds_where_its_tests_were_credited_on_shared_rows() -> Result<()> {
        let text = fs::read_to_string(root().join(MATRIX))?;
        let mut matrix = parse(&text)?;
        matrix
            .rows
            .retain(|id, _| id == "register:HCR_EL2" || id == "register:HCRX_EL2");
        let mut implicit = entry("register:*", &[REGISTRY_BASE_CHIP], "implemented");
        implicit.explicit = false;
        implicit.tests = vec![TEST.into()];
        let rendered: Value =
            serde_json::from_str(&render(&matrix, &[implicit], &m3_runs()?, "")?)?;
        let rows = rendered["rows"].as_array().context("rows")?;
        let row = |id: &str| rows.iter().find(|row| row["id"] == id).cloned().unwrap();
        // The M3 run credited the test: HCR_EL2 holds there too, and not on
        // the uncredited M4.
        let hcr = row("register:HCR_EL2");
        assert_eq!(hcr["statuses"]["apple-m3"], "implemented");
        assert_eq!(hcr["statuses"]["apple-m4"], "open");
        // HCRX_EL2 is not an M2 row, so the M2's tests do not reach it.
        let hcrx = row("register:HCRX_EL2");
        assert_eq!(hcrx["status"], "open");
        assert!(hcrx["statuses"].is_null(), "open on every chip");
        Ok(())
    }

    #[test]
    fn a_later_implicit_entry_overrides_earlier_ones_on_every_chip() -> Result<()> {
        let text = fs::read_to_string(root().join(MATRIX))?;
        let mut matrix = parse(&text)?;
        matrix.rows.retain(|id, _| id == "register:HCR_EL2");
        let mut implemented = entry("register:*", &[REGISTRY_BASE_CHIP], "implemented");
        implemented.explicit = false;
        implemented.tests = vec![TEST.into()];
        let mut refused = entry("register:HCR_EL2", &[REGISTRY_BASE_CHIP], "refused");
        refused.explicit = false;
        let render = |registry: &[Entry]| -> Result<Value> {
            Ok(serde_json::from_str(&render(
                &matrix,
                registry,
                &m3_runs()?,
                "",
            )?)?)
        };
        // A refusal for the M2 holds on every chip, though an earlier entry
        // was credited on the M3.
        let mut first = entry("register:*", &[REGISTRY_BASE_CHIP], "implemented");
        first.explicit = false;
        first.tests = vec![TEST.into()];
        let rendered = render(&[first, refused])?;
        assert_eq!(rendered["rows"][0]["status"], "refused");
        assert!(rendered["rows"][0]["statuses"].is_null());
        // An uncredited implemented entry leaves the row open on the M3
        // instead of falling back to an earlier credited one.
        let mut later = entry("register:HCR_EL2", &[REGISTRY_BASE_CHIP], "implemented");
        later.explicit = false;
        later.tests = vec!["crates/stela-runtime/src/machine/engine.rs#illegal_returns_set_il_and_the_next_instruction_takes_ec_0x0e".into()];
        let rendered = render(&[implemented, later])?;
        assert_eq!(rendered["rows"][0]["statuses"]["apple-m3"], "open");
        Ok(())
    }
}
