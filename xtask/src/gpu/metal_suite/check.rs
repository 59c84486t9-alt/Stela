//! Holding a run to the plan's expectations, or to a reference run.
//!
//! Each output is compared element by element within its tolerance: floats
//! by ulps on the line of representable values, an absolute or a relative
//! error, subnormals flushed unless the output says otherwise; integers by
//! their difference. An expectation can name alternatives where Metal
//! allows several results. Informational cases report differences without
//! failing, and the cases that ran much slower than the reference are
//! listed, since the suite is for a driver that is fast as well as correct.
use super::plan::{self, Tolerance};
use super::values::{Dtype, elements, f16_bits, int_elements};
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
    fs,
    path::Path,
};

/// An output's elements: floats with their width, or integers.
#[derive(Clone, Debug, PartialEq)]
enum Elements {
    Float(Vec<f64>, u32),
    Int(Vec<i128>),
}

impl Elements {
    fn of(dtype: Dtype, data: &[u8]) -> Self {
        match dtype.float_bits() {
            Some(bits) => Self::Float(elements(dtype, data), bits),
            None => Self::Int(int_elements(dtype, data)),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Float(v, _) => v.len(),
            Self::Int(v) => v.len(),
        }
    }

    fn sorted(mut self) -> Self {
        match &mut self {
            Self::Float(v, _) => {
                v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            }
            Self::Int(v) => v.sort(),
        }
        self
    }

    /// The property an output's `derive` names, element by element:
    /// `nonzero` (1 where an element is not zero) or `ordered` (1 where it
    /// is not zero and not below the element before it), for results whose
    /// values Metal leaves open but whose relations it fixes.
    fn derive(self, kind: &str) -> Result<Self> {
        fn property<T: PartialOrd + Default>(v: &[T], kind: &str) -> Result<Vec<i128>> {
            let zero = T::default();
            Ok(match kind {
                "nonzero" => v.iter().map(|x| i128::from(*x != zero)).collect(),
                "ordered" => (0..v.len())
                    .map(|i| i128::from(v[i] != zero && (i == 0 || v[i] >= v[i - 1])))
                    .collect(),
                other => bail!("unknown derived property {other}"),
            })
        }
        Ok(Self::Int(match &self {
            Self::Int(v) => property(v, kind)?,
            Self::Float(v, _) => property(v, kind)?,
        }))
    }

    fn show(&self, i: usize) -> String {
        match self {
            Self::Float(v, _) => format!("{:?}", v[i]),
            Self::Int(v) => v[i].to_string(),
        }
    }
}

/// A float's position on the line of representable values.
fn ordered(value: f64, bits: u32) -> i64 {
    let i = if bits == 32 {
        i64::from((value as f32).to_bits())
    } else {
        i64::from(f16_bits(value))
    };
    let sign = 1i64 << (bits - 1);
    if i & sign != 0 {
        sign - (i & (sign - 1))
    } else {
        sign + i
    }
}

fn flush(value: f64, bits: u32) -> f64 {
    let smallest = if bits == 32 {
        2f64.powi(-126)
    } else {
        2f64.powi(-14)
    };
    // Tininess may be detected before rounding, so a result that rounds up
    // to the smallest normal may be flushed too.
    if value.abs() <= smallest {
        0.0f64.copysign(value)
    } else {
        value
    }
}

/// Whether `test` is within `tol` of `reference`, and its error in ulps.
fn float_match(reference: f64, test: f64, bits: u32, tol: &Tolerance) -> (bool, f64) {
    if reference.is_nan() || test.is_nan() {
        let both = reference.is_nan() && test.is_nan();
        return (
            both || tol.nan_ignore,
            if both { 0.0 } else { f64::INFINITY },
        );
    }
    let (reference, test) = if tol.ftz.unwrap_or(true) {
        (flush(reference, bits), flush(test, bits))
    } else {
        (reference, test)
    };
    if reference == test {
        let same = !tol.signed_zero.unwrap_or(false)
            || reference.is_sign_negative() == test.is_sign_negative();
        return (same, if same { 0.0 } else { 1.0 });
    }
    if reference.is_infinite() || test.is_infinite() {
        return (false, f64::INFINITY);
    }
    let ulps = (ordered(reference, bits) - ordered(test, bits)).unsigned_abs() as f64;
    let error = (reference - test).abs();
    let ok = ulps <= tol.ulp.unwrap_or(0.0)
        || error <= tol.abs.unwrap_or(0.0)
        || error <= tol.rel.unwrap_or(0.0) * reference.abs();
    (ok, ulps)
}

/// What an output's comparison found.
#[derive(Debug, Default)]
struct Outcome {
    error: Option<String>,
    elements: usize,
    mismatches: Vec<(usize, String, String)>,
    count: usize,
    max_ulps: Option<f64>,
}

/// Compares `test` against `expected` and any alternatives, element by
/// element where `mask` (cycling, `stride` elements per entry) selects.
fn compare(
    expected: &Elements,
    alternatives: &[Elements],
    test: &Elements,
    tol: &Tolerance,
    mask: Option<&[u8]>,
    stride: usize,
) -> Outcome {
    let mut out = Outcome {
        elements: expected.len(),
        ..Outcome::default()
    };
    if expected.len() != test.len() {
        out.error = Some(format!(
            "{} elements, expected {}",
            test.len(),
            expected.len()
        ));
        return out;
    }
    let mut worst = 0.0f64;
    for i in 0..expected.len() {
        if let Some(mask) = mask.filter(|m| !m.is_empty())
            && mask[(i / stride) % mask.len()] == 0
        {
            continue;
        }
        let ok = std::iter::once(expected)
            .chain(alternatives)
            .any(|e| match (e, test) {
                (Elements::Float(r, bits), Elements::Float(t, _)) => {
                    let (ok, ulps) = float_match(r[i], t[i], *bits, tol);
                    if std::ptr::eq(e, expected) {
                        worst = worst.max(ulps);
                    }
                    ok
                }
                (Elements::Int(r), Elements::Int(t)) => {
                    (r[i] - t[i]).unsigned_abs() as f64 <= tol.units.unwrap_or(0.0)
                }
                _ => false,
            });
        if !ok {
            out.count += 1;
            if out.mismatches.len() < 12 {
                out.mismatches.push((i, expected.show(i), test.show(i)));
            }
        }
    }
    if matches!(expected, Elements::Float(..)) {
        out.max_ulps = Some(worst);
    }
    out
}

/// Values of the runner's lookup tables, or whole tables (`*`), that no
/// case can use on the reference device, with the reason.
const LOOKUPS_LEFT_OUT: [(&str, &str, &str); 8] = [
    (
        "cull mode",
        "*",
        "indirect command buffer draw state needs Apple10",
    ),
    (
        "depth clip mode",
        "*",
        "indirect command buffer draw state needs Apple10",
    ),
    (
        "fill mode",
        "*",
        "indirect command buffer draw state needs Apple10",
    ),
    (
        "winding",
        "*",
        "indirect command buffer draw state needs Apple10",
    ),
    (
        "reduction mode",
        "*",
        "sampler min-max reduction needs Apple10",
    ),
    (
        "forward progress",
        "simdgroup_parallel",
        "forward progress guarantees need Apple11",
    ),
    (
        "pixel format",
        "depth24unorm_stencil8",
        "the M1 Pro has no depth24Unorm_stencil8",
    ),
    (
        "pixel format",
        "x24_stencil8",
        "the M1 Pro has no depth24Unorm_stencil8",
    ),
];

/// The table labels the runner's `lookup` calls name: each call's second
/// argument, after a first that may be a dictionary literal.
fn lookup_labels(runner: &str) -> BTreeSet<String> {
    runner
        .match_indices("lookup(")
        .filter(|(at, _)| !runner[..*at].ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_'))
        .filter_map(|(at, call)| {
            let mut depth = 0usize;
            let mut quoted = false;
            let rest = &runner[at + call.len()..];
            let comma = rest.char_indices().find_map(|(i, c)| {
                match c {
                    '"' => quoted = !quoted,
                    _ if quoted => {}
                    '(' | '[' | '{' => depth += 1,
                    ')' | ']' | '}' if depth == 0 => return Some(None),
                    ')' | ']' | '}' => depth -= 1,
                    ',' if depth == 0 => return Some(Some(i)),
                    _ => {}
                }
                None
            })??;
            let label = rest[comma + 1..].trim_start().strip_prefix("@\"")?;
            Some(label[..label.find('"')?].to_string())
        })
        .collect()
}

/// The named values of the runner's tables that no case of a complete
/// reference run looked up, and the tables no case reached; None when the
/// run is not complete.
fn unused_lookups(plan: &Value, test: &Path) -> Result<Option<Vec<String>>> {
    let mut used: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for case in plan["cases"].as_array().unwrap() {
        let s = status(&test.join(plan::name_of(case)));
        if status_name(&s) == "not run" || status_name(&s) == "running" {
            return Ok(None);
        }
        for (label, values) in s["lookups"].as_object().into_iter().flatten() {
            let values = values
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str);
            used.entry(label.clone())
                .or_default()
                .extend(values.map(str::to_string));
        }
    }
    let path = test.join("lookups.json");
    let tables: BTreeMap<String, BTreeSet<String>> = serde_json::from_str(
        &fs::read_to_string(&path).with_context(|| path.display().to_string())?,
    )?;
    let runner = fs::read_to_string(super::assets().join("runner.m"))?;
    let left_out: BTreeSet<(&str, &str)> =
        LOOKUPS_LEFT_OUT.iter().map(|(t, v, _)| (*t, *v)).collect();
    let mut lines: Vec<String> = lookup_labels(&runner)
        .into_iter()
        .filter(|label| !tables.contains_key(label) && !left_out.contains(&(label.as_str(), "*")))
        .map(|label| format!("UNUSED    {label}: no case looks up this table"))
        .collect();
    // An entry left out that a case now reaches is stale.
    for (table, value) in &left_out {
        let reached = if *value == "*" {
            tables.contains_key(*table)
        } else {
            used.get(*table).is_some_and(|seen| seen.contains(*value))
        };
        if reached {
            lines.push(format!(
                "STALE     {table}: {value} is left out but a case reaches it"
            ));
        }
    }
    for (label, values) in &tables {
        let none = BTreeSet::new();
        let seen = used.get(label).unwrap_or(&none);
        let unused: Vec<&str> = values
            .iter()
            .filter(|v| !seen.contains(*v) && !left_out.contains(&(label.as_str(), v.as_str())))
            .map(String::as_str)
            .collect();
        if !unused.is_empty() {
            lines.push(format!("UNUSED    {label}: {}", unused.join(", ")));
        }
    }
    Ok(Some(lines))
}

/// Whether a results directory holds the reference device's results.
fn is_reference(results: &Path) -> bool {
    results.file_name().is_some_and(|n| n == "mac")
}

fn status(dir: &Path) -> Value {
    fs::read_to_string(dir.join("status.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_else(|| serde_json::json!({"status": "not run"}))
}

fn status_name(s: &Value) -> &str {
    s["status"].as_str().unwrap_or("not run")
}

/// The capability answers in which two devices differ.
fn device_differences(reference: Option<&Path>, test: &Path, name: &str) -> Result<Vec<String>> {
    let Some(reference) = reference else {
        return Ok(vec![]);
    };
    let flat = |root: &Path| -> Result<BTreeMap<String, Value>> {
        let path = root.join(name).join("properties.json");
        let data: Value = serde_json::from_str(
            &fs::read_to_string(&path).with_context(|| path.display().to_string())?,
        )?;
        let mut out = BTreeMap::new();
        for (group, values) in data.as_object().into_iter().flatten() {
            for (key, value) in values.as_object().into_iter().flatten() {
                out.insert(format!("{group}.{key}"), value.clone());
            }
        }
        Ok(out)
    };
    let (a, b) = (flat(reference)?, flat(test)?);
    let keys: std::collections::BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    Ok(keys
        .into_iter()
        .filter(|k| a.get(*k) != b.get(*k))
        .map(|k| format!("{k}: reference {}, test {}", show(a.get(k)), show(b.get(k))))
        .collect())
}

/// The answers of the tested device that break the driver's policy: each
/// `group.key` the policy names must have the value it gives. The policy
/// is the driver's, not Metal's, so it binds only the device compared
/// against a reference.
fn policy_breaches(policy: &Value, test: &Path, name: &str) -> Result<Vec<String>> {
    let path = test.join(name).join("properties.json");
    let data: Value = serde_json::from_str(
        &fs::read_to_string(&path).with_context(|| path.display().to_string())?,
    )?;
    Ok(policy
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(key, want)| {
            let (group, field) = key.split_once('.')?;
            let got = data.get(group).and_then(|g| g.get(field));
            (got != Some(want)).then(|| format!("{key}: policy {want}, device {}", show(got)))
        })
        .collect())
}

fn show(v: Option<&Value>) -> String {
    v.map_or_else(|| "none".into(), Value::to_string)
}

fn mask_of(v: &Value) -> Option<Vec<u8>> {
    v.as_array().map(|a| {
        a.iter()
            .map(|x| u8::from(x.as_u64().unwrap_or(0) != 0 || x.as_bool() == Some(true)))
            .collect()
    })
}

/// The counts a run's check sums to, in all and per area: the case
/// name's first segment (math, render, sequence...).
#[derive(Default)]
struct Summary {
    counts: BTreeMap<&'static str, usize>,
    areas: BTreeMap<String, BTreeMap<&'static str, usize>>,
    area: String,
    /// Each mismatched case's share of differing elements, and its line.
    worst: Vec<(f64, String)>,
    /// How many failed cases each error message stopped.
    errors: BTreeMap<String, usize>,
}

impl Summary {
    fn add(&mut self, key: &'static str) {
        *self.counts.entry(key).or_default() += 1;
        *self
            .areas
            .entry(self.area.clone())
            .or_default()
            .entry(key)
            .or_default() += 1;
    }

    /// The table of counts per area, the worst mismatches and the most
    /// common failures: a few lines to relay.
    fn brief(&self) -> Vec<String> {
        let columns = ["match", "mismatch", "test failed", "unsupported"];
        let mut lines = vec![format!(
            "{:<12}{:>8}{:>9}{:>8}{:>12}{:>7}",
            "area", "pass", "mismatch", "failed", "unsupported", "other"
        )];
        for (area, counts) in &self.areas {
            let get = |k: &str| counts.get(k).copied().unwrap_or(0);
            let other: usize = counts
                .iter()
                .filter(|(k, _)| !columns.contains(k))
                .map(|(_, n)| n)
                .sum();
            lines.push(format!(
                "{area:<12}{:>8}{:>9}{:>8}{:>12}{other:>7}",
                get("match"),
                get("mismatch"),
                get("test failed"),
                get("unsupported")
            ));
        }
        let mut worst = self.worst.clone();
        worst.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
        lines.extend(worst.iter().take(5).map(|(_, l)| format!("worst: {l}")));
        let mut errors: Vec<_> = self.errors.iter().collect();
        errors.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        lines.extend(
            errors
                .iter()
                .take(3)
                .map(|(e, n)| format!("failed: {n} x {e}")),
        );
        lines
    }

    fn get(&self, key: &str) -> usize {
        self.counts.get(key).copied().unwrap_or(0)
    }
}

const KEYS: [&str; 7] = [
    "match",
    "mismatch",
    "test failed",
    "reference failed",
    "informational",
    "unchecked",
    "unsupported",
];

/// Checks the run in `test` against `reference`, or with no reference
/// against the expectations the plan states, and fails on any mismatch or
/// failed case.
pub fn run(
    out: &Path,
    reference: Option<&Path>,
    test: &Path,
    only: &[String],
    report: Option<&Path>,
) -> Result<()> {
    let plan_dir = out.join("plan");
    let plan = plan::load(&plan_dir)?;
    let mut lines: Vec<String> = vec![];
    let mut summary = Summary::default();
    let mut timings: Vec<(f64, f64, String)> = vec![];
    for case in plan["cases"].as_array().unwrap() {
        let name = plan::name_of(case);
        if !plan::selects(only, name) {
            continue;
        }
        summary.area = name.split('.').next().unwrap_or(name).to_string();
        let test_status = status(&test.join(name));
        let ref_status = reference.map_or_else(
            || serde_json::json!({"status": "ok"}),
            |r| status(&r.join(name)),
        );
        let error = |s: &Value| s["error"].as_str().unwrap_or_default().to_string();
        if status_name(&test_status) != "ok" && case["expect_error"].as_bool() == Some(true) {
            summary.add("match");
            continue;
        }
        if status_name(&test_status) == "unsupported" {
            summary.add("unsupported");
            lines.push(format!("UNSUPPORTED {name}: {}", error(&test_status)));
            continue;
        }
        // A case the reference device diverges on is held to its
        // expectation, not to that device's results.
        let reference_root = if status_name(&ref_status) == "unsupported"
            || case["reference_divergence"].is_string()
        {
            None
        } else {
            reference
        };
        if case["kind"] == "device" && reference.is_some() && case["policy"].is_object() {
            let broken = policy_breaches(&case["policy"], test, name)?;
            summary.add(if broken.is_empty() {
                "match"
            } else {
                "mismatch"
            });
            lines.extend(broken.iter().map(|d| format!("MISMATCH  {name}: {d}")));
            continue;
        }
        // The policy holds the device under test, which only a comparison
        // with the reference names: one run alone may be the Mac's.
        if case["kind"] == "device" && case["policy"].is_object() {
            summary.add("unchecked");
            lines.push(format!(
                "UNCHECKED {name}: its policy needs a reference run"
            ));
            continue;
        }
        if case["kind"] == "device" {
            let differences = device_differences(reference_root, test, name)?;
            summary.add(if differences.is_empty() {
                "match"
            } else {
                "informational"
            });
            lines.extend(differences.iter().map(|d| format!("DEVICE    {name}: {d}")));
            continue;
        }
        if reference_root.is_some() && status_name(&ref_status) != "ok" {
            summary.add("reference failed");
            lines.push(format!(
                "REFERENCE {name}: {} {}",
                status_name(&ref_status),
                error(&ref_status)
            ));
            continue;
        }
        if status_name(&test_status) != "ok" {
            summary.add("test failed");
            let message: String = format!("{} {}", status_name(&test_status), error(&test_status))
                .chars()
                .take(100)
                .collect();
            *summary.errors.entry(message).or_default() += 1;
            lines.push(format!(
                "FAILED    {name}: {} {}",
                status_name(&test_status),
                error(&test_status)
            ));
            continue;
        }
        if let (Some(r), Some(t)) = (
            ref_status["gpu_ms"].as_f64(),
            test_status["gpu_ms"].as_f64(),
        ) {
            timings.push((r, t, name.to_string()));
        }
        let outputs = case["outputs"].as_array().cloned().unwrap_or_default();
        let by_name: BTreeMap<&str, &Value> = outputs
            .iter()
            .map(|o| (o["name"].as_str().unwrap_or_default(), o))
            .collect();
        let actual = |root: &Path, output: &Value| -> Result<Elements> {
            let read = |o: &Value| -> Result<Vec<u8>> {
                let file = o["as"].as_str().or(o["name"].as_str()).unwrap_or_default();
                let path = root.join(name).join(format!("{file}.bin"));
                fs::read(&path).with_context(|| path.display().to_string())
            };
            let mut data = read(output)?;
            if let Some(next) = output["append"].as_str() {
                data.extend(read(by_name.get(next).context("appended output")?)?);
            }
            let dtype = dtype_of(output)?;
            let mut e = Elements::of(dtype, &data);
            if output["sorted_compare"].as_bool() == Some(true) {
                e = e.sorted();
            }
            match output["derive"].as_str() {
                Some(kind) => e.derive(kind),
                None => Ok(e),
            }
        };
        let mut problems = vec![];
        let mut checked = 0;
        for output in &outputs {
            if output["compare"] == false {
                continue;
            }
            let dtype = dtype_of(output)?;
            let stride = output["stride"].as_u64().unwrap_or(1).max(1) as usize;
            let (expected, alternatives, tol, mask) = if let Some(root) = reference_root {
                (
                    actual(root, output)?,
                    vec![],
                    Tolerance::from_json(output.get("tolerance")),
                    mask_of(&output["mask"]),
                )
            } else if let Some(file) = output["expect"].as_str() {
                let read = |f: &str| -> Result<Elements> {
                    let data = fs::read(plan_dir.join(f)).with_context(|| f.to_string())?;
                    // A derived output's expectation is the property itself.
                    let dtype = if output["derive"].is_null() {
                        dtype
                    } else {
                        Dtype::U32
                    };
                    let e = Elements::of(dtype, &data);
                    Ok(if output["sorted_compare"].as_bool() == Some(true) {
                        e.sorted()
                    } else {
                        e
                    })
                };
                let alternatives = output["expect_alternatives"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(read)
                    .collect::<Result<Vec<_>>>()?;
                let tol = output.get("expect_tolerance").or(output.get("tolerance"));
                let mask = if output["expect_mask"].is_null() {
                    &output["mask"]
                } else {
                    &output["expect_mask"]
                };
                (
                    read(file)?,
                    alternatives,
                    Tolerance::from_json(tol),
                    mask_of(mask),
                )
            } else {
                continue;
            };
            checked += 1;
            let result = compare(
                &expected,
                &alternatives,
                &actual(test, output)?,
                &tol,
                mask.as_deref(),
                stride,
            );
            if result.error.is_some() || result.count > 0 {
                problems.push((
                    output["name"].as_str().unwrap_or_default().to_string(),
                    result,
                ));
            }
        }
        if checked == 0 {
            summary.add("unchecked");
            continue;
        }
        if problems.is_empty() {
            summary.add("match");
            continue;
        }
        // A divergence the reference device is known for counts against
        // that device only as information; every other device is held to
        // the specification.
        let divergence =
            case["reference_divergence"].is_string() && reference.is_none() && is_reference(test);
        let informational = case["informational"].as_bool() == Some(true) || divergence;
        summary.add(if informational {
            "informational"
        } else {
            "mismatch"
        });
        let note = case["note"]
            .as_str()
            .or(case["reference_divergence"].as_str().filter(|_| divergence))
            .map(|n| format!(" ({n})"))
            .unwrap_or_default();
        lines.push(format!(
            "{} {name}{note}",
            if informational {
                "DIFFERS  "
            } else {
                "MISMATCH "
            }
        ));
        if !informational {
            let (share, detail) = problems
                .iter()
                .map(|(output, r)| match &r.error {
                    Some(e) => (1.0, format!("{output}: {e}")),
                    None => (
                        r.count as f64 / r.elements.max(1) as f64,
                        format!(
                            "{output} {} of {} differ{}",
                            r.count,
                            r.elements,
                            r.max_ulps
                                .map(|u| format!(", max {u} ulps"))
                                .unwrap_or_default()
                        ),
                    ),
                })
                .max_by(|a, b| a.0.total_cmp(&b.0))
                .unwrap();
            summary.worst.push((share, format!("{name} ({detail})")));
        }
        for (output, result) in problems {
            if let Some(e) = result.error {
                lines.push(format!("    {output}: {e}"));
                continue;
            }
            let ulps = result
                .max_ulps
                .map(|u| format!(", max {u} ulps"))
                .unwrap_or_default();
            lines.push(format!(
                "    {output}: {} of {} differ{ulps}",
                result.count, result.elements
            ));
            for (i, r, t) in result.mismatches {
                lines.push(format!("      [{i}] expected {r} test {t}"));
            }
        }
    }
    lines.extend(slow(&timings));
    // A complete reference run must use every value the runner can name.
    let mut unused = 0;
    if only.is_empty() && is_reference(test) {
        match unused_lookups(&plan, test)? {
            Some(found) => {
                unused = found.len();
                lines.extend(found);
            }
            None => lines.push("lookup coverage needs a complete run".into()),
        }
    }
    lines.extend(summary.brief());
    lines.push(
        KEYS.iter()
            .map(|k| format!("{} {k}", summary.get(k)))
            .collect::<Vec<_>>()
            .join(", "),
    );
    let mut text = String::new();
    for line in &lines {
        writeln!(text, "{line}")?;
    }
    print!("{text}");
    if let Some(path) = report {
        fs::write(path, &text)?;
    }
    if summary.get("mismatch") > 0 || summary.get("test failed") > 0 || unused > 0 {
        bail!(
            "{} mismatched, {} failed, {unused} lookup table problems",
            summary.get("mismatch"),
            summary.get("test failed")
        );
    }
    Ok(())
}

fn dtype_of(output: &Value) -> Result<Dtype> {
    let name = output["dtype"].as_str().unwrap_or("u8");
    Dtype::parse(name).with_context(|| format!("dtype {name}"))
}

/// The cases a run took more than twice the reference's GPU time for, of
/// at least a millisecond: performance to fix, never a failure.
fn slow(timings: &[(f64, f64, String)]) -> Vec<String> {
    let mut slow: Vec<_> = timings
        .iter()
        .filter(|(r, t, _)| *t >= 1.0 && *t > 2.0 * r.max(0.01))
        .collect();
    slow.sort_by(|a, b| (b.1 / b.0.max(0.01)).total_cmp(&(a.1 / a.0.max(0.01))));
    let total = |f: fn(&(f64, f64, String)) -> f64| timings.iter().map(f).sum::<f64>();
    let mut lines: Vec<String> = slow
        .iter()
        .take(25)
        .map(|(r, t, name)| {
            format!(
                "SLOWER    {name}: {t:.3} ms, reference {r:.3} ms ({:.1}x)",
                t / r.max(0.01)
            )
        })
        .collect();
    if !timings.is_empty() {
        lines.push(format!(
            "GPU time  {:.1} ms, reference {:.1} ms over {} cases; {} more than twice as slow",
            total(|t| t.1),
            total(|t| t.0),
            timings.len(),
            slow.len()
        ));
    }
    lines
}

#[cfg(test)]
mod lookup_tests {
    use super::*;

    #[test]
    fn lookup_labels_reads_each_call() {
        let runner = "static NSUInteger lookup(NSDictionary *table, NSString *kind, id name)\n\
                      x = lookup(modes, @\"math mode\", w[@\"m\"]);\n\
                      y = lookup(compare_functions(), @\"compare function\", a);\n";
        let labels: Vec<String> = lookup_labels(runner).into_iter().collect();
        assert_eq!(labels, ["compare function", "math mode"]);
    }

    /// Labels are how a run's record names its tables, so each must name
    /// one table.
    #[test]
    fn runner_labels_are_distinct_tables() {
        let runner = fs::read_to_string(super::super::assets().join("runner.m")).unwrap();
        let labels = lookup_labels(&runner);
        assert!(labels.len() > 25, "{labels:?}");
        let inline = lookup_labels(
            "lookup(@{@\"reset\" : @(0), @\"add\" : @(f(1, 2))}, @\"visibility type\", x); my_lookup(t, @\"no\", y);",
        );
        assert_eq!(inline, BTreeSet::from(["visibility type".to_string()]));
        assert!(
            labels.iter().all(|l| !l.is_empty() && !l.contains('%')),
            "{labels:?}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats_compare_by_ulps_and_bounds() {
        let one = Tolerance::ulp(1.0);
        assert!(float_match(1.0, f64::from(1.0f32 + f32::EPSILON), 32, &one).0);
        assert!(!float_match(1.0, f64::from(1.0f32 + 2.0 * f32::EPSILON), 32, &one).0);
        assert!(float_match(1.0, 1.004, 32, &Tolerance::abs(0.005)).0);
        assert!(float_match(0.0, -0.0, 32, &Tolerance::exact()).0);
        assert!(!float_match(0.0, -0.0, 32, &Tolerance::exact().with_signed_zero(true)).0);
        // Subnormals flush unless the output keeps them.
        assert!(float_match(1e-40, 0.0, 32, &Tolerance::exact()).0);
        assert!(!float_match(1e-40, 0.0, 32, &Tolerance::exact().with_ftz(false)).0);
        assert!(float_match(f64::NAN, f64::NAN, 16, &Tolerance::exact()).0);
        assert!(!float_match(f64::NAN, 1.0, 16, &Tolerance::exact()).0);
        // Across zero, ulps count both sides.
        assert_eq!(
            ordered(f64::from(f32::from_bits(1)), 32) - ordered(-f64::from(f32::from_bits(1)), 32),
            2
        );
    }

    #[test]
    fn alternatives_and_masks_select_elements() {
        let e = Elements::Int(vec![1, 2, 3, 4]);
        let alt = Elements::Int(vec![9, 9, 9, 9]);
        let t = Elements::Int(vec![1, 9, 0, 4]);
        let tol = Tolerance::exact();
        assert_eq!(
            compare(&e, std::slice::from_ref(&alt), &t, &tol, None, 1).count,
            1
        );
        assert_eq!(
            compare(&e, &[alt], &t, &tol, Some(&[1, 1, 0, 1]), 1).count,
            0
        );
        assert_eq!(compare(&e, &[], &t, &tol, Some(&[0, 1]), 2).count, 1);
        assert!(
            compare(&e, &[], &Elements::Int(vec![1]), &tol, None, 1)
                .error
                .is_some()
        );
    }

    #[test]
    fn derived_properties_replace_open_values() {
        let t = Elements::Int(vec![5, 0, 7, 6, 9]);
        assert_eq!(
            t.clone().derive("nonzero").unwrap(),
            Elements::Int(vec![1, 0, 1, 1, 1])
        );
        assert_eq!(
            t.derive("ordered").unwrap(),
            Elements::Int(vec![1, 0, 1, 0, 1])
        );
        assert!(Elements::Int(vec![]).derive("other").is_err());
    }

    #[test]
    fn slow_cases_are_reported_not_failed() {
        let lines = slow(&[
            (1.0, 5.0, "a".into()),
            (1.0, 1.5, "b".into()),
            (0.0, 0.5, "c".into()),
        ]);
        assert!(lines[0].starts_with("SLOWER    a"));
        assert_eq!(lines.len(), 2);
    }
}
