//! Immutable trials and explicit native-efficiency accounting.
use super::{PROGRAMS, Program, Variant, median};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

pub(super) fn unix_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

pub(super) fn write_new(path: &Path, value: &Value) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create immutable evidence {}", path.display()))?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.write_all(b"\n")?;
    Ok(())
}

pub(super) fn unique_names(names: &[String], allowed: &[&str]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for name in names {
        ensure!(
            allowed.contains(&name.as_str()),
            "unknown benchmark selection {name}"
        );
        ensure!(seen.insert(name), "duplicate benchmark selection {name}");
    }
    Ok(())
}

type Kernel = (String, f64, String, String);
pub(super) fn parse(output: &str, expected: &[&str]) -> Result<Vec<Kernel>> {
    let mut seen = BTreeSet::new();
    let mut kernels = Vec::new();
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("stela-bench") {
            continue;
        }
        let kernel = fields.next().context("kernel name")?;
        ensure!(
            expected.contains(&kernel),
            "unexpected benchmark kernel {kernel}"
        );
        ensure!(seen.insert(kernel), "duplicate benchmark kernel {kernel}");
        let time: f64 = fields.next().context("seconds")?.parse()?;
        ensure!(
            time.is_finite() && time > 0.0,
            "invalid benchmark time for {kernel}: {time}"
        );
        let checksum = fields.next().context("checksum")?;
        ensure!(
            checksum.len() == 16 && checksum.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "invalid checksum for {kernel}"
        );
        kernels.push((
            kernel.to_owned(),
            time,
            checksum.to_owned(),
            fields.collect::<Vec<_>>().join(" "),
        ));
    }
    ensure!(
        seen.len() == expected.len(),
        "missing benchmark kernel: expected {expected:?}, observed {seen:?}"
    );
    Ok(kernels)
}

fn geomean(values: impl IntoIterator<Item = f64>) -> f64 {
    let values: Vec<_> = values.into_iter().collect();
    (values.iter().map(|value| value.ln()).sum::<f64>() / values.len() as f64).exp()
}

/// Pair each round's identical work, then weight programs equally. Missing
/// cases cannot reach this function through the validating run loop. A pilot
/// or subset has no suite headline; it retains its individual case evidence.
pub(super) fn score(
    programs: &[&Program],
    variants: &[Variant],
    seconds: &BTreeMap<(&str, String), Vec<f64>>,
    walls: &BTreeMap<(&str, String), Vec<f64>>,
    rounds: usize,
) -> Value {
    let complete = programs.len() == PROGRAMS.len();
    let mut scores = serde_json::Map::new();
    for variant in &variants[1..] {
        let mut program_scores = serde_json::Map::new();
        let mut efficiencies = Vec::new();
        let mut wall_efficiencies = Vec::new();
        for program in programs {
            let kernels: Vec<_> = program
                .kernels
                .iter()
                .map(|kernel| {
                    let native = &seconds[&(*kernel, "native".to_owned())];
                    let translated = &seconds[&(*kernel, variant.label.clone())];
                    median(
                        native
                            .iter()
                            .zip(translated)
                            .map(|(n, t)| 100.0 * n / t)
                            .collect(),
                    )
                })
                .collect();
            let percent = geomean(kernels);
            efficiencies.push(percent);
            let native = &walls[&(program.name, "native".to_owned())];
            let translated = &walls[&(program.name, variant.label.clone())];
            let wall = median(
                native
                    .iter()
                    .zip(translated)
                    .map(|(n, t)| 100.0 * n / t)
                    .collect(),
            );
            wall_efficiencies.push(wall);
            program_scores.insert(
                program.name.into(),
                json!({"kernel_native_percent": percent, "process_wall_native_percent": wall}),
            );
        }
        scores.insert(variant.label.clone(), json!({
            "programs": program_scores,
            "suite_native_percent": if complete && rounds>=7 { Some(geomean(efficiencies)) } else { None },
            "suite_process_wall_native_percent": if complete && rounds>=7 { Some(geomean(wall_efficiencies)) } else { None },
        }));
    }
    json!({"scope":"physical hosted process; not freestanding shared-MMU boot",
        "definition":"100 * native_seconds / translated_seconds, median paired rounds per kernel; geometric mean within program then equal weight per program",
        "required_programs":PROGRAMS.len(), "observed_programs":programs.len(),
        "required_kernels":PROGRAMS.iter().map(|program|program.kernels.len()).sum::<usize>(),
        "complete_suite":complete, "minimum_headline_rounds":7,
        "headline_available":complete && rounds>=7, "variants":scores})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_ambiguous_missing_and_invalid_timing_outputs() {
        let valid = "stela-bench x 0.25 0123456789abcdef";
        assert_eq!(parse(valid, &["x"]).unwrap()[0].1, 0.25);
        for output in [
            String::new(),
            format!("{valid}\n{valid}"),
            "stela-bench y 1 0123456789abcdef".into(),
            "stela-bench x NaN 0123456789abcdef".into(),
            "stela-bench x 0 0123456789abcdef".into(),
            "stela-bench x -1 0123456789abcdef".into(),
            "stela-bench x 1 wrong".into(),
        ] {
            assert!(parse(&output, &["x"]).is_err(), "{output}");
        }
        assert!(unique_names(&["x".into(), "x".into()], &["x"]).is_err());
        assert!(unique_names(&["x".into(), "typo".into()], &["x"]).is_err());
    }
    #[test]
    fn aggregate_weights_programs_and_refuses_partial_headlines() {
        let programs = PROGRAMS.iter().collect::<Vec<_>>();
        let variants = vec![
            Variant {
                label: "native".into(),
                arch: "x86_64",
                stela: None,
            },
            Variant {
                label: "arm64e".into(),
                arch: "arm64e",
                stela: None,
            },
        ];
        let mut seconds = BTreeMap::new();
        let mut walls = BTreeMap::new();
        for (i, program) in programs.iter().enumerate() {
            let time = if i < 4 { 2.0 } else { 8.0 };
            for kernel in program.kernels {
                seconds.insert((*kernel, "native".into()), vec![1.0; 7]);
                seconds.insert((*kernel, "arm64e".into()), vec![time; 7]);
            }
            walls.insert((program.name, "native".into()), vec![1.0; 7]);
            walls.insert((program.name, "arm64e".into()), vec![time; 7]);
        }
        let full = score(&programs, &variants, &seconds, &walls, 7);
        let percent = full["variants"]["arm64e"]["suite_native_percent"]
            .as_f64()
            .unwrap();
        assert!((percent - 25.0).abs() < 1e-10);
        assert!(score(&programs[..7],&variants,&seconds,&walls,7)["variants"]["arm64e"]["suite_native_percent"].is_null());
        assert!(score(&programs,&variants,&seconds,&walls,1)["variants"]["arm64e"]["suite_native_percent"].is_null());
    }
}
