//! Typed probe records: the one machine-readable output of Stela's compiler
//! probes, written by `gpu/compiler/tests/probe_report.h`.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const PREFIX: &str = "STELA_RECORD ";

type Facts = Map<String, Value>;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Outcome {
    Compiled,
    Held,
    Refused,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Origin {
    RawInputFile,
    OriginalFixture,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Record {
    /// A target's expected outcome, recorded before it compiles. A compiled
    /// expectation may name the refusal by design its input can require.
    Expect {
        target: String,
        outcome: Outcome,
        reason: Option<String>,
        unless_refused: Option<String>,
    },
    Compiled {
        target: String,
        bytes: u64,
        facts: Option<Facts>,
    },
    Held {
        target: String,
        reason: String,
    },
    Refused {
        target: String,
        reason: String,
    },
    /// A file written into the artifact directory the probe was given.
    Artifact {
        path: String,
    },
    AirInput {
        origin: Origin,
        bytes: u64,
        blake3: String,
        entry: String,
        facts: Option<Facts>,
    },
    AirProfile {
        name: String,
        fp_profile: u32,
    },
    AirEnvironment {
        target: String,
        fp_profile: u32,
        nir_float_controls: u32,
    },
    Evidence {
        topic: String,
        facts: Facts,
    },
}

/// The checked records of one probe run.
#[derive(Debug, Default, Serialize)]
pub(super) struct Report {
    /// Each compiled, held or refused target with its record.
    pub outcomes: Vec<Record>,
    pub artifacts: BTreeSet<String>,
    pub inputs: Vec<Record>,
    pub profiles: Vec<Record>,
    pub environments: Vec<Record>,
    pub evidence: Vec<Record>,
}

impl Report {
    /// Parses every record line of a probe log, ignoring diagnostic text, and
    /// checks the outcomes against the expectations recorded before them:
    /// both sets must name the same targets, each exactly once.
    pub fn parse(log: &str) -> Result<Self> {
        let mut report = Self::default();
        let mut expected = BTreeMap::new();
        let mut finished = BTreeSet::new();
        for (number, line) in log.lines().enumerate() {
            let Some(json) = line.strip_prefix(PREFIX) else {
                continue;
            };
            let record: Record = serde_json::from_str(json)
                .with_context(|| format!("invalid probe record on line {}", number + 1))?;
            match &record {
                Record::Expect { target, .. } => {
                    ensure!(
                        !finished.contains(target)
                            && expected.insert(target.clone(), record.clone()).is_none(),
                        "repeated expectation for {target}"
                    );
                }
                Record::Compiled { target, .. }
                | Record::Held { target, .. }
                | Record::Refused { target, .. } => {
                    let expectation = expected
                        .get(target)
                        .with_context(|| format!("outcome for {target} was never expected"))?;
                    ensure!(
                        finished.insert(target.clone()),
                        "repeated outcome for {target}"
                    );
                    check_outcome(expectation, &record)?;
                    report.outcomes.push(record);
                }
                Record::Artifact { path } => ensure!(
                    !path.is_empty()
                        && !path.contains('/')
                        && report.artifacts.insert(path.clone()),
                    "invalid or repeated artifact {path}"
                ),
                Record::AirInput { .. } => report.inputs.push(record),
                Record::AirProfile { .. } => report.profiles.push(record),
                Record::AirEnvironment { .. } => report.environments.push(record),
                Record::Evidence { .. } => report.evidence.push(record),
            }
        }
        let missing = expected
            .keys()
            .filter(|target| !finished.contains(*target))
            .collect::<Vec<_>>();
        ensure!(missing.is_empty(), "no outcome for {missing:?}");
        Ok(report)
    }

    pub fn compiled(&self) -> impl Iterator<Item = (&str, &Option<Facts>)> {
        self.outcomes.iter().filter_map(|record| match record {
            Record::Compiled { target, facts, .. } => Some((target.as_str(), facts)),
            _ => None,
        })
    }

    /// Held targets, which count as unsupported. A refusal by design passes.
    pub fn held(&self) -> impl Iterator<Item = &Record> {
        self.outcomes
            .iter()
            .filter(|record| matches!(record, Record::Held { .. }))
    }

    pub fn count(&self, outcome: Outcome) -> usize {
        self.outcomes
            .iter()
            .filter(|record| {
                matches!(
                    (record, outcome),
                    (Record::Compiled { .. }, Outcome::Compiled)
                        | (Record::Held { .. }, Outcome::Held)
                        | (Record::Refused { .. }, Outcome::Refused)
                )
            })
            .count()
    }

    /// The one AIR input a probe compiled.
    pub fn input(&self) -> Result<(Origin, u64, &str, &str)> {
        match self.inputs.as_slice() {
            [
                Record::AirInput {
                    origin,
                    bytes,
                    blake3,
                    entry,
                    ..
                },
            ] => Ok((*origin, *bytes, blake3, entry)),
            _ => bail!("probe must identify exactly one AIR input"),
        }
    }

    /// The one floating-point profile a probe applied.
    pub fn profile(&self) -> Result<(&str, u32)> {
        match self.profiles.as_slice() {
            [Record::AirProfile { name, fp_profile }] => Ok((name, *fp_profile)),
            _ => bail!("probe must identify exactly one AIR floating-point profile"),
        }
    }

    /// The float controls each compiled target requested, which must all
    /// carry `fp_profile`. Every compiled target reports exactly one.
    pub fn environments(&self, fp_profile: u32) -> Result<BTreeMap<&str, u32>> {
        let mut controls = BTreeMap::new();
        for record in &self.environments {
            let Record::AirEnvironment {
                target,
                fp_profile: profile,
                nir_float_controls,
            } = record
            else {
                unreachable!("environments holds only environment records");
            };
            ensure!(
                *profile == fp_profile,
                "{target} compiled with another AIR profile"
            );
            ensure!(
                controls
                    .insert(target.as_str(), *nir_float_controls)
                    .is_none(),
                "repeated AIR environment for {target}"
            );
        }
        let compiled = self
            .compiled()
            .map(|(target, _)| target)
            .collect::<BTreeSet<_>>();
        ensure!(
            controls.keys().copied().collect::<BTreeSet<_>>() == compiled,
            "AIR environments must name exactly the compiled targets"
        );
        Ok(controls)
    }
}

fn check_outcome(expectation: &Record, outcome: &Record) -> Result<()> {
    let Record::Expect {
        target,
        outcome: expected,
        reason,
        unless_refused,
    } = expectation
    else {
        unreachable!("expectations holds only expect records");
    };
    match (expected, outcome) {
        (Outcome::Compiled, Record::Compiled { bytes, .. }) => {
            ensure!(*bytes > 0, "{target} compiled no code");
        }
        (Outcome::Compiled, Record::Refused { reason: actual, .. })
            if unless_refused.as_ref() == Some(actual) => {}
        (Outcome::Held, Record::Held { reason: actual, .. })
        | (Outcome::Refused, Record::Refused { reason: actual, .. })
            if reason.as_ref() == Some(actual) => {}
        _ => bail!("{target}: expected {expectation:?}, got {outcome:?}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log(lines: &[&str]) -> String {
        lines
            .iter()
            .map(|line| format!("{PREFIX}{line}\n"))
            .collect()
    }

    const SM75: &str = r#"{"kind":"expect","target":"sm75","outcome":"compiled"}"#;
    const SM75_CODE: &str = r#"{"kind":"compiled","target":"sm75","bytes":96}"#;
    const NVL: &str = r#"{"kind":"expect","target":"nvl","outcome":"held","reason":"gen35"}"#;
    const NVL_HELD: &str = r#"{"kind":"held","target":"nvl","reason":"gen35"}"#;

    #[test]
    fn outcomes_must_match_the_expected_set() {
        let report = Report::parse(&format!(
            "diagnostic text\n{}",
            log(&[SM75, NVL, SM75_CODE, NVL_HELD])
        ))
        .unwrap();
        assert_eq!(report.count(Outcome::Compiled), 1);
        assert_eq!(report.held().count(), 1);
        assert!(Report::parse(&log(&[SM75, NVL, SM75_CODE])).is_err());
        assert!(Report::parse(&log(&[SM75_CODE])).is_err());
        assert!(Report::parse(&log(&[SM75, SM75_CODE, SM75_CODE])).is_err());
        assert!(Report::parse(&log(&[SM75, SM75_CODE, SM75])).is_err());
        assert!(Report::parse(&log(&[SM75, SM75, SM75_CODE])).is_err());
        assert!(Report::parse(&log(&[NVL, &NVL_HELD.replace("gen35", "other")])).is_err());
        assert!(Report::parse(&log(&[SM75, &SM75_CODE.replace("96", "0")])).is_err());
        assert!(Report::parse(&log(&[NVL, &SM75_CODE.replace("sm75", "nvl")])).is_err());
    }

    #[test]
    fn compiler_refusal_requires_matching_expectation() {
        let refused = r#"{"kind":"refused","target":"ivb","reason":"fp32"}"#;
        let by_design = r#"{"kind":"expect","target":"ivb","outcome":"refused","reason":"fp32"}"#;
        let unless =
            r#"{"kind":"expect","target":"ivb","outcome":"compiled","unless_refused":"fp32"}"#;
        let compiled = r#"{"kind":"compiled","target":"ivb","bytes":4}"#;
        assert!(Report::parse(&log(&[by_design, refused])).is_ok());
        assert!(Report::parse(&log(&[by_design, compiled])).is_err());
        assert!(Report::parse(&log(&[unless, refused])).is_ok());
        assert!(Report::parse(&log(&[unless, compiled])).is_ok());
        assert!(Report::parse(&log(&[unless, &refused.replace("fp32", "other")])).is_err());
        let plain = r#"{"kind":"expect","target":"ivb","outcome":"compiled"}"#;
        assert!(Report::parse(&log(&[plain, refused])).is_err());
    }

    #[test]
    fn records_are_typed() {
        assert!(Report::parse(&log(&[r#"{"kind":"compiled","target":"x"}"#])).is_err());
        assert!(Report::parse(&log(&[r#"{"kind":"unknown"}"#])).is_err());
        assert!(Report::parse(&log(&[&SM75.replace("}", r#","extra":1}"#)])).is_err());
        assert!(Report::parse(&log(&[r#"{"kind":"artifact","path":"a.bin"}"#])).is_ok());
        assert!(Report::parse(&log(&[r#"{"kind":"artifact","path":"../a"}"#])).is_err());
        let artifact = r#"{"kind":"artifact","path":"a.bin"}"#;
        assert!(Report::parse(&log(&[artifact, artifact])).is_err());
        assert!(Report::parse(&format!("{PREFIX}{{\"kind\":\"expect\"\n")).is_err());
    }

    #[test]
    fn air_evidence_binds_inputs_profiles_and_targets() {
        let input = r#"{"kind":"air_input","origin":"raw_input_file","bytes":4,"blake3":"00","entry":"kernel"}"#;
        let profile = r#"{"kind":"air_profile","name":"ieee","fp_profile":0}"#;
        let environment =
            r#"{"kind":"air_environment","target":"sm75","fp_profile":0,"nir_float_controls":7}"#;
        let report = Report::parse(&log(&[input, profile, SM75, SM75_CODE, environment])).unwrap();
        assert_eq!(
            report.input().unwrap(),
            (Origin::RawInputFile, 4, "00", "kernel")
        );
        assert_eq!(report.profile().unwrap(), ("ieee", 0));
        assert_eq!(report.environments(0).unwrap()["sm75"], 7);
        assert!(report.environments(1).is_err());
        let doubled = Report::parse(&log(&[input, input, profile, profile])).unwrap();
        assert!(doubled.input().is_err() && doubled.profile().is_err());
        let missing = Report::parse(&log(&[SM75, SM75_CODE])).unwrap();
        assert!(missing.environments(0).is_err());
        let extra = Report::parse(&log(&[environment, environment])).unwrap();
        assert!(extra.environments(0).is_err());
    }
}
