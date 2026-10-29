//! Canonical ignored-test annotations derived from declared prerequisites.
use super::{Entry, Kind};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::collections::BTreeSet;

/// An oracle without named file/value/output/program prerequisites must
/// declare why it is outside the default suite.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Precondition {
    Exhaustive,
    FreshProcess,
    Network,
}

impl Precondition {
    fn label(self) -> &'static str {
        match self {
            Self::Exhaustive => "exhaustive",
            Self::FreshProcess => "fresh-process",
            Self::Network => "network",
        }
    }
}

pub(super) fn canonical_reason(entry: &Entry) -> Result<String> {
    let mut prerequisites: BTreeSet<String> = entry
        .inputs
        .iter()
        .chain(&entry.values)
        .chain(&entry.outputs)
        .cloned()
        .collect();
    prerequisites.extend(
        entry
            .programs
            .iter()
            .map(|path| format!("program:{}", path.display())),
    );
    ensure!(
        entry.precondition.is_none() || (entry.kind == Kind::Oracle && prerequisites.is_empty()),
        "unexpected intrinsic precondition in {}",
        entry.test
    );
    let kind = match entry.kind {
        Kind::Oracle => "oracle",
        Kind::Manual => "manual",
        Kind::Isolation => "isolation",
    };
    if entry.kind == Kind::Isolation {
        ensure!(
            prerequisites.is_empty(),
            "isolation child {} must inherit its parent's inputs",
            entry.test
        );
        return Ok("isolation: child".into());
    }
    let condition = if prerequisites.is_empty() {
        match entry.kind {
            Kind::Oracle => entry
                .precondition
                .with_context(|| {
                    format!(
                        "oracle {} has no declared prerequisites or intrinsic precondition",
                        entry.test
                    )
                })?
                .label()
                .into(),
            Kind::Manual => "opt-in".into(),
            Kind::Isolation => unreachable!(),
        }
    } else {
        prerequisites.into_iter().collect::<Vec<_>>().join(", ")
    };
    Ok(format!("{kind}: {condition}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(kind: Kind) -> Entry {
        Entry {
            package: "fixture".into(),
            test: "oracle".into(),
            source: "fixture.rs".into(),
            kind,
            inputs: vec![],
            values: vec![],
            outputs: vec![],
            programs: vec![],
            reason: "human prerequisite detail".into(),
            precondition: None,
        }
    }

    #[test]
    fn names_every_prerequisite_kind_in_stable_order() {
        let mut entry = fixture(Kind::Oracle);
        entry.inputs = vec!["STELA_Z_INPUT".into()];
        entry.values = vec!["STELA_A_VALUE".into()];
        entry.outputs = vec!["STELA_M_OUTPUT".into()];
        entry.programs = vec!["/oracle/tool".into()];
        assert_eq!(
            canonical_reason(&entry).unwrap(),
            "oracle: STELA_A_VALUE, STELA_M_OUTPUT, STELA_Z_INPUT, program:/oracle/tool"
        );
    }

    #[test]
    fn no_environment_preconditions_have_explicit_labels() {
        let mut entry = fixture(Kind::Oracle);
        assert!(canonical_reason(&entry).is_err());
        for (precondition, label) in [
            (Precondition::Exhaustive, "exhaustive"),
            (Precondition::FreshProcess, "fresh-process"),
            (Precondition::Network, "network"),
        ] {
            entry.precondition = Some(precondition);
            assert_eq!(
                canonical_reason(&entry).unwrap(),
                format!("oracle: {label}")
            );
        }
        entry.inputs.push("STELA_INPUT".into());
        assert!(canonical_reason(&entry).is_err());
    }

    #[test]
    fn children_and_manual_work_remain_explicit() {
        let mut child = fixture(Kind::Isolation);
        assert_eq!(canonical_reason(&child).unwrap(), "isolation: child");
        child.inputs.push("STELA_INPUT".into());
        assert!(canonical_reason(&child).is_err());
        assert_eq!(
            canonical_reason(&fixture(Kind::Manual)).unwrap(),
            "manual: opt-in"
        );
    }

    #[test]
    fn repeated_prerequisite_variables_are_rejected() {
        let mut entry = fixture(Kind::Oracle);
        entry.inputs.push("STELA_INPUT".into());
        entry.values.push("STELA_INPUT".into());
        assert!(crate::oracles::validate(&[entry]).is_err());
    }
    #[test]
    fn feature_gates_name_their_enabling_feature() {
        let files = crate::oracles::git(&[
            "grep",
            "-l",
            "cfg_attr",
            "--",
            "crates/**/*.rs",
            "xtask/**/*.rs",
        ])
        .unwrap();
        let mut inspected = 0;
        for file in files.lines() {
            let text = std::fs::read_to_string(crate::tools::root().join(file)).unwrap();
            let marker = concat!("#[", "cfg_attr(");
            for (offset, _) in text.match_indices(marker) {
                let tail = &text[offset + marker.len()..];
                let attribute = &tail[..tail.find(")]").expect("conditional attribute terminator")];
                let ignored = attribute.rsplit(',').find(|part| {
                    let part = part.trim();
                    part == "ignore" || part.starts_with("ignore =")
                });
                if let Some(ignored) = ignored {
                    assert_eq!(
                        ignored.trim(),
                        "ignore = \"feature: fetched-sources\"",
                        "{file}"
                    );
                    assert_eq!(
                        attribute.trim().split_once(',').unwrap().0,
                        "not(feature = \"fetched-sources\")",
                        "{file}"
                    );
                    inspected += 1;
                }
            }
        }
        assert!(
            inspected > 0,
            "feature-gated source checks must remain represented"
        );
    }
}
