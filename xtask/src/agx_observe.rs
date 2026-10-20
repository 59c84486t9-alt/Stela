//! Consolidate a boot run's AGX observation log into a field-confirmation
//! report (`--agx-observe`; docs/research/agx.md §5.1).
//!
//! A run with `--agx-observe` logs one `AGX OBSERVE` header per channel work
//! command the guest's driver submitted and one `AGX OBSERVE field` line per
//! command field the firmware model confirmed by following it to a structure
//! it decodes — a control stream, a USC word list, a tile-size word or the
//! completion stamp. This task reads those lines (from a serial log) and
//! reports, per command type, every offset confirmed and how often, so the
//! evidence can be entered in agx.md's matrix. A field is reported only when
//! observation confirmed it; the task invents nothing.
//!
//! The observed records are run output, never committed; this task reads a
//! log the lead hands over and writes only the summary to stdout.

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct AgxObserve {
    /// A boot run's serial log (or any file holding its `AGX OBSERVE` lines).
    #[arg(long)]
    log: PathBuf,
}

impl AgxObserve {
    pub fn run(&self) -> Result<()> {
        let text = std::fs::read_to_string(&self.log)
            .with_context(|| format!("cannot read {}", self.log.display()))?;
        let report = Report::parse(&text);
        for line in report.render() {
            println!("{line}");
        }
        Ok(())
    }
}

/// A command field confirmed by observation: where it is and what it named.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Field {
    offset: String,
    evidence: String,
}

/// What a log held, grouped by command type.
#[derive(Debug, Default, PartialEq, Eq)]
struct Report {
    /// Commands observed per type (`ThreeD`, `Cl`, `type=0x..`, ...).
    commands: BTreeMap<String, usize>,
    /// How often each (type, field) confirmation appeared.
    fields: BTreeMap<(String, Field), usize>,
    /// Lines that began `AGX OBSERVE` but matched no known shape.
    unparsed: usize,
}

impl Report {
    fn parse(text: &str) -> Self {
        let mut report = Report::default();
        // The command type each `command=` VA was last seen with, so a field
        // line is attributed to its command's type.
        let mut kind_of: BTreeMap<String, String> = BTreeMap::new();
        for line in text.lines() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix("AGX OBSERVE ") else {
                continue;
            };
            if let Some(rest) = rest.strip_prefix("field ") {
                match parse_field(rest) {
                    Some((command, field)) => {
                        let kind = kind_of
                            .get(&command)
                            .cloned()
                            .unwrap_or_else(|| "unknown".into());
                        *report.fields.entry((kind, field)).or_default() += 1;
                    }
                    None => report.unparsed += 1,
                }
            } else if rest.starts_with("journal dropped") {
                // A bound notice, not a record.
            } else if let Some((command, kind)) = parse_header(rest) {
                kind_of.insert(command, kind.clone());
                *report.commands.entry(kind).or_default() += 1;
            } else {
                report.unparsed += 1;
            }
        }
        report
    }

    fn render(&self) -> Vec<String> {
        let mut lines = Vec::new();
        let total: usize = self.commands.values().sum();
        lines.push(format!(
            "AGX OBSERVE MATRIX commands={total} types={} confirmed-fields={} unparsed={}",
            self.commands.len(),
            self.fields.len(),
            self.unparsed,
        ));
        for (kind, count) in &self.commands {
            lines.push(format!("AGX OBSERVE MATRIX type {kind} commands={count}"));
            for ((field_kind, field), seen) in &self.fields {
                if field_kind == kind {
                    lines.push(format!(
                        "AGX OBSERVE MATRIX type {kind} field +{} {} seen={seen}",
                        field.offset, field.evidence,
                    ));
                }
            }
        }
        // Fields whose command type was never seen in a header (a truncated
        // log) are reported under "unknown" so none is silently dropped.
        for ((field_kind, field), seen) in &self.fields {
            if !self.commands.contains_key(field_kind) {
                lines.push(format!(
                    "AGX OBSERVE MATRIX type {field_kind} field +{} {} seen={seen}",
                    field.offset, field.evidence,
                ));
            }
        }
        lines
    }
}

/// Parse a header's tail: `pipe=P index=I channel=0x.. command=0x.. KIND
/// raw[N]=HEX`, returning the command VA and its type.
fn parse_header(rest: &str) -> Option<(String, String)> {
    let command = token_after(rest, "command=")?;
    // The type is the word right after the `command=…` token.
    let after_command = rest.split("command=").nth(1)?;
    let kind = after_command.split_whitespace().nth(1)?.to_string();
    Some((command, kind))
}

/// Parse a field tail: `command=0x.. +0xOFF value=0x.. DESCRIPTION`.
fn parse_field(rest: &str) -> Option<(String, Field)> {
    let command = token_after(rest, "command=")?;
    let mut words = rest.split_whitespace();
    // Find the `+…` offset token, then the description after `value=…`.
    let offset = words
        .find(|w| w.starts_with('+'))?
        .trim_start_matches('+')
        .to_string();
    let after_value = rest.split("value=").nth(1)?;
    let evidence = after_value
        .split_whitespace()
        .skip(1)
        .collect::<Vec<_>>()
        .join(" ");
    if evidence.is_empty() {
        return None;
    }
    Some((command, Field { offset, evidence }))
}

/// The whitespace token that follows `key` in `text`.
fn token_after(text: &str, key: &str) -> Option<String> {
    text.split(key)
        .nth(1)?
        .split_whitespace()
        .next()
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "\
boot line that is not an observation
AGX OBSERVE pipe=1 index=0 channel=0x100 command=0x10000 ThreeD raw[8]=0100000000000000
AGX OBSERVE field command=0x10000 +0x14 value=0xffffffa000003400 VDM control stream (draws=1)
AGX OBSERVE field command=0x10000 +0x80 value=0x4000 tile-size word 0x4000
AGX OBSERVE pipe=2 index=1 channel=0x200 command=0x20000 Cl raw[8]=0300000000000000
AGX OBSERVE field command=0x20000 +0x1e8 value=0xffffffa000005000 CDM control stream (launches=1)
AGX OBSERVE pipe=1 index=0 channel=0x300 command=0x30000 ThreeD raw[8]=0100000000000000
AGX OBSERVE field command=0x30000 +0x14 value=0xffffffa000007000 VDM control stream (draws=2)
";

    #[test]
    fn the_report_groups_confirmed_fields_by_command_type() {
        let report = Report::parse(LOG);
        assert_eq!(report.commands["ThreeD"], 2);
        assert_eq!(report.commands["Cl"], 1);
        assert_eq!(report.unparsed, 0);
        // The 3D +0x14 VDM stream confirmation appears under both draw counts,
        // so the (type, offset, evidence) key counts the identical ones.
        let key = (
            "ThreeD".to_string(),
            Field {
                offset: "0x80".into(),
                evidence: "tile-size word 0x4000".into(),
            },
        );
        assert_eq!(report.fields[&key], 1);
        let rendered = report.render();
        assert!(rendered[0].contains("commands=3"));
        assert!(
            rendered
                .iter()
                .any(|l| l.contains("type ThreeD field +0x14 VDM control stream (draws=1)"))
        );
        assert!(
            rendered
                .iter()
                .any(|l| l.contains("type Cl field +0x1e8 CDM control stream (launches=1)"))
        );
    }

    #[test]
    fn an_unknown_type_word_and_a_field_without_a_header_are_kept() {
        let log = "\
AGX OBSERVE pipe=0 index=0 channel=0x1 command=0x40000 type=0x10 raw[4]=10000000
AGX OBSERVE field command=0x90000 +0x10 value=0xffffffa000009000 completion stamp (index=5)
";
        let report = Report::parse(log);
        assert_eq!(report.commands["type=0x10"], 1);
        // The orphan field's command VA has no header; it is reported as
        // unknown rather than dropped.
        let rendered = report.render();
        assert!(
            rendered
                .iter()
                .any(|l| l.contains("type unknown field +0x10 completion stamp (index=5)"))
        );
    }

    #[test]
    fn a_dropped_notice_is_not_a_record() {
        let log = "AGX OBSERVE journal dropped 3 older lines\n";
        let report = Report::parse(log);
        assert_eq!(report.unparsed, 0);
        assert!(report.commands.is_empty());
    }
}
