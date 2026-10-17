//! `machine/chip/checks.rs`: each A64 form's FP, SVE, SME and FPMR access
//! checks, in the order its Execute pseudocode in Arm's pinned
//! `ISA_A64_xml_A_profile-2026-06` calls them, resolved per Apple CPU. The
//! system engine applies them where streaming mode changes what an
//! instruction may do: `AArch64_CheckFPAdvSIMDEnabled` and
//! `CheckNonStreamingSVEEnabled` trap in streaming mode, while
//! `AArch64_CheckFPEnabled` does not.
//!
//! A check guarded by `if`, `elsif` and `else` takes the branch its condition
//! selects. A condition is a conjunction or disjunction of
//! `IsFeatureImplemented`, decided by the chip's profile, and three decode
//! variables, decided by the encoding as their decode pseudocode fixes them:
//! `elements == 1` holds for the scalar (`asisd`) encodings, `esize` is 128
//! exactly in the `_q` encodings, and `index == 0` holds for the SMOV and
//! UMOV words whose imm5 (bits 20:16) has one bit set, since
//! `index = UInt(imm5<4:size+1>)` with `size = LowestSetBit(imm5)`. Any other
//! condition around a check, or a check inside another construct, fails
//! generation.
use super::{CHIPS, expression::Profile};
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
    fs,
    path::Path,
};

pub const GENERATED: &str = "crates/stela-runtime/src/machine/chip/checks.rs";
pub const DIRECTORY: &str = "ISA_A64_xml_A_profile-2026-06";
/// Bits 20:16, the imm5 field of SMOV and UMOV.
const IMM5: u32 = 0x1f << 16;

/// The checks, by their pseudocode names.
const CHECKS: [(&str, &str); 10] = [
    ("AArch64_CheckFPEnabled", "Fp"),
    ("AArch64_CheckFPAdvSIMDEnabled", "FpAdvSimd"),
    ("CheckSVEEnabled", "Sve"),
    ("CheckNonStreamingSVEEnabled", "NonStreamingSve"),
    ("CheckStreamingSVEEnabled", "StreamingSve"),
    ("CheckStreamingSVEAndZAEnabled", "StreamingSveAndZa"),
    ("CheckSMEEnabled", "Sme"),
    ("CheckSMEAndZAEnabled", "SmeAndZa"),
    ("CheckSMEZT0Enabled", "SmeZt0"),
    ("CheckFPMREnabled", "Fpmr"),
];

/// What a decode-variable condition depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Word {
    Any,
    /// imm5 has one bit set (`index == 0`), or not.
    SingleImm5(bool),
}

#[derive(Debug)]
enum Statement {
    Check(&'static str),
    If(Vec<(Option<String>, Vec<Statement>)>),
}

/// The Execute pseudocode's text, tags removed.
fn execute_text(xml: &str) -> Result<String> {
    let mut out = String::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<pstext") {
        let tag_end = rest[start..].find('>').context("unterminated pstext")? + start;
        let tag = &rest[start..tag_end];
        let end = rest[tag_end..]
            .find("</pstext>")
            .context("unclosed pstext")?
            + tag_end;
        if tag.contains("section=\"Execute\"") {
            out.push_str(&strip(&rest[tag_end + 1..end]));
            out.push('\n');
        }
        rest = &rest[end..];
    }
    Ok(out)
}

fn strip(text: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for character in text.chars() {
        match character {
            '<' => inside = true,
            '>' => inside = false,
            _ if !inside => out.push(character),
            _ => {}
        }
    }
    out.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn check_name(line: &str) -> Option<&'static str> {
    let call = line.strip_suffix("();")?;
    CHECKS
        .iter()
        .find(|(name, _)| *name == call)
        .map(|(_, variant)| *variant)
}

/// Parse the checks and the `if` structure around them; other statements
/// are skipped.
fn parse(text: &str) -> Result<Vec<Statement>> {
    fn block<'a>(
        lines: &mut std::iter::Peekable<impl Iterator<Item = &'a str>>,
        nested: bool,
    ) -> Result<Vec<Statement>> {
        let mut statements = Vec::new();
        while let Some(&line) = lines.peek() {
            if nested && (line == "else" || line == "end;" || line.starts_with("elsif ")) {
                return Ok(statements);
            }
            lines.next();
            if let Some(check) = check_name(line) {
                statements.push(Statement::Check(check));
            } else if let Some(condition) = line
                .strip_prefix("if ")
                .and_then(|line| line.strip_suffix(" then"))
            {
                let mut arms = vec![(Some(condition.to_owned()), block(lines, true)?)];
                loop {
                    match lines.next() {
                        Some("end;") => break,
                        Some("else") => arms.push((None, block(lines, true)?)),
                        Some(line) if line.starts_with("elsif ") => {
                            let condition = line
                                .strip_prefix("elsif ")
                                .and_then(|line| line.strip_suffix(" then"))
                                .with_context(|| format!("malformed {line}"))?;
                            arms.push((Some(condition.to_owned()), block(lines, true)?));
                        }
                        other => bail!("unterminated if: {other:?}"),
                    }
                }
                if contains_check(&arms) {
                    statements.push(Statement::If(arms));
                }
            } else if CHECKS.iter().any(|(name, _)| line.contains(name)) {
                bail!("a check outside a plain call or if: {line}");
            } else if line.ends_with(" do") || line.ends_with(" of") {
                // A loop or case: no check may sit inside it.
                let mut depth = 1;
                for line in lines.by_ref() {
                    ensure!(
                        !CHECKS.iter().any(|(name, _)| line.contains(name)),
                        "a check inside a loop or case: {line}"
                    );
                    if line.ends_with(" do") || line.ends_with(" of") || is_open_if(line) {
                        depth += 1;
                    } else if line == "end;" {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                }
            }
        }
        ensure!(!nested, "unterminated block");
        Ok(statements)
    }
    fn contains_check(arms: &[(Option<String>, Vec<Statement>)]) -> bool {
        arms.iter().any(|(_, body)| !body.is_empty())
    }
    // A condition may continue over several lines up to its `then`.
    let mut lines: Vec<String> = Vec::new();
    let mut open = false;
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        match lines.last_mut() {
            Some(last) if open => {
                last.push(' ');
                last.push_str(line);
            }
            _ => lines.push(line.to_owned()),
        }
        let last = lines.last().expect("a line");
        open = (last.starts_with("if ") || last.starts_with("elsif "))
            && !last.ends_with(" then")
            && !last.ends_with(';');
    }
    ensure!(!open, "unterminated condition");
    // A line may hold several statements, or a whole `if`.
    let lines: Vec<String> = lines.iter().flat_map(|line| expand(line)).collect();
    block(&mut lines.iter().map(String::as_str).peekable(), false)
}

/// One statement or `if` keyword per line: `if c then a(); else b(); end;`
/// becomes five lines.
fn expand(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line.trim();
    while !rest.is_empty() {
        let keyword = ["if ", "elsif "]
            .iter()
            .find(|keyword| rest.starts_with(**keyword));
        if let Some(then) = keyword.and_then(|_| rest.find(" then")) {
            out.push(rest[..then + " then".len()].to_owned());
            rest = rest[then + " then".len()..].trim_start();
        } else if let Some(after) = rest
            .strip_prefix("else")
            .filter(|after| after.is_empty() || after.starts_with(' '))
        {
            out.push("else".to_owned());
            rest = after.trim_start();
        } else if let Some(after) = rest.strip_prefix("end;") {
            out.push("end;".to_owned());
            rest = after.trim_start();
        } else {
            let end = rest.find("; ").map_or(rest.len(), |end| end + 1);
            out.push(rest[..end].to_owned());
            rest = rest[end..].trim_start();
        }
    }
    out
}

fn is_open_if(line: &str) -> bool {
    line.starts_with("if ") && line.ends_with(" then")
}

/// Evaluate `condition` for one chip, encoding and word class.
fn holds(condition: &str, features: &BTreeSet<String>, encoding: &str, word: Word) -> Result<bool> {
    let any = condition.split(" || ").map(|conjunction| {
        conjunction.split(" && ").try_fold(true, |all, atom| {
            let atom = atom.trim();
            let (negated, atom) = match atom.strip_prefix('!') {
                Some(atom) => (true, atom),
                None => (false, atom),
            };
            let value = if let Some(feature) = atom
                .strip_prefix("IsFeatureImplemented(")
                .and_then(|atom| atom.strip_suffix(')'))
            {
                features.contains(feature)
            } else {
                match atom {
                    "elements == 1" => {
                        ensure!(
                            encoding.contains("_asisd") || encoding.contains("_asimd"),
                            "{encoding}: elements without a scalar or vector class"
                        );
                        encoding.contains("_asisd")
                    }
                    "esize == 128" => encoding.ends_with("_q"),
                    "esize < 128" => !encoding.ends_with("_q"),
                    "index == 0" => match word {
                        Word::SingleImm5(single) => single,
                        Word::Any => bail!("{encoding}: index without an imm5 split"),
                    },
                    _ => bail!("{encoding}: unknown condition {atom}"),
                }
            };
            Ok::<bool, anyhow::Error>(all && value != negated)
        })
    });
    let mut result = false;
    for value in any {
        result |= value?;
    }
    Ok(result)
}

fn resolve(
    statements: &[Statement],
    features: &BTreeSet<String>,
    encoding: &str,
    word: Word,
    out: &mut Vec<&'static str>,
) -> Result<()> {
    for statement in statements {
        match statement {
            Statement::Check(check) => out.push(check),
            Statement::If(arms) => {
                for (condition, body) in arms {
                    let taken = match condition {
                        Some(condition) => holds(condition, features, encoding, word)?,
                        None => true,
                    };
                    if taken {
                        resolve(body, features, encoding, word, out)?;
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

fn uses_index(statements: &[Statement]) -> bool {
    statements.iter().any(|statement| match statement {
        Statement::Check(_) => false,
        Statement::If(arms) => arms.iter().any(|(condition, body)| {
            condition
                .as_deref()
                .is_some_and(|condition| condition.contains("index"))
                || uses_index(body)
        }),
    })
}

struct Form {
    mask: u32,
    value: u32,
    /// Per chip bit set, word class and check sequence.
    variants: Vec<(u8, Word, Vec<&'static str>)>,
}

fn hex(form: &Value, key: &str) -> Result<u32> {
    let text = form[key]
        .as_str()
        .with_context(|| format!("form without {key}"))?;
    Ok(u32::from_str_radix(text.trim_start_matches("0x"), 16)?)
}

/// Render the table from the extracted archive, the checklist forms and each
/// chip's profile.
pub fn render(directory: &Path, checklist: &Value, chips: &[(&str, Profile)]) -> Result<String> {
    let hashes = checklist["source_files_sha256"]
        .as_object()
        .context("checklist without source hashes")?;
    let checklist = checklist["forms"]
        .as_array()
        .context("checklist without forms")?;
    ensure!(
        chips
            .iter()
            .map(|(name, _)| *name)
            .eq(CHIPS.iter().map(|chip| chip.name)),
        "the profiles are not the platform's chips"
    );
    let mut parsed: BTreeMap<String, Vec<Statement>> = BTreeMap::new();
    let mut forms = Vec::new();
    for form in checklist {
        let id = form["id"].as_str().context("form without id")?;
        let file = form["source_file"]
            .as_str()
            .context("form without source")?;
        if !parsed.contains_key(file) {
            let bytes =
                fs::read(directory.join(file)).with_context(|| format!("cannot read {file}"))?;
            ensure!(
                hashes.get(file).and_then(Value::as_str)
                    == Some(stela_runtime::sha256(&bytes).as_str()),
                "{file} is not the checklist's pinned source"
            );
            let xml = String::from_utf8(bytes)?;
            let statements = parse(&execute_text(&xml)?).with_context(|| format!("in {file}"))?;
            parsed.insert(file.to_owned(), statements);
        }
        let statements = &parsed[file];
        if statements.is_empty() {
            continue;
        }
        let words: &[Word] = if uses_index(statements) {
            &[Word::SingleImm5(true), Word::SingleImm5(false)]
        } else {
            &[Word::Any]
        };
        let mut variants: Vec<(u8, Word, Vec<&'static str>)> = Vec::new();
        for &word in words {
            for (index, (_, profile)) in chips.iter().enumerate() {
                let mut checks = Vec::new();
                resolve(statements, &profile.features, id, word, &mut checks)
                    .with_context(|| format!("in {file}"))?;
                match variants
                    .iter_mut()
                    .find(|(_, other, sequence)| *other == word && *sequence == checks)
                {
                    Some((bits, ..)) => *bits |= 1 << index,
                    None => variants.push((1 << index, word, checks)),
                }
            }
        }
        forms.push(Form {
            mask: hex(form, "encoding_mask")?,
            value: hex(form, "encoding_value")?,
            variants,
        });
    }
    let mut groups: BTreeMap<u32, Vec<Form>> = BTreeMap::new();
    for form in forms {
        groups.entry(form.mask).or_default().push(form);
    }
    let mut out = String::new();
    writeln!(
        out,
        "//! Each A64 form's FP, SVE, SME and FPMR access checks, in its Execute\n\
         //! pseudocode's order, per Apple CPU: generated by `cargo xtask system-matrix`\n\
         //! from Arm's `{DIRECTORY}` and the checklist forms. Do not edit."
    )?;
    writeln!(
        out,
        "use super::{{Check, CheckForm, CheckGroup, CheckVariant, WordClass}};\n"
    )?;
    writeln!(
        out,
        "/// Grouped by encoding mask, most specific first, each group sorted by\n\
         /// value. `chips` bit `n` is set for chip `n` ({}).",
        CHIPS
            .iter()
            .map(|chip| chip.name)
            .collect::<Vec<_>>()
            .join(", ")
    )?;
    writeln!(out, "pub(super) static CHECKS: &[CheckGroup] = &[")?;
    let mut masks: Vec<u32> = groups.keys().copied().collect();
    masks.sort_by_key(|mask| (std::cmp::Reverse(mask.count_ones()), *mask));
    for mask in masks {
        let forms = groups.get_mut(&mask).expect("a group");
        forms.sort_by_key(|form| form.value);
        for pair in forms.windows(2) {
            ensure!(
                pair[0].value != pair[1].value,
                "two forms {mask:#x}/{:#x}",
                pair[0].value
            );
        }
        writeln!(out, "    CheckGroup {{ mask: {mask:#010x}, forms: &[")?;
        for form in forms.iter() {
            write!(
                out,
                "        CheckForm {{ value: {:#010x}, variants: &[",
                form.value
            )?;
            for (chips, word, checks) in &form.variants {
                let class = match word {
                    Word::Any => "WordClass::Any".to_owned(),
                    Word::SingleImm5(single) => format!("WordClass::SingleImm5({single})"),
                };
                let checks: Vec<String> = checks
                    .iter()
                    .map(|check| format!("Check::{check}"))
                    .collect();
                write!(
                    out,
                    "CheckVariant {{ chips: {chips:#04x}, class: {class}, checks: &[{}] }}, ",
                    checks.join(", ")
                )?;
            }
            writeln!(out, "] }},")?;
        }
        writeln!(out, "    ] }},")?;
    }
    writeln!(out, "];")?;
    writeln!(
        out,
        "\n/// imm5 of SMOV and UMOV.\npub(super) const IMM5: u32 = {IMM5:#x};"
    )?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PMULLB: &str = r#"<ps><pstext mayhavelinks="1" section="Execute" rep_section="execute">if esize == 128 then
    if <a link="x">IsFeatureImplemented</a>(FEAT_SSVE_AES) then
        <a link="y">CheckSVEEnabled</a>();
    else
        <a link="z">CheckNonStreamingSVEEnabled</a>();
    end;
else
    <a link="y">CheckSVEEnabled</a>();
end;
let VL : integer{} = CurrentVL();
for e = 0 to elements-1 do
    Elem[result, e, esize] = Elem[operand, e, esize];
end;</pstext></ps>"#;

    #[test]
    fn conditions_select_the_checks_per_encoding_and_feature() -> Result<()> {
        let statements = parse(&execute_text(PMULLB)?)?;
        let none = BTreeSet::new();
        let aes: BTreeSet<String> = ["FEAT_SSVE_AES".to_owned()].into();
        let run = |features, encoding| -> Result<Vec<&'static str>> {
            let mut out = Vec::new();
            resolve(&statements, features, encoding, Word::Any, &mut out)?;
            Ok(out)
        };
        assert_eq!(run(&none, "pmullb_z_zz_q")?, ["NonStreamingSve"]);
        assert_eq!(run(&aes, "pmullb_z_zz_q")?, ["Sve"]);
        assert_eq!(run(&none, "pmullb_z_zz_")?, ["Sve"]);
        Ok(())
    }

    #[test]
    fn index_and_elements_follow_the_word_and_the_class() -> Result<()> {
        let smov = "<pstext section=\"Execute\">if index == 0 then\n    \
            <a>AArch64_CheckFPEnabled</a>();\nelse\n    \
            <a>AArch64_CheckFPAdvSIMDEnabled</a>();\nend;</pstext>";
        let statements = parse(&execute_text(smov)?)?;
        assert!(uses_index(&statements));
        let none = BTreeSet::new();
        for (word, expected) in [
            (Word::SingleImm5(true), "Fp"),
            (Word::SingleImm5(false), "FpAdvSimd"),
        ] {
            let mut out = Vec::new();
            resolve(&statements, &none, "SMOV_asimdins_W_w", word, &mut out)?;
            assert_eq!(out, [expected]);
        }
        let mut out = Vec::new();
        assert!(resolve(&statements, &none, "SMOV_asimdins_W_w", Word::Any, &mut out).is_err());
        assert!(holds(
            "elements == 1",
            &none,
            "FMULX_asisdsame_only",
            Word::Any
        )?);
        assert!(!holds(
            "elements == 1",
            &none,
            "FMULX_asimdsame_only",
            Word::Any
        )?);
        assert!(holds("elements == 1", &none, "abs_z_p_z_", Word::Any).is_err());
        Ok(())
    }

    #[test]
    fn unknown_conditions_and_hidden_checks_fail() {
        let unknown = "<pstext section=\"Execute\">if size == 3 then\n    \
            <a>CheckSVEEnabled</a>();\nend;</pstext>";
        let statements = parse(&execute_text(unknown).unwrap()).unwrap();
        let mut out = Vec::new();
        assert!(resolve(&statements, &BTreeSet::new(), "x", Word::Any, &mut out).is_err());
        let looped = "<pstext section=\"Execute\">for e = 0 to 3 do\n    \
            <a>CheckSVEEnabled</a>();\nend;</pstext>";
        assert!(parse(&execute_text(looped).unwrap()).is_err());
        let inline =
            "<pstext section=\"Execute\">if x then <a>CheckSVEEnabled</a>(); end;</pstext>";
        let statements = parse(&execute_text(inline).unwrap()).unwrap();
        assert!(resolve(&statements, &BTreeSet::new(), "x", Word::Any, &mut out).is_err());
    }
}
