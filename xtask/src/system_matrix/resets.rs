//! Architectural field reset values from Arm's System register XML release
//! (`SysReg_xml_A_profile`): AARCHMRS leaves every reset empty and the ASL's
//! `AArch64_ResetControlRegisters` is IMPLEMENTATION DEFINED, so this is the
//! only machine-readable source. Only derived facts (each field's value under
//! the profile) leave this module; the archive and Arm's prose stay in `.stela`.
//!
//! A field's `field_reset` of type Warm or Cold applies at the engine's reset,
//! which is a Cold reset and so also a Warm one. Conditional resets name the
//! highest implemented EL, EL3 or a feature, all decided by the profile; a
//! reset whose conditions all fail does not apply. Architecturally UNKNOWN
//! values read 0 (Stela's choice), and IMPLEMENTATION DEFINED ones take the
//! choices in [`IMPLEMENTATION_DEFINED`].
use super::expression::Profile;
use anyhow::{Context, Result, bail, ensure};
use std::{collections::BTreeMap, fs, path::Path};

pub const URI: &str = "https://developer.arm.com/-/cdn-downloads/permalink/\
    Exploration-Tools-Arm-Architecture-System-Registers/SysReg/\
    SysReg_xml_A_profile-2026-06.tar.gz";
pub const SHA256: &str = "4795c769085ff9056d9f18abbd9e23d7b0f0a955214cfb2a2121a9698b50d509";
pub const BYTES: usize = 43_124_482;
/// The release directory inside the archive.
pub const DIRECTORY: &str = "SysReg_xml_A_profile-2026-06";

/// (register, field, value, reason) for every reset in the profile that the
/// XML leaves to the implementation or to state outside the profile. A reset
/// of that kind missing here stops generation.
pub const IMPLEMENTATION_DEFINED: &[(&str, &str, u64, &str)] = &[
    (
        "SSBS",
        "SSBS",
        0,
        "machine::exception::Pstate::reset clears SSBS (Arm AArch64_TakeReset: ImpDefBit)",
    ),
    (
        "DBGPRCR_EL1",
        "CORENPDRQ",
        0,
        "EDPRCR.COREPURQ: no external debugger requests core power-up",
    ),
    (
        "SCTLR_EL1",
        "DSSBS",
        0,
        "PSTATE.SSBS also resets to 0 (machine::exception::Pstate::reset)",
    ),
    (
        "SCTLR_EL2",
        "DSSBS",
        0,
        "PSTATE.SSBS also resets to 0 (machine::exception::Pstate::reset)",
    ),
    (
        "SCTLR_EL1",
        "EE",
        0,
        "little-endian; RES0 without FEAT_MixedEnd",
    ),
    (
        "SCTLR_EL2",
        "EE",
        0,
        "little-endian; RES0 without FEAT_MixedEnd",
    ),
];

/// What one field resets to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reset {
    Value(u64),
    Unknown,
    ImplementationDefined,
    /// A value named by an expression, such as `NUM_PMU_COUNTERS`.
    Expression(String),
    /// The value of another register's field, such as an external debug
    /// register's.
    Field(String),
}

/// One field's reset at bits `lsb..lsb + width`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub lsb: u32,
    pub width: u32,
    pub reset: Reset,
}

/// Every AArch64 register's field resets under `profile`, keyed by the
/// register name with array placeholders such as `<n>` removed.
pub fn read(directory: &Path, profile: &Profile) -> Result<BTreeMap<String, Vec<Field>>> {
    let mut registers: BTreeMap<String, Vec<Field>> = BTreeMap::new();
    let mut entries: Vec<_> = fs::read_dir(directory)
        .with_context(|| format!("cannot read {}", directory.display()))?
        .collect::<Result<_, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let file = entry.file_name().to_string_lossy().into_owned();
        if !(file.starts_with("AArch64-") && file.ends_with(".xml")) {
            continue;
        }
        let text = fs::read_to_string(entry.path())?;
        let page = parse(&text).with_context(|| format!("cannot parse {file}"))?;
        for register in page.descendants("register") {
            if register.attribute("execution_state") != Some("AArch64") {
                continue;
            }
            let Some(name) = register.child("reg_short_name").map(Element::text) else {
                continue;
            };
            let fields = registers.entry(plain_name(&name)).or_default();
            for field in register.descendants("field") {
                fields.extend(field_resets(field, profile).with_context(|| {
                    format!(
                        "{name}.{}",
                        field
                            .child("field_name")
                            .map_or(String::new(), Element::text)
                    )
                })?);
            }
        }
    }
    Ok(registers)
}

/// `DBGBCR<n>_EL1` → `DBGBCR_EL1`, the register file's name.
pub fn plain_name(name: &str) -> String {
    super::codegen::rust_name(name)
}

fn field_resets(field: &Element, profile: &Profile) -> Result<Vec<Field>> {
    let (Some(name), Some(msb), Some(lsb)) = (
        field.child("field_name").map(Element::text),
        field.child("field_msb").map(Element::text),
        field.child("field_lsb").map(Element::text),
    ) else {
        return Ok(Vec::new());
    };
    let (msb, lsb): (u32, u32) = (msb.trim().parse()?, lsb.trim().parse()?);
    ensure!(msb >= lsb, "bad range {msb}:{lsb}");
    // 128-bit layouts (FEAT_D128) are outside the profile.
    if msb >= 64 {
        return Ok(Vec::new());
    }
    let width = msb - lsb + 1;
    let mut out = Vec::new();
    for reset in field
        .child("field_resets")
        .into_iter()
        .flat_map(|resets| resets.children_named("field_reset"))
    {
        if !matches!(reset.attribute("reset_type"), Some("Warm" | "Cold")) {
            continue;
        }
        if let Some(value) = resolve(reset, width, profile)? {
            out.push(Field {
                name: name.clone(),
                lsb,
                width,
                reset: value,
            });
        }
    }
    Ok(out)
}

/// A `field_reset` under the profile, or `None` when no condition holds.
fn resolve(reset: &Element, width: u32, profile: &Profile) -> Result<Option<Reset>> {
    if let Some(number) = reset.child("field_reset_number") {
        let bits = number.text();
        let bits = bits.trim().trim_matches('\'');
        // An array field such as CLAIM<m> gives one element's reset.
        let element = bits.len() as u32;
        ensure!(
            element != 0
                && width.is_multiple_of(element)
                && bits.chars().all(|bit| matches!(bit, '0' | '1')),
            "reset {bits:?} does not fill {width} bits"
        );
        let one = u64::from_str_radix(bits, 2)?;
        let value =
            (0..width / element).fold(0u64, |value, index| value | one << (index * element));
        return Ok(Some(Reset::Value(value)));
    }
    if let Some(expression) = reset.child("field_reset_expression") {
        let text = expression.text();
        let text = text.trim();
        return Ok(Some(match text.strip_prefix("0x") {
            Some(hex) => Reset::Value(u64::from_str_radix(hex, 16)?),
            None => Reset::Expression(text.to_owned()),
        }));
    }
    if let Some(other) = reset.child("field_reset_other_field") {
        let name = |tag| other.child(tag).map(Element::text).unwrap_or_default();
        return Ok(Some(Reset::Field(format!(
            "{}.{}",
            name("field_reset_other_field_regname").trim(),
            name("field_reset_other_field_fieldname").trim()
        ))));
    }
    if let Some(text) = reset.child("field_reset_standard_text") {
        return match text.text().trim() {
            "AU" | "U" => Ok(Some(Reset::Unknown)),
            "ID" => Ok(Some(Reset::ImplementationDefined)),
            other => bail!("unknown reset text {other:?}"),
        };
    }
    let Some(conditions) = reset.child("field_reset_conditions") else {
        bail!("field reset without a value");
    };
    for condition in conditions.children_named("field_reset_condition") {
        let holds = match condition.attribute("condition") {
            None => true,
            Some(text) => holds(text, profile)?,
        };
        if holds {
            let inner = condition
                .child("field_reset")
                .context("condition without a reset")?;
            return resolve(inner, width, profile);
        }
    }
    Ok(None)
}

/// A reset condition's truth under the profile.
fn holds(condition: &str, profile: &Profile) -> Result<bool> {
    if let Some(level) = condition.strip_prefix("the highest implemented Exception level is EL") {
        return Ok(level.parse::<u8>()? == profile.highest_el);
    }
    let (subject, implemented) = if let Some(subject) = condition.strip_suffix(" is implemented") {
        (subject, true)
    } else if let Some(subject) = condition.strip_suffix(" is not implemented") {
        (subject, false)
    } else {
        bail!("unknown reset condition {condition:?}");
    };
    let present = match subject {
        "EL3" => profile.highest_el >= 3,
        feature if feature.starts_with("FEAT_") => profile.features.contains(feature),
        other => bail!("unknown reset condition subject {other:?}"),
    };
    Ok(present == implemented)
}

/// Apply `fields` to a register whose profile layout has `positions` (name →
/// (lsb, width)) and reserved masks `res0`/`res1`. Fields absent from the
/// layout, or at another position, are not part of the profile's register.
pub fn value(
    register: &str,
    fields: &[Field],
    positions: &BTreeMap<String, (u32, u32)>,
    res0: u64,
    res1: u64,
) -> Result<u64> {
    let mut value = 0u64;
    for field in fields {
        if positions.get(&field.name) != Some(&(field.lsb, field.width)) {
            continue;
        }
        let bits = match &field.reset {
            Reset::Value(bits) => *bits,
            Reset::Unknown => 0,
            choice => IMPLEMENTATION_DEFINED
                .iter()
                .find(|(name, field_name, ..)| *name == register && *field_name == field.name)
                .map(|(_, _, value, _)| *value)
                .with_context(|| {
                    format!(
                        "{register}.{} resets to {choice:?}, which has no recorded choice",
                        field.name
                    )
                })?,
        };
        let mask = if field.width == 64 {
            u64::MAX
        } else {
            (1u64 << field.width) - 1
        };
        value = (value & !(mask << field.lsb)) | (bits & mask) << field.lsb;
    }
    Ok((value & !res0) | res1)
}

/// A minimal XML element tree: enough for Arm's well-formed register pages.
#[derive(Debug, Default)]
pub struct Element {
    name: String,
    attributes: Vec<(String, String)>,
    children: Vec<Node>,
}

#[derive(Debug)]
enum Node {
    Element(Element),
    Text(String),
}

impl Element {
    fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn children_named<'a, 'b>(
        &'a self,
        name: &'b str,
    ) -> impl Iterator<Item = &'a Element> + use<'a, 'b> {
        self.children.iter().filter_map(move |node| match node {
            Node::Element(element) if element.name == name => Some(element),
            _ => None,
        })
    }

    fn child(&self, name: &str) -> Option<&Element> {
        self.children_named(name).next()
    }

    /// Every element named `name` below this one, outermost first; the
    /// search does not descend into a match.
    fn descendants<'a>(&'a self, name: &str) -> Vec<&'a Element> {
        let mut out = Vec::new();
        for node in &self.children {
            if let Node::Element(element) = node {
                if element.name == name {
                    out.push(element);
                } else {
                    out.extend(element.descendants(name));
                }
            }
        }
        out
    }

    /// The concatenated text of this element and its descendants.
    fn text(&self) -> String {
        let mut out = String::new();
        for node in &self.children {
            match node {
                Node::Text(text) => out.push_str(text),
                Node::Element(element) => out.push_str(&element.text()),
            }
        }
        out
    }
}

/// Parse a document into a root element holding its top-level elements.
pub fn parse(text: &str) -> Result<Element> {
    let mut stack = vec![Element::default()];
    let mut rest = text;
    while !rest.is_empty() {
        let Some(start) = rest.find('<') else {
            push_text(&mut stack, rest)?;
            break;
        };
        push_text(&mut stack, &rest[..start])?;
        rest = &rest[start..];
        let skip = |rest: &str, end: &str| -> Result<usize> {
            rest.find(end)
                .map(|at| at + end.len())
                .with_context(|| format!("unterminated {end}"))
        };
        if rest.starts_with("<!--") {
            rest = &rest[skip(rest, "-->")?..];
        } else if rest.starts_with("<![CDATA[") {
            let end = skip(rest, "]]>")?;
            let content = &rest["<![CDATA[".len()..end - 3];
            stack
                .last_mut()
                .context("text outside the document")?
                .children
                .push(Node::Text(content.to_owned()));
            rest = &rest[end..];
        } else if rest.starts_with("<?") {
            rest = &rest[skip(rest, "?>")?..];
        } else if rest.starts_with("<!") {
            rest = &rest[skip(rest, ">")?..];
        } else if let Some(close) = rest.strip_prefix("</") {
            let end = close.find('>').context("unterminated end tag")?;
            let name = close[..end].trim();
            let element = stack.pop().context("unbalanced end tag")?;
            ensure!(element.name == name, "</{name}> closes <{}>", element.name);
            stack
                .last_mut()
                .context("end tag closes the document")?
                .children
                .push(Node::Element(element));
            rest = &close[end + 1..];
        } else {
            let (element, closed, length) = start_tag(rest)?;
            rest = &rest[length..];
            if closed {
                stack
                    .last_mut()
                    .context("element outside the document")?
                    .children
                    .push(Node::Element(element));
            } else {
                stack.push(element);
            }
        }
    }
    ensure!(
        stack.len() == 1,
        "unclosed <{}>",
        stack.last().map_or("", |e| e.name.as_str())
    );
    Ok(stack.pop().expect("the document root"))
}

fn push_text(stack: &mut [Element], text: &str) -> Result<()> {
    if text.trim().is_empty() {
        return Ok(());
    }
    let element = stack.last_mut().context("text outside the document")?;
    element.children.push(Node::Text(unescape(text)?));
    Ok(())
}

/// A start tag at the beginning of `text`: the element, whether it closes
/// itself, and the tag's length.
fn start_tag(text: &str) -> Result<(Element, bool, usize)> {
    let mut chars = text.char_indices().skip(1).peekable();
    let mut name = String::new();
    while let Some(&(_, c)) = chars.peek() {
        if c.is_whitespace() || c == '>' || c == '/' {
            break;
        }
        name.push(c);
        chars.next();
    }
    let mut element = Element {
        name,
        ..Element::default()
    };
    loop {
        while chars.peek().is_some_and(|&(_, c)| c.is_whitespace()) {
            chars.next();
        }
        match chars.next() {
            Some((at, '>')) => return Ok((element, false, at + 1)),
            Some((_, '/')) => {
                let (at, c) = chars.next().context("unterminated start tag")?;
                ensure!(c == '>', "stray / in <{}>", element.name);
                return Ok((element, true, at + 1));
            }
            Some((_, first)) => {
                let mut key = String::from(first);
                while let Some(&(_, c)) = chars.peek() {
                    if c == '=' || c.is_whitespace() {
                        break;
                    }
                    key.push(c);
                    chars.next();
                }
                while chars
                    .peek()
                    .is_some_and(|&(_, c)| c.is_whitespace() || c == '=')
                {
                    chars.next();
                }
                let (_, quote) = chars.next().context("attribute without a value")?;
                ensure!(quote == '"' || quote == '\'', "unquoted attribute {key}");
                let mut value = String::new();
                loop {
                    let (_, c) = chars.next().context("unterminated attribute value")?;
                    if c == quote {
                        break;
                    }
                    value.push(c);
                }
                element.attributes.push((key, unescape(&value)?));
            }
            None => bail!("unterminated start tag <{}>", element.name),
        }
    }
}

fn unescape(text: &str) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let end = rest[at..].find(';').context("unterminated entity")? + at;
        let entity = &rest[at + 1..end];
        match entity {
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "amp" => out.push('&'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            _ if entity.starts_with("#x") => out.push(
                char::from_u32(u32::from_str_radix(&entity[2..], 16)?).context("bad character")?,
            ),
            _ if entity.starts_with('#') => {
                out.push(char::from_u32(entity[1..].parse()?).context("bad character")?)
            }
            _ => bail!("unknown entity &{entity};"),
        }
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const PAGE: &str = r#"<?xml version='1.0'?>
<!DOCTYPE register_page SYSTEM "registers.dtd">
<!-- comment -->
<register_page><registers>
  <register execution_state="AArch64">
    <reg_short_name>DBGBCR&lt;n&gt;_EL1</reg_short_name>
    <reg_fieldsets><fields id="fieldset_0" length="64">
      <field id="f1"><field_name>E</field_name><field_msb>0</field_msb><field_lsb>0</field_lsb>
        <field_resets>
          <field_reset reset_type="Warm">
            <field_reset_conditions>
              <field_reset_condition condition="the highest implemented Exception level is EL1">
                <field_reset><field_reset_number>'1'</field_reset_number></field_reset>
              </field_reset_condition>
              <field_reset_condition>
                <field_reset><field_reset_number>'0'</field_reset_number></field_reset>
              </field_reset_condition>
            </field_reset_conditions>
          </field_reset>
          <field_reset reset_type="Cold">
            <field_reset_conditions>
              <field_reset_condition condition="FEAT_X is implemented">
                <field_reset><field_reset_standard_text>AU</field_reset_standard_text></field_reset>
              </field_reset_condition>
            </field_reset_conditions>
          </field_reset>
        </field_resets>
      </field>
      <field id="f2"><field_name>PMC</field_name><field_msb>2</field_msb><field_lsb>1</field_lsb>
        <field_resets><field_reset reset_type="Warm"><field_reset_number>'10'</field_reset_number></field_reset></field_resets>
      </field>
      <field id="f3"><field_name>EE</field_name><field_msb>25</field_msb><field_lsb>25</field_lsb>
        <field_resets><field_reset reset_type="Warm"><field_reset_standard_text>ID</field_reset_standard_text></field_reset></field_resets>
      </field>
    </fields></reg_fieldsets>
  </register>
</registers></register_page>"#;

    fn profile() -> Profile {
        Profile {
            parameters: BTreeSet::new(),
            features: BTreeSet::new(),
            highest_el: 2,
        }
    }

    #[test]
    fn page_resets_follow_conditions_under_the_profile() {
        let page = parse(PAGE).unwrap();
        let register = page.descendants("register")[0];
        assert_eq!(
            plain_name(&register.child("reg_short_name").unwrap().text()),
            "DBGBCR_EL1"
        );
        let fields: Vec<Field> = register
            .descendants("field")
            .into_iter()
            .flat_map(|field| field_resets(field, &profile()).unwrap())
            .collect();
        // E: the EL1 condition fails and the unconditional one gives '0'; the
        // Cold reset needs an absent feature and does not apply.
        assert_eq!(
            fields
                .iter()
                .map(|f| (f.name.as_str(), f.reset.clone()))
                .collect::<Vec<_>>(),
            [
                ("E", Reset::Value(0)),
                ("PMC", Reset::Value(0b10)),
                ("EE", Reset::ImplementationDefined)
            ]
        );
        let positions: BTreeMap<String, (u32, u32)> =
            [("E".into(), (0, 1)), ("PMC".into(), (1, 2))]
                .into_iter()
                .collect();
        // EE is not in this layout; bit 63 is RES1 and bit 1 RES0.
        assert_eq!(
            value("DBGBCR_EL1", &fields, &positions, 1 << 1, 1 << 63).unwrap(),
            1 << 63 | 0b100
        );
        let positions: BTreeMap<String, (u32, u32)> =
            [("EE".into(), (25, 1))].into_iter().collect();
        assert!(
            value("DBGBCR_EL1", &fields, &positions, 0, 0).is_err(),
            "unrecorded choice"
        );
        assert_eq!(value("SCTLR_EL1", &fields, &positions, 0, 0).unwrap(), 0);
    }

    #[test]
    fn conditions_and_entities() {
        let profile = profile();
        assert!(holds("the highest implemented Exception level is EL2", &profile).unwrap());
        assert!(!holds("EL3 is implemented", &profile).unwrap());
        assert!(holds("FEAT_BRBEv1p1 is not implemented", &profile).unwrap());
        assert!(holds("the moon is full", &profile).is_err());
        assert_eq!(unescape("a&lt;b&amp;&#x41;&#66;").unwrap(), "a<b&AB");
        assert!(parse("<a><b></a>").is_err());
    }
}
