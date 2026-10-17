//! Text edits to an OpenCore `config.plist` that change nothing but the
//! `Misc.Tools` array: every other byte (key order, indentation, comments,
//! `<data>` layout, line endings) stays as the user's configurator wrote it.
//!
//! The file is read as XML only far enough to find the byte spans of
//! elements. An entry is inserted as whole lines right after `<array>`, in
//! the file's own indentation and line ending, and removed as exactly those
//! lines. Every edit is checked by parsing the result: it must equal the
//! original with only that entry added or removed.
use anyhow::{Context, Result, bail, ensure};

/// One element with the byte spans of its tags and content.
#[derive(Debug, Clone)]
pub(super) struct Element {
    pub name: String,
    /// Offset of the opening `<`.
    pub start: usize,
    /// Offset just past the closing `>`.
    pub end: usize,
    /// The bytes between the tags; empty for `<name/>`.
    pub content: std::ops::Range<usize>,
    pub children: Vec<Element>,
}

/// Skip a comment, processing instruction or declaration at `at`; return
/// where it ends, or `None` when `at` starts an element tag.
fn skip_markup(text: &str, at: usize) -> Result<Option<usize>> {
    let rest = &text[at..];
    let close = if rest.starts_with("<!--") {
        "-->"
    } else if rest.starts_with("<?") {
        "?>"
    } else if rest.starts_with("<![CDATA[") {
        bail!("CDATA sections are not supported in config.plist");
    } else if rest.starts_with("<!") {
        ">"
    } else {
        return Ok(None);
    };
    let length = rest
        .find(close)
        .context("unterminated XML comment or declaration")?;
    Ok(Some(at + length + close.len()))
}

/// Parse the element whose `<` is at `at`.
fn element(text: &str, at: usize, depth: usize) -> Result<Element> {
    ensure!(depth < 64, "XML nests too deeply");
    let tag_end = at + text[at..].find('>').context("unterminated XML tag")?;
    let tag = &text[at + 1..tag_end];
    let self_closing = tag.ends_with('/');
    let name: String = tag
        .trim_end_matches('/')
        .split(|c: char| c.is_ascii_whitespace())
        .next()
        .unwrap_or_default()
        .to_owned();
    ensure!(
        !name.is_empty() && !name.starts_with('/'),
        "malformed XML tag"
    );
    if self_closing {
        return Ok(Element {
            name,
            start: at,
            end: tag_end + 1,
            content: tag_end + 1..tag_end + 1,
            children: vec![],
        });
    }
    let content_start = tag_end + 1;
    let mut children = Vec::new();
    let mut position = content_start;
    loop {
        let next = position
            + text[position..]
                .find('<')
                .with_context(|| format!("<{name}> is not closed"))?;
        if let Some(after) = skip_markup(text, next)? {
            position = after;
            continue;
        }
        if text[next..].starts_with("</") {
            let close_end = next + text[next..].find('>').context("unterminated XML tag")?;
            ensure!(
                text[next + 2..close_end].trim_end() == name,
                "<{name}> is closed by a different tag"
            );
            return Ok(Element {
                name,
                start: at,
                end: close_end + 1,
                content: content_start..next,
                children,
            });
        }
        let child = element(text, next, depth + 1)?;
        position = child.end;
        children.push(child);
    }
}

/// The document's root element.
pub(super) fn root(text: &str) -> Result<Element> {
    let mut position = 0;
    loop {
        let next = position + text[position..].find('<').context("no XML root element")?;
        match skip_markup(text, next)? {
            Some(after) => position = after,
            None => return element(text, next, 0),
        }
    }
}

/// Plain text with the five XML entities decoded.
fn decode(text: &str) -> Result<String> {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let (entity, after) = rest[at..]
            .split_once(';')
            .context("unterminated XML entity")?;
        out.push(match entity {
            "&amp" => '&',
            "&lt" => '<',
            "&gt" => '>',
            "&quot" => '"',
            "&apos" => '\'',
            _ => bail!("unsupported XML entity in a key"),
        });
        rest = after;
    }
    out.push_str(rest);
    Ok(out)
}

/// The value element a `<dict>` holds under `key`.
pub(super) fn value<'e>(text: &str, dict: &'e Element, key: &str) -> Result<Option<&'e Element>> {
    ensure!(dict.name == "dict", "expected a <dict>");
    let mut children = dict.children.iter();
    let mut found = None;
    while let Some(child) = children.next() {
        ensure!(child.name == "key", "a <dict> entry has no <key>");
        let value = children.next().context("a <dict> key has no value")?;
        if decode(&text[child.content.clone()])? == key {
            ensure!(found.is_none(), "a <dict> repeats a key");
            found = Some(value);
        }
    }
    Ok(found)
}

/// The leading whitespace of the line holding `at`.
fn indent(text: &str, at: usize) -> &str {
    let line = text[..at].rfind('\n').map_or(0, |n| n + 1);
    let lead = &text[line..at];
    let end = lead
        .find(|c: char| !c.is_ascii_whitespace())
        .unwrap_or(lead.len());
    &lead[..end]
}

/// The `Misc.Tools` array and the `Misc` and `Tools` key positions.
pub(super) struct Tools {
    pub array: Element,
    /// Indentation of the array's entries.
    pub entry_indent: String,
    /// One level of indentation.
    pub unit: String,
}

pub(super) fn tools(text: &str) -> Result<Tools> {
    let mut root = root(text)?;
    ensure!(root.name == "plist", "the root element is not <plist>");
    ensure!(
        root.children.len() == 1 && root.children[0].name == "dict",
        "<plist> does not hold one <dict>"
    );
    let top = root.children.remove(0);
    let misc = value(text, &top, "Misc")?.context("there is no Misc dictionary")?;
    ensure!(misc.name == "dict", "Misc is not a dictionary");
    let tools = value(text, misc, "Tools")?.context("there is no Misc.Tools array")?;
    ensure!(tools.name == "array", "Misc.Tools is not an array");
    let key_of = |dict: &Element, value: &Element| {
        let index = dict
            .children
            .iter()
            .position(|child| std::ptr::eq(child, value))
            .expect("the value is a child");
        dict.children[index - 1].start
    };
    let misc_indent = indent(text, key_of(&top, misc)).to_owned();
    let tools_indent = indent(text, key_of(misc, tools)).to_owned();
    let unit = tools_indent
        .strip_prefix(misc_indent.as_str())
        .filter(|unit| !unit.is_empty())
        .unwrap_or("\t")
        .to_owned();
    let entry_indent = match tools.children.first() {
        Some(first) => indent(text, first.start).to_owned(),
        None => format!("{tools_indent}{unit}"),
    };
    Ok(Tools {
        array: tools.clone(),
        entry_indent,
        unit,
    })
}

/// The file's line ending.
pub(super) fn newline(text: &str) -> &'static str {
    if text.contains("\r\n") { "\r\n" } else { "\n" }
}

/// The byte range of whole lines an element occupies: from the start of its
/// first line, when only whitespace precedes it there, through the line
/// ending after it, when only whitespace follows it.
pub(super) fn lines(text: &str, element: &Element) -> std::ops::Range<usize> {
    let line_start = text[..element.start].rfind('\n').map_or(0, |n| n + 1);
    let start = if text[line_start..element.start].trim().is_empty() {
        line_start
    } else {
        element.start
    };
    let rest = &text[element.end..];
    let line_end = rest.find('\n').map(|n| element.end + n + 1);
    let end = match line_end {
        Some(end) if text[element.end..end].trim().is_empty() => end,
        _ => element.end,
    };
    start..end
}

/// The string value of a `<dict>` entry's `key`, if it is a `<string>`.
pub(super) fn string(text: &str, dict: &Element, key: &str) -> Result<Option<String>> {
    match value(text, dict, key)? {
        Some(element) if element.name == "string" => {
            Ok(Some(decode(&text[element.content.clone()])?))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "<?xml version=\"1.0\"?>\n<!-- top -->\n<plist version=\"1.0\">\n<dict>\n\
        \t<key>Misc</key>\n\t<dict>\n\t\t<!-- tools -->\n\t\t<key>Tools</key>\n\t\t<array>\n\
        \t\t\t<dict>\n\t\t\t\t<key>Path</key>\n\t\t\t\t<string>A&amp;B.efi</string>\n\t\t\t</dict>\n\
        \t\t</array>\n\t</dict>\n</dict>\n</plist>\n";

    #[test]
    fn finds_the_tools_array_its_indentation_and_entries() {
        let tools = tools(SAMPLE).unwrap();
        assert_eq!(tools.array.children.len(), 1);
        assert_eq!(tools.entry_indent, "\t\t\t");
        assert_eq!(tools.unit, "\t");
        let entry = &tools.array.children[0];
        assert_eq!(
            string(SAMPLE, entry, "Path").unwrap().as_deref(),
            Some("A&B.efi")
        );
        let range = lines(SAMPLE, entry);
        assert!(SAMPLE[range.clone()].starts_with("\t\t\t<dict>"));
        assert!(SAMPLE[range].ends_with("</dict>\n"));
    }

    #[test]
    fn refuses_structures_it_cannot_edit_exactly() {
        for broken in [
            "<plist><dict><key>Misc</key><dict></dict></dict></plist>",
            "<plist><dict><key>Misc</key><array/></dict></plist>",
            "<plist><dict><key>Misc</key><dict><key>Tools</key><dict/></dict></dict></plist>",
            "<plist><dict><key>Misc</key><dict><key>Tools</key><array></dict></dict></plist>",
            "<plist><dict><key>Misc</key><dict/><key>Misc</key><dict/></dict></plist>",
            "<plist><dict><![CDATA[x]]></dict></plist>",
        ] {
            assert!(tools(broken).is_err(), "{broken}");
        }
    }
}
