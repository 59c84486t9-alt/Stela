//! A minimal XML element tree and parser: enough for the well-formed archives
//! the generators read (Arm's register pages, Mesa's AGX2 ISA description).

use anyhow::{Context, Result, bail, ensure};

/// An element: its name, attributes and children in document order.
#[derive(Debug, Default)]
pub struct Element {
    pub name: String,
    pub attributes: Vec<(String, String)>,
    pub children: Vec<Node>,
}

#[derive(Debug)]
pub enum Node {
    Element(Element),
    Text(String),
}

impl Element {
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    pub fn children_named<'a, 'b>(
        &'a self,
        name: &'b str,
    ) -> impl Iterator<Item = &'a Element> + use<'a, 'b> {
        self.children.iter().filter_map(move |node| match node {
            Node::Element(element) if element.name == name => Some(element),
            _ => None,
        })
    }

    /// The child elements, in document order.
    pub fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|node| match node {
            Node::Element(element) => Some(element),
            Node::Text(_) => None,
        })
    }

    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children_named(name).next()
    }

    /// Every element named `name` below this one, outermost first; the
    /// search does not descend into a match.
    pub fn descendants<'a>(&'a self, name: &str) -> Vec<&'a Element> {
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
    pub fn text(&self) -> String {
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

pub fn unescape(text: &str) -> Result<String> {
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
