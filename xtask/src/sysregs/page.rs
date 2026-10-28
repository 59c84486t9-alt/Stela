//! A register page as an element tree, read with quick-xml.

use anyhow::{Context, Result, bail, ensure};
use quick_xml::{
    Reader, XmlVersion,
    escape::resolve_predefined_entity,
    events::{BytesStart, Event},
};

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

    /// The elements named `name` below this one, in document order.
    pub fn descendants(&self, name: &str) -> Vec<&Element> {
        let mut found = Vec::new();
        let mut stack: Vec<&Element> = self.elements().collect();
        stack.reverse();
        while let Some(element) = stack.pop() {
            if element.name == name {
                found.push(element);
            }
            let start = stack.len();
            stack.extend(element.elements());
            stack[start..].reverse();
        }
        found
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
/// Text that is only whitespace between tags is dropped.
pub fn parse(text: &str) -> Result<Element> {
    let mut reader = Reader::from_str(text);
    let mut stack = vec![Element::default()];
    let mut pending = String::new();
    loop {
        let event = reader
            .read_event()
            .with_context(|| format!("XML at byte {}", reader.buffer_position()))?;
        match event {
            Event::Text(text) => pending.push_str(&text.xml10_content()),
            Event::CData(data) => pending.push_str(&data.xml10_content()),
            Event::GeneralRef(reference) => {
                if let Some(c) = reference.resolve_char_ref()? {
                    pending.push(c);
                } else {
                    let name = reference.xml10_content();
                    let value = resolve_predefined_entity(&name)
                        .with_context(|| format!("unknown entity &{name};"))?;
                    pending.push_str(value);
                }
            }
            Event::Start(start) => {
                flush(&mut stack, &mut pending);
                stack.push(element(&start)?);
            }
            Event::Empty(start) => {
                flush(&mut stack, &mut pending);
                let element = element(&start)?;
                stack
                    .last_mut()
                    .context("element outside the document")?
                    .children
                    .push(Node::Element(element));
            }
            Event::End(_) => {
                flush(&mut stack, &mut pending);
                let element = stack.pop().context("unbalanced end tag")?;
                stack
                    .last_mut()
                    .context("end tag closes the document")?
                    .children
                    .push(Node::Element(element));
            }
            Event::Eof => break,
            Event::Comment(_) | Event::Decl(_) | Event::PI(_) | Event::DocType(_) => {}
        }
    }
    flush(&mut stack, &mut pending);
    ensure!(
        stack.len() == 1,
        "unclosed <{}>",
        stack.last().map_or("", |e| e.name.as_str())
    );
    Ok(stack.pop().expect("the document root"))
}

fn element(start: &BytesStart<'_>) -> Result<Element> {
    let name = start.name().as_ref().to_owned();
    let mut attributes = Vec::new();
    for attribute in start.attributes() {
        let attribute = attribute?;
        let key = attribute.key.as_ref().to_owned();
        attributes.push((
            key,
            attribute
                .normalized_value(XmlVersion::Implicit1_0)?
                .into_owned(),
        ));
    }
    if name.is_empty() {
        bail!("an element without a name");
    }
    Ok(Element {
        name,
        attributes,
        children: Vec::new(),
    })
}

fn flush(stack: &mut [Element], pending: &mut String) {
    let text = std::mem::take(pending);
    if !text.trim().is_empty()
        && let Some(element) = stack.last_mut()
    {
        element.children.push(Node::Text(text));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entities_and_balance() {
        let page = parse("<a x='&lt;1'>a&lt;b&amp;&#x41;&#66;<b/></a>").unwrap();
        let a = page.child("a").unwrap();
        assert_eq!(a.attribute("x"), Some("<1"));
        assert_eq!(a.text(), "a<b&AB");
        assert_eq!(a.descendants("b").len(), 1);
        assert!(parse("<a><b></a>").is_err());
        assert!(parse("<a>").is_err());
    }
}
