//! The XML property lists `OSUnserializeXML` reads: the forms `Info.plist`
//! and the prelink information have in the kernel. A date or a real has no
//! form there, so reading one refuses it. `stela.efi` links kexts, so this
//! needs no `std`.
use crate::Result;
use alloc::{
    borrow::ToOwned,
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
use stela_contracts::{refuse, require};

pub type Dictionary = BTreeMap<String, Value>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    Array(Vec<Value>),
    Boolean(bool),
    Data(Vec<u8>),
    Dictionary(Dictionary),
    Integer(u64),
    String(String),
}

impl Value {
    pub fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_dictionary(&self) -> Option<&Dictionary> {
        match self {
            Self::Dictionary(dictionary) => Some(dictionary),
            _ => None,
        }
    }

    pub fn into_dictionary(self) -> Option<Dictionary> {
        match self {
            Self::Dictionary(dictionary) => Some(dictionary),
            _ => None,
        }
    }
}

/// One element's opening: its name, and whether it closed itself.
struct Tag<'a> {
    name: &'a str,
    empty: bool,
}

struct Reader<'a> {
    rest: &'a str,
}

impl<'a> Reader<'a> {
    /// Past white space, comments, declarations and the document type.
    fn skip(&mut self) -> Result<()> {
        loop {
            self.rest = self.rest.trim_start();
            let (open, close) = if self.rest.starts_with("<!--") {
                ("<!--", "-->")
            } else if self.rest.starts_with("<?") {
                ("<?", "?>")
            } else if self.rest.starts_with("<!") {
                ("<!", ">")
            } else {
                return Ok(());
            };
            let (_, rest) = self.rest[open.len()..]
                .split_once(close)
                .ok_or(refuse!("Info.plist ends inside a declaration"))?;
            self.rest = rest;
        }
    }

    fn open(&mut self) -> Result<Tag<'a>> {
        self.skip()?;
        let rest = self
            .rest
            .strip_prefix('<')
            .ok_or(refuse!("Info.plist has text where an element belongs"))?;
        let (tag, rest) = rest
            .split_once('>')
            .ok_or(refuse!("Info.plist ends inside an element"))?;
        self.rest = rest;
        let (tag, empty) = match tag.strip_suffix('/') {
            Some(tag) => (tag, true),
            None => (tag, false),
        };
        let name = tag.split_ascii_whitespace().next().unwrap_or_default();
        Ok(Tag { name, empty })
    }

    /// Past `</name>`, if it comes next.
    fn closes(&mut self, name: &str) -> Result<bool> {
        self.skip()?;
        let close = self
            .rest
            .strip_prefix("</")
            .and_then(|rest| rest.strip_prefix(name))
            .and_then(|rest| rest.trim_start().strip_prefix('>'));
        if let Some(rest) = close {
            self.rest = rest;
        }
        Ok(close.is_some())
    }

    /// The raw text before `</name>`, and past it.
    fn text(&mut self, tag: &Tag<'_>) -> Result<&'a str> {
        if tag.empty {
            return Ok("");
        }
        let (text, rest) = self
            .rest
            .split_once("</")
            .ok_or(refuse!("Info.plist ends inside an element"))?;
        self.rest = rest;
        let rest = self
            .rest
            .strip_prefix(tag.name)
            .and_then(|rest| rest.trim_start().strip_prefix('>'))
            .ok_or(refuse!("Info.plist closes an element it did not open"))?;
        self.rest = rest;
        Ok(text)
    }

    fn value(&mut self) -> Result<Value> {
        let tag = self.open()?;
        match tag.name {
            "true" | "false" if tag.empty => Ok(Value::Boolean(tag.name == "true")),
            "string" => Ok(Value::String(unescape(self.text(&tag)?)?)),
            "integer" => integer(self.text(&tag)?).map(Value::Integer),
            "data" => decode(self.text(&tag)?).map(Value::Data),
            "array" => self.array(&tag).map(Value::Array),
            "dict" => self.dictionary(&tag).map(Value::Dictionary),
            name => Err(refuse!(
                "Info.plist holds a value the kernel cannot read: {name}",
                name
            )
            .into()),
        }
    }

    fn array(&mut self, tag: &Tag<'_>) -> Result<Vec<Value>> {
        let mut values = Vec::new();
        while !tag.empty && !self.closes(tag.name)? {
            values.push(self.value()?);
        }
        Ok(values)
    }

    fn dictionary(&mut self, tag: &Tag<'_>) -> Result<Dictionary> {
        let mut dictionary = Dictionary::new();
        while !tag.empty && !self.closes(tag.name)? {
            let key = self.open()?;
            require!(key.name == "key", "Info.plist has a value with no key");
            let key = unescape(self.text(&key)?)?;
            dictionary.insert(key, self.value()?);
        }
        Ok(dictionary)
    }
}

fn integer(text: &str) -> Result<u64> {
    let text = text.trim();
    let parsed = match text.strip_prefix("0x") {
        Some(digits) => u64::from_str_radix(digits, 16),
        None => text.parse(),
    };
    parsed.map_err(|_| refuse!("Info.plist has a bad integer: {text}", text).into())
}

fn unescape(text: &str) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some((before, after)) = rest.split_once('&') {
        out.push_str(before);
        let (entity, after) = after
            .split_once(';')
            .ok_or(refuse!("Info.plist has a bare ampersand"))?;
        out.push(match entity {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            entity => {
                return Err(refuse!("Info.plist names an entity: {entity}", entity).into());
            }
        });
        rest = after;
    }
    out.push_str(rest);
    Ok(out)
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn decode(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let (mut bits, mut count) = (0u32, 0u32);
    for byte in text.bytes() {
        if byte.is_ascii_whitespace() || byte == b'=' {
            continue;
        }
        let digit = ALPHABET
            .iter()
            .position(|&letter| letter == byte)
            .ok_or(refuse!("Info.plist has bad base64 data"))?;
        bits = bits << 6 | digit as u32;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    Ok(out)
}

fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let bits = chunk
            .iter()
            .fold(0u32, |bits, &byte| bits << 8 | u32::from(byte))
            << (8 * (3 - chunk.len()));
        for digit in 0..4 {
            if digit <= chunk.len() {
                out.push(ALPHABET[(bits >> (18 - 6 * digit) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Array(values) => {
            out.push_str("<array>");
            values.iter().for_each(|value| write_value(out, value));
            out.push_str("</array>");
        }
        Value::Boolean(true) => out.push_str("<true/>"),
        Value::Boolean(false) => out.push_str("<false/>"),
        Value::Data(data) => out.push_str(&format!("<data>{}</data>", encode(data))),
        Value::Dictionary(dictionary) => {
            out.push_str("<dict>");
            for (key, value) in dictionary {
                out.push_str(&format!("<key>{}</key>", escape(key)));
                write_value(out, value);
            }
            out.push_str("</dict>");
        }
        Value::Integer(value) => out.push_str(&format!("<integer>{value}</integer>")),
        Value::String(text) => out.push_str(&format!("<string>{}</string>", escape(text))),
    }
}

/// `xml`'s root value.
pub fn parse(xml: &[u8]) -> Result<Value> {
    let rest = core::str::from_utf8(xml).map_err(|_| refuse!("Info.plist is not UTF-8"))?;
    let mut reader = Reader { rest };
    let root = reader.open()?;
    require!(root.name == "plist", "Info.plist is not a property list");
    let value = reader.value()?;
    require!(
        reader.closes(root.name)?,
        "Info.plist holds more than one value"
    );
    Ok(value)
}

/// `value` as a document.
pub fn write(value: &Value) -> Vec<u8> {
    let mut out = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">".to_owned();
    write_value(&mut out, value);
    out.push_str("</plist>\n");
    out.into_bytes()
}

impl From<&str> for Value {
    fn from(text: &str) -> Self {
        Self::String(text.to_string())
    }
}

impl From<u64> for Value {
    fn from(value: u64) -> Self {
        Self::Integer(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOCUMENT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<!-- a comment -->
	<key>Name &amp; more</key>
	<string>a &lt;b&gt;</string>
	<key>Count</key>
	<integer>0x20</integer>
	<key>List</key>
	<array>
		<true/>
		<false/>
		<string/>
		<dict/>
		<array/>
	</array>
	<key>Bytes</key>
	<data>
	AQID
	BA==
	</data>
</dict>
</plist>
"#;

    #[test]
    fn reads_what_the_crate_reads_and_writes_what_it_reads() {
        let value = parse(DOCUMENT.as_bytes()).unwrap();
        let dictionary = value.as_dictionary().unwrap();
        assert_eq!(dictionary["Name & more"].as_string(), Some("a <b>"));
        assert_eq!(dictionary["Count"], Value::Integer(32));
        assert_eq!(dictionary["Bytes"], Value::Data(alloc::vec![1, 2, 3, 4]));
        let Value::Array(list) = &dictionary["List"] else {
            panic!("an array");
        };
        assert_eq!(list.len(), 5);
        assert_eq!(list[2].as_string(), Some(""));
        assert_eq!(parse(&write(&value)).unwrap(), value);

        // An independent reader agrees.
        let written = write(&value);
        let other = ::plist::Value::from_reader_xml(&written[..]).unwrap();
        let other = other.as_dictionary().unwrap();
        assert_eq!(other["Name & more"].as_string(), Some("a <b>"));
        assert_eq!(other["Bytes"].as_data(), Some(&[1, 2, 3, 4][..]));
    }

    #[test]
    fn base64_rounds_every_tail() {
        for length in 0..7 {
            let data: Vec<u8> = (0..length).map(|byte| byte * 37 + 1).collect();
            assert_eq!(decode(&encode(&data)).unwrap(), data);
        }
    }

    #[test]
    fn refuses_what_the_kernel_cannot_read() {
        let wrap = |value: &str| format!("<plist version=\"1.0\">{value}</plist>");
        for value in [
            "<real>1.5</real>",
            "<date>2026-01-01T00:00:00Z</date>",
            "<dict><string>no key</string></dict>",
            "<string>a</string><string>b</string>",
            "<string>unclosed",
            "<string>&unknown;</string>",
            "<integer>x</integer>",
        ] {
            assert!(parse(wrap(value).as_bytes()).is_err(), "{value}");
        }
    }
}
