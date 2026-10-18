//! Bounded property lists. XML entities never resolve external resources.
//! Binary layout follows Apple's CFBinaryPList trailer/object-reference format.
//! Unsupported value kinds refuse instead of dropping dictionary entries.
use super::{Error, Result};
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Boolean(bool),
    Integer(u64),
    Signed(i64),
    Data(Vec<u8>),
    String(String),
    Array(Vec<Value>),
    Dict(BTreeMap<String, Value>),
}
impl Value {
    pub fn dict<const N: usize>(pairs: [(&str, Value); N]) -> Self {
        Self::Dict(pairs.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Dict(d) => d.get(key),
            _ => None,
        }
    }
    pub fn string(&self) -> Result<&str> {
        match self {
            Self::String(s) => Ok(s),
            _ => Err(Error::Invalid("expected plist string")),
        }
    }
    pub fn uint(&self) -> Result<u64> {
        match self {
            Self::Integer(n) => Ok(*n),
            _ => Err(Error::Invalid("expected plist unsigned integer")),
        }
    }
    pub fn boolean(&self) -> Result<bool> {
        match self {
            Self::Boolean(b) => Ok(*b),
            _ => Err(Error::Invalid("expected plist boolean")),
        }
    }
    pub fn data(&self) -> Result<&[u8]> {
        match self {
            Self::Data(b) => Ok(b),
            _ => Err(Error::Invalid("expected plist data")),
        }
    }
    pub fn required(&self, key: &str) -> Result<&Self> {
        self.get(key).ok_or(Error::Invalid("missing plist field"))
    }
    pub fn array(&self) -> Result<&[Value]> {
        match self {
            Self::Array(a) => Ok(a),
            _ => Err(Error::Invalid("expected plist array")),
        }
    }
}
impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Self::String(s.into())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub bytes: usize,
    pub nodes: usize,
    pub depth: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes: 16 * 1024 * 1024,
            nodes: 100_000,
            depth: 64,
        }
    }
}
struct Budget {
    limits: Limits,
    nodes: usize,
    bytes: usize,
}
impl Budget {
    fn new(limits: Limits) -> Self {
        Self {
            limits,
            nodes: 0,
            bytes: 0,
        }
    }
    fn node(&mut self, depth: usize) -> Result<()> {
        self.nodes += 1;
        if depth > self.limits.depth || self.nodes > self.limits.nodes {
            return Err(Error::Limit("plist depth/nodes"));
        }
        Ok(())
    }
    fn bytes(&mut self, n: usize) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(n)
            .ok_or(Error::Limit("plist allocation"))?;
        if self.bytes > self.limits.bytes {
            return Err(Error::Limit("plist decoded bytes"));
        }
        Ok(())
    }
}
pub fn decode(bytes: &[u8], limits: Limits) -> Result<Value> {
    if bytes.starts_with(b"bplist00") {
        if bytes.len() > limits.bytes {
            return Err(Error::Limit("plist input bytes"));
        }
        return Binary::decode(bytes, limits);
    }
    decode_xml(bytes, limits, None)
}

/// Where the elements of one array go instead of the decoded tree.
pub struct Stream<'a> {
    /// Dictionary keys from the root to the array.
    pub path: &'a [&'a str],
    /// Receives each element, with its index, as soon as it is decoded.
    pub sink: &'a mut dyn FnMut(usize, Value) -> Result<()>,
}

/// Decode an XML plist, handing each element of the array at
/// `stream.path` to its sink rather than keeping it: that array decodes
/// empty. Memory then holds only what the sink keeps, which bounds a very
/// large document such as a universal BuildManifest.
pub fn decode_streaming(bytes: &[u8], limits: Limits, stream: Stream<'_>) -> Result<Value> {
    decode_xml(bytes, limits, Some(stream))
}

fn decode_xml(bytes: &[u8], limits: Limits, stream: Option<Stream<'_>>) -> Result<Value> {
    if bytes.len() > limits.bytes {
        return Err(Error::Limit("plist input bytes"));
    }
    let text = core::str::from_utf8(bytes).map_err(|_| Error::Invalid("XML UTF-8"))?;
    let mut xml = Xml {
        rest: text,
        budget: Budget::new(limits),
        stream,
        keys: Vec::new(),
    };
    xml.space();
    if xml.rest.starts_with("<?xml ") {
        xml.skip_to("?>")?;
    }
    xml.space();
    if xml.rest.starts_with("<!DOCTYPE") {
        let end = xml.rest.find('>').ok_or(Error::Invalid("XML doctype"))?;
        let declaration = &xml.rest[..=end];
        if declaration
            != "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"
        {
            return Err(Error::Invalid("unsupported XML doctype"));
        }
        xml.rest = &xml.rest[end + 1..];
    }
    xml.space();
    if !xml.take("<plist version=\"1.0\">") && !xml.take("<plist>") {
        return Err(Error::Invalid("XML plist envelope"));
    }
    let value = xml.value(0)?;
    xml.expect("</plist>")?;
    xml.space();
    if !xml.rest.is_empty() {
        return Err(Error::Invalid("XML trailing bytes"));
    }
    Ok(value)
}
struct Xml<'a, 's> {
    rest: &'a str,
    budget: Budget,
    stream: Option<Stream<'s>>,
    /// The dictionary keys above the current value, kept while streaming.
    keys: Vec<String>,
}
impl<'a> Xml<'a, '_> {
    fn streamed(&self) -> bool {
        self.stream.as_ref().is_some_and(|stream| {
            stream
                .path
                .iter()
                .copied()
                .eq(self.keys.iter().map(String::as_str))
        })
    }
    fn space(&mut self) {
        self.rest = self.rest.trim_start_matches([' ', '\t', '\r', '\n']);
    }
    fn take(&mut self, s: &str) -> bool {
        self.space();
        if let Some(rest) = self.rest.strip_prefix(s) {
            self.rest = rest;
            true
        } else {
            false
        }
    }
    fn expect(&mut self, s: &str) -> Result<()> {
        if self.take(s) {
            Ok(())
        } else {
            Err(Error::Invalid("XML unexpected tag"))
        }
    }
    fn skip_to(&mut self, s: &str) -> Result<()> {
        let n = self
            .rest
            .find(s)
            .ok_or(Error::Invalid("XML truncated header"))?;
        self.rest = &self.rest[n + s.len()..];
        Ok(())
    }
    fn text(&mut self, end: &str) -> Result<String> {
        let n = self
            .rest
            .find(end)
            .ok_or(Error::Invalid("XML unterminated value"))?;
        let raw = &self.rest[..n];
        self.rest = &self.rest[n + end.len()..];
        self.budget.bytes(raw.len())?;
        unescape(raw)
    }
    fn value(&mut self, depth: usize) -> Result<Value> {
        self.budget.node(depth)?;
        if self.take("<true/>") || self.take("<true />") {
            return Ok(Value::Boolean(true));
        }
        if self.take("<false/>") || self.take("<false />") {
            return Ok(Value::Boolean(false));
        }
        if self.take("<string/>") || self.take("<string />") {
            return Ok(Value::String(String::new()));
        }
        if self.take("<data/>") || self.take("<data />") {
            return Ok(Value::Data(Vec::new()));
        }
        if self.take("<string>") {
            return Ok(Value::String(self.text("</string>")?));
        }
        if self.take("<integer>") {
            let s = self.text("</integer>")?;
            let s = s.trim();
            return if s.starts_with('-') {
                s.parse().map(Value::Signed)
            } else if let Some(hex) = s.strip_prefix("0x") {
                u64::from_str_radix(hex, 16).map(Value::Integer)
            } else {
                s.parse().map(Value::Integer)
            }
            .map_err(|_| Error::Invalid("XML integer"));
        }
        if self.take("<data>") {
            return Ok(Value::Data(base64_decode(&self.text("</data>")?)?));
        }
        if self.take("<array/>") || self.take("<array />") {
            return Ok(Value::Array(Vec::new()));
        }
        if self.take("<array>") {
            let streamed = self.streamed();
            let mut a = Vec::new();
            let mut index = 0;
            while !self.take("</array>") {
                let element = self.value(depth + 1)?;
                match &mut self.stream {
                    Some(stream) if streamed => (stream.sink)(index, element)?,
                    _ => a.push(element),
                }
                index += 1;
            }
            return Ok(Value::Array(a));
        }
        if self.take("<dict/>") || self.take("<dict />") {
            return Ok(Value::dict([]));
        }
        if self.take("<dict>") {
            let mut d = BTreeMap::new();
            while !self.take("</dict>") {
                self.budget.node(depth + 1)?;
                let k = if self.take("<key/>") {
                    String::new()
                } else {
                    self.expect("<key>")?;
                    self.text("</key>")?
                };
                let v = if self.stream.is_some() {
                    self.keys.push(k.clone());
                    let v = self.value(depth + 1);
                    self.keys.pop();
                    v?
                } else {
                    self.value(depth + 1)?
                };
                if d.insert(k, v).is_some() {
                    return Err(Error::Invalid("duplicate plist key"));
                }
            }
            return Ok(Value::Dict(d));
        }
        Err(Error::Invalid("unsupported XML plist value"))
    }
}
fn unescape(s: &str) -> Result<String> {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        if rest[..i].contains('<') {
            return Err(Error::Invalid("XML text markup"));
        }
        out.push_str(&rest[..i]);
        rest = &rest[i + 1..];
        let end = rest.find(';').ok_or(Error::Invalid("XML entity"))?;
        let c = match &rest[..end] {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            n if n.starts_with('#') => {
                let n = if let Some(h) = n.strip_prefix("#x") {
                    u32::from_str_radix(h, 16)
                } else {
                    n[1..].parse()
                }
                .map_err(|_| Error::Invalid("XML character reference"))?;
                char::from_u32(n).ok_or(Error::Invalid("XML character"))?
            }
            _ => return Err(Error::Invalid("XML external/unknown entity")),
        };
        out.push(c);
        rest = &rest[end + 1..];
    }
    if rest.contains('<') {
        return Err(Error::Invalid("XML text markup"));
    }
    out.push_str(rest);
    if !out.chars().all(xml_char) {
        return Err(Error::Invalid("XML forbidden character"));
    }
    Ok(out)
}
fn xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r') || (c >= ' ' && c != '\u{fffe}' && c != '\u{ffff}')
}
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
fn base64_decode(s: &str) -> Result<Vec<u8>> {
    let b: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    if !b.len().is_multiple_of(4) {
        return Err(Error::Invalid("base64 length"));
    }
    let mut out = Vec::new();
    for (i, q) in b.as_chunks::<4>().0.iter().enumerate() {
        let digit = |x| {
            BASE64
                .iter()
                .position(|&v| v == x)
                .map(|n| n as u8)
                .ok_or(Error::Invalid("base64 digit"))
        };
        let a = digit(q[0])?;
        let c = digit(q[1])?;
        out.push((a << 2) | (c >> 4));
        if q[2] == b'=' {
            if q[3] != b'=' || c & 15 != 0 || i + 1 != b.len() / 4 {
                return Err(Error::Invalid("base64 padding"));
            }
            continue;
        }
        let d = digit(q[2])?;
        out.push((c << 4) | (d >> 2));
        if q[3] == b'=' {
            if d & 3 != 0 || i + 1 != b.len() / 4 {
                return Err(Error::Invalid("base64 padding"));
            }
            continue;
        }
        out.push((d << 6) | digit(q[3])?);
    }
    Ok(out)
}
fn base64_encode(b: &[u8]) -> String {
    let mut out = String::new();
    for q in b.chunks(3) {
        let a = q[0];
        let c = q.get(1).copied().unwrap_or(0);
        let d = q.get(2).copied().unwrap_or(0);
        for v in [
            BASE64[(a >> 2) as usize],
            BASE64[(((a & 3) << 4) | (c >> 4)) as usize],
            if q.len() > 1 {
                BASE64[(((c & 15) << 2) | (d >> 6)) as usize]
            } else {
                b'='
            },
            if q.len() > 2 {
                BASE64[(d & 63) as usize]
            } else {
                b'='
            },
        ] {
            out.push(v as char);
        }
    }
    out
}
/// Validate the complete tree before encoding (including caller-constructed trees).
fn validate(v: &Value, b: &mut Budget, depth: usize) -> Result<()> {
    b.node(depth)?;
    match v {
        Value::Data(d) => b.bytes(d.len())?,
        Value::String(s) => b.bytes(s.len())?,
        Value::Array(a) => {
            for v in a {
                validate(v, b, depth + 1)?;
            }
        }
        Value::Dict(d) => {
            for (k, v) in d {
                b.node(depth + 1)?;
                b.bytes(k.len())?;
                validate(v, b, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
pub fn encode_xml(v: &Value, limits: Limits) -> Result<Vec<u8>> {
    validate(v, &mut Budget::new(limits), 0)?;
    let mut out =
        String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">");
    fn text(out: &mut String, s: &str) -> Result<()> {
        for c in s.chars() {
            if !xml_char(c) {
                return Err(Error::Invalid("XML forbidden character"));
            }
            out.push_str(match c {
                '&' => "&amp;",
                '<' => "&lt;",
                '>' => "&gt;",
                '"' => "&quot;",
                '\'' => "&apos;",
                _ => {
                    out.push(c);
                    continue;
                }
            });
        }
        Ok(())
    }
    fn emit(v: &Value, o: &mut String, limit: usize) -> Result<()> {
        match v {
            Value::Boolean(b) => o.push_str(if *b { "<true/>" } else { "<false/>" }),
            Value::Integer(n) => {
                o.push_str("<integer>");
                o.push_str(&n.to_string());
                o.push_str("</integer>");
            }
            Value::Signed(n) => {
                o.push_str("<integer>");
                o.push_str(&n.to_string());
                o.push_str("</integer>");
            }
            Value::String(s) => {
                o.push_str("<string>");
                text(o, s)?;
                o.push_str("</string>");
            }
            Value::Data(d) => {
                o.push_str("<data>");
                o.push_str(&base64_encode(d));
                o.push_str("</data>");
            }
            Value::Array(a) => {
                o.push_str("<array>");
                for v in a {
                    emit(v, o, limit)?;
                }
                o.push_str("</array>");
            }
            Value::Dict(d) => {
                o.push_str("<dict>");
                for (k, v) in d {
                    o.push_str("<key>");
                    text(o, k)?;
                    o.push_str("</key>");
                    emit(v, o, limit)?;
                }
                o.push_str("</dict>");
            }
        }
        if o.len() > limit {
            return Err(Error::Limit("XML encoded bytes"));
        }
        Ok(())
    }
    emit(v, &mut out, limits.bytes)?;
    out.push_str("</plist>\n");
    if out.len() > limits.bytes {
        return Err(Error::Limit("XML encoded bytes"));
    }
    Ok(out.into_bytes())
}

const TRAILER: usize = 32;
struct Binary<'a> {
    bytes: &'a [u8],
    offsets: Vec<usize>,
    refs: usize,
    table: usize,
    budget: Budget,
}
fn be(b: &[u8]) -> Result<u64> {
    if b.is_empty() || b.len() > 8 {
        return Err(Error::Invalid("bplist integer width"));
    }
    Ok(b.iter().fold(0, |n, &v| (n << 8) | v as u64))
}
impl<'a> Binary<'a> {
    fn decode(bytes: &'a [u8], limits: Limits) -> Result<Value> {
        let t = bytes
            .len()
            .checked_sub(TRAILER)
            .ok_or(Error::Invalid("bplist trailer"))?;
        if t < 8 {
            return Err(Error::Invalid("bplist length"));
        }
        let tr = &bytes[t..];
        let width = tr[6] as usize;
        let refs = tr[7] as usize;
        if !(1..=8).contains(&width) || !(1..=8).contains(&refs) {
            return Err(Error::Invalid("bplist widths"));
        }
        let cv = |s| usize::try_from(be(s)?).map_err(|_| Error::Limit("bplist address"));
        let count = cv(&tr[8..16])?;
        let root = cv(&tr[16..24])?;
        let table = cv(&tr[24..32])?;
        if count == 0
            || count > limits.nodes
            || root >= count
            || table < 8
            || table > t
            || count > (t - table) / width
        {
            return Err(Error::Invalid("bplist offset table"));
        }
        let mut offsets = Vec::new();
        for i in 0..count {
            let at = cv(&bytes[table + i * width..table + (i + 1) * width])?;
            if at < 8 || at >= table {
                return Err(Error::Invalid("bplist object offset"));
            }
            offsets.push(at);
        }
        Self {
            bytes,
            offsets,
            refs,
            table,
            budget: Budget::new(limits),
        }
        .object(root, 0)
    }
    fn slice(&self, at: usize, n: usize) -> Result<&'a [u8]> {
        let end = at
            .checked_add(n)
            .ok_or(Error::Invalid("bplist range overflow"))?;
        if end > self.table {
            return Err(Error::Invalid("bplist truncated object"));
        }
        self.bytes
            .get(at..end)
            .ok_or(Error::Invalid("bplist range"))
    }
    fn length(&self, at: &mut usize, info: u8) -> Result<usize> {
        if info < 15 {
            return Ok(info as usize);
        }
        let marker = self.slice(*at, 1)?[0];
        *at += 1;
        if marker >> 4 != 1 || marker & 15 > 3 {
            return Err(Error::Invalid("bplist length integer"));
        }
        let width = 1usize << (marker & 15);
        let n = be(self.slice(*at, width)?)?;
        *at += width;
        usize::try_from(n).map_err(|_| Error::Limit("bplist length"))
    }
    fn reference(&self, at: usize) -> Result<usize> {
        let n = usize::try_from(be(self.slice(at, self.refs)?)?)
            .map_err(|_| Error::Invalid("bplist reference"))?;
        if n >= self.offsets.len() {
            return Err(Error::Invalid("bplist missing object"));
        }
        Ok(n)
    }
    fn object(&mut self, index: usize, depth: usize) -> Result<Value> {
        self.budget.node(depth)?;
        let mut at = self.offsets[index];
        let marker = self.bytes[at];
        at += 1;
        let info = marker & 15;
        match marker >> 4 {
            0 => match info {
                8 => Ok(Value::Boolean(false)),
                9 => Ok(Value::Boolean(true)),
                _ => Err(Error::Invalid("unsupported bplist singleton")),
            },
            1 => {
                if info > 4 {
                    return Err(Error::Invalid("bplist integer width"));
                }
                let w = 1usize << info;
                let b = self.slice(at, w)?;
                if w == 16 {
                    if b[..8] != [0; 8] {
                        return Err(Error::Invalid("bplist wide integer"));
                    }
                    return Ok(Value::Integer(be(&b[8..])?));
                }
                let n = be(b)?;
                if w == 8 && n >> 63 != 0 {
                    Ok(Value::Signed(n as i64))
                } else {
                    Ok(Value::Integer(n))
                }
            }
            4..=6 => {
                let n = self.length(&mut at, info)?;
                let width = if marker >> 4 == 6 { 2 } else { 1 };
                let size = n.checked_mul(width).ok_or(Error::Limit("bplist scalar"))?;
                self.budget.bytes(size)?;
                let b = self.slice(at, size)?;
                if marker >> 4 == 4 {
                    return Ok(Value::Data(b.to_vec()));
                }
                let s = if width == 2 {
                    String::from_utf16(
                        &b.as_chunks::<2>()
                            .0
                            .iter()
                            .map(|v| u16::from_be_bytes([v[0], v[1]]))
                            .collect::<Vec<_>>(),
                    )
                    .map_err(|_| Error::Invalid("bplist UTF-16"))?
                } else {
                    if !b.is_ascii() {
                        return Err(Error::Invalid("bplist ASCII"));
                    }
                    core::str::from_utf8(b).unwrap().into()
                };
                Ok(Value::String(s))
            }
            10 | 13 => {
                let n = self.length(&mut at, info)?;
                let dict = marker >> 4 == 13;
                let refs = n
                    .checked_mul(if dict { 2 } else { 1 })
                    .and_then(|n| n.checked_mul(self.refs))
                    .ok_or(Error::Limit("bplist references"))?;
                self.slice(at, refs)?;
                if n > self.budget.limits.nodes.saturating_sub(self.budget.nodes) {
                    return Err(Error::Limit("bplist collection nodes"));
                }
                if dict {
                    let mut d = BTreeMap::new();
                    for i in 0..n {
                        let key = self.object(self.reference(at + i * self.refs)?, depth + 1)?;
                        let v =
                            self.object(self.reference(at + (n + i) * self.refs)?, depth + 1)?;
                        let Value::String(k) = key else {
                            return Err(Error::Invalid("bplist dictionary key"));
                        };
                        if d.insert(k, v).is_some() {
                            return Err(Error::Invalid("duplicate plist key"));
                        }
                    }
                    Ok(Value::Dict(d))
                } else {
                    let mut a = Vec::new();
                    for i in 0..n {
                        a.push(self.object(self.reference(at + i * self.refs)?, depth + 1)?);
                    }
                    Ok(Value::Array(a))
                }
            }
            _ => Err(Error::Invalid("unsupported bplist object kind")),
        }
    }
}
/// Canonical, unshared object table; 8-byte references avoid narrowing casts.
pub fn encode_binary(v: &Value, limits: Limits) -> Result<Vec<u8>> {
    validate(v, &mut Budget::new(limits), 0)?;
    let mut objects: Vec<Vec<u8>> = Vec::new();
    fn size(out: &mut Vec<u8>, tag: u8, n: usize) {
        if n < 15 {
            out.push(tag | n as u8);
        } else {
            out.extend_from_slice(&[tag | 15, 0x13]);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    fn emit(v: &Value, objects: &mut Vec<Vec<u8>>) -> usize {
        let mut out = Vec::new();
        match v {
            Value::Boolean(b) => out.push(if *b { 9 } else { 8 }),
            Value::Integer(n) => {
                if *n > i64::MAX as u64 {
                    out.push(0x14);
                    out.extend_from_slice(&[0; 8]);
                } else {
                    out.push(0x13);
                }
                out.extend_from_slice(&n.to_be_bytes());
            }
            Value::Signed(n) => {
                out.push(0x13);
                out.extend_from_slice(&n.to_be_bytes());
            }
            Value::Data(b) => {
                size(&mut out, 0x40, b.len());
                out.extend_from_slice(b);
            }
            Value::String(s) => {
                if s.is_ascii() {
                    size(&mut out, 0x50, s.len());
                    out.extend_from_slice(s.as_bytes());
                } else {
                    size(&mut out, 0x60, s.encode_utf16().count());
                    for c in s.encode_utf16() {
                        out.extend_from_slice(&c.to_be_bytes());
                    }
                }
            }
            Value::Array(a) => {
                size(&mut out, 0xa0, a.len());
                for v in a {
                    out.extend_from_slice(&(emit(v, objects) as u64).to_be_bytes());
                }
            }
            Value::Dict(d) => {
                size(&mut out, 0xd0, d.len());
                for k in d.keys() {
                    out.extend_from_slice(
                        &(emit(&Value::String(k.clone()), objects) as u64).to_be_bytes(),
                    );
                }
                for v in d.values() {
                    out.extend_from_slice(&(emit(v, objects) as u64).to_be_bytes());
                }
            }
        }
        let i = objects.len();
        objects.push(out);
        i
    }
    let root = emit(v, &mut objects);
    let mut out = b"bplist00".to_vec();
    let mut offsets = Vec::new();
    for o in &objects {
        offsets.push(out.len() as u64);
        out.extend_from_slice(o);
        if out.len() > limits.bytes {
            return Err(Error::Limit("bplist encoded bytes"));
        }
    }
    let table = out.len() as u64;
    for off in offsets {
        out.extend_from_slice(&off.to_be_bytes());
    }
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0, 8, 8]);
    out.extend_from_slice(&(objects.len() as u64).to_be_bytes());
    out.extend_from_slice(&(root as u64).to_be_bytes());
    out.extend_from_slice(&table.to_be_bytes());
    if out.len() > limits.bytes {
        return Err(Error::Limit("bplist encoded bytes"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn streaming_hands_one_arrays_elements_to_the_sink() {
        let xml = br#"<plist version="1.0"><dict><key>Other</key><array><string>kept</string></array><key>Ids</key><array><dict><key>Ids</key><array><integer>9</integer></array></dict><integer>7</integer></array></dict></plist>"#;
        let mut seen = Vec::new();
        let mut sink = |index, value| {
            seen.push((index, value));
            Ok(())
        };
        let tree = decode_streaming(
            xml,
            Limits::default(),
            Stream {
                path: &["Ids"],
                sink: &mut sink,
            },
        )
        .unwrap();
        assert_eq!(tree.required("Ids").unwrap().array().unwrap(), []);
        assert_eq!(tree.required("Other").unwrap().array().unwrap().len(), 1);
        // A nested array of the same key name is not the root path.
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[1], (1, Value::Integer(7)));
        assert_eq!(seen[0].1.required("Ids").unwrap().array().unwrap().len(), 1);
        let mut refuse = |_, _| Err(Error::Invalid("sink refused"));
        let stream = Stream {
            path: &["Ids"],
            sink: &mut refuse,
        };
        assert!(decode_streaming(xml, Limits::default(), stream).is_err());
    }
    #[test]
    fn both_encodings_preserve_restore_dictionary() {
        let v = Value::dict([
            ("s", Value::from("<&\"你好🦀")),
            ("n", Value::Integer(u64::MAX)),
            ("negative", Value::Signed(-2)),
            ("data", Value::Data(vec![0, 255, 12, 34])),
            (
                "array",
                Value::Array(vec![Value::Boolean(true), Value::dict([])]),
            ),
        ]);
        for b in [
            encode_xml(&v, Limits::default()).unwrap(),
            encode_binary(&v, Limits::default()).unwrap(),
        ] {
            assert_eq!(decode(&b, Limits::default()).unwrap(), v);
            for i in 0..b.len().saturating_sub(1) {
                assert!(decode(&b[..i], Limits::default()).is_err());
            }
        }
    }
    #[test]
    fn independent_python_binary_fixture_and_xml_entities() {
        // Python plistlib.dumps({"x": [True, 42]}, FMT_BINARY).
        let b=hex::decode("62706c6973743030d101025178a2030409102a080b0d10110000000000000101000000000000000500000000000000000000000000000013").unwrap();
        assert_eq!(
            decode(&b, Limits::default()).unwrap(),
            Value::dict([(
                "x",
                Value::Array(vec![Value::Boolean(true), Value::Integer(42)])
            )])
        );
        assert_eq!(
            decode(
                b"<plist><string>&#x1f980;&amp;</string></plist>",
                Limits::default()
            )
            .unwrap(),
            Value::from("🦀&")
        );
        for b in [
            b"<plist><data>AB==</data></plist>".as_slice(),
            b"<plist><dict><key>x</key><true/><key>x</key><false/></dict></plist>",
            b"<plist><string>&external;</string></plist>",
        ] {
            assert!(decode(b, Limits::default()).is_err());
        }
    }
    #[test]
    fn budgets_stop_recursive_references_and_expansion() {
        let v = Value::Array(vec![Value::from("x")]);
        let b = encode_binary(&v, Limits::default()).unwrap();
        assert!(
            decode(
                &b,
                Limits {
                    nodes: 1,
                    ..Limits::default()
                }
            )
            .is_err()
        );
        let mut cycle = b.clone();
        cycle[11..19].copy_from_slice(&1u64.to_be_bytes());
        assert!(
            decode(
                &cycle,
                Limits {
                    depth: 4,
                    ..Limits::default()
                }
            )
            .is_err()
        );
        assert!(
            encode_xml(
                &v,
                Limits {
                    bytes: 10,
                    ..Limits::default()
                }
            )
            .is_err()
        );
    }
}
