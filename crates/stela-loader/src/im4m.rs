//! Image4 manifests (IM4M): the signed property lists iBoot evaluates and
//! summarizes into `/chosen` for SPTM, TXM and XNU.
//!
//! `IM4M ::= SEQUENCE { IA5 "IM4M", INTEGER version, SET { MANB }, OCTET
//! STRING signature, SEQUENCE certificates }`. `MANB` and each entry inside
//! it are private-class DER tags named by their four characters, holding
//! `SEQUENCE { IA5 name, SET { properties } }`; a property is
//! `SEQUENCE { IA5 name, value }`. `MANP` carries the manifest-wide
//! properties and every other entry describes one boot object
//! ([blacktop/ipsw img4 manifest](https://github.com/blacktop/ipsw/blob/master/pkg/img4/manifest.go)).
//! The signature and certificates are kept but not evaluated.
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use sha2::{Digest, Sha384};

const CLASS_UNIVERSAL: u8 = 0;
const CLASS_PRIVATE: u8 = 3;
const TAG_BOOLEAN: u32 = 1;
const TAG_INTEGER: u32 = 2;
const TAG_OCTET_STRING: u32 = 4;
const TAG_IA5_STRING: u32 = 22;
const TAG_SEQUENCE: u32 = 16;
const TAG_SET: u32 = 17;
const MANIFEST_PROPERTIES: &str = "MANP";
pub const SHA384_BYTES: usize = 48;

#[derive(Debug, Clone, Copy)]
struct Header {
    class: u8,
    constructed: bool,
    number: u32,
}

struct Der<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Der<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn byte(&mut self) -> Result<u8> {
        let byte = *self.bytes.get(self.position).context("truncated DER")?;
        self.position += 1;
        Ok(byte)
    }

    fn next(&mut self) -> Result<(Header, &'a [u8])> {
        let first = self.byte()?;
        let mut number = u32::from(first & 0x1f);
        if number == 0x1f {
            number = 0;
            loop {
                let byte = self.byte()?;
                ensure!(number >> 25 == 0, "DER tag number overflows");
                number = (number << 7) | u32::from(byte & 0x7f);
                if byte & 0x80 == 0 {
                    break;
                }
            }
        }
        let length_byte = self.byte()?;
        let length = if length_byte < 0x80 {
            usize::from(length_byte)
        } else {
            let width = usize::from(length_byte & 0x7f);
            ensure!(
                (1..=size_of::<usize>()).contains(&width),
                "indefinite or oversized DER length"
            );
            let mut length = 0usize;
            for _ in 0..width {
                let byte = usize::from(self.byte()?);
                length = length
                    .checked_mul(256)
                    .and_then(|n| n.checked_add(byte))
                    .context("DER length overflow")?;
            }
            length
        };
        let end = self
            .position
            .checked_add(length)
            .context("DER range overflow")?;
        let value = self
            .bytes
            .get(self.position..end)
            .context("DER value is out of bounds")?;
        self.position = end;
        Ok((
            Header {
                class: first >> 6,
                constructed: first & 0x20 != 0,
                number,
            },
            value,
        ))
    }

    fn universal(&mut self, number: u32) -> Result<&'a [u8]> {
        let (header, value) = self.next()?;
        ensure!(
            header.class == CLASS_UNIVERSAL && header.number == number,
            "expected universal DER tag {number}, found class {} tag {}",
            header.class,
            header.number
        );
        Ok(value)
    }

    fn done(&self) -> bool {
        self.position == self.bytes.len()
    }
}

fn four_cc(number: u32) -> Result<String> {
    let text = String::from_utf8(number.to_be_bytes().to_vec())?;
    ensure!(
        text.bytes().all(|b| b.is_ascii_graphic()),
        "private tag {number:#x} is not a four-character name"
    );
    Ok(text)
}

/// One manifest property value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "type", content = "value")]
pub enum Value {
    Integer(u64),
    Boolean(bool),
    /// An OCTET STRING, hex-encoded when serialized.
    #[serde(serialize_with = "hex_bytes")]
    Data(Vec<u8>),
}

fn hex_bytes<S: serde::Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&hex::encode(bytes))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Property {
    pub name: String,
    pub value: Value,
}

/// A boot object the manifest admits, such as `krnl` with its `DGST`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Object {
    pub tag: String,
    pub properties: Vec<Property>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Manifest {
    pub version: u64,
    /// `MANP`, in manifest order.
    pub properties: Vec<Property>,
    pub objects: Vec<Object>,
    /// SHA-384 of the whole IM4M encoding.
    pub sha384: String,
    #[serde(skip)]
    pub digest: [u8; SHA384_BYTES],
    pub signature_validated: bool,
}

impl Manifest {
    pub fn property(&self, name: &str) -> Option<&Value> {
        self.properties
            .iter()
            .find(|p| p.name == name)
            .map(|p| &p.value)
    }

    pub fn object(&self, tag: &str) -> Option<&Object> {
        self.objects.iter().find(|o| o.tag == tag)
    }
}

fn integer(bytes: &[u8]) -> Result<u64> {
    ensure!(
        !bytes.is_empty() && bytes[0] & 0x80 == 0,
        "negative or empty DER integer"
    );
    let digits = if bytes.len() > 1 && bytes[0] == 0 {
        &bytes[1..]
    } else {
        bytes
    };
    ensure!(digits.len() <= 8, "DER integer exceeds 64 bits");
    Ok(digits.iter().fold(0, |n, &b| (n << 8) | u64::from(b)))
}

fn value(header: Header, bytes: &[u8]) -> Result<Value> {
    ensure!(
        header.class == CLASS_UNIVERSAL && !header.constructed,
        "unsupported manifest property value"
    );
    Ok(match header.number {
        TAG_INTEGER => Value::Integer(integer(bytes)?),
        TAG_BOOLEAN => {
            ensure!(bytes.len() == 1, "DER boolean is not one byte");
            Value::Boolean(bytes[0] != 0)
        }
        TAG_OCTET_STRING => Value::Data(bytes.to_vec()),
        other => bail!("unsupported manifest property value tag {other}"),
    })
}

/// `[PRIVATE name] SEQUENCE { IA5 name, inner }` → `(name, inner)`.
fn named<'a>(header: Header, bytes: &'a [u8]) -> Result<(String, Der<'a>)> {
    ensure!(
        header.class == CLASS_PRIVATE && header.constructed,
        "expected a private named manifest entry"
    );
    let name = four_cc(header.number)?;
    let mut outer = Der::new(bytes);
    let mut sequence = Der::new(outer.universal(TAG_SEQUENCE)?);
    ensure!(outer.done(), "trailing bytes after manifest entry {name}");
    let label = sequence.universal(TAG_IA5_STRING)?;
    ensure!(
        label == name.as_bytes(),
        "manifest entry {name} is labeled {}",
        String::from_utf8_lossy(label)
    );
    Ok((name, sequence))
}

fn properties(set: &[u8]) -> Result<Vec<Property>> {
    let mut reader = Der::new(set);
    let mut properties = vec![];
    while !reader.done() {
        let (header, bytes) = reader.next()?;
        let (name, mut entry) = named(header, bytes)?;
        let (value_header, value_bytes) = entry.next()?;
        ensure!(entry.done(), "trailing fields in manifest property {name}");
        properties.push(Property {
            name,
            value: value(value_header, value_bytes)?,
        });
    }
    Ok(properties)
}

pub fn sha384(bytes: &[u8]) -> [u8; SHA384_BYTES] {
    Sha384::digest(bytes).into()
}

/// Parse an IM4M without evaluating its signature.
pub fn parse(bytes: &[u8]) -> Result<Manifest> {
    let mut outer = Der::new(bytes);
    let mut sequence = Der::new(outer.universal(TAG_SEQUENCE)?);
    ensure!(outer.done(), "trailing bytes after IM4M");
    ensure!(
        sequence.universal(TAG_IA5_STRING)? == b"IM4M",
        "expected an IM4M"
    );
    let version = integer(sequence.universal(TAG_INTEGER)?)?;
    let mut body = Der::new(sequence.universal(TAG_SET)?);
    let (header, manb) = body.next()?;
    ensure!(body.done(), "IM4M body holds more than MANB");
    let (name, mut manb) = named(header, manb)?;
    ensure!(name == "MANB", "IM4M body is {name}, expected MANB");
    let mut entries = Der::new(manb.universal(TAG_SET)?);
    ensure!(manb.done(), "trailing fields in MANB");
    let mut manifest_properties = None;
    let mut objects = vec![];
    while !entries.done() {
        let (header, bytes) = entries.next()?;
        let (tag, mut entry) = named(header, bytes)?;
        let list = properties(entry.universal(TAG_SET)?)?;
        ensure!(entry.done(), "trailing fields in manifest entry {tag}");
        if tag == MANIFEST_PROPERTIES {
            ensure!(manifest_properties.is_none(), "duplicate MANP");
            manifest_properties = Some(list);
        } else {
            objects.push(Object {
                tag,
                properties: list,
            });
        }
    }
    sequence.universal(TAG_OCTET_STRING)?;
    sequence.universal(TAG_SEQUENCE)?;
    ensure!(sequence.done(), "trailing fields after IM4M certificates");
    Ok(Manifest {
        version,
        properties: manifest_properties.context("IM4M has no MANP")?,
        objects,
        sha384: hex::encode(sha384(bytes)),
        digest: sha384(bytes),
        signature_validated: false,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn der(first: &[u8], value: &[u8]) -> Vec<u8> {
        let mut out = first.to_vec();
        if value.len() < 0x80 {
            out.push(value.len() as u8);
        } else {
            let length = (value.len() as u32).to_be_bytes();
            let skip = length.iter().take_while(|&&b| b == 0).count();
            out.push(0x80 | (4 - skip) as u8);
            out.extend(&length[skip..]);
        }
        out.extend(value);
        out
    }

    /// The identifier octets of a private constructed tag named `name`.
    fn private(name: &str) -> Vec<u8> {
        let mut number = u32::from_be_bytes(name.as_bytes().try_into().unwrap());
        let mut groups = vec![];
        while number > 0 || groups.is_empty() {
            groups.push((number & 0x7f) as u8);
            number >>= 7;
        }
        let mut out = vec![0xff];
        for (index, group) in groups.iter().rev().enumerate() {
            out.push(if index + 1 < groups.len() {
                group | 0x80
            } else {
                *group
            });
        }
        out
    }

    pub(crate) fn entry(name: &str, inner: &[u8]) -> Vec<u8> {
        der(
            &private(name),
            &der(
                &[0x30],
                &[der(&[0x16], name.as_bytes()), inner.to_vec()].concat(),
            ),
        )
    }

    pub(crate) fn manifest(manp: &[Vec<u8>], objects: &[Vec<u8>]) -> Vec<u8> {
        let mut set = entry("MANP", &der(&[0x31], &manp.concat()));
        for object in objects {
            set.extend(object);
        }
        let manb = entry("MANB", &der(&[0x31], &set));
        der(
            &[0x30],
            &[
                der(&[0x16], b"IM4M"),
                der(&[0x02], &[0]),
                der(&[0x31], &manb),
                der(&[0x04], &[0xaa; 4]),
                der(&[0x30], &[]),
            ]
            .concat(),
        )
    }

    #[test]
    fn reads_manifest_and_object_properties() -> Result<()> {
        let bytes = manifest(
            &[
                entry("BORD", &der(&[0x02], &[0x24])),
                entry("CHIP", &der(&[0x02], &[0x00, 0x81, 0x12])),
                entry("CPRO", &der(&[0x01], &[0xff])),
                entry("love", &der(&[0x04], b"26.1.434.0.0,0")),
            ],
            &[entry(
                "krnl",
                &der(&[0x31], &entry("DGST", &der(&[0x04], &[7; 48]))),
            )],
        );
        let parsed = parse(&bytes)?;
        assert_eq!(parsed.property("BORD"), Some(&Value::Integer(0x24)));
        assert_eq!(parsed.property("CHIP"), Some(&Value::Integer(0x8112)));
        assert_eq!(parsed.property("CPRO"), Some(&Value::Boolean(true)));
        assert_eq!(
            parsed.property("love"),
            Some(&Value::Data(b"26.1.434.0.0,0".to_vec()))
        );
        assert_eq!(parsed.object("krnl").unwrap().properties[0].name, "DGST");
        assert_eq!(parsed.sha384, hex::encode(sha384(&bytes)));
        assert!(!parsed.signature_validated);
        Ok(())
    }

    #[test]
    fn rejects_mislabeled_entries_and_trailing_bytes() {
        let good = manifest(&[entry("BORD", &der(&[0x02], &[1]))], &[]);
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(parse(&trailing).is_err());
        let mislabeled = der(
            &private("BORD"),
            &der(
                &[0x30],
                &[der(&[0x16], b"CHIP"), der(&[0x02], &[1])].concat(),
            ),
        );
        assert!(parse(&manifest(&[mislabeled], &[])).is_err());
        assert!(parse(&manifest(&[entry("BIGN", &der(&[0x02], &[1; 10]))], &[])).is_err());
    }
}
