//! The flattened Apple DeviceTree ("ADT") that iBoot hands to XNU.
//!
//! Layout from public XNU `pexpert/pexpert/device_tree.h` at tag
//! `xnu-12377.121.6` (commit `ac9718fb1af618d5ce8678d0dc6e8a58f252216f`):
//! a node is `u32 nProperties, u32 nChildren`, then its properties, then its
//! children. A property is a NUL-padded 32-byte name, a `u32` length and the
//! value padded to four bytes. Restore-image templates set bit 31 of the
//! length on values that iBoot fills in (the value is then a fill-in recipe
//! such as `syscfg/WMac/6`); Asahi's m1n1 `proxyclient/m1n1/adt.py` reads the
//! same flag. Parsing rejects anything that would not serialize back to the
//! same bytes, so `serialize(parse(bytes)) == bytes` for every accepted tree.
//! Readers step over a value's padding by its rounded length, so padding
//! bytes a template leaves non-zero (26A434 J700AP's four SPMI
//! `irq-behavior-map` values, two bytes followed by `21 04`) are kept as
//! they are while the value keeps its length.
pub mod assigned;

use crate::Result;
use alloc::{borrow::ToOwned, format, string::String, vec, vec::Vec};
use serde::Serialize;
use stela_contracts::{refuse, require};
pub use stela_formats::boot_bundle::schema::Placeholder;

/// `kPropNameLength`: the NUL-padded property name field.
pub const PROPERTY_NAME_BYTES: usize = 32;
/// Template properties whose value iBoot replaces before handing off.
pub const PLACEHOLDER_FLAG: u32 = 1 << 31;
const LENGTH_MASK: u32 = !PLACEHOLDER_FLAG;
const WORD_BYTES: usize = size_of::<u32>();
const NODE_HEADER_BYTES: usize = 2 * WORD_BYTES;
const PROPERTY_HEADER_BYTES: usize = PROPERTY_NAME_BYTES + WORD_BYTES;
/// Deeper trees are rejected rather than recursed into.
const MAX_DEPTH: usize = 64;
const NAME_PROPERTY: &str = "name";

fn padded(length: usize) -> usize {
    length.next_multiple_of(WORD_BYTES)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Property {
    name: String,
    pub value: Vec<u8>,
    /// Bit 31 of the encoded length: a template value iBoot must fill in.
    pub placeholder: bool,
    /// Non-zero padding after the template's value, written back while the
    /// value keeps its length.
    padding: Vec<u8>,
}

impl Property {
    pub fn new(name: &str, value: Vec<u8>) -> Result<Self> {
        require!(
            !name.is_empty() && name.len() < PROPERTY_NAME_BYTES && !name.contains('\0'),
            "property name {name} does not fit the 32-byte ADT name field",
            name = alloc::format!("{name:?}")
        );
        require!(
            value.len() <= LENGTH_MASK as usize,
            "property value is too large"
        );
        Ok(Self {
            name: name.into(),
            value,
            placeholder: false,
            padding: Vec::new(),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// The value as a NUL-terminated string, without the terminator.
    pub fn as_str(&self) -> Option<&str> {
        let end = self.value.iter().position(|&b| b == 0)?;
        core::str::from_utf8(&self.value[..end]).ok()
    }

    pub fn as_u32(&self) -> Option<u32> {
        Some(u32::from_le_bytes(self.value.as_slice().try_into().ok()?))
    }

    pub fn as_u64(&self) -> Option<u64> {
        Some(u64::from_le_bytes(self.value.as_slice().try_into().ok()?))
    }

    fn encoded_bytes(&self) -> usize {
        PROPERTY_HEADER_BYTES + padded(self.value.len())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Node {
    pub properties: Vec<Property>,
    pub children: Vec<Node>,
}

impl Node {
    /// A node holding only its `name` property.
    pub fn named(name: &str) -> Result<Self> {
        let mut value = name.as_bytes().to_vec();
        value.push(0);
        Ok(Self {
            properties: vec![Property::new(NAME_PROPERTY, value)?],
            children: vec![],
        })
    }

    pub fn name(&self) -> Option<&str> {
        self.property(NAME_PROPERTY).and_then(Property::as_str)
    }

    pub fn property(&self, name: &str) -> Option<&Property> {
        self.properties.iter().find(|p| p.name == name)
    }

    pub fn property_mut(&mut self, name: &str) -> Option<&mut Property> {
        self.properties.iter_mut().find(|p| p.name == name)
    }

    /// Replace an existing value in place, or append a new property.
    /// The result is never a placeholder.
    pub fn set_property(&mut self, name: &str, value: Vec<u8>) -> Result<()> {
        let property = Property::new(name, value)?;
        match self.property_mut(name) {
            Some(existing) => *existing = property,
            None => self.properties.push(property),
        }
        Ok(())
    }

    /// Give an existing property a new name and value in place, keeping its
    /// position; template slots such as `UnusedIntegerProperty0` are filled
    /// this way.
    pub fn replace_property(&mut self, old: &str, name: &str, value: Vec<u8>) -> Result<()> {
        require!(
            old == name || self.property(name).is_none(),
            "node already has a property {name}",
            name
        );
        let slot = self
            .property_mut(old)
            .ok_or_else(|| refuse!("node has no property {old}", old))?;
        *slot = Property::new(name, value)?;
        Ok(())
    }

    pub fn remove_property(&mut self, name: &str) -> Option<Property> {
        let index = self.properties.iter().position(|p| p.name == name)?;
        Some(self.properties.remove(index))
    }

    pub fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.name() == Some(name))
    }

    pub fn child_mut(&mut self, name: &str) -> Option<&mut Node> {
        self.children.iter_mut().find(|c| c.name() == Some(name))
    }

    fn encoded_bytes(&self) -> usize {
        NODE_HEADER_BYTES
            + self
                .properties
                .iter()
                .map(Property::encoded_bytes)
                .sum::<usize>()
            + self.children.iter().map(Node::encoded_bytes).sum::<usize>()
    }
}

/// Where a property's value lies in a serialized tree, for in-place patches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PropertyLocation {
    pub path: String,
    pub property: String,
    pub value_offset: usize,
    pub value_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceTree {
    pub root: Node,
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Reader<'_> {
    fn take(&mut self, length: usize) -> Result<&[u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(refuse!("DeviceTree offset overflow"))?;
        let bytes = self.bytes.get(self.position..end).ok_or_else(|| {
            refuse!(
                "DeviceTree truncated at offset {position:#x}",
                position = self.position
            )
        })?;
        self.position = end;
        Ok(bytes)
    }

    fn word(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(WORD_BYTES)?.try_into().unwrap(),
        ))
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    fn property(&mut self) -> Result<Property> {
        let at = self.position;
        let raw_name = self.take(PROPERTY_NAME_BYTES)?;
        let end = raw_name
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| refuse!("property name at {at:#x} is not NUL-terminated", at))?;
        require!(
            raw_name[end..].iter().all(|&b| b == 0),
            "property name at {at:#x} has bytes after its terminator",
            at
        );
        let name = core::str::from_utf8(&raw_name[..end])
            .map_err(|_| refuse!("property name at {at:#x} is not UTF-8", at))?
            .to_owned();
        require!(!name.is_empty(), "empty property name at {at:#x}", at);
        let encoded = self.word()?;
        let length = (encoded & LENGTH_MASK) as usize;
        let value = self.take(length)?.to_vec();
        let padding = self.take(padded(length) - length)?;
        let padding = if padding.iter().any(|&b| b != 0) {
            padding.to_vec()
        } else {
            Vec::new()
        };
        Ok(Property {
            name,
            value,
            placeholder: encoded & PLACEHOLDER_FLAG != 0,
            padding,
        })
    }

    fn node(&mut self, depth: usize) -> Result<Node> {
        require!(
            depth < MAX_DEPTH,
            "DeviceTree nesting exceeds {MAX_DEPTH}",
            MAX_DEPTH
        );
        let property_count = self.word()? as usize;
        let child_count = self.word()? as usize;
        // Every property and child occupies at least a header; reject counts
        // that cannot fit before allocating for them.
        require!(
            property_count.saturating_mul(PROPERTY_HEADER_BYTES)
                + child_count.saturating_mul(NODE_HEADER_BYTES)
                <= self.remaining(),
            "DeviceTree node counts exceed the remaining bytes"
        );
        let properties = (0..property_count)
            .map(|_| self.property())
            .collect::<Result<_>>()?;
        let children = (0..child_count)
            .map(|_| self.node(depth + 1))
            .collect::<Result<_>>()?;
        Ok(Node {
            properties,
            children,
        })
    }
}

impl DeviceTree {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader { bytes, position: 0 };
        let root = reader.node(0)?;
        require!(
            reader.remaining() == 0,
            "{remaining} trailing bytes after the DeviceTree root",
            remaining = reader.remaining()
        );
        Ok(Self { root })
    }

    pub fn encoded_bytes(&self) -> usize {
        self.root.encoded_bytes()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_bytes());
        write_node(&self.root, &mut out);
        out
    }

    /// The node at a `/`-separated path of `name` values below the root,
    /// such as `/chosen/memory-map`; `/` is the root itself.
    pub fn node(&self, path: &str) -> Option<&Node> {
        components(path).try_fold(&self.root, |node, name| node.child(name))
    }

    pub fn node_mut(&mut self, path: &str) -> Option<&mut Node> {
        components(path).try_fold(&mut self.root, |node, name| node.child_mut(name))
    }

    pub fn property(&self, path: &str, name: &str) -> Option<&Property> {
        self.node(path)?.property(name)
    }

    pub fn set_property(&mut self, path: &str, name: &str, value: Vec<u8>) -> Result<()> {
        self.node_mut(path)
            .ok_or_else(|| refuse!("DeviceTree has no node {path}", path))?
            .set_property(name, value)
    }

    /// Add `child` below `parent` unless a child of that name exists.
    pub fn ensure_child(&mut self, parent: &str, child: &str) -> Result<()> {
        let node = self
            .node_mut(parent)
            .ok_or_else(|| refuse!("DeviceTree has no node {parent}", parent))?;
        if node.child(child).is_none() {
            node.children.push(Node::named(child)?);
        }
        Ok(())
    }

    /// Every template property still carrying a fill-in recipe.
    pub fn placeholders(&self) -> Vec<Placeholder> {
        let mut found = vec![];
        walk(&self.root, "", &mut |path, node| {
            for property in node.properties.iter().filter(|p| p.placeholder) {
                found.push(Placeholder {
                    path: path.into(),
                    property: property.name.clone(),
                    recipe: property
                        .as_str()
                        .map_or_else(|| hex::encode(&property.value), str::to_owned),
                });
            }
        });
        found
    }

    /// Serialized offset of one property's value, for in-place patching.
    pub fn locate(&self, path: &str, name: &str) -> Result<PropertyLocation> {
        let mut offset = 0;
        let mut node = &self.root;
        for component in components(path) {
            offset += NODE_HEADER_BYTES
                + node
                    .properties
                    .iter()
                    .map(Property::encoded_bytes)
                    .sum::<usize>();
            let index = node
                .children
                .iter()
                .position(|c| c.name() == Some(component))
                .ok_or_else(|| refuse!("DeviceTree has no node {path}", path))?;
            offset += node.children[..index]
                .iter()
                .map(Node::encoded_bytes)
                .sum::<usize>();
            node = &node.children[index];
        }
        offset += NODE_HEADER_BYTES;
        for property in &node.properties {
            if property.name == name {
                return Ok(PropertyLocation {
                    path: path.into(),
                    property: name.into(),
                    value_offset: offset + PROPERTY_HEADER_BYTES,
                    value_bytes: property.value.len(),
                });
            }
            offset += property.encoded_bytes();
        }
        Err(refuse!("DeviceTree node {path} has no property {name}", path, name).into())
    }
}

fn components(path: &str) -> impl Iterator<Item = &str> {
    path.split('/').filter(|c| !c.is_empty())
}

fn walk(node: &Node, path: &str, visit: &mut impl FnMut(&str, &Node)) {
    let here = if path.is_empty() { "/" } else { path };
    visit(here, node);
    for child in &node.children {
        let name = child.name().unwrap_or("?");
        walk(child, &format!("{path}/{name}"), visit);
    }
}

fn write_node(node: &Node, out: &mut Vec<u8>) {
    out.extend((node.properties.len() as u32).to_le_bytes());
    out.extend((node.children.len() as u32).to_le_bytes());
    for property in &node.properties {
        let mut name = [0u8; PROPERTY_NAME_BYTES];
        name[..property.name.len()].copy_from_slice(property.name.as_bytes());
        out.extend(name);
        let flag = if property.placeholder {
            PLACEHOLDER_FLAG
        } else {
            0
        };
        out.extend((property.value.len() as u32 | flag).to_le_bytes());
        out.extend(&property.value);
        let pad = padded(property.value.len()) - property.value.len();
        if property.padding.len() == pad {
            out.extend(&property.padding);
        } else {
            out.resize(out.len() + pad, 0);
        }
    }
    for child in &node.children {
        write_node(child, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    fn property(name: &str, value: &[u8], flags: u32) -> Vec<u8> {
        let mut out = vec![0u8; PROPERTY_NAME_BYTES];
        out[..name.len()].copy_from_slice(name.as_bytes());
        out.extend((value.len() as u32 | flags).to_le_bytes());
        out.extend(value);
        out.resize(out.len().next_multiple_of(4), 0);
        out
    }

    fn node(properties: &[Vec<u8>], children: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![];
        out.extend((properties.len() as u32).to_le_bytes());
        out.extend((children.len() as u32).to_le_bytes());
        properties.iter().for_each(|p| out.extend(p));
        children.iter().for_each(|c| out.extend(c));
        out
    }

    fn fixture() -> Vec<u8> {
        let memory_map = node(
            &[
                property("name", b"memory-map\0", 0),
                property("MemoryMapReserved-0", &[0; 16], 0),
            ],
            &[],
        );
        let chosen = node(
            &[
                property("name", b"chosen\0", 0),
                property(
                    "mac-address-wifi0",
                    b"macaddr/wifiaddr,syscfg/WMac/6\0",
                    1 << 31,
                ),
                property("random-seed", &[0; 5], 0),
            ],
            &[memory_map],
        );
        node(
            &[
                property("name", b"device-tree\0", 0),
                property("#address-cells", &2u32.to_le_bytes(), 0),
            ],
            &[chosen],
        )
    }

    #[test]
    fn round_trips_exactly_and_finds_paths() -> Result<()> {
        let bytes = fixture();
        let tree = DeviceTree::parse(&bytes)?;
        assert_eq!(tree.serialize(), bytes);
        assert_eq!(tree.encoded_bytes(), bytes.len());
        assert_eq!(tree.root.name(), Some("device-tree"));
        assert_eq!(
            tree.property("/", "#address-cells")
                .and_then(Property::as_u32),
            Some(2)
        );
        assert!(tree.node("/chosen/memory-map").is_some());
        assert!(tree.node("/chosen/missing").is_none());
        let placeholders = tree.placeholders();
        assert_eq!(placeholders.len(), 1);
        assert_eq!(placeholders[0].path, "/chosen");
        assert_eq!(placeholders[0].recipe, "macaddr/wifiaddr,syscfg/WMac/6");
        Ok(())
    }

    #[test]
    fn edits_values_and_locates_them_in_the_serialized_tree() -> Result<()> {
        let mut tree = DeviceTree::parse(&fixture())?;
        tree.set_property(
            "/chosen",
            "dram-size",
            0x2_0000_0000u64.to_le_bytes().to_vec(),
        )?;
        tree.set_property("/chosen/memory-map", "TrustCache", vec![7; 16])?;
        tree.ensure_child("/chosen", "hibernation")?;
        tree.set_property("/chosen/hibernation", "key-xnu-ctrr", vec![9; 0x30])?;
        let wifi = tree
            .node_mut("/chosen")
            .and_then(|n| n.remove_property("mac-address-wifi0"));
        assert!(wifi.is_some_and(|p| p.placeholder));
        let bytes = tree.serialize();
        assert_eq!(DeviceTree::parse(&bytes)?, tree);
        for (path, name, expected) in [
            (
                "/chosen",
                "dram-size",
                0x2_0000_0000u64.to_le_bytes().to_vec(),
            ),
            ("/chosen/memory-map", "TrustCache", vec![7; 16]),
            ("/chosen/hibernation", "key-xnu-ctrr", vec![9; 0x30]),
            ("/chosen", "random-seed", vec![0; 5]),
        ] {
            let at = tree.locate(path, name)?;
            assert_eq!(
                &bytes[at.value_offset..at.value_offset + at.value_bytes],
                expected.as_slice()
            );
        }
        assert!(tree.locate("/chosen", "absent").is_err());
        let chosen = tree.node_mut("/chosen").unwrap();
        chosen.replace_property("random-seed", "love", b"26.1\0".to_vec())?;
        assert_eq!(chosen.properties[1].name(), "love");
        assert!(
            chosen
                .replace_property("love", "dram-size", vec![])
                .is_err()
        );
        assert!(tree.set_property("/nowhere", "x", vec![]).is_err());
        Ok(())
    }

    #[test]
    fn keeps_non_zero_padding_while_the_value_keeps_its_length() -> Result<()> {
        // The 5-byte random-seed value has three padding bytes.
        let mut bytes = fixture();
        let header = PROPERTY_HEADER_BYTES;
        let value = bytes.windows(11).position(|w| w == b"random-seed").unwrap() + header;
        bytes[value + 5..value + 8].copy_from_slice(&[0x21, 0x04, 0x21]);
        let mut tree = DeviceTree::parse(&bytes)?;
        assert_eq!(tree.serialize(), bytes);
        fn seed(tree: &mut DeviceTree) -> &mut Vec<u8> {
            let chosen = tree.node_mut("/chosen").unwrap();
            &mut chosen.property_mut("random-seed").unwrap().value
        }
        seed(&mut tree)[0] = 7;
        bytes[value] = 7;
        assert_eq!(tree.serialize(), bytes);
        seed(&mut tree).push(0);
        assert!(!tree.serialize().contains(&0x21));
        Ok(())
    }

    #[test]
    fn rejects_inputs_that_would_not_round_trip() {
        let good = fixture();
        assert!(DeviceTree::parse(&good[..good.len() - 1]).is_err());
        let mut trailing = good.clone();
        trailing.extend([0; 4]);
        assert!(DeviceTree::parse(&trailing).is_err());
        // Garbage after the name terminator.
        let mut name = good.clone();
        name[8 + 6] = b'x';
        assert!(DeviceTree::parse(&name).is_err());
        let mut counts = good;
        counts[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(DeviceTree::parse(&counts).is_err());
        assert!(Property::new(&"x".repeat(32), vec![]).is_err());
    }
}
