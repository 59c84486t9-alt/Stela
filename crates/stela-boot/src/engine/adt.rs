//! Read-only lookups in an Apple DeviceTree (ADT) image: nodes are a property
//! count, a child count, properties (32-byte name, 32-bit length whose top
//! bit is a flag, value padded to 4 bytes), then children
//! (m1n1 `adt.c`; the format `stela-loader` parses and serializes exactly).
use alloc::vec::Vec;

pub struct Node<'a> {
    data: &'a [u8],
    properties: usize,
    children: usize,
    /// Offset of the first property.
    start: usize,
}

/// Little-endian u64 cells; a trailing partial cell is ignored.
fn cells(value: &[u8]) -> Vec<u64> {
    value
        .as_chunks::<8>()
        .0
        .iter()
        .map(|cell| u64::from_le_bytes(*cell))
        .collect()
}

/// (name, value) of every property of a node.
type Properties<'a> = Vec<(&'a [u8], &'a [u8])>;

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

impl<'a> Node<'a> {
    pub fn root(data: &'a [u8]) -> Option<Self> {
        Self::at(data, 0)
    }

    fn at(data: &'a [u8], offset: usize) -> Option<Self> {
        Some(Self {
            data,
            properties: u32_at(data, offset)? as usize,
            children: u32_at(data, offset + 4)? as usize,
            start: offset + 8,
        })
    }

    /// Every property as (name, value), and the offset after them.
    fn walk_properties(&self) -> Option<(Properties<'a>, usize)> {
        let mut offset = self.start;
        let mut properties = Vec::with_capacity(self.properties);
        for _ in 0..self.properties {
            let name = self.data.get(offset..offset + 32)?;
            let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(32)];
            let length = (u32_at(self.data, offset + 32)? & 0x7fff_ffff) as usize;
            let value = self.data.get(offset + 36..offset + 36 + length)?;
            properties.push((name, value));
            offset += 36 + length.next_multiple_of(4);
        }
        Some((properties, offset))
    }

    fn end(&self) -> Option<usize> {
        let (_, mut offset) = self.walk_properties()?;
        for _ in 0..self.children {
            offset = Self::at(self.data, offset)?.end()?;
        }
        Some(offset)
    }

    pub fn property(&self, name: &str) -> Option<&'a [u8]> {
        let (properties, _) = self.walk_properties()?;
        properties
            .into_iter()
            .find(|(candidate, _)| *candidate == name.as_bytes())
            .map(|(_, value)| value)
    }

    pub fn child(&self, name: &str) -> Option<Self> {
        let (_, mut offset) = self.walk_properties()?;
        for _ in 0..self.children {
            let child = Self::at(self.data, offset)?;
            let own = child.property("name")?;
            if own.strip_suffix(&[0]).unwrap_or(own) == name.as_bytes() {
                return Some(child);
            }
            offset = child.end()?;
        }
        None
    }

    /// A property as little-endian u64 pairs (`reg` with two address and
    /// two size cells).
    pub fn pairs(&self, name: &str) -> Option<Vec<(u64, u64)>> {
        let cells = cells(self.property(name)?);
        Some(
            cells
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&[a, b]| (a, b))
                .collect(),
        )
    }

    /// `ranges` with two child, two parent and two size cells, as
    /// (child, parent, bytes).
    pub fn ranges(&self) -> Option<Vec<(u64, u64, u64)>> {
        let cells = cells(self.property("ranges")?);
        Some(
            cells
                .as_chunks::<3>()
                .0
                .iter()
                .map(|&[child, parent, bytes]| (child, parent, bytes))
                .collect(),
        )
    }

    /// Visit this node and every descendant, depth first.
    pub fn visit(&self, visitor: &mut dyn FnMut(&Node<'a>)) -> Option<()> {
        visitor(self);
        let (_, mut offset) = self.walk_properties()?;
        for _ in 0..self.children {
            let child = Self::at(self.data, offset)?;
            child.visit(visitor)?;
            offset = child.end()?;
        }
        Some(())
    }

    /// A property as little-endian u32 cells.
    pub fn cells32(&self, name: &str) -> Option<Vec<u32>> {
        Some(
            self.property(name)?
                .as_chunks::<4>()
                .0
                .iter()
                .map(|cell| u32::from_le_bytes(*cell))
                .collect(),
        )
    }

    /// The first 32-bit cell of a property.
    pub fn first_u32(&self, name: &str) -> Option<u32> {
        u32_at(self.property(name)?, 0)
    }
}
