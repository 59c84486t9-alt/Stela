//! Read-only lookups in an Apple DeviceTree (ADT) image: nodes are a property
//! count, a child count, properties (32-byte name, 32-bit length whose top
//! bit is a flag, value padded to 4 bytes), then children
//! (m1n1 `adt.c`; the format `stela-loader` parses and serializes exactly).
use alloc::vec::Vec;

const NODE_HEADER_BYTES: usize = 8;
const PROPERTY_NAME_BYTES: usize = 32;
const PROPERTY_HEADER_BYTES: usize = PROPERTY_NAME_BYTES + 4;
// Match the loader's accepted depths, including the root at depth zero.
const MAX_DEPTH: usize = 64;

#[derive(Clone)]
pub struct Node<'a> {
    data: &'a [u8],
    properties: usize,
    children: usize,
    /// Offset of the first property.
    start: usize,
    depth: usize,
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
        data.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

struct Property<'a> {
    name: &'a [u8],
    value: &'a [u8],
    encoded_length: u32,
    next: usize,
}

fn property_at(data: &[u8], offset: usize) -> Option<Property<'_>> {
    let name_end = offset.checked_add(PROPERTY_NAME_BYTES)?;
    let value_start = offset.checked_add(PROPERTY_HEADER_BYTES)?;
    let name = data.get(offset..name_end)?;
    let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
    let encoded_length = u32_at(data, name_end)?;
    let length = (encoded_length & 0x7fff_ffff) as usize;
    let value_end = value_start.checked_add(length)?;
    let padded = length.checked_add(3)? & !3;
    let next = value_start.checked_add(padded)?;
    // Padding belongs to the property extent, even when it is nonzero.
    data.get(value_end..next)?;
    Some(Property {
        name,
        value: data.get(value_start..value_end)?,
        encoded_length,
        next,
    })
}

impl<'a> Node<'a> {
    /// Translate a complete extent through this node's actual `ranges`.
    /// Adjacent rows may contribute only when every byte has the same affine
    /// translation. Matching endpoints alone cannot establish ownership.
    /// Rows may overlap where they translate the shared bytes alike, as the
    /// identity rows of the 26A434 J473AP `/arm-io` do (0x3_8000_0000 for
    /// 0x1_8000_0000 beside 0x4_0000_0000 for 0x8000_0000); rows that
    /// translate one source byte two ways refuse the node.
    pub fn translate_range(&self, offset: u64, bytes: u64) -> Option<u64> {
        let raw = self.property("ranges")?;
        if raw.is_empty() || !raw.len().is_multiple_of(24) || bytes == 0 {
            return None;
        }
        let end = offset.checked_add(bytes)?;
        let mut ranges = self.ranges()?;
        for &(child, parent, size) in &ranges {
            if size == 0 {
                return None;
            }
            child.checked_add(size)?;
            parent.checked_add(size)?;
        }
        ranges.sort_unstable_by_key(|&(child, _, _)| child);
        let conflicting = ranges
            .iter()
            .enumerate()
            .any(|(i, &(child, parent, size))| {
                ranges[i + 1..]
                    .iter()
                    .take_while(|&&(other, _, _)| other < child + size)
                    .any(|&(other, other_parent, _)| {
                        other_parent.wrapping_sub(other) != parent.wrapping_sub(child)
                    })
            });
        if conflicting {
            return None;
        }
        let &(child, parent, _) = ranges
            .iter()
            .find(|&&(child, _, size)| child <= offset && offset < child + size)?;
        let physical = parent.checked_add(offset - child)?;
        physical.checked_add(bytes)?;
        let mut cursor = offset;
        for (child, parent, size) in ranges {
            if child + size <= cursor {
                continue;
            }
            if child > cursor || parent + (cursor - child) != physical + (cursor - offset) {
                return None;
            }
            cursor = end.min(child + size);
            if cursor == end {
                return Some(physical);
            }
        }
        None
    }

    /// Open a root prefix; trailing bytes are permitted. Lookups validate the
    /// extents they consume. Use `root_exact` to validate a complete image.
    pub fn root(data: &'a [u8]) -> Option<Self> {
        Self::at(data, 0, 0)
    }

    /// Validate one complete image, including all descendants and padding,
    /// without allocating or accepting trailing bytes.
    pub fn root_exact(data: &'a [u8]) -> Option<Self> {
        let root = Self::root(data)?;
        (root.end()? == data.len()).then_some(root)
    }

    fn at(data: &'a [u8], offset: usize, depth: usize) -> Option<Self> {
        if depth >= MAX_DEPTH {
            return None;
        }
        let start = offset.checked_add(NODE_HEADER_BYTES)?;
        let properties = u32_at(data, offset)? as usize;
        let children = u32_at(data, offset.checked_add(4)?)? as usize;
        let minimum = properties
            .checked_mul(PROPERTY_HEADER_BYTES)?
            .checked_add(children.checked_mul(NODE_HEADER_BYTES)?)?;
        if minimum > data.len().checked_sub(start)? {
            return None;
        }
        Some(Self {
            data,
            properties,
            children,
            start,
            depth,
        })
    }

    fn properties_end(&self) -> Option<usize> {
        let mut offset = self.start;
        for _ in 0..self.properties {
            offset = property_at(self.data, offset)?.next;
        }
        Some(offset)
    }

    /// Every property as (name, value), and the offset after them.
    fn walk_properties(&self) -> Option<(Properties<'a>, usize)> {
        let mut offset = self.start;
        let mut properties = Vec::new();
        properties.try_reserve_exact(self.properties).ok()?;
        for _ in 0..self.properties {
            let property = property_at(self.data, offset)?;
            properties.push((property.name, property.value));
            offset = property.next;
        }
        Some((properties, offset))
    }

    fn end(&self) -> Option<usize> {
        self.scan(&mut |_| {})
    }

    /// Iterative depth-first traversal. Public visitation prevalidates the
    /// entire subtree before allowing any callback to observe it.
    fn scan(&self, visitor: &mut dyn FnMut(&Node<'a>)) -> Option<usize> {
        let mut pending = [0usize; MAX_DEPTH];
        let mut depth = self.depth;
        let mut offset = self.start.checked_sub(NODE_HEADER_BYTES)?;
        loop {
            let node = Self::at(self.data, offset, depth)?;
            offset = node.properties_end()?;
            visitor(&node);
            pending[depth] = node.children;
            loop {
                if pending[depth] != 0 {
                    pending[depth] -= 1;
                    depth = depth.checked_add(1)?;
                    if depth >= MAX_DEPTH {
                        return None;
                    }
                    break;
                }
                if depth == self.depth {
                    return Some(offset);
                }
                depth -= 1;
            }
        }
    }

    /// Every property as (name, value), in tree order.
    pub fn properties(&self) -> Option<Properties<'a>> {
        Some(self.walk_properties()?.0)
    }

    pub fn property(&self, name: &str) -> Option<&'a [u8]> {
        self.properties_end()?;
        let mut offset = self.start;
        for _ in 0..self.properties {
            let property = property_at(self.data, offset)?;
            if property.name == name.as_bytes() {
                return Some(property.value);
            }
            offset = property.next;
        }
        None
    }

    /// The ADT length's high bit marks an iBoot fill-in recipe. Its bytes are
    /// not a hardware value; the loader may resolve or remove that property.
    pub fn property_is_placeholder(&self, name: &str) -> Option<bool> {
        self.properties_end()?;
        let mut offset = self.start;
        for _ in 0..self.properties {
            let property = property_at(self.data, offset)?;
            if property.name == name.as_bytes() {
                return Some(property.encoded_length & 0x8000_0000 != 0);
            }
            offset = property.next;
        }
        None
    }

    pub fn child(&self, name: &str) -> Option<Self> {
        self.end()?;
        let mut offset = self.properties_end()?;
        for _ in 0..self.children {
            let child = Self::at(self.data, offset, self.depth + 1)?;
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

    /// The node's direct children, in tree order.
    pub fn children(&self) -> Option<Vec<Self>> {
        self.end()?;
        let mut offset = self.properties_end()?;
        let mut children = Vec::new();
        children.try_reserve_exact(self.children).ok()?;
        for _ in 0..self.children {
            let child = Self::at(self.data, offset, self.depth + 1)?;
            offset = child.end()?;
            children.push(child);
        }
        Some(children)
    }

    /// Visit this node and every descendant, depth first.
    pub fn visit(&self, visitor: &mut dyn FnMut(&Node<'a>)) -> Option<()> {
        self.end()?;
        self.scan(visitor)?;
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

    /// Whether the node's `compatible` list names `model`.
    pub fn compatible(&self, model: &str) -> bool {
        self.property("compatible").is_some_and(|list| {
            list.split(|byte| *byte == 0)
                .any(|entry| entry == model.as_bytes())
        })
    }

    /// The first 32-bit cell of a property.
    pub fn first_u32(&self, name: &str) -> Option<u32> {
        u32_at(self.property(name)?, 0)
    }

    /// A property's first 64 bits, little-endian, when it is at least eight
    /// bytes (e.g. `/chosen` `unique-chip-id`).
    pub fn first_u64(&self, name: &str) -> Option<u64> {
        let value = self.property(name)?;
        value
            .get(..8)
            .map(|bytes| u64::from_le_bytes(bytes.try_into().expect("eight bytes")))
    }
}

/// An ADT image of one node: `properties` as (name, value) and its encoded
/// children, for tests.
#[cfg(test)]
pub(crate) fn encode(properties: &[(&str, &[u8])], children: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend((properties.len() as u32).to_le_bytes());
    out.extend((children.len() as u32).to_le_bytes());
    for (name, value) in properties {
        let mut field = [0u8; 32];
        field[..name.len()].copy_from_slice(name.as_bytes());
        out.extend(field);
        out.extend((value.len() as u32).to_le_bytes());
        out.extend(*value);
        out.resize(out.len().next_multiple_of(4), 0);
    }
    for child in children {
        out.extend(child);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_images_require_every_header_value_and_padding_byte() {
        let child = encode(&[("name", b"child\0"), ("value", b"abc")], &[]);
        let tree = encode(&[("name", b"root\0")], &[child]);
        assert!(Node::root_exact(&tree).is_some());
        for length in 0..tree.len() {
            assert!(Node::root_exact(&tree[..length]).is_none(), "{length}");
        }
        let property = encode(&[("value", b"x")], &[]);
        for missing in 1..=3 {
            let root = Node::root(&property[..property.len() - missing]).unwrap();
            assert!(root.properties().is_none());
            assert!(root.property("value").is_none());
            assert!(root.property_is_placeholder("value").is_none());
        }
    }

    #[test]
    fn prefix_roots_and_exact_images_have_distinct_suffix_contracts() {
        for suffix in [0, 0xa5] {
            let mut tree = encode(&[], &[]);
            tree.push(suffix);
            let root = Node::root(&tree).unwrap();
            assert!(root.children().unwrap().is_empty());
            assert!(Node::root_exact(&tree).is_none());
        }
    }

    #[test]
    fn impossible_combined_counts_refuse_before_reservation() {
        for (properties, children) in [(u32::MAX, 0u32), (0, u32::MAX), (1, 1)] {
            let mut tree = Vec::new();
            tree.extend(properties.to_le_bytes());
            tree.extend(children.to_le_bytes());
            // One empty property can fit, but not its declared sibling child.
            tree.resize(NODE_HEADER_BYTES + PROPERTY_HEADER_BYTES, 0);
            assert!(Node::root(&tree).is_none());
            assert!(Node::root_exact(&tree).is_none());
        }
        assert!(u32_at(&[], usize::MAX).is_none());
        assert!(property_at(&[], usize::MAX).is_none());
    }

    #[test]
    fn recipe_flags_and_nonzero_padding_remain_structurally_valid() {
        let mut tree = encode(&[("value", b"x")], &[]);
        let length_offset = NODE_HEADER_BYTES + PROPERTY_NAME_BYTES;
        tree[length_offset..length_offset + 4].copy_from_slice(&0x8000_0001u32.to_le_bytes());
        let padding = NODE_HEADER_BYTES + PROPERTY_HEADER_BYTES + 1;
        tree[padding..].fill(0xa5);
        let root = Node::root_exact(&tree).unwrap();
        assert_eq!(root.property("value"), Some(b"x".as_slice()));
        assert_eq!(root.property_is_placeholder("value"), Some(true));
        assert_eq!(root.properties().unwrap().len(), 1);
    }

    #[test]
    fn traversal_bounds_depth_and_preserves_depth_first_order() {
        let mut tree = encode(&[], &[]);
        for _ in 1..MAX_DEPTH {
            tree = encode(&[], &[tree]);
        }
        let root = Node::root_exact(&tree).unwrap();
        let mut visited = 0;
        root.visit(&mut |_| visited += 1).unwrap();
        assert_eq!(visited, MAX_DEPTH);
        let too_deep = encode(&[], &[tree]);
        assert!(Node::root_exact(&too_deep).is_none());
        visited = 0;
        assert!(
            Node::root(&too_deep)
                .unwrap()
                .visit(&mut |_| visited += 1)
                .is_none()
        );
        assert_eq!(visited, 0);

        let grandchild = encode(&[("name", b"grandchild")], &[]);
        let first = encode(&[("name", b"first")], &[grandchild]);
        let second = encode(&[("name", b"second")], &[]);
        let tree = encode(&[("name", b"root")], &[first, second]);
        let root = Node::root_exact(&tree).unwrap();
        let mut names = Vec::new();
        root.visit(&mut |node| names.push(node.property("name").unwrap()))
            .unwrap();
        assert_eq!(
            names,
            [b"root".as_slice(), b"first", b"grandchild", b"second"]
        );
        assert_eq!(root.children().unwrap().len(), 2);
        assert!(root.child("first").unwrap().child("grandchild").is_some());
    }

    #[test]
    fn malformed_later_children_produce_no_partial_visitor_observations() {
        let first = encode(&[("name", b"first")], &[]);
        let mut second = encode(&[("name", b"second")], &[]);
        second.pop();
        let tree = encode(&[], &[first, second]);
        let root = Node::root(&tree).unwrap();
        let mut visited = 0;
        assert!(root.visit(&mut |_| visited += 1).is_none());
        assert_eq!(visited, 0);
        assert!(root.children().is_none());
        assert!(root.child("first").is_none());
    }

    #[test]
    fn early_property_matches_do_not_hide_malformed_later_properties() {
        let mut tree = encode(&[("first", b"ok"), ("later", b"x")], &[]);
        tree.pop();
        let root = Node::root(&tree).unwrap();
        assert!(root.property("first").is_none());
        assert!(root.property_is_placeholder("first").is_none());
        assert!(root.properties().is_none());
    }

    #[test]
    fn nonroot_traversal_stays_within_its_own_subtree() {
        let left = encode(&[("name", b"left")], &[]);
        let right = encode(&[("name", b"right")], &[]);
        let branch = encode(&[("name", b"branch")], &[left, right]);
        let outside = encode(&[("name", b"outside")], &[]);
        let tree = encode(&[], &[branch, outside]);
        let branch = Node::root_exact(&tree).unwrap().child("branch").unwrap();
        let mut names = Vec::new();
        branch
            .visit(&mut |node| names.push(node.property("name").unwrap()))
            .unwrap();
        assert_eq!(names, [b"branch".as_slice(), b"left", b"right"]);
        let children = branch.children().unwrap();
        assert_eq!(children.len(), 2);
        assert_eq!(children[1].property("name"), Some(b"right".as_slice()));
    }

    fn translate(ranges: &[(u64, u64, u64)], offset: u64, bytes: u64) -> Option<u64> {
        let raw = ranges
            .iter()
            .flat_map(|&(child, parent, size)| [child, parent, size])
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        let tree = encode(&[("ranges", &raw)], &[]);
        Node::root(&tree).unwrap().translate_range(offset, bytes)
    }

    #[test]
    fn extent_translation_requires_every_byte_not_just_matching_endpoints() {
        assert_eq!(
            translate(&[(0, 0x1000, 0x100), (0x200, 0x1200, 0x100)], 0, 0x300),
            None
        );
        assert_eq!(
            translate(&[(0, 0x1000, 0x100), (0x100, 0x1100, 0x200)], 0x80, 0x200),
            Some(0x1080)
        );
        assert_eq!(
            translate(&[(0x100, 0x1100, 0x200), (0, 0x1000, 0x100)], 0x80, 0x200),
            Some(0x1080)
        );
        assert_eq!(
            translate(&[(0, 0x1000, 0x100), (0x100, 0x2100, 0x200)], 0x80, 0x200),
            None
        );
        // Overlapping rows that translate their shared bytes alike, like
        // J473AP's identity rows, translate; rows that translate one byte
        // two ways refuse.
        assert_eq!(
            translate(&[(0, 0x1000, 0x100), (0x80, 0x1080, 0x200)], 0x80, 0x180),
            Some(0x1080)
        );
        assert_eq!(
            translate(
                &[
                    (0x3_8000_0000, 0x3_8000_0000, 0x1_8000_0000),
                    (0x4_0000_0000, 0x4_0000_0000, 0x8000_0000),
                    (0x4_8000_0000, 0x4_8000_0000, 0x8000_0000),
                ],
                0x4_8000_0000,
                0x1000
            ),
            Some(0x4_8000_0000)
        );
        assert_eq!(
            translate(&[(0, 0x1000, 0x100), (0x80, 0x2080, 0x200)], 0, 4),
            None
        );
        assert_eq!(translate(&[(0, 0x1000, 0x100)], 0, 0x100), Some(0x1000));
        assert_eq!(translate(&[(0, 0x1000, 0x100)], 0x100, 1), None);
    }

    #[test]
    fn extent_translation_refuses_malformed_zero_and_overflowing_authority() {
        for ranges in [
            vec![],
            vec![(0, 0, 0)],
            vec![(u64::MAX, 0, 2)],
            vec![(0, u64::MAX, 2)],
        ] {
            assert_eq!(translate(&ranges, 0, 1), None);
        }
        assert_eq!(translate(&[(0, 0x1000, 0x100)], 0, 0), None);
        assert_eq!(translate(&[(0, 0x1000, 0x100)], u64::MAX, 2), None);
        let tree = encode(&[("ranges", &[0; 25])], &[]);
        assert_eq!(Node::root(&tree).unwrap().translate_range(0, 1), None);
    }

    #[test]
    fn nodes_properties_and_compatibles_read_back() {
        let child = encode(
            &[
                ("name", b"uart0\0"),
                ("compatible", b"uart-1,samsung\0ARM,x\0"),
            ],
            &[],
        );
        let tree = encode(
            &[
                ("name", b"device-tree\0"),
                ("reg", &[1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]),
            ],
            &[child],
        );
        let root = Node::root(&tree).unwrap();
        assert_eq!(root.pairs("reg"), Some(vec![(1, 2)]));
        let uart = root.child("uart0").unwrap();
        assert!(uart.compatible("uart-1,samsung") && uart.compatible("ARM,x"));
        assert!(!uart.compatible("uart-1"));
        assert!(root.child("wdt").is_none());
    }
}
