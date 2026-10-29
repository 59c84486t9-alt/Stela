//! Emitted byte buffers with instruction-boundary accounting.
use super::Asm;
use alloc::vec::Vec;

/// Emitted bytes and the number of instructions among them.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Code {
    pub(super) bytes: Vec<u8>,
    pub(super) instructions: usize,
}

/// A byte and instruction position captured at an emission boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Checkpoint {
    bytes: usize,
    pub(super) instructions: usize,
}

impl Checkpoint {
    pub(crate) const fn offset(self) -> usize {
        self.bytes
    }
}

/// A complete emitted fragment, including its exact instruction count.
/// Both endpoints belong to the same unmodified Code buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Span {
    start: Checkpoint,
    end: Checkpoint,
}
impl Span {
    pub(crate) const fn start(self) -> Checkpoint {
        self.start
    }
    pub(crate) const fn end(self) -> Checkpoint {
        self.end
    }
    pub(crate) const fn instructions(self) -> usize {
        self.end.instructions - self.start.instructions
    }
    pub(crate) const fn is_empty(self) -> bool {
        self.start.bytes == self.end.bytes
    }
}

impl Code {
    pub(crate) const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            instructions: 0,
        }
    }
    /// An encoder that appends here and adds to this count.
    pub(crate) fn asm(&mut self) -> Asm<'_> {
        Asm {
            code: &mut self.bytes,
            instructions: 0,
            shared: Some(&mut self.instructions),
        }
    }
    /// The instructions emitted through [`Self::asm`].
    pub(crate) const fn instructions(&self) -> usize {
        self.instructions
    }
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
    /// Append `other`'s bytes and instructions.
    pub(crate) fn append(&mut self, other: Code) {
        self.bytes.extend(other.bytes);
        self.instructions += other.instructions;
    }
    /// The current emission boundary, for splitting or truncating this buffer.
    pub(crate) fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            bytes: self.bytes.len(),
            instructions: self.instructions,
        }
    }
    /// Record complete instructions emitted since this buffer's checkpoint.
    pub(crate) fn span_since(&self, start: Checkpoint) -> Span {
        let end = self.checkpoint();
        assert!(start.bytes <= end.bytes && start.instructions <= end.instructions);
        Span { start, end }
    }
    /// Copy a fragment from its unmodified source buffer. Internal branches and
    /// instruction-associated data move together; no byte decoding is involved.
    pub(crate) fn append_span(&mut self, source: &Code, span: Span) {
        assert!(
            span.end.bytes <= source.bytes.len() && span.end.instructions <= source.instructions
        );
        self.bytes
            .extend_from_slice(&source.bytes[span.start.bytes..span.end.bytes]);
        self.instructions += span.instructions();
    }
    /// Replace a fixed-size field without changing buffer length or count.
    pub(crate) fn patch<const N: usize>(&mut self, offset: usize, bytes: [u8; N]) {
        let end = offset
            .checked_add(N)
            .expect("patch field offset does not overflow");
        self.bytes
            .get_mut(offset..end)
            .expect("patch field lies in emitted code")
            .copy_from_slice(&bytes);
    }
    /// Move the instructions emitted after `at` into a separate buffer.
    pub(crate) fn split_off(&mut self, at: Checkpoint) -> Self {
        assert!(at.bytes <= self.bytes.len() && at.instructions <= self.instructions);
        let tail = Self {
            bytes: self.bytes.split_off(at.bytes),
            instructions: self.instructions - at.instructions,
        };
        self.instructions = at.instructions;
        tail
    }
    /// Discard the instructions emitted after `at`.
    pub(crate) fn truncate(&mut self, at: Checkpoint) {
        assert!(at.bytes <= self.bytes.len() && at.instructions <= self.instructions);
        self.bytes.truncate(at.bytes);
        self.instructions = at.instructions;
    }
    /// Remove one complete instruction whose bytes the caller identified.
    pub(crate) fn remove_instruction(&mut self, range: core::ops::Range<usize>) {
        assert!(!range.is_empty());
        self.bytes.drain(range);
        self.instructions = self
            .instructions
            .checked_sub(1)
            .expect("counted instruction");
    }
    /// Remove every byte and instruction.
    #[cfg(test)]
    pub(crate) fn clear(&mut self) {
        self.bytes.clear();
        self.instructions = 0;
    }
}

impl PartialEq<[u8]> for Code {
    fn eq(&self, other: &[u8]) -> bool {
        self.bytes == other
    }
}

impl PartialEq<Vec<u8>> for Code {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.bytes == *other
    }
}

impl<const N: usize> PartialEq<[u8; N]> for Code {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.bytes == other
    }
}

impl PartialEq<&[u8]> for Code {
    fn eq(&self, other: &&[u8]) -> bool {
        self.bytes == *other
    }
}

impl PartialEq<Code> for [u8] {
    fn eq(&self, other: &Code) -> bool {
        self == other.bytes
    }
}

impl PartialEq<Code> for &[u8] {
    fn eq(&self, other: &Code) -> bool {
        *self == other.bytes
    }
}

impl PartialEq<Code> for Vec<u8> {
    fn eq(&self, other: &Code) -> bool {
        *self == other.bytes
    }
}

impl<const N: usize> PartialEq<Code> for [u8; N] {
    fn eq(&self, other: &Code) -> bool {
        self[..] == other.bytes
    }
}

impl From<Code> for Vec<u8> {
    fn from(code: Code) -> Self {
        code.bytes
    }
}

impl<const N: usize> TryFrom<Code> for [u8; N] {
    type Error = Vec<u8>;
    fn try_from(code: Code) -> Result<Self, Vec<u8>> {
        code.bytes.try_into()
    }
}

impl<'a> IntoIterator for &'a Code {
    type Item = &'a u8;
    type IntoIter = core::slice::Iter<'a, u8>;
    fn into_iter(self) -> Self::IntoIter {
        self.bytes.iter()
    }
}

impl IntoIterator for Code {
    type Item = u8;
    type IntoIter = alloc::vec::IntoIter<u8>;
    fn into_iter(self) -> Self::IntoIter {
        self.bytes.into_iter()
    }
}

impl core::ops::Deref for Code {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.bytes
    }
}
