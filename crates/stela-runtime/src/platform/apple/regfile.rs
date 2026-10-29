//! Register files a model describes span by span: the registers of one span
//! share a width and a role the model gives meaning to. An offset no span
//! covers, or an access of another width, has no described meaning and
//! refuses.
use crate::Result;
use alloc::collections::BTreeMap;
use stela_contracts::bus::Width;
use stela_contracts::refuse;

/// Registers `[start, end)` of `width`, one every `width` bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span<R> {
    pub start: u64,
    pub end: u64,
    pub width: Width,
    pub role: R,
}

impl<R> Span<R> {
    pub const fn new(start: u64, end: u64, width: Width, role: R) -> Self {
        Self {
            start,
            end,
            width,
            role,
        }
    }
}

/// The role of the register at `offset` among `spans`.
pub fn role<R: Copy>(spans: &[Span<R>], offset: u64, width: Width) -> Result<R> {
    let span = spans
        .iter()
        .find(|span| (span.start..span.end).contains(&offset))
        .ok_or(refuse!("register without described meaning"))?;
    if width != span.width {
        return Err(refuse!("register access of another width"));
    }
    if !(offset - span.start).is_multiple_of(width.bytes()) {
        return Err(refuse!("access between registers"));
    }
    Ok(span.role)
}

/// Registers that hold what software last wrote, reading 0 until then.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Held(BTreeMap<u64, u64>);

impl Held {
    pub fn get(&self, offset: u64) -> u64 {
        self.0.get(&offset).copied().unwrap_or(0)
    }

    pub fn set(&mut self, offset: u64, value: u64) {
        self.0.insert(offset, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_give_roles_only_at_their_width_and_registers() {
        const SPANS: [Span<u8>; 2] = [
            Span::new(0x10, 0x20, Width::Word, 1),
            Span::new(0x100, 0x110, Width::Double, 2),
        ];
        assert_eq!(role(&SPANS, 0x1c, Width::Word), Ok(1));
        assert_eq!(role(&SPANS, 0x108, Width::Double), Ok(2));
        assert!(role(&SPANS, 0x20, Width::Word).is_err());
        assert!(role(&SPANS, 0x10, Width::Double).is_err());
        assert!(role(&SPANS, 0x104, Width::Word).is_err());
        let mut held = Held::default();
        assert_eq!(held.get(0x10), 0);
        held.set(0x10, 7);
        assert_eq!(held.get(0x10), 7);
    }
}
