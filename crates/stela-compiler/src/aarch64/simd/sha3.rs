//! EOR3, BCAX, RAX1 and XAR.
const REGISTER_MASK: u32 = 31;
const DESTINATION_SHIFT: u32 = 0;
const LEFT_SHIFT: u32 = 5;
const RIGHT_SHIFT: u32 = 16;
const THIRD_SHIFT: u32 = 10;
const XAR_ROTATION_SHIFT: u32 = 10;
const XAR_ROTATION_MASK: u32 = 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Eor3 { third: u8 },
    Bcax { third: u8 },
    Rax1,
    Xar { rotation: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub destination: u8,
    pub left: u8,
    pub right: u8,
}

#[derive(Clone, Copy)]
enum Encoding {
    Eor3,
    Bcax,
    Rax1,
    Xar,
}

impl Encoding {
    const ALL: &'static [Self] = &[Self::Eor3, Self::Bcax, Self::Rax1, Self::Xar];

    fn facts(self) -> (u32, u32) {
        match self {
            Self::Eor3 => (0xffe08000, 0xce000000),
            Self::Bcax => (0xffe08000, 0xce200000),
            Self::Rax1 => (0xffe0fc00, 0xce608c00),
            Self::Xar => (0xffe00000, 0xce800000),
        }
    }

    fn kind(self, word: u32) -> Kind {
        let third = register(word, THIRD_SHIFT);
        match self {
            Self::Eor3 => Kind::Eor3 { third },
            Self::Bcax => Kind::Bcax { third },
            Self::Rax1 => Kind::Rax1,
            Self::Xar => Kind::Xar {
                rotation: ((word >> XAR_ROTATION_SHIFT) & XAR_ROTATION_MASK) as u8,
            },
        }
    }
}

/// Every register and immediate within the four exact fixed-bit masks is valid.
/// Same-named SVE forms remain another encoding class and receive no support here.
#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let encoding = Encoding::ALL.iter().copied().find(|encoding| {
        let (mask, value) = encoding.facts();
        word & mask == value
    })?;
    Some(Ok(Operand {
        kind: encoding.kind(word),
        destination: register(word, DESTINATION_SHIFT),
        left: register(word, LEFT_SHIFT),
        right: register(word, RIGHT_SHIFT),
    }))
}

fn register(word: u32, shift: u32) -> u8 {
    ((word >> shift) & REGISTER_MASK) as u8
}

#[cfg(test)]
mod tests;
