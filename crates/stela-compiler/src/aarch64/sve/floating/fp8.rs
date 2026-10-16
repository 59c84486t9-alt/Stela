//! SVE FP8 conversions.

const REGISTER_MASK: u32 = 31;
const SOURCE_SHIFT: u32 = 5;
const PAIR_SOURCE_MASK: u32 = 30;
const SINGLE_MASK: u32 = 0xffff_fc00;
const PAIR_MASK: u32 = 0xffff_fc20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Precision {
    Half,
    Bfloat16,
    Single,
}

impl Precision {
    pub const fn bytes(self) -> usize {
        match self {
            Self::Half | Self::Bfloat16 => 2,
            Self::Single => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Widen {
        precision: Precision,
        source2: bool,
        top: bool,
    },
    Narrow {
        precision: Precision,
        top: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operand {
    pub kind: Kind,
    pub destination: u8,
    /// Narrowing reads this even register and its successor before writing.
    pub source: u8,
}

struct Encoding {
    value: u32,
    id: &'static str,
    kind: Kind,
}

const ENCODINGS: &[Encoding] = &[
    Encoding {
        value: 0x6508_3000,
        id: "f1cvt_z_z8_b2h",
        kind: Kind::Widen {
            precision: Precision::Half,
            source2: false,
            top: false,
        },
    },
    Encoding {
        value: 0x6509_3000,
        id: "f1cvtlt_z_z8_b2h",
        kind: Kind::Widen {
            precision: Precision::Half,
            source2: false,
            top: true,
        },
    },
    Encoding {
        value: 0x6508_3400,
        id: "f2cvt_z_z8_b2h",
        kind: Kind::Widen {
            precision: Precision::Half,
            source2: true,
            top: false,
        },
    },
    Encoding {
        value: 0x6509_3400,
        id: "f2cvtlt_z_z8_b2h",
        kind: Kind::Widen {
            precision: Precision::Half,
            source2: true,
            top: true,
        },
    },
    Encoding {
        value: 0x6508_3800,
        id: "bf1cvt_z_z8_b2bf",
        kind: Kind::Widen {
            precision: Precision::Bfloat16,
            source2: false,
            top: false,
        },
    },
    Encoding {
        value: 0x6509_3800,
        id: "bf1cvtlt_z_z8_b2bf",
        kind: Kind::Widen {
            precision: Precision::Bfloat16,
            source2: false,
            top: true,
        },
    },
    Encoding {
        value: 0x6508_3c00,
        id: "bf2cvt_z_z8_b2bf",
        kind: Kind::Widen {
            precision: Precision::Bfloat16,
            source2: true,
            top: false,
        },
    },
    Encoding {
        value: 0x6509_3c00,
        id: "bf2cvtlt_z_z8_b2bf",
        kind: Kind::Widen {
            precision: Precision::Bfloat16,
            source2: true,
            top: true,
        },
    },
    Encoding {
        value: 0x650a_3000,
        id: "fcvtn_z8_mz2_h2b",
        kind: Kind::Narrow {
            precision: Precision::Half,
            top: false,
        },
    },
    Encoding {
        value: 0x650a_3800,
        id: "bfcvtn_z8_mz2_bf2b",
        kind: Kind::Narrow {
            precision: Precision::Bfloat16,
            top: false,
        },
    },
    Encoding {
        value: 0x650a_3400,
        id: "fcvtnb_z8_mz2_s2b",
        kind: Kind::Narrow {
            precision: Precision::Single,
            top: false,
        },
    },
    Encoding {
        value: 0x650a_3c00,
        id: "fcvtnt_z8_mz2_s2b",
        kind: Kind::Narrow {
            precision: Precision::Single,
            top: true,
        },
    },
];

fn encoding(word: u32) -> Option<&'static Encoding> {
    ENCODINGS.iter().find(|encoding| {
        let mask = match encoding.kind {
            Kind::Widen { .. } => SINGLE_MASK,
            Kind::Narrow { .. } => PAIR_MASK,
        };
        word & mask == encoding.value
    })
}

pub fn canonical_id(word: u32) -> Option<&'static str> {
    encoding(word).map(|encoding| encoding.id)
}

#[allow(clippy::result_unit_err)]
pub fn decode(word: u32) -> Option<Result<Operand, ()>> {
    let encoding = encoding(word)?;
    let source_mask = match encoding.kind {
        Kind::Widen { .. } => REGISTER_MASK,
        Kind::Narrow { .. } => PAIR_SOURCE_MASK,
    };
    Some(Ok(Operand {
        kind: encoding.kind,
        source: ((word >> SOURCE_SHIFT) & source_mask) as u8,
        destination: (word & REGISTER_MASK) as u8,
    }))
}

#[cfg(test)]
mod tests;
