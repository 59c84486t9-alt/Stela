//! Apple fast-IPI register encodings, shared by architectural admission and
//! the board's interrupt model. Linux irq-apple-aic and m1n1 cpu_regs name
//! the four selectors; countdown and request effects belong to the model.
use stela_compiler::aarch64::system::registers::Encoding;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    RequestLocal,
    RequestGlobal,
    Status,
    Countdown,
}
impl Register {
    pub const fn encoding(self) -> Encoding {
        match self {
            Self::RequestLocal => Encoding::new(3, 5, 15, 0, 0),
            Self::RequestGlobal => Encoding::new(3, 5, 15, 0, 1),
            Self::Status => Encoding::new(3, 5, 15, 1, 1),
            Self::Countdown => Encoding::new(3, 5, 15, 3, 1),
        }
    }
    pub const fn decode(encoding: Encoding) -> Option<Self> {
        match (
            encoding.op0(),
            encoding.op1(),
            encoding.crn(),
            encoding.crm(),
            encoding.op2(),
        ) {
            (3, 5, 15, 0, 0) => Some(Self::RequestLocal),
            (3, 5, 15, 0, 1) => Some(Self::RequestGlobal),
            (3, 5, 15, 1, 1) => Some(Self::Status),
            (3, 5, 15, 3, 1) => Some(Self::Countdown),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_fast_ipi_selectors_round_trip_without_admitting_neighbors() {
        for register in [
            Register::RequestLocal,
            Register::RequestGlobal,
            Register::Status,
            Register::Countdown,
        ] {
            assert_eq!(Register::decode(register.encoding()), Some(register));
        }
        for encoding in [
            Encoding::new(2, 5, 15, 0, 0),
            Encoding::new(3, 4, 15, 0, 0),
            Encoding::new(3, 5, 14, 0, 0),
            Encoding::new(3, 5, 15, 2, 1),
            Encoding::new(3, 5, 15, 3, 0),
            Encoding::new(3, 5, 15, 3, 2),
        ] {
            assert_eq!(Register::decode(encoding), None);
        }
    }
}
