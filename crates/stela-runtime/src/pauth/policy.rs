//! Fixed VA47/iTBI0/dTBI1 PAuth bit-layout policies, independent of key lifetime.
//! The caller supplies an exact QARMA result and the effective key-enable policy.
const ADDRESS_BITS: u32 = 47;
const ADDRESS_MASK: u64 = (1 << ADDRESS_BITS) - 1;
const REGION_SHIFT: u32 = 55;
const REGION_BIT: u64 = 1 << REGION_SHIFT;
const DATA_TOP_SHIFT: u32 = 55;
const INSTRUCTION_TOP_SHIFT: u32 = 63;
const DATA_EXTENSION_MASK: u64 = ((1 << 56) - 1) & !ADDRESS_MASK;
const INSTRUCTION_EXTENSION_MASK: u64 = !ADDRESS_MASK;
const DATA_POISON_SHIFT: u32 = 53;
const INSTRUCTION_POISON_SHIFT: u32 = 61;
const POISON_FIELD_MASK: u64 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    Classic,
    Enhanced,
    Faulting,
    FaultingCombined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    Instruction,
    Data,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    A,
    B,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authentication {
    pub pointer: u64,
    pub authenticated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    /// Architectural PAC failure syndrome low two bits (data::key_number).
    pub code: u8,
}

impl Domain {
    const fn extension_mask(self) -> u64 {
        match self {
            Self::Instruction => INSTRUCTION_EXTENSION_MASK,
            Self::Data => DATA_EXTENSION_MASK,
        }
    }
    const fn pac_mask(self) -> u64 {
        self.extension_mask() & !REGION_BIT
    }
    const fn top_shift(self) -> u32 {
        match self {
            Self::Instruction => INSTRUCTION_TOP_SHIFT,
            Self::Data => DATA_TOP_SHIFT,
        }
    }
    const fn poison_shift(self) -> u32 {
        match self {
            Self::Instruction => INSTRUCTION_POISON_SHIFT,
            Self::Data => DATA_POISON_SHIFT,
        }
    }
}

pub fn signing_input(domain: Domain, pointer: u64) -> u64 {
    let extension = if pointer & (1 << domain.top_shift()) != 0 {
        domain.extension_mask()
    } else {
        0
    };
    (pointer & !domain.extension_mask()) | extension
}

pub fn authentication_input(domain: Domain, pointer: u64) -> u64 {
    (pointer & !domain.extension_mask())
        | if pointer & REGION_BIT != 0 {
            domain.extension_mask()
        } else {
            0
        }
}

/// `pac` is ComputePAC(signing_input(domain,pointer),modifier,key).
pub fn sign(version: Version, domain: Domain, pointer: u64, mut pac: u64) -> u64 {
    let extension = signing_input(domain, pointer) & domain.extension_mask();
    if version == Version::Classic {
        let field = pointer & domain.extension_mask();
        if field != 0 && field != domain.extension_mask() {
            pac ^= 1 << (domain.top_shift() - 1);
        }
        (pointer & !domain.extension_mask()) | (extension & REGION_BIT) | (pac & domain.pac_mask())
    } else {
        ((pointer ^ (pac & domain.pac_mask())) & !REGION_BIT) | (extension & REGION_BIT)
    }
}

/// `pac` is ComputePAC(authentication_input(domain,pointer),modifier,key).
/// FPAC faults standalone AUT; FPACCOMBINE additionally faults LDRA and transfers.
pub fn authenticate(
    version: Version,
    domain: Domain,
    side: Side,
    combined: bool,
    pointer: u64,
    pac: u64,
) -> Result<Authentication, Failure> {
    let original = authentication_input(domain, pointer);
    if version == Version::Classic {
        let authenticated = (pac ^ pointer) & domain.pac_mask() == 0;
        let poison = match side {
            Side::A => 1,
            Side::B => 2,
        };
        let shift = domain.poison_shift();
        return Ok(Authentication {
            pointer: if authenticated {
                original
            } else {
                (original & !(POISON_FIELD_MASK << shift)) | (poison << shift)
            },
            authenticated,
        });
    }
    let pointer = pointer ^ (pac & domain.pac_mask());
    let authenticated = (pointer ^ original) & domain.extension_mask() == 0;
    let faulting =
        version == Version::FaultingCombined || (version == Version::Faulting && !combined);
    if faulting && !authenticated {
        return Err(Failure {
            code: (u8::from(domain == Domain::Data) << 1) | u8::from(side == Side::B),
        });
    }
    Ok(Authentication {
        pointer,
        authenticated,
    })
}

#[cfg(test)]
mod tests;
