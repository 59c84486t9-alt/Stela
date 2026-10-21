// SPDX-License-Identifier: GPL-2.0-only
// SCI conforming electrical defaults adapted from Linux arch/x86/kernel/acpi/boot.c,
// Copyright (C) 2001, 2002 Paul Diefenbaugh; (C) 2001 Jun Nakajima.
//! Bounded ACPI line routing; CPU enumeration/bootstrap belongs to its owner.
//! SCI conforming electrical flags mean active-low/level, rather than ISA's
//! active-high/edge defaults. No bridge/PIRQ routing is inferred from a MADT.
use alloc::vec::Vec;
use stela_drivers::bus::irq::{LineRoute, Polarity, Trigger};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteError {
    InvalidTable,
    InvalidStructure,
    UnsupportedStructure(u8),
    InvalidAddress,
    InvalidElectrical,
    Duplicate,
    MissingUnit,
    NmiConflict,
    UnsupportedSci,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Unit {
    pub id: u8,
    pub base: u64,
    pub gsi_base: u32,
}
#[derive(Clone, Copy, Debug)]
struct Override {
    source: u8,
    gsi: u32,
    flags: u16,
}

pub struct Routing {
    pub units: Vec<Unit>,
    overrides: Vec<Override>,
    nmis: Vec<u32>,
}
fn word(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn dword(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn table<'a>(b: &'a [u8], signature: &[u8; 4], minimum: usize) -> Result<&'a [u8], RouteError> {
    if b.len() < minimum || &b[..4] != signature {
        return Err(RouteError::InvalidTable);
    }
    let length = dword(b, 4) as usize;
    if length < minimum || length > b.len() {
        return Err(RouteError::InvalidTable);
    }
    let b = &b[..length];
    if b.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) != 0 {
        return Err(RouteError::InvalidTable);
    }
    Ok(b)
}
fn electrical(flags: u16, sci: bool) -> Result<(Polarity, Trigger), RouteError> {
    let default = if sci {
        (Polarity::Low, Trigger::Level)
    } else {
        (Polarity::High, Trigger::Edge)
    };
    if flags & !15 != 0 {
        return Err(RouteError::InvalidElectrical);
    }
    let polarity = match flags & 3 {
        0 => default.0,
        1 => Polarity::High,
        3 => Polarity::Low,
        _ => return Err(RouteError::InvalidElectrical),
    };
    let trigger = match flags >> 2 {
        0 => default.1,
        1 => Trigger::Edge,
        3 => Trigger::Level,
        _ => return Err(RouteError::InvalidElectrical),
    };
    Ok((polarity, trigger))
}

impl Routing {
    pub fn parse(madt: &[u8], physical_bits: u8) -> Result<Self, RouteError> {
        if !(32..=52).contains(&physical_bits) {
            return Err(RouteError::InvalidAddress);
        }
        let madt = table(madt, b"APIC", 44)?;
        // The PC/AT compatibility flag is the only currently defined bit.
        if dword(madt, 40) & !1 != 0 {
            return Err(RouteError::InvalidTable);
        }
        let mut routing = Self {
            units: Vec::new(),
            overrides: Vec::new(),
            nmis: Vec::new(),
        };
        let mut lapic_override = false;
        let mut offset = 44;
        while offset < madt.len() {
            if madt.len() - offset < 2 {
                return Err(RouteError::InvalidStructure);
            }
            let length = usize::from(madt[offset + 1]);
            if length < 2 || length > madt.len() - offset {
                return Err(RouteError::InvalidStructure);
            }
            let entry = &madt[offset..offset + length];
            match (entry[0], length) {
                (1, 12) => {
                    let base = u64::from(dword(entry, 4));
                    if entry[3] != 0
                        || base == 0
                        || base & 4095 != 0
                        || base
                            .checked_add(4096)
                            .is_none_or(|end| end > 1u64 << physical_bits)
                    {
                        return Err(RouteError::InvalidAddress);
                    }
                    let unit = Unit {
                        id: entry[2],
                        base,
                        gsi_base: dword(entry, 8),
                    };
                    if routing
                        .units
                        .iter()
                        .any(|u| u.id == unit.id || u.base == base || u.gsi_base == unit.gsi_base)
                    {
                        return Err(RouteError::Duplicate);
                    }
                    routing.units.push(unit);
                }
                (2, 10) => {
                    let flags = word(entry, 8);
                    electrical(flags, false)?;
                    if entry[2] != 0 || entry[3] >= 16 {
                        return Err(RouteError::InvalidStructure);
                    }
                    let value = Override {
                        source: entry[3],
                        gsi: dword(entry, 4),
                        flags,
                    };
                    if routing
                        .overrides
                        .iter()
                        .any(|old| old.source == value.source || old.gsi == value.gsi)
                    {
                        return Err(RouteError::Duplicate);
                    }
                    routing.overrides.push(value);
                }
                (3, 8) => {
                    electrical(word(entry, 2), false)?;
                    let gsi = dword(entry, 4);
                    if routing.nmis.contains(&gsi) {
                        return Err(RouteError::Duplicate);
                    }
                    routing.nmis.push(gsi);
                }
                // Validate lengths, but never apply or elect processors here.
                (0, 8) | (4, 6) | (9, 16) | (10, 12) => {}
                (5, 12) => {
                    let address = u64::from_le_bytes(entry[4..12].try_into().unwrap());
                    if lapic_override
                        || word(entry, 2) != 0
                        || address == 0
                        || address & 4095 != 0
                        || address
                            .checked_add(4096)
                            .is_none_or(|end| end > 1u64 << physical_bits)
                    {
                        return Err(RouteError::InvalidAddress);
                    }
                    lapic_override = true;
                }
                (kind @ (0..=5 | 9 | 10), _) => {
                    let _ = kind;
                    return Err(RouteError::InvalidStructure);
                }
                (kind, _) => return Err(RouteError::UnsupportedStructure(kind)),
            }
            offset += length;
        }
        if routing.units.is_empty() {
            return Err(RouteError::MissingUnit);
        }
        Ok(routing)
    }

    pub fn isa(&self, irq: u8) -> Result<LineRoute, RouteError> {
        if irq >= 16 {
            return Err(RouteError::InvalidStructure);
        }
        self.line(u32::from(irq), false)
    }
    pub fn sci(&self, fadt: &[u8]) -> Result<LineRoute, RouteError> {
        let fadt = table(fadt, b"FACP", 116)?;
        let irq = u32::from(word(fadt, 46));
        if irq == 0 || irq == u32::from(u16::MAX) {
            return Err(RouteError::UnsupportedSci);
        }
        let line = self.line(irq, true)?;
        if line.trigger != Trigger::Level {
            return Err(RouteError::UnsupportedSci);
        }
        Ok(line)
    }
    fn line(&self, irq: u32, sci: bool) -> Result<LineRoute, RouteError> {
        let override_ = self.overrides.iter().find(|o| u32::from(o.source) == irq);
        let (gsi, flags) = override_.map_or((irq, 0), |o| (o.gsi, o.flags));
        if self.nmis.contains(&gsi) {
            return Err(RouteError::NmiConflict);
        }
        if self
            .overrides
            .iter()
            .any(|o| o.gsi == gsi && u32::from(o.source) != irq)
        {
            return Err(RouteError::Duplicate);
        }
        let (polarity, trigger) = electrical(flags, sci)?;
        Ok(LineRoute {
            gsi,
            polarity,
            trigger,
        })
    }

    /// Bind actual IOAPIC version-reported pin counts, never a guessed 24-pin
    /// span. Every MADT unit must be present exactly once, with disjoint GSIs.
    pub fn owner(&self, line: LineRoute, actual: &[(Unit, u16)]) -> Result<Unit, RouteError> {
        if actual.len() != self.units.len() {
            return Err(RouteError::MissingUnit);
        }
        for (index, (unit, pins)) in actual.iter().enumerate() {
            if !self.units.contains(unit) || *pins == 0 || *pins > 120 {
                return Err(RouteError::MissingUnit);
            }
            let end = unit
                .gsi_base
                .checked_add(u32::from(*pins))
                .ok_or(RouteError::InvalidAddress)?;
            for (other, other_pins) in &actual[..index] {
                let other_end = other
                    .gsi_base
                    .checked_add(u32::from(*other_pins))
                    .ok_or(RouteError::InvalidAddress)?;
                if unit.gsi_base < other_end && other.gsi_base < end {
                    return Err(RouteError::Duplicate);
                }
            }
        }
        if self.nmis.contains(&line.gsi) {
            return Err(RouteError::NmiConflict);
        }
        actual
            .iter()
            .find(|(u, pins)| line.gsi >= u.gsi_base && line.gsi - u.gsi_base < u32::from(*pins))
            .map(|(u, _)| *u)
            .ok_or(RouteError::MissingUnit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    fn finish(mut b: Vec<u8>, sig: &[u8; 4]) -> Vec<u8> {
        b[..4].copy_from_slice(sig);
        let length = b.len() as u32;
        b[4..8].copy_from_slice(&length.to_le_bytes());
        b[9] = 0;
        b[9] = 0u8.wrapping_sub(b.iter().fold(0u8, |s, x| s.wrapping_add(*x)));
        b
    }
    fn madt(extra: &[u8]) -> Vec<u8> {
        let mut b = vec![0; 44];
        b.extend_from_slice(&[1, 12, 0, 0, 0, 0, 0xc0, 0xfe, 0, 0, 0, 0]);
        b.extend_from_slice(extra);
        finish(b, b"APIC")
    }
    fn fadt(irq: u16) -> Vec<u8> {
        let mut b = vec![0; 116];
        b[46..48].copy_from_slice(&irq.to_le_bytes());
        finish(b, b"FACP")
    }
    #[test]
    fn sci_override_conform_means_low_level_while_isa_is_high_edge() {
        let r = Routing::parse(&madt(&[2, 10, 0, 9, 11, 0, 0, 0, 0, 0]), 48).unwrap();
        assert_eq!(
            r.sci(&fadt(9)),
            Ok(LineRoute {
                gsi: 11,
                polarity: Polarity::Low,
                trigger: Trigger::Level
            })
        );
        assert_eq!(
            r.isa(9),
            Ok(LineRoute {
                gsi: 11,
                polarity: Polarity::High,
                trigger: Trigger::Edge
            })
        );
        assert_eq!(r.sci(&fadt(20)).unwrap().gsi, 20);
        let explicit = Routing::parse(&madt(&[2, 10, 0, 9, 9, 0, 0, 0, 15, 0]), 48).unwrap();
        assert_eq!(explicit.sci(&fadt(9)).unwrap().trigger, Trigger::Level);
        let high = Routing::parse(&madt(&[2, 10, 0, 9, 9, 0, 0, 0, 13, 0]), 48).unwrap();
        assert_eq!(
            high.sci(&fadt(9)),
            Ok(LineRoute {
                gsi: 9,
                polarity: Polarity::High,
                trigger: Trigger::Level
            })
        );
        let alias = Routing::parse(&madt(&[2, 10, 0, 5, 9, 0, 0, 0, 13, 0]), 48).unwrap();
        assert_eq!(alias.sci(&fadt(9)), Err(RouteError::Duplicate));
        let edge = Routing::parse(&madt(&[2, 10, 0, 9, 9, 0, 0, 0, 5, 0]), 48).unwrap();
        assert_eq!(edge.sci(&fadt(9)), Err(RouteError::UnsupportedSci));
    }
    #[test]
    fn malformed_flags_duplicates_unknown_entries_and_nmi_are_refused() {
        for extra in [
            &[2, 0][..],
            &[2, 11, 0, 0][..],
            &[2, 10, 0, 9, 9, 0, 0, 0, 2, 0][..],
            &[2, 10, 0, 9, 9, 0, 0, 0, 0, 128][..],
            &[6, 2][..],
        ] {
            assert!(Routing::parse(&madt(extra), 48).is_err());
        }
        let iso = [2, 10, 0, 9, 9, 0, 0, 0, 15, 0];
        let mut duplicate = iso.to_vec();
        duplicate.extend_from_slice(&iso);
        assert!(matches!(
            Routing::parse(&madt(&duplicate), 48),
            Err(RouteError::Duplicate)
        ));
        let r = Routing::parse(&madt(&[3, 8, 15, 0, 9, 0, 0, 0]), 48).unwrap();
        assert_eq!(r.sci(&fadt(9)), Err(RouteError::NmiConflict));
        let mut bad = madt(&[]);
        bad[9] ^= 1;
        assert!(matches!(
            Routing::parse(&bad, 48),
            Err(RouteError::InvalidTable)
        ));
    }
    #[test]
    fn ownership_uses_live_pin_counts_and_refuses_missing_duplicate_or_overlapping_units() {
        let r = Routing::parse(&madt(&[]), 48).unwrap();
        let u = r.units[0];
        let line = r.sci(&fadt(9)).unwrap();
        assert_eq!(r.owner(line, &[(u, 24)]), Ok(u));
        assert_eq!(r.owner(line, &[]), Err(RouteError::MissingUnit));
        assert_eq!(r.owner(line, &[(u, 8)]), Err(RouteError::MissingUnit));
        assert_eq!(r.owner(line, &[(u, 121)]), Err(RouteError::MissingUnit));
        let mut second = [1, 12, 1, 0, 0, 16, 0xc0, 0xfe, 16, 0, 0, 0];
        let r = Routing::parse(&madt(&second), 48).unwrap();
        assert_eq!(
            r.owner(line, &[(r.units[0], 24), (r.units[1], 24)]),
            Err(RouteError::Duplicate)
        );
        second[8] = 24;
        let r = Routing::parse(&madt(&second), 48).unwrap();
        assert_eq!(
            r.owner(line, &[(r.units[0], 24), (r.units[0], 24)]),
            Err(RouteError::Duplicate)
        );
        assert_eq!(
            r.owner(line, &[(r.units[0], 24), (r.units[1], 24)]),
            Ok(r.units[0])
        );
    }
}
