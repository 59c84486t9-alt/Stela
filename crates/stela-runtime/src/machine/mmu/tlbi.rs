//! The exact scope of a TLB maintenance instruction (pseudocode
//! AArch64.TLBI_*, TLBIRange, AArch64.EffectiveBroadcast and TLBIMatch) for
//! the profile: no FEAT_XS, FEAT_D128, FEAT_LPA2, FEAT_RME or FEAT_TLBID.
//!
//! Removing more than the scope is always permitted, so a cache that keeps
//! no translation context may discard everything instead, and one that
//! holds a single context's translations may discard what [`Scope::reach`]
//! names.

use super::Regime;
use crate::machine::system::{Broadcast, Regime as Named, Tlbi, TlbiKind, TlbiLevel};

/// A cached translation with the context it was made in (pseudocode
/// TLBRecord).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub regime: Regime,
    /// The VMID of an EL1&0 entry made while EL2 is enabled (UseVMID).
    pub vmid: Option<u8>,
    /// The ASID of a non-global entry; `None` for a global entry and in the
    /// EL2 regime, which has no ASIDs.
    pub asid: Option<u16>,
    /// The input address: a VA, or an IPA for a stage-2-only entry.
    pub address: u64,
    /// log2 of the bytes the entry maps.
    pub size_bits: u32,
    /// log2 of the translation granule (12 or 14).
    pub granule_bits: u32,
    /// The lookup level of the descriptor it came from.
    pub level: i8,
    /// The entry holds stage-1 and stage-2 information respectively.
    pub stage1: bool,
    pub stage2: bool,
    /// A walk-cache entry for a table descriptor rather than a leaf.
    pub table: bool,
}

/// The PE state a TLBI's effect depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Context {
    /// The EL the instruction executes at.
    pub el: u8,
    /// EL2 is implemented and enabled (EL2Enabled).
    pub el2: bool,
    /// HCR_EL2.E2H and TGE.
    pub e2h: bool,
    pub tge: bool,
    /// HCR_EL2.FB: EL1 TLBIs are broadcast in the Inner Shareable domain.
    pub fb: bool,
}

/// The set of entries one TLBI removes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scope {
    kind: TlbiKind,
    regime: Regime,
    /// The VMID compared, for the forms that compare one.
    vmid: Option<u8>,
    asid: u16,
    /// The first address, and for a range form the address after the last.
    address: u64,
    end: u64,
    /// TTL[3:0] of a VA or IPA form, or TG:TTL[1:0] of a range form.
    ttl: u8,
    level: TlbiLevel,
    /// The domain the operation reaches after HCR_EL2.FB. One PE makes every
    /// domain equivalent to the local one.
    pub broadcast: Broadcast,
    /// A range form with TG 0b00 removes nothing.
    valid: bool,
}

/// VA[55:0] and IPA[55:0] as compared by the matching.
const ADDRESS_BITS: u64 = (1 << 56) - 1;
const PAGE_SHIFT: u64 = 12;
const VA_OPERAND: u64 = (1 << 44) - 1;
const IPA_OPERAND: u64 = (1 << 40) - 1;
const RANGE_BASE: u64 = (1 << 37) - 1;

fn regime(named: Named) -> Regime {
    match named {
        Named::EL10 => Regime::El10,
        Named::EL20 => Regime::El20,
        Named::EL2 => Regime::El2,
    }
}

/// The granule a TG field selects; `None` for 0b00.
fn granule(tg: u8) -> Option<u32> {
    match tg & 3 {
        1 => Some(12),
        2 => Some(14),
        3 => Some(16),
        _ => None,
    }
}

/// TTL values that hint nothing (pseudocode ResTLBITTL without FEAT_LPA2).
fn reserved_ttl(ttl: u8) -> bool {
    matches!(ttl & 0xf, 0b0000..=0b0100 | 0b1000 | 0b1001 | 0b1100)
}

/// Range TTL values that hint nothing (pseudocode ResTLBIRTTL).
fn reserved_range_ttl(tg: u8, ttl: u8) -> bool {
    match ttl & 3 {
        0 => true,
        1 => granule(tg) == Some(14),
        _ => false,
    }
}

/// The first and end addresses of a range operand (pseudocode TLBIRange
/// without FEAT_LPA2): BaseADDR in units of the granule, sign-extended from
/// its top bit, and (NUM + 1) * 2^(5 * SCALE + 1) granules.
fn range(operand: u64) -> Option<(u8, u64, u64)> {
    let tg = (operand >> 46) as u8 & 3;
    let bits = granule(tg)?;
    let scale = (operand >> 44) & 3;
    let num = (operand >> 39) & 0x1f;
    let base = operand & RANGE_BASE;
    let top = bits + 36;
    let start = ((base << bits) as i64) << (63 - top) >> (63 - top);
    let start = start as u64;
    let end = start.wrapping_add((num + 1) << (5 * scale + 1 + u64::from(bits)));
    // A range that crosses bit 52 ends at the top of its half.
    let end = if (end ^ start) >> 52 & 1 != 0 {
        if start >> 52 & 1 != 0 {
            u64::MAX
        } else {
            (1 << 52) - 1
        }
    } else {
        end
    };
    Some((tg, start, end))
}

impl Scope {
    /// The scope of `tlbi` as the generated accessor decoded it, executed in
    /// `context`.
    pub fn new(tlbi: &Tlbi, context: Context) -> Self {
        let in_host = context.e2h && context.tge;
        let named = regime(tlbi.regime);
        let regime = match tlbi.kind {
            TlbiKind::VA | TlbiKind::RVA => match named {
                Regime::El10 if in_host => Regime::El20,
                Regime::El2 if context.e2h => Regime::El20,
                other => other,
            },
            TlbiKind::ASID | TlbiKind::VAA | TlbiKind::RVAA | TlbiKind::VMALL if in_host => {
                Regime::El20
            }
            _ => named,
        };
        let vmid = match tlbi.kind {
            TlbiKind::IPAS2 | TlbiKind::RIPAS2 | TlbiKind::VMALLS12 => {
                Some(tlbi.vmid.unwrap_or(0) as u8)
            }
            TlbiKind::ALL => None,
            _ if regime == Regime::El10 && context.el2 => Some(tlbi.vmid.unwrap_or(0) as u8),
            _ => None,
        };
        let operand = tlbi.operand;
        let mut scope = Self {
            kind: tlbi.kind,
            regime,
            vmid,
            asid: (operand >> 48) as u16,
            address: 0,
            end: 0,
            ttl: (operand >> 44) as u8 & 0xf,
            level: tlbi.level,
            broadcast: effective_broadcast(tlbi.broadcast, context),
            valid: true,
        };
        match tlbi.kind {
            TlbiKind::VA | TlbiKind::VAA => {
                scope.address = (operand & VA_OPERAND) << PAGE_SHIFT;
            }
            TlbiKind::IPAS2 => scope.address = (operand & IPA_OPERAND) << PAGE_SHIFT,
            TlbiKind::RVA | TlbiKind::RVAA | TlbiKind::RIPAS2 => match range(operand) {
                Some((tg, start, end)) => {
                    scope.ttl = tg << 2 | (operand >> 37) as u8 & 3;
                    scope.address = start;
                    scope.end = end;
                }
                None => scope.valid = false,
            },
            _ => {}
        }
        scope
    }

    fn vmid_matches(self, entry: &Entry) -> bool {
        self.vmid == entry.vmid
    }

    /// The entry's VMID is either unused or the one this scope names.
    fn vmid_covers(self, entry: &Entry) -> bool {
        entry.vmid.is_none() || entry.vmid == self.vmid
    }

    /// The address bits above the entry's size match.
    fn address_matches(self, entry: &Entry) -> bool {
        let mask = ADDRESS_BITS & !((1u64 << entry.size_bits) - 1);
        self.address & mask == entry.address & mask
    }

    fn ttl_matches(self, entry: &Entry) -> bool {
        reserved_ttl(self.ttl)
            || granule(self.ttl >> 2) == Some(entry.granule_bits)
                && i8::try_from(self.ttl & 3) == Ok(entry.level)
    }

    fn range_matches(self, entry: &Entry) -> bool {
        let tg = self.ttl >> 2;
        let mask = (1u64 << entry.size_bits) - 1;
        let first = entry.address & !mask & ADDRESS_BITS;
        let last = (entry.address | mask) & ADDRESS_BITS;
        granule(tg) == Some(entry.granule_bits)
            && (reserved_range_ttl(tg, self.ttl) || i8::try_from(self.ttl & 3) == Ok(entry.level))
            && self.address & ADDRESS_BITS <= last
            && self.end & ADDRESS_BITS > first
    }

    fn level_matches(self, entry: &Entry) -> bool {
        self.level == TlbiLevel::Any || !entry.table
    }

    /// Whether the TLBI removes `entry` (pseudocode TLBIMatch).
    pub fn covers(self, entry: &Entry) -> bool {
        if !self.valid {
            return false;
        }
        let same_regime = self.regime == entry.regime;
        let first_stage = entry.stage1 && same_regime && self.vmid_matches(entry);
        let asid = match entry.asid {
            Some(asid) => asid == self.asid,
            None => true,
        };
        match self.kind {
            TlbiKind::ALL => {
                let el2 = |regime| matches!(regime, Regime::El20 | Regime::El2);
                same_regime || el2(self.regime) && el2(entry.regime)
            }
            TlbiKind::VMALL => first_stage,
            TlbiKind::VMALLS12 => same_regime && self.vmid_covers(entry),
            TlbiKind::ASID => first_stage && entry.asid == Some(self.asid),
            TlbiKind::VA => {
                first_stage
                    && asid
                    && self.address_matches(entry)
                    && self.ttl_matches(entry)
                    && self.level_matches(entry)
            }
            TlbiKind::VAA => {
                first_stage
                    && self.address_matches(entry)
                    && self.ttl_matches(entry)
                    && self.level_matches(entry)
            }
            TlbiKind::RVA => {
                first_stage && asid && self.range_matches(entry) && self.level_matches(entry)
            }
            TlbiKind::RVAA => first_stage && self.range_matches(entry) && self.level_matches(entry),
            TlbiKind::IPAS2 | TlbiKind::RIPAS2 => {
                let stage2_only = !entry.stage1 && entry.stage2 && same_regime;
                let address = if self.kind == TlbiKind::IPAS2 {
                    self.address_matches(entry) && self.ttl_matches(entry)
                } else {
                    self.range_matches(entry)
                };
                stage2_only && self.vmid_covers(entry) && address && self.level_matches(entry)
            }
        }
    }
}

/// The one context a cache that keeps no context per entry holds
/// translations of: the regime the PE translates in now, under the VMID it
/// uses now (the one every TLBI that names a VMID takes from VTTBR_EL2), with
/// non-global entries of one ASID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Current {
    pub regime: Regime,
    /// The ASID of its non-global entries; `None` in the EL2 regime.
    pub asid: Option<u16>,
}

/// What a TLBI removes from a cache of the [`Current`] context's
/// stage-1 (or combined) translations, as a superset of its scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    Nothing,
    /// The entries whose input range holds this VA, canonical.
    Containing(u64),
    /// The entries whose input range overlaps `first..=last`, canonical VAs.
    Overlapping {
        first: u64,
        last: u64,
    },
    All,
}

impl Reach {
    /// Whether it removes nothing of the upper half (VA bit 55 set, TTBR1's
    /// range): it names no entry or only lower-half addresses.
    pub fn lower_only(self) -> bool {
        const UPPER: u64 = 1 << 55;
        match self {
            Self::Nothing => true,
            Self::Containing(address) => address & UPPER == 0,
            Self::Overlapping { first, last } => (first | last) & UPPER == 0,
            Self::All => false,
        }
    }
}

/// VA[55:0] with bit 55 copied above: the address of either half.
fn canonical(address: u64) -> u64 {
    (((address << 8) as i64) >> 8) as u64
}

impl Scope {
    /// What this TLBI removes from a cache of `current`'s translations: no
    /// entry of another regime, nothing of ASID forms for another ASID, all
    /// for the forms without an address, and for the address forms the
    /// entries at their address or range whatever their ASID, level or
    /// size. The IPA forms remove only stage-2-only entries
    /// ([`Scope::covers`]); they remove everything here, which the
    /// combined stage-1 and stage-2 entries a VMALLS12E1 must follow make
    /// harmless.
    pub fn reach(self, current: &Current) -> Reach {
        if !self.valid {
            return Reach::Nothing;
        }
        let same_regime = self.regime == current.regime;
        let all = |reaches: bool| if reaches { Reach::All } else { Reach::Nothing };
        match self.kind {
            TlbiKind::ALL => {
                let el2 = |regime| matches!(regime, Regime::El20 | Regime::El2);
                all(same_regime || el2(self.regime) && el2(current.regime))
            }
            TlbiKind::VMALL | TlbiKind::VMALLS12 | TlbiKind::IPAS2 | TlbiKind::RIPAS2 => {
                all(same_regime)
            }
            TlbiKind::ASID => all(same_regime && current.asid == Some(self.asid)),
            TlbiKind::VA | TlbiKind::VAA if same_regime => {
                Reach::Containing(canonical(self.address))
            }
            TlbiKind::RVA | TlbiKind::RVAA if same_regime => Reach::Overlapping {
                first: canonical(self.address),
                last: if self.end == u64::MAX {
                    u64::MAX
                } else {
                    canonical(self.end.wrapping_sub(1))
                },
            },
            TlbiKind::VA | TlbiKind::VAA | TlbiKind::RVA | TlbiKind::RVAA => Reach::Nothing,
        }
    }
}

/// HCR_EL2.FB makes a local TLBI at EL1 Inner Shareable (pseudocode
/// AArch64.EffectiveBroadcast without FEAT_TLBID).
fn effective_broadcast(broadcast: Broadcast, context: Context) -> Broadcast {
    if broadcast == Broadcast::NSH && context.el == 1 && context.el2 && context.fb {
        Broadcast::ISH
    } else {
        broadcast
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::system::TlbiAttr;

    fn tlbi(kind: TlbiKind, regime: Named, level: TlbiLevel, operand: u64) -> Tlbi {
        Tlbi {
            kind,
            regime,
            vmid: Some(5),
            broadcast: Broadcast::NSH,
            level,
            attr: TlbiAttr::AllAttr,
            operand,
        }
    }

    const GUEST: Context = Context {
        el: 1,
        el2: true,
        e2h: true,
        tge: false,
        fb: false,
    };
    const HOST: Context = Context {
        el: 2,
        tge: true,
        ..GUEST
    };

    /// A 16 KiB level-3 page of EL1&0 at `address`, VMID 5, ASID 7.
    fn page(address: u64) -> Entry {
        Entry {
            regime: Regime::El10,
            vmid: Some(5),
            asid: Some(7),
            address,
            size_bits: 14,
            granule_bits: 14,
            level: 3,
            stage1: true,
            stage2: true,
            table: false,
        }
    }

    fn covers(tlbi: Tlbi, context: Context, entry: Entry) -> bool {
        Scope::new(&tlbi, context).covers(&entry)
    }

    #[test]
    fn va_forms_match_address_asid_level_and_ttl() {
        super::super::test_translation_chip();
        let va = 0x1_2345_c000_u64;
        let entry = page(va);
        let vae1 = |asid: u64, ttl: u64, va: u64, level| {
            tlbi(
                TlbiKind::VA,
                Named::EL10,
                level,
                asid << 48 | ttl << 44 | va >> 12,
            )
        };
        assert!(covers(vae1(7, 0, va + 0x123, TlbiLevel::Any), GUEST, entry));
        assert!(!covers(vae1(8, 0, va, TlbiLevel::Any), GUEST, entry));
        assert!(!covers(
            vae1(7, 0, va + 0x4000, TlbiLevel::Any),
            GUEST,
            entry
        ));
        // A global entry matches any ASID; VAAE1 ignores the ASID.
        let global = Entry {
            asid: None,
            ..entry
        };
        assert!(covers(vae1(8, 0, va, TlbiLevel::Any), GUEST, global));
        let vaae1 = tlbi(
            TlbiKind::VAA,
            Named::EL10,
            TlbiLevel::Any,
            9 << 48 | va >> 12,
        );
        assert!(covers(vaae1, GUEST, entry));
        // A 32 MiB block matches any VA inside it.
        let block = Entry {
            size_bits: 25,
            level: 2,
            ..entry
        };
        assert!(covers(
            vae1(7, 0, va | 0x1ff_0000, TlbiLevel::Any),
            GUEST,
            block
        ));
        // Last level only skips walk-cache entries.
        let table = Entry {
            table: true,
            ..block
        };
        assert!(!covers(vae1(7, 0, va, TlbiLevel::Last), GUEST, table));
        assert!(covers(vae1(7, 0, va, TlbiLevel::Any), GUEST, table));
        // TTL 0b1011 (16 KiB, level 3) matches the page and not the block;
        // 0b0111 (4 KiB) matches neither; the reserved 0b1000 is no hint.
        assert!(covers(vae1(7, 0b1011, va, TlbiLevel::Any), GUEST, entry));
        assert!(!covers(vae1(7, 0b1011, va, TlbiLevel::Any), GUEST, block));
        assert!(!covers(vae1(7, 0b0111, va, TlbiLevel::Any), GUEST, entry));
        assert!(covers(vae1(7, 0b1000, va, TlbiLevel::Any), GUEST, block));
        // Another VMID, another regime, or a stage-2-only entry is untouched.
        assert!(!covers(
            vae1(7, 0, va, TlbiLevel::Any),
            GUEST,
            Entry {
                vmid: Some(6),
                ..entry
            }
        ));
        assert!(!covers(
            vae1(7, 0, va, TlbiLevel::Any),
            GUEST,
            Entry {
                regime: Regime::El20,
                ..entry
            }
        ));
        assert!(!covers(
            vae1(7, 0, va, TlbiLevel::Any),
            GUEST,
            Entry {
                stage1: false,
                ..entry
            }
        ));
        // The upper half compares VA[55:12].
        let high = 0xffff_fff0_0000_4000_u64;
        assert!(covers(
            vae1(7, 0, high & ((1 << 56) - 1), TlbiLevel::Any),
            GUEST,
            page(high)
        ));
    }

    #[test]
    fn host_forms_name_the_el2_and_0_regime_without_a_vmid() {
        super::super::test_translation_chip();
        let host_entry = Entry {
            regime: Regime::El20,
            vmid: None,
            ..page(0x8000)
        };
        // VAE1, ASIDE1 and VMALLE1 in the host (E2H and TGE) act on EL2&0.
        let vae1 = tlbi(TlbiKind::VA, Named::EL10, TlbiLevel::Any, 7 << 48 | 0x8);
        assert!(covers(vae1, HOST, host_entry));
        assert!(!covers(vae1, HOST, page(0x8000)));
        let aside1 = tlbi(TlbiKind::ASID, Named::EL10, TlbiLevel::Any, 7 << 48);
        assert!(covers(aside1, HOST, host_entry));
        let vmalle1 = tlbi(TlbiKind::VMALL, Named::EL10, TlbiLevel::Any, 0);
        assert!(covers(vmalle1, HOST, host_entry));
        // VAE2 with E2H acts on EL2&0 whatever TGE holds.
        let vae2 = tlbi(TlbiKind::VA, Named::EL2, TlbiLevel::Any, 7 << 48 | 0x8);
        assert!(covers(vae2, GUEST, host_entry));
        // ASIDE1 removes only non-global entries of its ASID.
        assert!(!covers(
            aside1,
            HOST,
            Entry {
                asid: None,
                ..host_entry
            }
        ));
        assert!(!covers(
            aside1,
            HOST,
            Entry {
                asid: Some(8),
                ..host_entry
            }
        ));
    }

    #[test]
    fn all_and_vmall_forms_follow_regime_and_vmid() {
        super::super::test_translation_chip();
        let entry = page(0x4000);
        let stage2_only = Entry {
            stage1: false,
            asid: None,
            ..entry
        };
        let vmalle1 = tlbi(TlbiKind::VMALL, Named::EL10, TlbiLevel::Any, 0);
        assert!(covers(vmalle1, GUEST, entry));
        assert!(!covers(vmalle1, GUEST, stage2_only));
        assert!(!covers(
            vmalle1,
            GUEST,
            Entry {
                vmid: Some(6),
                ..entry
            }
        ));
        let vmalls12 = tlbi(TlbiKind::VMALLS12, Named::EL10, TlbiLevel::Any, 0);
        assert!(covers(vmalls12, GUEST, entry) && covers(vmalls12, GUEST, stage2_only));
        assert!(!covers(
            vmalls12,
            GUEST,
            Entry {
                vmid: Some(6),
                ..entry
            }
        ));
        // ALLE1 removes every EL1&0 entry of every VMID; ALLE2 every EL2 and
        // EL2&0 entry.
        let alle1 = tlbi(TlbiKind::ALL, Named::EL10, TlbiLevel::Any, 0);
        assert!(covers(
            alle1,
            GUEST,
            Entry {
                vmid: Some(6),
                ..entry
            }
        ));
        let alle2 = tlbi(TlbiKind::ALL, Named::EL2, TlbiLevel::Any, 0);
        assert!(covers(
            alle2,
            GUEST,
            Entry {
                regime: Regime::El20,
                ..entry
            }
        ));
        assert!(covers(
            alle2,
            GUEST,
            Entry {
                regime: Regime::El2,
                ..entry
            }
        ));
        assert!(!covers(alle2, GUEST, entry));
    }

    #[test]
    fn range_forms_decode_tg_scale_num_and_ttl() {
        super::super::test_translation_chip();
        // RVAE1 over 16 KiB pages: BaseADDR in 16 KiB units, NUM 1, SCALE 0:
        // (1 + 1) * 2^1 = 4 pages from VA 0x10_0000.
        let base = 0x10_0000_u64 >> 14;
        let rvae1 = |tg: u64, ttl: u64, scale: u64, num: u64, base: u64| {
            tlbi(
                TlbiKind::RVA,
                Named::EL10,
                TlbiLevel::Any,
                7 << 48 | tg << 46 | scale << 44 | num << 39 | ttl << 37 | base,
            )
        };
        let range = rvae1(0b10, 0, 0, 1, base);
        assert!(covers(range, GUEST, page(0x10_0000)));
        assert!(covers(range, GUEST, page(0x10_c000)));
        assert!(!covers(range, GUEST, page(0x11_0000)));
        assert!(!covers(range, GUEST, page(0xf_c000)));
        // A 32 MiB block overlapping the range is removed.
        let block = Entry {
            address: 0,
            size_bits: 25,
            level: 2,
            ..page(0)
        };
        assert!(covers(range, GUEST, block));
        // TTL 0b11 limits it to level-3 entries; TG must equal the entry's.
        assert!(!covers(rvae1(0b10, 0b11, 0, 1, base), GUEST, block));
        assert!(covers(
            rvae1(0b10, 0b11, 0, 1, base),
            GUEST,
            page(0x10_0000)
        ));
        assert!(!covers(rvae1(0b01, 0, 0, 1, 0x100), GUEST, page(0x10_0000)));
        // TG 0b00 is invalid and removes nothing.
        assert!(!covers(rvae1(0, 0, 0, 1, base), GUEST, page(0x10_0000)));
        // SCALE 1, NUM 0: 2^6 pages; BaseADDR's top bit extends the sign.
        let wide = rvae1(0b10, 0, 1, 0, base);
        assert!(covers(wide, GUEST, page(0x10_0000 + 63 * 0x4000)));
        assert!(!covers(wide, GUEST, page(0x10_0000 + 64 * 0x4000)));
        let high = 0xffff_ffff_ffff_0000_u64;
        let upper = rvae1(0b10, 0, 0, 0, (high >> 14) & ((1 << 37) - 1));
        assert!(covers(upper, GUEST, page(high & ((1 << 56) - 1))));
        assert_eq!(
            super::range(2 << 46 | (1 << 36)),
            Some((2, 0xfffc_0000_0000_0000, 0xfffc_0000_0000_8000))
        );
    }

    /// Every entry of the current context a TLBI covers is in its reach,
    /// over random forms, operands, contexts and entries of each size.
    #[test]
    fn the_reach_holds_every_current_entry_the_scope_covers() {
        super::super::test_translation_chip();
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let kinds = [
            TlbiKind::ALL,
            TlbiKind::VMALL,
            TlbiKind::VMALLS12,
            TlbiKind::ASID,
            TlbiKind::VA,
            TlbiKind::VAA,
            TlbiKind::RVA,
            TlbiKind::RVAA,
            TlbiKind::IPAS2,
            TlbiKind::RIPAS2,
        ];
        let named = [Named::EL10, Named::EL20, Named::EL2];
        let regimes = [Regime::El10, Regime::El20, Regime::El2];
        let sizes = [
            (12, 12, 3),
            (14, 14, 3),
            (16, 16, 3),
            (21, 12, 2),
            (25, 14, 2),
            (36, 14, 1),
        ];
        let (mut covered, mut reaches) = ([0; 3], [0; 4]);
        for _ in 0..400_000 {
            let random = next();
            let context = Context {
                el: 1 + (random & 1) as u8,
                el2: true,
                e2h: true,
                tge: random & 2 != 0,
                fb: random & 4 != 0,
            };
            let regime = regimes[(random >> 3) as usize % 3];
            let current = Current {
                regime,
                asid: (regime != Regime::El2).then_some((random >> 8) as u16 & 3),
            };
            let (size_bits, granule_bits, level) = sizes[(random >> 16) as usize % sizes.len()];
            // Addresses near each other, in either half.
            let address = (next() & 0x3f_ffff_ffff) << 12 & !((1u64 << size_bits) - 1);
            let address = if random & 1 << 24 != 0 {
                address | 0xffff_ff00_0000_0000
            } else {
                address
            };
            let entry = Entry {
                regime,
                vmid: (regime == Regime::El10).then_some(5),
                asid: current.asid.filter(|_| random & 1 << 25 != 0),
                address,
                size_bits,
                granule_bits,
                level,
                stage1: true,
                stage2: random & 1 << 26 != 0,
                table: random & 1 << 27 != 0,
            };
            let kind = kinds[(random >> 32) as usize % kinds.len()];
            // The operand aims inside the entry or near it: its ASID and TTL
            // fields drawn small, range fields at random.
            let spread = if random & 1 << 28 != 0 {
                (1 << size_bits) - 1
            } else {
                0x3ff_ffff
            };
            let near = entry.address.wrapping_add(next() & spread) & ADDRESS_BITS;
            let operand = match kind {
                TlbiKind::RVA | TlbiKind::RVAA | TlbiKind::RIPAS2 => {
                    let tg = next() % 4;
                    let bits = granule(tg as u8).unwrap_or(12);
                    // Ranges start up to 1 MiB before the entry.
                    let below = entry.address.wrapping_sub(next() & 0xf_ffff);
                    let base = (canonical(below & ADDRESS_BITS) >> bits) & RANGE_BASE;
                    (random >> 40 & 3) << 48 | tg << 46 | (next() & 0x7f) << 37 | base
                }
                _ => (random >> 40 & 3) << 48 | (random >> 44 & 0xf) << 44 | near >> 12,
            };
            let tlbi = Tlbi {
                kind,
                regime: named[(random >> 48) as usize % 3],
                vmid: Some(5),
                broadcast: Broadcast::NSH,
                level: if random & 1 << 52 != 0 {
                    TlbiLevel::Last
                } else {
                    TlbiLevel::Any
                },
                attr: TlbiAttr::AllAttr,
                operand,
            };
            let scope = Scope::new(&tlbi, context);
            let reach = scope.reach(&current);
            reaches[match reach {
                Reach::Nothing => 0,
                Reach::Containing(_) => 1,
                Reach::Overlapping { .. } => 2,
                Reach::All => 3,
            }] += 1;
            if !scope.covers(&entry) {
                continue;
            }
            covered[match reach {
                Reach::Containing(_) => 1,
                Reach::Overlapping { .. } => 2,
                _ => 0,
            }] += 1;
            let last = entry.address | ((1 << size_bits) - 1);
            let held = match reach {
                Reach::Nothing => false,
                Reach::Containing(address) => (entry.address..=last).contains(&address),
                Reach::Overlapping { first, last: end } => first <= last && entry.address <= end,
                Reach::All => true,
            };
            assert!(held, "{tlbi:?} {context:?} {current:?} {entry:?} {reach:?}");
        }
        assert!(covered.iter().all(|count| *count > 1000), "{covered:?}");
        assert!(reaches.iter().all(|count| *count > 1000), "{reaches:?}");
    }

    #[test]
    fn lower_only_reaches_name_no_upper_half_address() {
        assert!(Reach::Nothing.lower_only());
        assert!(Reach::Containing(0x1_0000).lower_only());
        assert!(!Reach::Containing(0xffff_fe00_0000_0000).lower_only());
        let range = |first, last| Reach::Overlapping { first, last };
        assert!(range(0x1000, 0x7f_ffff_ffff_ffff).lower_only());
        assert!(!range(0x1000, 0xff80_0000_0000_0000).lower_only());
        assert!(!Reach::All.lower_only());
    }

    #[test]
    fn reaches_name_the_address_the_range_or_nothing_of_other_contexts() {
        super::super::test_translation_chip();
        let host = Current {
            regime: Regime::El20,
            asid: Some(7),
        };
        let reach = |kind, regime, operand| {
            Scope::new(&tlbi(kind, regime, TlbiLevel::Any, operand), HOST).reach(&host)
        };
        let high = 0xffff_fe00_0123_4000_u64;
        assert_eq!(
            reach(
                TlbiKind::VA,
                Named::EL10,
                9 << 48 | (high & ADDRESS_BITS) >> 12
            ),
            Reach::Containing(high)
        );
        assert_eq!(
            reach(TlbiKind::VAA, Named::EL10, 0x8),
            Reach::Containing(0x8000)
        );
        // ASIDE1 of another ASID reaches no entry: the global ones stay.
        assert_eq!(reach(TlbiKind::ASID, Named::EL10, 8 << 48), Reach::Nothing);
        assert_eq!(reach(TlbiKind::ASID, Named::EL10, 7 << 48), Reach::All);
        // Four 16 KiB pages from 0x10_0000.
        assert_eq!(
            reach(
                TlbiKind::RVA,
                Named::EL10,
                2 << 46 | 1 << 39 | 0x10_0000 >> 14
            ),
            Reach::Overlapping {
                first: 0x10_0000,
                last: 0x10_ffff
            }
        );
        // From EL2 without TGE, EL1 forms act on the guest's EL1&0 regime.
        let guest = Scope::new(
            &tlbi(TlbiKind::VA, Named::EL10, TlbiLevel::Any, 0x8),
            Context { tge: false, ..HOST },
        );
        assert_eq!(guest.reach(&host), Reach::Nothing);
        // A range of TG 0b00 is invalid.
        assert_eq!(reach(TlbiKind::RVA, Named::EL10, 0x8), Reach::Nothing);
        assert_eq!(reach(TlbiKind::ALL, Named::EL2, 0), Reach::All);
        assert_eq!(reach(TlbiKind::ALL, Named::EL10, 0), Reach::Nothing);
    }

    #[test]
    fn ipa_forms_remove_only_stage_two_entries_and_fb_broadcasts() {
        super::super::test_translation_chip();
        let stage2_only = Entry {
            stage1: false,
            asid: None,
            size_bits: 12,
            granule_bits: 12,
            ..page(0x8_0000_1000)
        };
        let ipas2e1 = tlbi(
            TlbiKind::IPAS2,
            Named::EL10,
            TlbiLevel::Any,
            0x8_0000_1000 >> 12,
        );
        assert!(covers(ipas2e1, HOST, stage2_only));
        assert!(!covers(ipas2e1, HOST, page(0x8_0000_1000)));
        assert!(!covers(
            ipas2e1,
            HOST,
            Entry {
                vmid: Some(6),
                ..stage2_only
            }
        ));
        let ripas2e1 = tlbi(
            TlbiKind::RIPAS2,
            Named::EL10,
            TlbiLevel::Any,
            0b01 << 46 | 3 << 39 | 0x8_0000_0000 >> 12,
        );
        assert!(covers(ripas2e1, HOST, stage2_only));
        assert!(!covers(
            ripas2e1,
            HOST,
            Entry {
                address: 0x8_0000_8000,
                ..stage2_only
            }
        ));
        // HCR_EL2.FB makes VAE1 at EL1 Inner Shareable; IS forms stay so.
        let fb = Context { fb: true, ..GUEST };
        let vae1 = tlbi(TlbiKind::VA, Named::EL10, TlbiLevel::Any, 0);
        assert_eq!(Scope::new(&vae1, fb).broadcast, Broadcast::ISH);
        assert_eq!(Scope::new(&vae1, GUEST).broadcast, Broadcast::NSH);
        assert_eq!(
            Scope::new(&vae1, Context { fb: true, ..HOST }).broadcast,
            Broadcast::NSH
        );
    }
}
