//! The exact scope of a TLB maintenance instruction (pseudocode
//! AArch64.TLBI_*, TLBIRange, AArch64.EffectiveBroadcast and TLBIMatch) for
//! the profile: no FEAT_XS, FEAT_D128, FEAT_LPA2, FEAT_RME or FEAT_TLBID.
//!
//! Removing more than the scope is always permitted, so a cache that keeps
//! no translation context may discard everything instead.

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
