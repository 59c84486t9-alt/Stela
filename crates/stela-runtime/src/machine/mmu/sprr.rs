//! Apple SPRR: page permissions indirected through per-index registers
//! (Asahi Linux "SPRR and GXF"; m1n1 `cpu_regs.h`).

use super::{Requester, Unsupported};

/// With SPRR enabled the descriptor bits AP[1], AP[0], UXN and PXN form a
/// 4-bit index (bit 3 down to bit 0), and nibble `index` of SPRR_PERM_EL1
/// holds GL[1:0], EL[1:0].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Sprr {
    /// SPRR_CONFIG_EL1: EN bit 0, LOCK_CONFIG bit 1, LOCK_PERM (EL0) bit 4,
    /// LOCK_KERNEL_PERM bit 5, and bits 2, 3, 6 and 7, whose meaning is
    /// undocumented (Sven Peter: setting every bit locks the SPRR registers).
    pub config: u64,
    /// SPRR_PERM_EL1 (the kernel level's and its GL's permissions).
    pub el1: u64,
    /// SPRR_PERM_EL0: nibble `index` holds GL0[1:0], EL0[1:0], laid out as
    /// SPRR_PERM_EL1. Asahi describes only the EL0 field; SPTM 26A434 writes
    /// `0x8004_000c_8080` before entering TXM at GL0 (`__text+0x2a9c`),
    /// every set bit in a GL0 field, and restores the kernel's value after.
    pub el0: u64,
    /// `S3_6_C15_C3_0` and `S3_6_C15_C3_1`: no public name. Each holds sixteen
    /// 2-bit fields, field `index` at bits `2*index+1:2*index`, indexed by the
    /// same SPRR permission index: the 26A434 kernel's pmap reads
    /// `S3_6_C15_C3_0` that way. A field of 1 keeps that index's EL field
    /// writable after the locks, `S3_6_C15_C3_1` in SPRR_PERM_EL1 and
    /// `S3_6_C15_C3_0` in SPRR_PERM_EL0 ([`sprr_unlocked`]). They do not
    /// change an access.
    pub fields: [u64; 2],
}

pub const SPRR_CONFIG_EN: u64 = 1 << 0;
pub const SPRR_CONFIG_LOCK_CONFIG: u64 = 1 << 1;
pub const SPRR_CONFIG_LOCK_PERM_EL0: u64 = 1 << 4;
pub const SPRR_CONFIG_LOCK_PERM_EL1: u64 = 1 << 5;
/// SPRR_CONFIG_EL1 bits 2, 3, 6 and 7: written by SPTM 26A434 (`0xfb`,
/// `0xff`), meaning undocumented; treated as locks of unknown scope.
pub const SPRR_CONFIG_UNDOCUMENTED: u64 = 0xcc;

impl Sprr {
    pub fn enabled(self) -> bool {
        self.config & SPRR_CONFIG_EN != 0
    }
}

/// The SPRR_PERM bits that stay writable after the locks under `fields`
/// (`S3_6_C15_C3_1` for SPRR_PERM_EL1, `S3_6_C15_C3_0` for SPRR_PERM_EL0):
/// the EL field of every index whose field is 1. SPTM 26A434 sets fields 2
/// and 9 of `S3_6_C15_C3_1` before locking SPRR (`__text+0xbe2c`), and every
/// SPRR_PERM_EL1 write of the 26A434 kernel changes only the EL field of
/// index 2 (`0xa` to `0xb`, `0xfffffe000bd68db4`) or of index 9 (`0x2` to
/// `0x3`, `0xfffffe000bd72344`); SPTM writes `S3_6_C15_C3_0` per thread
/// and the kernel rewrites SPRR_PERM_EL0 per thread (inference from that
/// pairing; no public description).
pub fn sprr_unlocked(fields: u64) -> u64 {
    (0..16)
        .filter(|index| (fields >> (2 * index)) & 3 == 1)
        .fold(0, |mask, index| mask | 3 << (4 * index))
}

/// Whether every field is 0 or 1, the only values seen; others stop.
pub fn sprr_fields_valid(fields: u64) -> bool {
    (0..16).all(|index| (fields >> (2 * index)) & 3 <= 1)
}

/// (readable, writable, executable) of a 2-bit SPRR permission: `---`,
/// `r-x`, `r--`, `rw-`.
fn rights(bits: u64) -> (bool, bool, bool) {
    match bits & 3 {
        0 => (false, false, false),
        1 => (true, false, true),
        2 => (true, false, false),
        _ => (true, true, false),
    }
}

/// Whether EL0 can access permission index `index`, for PAN: the EL0 field
/// of SPRR_PERM_EL0, which every nonzero value makes readable, not AP[1].
/// The 26A434 kernel reads TXM's Mach-O header with PAN set
/// (`0xfffffe000bd70358`) through an index with AP[1] set and no EL0 access,
/// which Arm's AP[1] rule would fault. That PAN still applies through the
/// EL0 field is an inference: no source describes PAN under SPRR.
fn user_accessible(sprr: Sprr, index: u64) -> bool {
    (sprr.el0 >> (4 * index)) & 3 != 0
}

/// What the stage-1 walk collected above an SPRR leaf.
pub struct Hierarchy {
    pub no_el0: bool,
    pub read_only: bool,
    pub pxn_table: bool,
    pub uxn_table: bool,
}

/// (readable, writable, executable) of a leaf under SPRR. The two special
/// GL/EL combinations follow the Asahi table: GL `r-x` with EL `rw-` gives
/// EL `---`, and GL `r--` with EL `r-x` gives EL `--x`.
pub fn permissions(
    sprr: Sprr,
    requester: Requester,
    hierarchy: &Hierarchy,
    descriptor: u64,
) -> Result<(bool, bool, bool), Unsupported> {
    if hierarchy.no_el0 || hierarchy.read_only {
        return Err(Unsupported::Sprr("APTable with SPRR"));
    }
    // The index comes from the leaf alone, as the 26A434 kernel's pmap
    // computes it from the PTE; PXNTable and UXNTable keep their Arm meaning
    // and only remove execution (inference: no public description).
    let table_xn = if requester.el == 0 {
        hierarchy.uxn_table
    } else {
        hierarchy.pxn_table
    };
    let index = ((descriptor >> 7) & 1) << 3
        | ((descriptor >> 6) & 1) << 2
        | ((descriptor >> 54) & 1) << 1
        | ((descriptor >> 53) & 1);
    let as_el0 = requester.el == 0 || requester.unprivileged;
    let (readable, writable, executable) = if as_el0 {
        let nibble = (sprr.el0 >> (4 * index)) & 0xf;
        let (guarded, el) = (nibble >> 2, nibble & 3);
        if requester.guarded {
            rights(guarded)
        } else if guarded != 0 && el != 0 {
            // EL1's register has special GL/EL combinations; whether EL0's
            // has them is undocumented.
            return Err(Unsupported::Sprr(
                "EL0 permission with both GL0 and EL0 set",
            ));
        } else {
            rights(el)
        }
    } else {
        let nibble = (sprr.el1 >> (4 * index)) & 0xf;
        let (guarded, el) = (nibble >> 2, nibble & 3);
        if requester.guarded {
            rights(guarded)
        } else {
            let (readable, writable, executable) = match (guarded, el) {
                (1, 3) => (false, false, false),
                (2, 1) => (false, false, true),
                (_, el) => rights(el),
            };
            // PAN removes data access to a location EL0 can access.
            if requester.pan && user_accessible(sprr, index) {
                (false, false, executable)
            } else {
                (readable, writable, executable)
            }
        }
    };
    Ok((readable, writable, executable && !table_xn))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLAT: Hierarchy = Hierarchy {
        no_el0: false,
        read_only: false,
        pxn_table: false,
        uxn_table: false,
    };

    /// A leaf whose permission index is `index`.
    fn leaf(index: u64) -> u64 {
        (index >> 3 & 1) << 7 | (index >> 2 & 1) << 6 | (index >> 1 & 1) << 54 | (index & 1) << 53
    }

    fn requester(el: u8, pan: bool, guarded: bool) -> Requester {
        Requester {
            el,
            pan,
            unprivileged: false,
            guarded,
        }
    }

    #[test]
    fn gl0_takes_the_upper_bits_of_sprr_perm_el0() {
        // SPTM 26A434's value for TXM: index 1 r--, 3 r--, 4 rw-, 8 r-x.
        let sprr = Sprr {
            config: SPRR_CONFIG_EN,
            el0: 0x8004_000c_8080,
            ..Sprr::default()
        };
        let gl0 = requester(0, false, true);
        let at = |index, requester| permissions(sprr, requester, &FLAT, leaf(index));
        assert_eq!(at(1, gl0), Ok((true, false, false)));
        assert_eq!(at(4, gl0), Ok((true, true, false)));
        assert_eq!(at(8, gl0), Ok((true, false, true)));
        assert_eq!(at(2, gl0), Ok((false, false, false)));
        // EL0 has no access through any of them.
        assert_eq!(at(4, requester(0, false, false)), Ok((false, false, false)));
        let both = Sprr { el0: 0x9, ..sprr };
        assert!(permissions(both, requester(0, false, false), &FLAT, leaf(0)).is_err());
    }

    #[test]
    fn pan_follows_sprr_perm_el0_not_ap1() {
        // Index 0: kernel rw-, no EL0 access. Index 4 (AP[1]): kernel rw-,
        // EL0 rw-. Index 1: kernel rw- and EL0 rw- without AP[1]. Index 5
        // (AP[1]): kernel rw-, no EL0 access.
        let sprr = Sprr {
            config: SPRR_CONFIG_EN,
            el1: 0x3 | 0x3 << 4 | 0x3 << 16 | 0x3 << 20,
            el0: 0x3 << 4 | 0x3 << 16,
            ..Sprr::default()
        };
        let kernel = requester(2, true, false);
        let at = |index| permissions(sprr, kernel, &FLAT, leaf(index));
        assert_eq!(at(0), Ok((true, true, false)));
        assert_eq!(at(4), Ok((false, false, false)));
        assert_eq!(at(1), Ok((false, false, false)));
        assert_eq!(at(5), Ok((true, true, false)));
        // Without PAN, and at a guarded level, the kernel keeps its rights.
        let unmasked = |requester| permissions(sprr, requester, &FLAT, leaf(4));
        assert_eq!(
            unmasked(requester(2, false, false)),
            Ok((true, true, false))
        );
        assert_eq!(
            unmasked(requester(2, true, true)),
            Ok((false, false, false))
        );
    }
}
