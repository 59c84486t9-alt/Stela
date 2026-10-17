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
    /// SPRR_PERM_EL0.
    pub el0: u64,
    /// `S3_6_C15_C3_0` and `S3_6_C15_C3_1`: no public name. Each holds sixteen
    /// 2-bit fields, field `index` at bits `2*index+1:2*index`, indexed by the
    /// same SPRR permission index: the 26A434 kernel's pmap reads
    /// `S3_6_C15_C3_0` that way. SPTM writes `S3_6_C15_C3_1` once at boot and
    /// `S3_6_C15_C3_0` per thread. What a set field does to an access is
    /// undocumented, so a translation through such an index stops.
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
    if sprr
        .fields
        .iter()
        .any(|fields| (fields >> (2 * index)) & 3 != 0)
    {
        return Err(Unsupported::Sprr(
            "permission index with an S3_6_C15_C3_x field set",
        ));
    }
    let as_el0 = requester.el == 0 || requester.unprivileged;
    let (readable, writable, executable) = if as_el0 {
        let nibble = (sprr.el0 >> (4 * index)) & 0xf;
        if nibble > 3 {
            return Err(Unsupported::Sprr("EL0 permission nibble above 3"));
        }
        rights(nibble)
    } else {
        if requester.pan && !requester.guarded {
            return Err(Unsupported::Sprr("PAN"));
        }
        let nibble = (sprr.el1 >> (4 * index)) & 0xf;
        let (guarded, el) = (nibble >> 2, nibble & 3);
        if requester.guarded {
            rights(guarded)
        } else {
            match (guarded, el) {
                (1, 3) => (false, false, false),
                (2, 1) => (false, false, true),
                (_, el) => rights(el),
            }
        }
    };
    Ok((readable, writable, executable && !table_xn))
}
