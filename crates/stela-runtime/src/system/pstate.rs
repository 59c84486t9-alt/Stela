//! PSTATE field masks and the MTE feature levels that decide TCO storage.

pub const NZCV_MASK: u64 = 0xf << 28;
pub const DAIF_SHIFT: u32 = 6;
pub const DAIF_MASK: u64 = 0xf << DAIF_SHIFT;
pub const SP_SELECT_MASK: u64 = 1;
pub const DIT_MASK: u64 = 1 << 24;
pub const TCO_MASK: u64 = 1 << 25;

/// MTE1's two implementation-defined choices are independent. MTE2+ requires
/// PSTATE.TCO storage for both register and immediate forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MteFeature {
    Absent,
    One {
        register_raz_wi: bool,
        immediate_ignored: bool,
    },
    TwoOrLater,
}
