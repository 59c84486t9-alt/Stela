//! GPIO profile identity and interrupt-group capacity.
/// The interrupt groups the 3-bit group field selects.
pub const GROUPS: usize = 8;

/// Source-checked register behavior; board nets and lifecycle remain
/// separately owned. The S5L driver does not implement T8101 lockGPIO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    T8101,
    S5l8960x,
}
