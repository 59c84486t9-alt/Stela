//! Legacy standalone DCS placement cannot supply actual initial configuration,
//! LPDDR refresh observations, active event accounting or drain completion.
//! T6000 channels belong to the shared direct [`super::mcc::Controller`]; the
//! mount must join their actual aperture and lifecycle there. T8112 retained
//! handoff support remains separate; its former nominal/zero placeholders do
//! not qualify initialization of either profile.
use super::bus::{Access, Direction, MmioDevice, MmioError, Width, refuse};

/// An old standalone placement has no qualified resource owner. Keep its
/// constructor signature so callers fail before adding/mapping a partial bank.
#[derive(Debug, Clone)]
pub struct Dcs;
impl Dcs {
    pub fn new(_: usize, _: u64) -> Result<Self, &'static str> {
        Err(
            "standalone DCS requires qualified configuration, accounting, drain and lifecycle ownership",
        )
    }
}
impl MmioDevice for Dcs {
    fn name(&self) -> &'static str {
        "dcs"
    }
    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        Err(refuse(
            "dcs",
            offset,
            width,
            Direction::Read,
            "DCS has no admitted owner",
        ))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        _: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        Err(refuse(
            "dcs",
            offset,
            width,
            Direction::Write,
            "DCS has no admitted owner",
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn old_nominal_temperature_and_zero_counter_placement_is_not_admitted() {
        assert!(Dcs::new(8, 0x400000).is_err());
    }
}
