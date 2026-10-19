//! Texture sampling (`smpf`, `smpi`) and image writes (`imgw`, `imgwblk`).

use super::decode::Instr;
use super::machine::{Env, Error, SimdGroup, Step};

impl SimdGroup {
    pub(super) fn texture(&mut self, _instr: &Instr, _env: &mut dyn Env) -> Result<Step, Error> {
        Err(Error::Refused(
            "texture sampling and image writes are not modeled yet",
        ))
    }
}
