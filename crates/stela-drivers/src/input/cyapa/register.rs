// SPDX-License-Identifier: GPL-2.0-only
//! Register-prefix I2C framing for the shared Gen3 register engine.
use super::{Address, Bus, ErrorKind, Operation, RegisterAccess};
impl<B: Bus> RegisterAccess for B {
    fn read_register(
        &mut self,
        address: Address,
        register: u8,
        bytes: &mut [u8],
        _allow_fallback: impl Fn() -> bool,
    ) -> Result<(), ErrorKind> {
        self.transaction(
            address,
            &mut [Operation::Write(&[register]), Operation::Read(bytes)],
        )
        .map_err(ErrorKind::Bus)
    }
    fn write_register(
        &mut self,
        address: Address,
        register: u8,
        bytes: &[u8],
    ) -> Result<(), ErrorKind> {
        if bytes.is_empty() || bytes.len() > 31 {
            return Err(ErrorKind::RegisterTransfer {
                register,
                length: bytes.len(),
                write: true,
            });
        }
        let mut wire = [0; 32];
        wire[0] = register;
        wire[1..=bytes.len()].copy_from_slice(bytes);
        self.transaction(address, &mut [Operation::Write(&wire[..bytes.len() + 1])])
            .map_err(ErrorKind::Bus)
    }
}
