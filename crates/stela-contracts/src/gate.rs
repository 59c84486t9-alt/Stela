//! A call gate: native code a guest thread enters through a device access,
//! reaching that thread's memory as its own unprivileged loads and stores
//! would.
use core::num::NonZeroU64;

/// Why the caller's memory refused an access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerFault {
    /// The address is unmapped, or the caller may not access it so.
    Denied { address: u64 },
    /// The address maps something other than ordinary RAM.
    NotRam { address: u64 },
    /// The caller's translation uses a configuration the model does not
    /// implement.
    Unsupported(&'static str),
}

/// The address space of the thread whose device access is being served,
/// checked with EL0 permissions in its current translation regime.
pub trait CallerMemory {
    fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), CallerFault>;
    /// Writes nothing unless every byte is writable RAM.
    fn write(&mut self, address: u64, data: &[u8]) -> Result<(), CallerFault>;
}

/// The native service a gate enters, by connection.
pub trait GateService {
    fn connect(&mut self) -> Result<NonZeroU64, &'static str>;
    /// Releases what the connection holds; in-flight work completes.
    fn disconnect(&mut self, connection: NonZeroU64);
    /// Runs the call whose record is at `record` in `caller`, completing
    /// the record; fails only when the record is out of reach.
    fn serve(
        &mut self,
        connection: NonZeroU64,
        record: u64,
        caller: &mut dyn CallerMemory,
    ) -> Result<(), CallerFault>;
    /// Whether the GPU completed work since this last answered true.
    fn signaled(&mut self) -> bool;
}
