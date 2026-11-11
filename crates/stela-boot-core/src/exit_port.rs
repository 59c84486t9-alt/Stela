//! The hypervisor exit port. A virtual machine may give I/O port 0xf4 to a
//! debug-exit device, where a stop code ends the run with that code. No PC
//! device is known to own the port, so the boot program writes it only when
//! CPUID reports a hypervisor (leaf 1, ECX bit 31); a PC without one never
//! sees the write.

/// The port a hypervisor's debug-exit device takes stop codes on.
pub const PORT: u16 = 0xf4;
/// CPUID leaf 1 ECX bit 31: the processor runs under a hypervisor.
pub const HYPERVISOR_BIT: u32 = 31;

/// The exit port when CPUID leaf 1's `ecx` reports a hypervisor.
pub const fn port(ecx: u32) -> Option<u16> {
    if ecx & (1 << HYPERVISOR_BIT) != 0 {
        Some(PORT)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_hypervisor_gets_the_exit_port() {
        // A desktop processor's leaf 1 ECX on bare metal: SSE3 to RDRAND,
        // no hypervisor bit.
        let bare = 0x7ef8_3203;
        assert_eq!(port(bare), None);
        assert_eq!(port(0), None);
        assert_eq!(port(bare | (1 << 31)), Some(0xf4));
        assert_eq!(port(1 << 31), Some(PORT));
    }
}
