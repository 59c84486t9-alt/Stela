//! x86 port I/O. The drivers run only on x86-64 PCs; ARM hosts compile them
//! into the host tools, which never drive hardware, so a port access there is
//! a bug rather than a degraded path.

macro_rules! ports {
    ($($read:ident $write:ident $ty:ty, $register:tt;)*) => {$(
        /// Read `port`.
        ///
        /// # Safety
        /// The caller owns `port` and holds I/O privilege.
        pub unsafe fn $read(port: u16) -> $ty {
            #[cfg(target_arch = "x86_64")]
            {
                let value;
                // SAFETY: the caller's ownership and privilege contract.
                unsafe {
                    core::arch::asm!(
                        concat!("in ", $register, ", dx"),
                        in("dx") port,
                        out($register) value,
                        options(nostack, preserves_flags),
                    );
                }
                value
            }
            #[cfg(not(target_arch = "x86_64"))]
            unreachable!("port {port:#x} read outside x86-64")
        }

        /// Write `value` to `port`.
        ///
        /// # Safety
        /// The caller owns `port` and holds I/O privilege.
        pub unsafe fn $write(port: u16, value: $ty) {
            #[cfg(target_arch = "x86_64")]
            // SAFETY: the caller's ownership and privilege contract.
            unsafe {
                core::arch::asm!(
                    concat!("out dx, ", $register),
                    in("dx") port,
                    in($register) value,
                    options(nostack, preserves_flags),
                );
            }
            #[cfg(not(target_arch = "x86_64"))]
            unreachable!("port {port:#x} written {value:#x} outside x86-64")
        }
    )*};
}

ports! {
    read8 write8 u8, "al";
    read16 write16 u16, "ax";
    read32 write32 u32, "eax";
}
