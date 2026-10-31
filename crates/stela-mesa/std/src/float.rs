//! `f32`'s methods that `core` lacks, as a trait the prelude brings in. Rust's
//! UEFI target is soft-float, so the arithmetic crosses to C as bits.
unsafe extern "C" {
    fn stela_libc_powf_bits(base: u32, exponent: u32) -> u32;
    fn stela_libc_log2f_bits(value: u32) -> u32;
    fn stela_libc_roundf_bits(value: u32) -> u32;
}

pub trait Float {
    fn powf(self, exponent: Self) -> Self;
    fn log2(self) -> Self;
    fn round(self) -> Self;
}

impl Float for f32 {
    fn powf(self, exponent: f32) -> f32 {
        // SAFETY: the function is pure.
        f32::from_bits(unsafe { stela_libc_powf_bits(self.to_bits(), exponent.to_bits()) })
    }
    fn log2(self) -> f32 {
        // SAFETY: the function is pure.
        f32::from_bits(unsafe { stela_libc_log2f_bits(self.to_bits()) })
    }
    fn round(self) -> f32 {
        // SAFETY: the function is pure.
        f32::from_bits(unsafe { stela_libc_roundf_bits(self.to_bits()) })
    }
}
