//! Thread-owned scalable register storage; the existing V registers own low Z bits.

use anyhow::{Result, ensure};
use stela_compiler::{
    GuestState,
    aarch64::scalable::{
        LOOKUP_TABLE_BYTES, PREDICATE_REGISTER_COUNT, STREAMING_RESET_FPSR, ScalableMode,
        VECTOR_CHUNK_BYTES, VECTOR_REGISTER_COUNT, VectorLength, is_predicate_register,
        is_z_register,
    },
    context::ScalableStateView,
};

/// Owns one guest thread's scalable state, without duplicating GuestState.v.
/// Controls exist before either of the independently lazy buffers is allocated.
#[derive(Debug, Clone)]
pub struct ScalableState {
    length: VectorLength,
    sme2: bool,
    mode: ScalableMode,
    tpidr2_el0: u64,
    fpmr: u64,
    vectors: Option<Vec<u8>>,
    matrices: Option<Vec<u8>>,
}

impl ScalableState {
    pub fn new(length: VectorLength, sme2: bool) -> Self {
        Self {
            length,
            sme2,
            mode: ScalableMode::new(false, false),
            tpidr2_el0: 0,
            fpmr: 0,
            vectors: None,
            matrices: None,
        }
    }

    pub fn vector_length(&self) -> VectorLength {
        self.length
    }

    pub fn mode(&self) -> ScalableMode {
        self.mode
    }

    pub fn tpidr2_el0(&self) -> u64 {
        self.tpidr2_el0
    }

    pub fn set_tpidr2_el0(&mut self, value: u64) {
        self.tpidr2_el0 = value;
    }

    pub fn fpmr(&self) -> u64 {
        self.fpmr
    }

    /// Architectural register accesses must apply their selected feature masks.
    pub fn set_fpmr(&mut self, value: u64) {
        self.fpmr = value;
    }

    /// Apply SM first, then ZA, after all required allocations have succeeded.
    /// Same-value writes preserve register contents and do not allocate.
    pub fn apply_mode(&mut self, registers: &mut GuestState, mode: ScalableMode) -> Result<()> {
        let new_vectors = if mode.streaming() && self.vectors.is_none() {
            Some(zeroed_buffer(self.vector_storage_bytes())?)
        } else {
            None
        };
        let new_matrices = if mode.za_enabled() && self.matrices.is_none() {
            Some(zeroed_buffer(self.matrix_storage_bytes())?)
        } else {
            None
        };
        if let Some(vectors) = new_vectors {
            self.vectors = Some(vectors);
        }
        if let Some(matrices) = new_matrices {
            self.matrices = Some(matrices);
        }
        if self.mode.streaming() != mode.streaming() {
            registers.v.fill([0; 2]);
            if let Some(vectors) = &mut self.vectors {
                vectors.fill(0);
            }
            registers.fpsr = STREAMING_RESET_FPSR;
            self.fpmr = 0;
        }
        if !self.mode.za_enabled() && mode.za_enabled() {
            self.matrices.as_mut().expect("allocated ZA state").fill(0);
        }
        self.mode = mode;
        Ok(())
    }

    /// Read a complete Z register, joining its authoritative low and upper parts.
    pub fn read_z(&self, registers: &GuestState, register: u8, output: &mut [u8]) -> Result<()> {
        self.check_vector(register, output.len())?;
        for (limb, destination) in registers.v[usize::from(register)].iter().zip(
            output[..VECTOR_CHUNK_BYTES]
                .as_chunks_mut::<{ size_of::<u64>() }>()
                .0
                .iter_mut(),
        ) {
            destination.copy_from_slice(&limb.to_le_bytes());
        }
        let start = usize::from(register) * self.upper_vector_bytes();
        output[VECTOR_CHUNK_BYTES..].copy_from_slice(
            &self.vectors.as_ref().expect("enabled vector state")
                [start..start + self.upper_vector_bytes()],
        );
        Ok(())
    }

    pub fn write_z(
        &mut self,
        registers: &mut GuestState,
        register: u8,
        input: &[u8],
    ) -> Result<()> {
        self.check_vector(register, input.len())?;
        let start = usize::from(register) * self.upper_vector_bytes();
        let end = start + self.upper_vector_bytes();
        for (limb, source) in registers.v[usize::from(register)].iter_mut().zip(
            input[..VECTOR_CHUNK_BYTES]
                .as_chunks::<{ size_of::<u64>() }>()
                .0
                .iter(),
        ) {
            *limb = u64::from_le_bytes(*source);
        }
        self.vectors.as_mut().expect("enabled vector state")[start..end]
            .copy_from_slice(&input[VECTOR_CHUNK_BYTES..]);
        Ok(())
    }

    /// Commit a complete low128 V result for an instruction permitted in this mode.
    /// The caller resolves scalar NEP/insertion masks before this boundary.
    /// Streaming legality belongs to the decoder; a V write clears upper Z bits.
    pub fn write_v(
        &mut self,
        registers: &mut GuestState,
        register: u8,
        value: [u64; 2],
    ) -> Result<()> {
        ensure!(is_z_register(register), "vector register out of range");
        if self.mode.streaming() {
            let start = usize::from(register) * self.upper_vector_bytes();
            let end = start + self.upper_vector_bytes();
            self.vectors.as_mut().expect("enabled vector state")[start..end].fill(0);
        }
        registers.v[usize::from(register)] = value;
        Ok(())
    }

    pub fn read_predicate(&self, register: u8, output: &mut [u8]) -> Result<()> {
        let range = self.predicate_range(register, output.len())?;
        output.copy_from_slice(&self.vectors.as_ref().expect("enabled vector state")[range]);
        Ok(())
    }

    pub fn write_predicate(&mut self, register: u8, input: &[u8]) -> Result<()> {
        let range = self.predicate_range(register, input.len())?;
        self.vectors.as_mut().expect("enabled vector state")[range].copy_from_slice(input);
        Ok(())
    }

    pub fn read_ffr(&self, output: &mut [u8]) -> Result<()> {
        self.check_predicate_bytes(output.len())?;
        output.copy_from_slice(
            &self.vectors.as_ref().expect("enabled vector state")[self.ffr_offset()..],
        );
        Ok(())
    }

    pub fn write_ffr(&mut self, input: &[u8]) -> Result<()> {
        self.check_predicate_bytes(input.len())?;
        let start = self.ffr_offset();
        self.vectors.as_mut().expect("enabled vector state")[start..].copy_from_slice(input);
        Ok(())
    }

    pub fn read_za(&self, offset: usize, output: &mut [u8]) -> Result<()> {
        let range = self.matrix_range(offset, output.len(), false)?;
        output.copy_from_slice(&self.matrices.as_ref().expect("enabled ZA state")[range]);
        Ok(())
    }

    pub fn write_za(&mut self, offset: usize, input: &[u8]) -> Result<()> {
        let range = self.matrix_range(offset, input.len(), false)?;
        self.matrices.as_mut().expect("enabled ZA state")[range].copy_from_slice(input);
        Ok(())
    }

    pub fn read_zt0(&self, offset: usize, output: &mut [u8]) -> Result<()> {
        let range = self.matrix_range(offset, output.len(), true)?;
        output.copy_from_slice(&self.matrices.as_ref().expect("enabled ZA state")[range]);
        Ok(())
    }

    pub fn write_zt0(&mut self, offset: usize, input: &[u8]) -> Result<()> {
        let range = self.matrix_range(offset, input.len(), true)?;
        self.matrices.as_mut().expect("enabled ZA state")[range].copy_from_slice(input);
        Ok(())
    }

    /// Borrow stable register buffers for one synchronous native invocation.
    ///
    /// # Safety
    ///
    /// The callback must not retain pointers or references from the view, access
    /// memory outside the described register buffers, modify pointer/length/mode
    /// fields, or unwind after changing controls. It may update register bytes,
    /// TPIDR2 and FPMR. Guest RAM must not alias this storage or its Rust owner.
    /// Mode changes must instead go through `apply_mode` outside the invocation.
    pub unsafe fn with_view<R>(&mut self, callback: impl FnOnce(&mut ScalableStateView) -> R) -> R {
        let predicate_offset = self.predicate_offset();
        let ffr_offset = self.ffr_offset();
        let za_bytes = self.za_bytes();
        let (z_upper, predicates, ffr) = match (self.mode.streaming(), &mut self.vectors) {
            (true, Some(storage)) => {
                let pointer = storage.as_mut_ptr();
                // SAFETY: Both offsets lie within the owned nonempty allocation.
                unsafe {
                    (
                        pointer,
                        pointer.add(predicate_offset),
                        pointer.add(ffr_offset),
                    )
                }
            }
            _ => (
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ),
        };
        let (za, zt0) = match (self.mode.za_enabled(), &mut self.matrices) {
            (true, Some(storage)) => {
                let pointer = storage.as_mut_ptr();
                let zt0 = if self.sme2 {
                    // SAFETY: SME2 storage includes the complete trailing ZT0.
                    unsafe { pointer.add(za_bytes) }
                } else {
                    std::ptr::null_mut()
                };
                (pointer, zt0)
            }
            _ => (std::ptr::null_mut(), std::ptr::null_mut()),
        };
        let mut view = ScalableStateView {
            svl_bytes: self.length.bytes() as u16,
            reserved: [0; 6],
            svcr: self.mode.svcr(),
            tpidr2_el0: self.tpidr2_el0,
            fpmr: self.fpmr,
            z_upper,
            predicates,
            ffr,
            za,
            zt0,
        };
        let result = callback(&mut view);
        self.tpidr2_el0 = view.tpidr2_el0;
        self.fpmr = view.fpmr;
        result
    }

    fn upper_vector_bytes(&self) -> usize {
        self.length.bytes() - VECTOR_CHUNK_BYTES
    }

    fn predicate_offset(&self) -> usize {
        usize::from(VECTOR_REGISTER_COUNT) * self.upper_vector_bytes()
    }

    fn ffr_offset(&self) -> usize {
        self.predicate_offset()
            + usize::from(PREDICATE_REGISTER_COUNT) * self.length.predicate_bytes()
    }

    fn vector_storage_bytes(&self) -> usize {
        self.ffr_offset() + self.length.predicate_bytes()
    }

    fn za_bytes(&self) -> usize {
        self.length.bytes() * self.length.bytes()
    }

    fn matrix_storage_bytes(&self) -> usize {
        self.za_bytes() + if self.sme2 { LOOKUP_TABLE_BYTES } else { 0 }
    }

    fn check_vector(&self, register: u8, bytes: usize) -> Result<()> {
        ensure!(self.mode.streaming(), "Z register requires streaming mode");
        ensure!(is_z_register(register), "vector register out of range");
        ensure!(bytes == self.length.bytes(), "Z register length mismatch");
        Ok(())
    }

    fn check_predicate_bytes(&self, bytes: usize) -> Result<()> {
        ensure!(self.mode.streaming(), "predicate requires streaming mode");
        ensure!(
            bytes == self.length.predicate_bytes(),
            "predicate length mismatch"
        );
        Ok(())
    }

    fn predicate_range(&self, register: u8, bytes: usize) -> Result<std::ops::Range<usize>> {
        self.check_predicate_bytes(bytes)?;
        ensure!(
            is_predicate_register(register),
            "predicate register out of range"
        );
        let start = self.predicate_offset() + usize::from(register) * bytes;
        Ok(start..start + bytes)
    }

    fn matrix_range(
        &self,
        offset: usize,
        bytes: usize,
        lookup: bool,
    ) -> Result<std::ops::Range<usize>> {
        ensure!(
            self.mode.za_enabled(),
            "matrix register requires ZA enabled"
        );
        ensure!(!lookup || self.sme2, "ZT0 requires SME2");
        let limit = if lookup {
            LOOKUP_TABLE_BYTES
        } else {
            self.za_bytes()
        };
        let end = offset.checked_add(bytes).filter(|end| *end <= limit);
        let end = end.ok_or_else(|| anyhow::anyhow!("matrix register range out of bounds"))?;
        let base = if lookup { self.za_bytes() } else { 0 };
        Ok(base + offset..base + end)
    }
}

fn zeroed_buffer(bytes: usize) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(bytes)?;
    buffer.resize(bytes, 0);
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::aarch64::scalable::MAX_VECTOR_BYTES;

    fn length(bytes: usize) -> VectorLength {
        VectorLength::from_bytes(bytes).expect("architectural vector length")
    }

    #[test]
    fn controls_and_disabled_state_do_not_allocate() -> Result<()> {
        let mut state = ScalableState::new(length(32), true);
        let mut registers = GuestState::default();
        registers.v[3] = [7, 9];
        registers.fpsr = u32::MAX;
        state.set_tpidr2_el0(123);
        state.set_fpmr(456);
        state.apply_mode(&mut registers, ScalableMode::new(false, false))?;
        assert_eq!(registers.v[3], [7, 9]);
        assert_eq!(registers.fpsr, u32::MAX);
        assert_eq!(state.tpidr2_el0(), 123);
        assert_eq!(state.fpmr(), 456);
        assert!(state.vectors.is_none());
        assert!(state.matrices.is_none());
        Ok(())
    }

    #[test]
    fn transitions_reset_exact_state_and_preserve_independent_matrix() -> Result<()> {
        let mut state = ScalableState::new(length(32), true);
        let mut registers = GuestState {
            fpcr: 123,
            nzcv: 0xa000_0000,
            ..GuestState::default()
        };
        state.set_tpidr2_el0(999);
        state.apply_mode(&mut registers, ScalableMode::new(true, true))?;
        state.write_z(&mut registers, 31, &[0x45; 32])?;
        state.write_predicate(15, &[0x67; 4])?;
        state.write_ffr(&[0x89; 4])?;
        state.write_za(1023, &[0xab])?;
        state.write_zt0(63, &[0xcd])?;
        state.set_fpmr(123);
        registers.fpsr = u32::MAX;
        state.apply_mode(&mut registers, ScalableMode::new(true, true))?;
        assert_eq!(registers.v[31], [0x4545_4545_4545_4545; 2]);
        assert_eq!(registers.fpsr, u32::MAX);
        assert_eq!(state.fpmr(), 123);
        state.apply_mode(&mut registers, ScalableMode::new(false, true))?;
        assert_eq!(registers.v, [[0; 2]; VECTOR_REGISTER_COUNT as usize]);
        assert!(
            state
                .vectors
                .as_ref()
                .unwrap()
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(registers.fpsr, STREAMING_RESET_FPSR);
        assert_eq!(state.fpmr(), 0);
        assert_eq!(state.tpidr2_el0(), 999);
        assert_eq!(registers.fpcr, 123);
        assert_eq!(registers.nzcv, 0xa000_0000);
        let mut byte = [0];
        state.read_za(1023, &mut byte)?;
        assert_eq!(byte, [0xab]);
        state.read_zt0(63, &mut byte)?;
        assert_eq!(byte, [0xcd]);
        state.apply_mode(&mut registers, ScalableMode::new(false, false))?;
        assert!(state.read_za(0, &mut byte).is_err());
        state.apply_mode(&mut registers, ScalableMode::new(false, true))?;
        state.read_za(1023, &mut byte)?;
        assert_eq!(byte, [0]);
        state.read_zt0(63, &mut byte)?;
        assert_eq!(byte, [0]);
        Ok(())
    }

    #[test]
    fn all_lengths_preserve_low_alias_and_bound_every_register_bank() -> Result<()> {
        for bytes in (VECTOR_CHUNK_BYTES..=MAX_VECTOR_BYTES).filter(|bytes| bytes.is_power_of_two())
        {
            let mut state = ScalableState::new(length(bytes), true);
            let mut registers = GuestState::default();
            state.apply_mode(&mut registers, ScalableMode::new(true, true))?;
            let input: Vec<u8> = (0..bytes).map(|byte| byte as u8).collect();
            let mut output = vec![0; bytes];
            state.write_z(&mut registers, 31, &input)?;
            registers.v[31][0] = u64::MAX;
            state.read_z(&registers, 31, &mut output)?;
            assert_eq!(&output[..8], &[0xff; 8]);
            assert_eq!(&output[8..], &input[8..]);
            state.write_v(&mut registers, 31, [3, 4])?;
            state.read_z(&registers, 31, &mut output)?;
            assert!(output[VECTOR_CHUNK_BYTES..].iter().all(|byte| *byte == 0));
            assert!(state.write_z(&mut registers, 32, &input).is_err());
            assert!(
                state
                    .write_z(&mut registers, 0, &input[..bytes - 1])
                    .is_err()
            );
            assert!(state.write_predicate(16, &vec![0; bytes / 8]).is_err());
            assert!(state.write_ffr(&vec![0; bytes / 8 + 1]).is_err());
            assert!(state.write_za(bytes * bytes, &[1]).is_err());
            assert!(state.write_za(usize::MAX, &[1]).is_err());
            assert!(state.write_zt0(64, &[1]).is_err());
        }
        Ok(())
    }

    #[test]
    fn clone_and_scoped_view_keep_storage_independent_and_stable() -> Result<()> {
        let mut state = ScalableState::new(length(32), true);
        let mut registers = GuestState::default();
        state.apply_mode(&mut registers, ScalableMode::new(true, true))?;
        state.write_za(0, &[7])?;
        let mut cloned = state.clone();
        cloned.write_za(0, &[9])?;
        let mut byte = [0];
        state.read_za(0, &mut byte)?;
        assert_eq!(byte, [7]);
        // SAFETY: Only live bounded storage is accessed; no pointers escape.
        unsafe {
            state.with_view(|view| {
                assert_eq!(view.svl_bytes, 32);
                assert_eq!(view.svcr, 3);
                *view.z_upper = 0x12;
                *view.predicates = 0x34;
                *view.ffr = 0x56;
                *view.za = 0x78;
                *view.zt0 = 0x9a;
                view.tpidr2_el0 = 111;
                view.fpmr = 222;
            });
        }
        let mut z = [0; 32];
        state.read_z(&registers, 0, &mut z)?;
        assert_eq!(z[16], 0x12);
        let mut predicate = [0; 4];
        state.read_predicate(0, &mut predicate)?;
        assert_eq!(predicate[0], 0x34);
        state.read_ffr(&mut predicate)?;
        assert_eq!(predicate[0], 0x56);
        state.read_za(0, &mut byte)?;
        assert_eq!(byte, [0x78]);
        state.read_zt0(0, &mut byte)?;
        assert_eq!(byte, [0x9a]);
        assert_eq!(state.tpidr2_el0(), 111);
        assert_eq!(state.fpmr(), 222);
        let without_sme2 = ScalableState::new(length(16), false);
        assert!(without_sme2.read_zt0(0, &mut byte).is_err());
        Ok(())
    }
}
