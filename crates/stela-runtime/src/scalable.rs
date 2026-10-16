//! SVE/SME register storage of a thread. The low 128 bits of each Z register
//! are the V registers in `GuestState`.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
mod context;
pub mod leaf;

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
#[derive(Debug)]
pub struct ScalableState {
    length: VectorLength,
    sme2: bool,
    mode: ScalableMode,
    tpidr2_el0: u64,
    fpmr: u64,
    vectors: Option<Vec<u8>>,
    matrices: Option<Vec<u8>>,
    za_scratch: Option<Vec<u8>>,
}

impl Clone for ScalableState {
    fn clone(&self) -> Self {
        Self {
            length: self.length,
            sme2: self.sme2,
            mode: self.mode,
            tpidr2_el0: self.tpidr2_el0,
            fpmr: self.fpmr,
            vectors: self.vectors.clone(),
            matrices: self.matrices.clone(),
            // Scratch space is always available, even during a borrow.
            za_scratch: Some(Vec::new()),
        }
    }
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
            za_scratch: Some(Vec::new()),
        }
    }

    /// Borrow reusable staging for the ZA rows an instruction affects, bounded
    /// by the whole matrix. The callback evaluates and commits; writes it
    /// chooses to make are not rolled back. Contents are unspecified, so every
    /// staged row must be initialized before use. Storage is kept between uses
    /// without re-zeroing; nested borrows are rejected.
    pub fn with_za_row_scratch<R, E>(
        &mut self,
        rows: usize,
        operation: impl FnOnce(&mut Self, &mut [u8]) -> Result<R, E>,
    ) -> Result<R, E>
    where
        E: From<anyhow::Error>,
    {
        let maximum_rows = self.length.bytes();
        if rows == 0 || rows > maximum_rows {
            return Err(anyhow::anyhow!("ZA scratch row count exceeds the physical matrix").into());
        }
        let storage = self
            .za_scratch
            .take()
            .ok_or_else(|| E::from(anyhow::anyhow!("ZA scratch is already borrowed")))?;
        let mut loan = ZaRowScratchLoan {
            state: self,
            storage,
        };
        // Validated architectural lengths and physical row counts bound this to 64KiB.
        let bytes = rows * loan.state.length.bytes();
        if bytes > loan.storage.len() {
            loan.storage
                .try_reserve_exact(bytes - loan.storage.len())
                .map_err(anyhow::Error::from)
                .map_err(E::from)?;
            loan.storage.resize(bytes, 0);
        }
        operation(loan.state, &mut loan.storage[..bytes])
    }

    /// Whether this owner reserves ZT0 backing storage. This allocation
    /// capability does not establish guest feature availability or access.
    pub const fn has_zt0_storage(&self) -> bool {
        self.sme2
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
                // SAFETY: both offsets are within the owned allocation.
                unsafe {
                    (
                        pointer,
                        pointer.add(predicate_offset),
                        pointer.add(ffr_offset),
                    )
                }
            }
            _ => (
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            ),
        };
        let (za, zt0) = match (self.mode.za_enabled(), &mut self.matrices) {
            (true, Some(storage)) => {
                let pointer = storage.as_mut_ptr();
                let zt0 = if self.sme2 {
                    // SAFETY: SME2 storage includes the complete trailing ZT0.
                    unsafe { pointer.add(za_bytes) }
                } else {
                    core::ptr::null_mut()
                };
                (pointer, zt0)
            }
            _ => (core::ptr::null_mut(), core::ptr::null_mut()),
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

    fn predicate_range(&self, register: u8, bytes: usize) -> Result<core::ops::Range<usize>> {
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
    ) -> Result<core::ops::Range<usize>> {
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

/// Return the detached buffer even when allocation/evaluation fails or unwinds.
struct ZaRowScratchLoan<'a> {
    state: &'a mut ScalableState,
    storage: Vec<u8>,
}

impl Drop for ZaRowScratchLoan<'_> {
    fn drop(&mut self) {
        self.state.za_scratch = Some(core::mem::take(&mut self.storage));
    }
}

fn zeroed_buffer(bytes: usize) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(bytes)?;
    buffer.resize(bytes, 0);
    Ok(buffer)
}

#[cfg(test)]
mod tests;

pub mod block;
