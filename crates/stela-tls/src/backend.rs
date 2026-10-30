//! Checked opaque Mbed contexts; private pointer ownership and fallible operations.
use core::{
    ffi::{c_int, c_uint, c_void},
    ptr::NonNull,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(pub i32);
pub trait Entropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error>;
}
#[derive(Clone, Copy)]
pub enum Group {
    X25519 = 1,
    P256 = 2,
}
#[repr(C)]
struct Opaque {
    _private: [u8; 0],
}
type Rng = unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> c_int;
unsafe extern "C" {
    fn stela_mbed_kx_new(
        group: c_uint,
        rng: Rng,
        context: *mut c_void,
        key: *mut *mut Opaque,
        public: *mut u8,
        capacity: usize,
        written: *mut usize,
    ) -> c_int;
    fn stela_mbed_kx_shared(
        key: *mut Opaque,
        peer: *const u8,
        length: usize,
        rng: Rng,
        context: *mut c_void,
        output: *mut u8,
        capacity: usize,
    ) -> c_int;
    fn stela_mbed_kx_free(key: *mut Opaque);
    fn stela_mbed_md_new(
        bits: c_uint,
        hmac: c_int,
        key: *const u8,
        key_bytes: usize,
        output: *mut *mut Opaque,
    ) -> c_int;
    fn stela_mbed_md_clone(source: *const Opaque, output: *mut *mut Opaque) -> c_int;
    fn stela_mbed_md_update(state: *mut Opaque, input: *const u8, bytes: usize) -> c_int;
    fn stela_mbed_md_finish(state: *mut Opaque, output: *mut u8, bytes: usize) -> c_int;
    fn stela_mbed_md_free(state: *mut Opaque);
    fn stela_mbed_verify(
        kind: c_uint,
        hash_bits: c_uint,
        public: *const u8,
        public_bytes: usize,
        message: *const u8,
        message_bytes: usize,
        signature: *const u8,
        signature_bytes: usize,
    ) -> c_int;
}
unsafe extern "C" fn random<R: Entropy>(
    context: *mut c_void,
    output: *mut u8,
    length: usize,
) -> c_int {
    if context.is_null() || output.is_null() || length > isize::MAX as usize {
        return -1;
    }
    // SAFETY: each synchronous checked Mbed call borrows its concrete R for the
    // whole call and provides a writable output of this exact bounded length.
    let (rng, output) = unsafe {
        (
            &mut *context.cast::<R>(),
            core::slice::from_raw_parts_mut(output, length),
        )
    };
    rng.fill(output).map_or_else(|_| -1, |()| 0)
}
pub struct Key<R: Entropy> {
    key: NonNull<Opaque>,
    rng: R,
    public: [u8; 65],
    length: usize,
}
impl<R: Entropy> Key<R> {
    pub fn new(group: Group, mut rng: R) -> Result<Self, Error> {
        let mut key = core::ptr::null_mut();
        let mut public = [0u8; 65];
        let mut length = 0;
        // SAFETY: output slots/array and concrete RNG remain live across
        // the synchronous checked call; C publishes a key only on success.
        let status = unsafe {
            stela_mbed_kx_new(
                group as c_uint,
                random::<R>,
                core::ptr::from_mut(&mut rng).cast(),
                &mut key,
                public.as_mut_ptr(),
                public.len(),
                &mut length,
            )
        };
        if status != 0 {
            return Err(Error(status));
        }
        Ok(Self {
            key: NonNull::new(key).ok_or(Error(-1))?,
            rng,
            public,
            length,
        })
    }
    pub fn public(&self) -> &[u8] {
        &self.public[..self.length]
    }
    pub fn complete(&mut self, peer: &[u8]) -> Result<[u8; 32], Error> {
        let mut output = [0u8; 32];
        // SAFETY: this exclusive affine key/RNG and peer/output remain alive;
        // the C adapter validates exact curve point length and checked public key.
        let status = unsafe {
            stela_mbed_kx_shared(
                self.key.as_ptr(),
                peer.as_ptr(),
                peer.len(),
                random::<R>,
                core::ptr::from_mut(&mut self.rng).cast(),
                output.as_mut_ptr(),
                output.len(),
            )
        };
        if status != 0 {
            Err(Error(status))
        } else {
            Ok(output)
        }
    }
}
impl<R: Entropy> Drop for Key<R> {
    fn drop(&mut self) {
        // SAFETY: exclusive key owns the exact C allocation with no outstanding
        // calls/borrowers; library frees/clears scalar and zeroizes its wrapper.
        unsafe { stela_mbed_kx_free(self.key.as_ptr()) };
    }
}

/// Exact public-key and signature formats are verified by the checked backend.
pub fn verify(
    kind: u32,
    hash_bits: u32,
    public: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    use der::Decode;
    // Both formats contain exactly two nonnegative canonical DER integers.
    // Mbed's ASN.1 MPI reader alone accepts BER/noncanonical signed encodings.
    if kind <= 2 {
        <[der::asn1::UintRef<'_>; 2]>::from_der(public).map_err(|_| Error(-1))?;
    } else {
        <[der::asn1::UintRef<'_>; 2]>::from_der(signature).map_err(|_| Error(-1))?;
    }
    // SAFETY: the synchronous backend borrows exactly these readable slices;
    // it keeps no pointers and checks public-key shape/algorithm/signature.
    let status = unsafe {
        stela_mbed_verify(
            kind,
            hash_bits,
            public.as_ptr(),
            public.len(),
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
            signature.len(),
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(Error(status))
    }
}

/// Affine digest/HMAC state; every allocation is freed/wiped by the backend.
pub struct Digest {
    state: NonNull<Opaque>,
    bits: u32,
}
impl Digest {
    pub fn new(bits: u32, key: Option<&[u8]>) -> Result<Self, Error> {
        let mut state = core::ptr::null_mut();
        let (pointer, bytes) = key.map_or((core::ptr::null(), 0), |key| (key.as_ptr(), key.len()));
        // SAFETY: synchronous call borrows the key/output slot, publishes
        // only its complete unique context, and keeps no key pointer.
        let status =
            unsafe { stela_mbed_md_new(bits, key.is_some() as c_int, pointer, bytes, &mut state) };
        if status != 0 {
            return Err(Error(status));
        }
        Ok(Self {
            state: NonNull::new(state).ok_or(Error(-1))?,
            bits,
        })
    }
    pub fn try_clone(&self) -> Result<Self, Error> {
        let mut state = core::ptr::null_mut();
        // SAFETY: immutable source is live; backend creates an independent owned
        // plain digest and refuses keyed contexts, with no mutable aliases.
        let status = unsafe { stela_mbed_md_clone(self.state.as_ptr(), &mut state) };
        if status != 0 {
            return Err(Error(status));
        }
        Ok(Self {
            state: NonNull::new(state).ok_or(Error(-1))?,
            bits: self.bits,
        })
    }
    pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        // SAFETY: affine mutable context and exact readable synchronous input.
        let status =
            unsafe { stela_mbed_md_update(self.state.as_ptr(), input.as_ptr(), input.len()) };
        if status == 0 {
            Ok(())
        } else {
            Err(Error(status))
        }
    }
    pub fn finish(self) -> Result<alloc::vec::Vec<u8>, Error> {
        let mut result = alloc::vec![0; (self.bits/8) as usize];
        // SAFETY: unique live context and exact initialized writable output.
        let status =
            unsafe { stela_mbed_md_finish(self.state.as_ptr(), result.as_mut_ptr(), result.len()) };
        if status == 0 {
            Ok(result)
        } else {
            Err(Error(status))
        }
    }
}
impl Drop for Digest {
    fn drop(&mut self) {
        // SAFETY: exact uniquely owned backend context, no calls outlive borrow.
        unsafe { stela_mbed_md_free(self.state.as_ptr()) };
    }
}
// SAFETY: each context has its own allocation, no thread-affine state or
// callback/input pointer. Global allocator installation is immutable
// and must be thread safe; mutation requires an exclusive Rust borrow.
unsafe impl Send for Digest {}
// SAFETY: shared methods only clone a plain context by const read; each clone
// is independent. Updating/finishing/freeing always require unique ownership.
unsafe impl Sync for Digest {}

// SAFETY: key owns independent scalar/group/public allocations and keeps its
// concrete RNG. No caller/input pointer escapes a synchronous backend call.
// Installed allocator is immutable and supports independent concurrent objects.
unsafe impl<R: Entropy + Send> Send for Key<R> {}
// SAFETY: shared access exposes only immutable public bytes; all scalar/group
// mutation and destruction need unique ownership. The kept RNG is Sync.
unsafe impl<R: Entropy + Sync> Sync for Key<R> {}

#[cfg(test)]
mod tests;
