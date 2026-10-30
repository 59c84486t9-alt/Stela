//! The service's wire format: fixed-width records, their status and the
//! operations that carry them.
//!
//! A record is `#[repr(C)]` without padding, of integers, floats and arrays
//! of them, little-endian on both sides of the call gate, so every byte
//! pattern is a value and a request is read by copying its bytes. A request
//! or response is exactly its record's size. Enumerations and option sets
//! cross as Metal's raw values and are decoded with their declarations'
//! own checks; a handle is a connection's `ObjectHandle`, zero for none.
use crate::gpu::{
    metal::{capabilities::block::Block, error::Error},
    protocol::identity::TableError,
};
use alloc::vec::Vec;

/// The protocol version a connection negotiates. A major version changes
/// records; a minor version only adds operations.
pub const MAJOR: u32 = 1;
pub const MINOR: u32 = 0;

/// A fixed-width wire record.
///
/// # Safety
///
/// The type is `#[repr(C)]` without padding bytes and every bit pattern is
/// one of its values.
pub unsafe trait Record: Copy + 'static {}

macro_rules! primitives {
    ($($ty:ty),*) => {$(
        // SAFETY: integers and floats have no padding and accept every bit
        // pattern.
        unsafe impl Record for $ty {}
    )*};
}

primitives!(u8, u32, u64, i32, i64, f32);
// SAFETY: an array of records has no padding between its elements.
unsafe impl<T: Record, const N: usize> Record for [T; N] {}
// SAFETY: the block's layout is checked to be its fields' sizes, all of
// them integers, floats and arrays of them.
unsafe impl Record for Block {}

/// Declares records: `#[repr(C)]` structures of records, checked to have
/// no padding.
macro_rules! records {
    ($(
        $(#[$meta:meta])*
        pub struct $name:ident {
            $($(#[$field_meta:meta])* pub $field:ident: $ty:ty,)*
        }
    )*) => {$(
        $(#[$meta])*
        #[repr(C)]
        #[derive(Clone, Copy, Debug, Default, PartialEq)]
        pub struct $name {
            $($(#[$field_meta])* pub $field: $ty,)*
        }

        const _: () = assert!(
            core::mem::size_of::<$name>() == 0 $(+ core::mem::size_of::<$ty>())*,
            "records have no padding"
        );

        // SAFETY: the fields are records and the assertion above rules out
        // padding.
        unsafe impl Record for $name where $($ty: Record,)* {}
    )*};
}

/// The records filling `bytes`.
pub fn read_array<T: Record>(bytes: &[u8]) -> Result<Vec<T>, Fault> {
    if !bytes.len().is_multiple_of(core::mem::size_of::<T>()) {
        return Err(Fault::MALFORMED);
    }
    bytes
        .chunks_exact(core::mem::size_of::<T>())
        .map(read)
        .collect()
}

/// The record in `bytes`, which must be exactly its size.
pub fn read<T: Record>(bytes: &[u8]) -> Result<T, Fault> {
    if bytes.len() != core::mem::size_of::<T>() {
        return Err(Fault::MALFORMED);
    }
    // SAFETY: `bytes` holds `size_of::<T>()` bytes, and every bit pattern is
    // a `T`.
    Ok(unsafe { bytes.as_ptr().cast::<T>().read_unaligned() })
}

/// Writes `value` to `out`, which must be exactly its size.
pub fn write<T: Record>(value: &T, out: &mut [u8]) -> Result<(), Fault> {
    if out.len() != core::mem::size_of::<T>() {
        return Err(Fault::MALFORMED);
    }
    // SAFETY: a record has no padding, so its bytes are initialized.
    let bytes = unsafe {
        core::slice::from_raw_parts((value as *const T).cast::<u8>(), core::mem::size_of::<T>())
    };
    out.copy_from_slice(bytes);
    Ok(())
}

records! {
    /// A range of the guest's address space, which the call gate resolves.
    pub struct Span {
        pub address: u64,
        pub length: u64,
    }

    /// No data.
    pub struct Empty {}

    /// `Negotiate`: the versions the frontend speaks.
    pub struct NegotiateRequest {
        pub major: u32,
        pub minor: u32,
    }

    /// The service's version and the size of the capability block.
    pub struct NegotiateResponse {
        pub major: u32,
        pub minor: u32,
        pub capability_bytes: u32,
        pub reserved: u32,
    }

    /// An object of the connection.
    pub struct Handle {
        pub handle: u64,
    }

    /// The length of variable data, which the response's span received
    /// when it was long enough.
    pub struct Length {
        pub length: u64,
    }

    /// `NewLibrary`: a Metal library's bytes.
    pub struct NewLibraryRequest {
        pub data: Span,
    }

    /// `LibraryFunctionNames`: the span receiving the names, each ended by
    /// a zero byte.
    pub struct LibraryFunctionNamesRequest {
        pub library: u64,
        pub out: Span,
    }

    /// `NewFunction`: the function's name and its `ConstantRecord`s.
    pub struct NewFunctionRequest {
        pub library: u64,
        pub name: Span,
        pub constants: Span,
    }

    /// A function constant value: an `MTLDataType` and the value's packed
    /// lanes, for the constant of `name`, or at `index` when it is empty.
    pub struct ConstantRecord {
        pub data_type: u64,
        pub index: u64,
        pub name: Span,
        pub value: Span,
    }

    /// `newBufferWithLength:options:`.
    pub struct NewBufferRequest {
        pub length: u64,
        pub options: u64,
    }

    /// A new buffer: its `gpuAddress`, its `contents` (zero for a private
    /// buffer), `allocatedSize` and `heapOffset`.
    pub struct BufferResponse {
        pub handle: u64,
        pub gpu_address: u64,
        pub contents: u64,
        pub allocated_size: u64,
        pub heap_offset: u64,
    }

    /// `didModifyRange:`.
    pub struct BufferRangeRequest {
        pub buffer: u64,
        pub offset: u64,
        pub length: u64,
    }

    /// `MTLTextureDescriptor`.
    pub struct TextureDescriptorRecord {
        pub texture_type: u64,
        pub pixel_format: u64,
        pub width: u64,
        pub height: u64,
        pub depth: u64,
        pub mipmap_level_count: u64,
        pub sample_count: u64,
        pub array_length: u64,
        pub options: u64,
        pub usage: u64,
        /// `MTLTextureSwizzleChannels`: red, green, blue and alpha.
        pub swizzle: [u8; 4],
        pub reserved: u32,
    }

    /// A new texture: its `gpuResourceID`, `allocatedSize`, `heapOffset`
    /// and, when `sparse`, `firstMipmapInTail` and `tailSizeInBytes`.
    pub struct TextureResponse {
        pub handle: u64,
        pub resource_id: u64,
        pub allocated_size: u64,
        pub heap_offset: u64,
        pub first_mipmap_in_tail: u64,
        pub tail_size: u64,
        pub sparse: u32,
        pub reserved: u32,
    }

    /// `newTextureViewWithPixelFormat:textureType:levels:slices:swizzle:`;
    /// ranges are a location and a length.
    pub struct NewTextureViewRequest {
        pub texture: u64,
        pub pixel_format: u64,
        pub texture_type: u64,
        pub levels: [u64; 2],
        pub slices: [u64; 2],
        pub swizzle: [u8; 4],
        pub reserved: u32,
    }

    /// `newTextureWithDescriptor:offset:bytesPerRow:` of a buffer.
    pub struct NewBufferTextureRequest {
        pub buffer: u64,
        pub descriptor: TextureDescriptorRecord,
        pub offset: u64,
        pub bytes_per_row: u64,
    }

    /// `MTLRegion` of one mipmap level and slice.
    pub struct RegionRecord {
        pub slice: u64,
        pub level: u64,
        pub origin: [u64; 3],
        pub size: [u64; 3],
    }

    /// `replaceRegion:…` from `bytes`, or `getBytes:…` into them.
    pub struct TextureBytesRequest {
        pub texture: u64,
        pub region: RegionRecord,
        pub bytes: Span,
        pub bytes_per_row: u64,
        pub bytes_per_image: u64,
    }

    /// `MTLSamplerDescriptor`; address modes are s, t and r.
    pub struct SamplerDescriptorRecord {
        pub min_filter: u64,
        pub mag_filter: u64,
        pub mip_filter: u64,
        pub max_anisotropy: u64,
        pub address_modes: [u64; 3],
        pub border_color: u64,
        pub reduction_mode: u64,
        pub compare_function: u64,
        pub lod_min_clamp: f32,
        pub lod_max_clamp: f32,
        pub normalized_coordinates: u32,
        pub reserved: u32,
    }

    /// A new sampler and its `gpuResourceID`.
    pub struct SamplerResponse {
        pub handle: u64,
        pub resource_id: u64,
    }

    /// `MTLHeapDescriptor`.
    pub struct HeapDescriptorRecord {
        pub size: u64,
        pub options: u64,
        pub heap_type: u64,
        pub sparse_page_size: u64,
    }

    /// `heapBufferSizeAndAlignWithLength:options:`.
    pub struct HeapBufferSizeRequest {
        pub length: u64,
        pub options: u64,
    }

    /// `MTLSizeAndAlign`.
    pub struct SizeAndAlignRecord {
        pub size: u64,
        pub align: u64,
    }

    /// `newBufferWithLength:options:offset:` of a heap, or without an offset
    /// when it is `AUTOMATIC`.
    pub struct NewHeapBufferRequest {
        pub heap: u64,
        pub length: u64,
        pub options: u64,
        pub offset: u64,
    }

    /// `newTextureWithDescriptor:offset:` of a heap, or without an offset
    /// when it is `AUTOMATIC`.
    pub struct NewHeapTextureRequest {
        pub heap: u64,
        pub descriptor: TextureDescriptorRecord,
        pub offset: u64,
    }

    /// `maxAvailableSizeWithAlignment:` of a heap.
    pub struct HeapUsageRequest {
        pub heap: u64,
        pub alignment: u64,
    }

    /// `usedSize` and `maxAvailableSizeWithAlignment:`.
    pub struct HeapUsageResponse {
        pub used_size: u64,
        pub max_available_size: u64,
    }
}

/// The offset of a resource the heap places itself.
pub const AUTOMATIC: u64 = u64::MAX;

raw_enum! {
    /// How an operation ended.
    pub enum Status: u32 {
        Ok = 0,
        /// The call violates Metal's API contract.
        Invalid = 1,
        /// Valid Metal this device cannot honor.
        Unsupported = 2,
        OutOfMemory = 3,
        DeviceLost = 4,
        UnknownOperation = 5,
        /// A record of the wrong size, or a value its type does not name.
        Malformed = 6,
        /// A handle this connection does not hold, or holds for another
        /// kind of object.
        StaleHandle = 7,
        /// The connection is unknown or closed.
        Closed = 8,
    }
}

/// A failed operation: its status and why.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fault {
    pub status: Status,
    pub reason: &'static str,
}

impl Fault {
    pub const MALFORMED: Self = Self::new(Status::Malformed, "malformed record");
    pub const STALE: Self = Self::new(Status::StaleHandle, "unknown or destroyed handle");
    pub const CLOSED: Self = Self::new(Status::Closed, "the connection is closed");

    pub const fn new(status: Status, reason: &'static str) -> Self {
        Self { status, reason }
    }

    /// A value its type does not name.
    pub const fn malformed(reason: &'static str) -> Self {
        Self::new(Status::Malformed, reason)
    }
}

impl From<Error> for Fault {
    fn from(error: Error) -> Self {
        match error {
            Error::Invalid(reason) => Self::new(Status::Invalid, reason),
            Error::Unsupported(capability) => Self::new(Status::Unsupported, capability),
            Error::OutOfMemory => Self::new(Status::OutOfMemory, "out of memory"),
            Error::DeviceLost => Self::new(Status::DeviceLost, "the device was lost"),
        }
    }
}

impl From<TableError> for Fault {
    fn from(error: TableError) -> Self {
        match error {
            TableError::StaleHandle => Self::STALE,
            TableError::Full => {
                Self::new(Status::OutOfMemory, "the connection holds too many objects")
            }
            TableError::OutOfMemory => Self::new(Status::OutOfMemory, "out of memory"),
            TableError::WrongConnection | TableError::WrongEpoch | TableError::Closed => {
                Self::CLOSED
            }
        }
    }
}

/// Declares the operations: their codes, grouped by area in the high byte,
/// and their request and response records.
macro_rules! operations {
    ($($(#[$meta:meta])* $name:ident = $code:expr => $request:ty, $response:ty;)*) => {
        raw_enum! {
            pub enum Operation: u32 {
                $($(#[$meta])* $name = $code,)*
            }
        }

        impl Operation {
            /// The sizes of the operation's request and response records.
            pub const fn sizes(self) -> (usize, usize) {
                match self {
                    $(Self::$name => (
                        core::mem::size_of::<$request>(),
                        core::mem::size_of::<$response>(),
                    ),)*
                }
            }
        }
    };
}

operations! {
    /// Agrees on the protocol version.
    Negotiate = 0x0001 => NegotiateRequest, NegotiateResponse;
    /// The device's capability block.
    Capabilities = 0x0002 => Empty, Block;
    /// Releases an object; the device keeps what other objects and
    /// in-flight work still use.
    Release = 0x0003 => Handle, Empty;
    /// `newLibraryWithData:`.
    NewLibrary = 0x0101 => NewLibraryRequest, Handle;
    /// `functionNames`.
    LibraryFunctionNames = 0x0102 => LibraryFunctionNamesRequest, Length;
    /// `newFunctionWithName:constantValues:`.
    NewFunction = 0x0103 => NewFunctionRequest, Handle;
    /// `newBufferWithLength:options:`.
    NewBuffer = 0x0201 => NewBufferRequest, BufferResponse;
    /// `didModifyRange:`.
    BufferDidModifyRange = 0x0202 => BufferRangeRequest, Empty;
    /// `newTextureWithDescriptor:`.
    NewTexture = 0x0203 => TextureDescriptorRecord, TextureResponse;
    NewTextureView = 0x0204 => NewTextureViewRequest, TextureResponse;
    NewBufferTexture = 0x0205 => NewBufferTextureRequest, TextureResponse;
    ReplaceRegion = 0x0206 => TextureBytesRequest, Empty;
    GetBytes = 0x0207 => TextureBytesRequest, Empty;
    /// `newSamplerStateWithDescriptor:`.
    NewSampler = 0x0208 => SamplerDescriptorRecord, SamplerResponse;
    /// `newHeapWithDescriptor:`.
    NewHeap = 0x0209 => HeapDescriptorRecord, Handle;
    HeapBufferSizeAndAlign = 0x020a => HeapBufferSizeRequest, SizeAndAlignRecord;
    /// `heapTextureSizeAndAlignWithDescriptor:`.
    HeapTextureSizeAndAlign = 0x020b => TextureDescriptorRecord, SizeAndAlignRecord;
    NewHeapBuffer = 0x020c => NewHeapBufferRequest, BufferResponse;
    NewHeapTexture = 0x020d => NewHeapTextureRequest, TextureResponse;
    HeapUsage = 0x020e => HeapUsageRequest, HeapUsageResponse;
    /// `makeAliasable` of a heap buffer or texture.
    MakeAliasable = 0x020f => Handle, Empty;
}
