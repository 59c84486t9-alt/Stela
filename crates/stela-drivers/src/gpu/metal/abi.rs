//! Metal's public enumerations and option sets with Apple's raw values.
//!
//! The guest frontend forwards `NSUInteger` arguments unchanged; decoding
//! refuses values the SDK does not name rather than guessing. Values match the
//! macOS 26 SDK declarations (`Metal.framework` headers). Pixel and vertex
//! formats live in their own modules.

raw_enum! {
    /// `MTLGPUFamily`.
    pub enum GpuFamily: u64 {
        Apple1 = 1001,
        Apple2 = 1002,
        Apple3 = 1003,
        Apple4 = 1004,
        Apple5 = 1005,
        Apple6 = 1006,
        Apple7 = 1007,
        Apple8 = 1008,
        Apple9 = 1009,
        Apple10 = 1010,
        Apple11 = 1011,
        Mac1 = 2001,
        Mac2 = 2002,
        Common1 = 3001,
        Common2 = 3002,
        Common3 = 3003,
        MacCatalyst1 = 4001,
        MacCatalyst2 = 4002,
        Metal3 = 5001,
        Metal4 = 5002,
    }
}

raw_enum! {
    /// `MTLDeviceLocation`.
    pub enum DeviceLocation: u64 {
        BuiltIn = 0,
        Slot = 1,
        External = 2,
        Unspecified = u64::MAX,
    }
}

raw_enum! {
    /// `MTLReadWriteTextureTier`.
    pub enum ReadWriteTextureTier: u64 {
        None = 0,
        Tier1 = 1,
        Tier2 = 2,
    }
}

raw_enum! {
    /// `MTLArgumentBuffersTier`.
    pub enum ArgumentBuffersTier: u64 {
        Tier1 = 0,
        Tier2 = 1,
    }
}

raw_enum! {
    /// `MTLCounterSamplingPoint`.
    pub enum CounterSamplingPoint: u64 {
        AtStageBoundary = 0,
        AtDrawBoundary = 1,
        AtDispatchBoundary = 2,
        AtTileDispatchBoundary = 3,
        AtBlitBoundary = 4,
    }
}

raw_enum! {
    /// `MTLTextureType`.
    pub enum TextureType: u64 {
        D1 = 0,
        D1Array = 1,
        D2 = 2,
        D2Array = 3,
        D2Multisample = 4,
        Cube = 5,
        CubeArray = 6,
        D3 = 7,
        D2MultisampleArray = 8,
        TextureBuffer = 9,
    }
}

impl TextureType {
    pub const fn is_array(self) -> bool {
        matches!(
            self,
            Self::D1Array | Self::D2Array | Self::CubeArray | Self::D2MultisampleArray
        )
    }

    pub const fn is_multisample(self) -> bool {
        matches!(self, Self::D2Multisample | Self::D2MultisampleArray)
    }

    pub const fn is_cube(self) -> bool {
        matches!(self, Self::Cube | Self::CubeArray)
    }
}

raw_enum! {
    /// `MTLTextureSwizzle`.
    pub enum TextureSwizzle: u8 {
        Zero = 0,
        One = 1,
        Red = 2,
        Green = 3,
        Blue = 4,
        Alpha = 5,
    }
}

/// `MTLTextureSwizzleChannels`: the source of red, green, blue and alpha.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SwizzleChannels(pub [TextureSwizzle; 4]);

impl SwizzleChannels {
    pub const IDENTITY: Self = Self([
        TextureSwizzle::Red,
        TextureSwizzle::Green,
        TextureSwizzle::Blue,
        TextureSwizzle::Alpha,
    ]);

    pub fn is_identity(self) -> bool {
        self == Self::IDENTITY
    }
}

raw_enum! {
    /// `MTLCPUCacheMode`.
    pub enum CpuCacheMode: u64 {
        DefaultCache = 0,
        WriteCombined = 1,
    }
}

raw_enum! {
    /// `MTLStorageMode`.
    pub enum StorageMode: u64 {
        Shared = 0,
        Managed = 1,
        Private = 2,
        Memoryless = 3,
    }
}

raw_enum! {
    /// `MTLHazardTrackingMode`.
    pub enum HazardTrackingMode: u64 {
        Default = 0,
        Untracked = 1,
        Tracked = 2,
    }
}

/// `MTLResourceOptions`, decoded into its three fields. The SDK packs the CPU
/// cache mode at bit 0, the storage mode at bit 4 and hazard tracking at bit 8.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ResourceOptions {
    pub cpu_cache_mode: CpuCacheMode,
    pub storage_mode: StorageMode,
    pub hazard_tracking_mode: HazardTrackingMode,
}

impl ResourceOptions {
    const CACHE_SHIFT: u32 = 0;
    const STORAGE_SHIFT: u32 = 4;
    const HAZARD_SHIFT: u32 = 8;
    const KNOWN: u64 = 0xf | 0xf << Self::STORAGE_SHIFT | 0x3 << Self::HAZARD_SHIFT;

    pub fn from_raw(raw: u64) -> Option<Self> {
        if raw & !Self::KNOWN != 0 {
            return None;
        }
        Some(Self {
            cpu_cache_mode: CpuCacheMode::from_raw(raw >> Self::CACHE_SHIFT & 0xf)?,
            storage_mode: StorageMode::from_raw(raw >> Self::STORAGE_SHIFT & 0xf)?,
            hazard_tracking_mode: HazardTrackingMode::from_raw(raw >> Self::HAZARD_SHIFT & 0x3)?,
        })
    }

    pub const fn raw(self) -> u64 {
        self.cpu_cache_mode.raw() << Self::CACHE_SHIFT
            | self.storage_mode.raw() << Self::STORAGE_SHIFT
            | self.hazard_tracking_mode.raw() << Self::HAZARD_SHIFT
    }
}

option_set! {
    /// `MTLTextureUsage`.
    pub struct TextureUsage: u64 {
        const SHADER_READ = 0x1;
        const SHADER_WRITE = 0x2;
        const RENDER_TARGET = 0x4;
        const PIXEL_FORMAT_VIEW = 0x10;
        const SHADER_ATOMIC = 0x20;
    }
}

raw_enum! {
    /// `MTLSparsePageSize`.
    pub enum SparsePageSize: u64 {
        Size16 = 101,
        Size64 = 102,
        Size256 = 103,
    }
}

impl SparsePageSize {
    pub const fn bytes(self) -> u64 {
        match self {
            Self::Size16 => 16 << 10,
            Self::Size64 => 64 << 10,
            Self::Size256 => 256 << 10,
        }
    }
}

raw_enum! {
    /// `MTLSparseTextureMappingMode`.
    pub enum SparseTextureMappingMode: u64 {
        Map = 0,
        Unmap = 1,
    }
}

raw_enum! {
    /// `MTLSparseTextureRegionAlignmentMode`.
    pub enum SparseTextureRegionAlignmentMode: u64 {
        Outward = 0,
        Inward = 1,
    }
}

raw_enum! {
    /// `MTLPurgeableState`.
    pub enum PurgeableState: u64 {
        KeepCurrent = 1,
        NonVolatile = 2,
        Volatile = 3,
        Empty = 4,
    }
}

raw_enum! {
    /// `MTLHeapType`.
    pub enum HeapType: u64 {
        Automatic = 0,
        Placement = 1,
        Sparse = 2,
    }
}

raw_enum! {
    /// `MTLSamplerMinMagFilter`.
    pub enum SamplerMinMagFilter: u64 {
        Nearest = 0,
        Linear = 1,
    }
}

raw_enum! {
    /// `MTLSamplerMipFilter`.
    pub enum SamplerMipFilter: u64 {
        NotMipmapped = 0,
        Nearest = 1,
        Linear = 2,
    }
}

raw_enum! {
    /// `MTLSamplerAddressMode`.
    pub enum SamplerAddressMode: u64 {
        ClampToEdge = 0,
        MirrorClampToEdge = 1,
        Repeat = 2,
        MirrorRepeat = 3,
        ClampToZero = 4,
        ClampToBorderColor = 5,
    }
}

raw_enum! {
    /// `MTLSamplerBorderColor`.
    pub enum SamplerBorderColor: u64 {
        TransparentBlack = 0,
        OpaqueBlack = 1,
        OpaqueWhite = 2,
    }
}

raw_enum! {
    /// `MTLSamplerReductionMode`.
    pub enum SamplerReductionMode: u64 {
        WeightedAverage = 0,
        Minimum = 1,
        Maximum = 2,
    }
}

raw_enum! {
    /// `MTLCompareFunction`.
    pub enum CompareFunction: u64 {
        Never = 0,
        Less = 1,
        Equal = 2,
        LessEqual = 3,
        Greater = 4,
        NotEqual = 5,
        GreaterEqual = 6,
        Always = 7,
    }
}

raw_enum! {
    /// `MTLStencilOperation`.
    pub enum StencilOperation: u64 {
        Keep = 0,
        Zero = 1,
        Replace = 2,
        IncrementClamp = 3,
        DecrementClamp = 4,
        Invert = 5,
        IncrementWrap = 6,
        DecrementWrap = 7,
    }
}

raw_enum! {
    /// `MTLLoadAction`.
    pub enum LoadAction: u64 {
        DontCare = 0,
        Load = 1,
        Clear = 2,
    }
}

raw_enum! {
    /// `MTLStoreAction`.
    pub enum StoreAction: u64 {
        DontCare = 0,
        Store = 1,
        MultisampleResolve = 2,
        StoreAndMultisampleResolve = 3,
        Unknown = 4,
        CustomSampleDepthStore = 5,
    }
}

impl StoreAction {
    pub const fn stores(self) -> bool {
        matches!(
            self,
            Self::Store | Self::StoreAndMultisampleResolve | Self::CustomSampleDepthStore
        )
    }

    pub const fn resolves(self) -> bool {
        matches!(
            self,
            Self::MultisampleResolve | Self::StoreAndMultisampleResolve
        )
    }
}

option_set! {
    /// `MTLStoreActionOptions`.
    pub struct StoreActionOptions: u64 {
        const CUSTOM_SAMPLE_POSITIONS = 0x1;
    }
}

raw_enum! {
    /// `MTLMultisampleDepthResolveFilter`.
    pub enum MultisampleDepthResolveFilter: u64 {
        Sample0 = 0,
        Min = 1,
        Max = 2,
    }
}

raw_enum! {
    /// `MTLMultisampleStencilResolveFilter`.
    pub enum MultisampleStencilResolveFilter: u64 {
        Sample0 = 0,
        DepthResolvedSample = 1,
    }
}

raw_enum! {
    /// `MTLBlendFactor`.
    pub enum BlendFactor: u64 {
        Zero = 0,
        One = 1,
        SourceColor = 2,
        OneMinusSourceColor = 3,
        SourceAlpha = 4,
        OneMinusSourceAlpha = 5,
        DestinationColor = 6,
        OneMinusDestinationColor = 7,
        DestinationAlpha = 8,
        OneMinusDestinationAlpha = 9,
        SourceAlphaSaturated = 10,
        BlendColor = 11,
        OneMinusBlendColor = 12,
        BlendAlpha = 13,
        OneMinusBlendAlpha = 14,
        Source1Color = 15,
        OneMinusSource1Color = 16,
        Source1Alpha = 17,
        OneMinusSource1Alpha = 18,
    }
}

impl BlendFactor {
    pub const fn uses_source1(self) -> bool {
        matches!(
            self,
            Self::Source1Color
                | Self::OneMinusSource1Color
                | Self::Source1Alpha
                | Self::OneMinusSource1Alpha
        )
    }
}

raw_enum! {
    /// `MTLBlendOperation`.
    pub enum BlendOperation: u64 {
        Add = 0,
        Subtract = 1,
        ReverseSubtract = 2,
        Min = 3,
        Max = 4,
    }
}

option_set! {
    /// `MTLColorWriteMask`. Unlike Vulkan, red is the highest bit.
    pub struct ColorWriteMask: u64 {
        const ALPHA = 0x1;
        const BLUE = 0x2;
        const GREEN = 0x4;
        const RED = 0x8;
    }
}

raw_enum! {
    /// `MTLPrimitiveTopologyClass`.
    pub enum PrimitiveTopologyClass: u64 {
        Unspecified = 0,
        Point = 1,
        Line = 2,
        Triangle = 3,
    }
}

raw_enum! {
    /// `MTLPrimitiveType`.
    pub enum PrimitiveType: u64 {
        Point = 0,
        Line = 1,
        LineStrip = 2,
        Triangle = 3,
        TriangleStrip = 4,
    }
}

impl PrimitiveType {
    pub const fn class(self) -> PrimitiveTopologyClass {
        match self {
            Self::Point => PrimitiveTopologyClass::Point,
            Self::Line | Self::LineStrip => PrimitiveTopologyClass::Line,
            Self::Triangle | Self::TriangleStrip => PrimitiveTopologyClass::Triangle,
        }
    }

    pub const fn is_strip(self) -> bool {
        matches!(self, Self::LineStrip | Self::TriangleStrip)
    }
}

raw_enum! {
    /// `MTLIndexType`.
    pub enum IndexType: u64 {
        UInt16 = 0,
        UInt32 = 1,
    }
}

impl IndexType {
    pub const fn bytes(self) -> u64 {
        match self {
            Self::UInt16 => 2,
            Self::UInt32 => 4,
        }
    }
}

raw_enum! {
    /// `MTLCullMode`.
    pub enum CullMode: u64 {
        None = 0,
        Front = 1,
        Back = 2,
    }
}

raw_enum! {
    /// `MTLWinding`.
    pub enum Winding: u64 {
        Clockwise = 0,
        CounterClockwise = 1,
    }
}

raw_enum! {
    /// `MTLDepthClipMode`.
    pub enum DepthClipMode: u64 {
        Clip = 0,
        Clamp = 1,
    }
}

raw_enum! {
    /// `MTLTriangleFillMode`.
    pub enum TriangleFillMode: u64 {
        Fill = 0,
        Lines = 1,
    }
}

raw_enum! {
    /// `MTLVisibilityResultMode`.
    pub enum VisibilityResultMode: u64 {
        Disabled = 0,
        Boolean = 1,
        Counting = 2,
    }
}

raw_enum! {
    /// `MTLTessellationPartitionMode`.
    pub enum TessellationPartitionMode: u64 {
        Pow2 = 0,
        Integer = 1,
        FractionalOdd = 2,
        FractionalEven = 3,
    }
}

raw_enum! {
    /// `MTLTessellationFactorFormat`.
    pub enum TessellationFactorFormat: u64 {
        Half = 0,
    }
}

raw_enum! {
    /// `MTLTessellationFactorStepFunction`.
    pub enum TessellationFactorStepFunction: u64 {
        Constant = 0,
        PerPatch = 1,
        PerInstance = 2,
        PerPatchAndPerInstance = 3,
    }
}

raw_enum! {
    /// `MTLTessellationControlPointIndexType`.
    pub enum TessellationControlPointIndexType: u64 {
        None = 0,
        UInt16 = 1,
        UInt32 = 2,
    }
}

raw_enum! {
    /// `MTLCommandBufferStatus`.
    pub enum CommandBufferStatus: u64 {
        NotEnqueued = 0,
        Enqueued = 1,
        Committed = 2,
        Scheduled = 3,
        Completed = 4,
        Error = 5,
    }
}

raw_enum! {
    /// `MTLCommandBufferError`.
    pub enum CommandBufferError: u64 {
        None = 0,
        Internal = 1,
        Timeout = 2,
        PageFault = 3,
        AccessRevoked = 4,
        NotPermitted = 7,
        OutOfMemory = 8,
        InvalidResource = 9,
        Memoryless = 10,
        DeviceRemoved = 11,
        StackOverflow = 12,
    }
}

raw_enum! {
    /// `MTLDispatchType`.
    pub enum DispatchType: u64 {
        Serial = 0,
        Concurrent = 1,
    }
}

option_set! {
    /// `MTLBarrierScope`.
    pub struct BarrierScope: u64 {
        const BUFFERS = 0x1;
        const TEXTURES = 0x2;
        const RENDER_TARGETS = 0x4;
    }
}

option_set! {
    /// `MTLRenderStages`.
    pub struct RenderStages: u64 {
        const VERTEX = 0x1;
        const FRAGMENT = 0x2;
        const TILE = 0x4;
        const OBJECT = 0x8;
        const MESH = 0x10;
    }
}

option_set! {
    /// `MTLResourceUsage`.
    pub struct ResourceUsage: u64 {
        const READ = 0x1;
        const WRITE = 0x2;
        const SAMPLE = 0x4;
    }
}

option_set! {
    /// `MTLBlitOption`.
    pub struct BlitOption: u64 {
        const DEPTH_FROM_DEPTH_STENCIL = 0x1;
        const STENCIL_FROM_DEPTH_STENCIL = 0x2;
        const ROW_LINEAR_PVRTC = 0x4;
    }
}

raw_enum! {
    /// `MTLFunctionType`.
    pub enum FunctionType: u64 {
        Vertex = 1,
        Fragment = 2,
        Kernel = 3,
        Visible = 5,
        Intersection = 6,
        Mesh = 7,
        Object = 8,
    }
}

raw_enum! {
    /// `MTLLanguageVersion`: the major version in bits 16 and up, minor below.
    pub enum LanguageVersion: u64 {
        V1_0 = 1 << 16,
        V1_1 = (1 << 16) + 1,
        V1_2 = (1 << 16) + 2,
        V2_0 = 2 << 16,
        V2_1 = (2 << 16) + 1,
        V2_2 = (2 << 16) + 2,
        V2_3 = (2 << 16) + 3,
        V2_4 = (2 << 16) + 4,
        V3_0 = 3 << 16,
        V3_1 = (3 << 16) + 1,
        V3_2 = (3 << 16) + 2,
        V4_0 = 4 << 16,
        V4_1 = (4 << 16) + 1,
    }
}
