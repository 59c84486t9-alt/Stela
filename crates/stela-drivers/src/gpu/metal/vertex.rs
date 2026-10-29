//! `MTLVertexDescriptor` lowered to Vulkan vertex input.
//!
//! Metal's vertex buffer indices are its buffer argument slots, so a layout
//! at index `n` becomes Vulkan binding `n` and attribute `a` becomes shader
//! location `a`. Strides are bound with the buffers
//! (`vkCmdBindVertexBuffers2`), which also serves Metal's dynamic strides.
//! Post-tessellation vertex functions step per patch or control point; the
//! compiler fetches their attributes from this layout ([`patch_input`]).
use super::{
    abi::IndexType,
    capabilities::{Capabilities, MAX_BUFFER_BINDINGS, MAX_VERTEX_ATTRIBUTES},
    error::{Error, Result, ensure, require},
    shader::NumericClass,
    vulkan::{
        Format, VertexInputRate,
        object::{VertexAttribute, VertexBinding, VertexInput},
    },
};
use alloc::vec::Vec;

raw_enum! {
    /// `MTLVertexFormat`, excluding `Invalid` (0).
    pub enum VertexFormat: u64 {
        UChar2 = 1,
        UChar3 = 2,
        UChar4 = 3,
        Char2 = 4,
        Char3 = 5,
        Char4 = 6,
        UChar2Normalized = 7,
        UChar3Normalized = 8,
        UChar4Normalized = 9,
        Char2Normalized = 10,
        Char3Normalized = 11,
        Char4Normalized = 12,
        UShort2 = 13,
        UShort3 = 14,
        UShort4 = 15,
        Short2 = 16,
        Short3 = 17,
        Short4 = 18,
        UShort2Normalized = 19,
        UShort3Normalized = 20,
        UShort4Normalized = 21,
        Short2Normalized = 22,
        Short3Normalized = 23,
        Short4Normalized = 24,
        Half2 = 25,
        Half3 = 26,
        Half4 = 27,
        Float = 28,
        Float2 = 29,
        Float3 = 30,
        Float4 = 31,
        Int = 32,
        Int2 = 33,
        Int3 = 34,
        Int4 = 35,
        UInt = 36,
        UInt2 = 37,
        UInt3 = 38,
        UInt4 = 39,
        Int1010102Normalized = 40,
        UInt1010102Normalized = 41,
        UChar4NormalizedBgra = 42,
        UChar = 45,
        Char = 46,
        UCharNormalized = 47,
        CharNormalized = 48,
        UShort = 49,
        Short = 50,
        UShortNormalized = 51,
        ShortNormalized = 52,
        Half = 53,
        FloatRg11B10 = 54,
        FloatRgb9E5 = 55,
    }
}

impl VertexFormat {
    /// The Vulkan format and the bytes one element occupies.
    pub const fn vulkan(self) -> (Format, u64) {
        use Format as F;
        use VertexFormat as V;
        match self {
            V::UChar => (F::R8Uint, 1),
            V::UChar2 => (F::R8G8Uint, 2),
            V::UChar3 => (F::R8G8B8Uint, 3),
            V::UChar4 => (F::R8G8B8A8Uint, 4),
            V::Char => (F::R8Sint, 1),
            V::Char2 => (F::R8G8Sint, 2),
            V::Char3 => (F::R8G8B8Sint, 3),
            V::Char4 => (F::R8G8B8A8Sint, 4),
            V::UCharNormalized => (F::R8Unorm, 1),
            V::UChar2Normalized => (F::R8G8Unorm, 2),
            V::UChar3Normalized => (F::R8G8B8Unorm, 3),
            V::UChar4Normalized => (F::R8G8B8A8Unorm, 4),
            V::CharNormalized => (F::R8Snorm, 1),
            V::Char2Normalized => (F::R8G8Snorm, 2),
            V::Char3Normalized => (F::R8G8B8Snorm, 3),
            V::Char4Normalized => (F::R8G8B8A8Snorm, 4),
            V::UShort => (F::R16Uint, 2),
            V::UShort2 => (F::R16G16Uint, 4),
            V::UShort3 => (F::R16G16B16Uint, 6),
            V::UShort4 => (F::R16G16B16A16Uint, 8),
            V::Short => (F::R16Sint, 2),
            V::Short2 => (F::R16G16Sint, 4),
            V::Short3 => (F::R16G16B16Sint, 6),
            V::Short4 => (F::R16G16B16A16Sint, 8),
            V::UShortNormalized => (F::R16Unorm, 2),
            V::UShort2Normalized => (F::R16G16Unorm, 4),
            V::UShort3Normalized => (F::R16G16B16Unorm, 6),
            V::UShort4Normalized => (F::R16G16B16A16Unorm, 8),
            V::ShortNormalized => (F::R16Snorm, 2),
            V::Short2Normalized => (F::R16G16Snorm, 4),
            V::Short3Normalized => (F::R16G16B16Snorm, 6),
            V::Short4Normalized => (F::R16G16B16A16Snorm, 8),
            V::Half => (F::R16Sfloat, 2),
            V::Half2 => (F::R16G16Sfloat, 4),
            V::Half3 => (F::R16G16B16Sfloat, 6),
            V::Half4 => (F::R16G16B16A16Sfloat, 8),
            V::Float => (F::R32Sfloat, 4),
            V::Float2 => (F::R32G32Sfloat, 8),
            V::Float3 => (F::R32G32B32Sfloat, 12),
            V::Float4 => (F::R32G32B32A32Sfloat, 16),
            V::Int => (F::R32Sint, 4),
            V::Int2 => (F::R32G32Sint, 8),
            V::Int3 => (F::R32G32B32Sint, 12),
            V::Int4 => (F::R32G32B32A32Sint, 16),
            V::UInt => (F::R32Uint, 4),
            V::UInt2 => (F::R32G32Uint, 8),
            V::UInt3 => (F::R32G32B32Uint, 12),
            V::UInt4 => (F::R32G32B32A32Uint, 16),
            // Metal packs red in the low bits, as Vulkan's A2B10G10R10.
            V::Int1010102Normalized => (F::A2B10G10R10SnormPack32, 4),
            V::UInt1010102Normalized => (F::A2B10G10R10UnormPack32, 4),
            V::UChar4NormalizedBgra => (F::B8G8R8A8Unorm, 4),
            V::FloatRg11B10 => (F::B10G11R11UfloatPack32, 4),
            V::FloatRgb9E5 => (F::E5B9G9R9UfloatPack32, 4),
        }
    }
}

impl VertexFormat {
    /// The shader type class an attribute of this format is read as.
    pub fn numeric_class(self) -> NumericClass {
        use VertexFormat as V;
        match self {
            V::UChar
            | V::UChar2
            | V::UChar3
            | V::UChar4
            | V::UShort
            | V::UShort2
            | V::UShort3
            | V::UShort4
            | V::UInt
            | V::UInt2
            | V::UInt3
            | V::UInt4 => NumericClass::Uint,
            V::Char
            | V::Char2
            | V::Char3
            | V::Char4
            | V::Short
            | V::Short2
            | V::Short3
            | V::Short4
            | V::Int
            | V::Int2
            | V::Int3
            | V::Int4 => NumericClass::Sint,
            _ => NumericClass::Float,
        }
    }
}

raw_enum! {
    /// `MTLVertexStepFunction`.
    pub enum StepFunction: u64 {
        Constant = 0,
        PerVertex = 1,
        PerInstance = 2,
        PerPatch = 3,
        PerPatchControlPoint = 4,
    }
}

/// `MTLBufferLayoutStrideDynamic`: the stride comes from
/// `setVertexBuffer:offset:attributeStride:`.
pub const STRIDE_DYNAMIC: u64 = u64::MAX;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Attribute {
    pub index: u32,
    pub format: VertexFormat,
    pub offset: u64,
    pub buffer_index: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Layout {
    pub buffer_index: u32,
    pub stride: u64,
    pub step_function: StepFunction,
    pub step_rate: u64,
}

/// The attributes and buffer layouts a vertex function fetches.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct VertexDescriptor {
    pub attributes: Vec<Attribute>,
    pub layouts: Vec<Layout>,
}

raw_enum! {
    /// `MTLStepFunction`, for kernel stage-in.
    pub enum StageInStep: u64 {
        Constant = 0,
        ThreadPositionInGridX = 5,
        ThreadPositionInGridY = 6,
        ThreadPositionInGridXIndexed = 7,
        ThreadPositionInGridYIndexed = 8,
    }
}

impl StageInStep {
    pub const fn indexed(self) -> bool {
        matches!(
            self,
            Self::ThreadPositionInGridXIndexed | Self::ThreadPositionInGridYIndexed
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StageInLayout {
    pub buffer_index: u32,
    pub stride: u64,
    pub step_function: StageInStep,
    pub step_rate: u64,
}

/// `MTLStageInputOutputDescriptor`: the kernel fetches its `[[stage_in]]`
/// attributes from bound buffers at its thread position within the
/// dispatch's stage-in region, through the index buffer for indexed steps.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct StageInputDescriptor {
    pub attributes: Vec<Attribute>,
    pub layouts: Vec<StageInLayout>,
    pub index_type: IndexType,
    pub index_buffer_index: u32,
}

pub fn stage_input(descriptor: &StageInputDescriptor) -> Result<()> {
    let mut indexed = false;
    for layout in &descriptor.layouts {
        ensure(
            layout.buffer_index < MAX_BUFFER_BINDINGS,
            "stage-in buffer index exceeds the argument table",
        )?;
        ensure(
            descriptor
                .layouts
                .iter()
                .filter(|other| other.buffer_index == layout.buffer_index)
                .count()
                == 1,
            "stage-in buffer layouts are unique",
        )?;
        ensure(
            layout.stride.is_multiple_of(4),
            "stage-in strides are multiples of four",
        )?;
        ensure(
            layout.step_function == StageInStep::Constant || layout.step_rate >= 1,
            "stage-in step rates are nonzero",
        )?;
        indexed |= layout.step_function.indexed();
    }
    if indexed {
        ensure(
            descriptor.index_buffer_index < MAX_BUFFER_BINDINGS
                && descriptor
                    .layouts
                    .iter()
                    .all(|layout| layout.buffer_index != descriptor.index_buffer_index),
            "the stage-in index buffer has its own slot",
        )?;
    }
    for attribute in &descriptor.attributes {
        ensure(
            descriptor
                .attributes
                .iter()
                .filter(|other| other.index == attribute.index)
                .count()
                == 1,
            "stage-in attributes are unique",
        )?;
        ensure(
            attribute.offset.is_multiple_of(4),
            "stage-in attribute offsets are multiples of four",
        )?;
        let layout = descriptor
            .layouts
            .iter()
            .find(|layout| layout.buffer_index == attribute.buffer_index)
            .ok_or(Error::Invalid("stage-in attribute names no buffer layout"))?;
        if layout.step_function != StageInStep::Constant {
            ensure(
                attribute.offset + attribute.format.vulkan().1 <= layout.stride,
                "stage-in attribute extends past its stride",
            )?;
        }
    }
    Ok(())
}

/// Lowers a vertex function's stage-in layout to fixed-function vertex
/// input.
pub fn vertex_input(
    capabilities: &Capabilities,
    descriptor: &VertexDescriptor,
) -> Result<VertexInput> {
    validate(capabilities, descriptor)?;
    let limits = &capabilities.limits;
    let mut input = VertexInput::default();
    for layout in &descriptor.layouts {
        let (input_rate, divisor) = match layout.step_function {
            StepFunction::PerVertex => {
                ensure(layout.stride != 0, "per-vertex layouts have a stride")?;
                (VertexInputRate::Vertex, 1)
            }
            StepFunction::PerInstance => {
                require(
                    layout.step_rate <= limits.max_vertex_step_rate,
                    "per-instance step rate",
                )?;
                (VertexInputRate::Instance, layout.step_rate as u32)
            }
            // Instance rate with divisor zero fetches element zero for every
            // vertex and instance.
            StepFunction::Constant => {
                require(
                    capabilities.constant_vertex_step,
                    "constant vertex step function",
                )?;
                (VertexInputRate::Instance, 0)
            }
            StepFunction::PerPatch | StepFunction::PerPatchControlPoint => {
                return Err(Error::Invalid(
                    "patch step functions need a post-tessellation vertex function",
                ));
            }
        };
        input.bindings.push(VertexBinding {
            binding: layout.buffer_index,
            input_rate,
            divisor,
            stride: (layout.stride != STRIDE_DYNAMIC).then_some(layout.stride as u32),
        });
    }
    for attribute in &descriptor.attributes {
        require(
            capabilities.supports_vertex_format(attribute.format),
            "vertex attribute format",
        )?;
        input.attributes.push(VertexAttribute {
            location: attribute.index,
            binding: attribute.buffer_index,
            format: attribute.format.vulkan().0,
            offset: attribute.offset as u32,
        });
    }
    Ok(input)
}

/// Validates the stage-in layout of a post-tessellation vertex function,
/// whose evaluation stage fetches it from the bound buffers.
pub fn patch_input(capabilities: &Capabilities, descriptor: &VertexDescriptor) -> Result<()> {
    validate(capabilities, descriptor)?;
    for layout in &descriptor.layouts {
        ensure(
            layout.step_function != StepFunction::PerVertex,
            "post-tessellation layouts step per patch, control point or instance",
        )?;
        if layout.step_function == StepFunction::PerPatch {
            ensure(layout.step_rate >= 1, "per-patch step rates are nonzero")?;
        }
    }
    Ok(())
}

/// The rules every stage-in layout follows, however it is fetched.
fn validate(capabilities: &Capabilities, descriptor: &VertexDescriptor) -> Result<()> {
    let limits = &capabilities.limits;
    for layout in &descriptor.layouts {
        ensure(
            layout.buffer_index < MAX_BUFFER_BINDINGS,
            "vertex buffer index exceeds the argument table",
        )?;
        ensure(
            descriptor
                .layouts
                .iter()
                .filter(|other| other.buffer_index == layout.buffer_index)
                .count()
                == 1,
            "vertex buffer layouts are unique",
        )?;
        if layout.stride != STRIDE_DYNAMIC {
            ensure(
                layout.stride.is_multiple_of(4),
                "vertex strides are multiples of four",
            )?;
            require(
                layout.stride <= limits.max_vertex_buffer_stride,
                "vertex buffer stride",
            )?;
        }
        if layout.step_function == StepFunction::PerInstance {
            ensure(layout.step_rate >= 1, "per-instance step rates are nonzero")?;
        }
    }
    for attribute in &descriptor.attributes {
        ensure(
            attribute.index < MAX_VERTEX_ATTRIBUTES,
            "vertex attribute index exceeds the limit",
        )?;
        ensure(
            descriptor
                .attributes
                .iter()
                .filter(|other| other.index == attribute.index)
                .count()
                == 1,
            "vertex attributes are unique",
        )?;
        ensure(
            attribute.offset.is_multiple_of(4),
            "vertex attribute offsets are multiples of four",
        )?;
        let layout = descriptor
            .layouts
            .iter()
            .find(|layout| layout.buffer_index == attribute.buffer_index)
            .ok_or(Error::Invalid("vertex attribute names no buffer layout"))?;
        let bytes = attribute.format.vulkan().1;
        if layout.stride != STRIDE_DYNAMIC && layout.step_function != StepFunction::Constant {
            ensure(
                attribute.offset + bytes <= layout.stride,
                "vertex attribute extends past its stride",
            )?;
        }
        require(
            attribute.offset <= limits.max_vertex_attribute_offset,
            "vertex attribute offset",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpu::metal::nvidia::fixture::capabilities;

    fn layout(
        buffer_index: u32,
        stride: u64,
        step_function: StepFunction,
        step_rate: u64,
    ) -> Layout {
        Layout {
            buffer_index,
            stride,
            step_function,
            step_rate,
        }
    }

    fn attribute(index: u32, format: VertexFormat, offset: u64, buffer_index: u32) -> Attribute {
        Attribute {
            index,
            format,
            offset,
            buffer_index,
        }
    }

    #[test]
    fn every_vertex_format_has_a_vulkan_equivalent_of_its_size() {
        for format in VertexFormat::ALL {
            let (_, bytes) = format.vulkan();
            assert!((1..=16).contains(&bytes), "{format:?}");
        }
        assert_eq!(VertexFormat::from_raw(43), None);
        assert_eq!(
            VertexFormat::UChar4NormalizedBgra.vulkan().0,
            Format::B8G8R8A8Unorm
        );
    }

    #[test]
    fn interleaved_instanced_and_constant_layouts() {
        let descriptor = VertexDescriptor {
            attributes: alloc::vec![
                attribute(0, VertexFormat::Float3, 0, 0),
                attribute(1, VertexFormat::Half2, 12, 0),
                attribute(2, VertexFormat::UChar4Normalized, 0, 1),
                attribute(3, VertexFormat::Float4, 0, 2),
            ],
            layouts: alloc::vec![
                layout(0, 16, StepFunction::PerVertex, 1),
                layout(1, 4, StepFunction::PerInstance, 3),
                layout(2, 0, StepFunction::Constant, 0),
            ],
        };
        let input = vertex_input(&capabilities(), &descriptor).unwrap();
        assert_eq!(
            input.bindings,
            [
                VertexBinding {
                    binding: 0,
                    input_rate: VertexInputRate::Vertex,
                    divisor: 1,
                    stride: Some(16)
                },
                VertexBinding {
                    binding: 1,
                    input_rate: VertexInputRate::Instance,
                    divisor: 3,
                    stride: Some(4)
                },
                VertexBinding {
                    binding: 2,
                    input_rate: VertexInputRate::Instance,
                    divisor: 0,
                    stride: Some(0)
                },
            ]
        );
        assert_eq!(
            input.attributes[1],
            VertexAttribute {
                location: 1,
                binding: 0,
                format: Format::R16G16Sfloat,
                offset: 12
            }
        );
    }

    #[test]
    fn dynamic_strides_are_bound_with_the_buffer() {
        let descriptor = VertexDescriptor {
            attributes: alloc::vec![attribute(0, VertexFormat::Float4, 64, 5)],
            layouts: alloc::vec![layout(5, STRIDE_DYNAMIC, StepFunction::PerVertex, 1)],
        };
        let input = vertex_input(&capabilities(), &descriptor).unwrap();
        assert_eq!(input.bindings[0].stride, None);
    }

    #[test]
    fn patch_layouts_belong_to_post_tessellation_functions() {
        let patch = VertexDescriptor {
            attributes: alloc::vec![attribute(0, VertexFormat::Float4, 0, 0)],
            layouts: alloc::vec![layout(0, 16, StepFunction::PerPatchControlPoint, 1)],
        };
        assert!(matches!(
            vertex_input(&capabilities(), &patch),
            Err(Error::Invalid(_))
        ));
        assert_eq!(patch_input(&capabilities(), &patch), Ok(()));
        let per_vertex = VertexDescriptor {
            layouts: alloc::vec![layout(0, 16, StepFunction::PerVertex, 1)],
            ..patch
        };
        assert!(matches!(
            patch_input(&capabilities(), &per_vertex),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn malformed_layouts_are_refused() {
        let check = |attributes: Vec<Attribute>, layouts: Vec<Layout>| {
            vertex_input(
                &capabilities(),
                &VertexDescriptor {
                    attributes,
                    layouts,
                },
            )
        };
        let per_vertex = layout(0, 16, StepFunction::PerVertex, 1);
        assert!(matches!(
            check(
                alloc::vec![attribute(0, VertexFormat::Float4, 4, 0)],
                alloc::vec![per_vertex]
            ),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            check(
                alloc::vec![attribute(0, VertexFormat::Float, 2, 0)],
                alloc::vec![per_vertex]
            ),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            check(
                alloc::vec![attribute(0, VertexFormat::Float, 0, 1)],
                alloc::vec![per_vertex]
            ),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            check(
                alloc::vec![],
                alloc::vec![layout(0, 0, StepFunction::PerVertex, 1)]
            ),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            check(
                alloc::vec![],
                alloc::vec![layout(0, 18, StepFunction::PerVertex, 1)]
            ),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            check(
                alloc::vec![],
                alloc::vec![layout(31, 16, StepFunction::PerVertex, 1)]
            ),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            check(
                alloc::vec![],
                alloc::vec![layout(0, 16, StepFunction::PerInstance, 0)]
            ),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            check(alloc::vec![], alloc::vec![per_vertex, per_vertex]),
            Err(Error::Invalid(_))
        ));
        assert_eq!(
            check(
                alloc::vec![],
                alloc::vec![layout(0, 4096, StepFunction::PerVertex, 1)]
            ),
            Err(Error::Unsupported("vertex buffer stride"))
        );
        let far = layout(0, STRIDE_DYNAMIC, StepFunction::PerVertex, 1);
        assert_eq!(
            check(
                alloc::vec![attribute(0, VertexFormat::Float, 4096, 0)],
                alloc::vec![far]
            ),
            Err(Error::Unsupported("vertex attribute offset"))
        );
        assert_eq!(
            check(
                alloc::vec![attribute(0, VertexFormat::FloatRgb9E5, 0, 0)],
                alloc::vec![per_vertex]
            ),
            Err(Error::Unsupported("vertex attribute format"))
        );
    }
}
