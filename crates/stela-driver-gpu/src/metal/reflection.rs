//! Binding reflection: a function's `MTLBinding`s and the `MTLType`s of the
//! structures, arrays, pointers and textures they reach, which
//! `MTLPipelineOptionBindingInfo` reflects and argument encoders lay out
//! their buffers by.
use super::abi::{DataType, TextureType};
use alloc::{boxed::Box, string::String, vec::Vec};

raw_enum! {
    /// `MTLBindingAccess`.
    pub enum BindingAccess: u64 {
        ReadOnly = 0,
        ReadWrite = 1,
        WriteOnly = 2,
    }
}

raw_enum! {
    /// `MTLBindingType`.
    pub enum BindingType: u64 {
        Buffer = 0,
        ThreadgroupMemory = 1,
        Texture = 2,
        Sampler = 3,
        VisibleFunctionTable = 24,
        ObjectPayload = 34,
    }
}

/// A function argument's `MTLBinding`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Binding {
    pub name: String,
    pub index: u32,
    pub access: BindingAccess,
    /// The function reads or writes the binding.
    pub used: bool,
    pub kind: BindingKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BindingKind {
    /// `MTLBufferBinding`, the buffer's pointer type: its pointee's data
    /// type, size and alignment, and whether it is an argument buffer.
    Buffer(PointerType),
    /// `MTLThreadgroupBinding`.
    Threadgroup {
        alignment: u32,
        data_size: u32,
    },
    /// `MTLTextureBinding`.
    Texture {
        texture: TextureReferenceType,
        array_length: u32,
    },
    Sampler {
        array_length: u32,
    },
    VisibleFunctionTable,
    /// `MTLObjectPayloadBinding`.
    ObjectPayload {
        alignment: u32,
        data_size: u32,
    },
}

impl BindingKind {
    pub const fn binding_type(&self) -> BindingType {
        match self {
            Self::Buffer(_) => BindingType::Buffer,
            Self::Threadgroup { .. } => BindingType::ThreadgroupMemory,
            Self::Texture { .. } => BindingType::Texture,
            Self::Sampler { .. } => BindingType::Sampler,
            Self::VisibleFunctionTable => BindingType::VisibleFunctionTable,
            Self::ObjectPayload { .. } => BindingType::ObjectPayload,
        }
    }
}

/// The `MTLType` of a structure member, an array element or a pointee.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Type {
    /// A scalar, vector, matrix, sampler, indirect command buffer or
    /// pipeline state.
    Data(DataType),
    Struct(StructType),
    Array(ArrayType),
    Pointer(PointerType),
    Texture(TextureReferenceType),
}

impl Type {
    pub fn data_type(&self) -> DataType {
        match self {
            Self::Data(data_type) => *data_type,
            Self::Struct(_) => DataType::Struct,
            Self::Array(_) => DataType::Array,
            Self::Pointer(_) => DataType::Pointer,
            Self::Texture(_) => DataType::Texture,
        }
    }

    /// The argument buffer `[[id]]`s a value of the type takes: one per
    /// resource or datum.
    pub fn id_span(&self) -> u32 {
        match self {
            Self::Struct(structure) => structure
                .members
                .iter()
                .map(|member| member.argument_index + member.ty.id_span())
                .max()
                .unwrap_or(0),
            Self::Array(array) => array.length * array.argument_index_stride,
            Self::Data(_) | Self::Pointer(_) | Self::Texture(_) => 1,
        }
    }
}

/// `MTLStructType`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StructType {
    pub members: Vec<StructMember>,
}

/// `MTLStructMember`; an argument buffer's member's `argumentIndex` is
/// its `[[id]]`, counted from its structure's.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructMember {
    pub name: String,
    pub offset: u32,
    pub ty: Type,
    pub argument_index: u32,
}

/// `MTLArrayType`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArrayType {
    pub element: Box<Type>,
    pub length: u32,
    pub stride: u32,
    /// `[[id]]`s per element, in argument buffers.
    pub argument_index_stride: u32,
}

/// `MTLPointerType`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PointerType {
    pub element: Box<Type>,
    pub access: BindingAccess,
    pub alignment: u32,
    pub data_size: u32,
    pub element_is_argument_buffer: bool,
}

/// `MTLTextureReferenceType`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TextureReferenceType {
    /// The component type.
    pub data_type: DataType,
    pub texture_type: TextureType,
    pub access: BindingAccess,
    pub depth: bool,
}
