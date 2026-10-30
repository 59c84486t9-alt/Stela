//! Binding reflection: a function's bindings, flattened into records that
//! name the types they reach by index, and argument buffer layouts.
use super::{
    Call, Service,
    libraries::Names,
    wire::{
        self, ArgumentLayoutRequest, ArgumentLayoutResponse, ArgumentRecord, BindingInfo, Fault,
        FunctionBindingsRequest, FunctionBindingsResponse, MemberInfo, NO_TYPE, TypeInfo,
    },
};
use crate::gpu::metal::{
    abi::DataType,
    argument::{self, ArgumentDescriptor},
    device::FunctionId,
    reflection::{Binding, BindingKind, PointerType, StructType, TextureReferenceType, Type},
    shader::Compiler,
    vulkan::backend::Backend,
};
use alloc::vec::Vec;
use core::mem::size_of;

impl<B: Backend, C: Compiler> Service<B, C> {
    pub(super) fn function_bindings(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: FunctionBindingsRequest = call.request()?;
        let function = self.object::<FunctionId>(call.connection, request.function)?;
        let bindings = self.device.function_bindings(function)?;
        // Records first, then the names they point into.
        let (types, members) = bindings.iter().fold((0, 0), |(types, members), binding| {
            let (more_types, more_members) = binding_counts(binding);
            (types + more_types, members + more_members)
        });
        let mut flat = Flat {
            types: Vec::with_capacity(types),
            members: Vec::with_capacity(members),
            names: Names {
                base: bindings.len() * size_of::<BindingInfo>()
                    + types * size_of::<TypeInfo>()
                    + members * size_of::<MemberInfo>(),
                bytes: Vec::new(),
            },
        };
        let records = bindings
            .iter()
            .map(|binding| flat.binding(binding))
            .collect::<Result<Vec<_>, Fault>>()?;
        let mut data = Vec::with_capacity(flat.names.base);
        records
            .iter()
            .for_each(|record| data.extend_from_slice(wire::bytes(record)));
        flat.types
            .iter()
            .for_each(|record| data.extend_from_slice(wire::bytes(record)));
        flat.members
            .iter()
            .for_each(|record| data.extend_from_slice(wire::bytes(record)));
        data.extend_from_slice(&flat.names.bytes);
        let response = FunctionBindingsResponse {
            binding_count: records.len() as u32,
            type_count: flat.types.len() as u32,
            member_count: flat.members.len() as u32,
            reserved: 0,
            length: data.len() as u64,
        };
        call.write_fitting(request.out, &data)?;
        call.reply(&response)
    }
}

pub(super) fn argument_layout(call: &mut Call) -> Result<(), Fault> {
    let request: ArgumentLayoutRequest = call.request()?;
    let arguments = wire::read_array::<ArgumentRecord>(call.memory.read(request.arguments)?)?
        .into_iter()
        .map(|record| {
            Ok(ArgumentDescriptor {
                data_type: DataType::from_raw(record.data_type)
                    .ok_or(Fault::malformed("argument data type"))?,
                index: record.index,
                array_length: record.array_length,
                constant_block_alignment: record.constant_block_alignment,
            })
        })
        .collect::<Result<Vec<_>, Fault>>()?;
    let layout = argument::layout(&arguments)?;
    let offsets: Vec<u8> = layout
        .offsets
        .iter()
        .flat_map(|offset| offset.to_le_bytes())
        .collect();
    call.write_fitting(request.out, &offsets)?;
    call.reply(&ArgumentLayoutResponse {
        encoded_length: layout.encoded_length,
        alignment: layout.alignment,
        length: offsets.len() as u64,
    })
}

/// The `TypeInfo`s and `MemberInfo`s a binding reaches.
fn binding_counts(binding: &Binding) -> (usize, usize) {
    match &binding.kind {
        BindingKind::Buffer(pointer) => pointer_counts(pointer),
        BindingKind::Texture { .. } => (1, 0),
        _ => (0, 0),
    }
}

fn pointer_counts(pointer: &PointerType) -> (usize, usize) {
    let (types, members) = counts(&pointer.element);
    (types + 1, members)
}

fn counts(ty: &Type) -> (usize, usize) {
    match ty {
        Type::Data(_) => (0, 0),
        Type::Struct(structure) => structure.members.iter().fold(
            (1, structure.members.len()),
            |(types, members), member| {
                let (more_types, more_members) = counts(&member.ty);
                (types + more_types, members + more_members)
            },
        ),
        Type::Array(array) => {
            let (types, members) = counts(&array.element);
            (types + 1, members)
        }
        Type::Pointer(pointer) => pointer_counts(pointer),
        Type::Texture(_) => (1, 0),
    }
}

/// Types and members flattened so far: a type's element and members come
/// before it, and each structure's members are contiguous.
struct Flat {
    types: Vec<TypeInfo>,
    members: Vec<MemberInfo>,
    names: Names,
}

impl Flat {
    fn binding(&mut self, binding: &Binding) -> Result<BindingInfo, Fault> {
        let (name, name_length) = self.names.add(&binding.name)?;
        let mut record = BindingInfo {
            name,
            name_length,
            binding_type: binding.kind.binding_type().raw() as u32,
            access: binding.access.raw() as u32,
            index: binding.index,
            used: binding.used.into(),
            array_length: 0,
            alignment: 0,
            data_size: 0,
            ty: NO_TYPE,
        };
        match &binding.kind {
            BindingKind::Buffer(pointer) => record.ty = self.pointer(pointer)?,
            BindingKind::Texture {
                texture,
                array_length,
            } => {
                record.ty = self.texture(texture);
                record.array_length = *array_length;
            }
            BindingKind::Sampler { array_length } => record.array_length = *array_length,
            BindingKind::Threadgroup {
                alignment,
                data_size,
            }
            | BindingKind::ObjectPayload {
                alignment,
                data_size,
            } => {
                record.alignment = *alignment;
                record.data_size = *data_size;
            }
            BindingKind::VisibleFunctionTable => {}
        }
        Ok(record)
    }

    /// The index of `ty`'s `TypeInfo`, or `NO_TYPE` for a datum.
    fn ty(&mut self, ty: &Type) -> Result<u32, Fault> {
        match ty {
            Type::Data(_) => Ok(NO_TYPE),
            Type::Struct(structure) => self.structure(structure),
            Type::Array(array) => {
                let element = self.ty(&array.element)?;
                Ok(self.push(TypeInfo {
                    data_type: ty.data_type().raw(),
                    element_data_type: array.element.data_type().raw(),
                    element,
                    length: array.length,
                    stride: array.stride,
                    argument_index_stride: array.argument_index_stride,
                    ..TypeInfo::default()
                }))
            }
            Type::Pointer(pointer) => self.pointer(pointer),
            Type::Texture(texture) => Ok(self.texture(texture)),
        }
    }

    fn structure(&mut self, structure: &StructType) -> Result<u32, Fault> {
        let records = structure
            .members
            .iter()
            .map(|member| {
                let (name, name_length) = self.names.add(&member.name)?;
                Ok(MemberInfo {
                    name,
                    name_length,
                    data_type: member.ty.data_type().raw(),
                    offset: member.offset,
                    argument_index: member.argument_index,
                    ty: self.ty(&member.ty)?,
                    reserved: 0,
                })
            })
            .collect::<Result<Vec<_>, Fault>>()?;
        let first_member = self.members.len() as u32;
        self.members.extend(records);
        Ok(self.push(TypeInfo {
            data_type: DataType::Struct.raw(),
            first_member,
            member_count: structure.members.len() as u32,
            ..TypeInfo::default()
        }))
    }

    fn pointer(&mut self, pointer: &PointerType) -> Result<u32, Fault> {
        let element = self.ty(&pointer.element)?;
        Ok(self.push(TypeInfo {
            data_type: DataType::Pointer.raw(),
            element_data_type: pointer.element.data_type().raw(),
            element,
            access: pointer.access.raw() as u32,
            alignment: pointer.alignment,
            data_size: pointer.data_size,
            element_is_argument_buffer: pointer.element_is_argument_buffer.into(),
            ..TypeInfo::default()
        }))
    }

    fn texture(&mut self, texture: &TextureReferenceType) -> u32 {
        self.push(TypeInfo {
            data_type: DataType::Texture.raw(),
            element_data_type: texture.data_type.raw(),
            access: texture.access.raw() as u32,
            texture_type: texture.texture_type.raw() as u32,
            depth: texture.depth.into(),
            ..TypeInfo::default()
        })
    }

    fn push(&mut self, record: TypeInfo) -> u32 {
        self.types.push(record);
        self.types.len() as u32 - 1
    }
}
