use super::{Memory, call, connect, new_function, new_library, service, status};
use crate::metal::{
    abi::{DataType, TextureType},
    reflection::{BindingAccess, BindingType},
    service::{
        GuestMemory,
        wire::{
            self, ArgumentLayoutRequest, ArgumentLayoutResponse, ArgumentRecord, BindingInfo,
            FunctionBindingsRequest, FunctionBindingsResponse, MemberInfo, NO_TYPE, Operation,
            Status, TypeInfo,
        },
    },
};
use alloc::vec::Vec;
use core::mem::size_of;

#[test]
fn bindings_flatten_their_types_before_them() {
    let mut service = service();
    let connection = connect(&mut service);
    let memory = &mut Memory::default();
    let library = new_library(&mut service, connection, memory);
    let function = new_function(&mut service, connection, library, "kernel", &[], memory)
        .unwrap()
        .handle;
    let out = memory.put(&alloc::vec![0; 4096]);
    let response: FunctionBindingsResponse = call(
        &mut service,
        connection,
        Operation::FunctionBindings,
        &FunctionBindingsRequest { function, out },
        memory,
    )
    .unwrap();
    // The device fixture's uniforms, argument buffer and sampler.
    let (bindings, types, members) = (3, 8, 6);
    assert_eq!(
        (
            response.binding_count,
            response.type_count,
            response.member_count
        ),
        (bindings, types, members)
    );
    let data = memory.read(out).unwrap();
    let mut at = 0;
    let mut records = |count: u32, size: usize| {
        let records = &data[at..at + count as usize * size];
        at += records.len();
        records
    };
    let bindings: Vec<BindingInfo> =
        wire::read_array(records(bindings, size_of::<BindingInfo>())).unwrap();
    let types: Vec<TypeInfo> = wire::read_array(records(types, size_of::<TypeInfo>())).unwrap();
    let members: Vec<MemberInfo> =
        wire::read_array(records(members, size_of::<MemberInfo>())).unwrap();
    let name = |offset: u32, length: u32| &data[offset as usize..(offset + length) as usize];
    // The guest builds each type from earlier ones: an element precedes its
    // type, and a structure or texture has none.
    for (index, ty) in types.iter().enumerate() {
        let leaf = [DataType::Struct.raw(), DataType::Texture.raw()].contains(&ty.data_type);
        assert!(
            if leaf {
                ty.element == NO_TYPE
            } else {
                ty.element == NO_TYPE || (ty.element as usize) < index
            },
            "type {index}: {ty:?}"
        );
    }

    // The uniforms' pointer, whose structure holds the inlined array.
    let uniforms = bindings[0];
    assert_eq!(name(uniforms.name, uniforms.name_length), b"u");
    let pointer = types[uniforms.ty as usize];
    assert_eq!(
        (
            pointer.data_type,
            pointer.element_data_type,
            pointer.alignment,
            pointer.data_size
        ),
        (DataType::Pointer.raw(), DataType::Struct.raw(), 16, 96)
    );
    // The binding sizes and aligns as its pointee, as an encoder of it does.
    assert_eq!((uniforms.alignment, uniforms.data_size), (16, 96));
    let structure = types[pointer.element as usize];
    assert_eq!(
        (structure.member_count, structure.data_type),
        (2, DataType::Struct.raw())
    );
    let inner = members[structure.first_member as usize + 1];
    assert_eq!(name(inner.name, inner.name_length), b"inner");
    assert_eq!((inner.offset, inner.data_type), (64, DataType::Array.raw()));
    let array = types[inner.ty as usize];
    assert_eq!(
        (array.length, array.stride, array.element_data_type),
        (2, 16, DataType::Struct.raw())
    );
    let uv = members[types[array.element as usize].first_member as usize];
    assert_eq!((uv.data_type, uv.ty), (DataType::Float2.raw(), NO_TYPE));

    // The argument buffer's texture and buffer.
    let arguments = types[bindings[1].ty as usize];
    assert_eq!(arguments.element_is_argument_buffer, 1);
    let first = types[arguments.element as usize].first_member as usize;
    let texture = types[members[first].ty as usize];
    assert_eq!(
        (
            texture.data_type,
            texture.element_data_type,
            texture.texture_type
        ),
        (
            DataType::Texture.raw(),
            DataType::Float.raw(),
            TextureType::D2.raw() as u32
        )
    );
    let buffer = members[first + 1];
    assert_eq!(
        (buffer.argument_index, buffer.data_type),
        (1, DataType::Pointer.raw())
    );
    assert_eq!(
        types[buffer.ty as usize].access,
        BindingAccess::ReadWrite.raw() as u32
    );

    let sampler = bindings[2];
    assert_eq!(
        (
            sampler.binding_type,
            sampler.array_length,
            sampler.used,
            sampler.ty
        ),
        (BindingType::Sampler.raw() as u32, 1, 0, NO_TYPE)
    );
    assert_eq!(at + 19, response.length as usize, "the names follow");
}

#[test]
fn argument_descriptors_answer_their_layout() {
    let mut service = service();
    let connection = connect(&mut service);
    let memory = &mut Memory::default();
    let record = |data_type: DataType, index, array_length| ArgumentRecord {
        data_type: data_type.raw(),
        index,
        array_length,
        ..ArgumentRecord::default()
    };
    let records = [
        record(DataType::Float4, 2, 0),
        record(DataType::Texture, 0, 2),
    ];
    let arguments = memory.records(&records);
    let out = memory.put(&[0; 8]);
    let response: ArgumentLayoutResponse = call(
        &mut service,
        connection,
        Operation::ArgumentLayout,
        &ArgumentLayoutRequest { arguments, out },
        memory,
    )
    .unwrap();
    assert_eq!(
        (response.encoded_length, response.alignment, response.length),
        (32, 16, 8)
    );
    assert_eq!(memory.read(out).unwrap(), [16, 0, 0, 0, 0, 0, 0, 0]);

    let unknown = ArgumentLayoutRequest {
        arguments: memory.records(&[ArgumentRecord {
            data_type: 1000,
            ..records[0]
        }]),
        out,
    };
    assert_eq!(
        status(call::<_, ArgumentLayoutResponse>(
            &mut service,
            connection,
            Operation::ArgumentLayout,
            &unknown,
            memory,
        )),
        Status::Malformed
    );
}

#[test]
fn a_buffer_of_scalars_reflects_a_structure_of_one_member() {
    use crate::metal::{
        reflection::{Binding, BindingKind, PointerType, StructMember, StructType, Type},
        service::reflection::as_metal_reflects,
    };
    use alloc::{boxed::Box, string::String, vec};
    let buffer = |element: Type| Binding {
        name: String::from("count"),
        index: 2,
        access: BindingAccess::ReadWrite,
        used: true,
        kind: BindingKind::Buffer(PointerType {
            element: Box::new(element),
            access: BindingAccess::ReadWrite,
            alignment: 4,
            data_size: 4,
            element_is_argument_buffer: false,
        }),
    };
    let BindingKind::Buffer(pointer) = as_metal_reflects(buffer(Type::Data(DataType::UInt))).kind
    else {
        unreachable!()
    };
    assert_eq!(
        *pointer.element,
        Type::Struct(StructType {
            members: vec![StructMember {
                name: String::from("__s"),
                offset: 0,
                ty: Type::Data(DataType::UInt),
                argument_index: 0,
            }],
        })
    );
    // A structure stays as it is.
    let structure = Type::Struct(StructType { members: vec![] });
    assert_eq!(
        as_metal_reflects(buffer(structure.clone())),
        buffer(structure)
    );
}
