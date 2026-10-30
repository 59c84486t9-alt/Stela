//! The service's binding reflection as [`Binding`]s: each binding and
//! member's MSL type spelling becomes its `MTLDataType`, and its structure,
//! the rows its range names, its `MTLStructType`.
use super::{MALFORMED, ffi, scalar, texture_type};
use crate::metal::{
    abi::DataType,
    error::{Error, Result},
    reflection::{
        ArrayType, Binding, BindingAccess, BindingKind, PointerType, StructMember, StructType,
        TextureReferenceType, Type,
    },
};
use alloc::{boxed::Box, string::String, vec::Vec};
use core::str;

/// Bytes of a resource in an argument buffer: its address or ID.
const RESOURCE_BYTES: u32 = 8;

pub(super) fn bindings(raw: &ffi::Bindings) -> Result<Vec<Binding>> {
    if raw.member_count as usize > ffi::MEMBERS {
        return Err(MALFORMED);
    }
    let reader = Reader { raw };
    raw.bindings
        .get(..raw.binding_count as usize)
        .ok_or(MALFORMED)?
        .iter()
        .map(|binding| reader.binding(binding))
        .collect()
}

struct Reader<'a> {
    raw: &'a ffi::Bindings,
}

impl Reader<'_> {
    fn binding(&self, row: &ffi::Binding) -> Result<Binding> {
        let access = access(row.access)?;
        let kind = match row.kind {
            ffi::binding::BUFFER => BindingKind::Buffer(PointerType {
                element: Box::new(self.value(
                    row.type_name,
                    row.type_bytes,
                    row.members,
                    row.member_count,
                    0,
                )?),
                access,
                alignment: row.alignment,
                data_size: row.size,
                element_is_argument_buffer: row.argument_buffer != 0,
            }),
            ffi::binding::THREADGROUP => BindingKind::Threadgroup {
                alignment: row.alignment,
                data_size: row.size,
            },
            ffi::binding::TEXTURE => BindingKind::Texture {
                texture: texture(row.texture_type, row.primitive, row.depth, access)?,
                array_length: row.count,
            },
            ffi::binding::SAMPLER => BindingKind::Sampler {
                array_length: row.count,
            },
            ffi::binding::FUNCTION_TABLE => BindingKind::VisibleFunctionTable,
            ffi::binding::OBJECT_PAYLOAD => BindingKind::ObjectPayload {
                alignment: row.alignment,
                data_size: row.size,
            },
            _ => return Err(MALFORMED),
        };
        Ok(Binding {
            name: self.text(row.name, row.name_bytes)?,
            index: row.index,
            access,
            used: row.used != 0,
            kind,
        })
    }

    /// A structure's members: rows `[first, first + count)`, which follow
    /// row `after` when a member row names them.
    fn structure(&self, first: u32, count: u32, after: u32) -> Result<StructType> {
        let end = first.checked_add(count).ok_or(MALFORMED)?;
        if first < after || end > self.raw.member_count {
            return Err(MALFORMED);
        }
        let members = (first..end)
            .map(|index| self.member(index))
            .collect::<Result<_>>()?;
        Ok(StructType { members })
    }

    /// What a pointer points to, or a datum is: the structure its members
    /// make, or the type its spelling names.
    fn value(&self, name: u32, bytes: u32, first: u32, count: u32, after: u32) -> Result<Type> {
        if count != 0 {
            return Ok(Type::Struct(self.structure(first, count, after)?));
        }
        DataType::from_spelling(self.bytes(name, bytes)?)
            .map(Type::Data)
            .ok_or(Error::Unsupported("reflected type"))
    }

    fn member(&self, index: u32) -> Result<StructMember> {
        let row = &self.raw.members[index as usize];
        let next = index + 1;
        let data = row.argument == 0 || row.kind == ffi::field::DATA;
        let element = if data {
            self.value(
                row.type_name,
                row.type_bytes,
                row.members,
                row.member_count,
                next,
            )?
        } else {
            let access = access(row.access)?;
            match row.kind {
                ffi::field::BUFFER | ffi::field::ARGUMENTS => Type::Pointer(PointerType {
                    element: Box::new(self.value(
                        row.type_name,
                        row.type_bytes,
                        row.members,
                        row.member_count,
                        next,
                    )?),
                    access,
                    alignment: row.alignment_pointed,
                    data_size: row.size_pointed,
                    element_is_argument_buffer: row.kind == ffi::field::ARGUMENTS,
                }),
                ffi::field::TEXTURE => {
                    Type::Texture(texture(row.texture_type, row.primitive, row.depth, access)?)
                }
                ffi::field::SAMPLER => Type::Data(DataType::Sampler),
                ffi::field::COMMANDS => Type::Data(DataType::IndirectCommandBuffer),
                ffi::field::RENDER_PIPELINE => Type::Data(DataType::RenderPipeline),
                ffi::field::COMPUTE_PIPELINE => Type::Data(DataType::ComputePipeline),
                _ => return Err(MALFORMED),
            }
        };
        // An array of resources takes one [[id]] and one address or ID per
        // element; an array of data, its elements' [[id]]s.
        let ty = if !data && row.count > 1 {
            Type::Array(ArrayType {
                element: Box::new(element),
                length: row.count,
                stride: RESOURCE_BYTES,
                argument_index_stride: 1,
            })
        } else if row.elements > 0 {
            let argument_index_stride = if row.argument != 0 {
                element.id_span()
            } else {
                0
            };
            Type::Array(ArrayType {
                element: Box::new(element),
                length: row.elements,
                stride: row.size,
                argument_index_stride,
            })
        } else {
            element
        };
        Ok(StructMember {
            name: self.text(row.name, row.name_bytes)?,
            offset: row.offset,
            ty,
            argument_index: row.id,
        })
    }

    fn bytes(&self, offset: u32, bytes: u32) -> Result<&[u8]> {
        let end = offset.checked_add(bytes).ok_or(MALFORMED)?;
        if end > self.raw.names_bytes {
            return Err(MALFORMED);
        }
        self.raw
            .names
            .get(offset as usize..end as usize)
            .ok_or(MALFORMED)
    }

    fn text(&self, offset: u32, bytes: u32) -> Result<String> {
        let text = str::from_utf8(self.bytes(offset, bytes)?).map_err(|_| MALFORMED)?;
        Ok(String::from(text))
    }
}

/// `STELA_METAL_ACCESS_*` flags as `MTLBindingAccess`.
fn access(bits: u32) -> Result<BindingAccess> {
    const READ: u32 = 1;
    const WRITE: u32 = 2;
    const SAMPLE: u32 = 4;
    Ok(match bits {
        0 | READ | SAMPLE => BindingAccess::ReadOnly,
        WRITE => BindingAccess::WriteOnly,
        _ if bits == READ | WRITE => BindingAccess::ReadWrite,
        _ => return Err(MALFORMED),
    })
}

fn texture(
    texture: u32,
    primitive: u32,
    depth: u32,
    access: BindingAccess,
) -> Result<TextureReferenceType> {
    Ok(TextureReferenceType {
        data_type: scalar(primitive)?.data_type(),
        texture_type: texture_type(texture)?,
        access,
        depth: depth != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metal::abi::TextureType;
    use alloc::vec;
    use ffi::{binding, field, primitive::FLOAT};

    const READ: u32 = 1;
    const READ_WRITE: u32 = 3;
    const SAMPLE: u32 = 4;
    /// `STELA_AIR_TEXTURE_2D`.
    const TEXTURE_2D: u32 = 3;

    /// Bindings the service wrote, with names added as rows are.
    struct Written(Box<ffi::Bindings>);

    impl Written {
        fn name(&mut self, text: &str) -> (u32, u32) {
            let raw = &mut self.0;
            let at = raw.names_bytes as usize;
            raw.names[at..at + text.len()].copy_from_slice(text.as_bytes());
            raw.names_bytes += text.len() as u32;
            (at as u32, text.len() as u32)
        }

        fn binding(&mut self, name: &str, ty: &str, row: ffi::Binding) {
            let (name, name_bytes) = self.name(name);
            let (type_name, type_bytes) = self.name(ty);
            let raw = &mut self.0;
            raw.bindings[raw.binding_count as usize] = ffi::Binding {
                name,
                name_bytes,
                type_name,
                type_bytes,
                ..row
            };
            raw.binding_count += 1;
        }

        fn member(&mut self, name: &str, ty: &str, row: ffi::Member) {
            let (name, name_bytes) = self.name(name);
            let (type_name, type_bytes) = self.name(ty);
            let raw = &mut self.0;
            raw.members[raw.member_count as usize] = ffi::Member {
                name,
                name_bytes,
                type_name,
                type_bytes,
                ..row
            };
            raw.member_count += 1;
        }
    }

    // SAFETY: every member is an integer.
    const BINDING: ffi::Binding = unsafe { core::mem::zeroed() };
    // SAFETY: every member is an integer.
    const MEMBER: ffi::Member = unsafe { core::mem::zeroed() };

    /// Uniforms of a matrix, two inlined structures and three ints; an
    /// argument buffer of two textures, a buffer and a float; a texture.
    fn written() -> Written {
        let mut written = Written(ffi::Bindings::zeroed());
        written.binding(
            "u",
            "Uniforms",
            ffi::Binding {
                kind: binding::BUFFER,
                access: READ,
                used: 1,
                size: 112,
                alignment: 16,
                members: 0,
                member_count: 3,
                ..BINDING
            },
        );
        written.binding(
            "args",
            "Args",
            ffi::Binding {
                kind: binding::BUFFER,
                index: 1,
                access: READ,
                argument_buffer: 1,
                size: 32,
                alignment: 8,
                members: 3,
                member_count: 3,
                ..BINDING
            },
        );
        written.binding(
            "rw",
            "texture2d<float, read_write>",
            ffi::Binding {
                kind: binding::TEXTURE,
                index: 1,
                count: 1,
                access: READ_WRITE,
                texture_type: TEXTURE_2D,
                primitive: FLOAT,
                ..BINDING
            },
        );
        written.member("mvp", "float4x4", MEMBER);
        written.member(
            "inner",
            "Inner",
            ffi::Member {
                offset: 64,
                size: 16,
                elements: 2,
                members: 6,
                member_count: 2,
                ..MEMBER
            },
        );
        written.member(
            "k",
            "int",
            ffi::Member {
                offset: 96,
                size: 4,
                elements: 3,
                ..MEMBER
            },
        );
        let argument = ffi::Member {
            argument: 1,
            ..MEMBER
        };
        written.member(
            "ts",
            "array<texture2d<float, sample>, 2>",
            ffi::Member {
                size: 16,
                count: 2,
                kind: field::TEXTURE,
                access: SAMPLE,
                texture_type: TEXTURE_2D,
                primitive: FLOAT,
                ..argument
            },
        );
        written.member(
            "d",
            "float",
            ffi::Member {
                offset: 16,
                size: 8,
                count: 1,
                kind: field::BUFFER,
                id: 2,
                access: READ_WRITE,
                size_pointed: 4,
                alignment_pointed: 4,
                ..argument
            },
        );
        written.member(
            "c",
            "float",
            ffi::Member {
                offset: 24,
                size: 4,
                count: 1,
                id: 3,
                ..argument
            },
        );
        written.member("uv", "float2", ffi::Member { size: 8, ..MEMBER });
        written.member(
            "h",
            "half",
            ffi::Member {
                offset: 8,
                size: 2,
                ..MEMBER
            },
        );
        written
    }

    fn member(name: &str, offset: u32, ty: Type, argument_index: u32) -> StructMember {
        StructMember {
            name: String::from(name),
            offset,
            ty,
            argument_index,
        }
    }

    fn array(element: Type, length: u32, stride: u32, argument_index_stride: u32) -> Type {
        Type::Array(ArrayType {
            element: Box::new(element),
            length,
            stride,
            argument_index_stride,
        })
    }

    #[test]
    fn rows_become_bindings_and_their_types() {
        let bindings = bindings(&written().0).unwrap();
        let inner = StructType {
            members: vec![
                member("uv", 0, Type::Data(DataType::Float2), 0),
                member("h", 8, Type::Data(DataType::Half), 0),
            ],
        };
        let uniforms = StructType {
            members: vec![
                member("mvp", 0, Type::Data(DataType::Float4x4), 0),
                member("inner", 64, array(Type::Struct(inner), 2, 16, 0), 0),
                member("k", 96, array(Type::Data(DataType::Int), 3, 4, 0), 0),
            ],
        };
        let texture = |access| TextureReferenceType {
            data_type: DataType::Float,
            texture_type: TextureType::D2,
            access,
            depth: false,
        };
        let arguments = StructType {
            members: vec![
                member(
                    "ts",
                    0,
                    array(Type::Texture(texture(BindingAccess::ReadOnly)), 2, 8, 1),
                    0,
                ),
                member(
                    "d",
                    16,
                    Type::Pointer(PointerType {
                        element: Box::new(Type::Data(DataType::Float)),
                        access: BindingAccess::ReadWrite,
                        alignment: 4,
                        data_size: 4,
                        element_is_argument_buffer: false,
                    }),
                    2,
                ),
                member("c", 24, Type::Data(DataType::Float), 3),
            ],
        };
        let pointer = |element, data_size, alignment, element_is_argument_buffer| {
            BindingKind::Buffer(PointerType {
                element: Box::new(Type::Struct(element)),
                access: BindingAccess::ReadOnly,
                alignment,
                data_size,
                element_is_argument_buffer,
            })
        };
        assert_eq!(bindings[0].kind, pointer(uniforms, 112, 16, false));
        assert!(bindings[0].used && bindings[0].name == "u");
        assert_eq!(bindings[1].kind, pointer(arguments.clone(), 32, 8, true));
        assert_eq!(Type::Struct(arguments).id_span(), 4, "ts, ts, d and c");
        assert_eq!(
            bindings[2].kind,
            BindingKind::Texture {
                texture: texture(BindingAccess::ReadWrite),
                array_length: 1,
            }
        );
        assert_eq!(bindings[2].access, BindingAccess::ReadWrite);
    }

    #[test]
    fn malformed_rows_are_refused() {
        // A member's structure before it.
        let mut written = written();
        written.0.members[1].members = 1;
        assert_eq!(bindings(&written.0), Err(MALFORMED));
        // A structure past the rows.
        let mut written = self::written();
        written.0.bindings[0].member_count = 9;
        assert_eq!(bindings(&written.0), Err(MALFORMED));
        // A type no spelling names.
        let mut written = self::written();
        written.0.members[0].type_bytes = 0;
        assert_eq!(
            bindings(&written.0),
            Err(Error::Unsupported("reflected type"))
        );
    }
}
