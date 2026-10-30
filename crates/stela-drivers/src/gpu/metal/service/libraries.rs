//! Libraries and their functions.
use super::{
    Call, Object, Service,
    wire::{
        self, AttributeInfo, ConstantInfo, ConstantRecord, Fault, FunctionReflectionRequest,
        FunctionReflectionResponse, LibraryFunctionNamesRequest, NewFunctionRequest,
        NewLibraryRequest,
    },
};
use crate::gpu::metal::{
    abi::DataType,
    device::{
        FunctionId, LibraryId,
        pipelines::{ConstantKey, ConstantValue},
    },
    shader::{Compiler, PatchDomain, Reflection},
    vulkan::backend::Backend,
};
use alloc::{string::String, vec::Vec};

impl<B: Backend, C: Compiler> Service<B, C> {
    pub(super) fn new_library(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: NewLibraryRequest = call.request()?;
        let data = call.memory.read(request.data)?.to_vec();
        let library = self.device.new_library(data)?;
        let handle = self.hold(call.connection, Object::Library(library))?;
        call.reply(&handle)
    }

    pub(super) fn library_function_names(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: LibraryFunctionNamesRequest = call.request()?;
        let library = self.object::<LibraryId>(call.connection, request.library)?;
        let mut names = Vec::new();
        for name in self.device.library_function_names(library)? {
            names.extend_from_slice(name.as_bytes());
            names.push(0);
        }
        call.reply_data(request.out, &names)
    }

    pub(super) fn new_function(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: NewFunctionRequest = call.request()?;
        let library = self.object::<LibraryId>(call.connection, request.library)?;
        let memory = &*call.memory;
        let name = text(memory.read(request.name)?)?;
        let values = wire::read_array::<ConstantRecord>(memory.read(request.constants)?)?
            .into_iter()
            .map(|record| {
                let key = if record.name.length == 0 {
                    let index = u32::try_from(record.index).map_err(|_| Fault::MALFORMED)?;
                    ConstantKey::Index(index)
                } else {
                    ConstantKey::Name(text(memory.read(record.name)?)?)
                };
                Ok(ConstantValue {
                    key,
                    data_type: DataType::from_raw(record.data_type)
                        .ok_or(Fault::malformed("function constant data type"))?,
                    value: memory.read(record.value)?.to_vec(),
                })
            })
            .collect::<Result<Vec<_>, Fault>>()?;
        let function = self.device.new_function(library, &name, &values)?;
        let handle = self.hold(call.connection, Object::Function(function))?;
        call.reply(&handle)
    }

    pub(super) fn function_reflection(&mut self, call: &mut Call) -> Result<(), Fault> {
        let request: FunctionReflectionRequest = call.request()?;
        let function = self.object::<FunctionId>(call.connection, request.function)?;
        let reflection = self.device.function_reflection(function)?;
        let (patch, attributes) = match reflection {
            Reflection::Stage(interface) => {
                (interface.patch, interface.declared_attributes.as_slice())
            }
            Reflection::Visible { .. } => (None, &[][..]),
        };
        let constants = reflection.constants();
        // Records first, then the names they point into.
        let mut names = Names {
            base: constants.len() * size_of::<ConstantInfo>()
                + attributes.len() * size_of::<AttributeInfo>(),
            bytes: Vec::new(),
        };
        let mut data = Vec::with_capacity(names.base);
        for constant in constants {
            let (name, name_length) = names.add(&constant.name)?;
            data.extend_from_slice(wire::bytes(&ConstantInfo {
                name,
                name_length,
                data_type: constant.data_type.raw(),
                index: constant.index,
                required: constant.required.into(),
            }));
        }
        for attribute in attributes {
            let (name, name_length) = names.add(&attribute.name)?;
            data.extend_from_slice(wire::bytes(&AttributeInfo {
                name,
                name_length,
                data_type: attribute.data_type.raw(),
                index: attribute.index,
                active: attribute.active.into(),
                patch_control_point: attribute.patch_control_point.into(),
                reserved: 0,
            }));
        }
        data.extend_from_slice(&names.bytes);
        let response = FunctionReflectionResponse {
            function_type: reflection.function_type().raw(),
            // `MTLPatchType`.
            patch_type: match patch.map(|patch| patch.domain) {
                None => 0,
                Some(PatchDomain::Triangle) => 1,
                Some(PatchDomain::Quad) => 2,
            },
            patch_control_points: patch
                .and_then(|patch| patch.control_points)
                .map_or(0, u64::from),
            constant_count: constants.len() as u32,
            attribute_count: attributes.len() as u32,
            length: data.len() as u64,
        };
        call.write_fitting(request.out, &data)?;
        call.reply(&response)
    }
}

/// The names of a reflection, which follow its `base` bytes of records.
pub(super) struct Names {
    pub(super) base: usize,
    pub(super) bytes: Vec<u8>,
}

impl Names {
    /// Adds `name`, returning its offset and length in the reflection.
    pub(super) fn add(&mut self, name: &str) -> Result<(u32, u32), Fault> {
        let offset = u32::try_from(self.base + self.bytes.len())
            .map_err(|_| Fault::malformed("reflection too large"))?;
        self.bytes.extend_from_slice(name.as_bytes());
        Ok((offset, name.len() as u32))
    }
}

/// UTF-8 text.
fn text(bytes: &[u8]) -> Result<String, Fault> {
    core::str::from_utf8(bytes)
        .map(String::from)
        .map_err(|_| Fault::malformed("text that is not UTF-8"))
}
