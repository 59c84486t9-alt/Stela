//! Libraries and their functions.
use super::{
    Call, Object, Service,
    wire::{
        self, ConstantRecord, Fault, LibraryFunctionNamesRequest, NewFunctionRequest,
        NewLibraryRequest,
    },
};
use crate::gpu::metal::{
    abi::DataType,
    device::{
        LibraryId,
        pipelines::{ConstantKey, ConstantValue},
    },
    shader::Compiler,
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
}

/// UTF-8 text.
fn text(bytes: &[u8]) -> Result<String, Fault> {
    core::str::from_utf8(bytes)
        .map(String::from)
        .map_err(|_| Fault::malformed("text that is not UTF-8"))
}
