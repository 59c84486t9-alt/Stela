//! Selection from immutable MTLB bytes. The index holds offsets into the
//! original library, and checks each module's digest and AIR framing once
//! when it is first needed.
use super::{
    super::library::{Air, Header, Library},
    Error, Result,
};
use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use core::{cell::OnceCell, ffi::CStr, ops::Range};

const INVALID: Error = Error::Invalid("Metal library");

pub(super) struct LoadedLibrary {
    bytes: Vec<u8>,
    functions: Vec<Entry>,
    modules: Vec<Module>,
    pub(super) dynamic: bool,
}

struct Entry {
    name: Range<usize>,
    module: usize,
}

struct Module {
    wrapped: Range<usize>,
    digest: [u8; 32],
    /// The original bitcode range, or a failed digest/framing check.
    checked: OnceCell<Option<Range<usize>>>,
    /// Successfully listed constexpr sampler declarations.
    samplers: OnceCell<Box<[u64]>>,
}

#[derive(Clone, Copy)]
pub(super) struct ModuleSource<'a> {
    pub(super) bitcode: &'a [u8],
    pub(super) slice_hash: [u8; 32],
    pub(super) samplers: &'a OnceCell<Box<[u64]>>,
}

pub(super) struct Selected<'a> {
    pub(super) module: ModuleSource<'a>,
    pub(super) name: &'a str,
    pub(super) entry: &'a CStr,
}

impl LoadedLibrary {
    pub(super) fn new(bytes: Vec<u8>) -> Result<Self> {
        let parsed = Library::parse(&bytes).map_err(|_| INVALID)?;
        let dynamic = parsed.header.kind == Header::DYNAMIC;
        let mut modules = Vec::new();
        let mut index = BTreeMap::new();
        let mut functions = Vec::new();
        functions
            .try_reserve_exact(parsed.functions().len())
            .map_err(|_| Error::OutOfMemory)?;
        for function in parsed.functions() {
            let wrapped = function.module_range();
            let digest = *function.digest;
            let module = *index
                .entry((wrapped.start, wrapped.end, digest))
                .or_insert_with(|| {
                    let index = modules.len();
                    modules.push(Module {
                        wrapped,
                        digest,
                        checked: OnceCell::new(),
                        samplers: OnceCell::new(),
                    });
                    index
                });
            // The parser borrowed NAME from these bytes and verified its
            // terminator. Keep the terminator for the compiler service.
            let start = function.name.as_ptr().addr() - bytes.as_ptr().addr();
            let name = start..start + function.name.len() + 1;
            functions.push(Entry { name, module });
        }
        Ok(Self {
            bytes,
            functions,
            modules,
            dynamic,
        })
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn select(&self, name: &str) -> Result<Selected<'_>> {
        let entry = self
            .functions
            .iter()
            .find(|entry| &self.bytes[entry.name.start..entry.name.end - 1] == name.as_bytes())
            .ok_or(Error::Invalid("no function of that name"))?;
        let module = &self.modules[entry.module];
        let entry =
            CStr::from_bytes_with_nul(&self.bytes[entry.name.clone()]).map_err(|_| INVALID)?;
        Ok(Selected {
            module: module.source(&self.bytes)?,
            name: entry.to_str().map_err(|_| INVALID)?,
            entry,
        })
    }

    pub(super) fn modules(&self) -> impl Iterator<Item = Result<ModuleSource<'_>>> {
        self.modules.iter().map(|module| module.source(&self.bytes))
    }
}

impl Module {
    fn source<'a>(&'a self, data: &'a [u8]) -> Result<ModuleSource<'a>> {
        let range = self.checked.get_or_init(|| {
            let wrapped = &data[self.wrapped.clone()];
            let bitcode = Air::verified(wrapped, &self.digest).ok()?.bitcode;
            let start = bitcode.as_ptr().addr() - data.as_ptr().addr();
            Some(start..start + bitcode.len())
        });
        range
            .as_ref()
            .map(|range| ModuleSource {
                bitcode: &data[range.clone()],
                slice_hash: self.digest,
                samplers: &self.samplers,
            })
            .ok_or(INVALID)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metal::library;

    #[test]
    fn selection_caches_one_checked_module_for_entries_sharing_an_extent_and_digest() {
        let data = library::assemble(
            b"BC\xc0\xdepayload",
            &[("first", 2), ("second", 2)],
            0,
            None,
        );
        let loaded = LoadedLibrary::new(data.clone()).unwrap();
        assert_eq!(loaded.bytes(), &data);
        assert_eq!(loaded.modules.len(), 1);
        assert!(loaded.modules[0].checked.get().is_none());
        let first = loaded.select("first").unwrap();
        let second = loaded.select("second").unwrap();
        assert_eq!(first.entry.to_bytes(), b"first");
        assert_eq!(second.entry.to_bytes(), b"second");
        assert_eq!(first.module.bitcode, b"BC\xc0\xdepayload");
        assert_eq!(
            first.module.bitcode.as_ptr(),
            second.module.bitcode.as_ptr()
        );
        assert_eq!(first.module.slice_hash, second.module.slice_hash);
        assert!(matches!(loaded.modules[0].checked.get(), Some(Some(_))));
    }

    #[test]
    fn mismatched_digests_do_not_share_an_air_check() {
        let mut data = library::assemble(b"BC\xc0\xdepayload", &[("good", 2), ("bad", 2)], 0, None);
        let parsed = Library::parse(&data).unwrap();
        let digest = parsed.functions()[1].digest.as_ptr().addr() - data.as_ptr().addr();
        data[digest] ^= 1;
        let loaded = LoadedLibrary::new(data).unwrap();
        assert_eq!(loaded.modules.len(), 2);
        assert!(loaded.select("good").is_ok());
        assert!(matches!(loaded.select("bad"), Err(INVALID)));
        assert!(matches!(loaded.select("bad"), Err(INVALID)));
        assert_eq!(loaded.modules[1].checked.get(), Some(&None));
    }
}
