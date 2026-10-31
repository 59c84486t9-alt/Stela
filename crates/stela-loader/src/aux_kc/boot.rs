//! The boot kernel collection an auxiliary collection links against: its
//! identity, its base and the symbols each of its fileset entries defines.
use std::collections::HashMap;

use super::fit;
use crate::{Result, Within};
use object::{
    LittleEndian as LE, macho,
    read::macho::{MachHeader, Nlist},
};
use stela_contracts::{refuse, require};

use crate::kernel_collection::KernelCollection;

/// The kernel's entry, which defines every `com.apple.kpi.*` interface.
pub const KERNEL: &str = "com.apple.kernel";

pub struct BootCollection<'a> {
    data: &'a [u8],
    collection: KernelCollection,
    pub uuid: [u8; 16],
}

impl<'a> BootCollection<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let collection =
            KernelCollection::parse(data).within(|| refuse!("reading the boot collection"))?;
        let uuid = collection
            .uuid
            .as_deref()
            .ok_or(refuse!("the boot collection has no LC_UUID"))
            .and_then(|uuid| {
                hex::decode(uuid)
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(refuse!("the boot collection's UUID is not 16 bytes"))
            })?;
        Ok(Self {
            data,
            collection,
            uuid,
        })
    }

    /// Cache level 0's base: the collection's lowest address.
    pub fn base(&self) -> u64 {
        self.collection.vm_base
    }

    pub fn cpu_subtype(&self) -> u32 {
        self.collection.cpu_subtype
    }

    pub fn contains(&self, entry: &str) -> bool {
        self.collection.fileset_entry(entry).is_some()
    }

    /// The target of the pointer the collection holds at `address`, which
    /// its chained fixups encode, or `None` for a null slot.
    pub fn pointer(&self, address: u64) -> Result<Option<u64>> {
        let segment = self
            .collection
            .segment_containing(address)
            .ok_or_else(|| refuse!("{address:#x} lies outside the boot collection", address))?;
        require!(
            address + 8 <= segment.vm_address + segment.file_size,
            "{address:#x} has no bytes in the boot collection",
            address
        );
        let offset: usize = fit(
            segment.file_offset + (address - segment.vm_address),
            "a boot collection file offset",
        )?;
        let raw = u64::from_le_bytes(
            self.data
                .get(offset..offset + 8)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(refuse!(
                    "a boot collection pointer {address:#x} past the file",
                    address
                ))?,
        );
        if raw == 0 {
            return Ok(None);
        }
        require!(
            raw >> 30 & 3 == 0,
            "the boot collection's pointer at {address:#x} leaves it",
            address
        );
        Ok(Some(self.base() + (raw & 0x3fff_ffff)))
    }

    /// The external symbols `entry` defines, by name, at their unslid
    /// addresses.
    pub fn exports(&self, entry: &str) -> Result<HashMap<String, u64>> {
        let offset = self
            .collection
            .fileset_entry(entry)
            .ok_or_else(|| refuse!("the boot collection has no {entry}", entry))?
            .file_offset;
        let header = macho::MachHeader64::<LE>::parse(self.data, offset)
            .within(|| refuse!("{entry}'s Mach-O header", entry))?;
        let mut commands = header.load_commands(LE, self.data, offset)?;
        let mut exports = HashMap::new();
        while let Some(command) = commands.next()? {
            let Some(symtab) = command.symtab()? else {
                continue;
            };
            // Symbol and string offsets are relative to the collection.
            let table = symtab.symbols::<macho::MachHeader64<LE>, _>(LE, self.data)?;
            for nlist in table.iter() {
                let kind = nlist.n_type();
                if kind & macho::N_STAB == 0
                    && kind & macho::N_TYPE == macho::N_SECT
                    && kind & macho::N_EXT != 0
                    && kind & macho::N_PEXT == 0
                {
                    let name =
                        core::str::from_utf8(nlist.name(LE, table.strings())?).map_err(|_| {
                            refuse!("{entry} exports a symbol whose name is not UTF-8", entry)
                        })?;
                    exports.insert(name.to_owned(), nlist.n_value(LE));
                }
            }
        }
        require!(!exports.is_empty(), "{entry} exports no symbols", entry);
        Ok(exports)
    }
}
