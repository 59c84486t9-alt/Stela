//! The relocatable objects (`MH_OBJECT`) a kext and the Metal plugin compile
//! to, read into the sections, symbols and relocations the linkers place.
use super::fit;
use crate::{Result, Within};
use alloc::{borrow::ToOwned, format, string::String, vec::Vec};
use object::{
    LittleEndian as LE, macho,
    read::macho::{MachHeader, Nlist, Section as _, Segment as _},
};
use stela_contracts::{refuse, require};

#[derive(Debug)]
pub struct Section<'a> {
    pub segment: String,
    pub name: String,
    /// The section's address in the object's own address space.
    pub address: u64,
    pub size: u64,
    /// log2 of its alignment.
    pub align: u32,
    pub flags: u32,
    /// Zeros with no bytes in the file: `__bss` and `__common`.
    pub zerofill: bool,
    pub data: &'a [u8],
    pub relocations: Vec<Relocation>,
}

impl Section<'_> {
    pub fn is_code(&self) -> bool {
        self.flags & (macho::S_ATTR_PURE_INSTRUCTIONS | macho::S_ATTR_SOME_INSTRUCTIONS) != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Definition {
    /// In section `section` (0-based) at object address `address`.
    Section {
        section: usize,
        address: u64,
    },
    Absolute(u64),
    Undefined {
        weak: bool,
    },
    /// A debugger entry (`N_STAB`), which nothing links against.
    Debug,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub definition: Definition,
    pub external: bool,
    /// A weak definition, which another definition overrides.
    pub weak: bool,
}

/// What a relocation refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Symbol(usize),
    /// Section `n` (0-based): the bytes in place hold the target's object
    /// address.
    Section(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A 64-bit pointer.
    Pointer,
    /// A 64-bit pointer signed with `key` and `diversity`.
    Authenticated {
        key: u8,
        address_diversity: bool,
        diversity: u16,
    },
    /// A 32- or 64-bit difference `target - minus`.
    Difference {
        minus: Target,
        bytes: u8,
    },
    Branch26,
    Page21,
    PageOffset12,
    GotPage21,
    GotPageOffset12,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relocation {
    /// Offset in its section.
    pub offset: u64,
    pub target: Target,
    pub kind: Kind,
    /// The addend: from a preceding `ARM64_RELOC_ADDEND`, or from the bytes
    /// in place for pointers and differences.
    pub addend: i64,
}

#[derive(Debug)]
pub struct Object<'a> {
    /// The header's CPU subtype, ABI bits included.
    pub subtype: u32,
    pub sections: Vec<Section<'a>>,
    pub symbols: Vec<Symbol>,
}

impl Object<'_> {
    pub fn is_arm64e(&self) -> bool {
        self.subtype & !macho::CPU_SUBTYPE_MASK & 0xff == macho::CPU_SUBTYPE_ARM64E
    }
}

pub fn parse(data: &[u8]) -> Result<Object<'_>> {
    let header =
        macho::MachHeader64::<LE>::parse(data, 0).within(|| refuse!("not a 64-bit Mach-O"))?;
    let subtype = header.cpusubtype(LE);
    require!(
        header.cputype(LE) == macho::CPU_TYPE_ARM64
            && matches!(
                subtype & !macho::CPU_SUBTYPE_MASK & 0xff,
                macho::CPU_SUBTYPE_ARM64_ALL | macho::CPU_SUBTYPE_ARM64E
            ),
        "not an arm64 or arm64e object"
    );
    require!(
        header.filetype(LE) == macho::MH_OBJECT,
        "not a relocatable object"
    );
    let mut sections = Vec::new();
    let mut relocations = Vec::new();
    let mut symbols = Vec::new();
    let mut commands = header.load_commands(LE, data, 0)?;
    while let Some(command) = commands.next()? {
        if let Some((segment, segment_data)) = command.segment_64()? {
            for section in segment.sections(LE, segment_data)? {
                sections.push(read_section(section, data)?);
                relocations.push(section.relocations(LE, data)?);
            }
        } else if let Some(symtab) = command.symtab()? {
            let table = symtab.symbols::<macho::MachHeader64<LE>, _>(LE, data)?;
            for nlist in table.iter() {
                symbols.push(read_symbol(nlist, table.strings())?);
            }
        }
    }
    let mut object = Object {
        subtype,
        sections,
        symbols,
    };
    for (index, raw) in relocations.into_iter().enumerate() {
        object.sections[index].relocations = decode(&object, index, raw)?;
    }
    Ok(object)
}

fn read_section<'a>(section: &macho::Section64<LE>, data: &'a [u8]) -> Result<Section<'a>> {
    let name = fixed(&section.sectname)?;
    let segment = fixed(&section.segname)?;
    let flags = section.flags(LE);
    let zerofill = matches!(
        flags & macho::SECTION_TYPE,
        macho::S_ZEROFILL | macho::S_GB_ZEROFILL
    );
    let bytes = if zerofill {
        &[][..]
    } else {
        section
            .data(LE, data)
            .map_err(|_| refuse!("{segment},{name} extends past the file", segment, name))?
    };
    Ok(Section {
        segment,
        name,
        address: section.addr(LE),
        size: section.size(LE),
        align: section.align(LE),
        flags,
        zerofill,
        data: bytes,
        relocations: Vec::new(),
    })
}

fn read_symbol(nlist: &macho::Nlist64<LE>, strings: object::StringTable<'_>) -> Result<Symbol> {
    let name = core::str::from_utf8(nlist.name(LE, strings)?)
        .map_err(|_| refuse!("a symbol name is not UTF-8"))?
        .to_owned();
    let kind = nlist.n_type() & macho::N_TYPE;
    let desc = nlist.n_desc(LE);
    let definition = match kind {
        _ if nlist.n_type() & macho::N_STAB != 0 => Definition::Debug,
        macho::N_UNDF if nlist.n_value(LE) != 0 => {
            return Err(refuse!(
                "{name} is a common symbol; objects build with -fno-common",
                name
            )
            .into());
        }
        macho::N_UNDF => Definition::Undefined {
            weak: desc & macho::N_WEAK_REF != 0,
        },
        macho::N_SECT => Definition::Section {
            section: usize::from(nlist.n_sect())
                .checked_sub(1)
                .ok_or(refuse!("a symbol in section 0"))?,
            address: nlist.n_value(LE),
        },
        macho::N_ABS => Definition::Absolute(nlist.n_value(LE)),
        _ => {
            return Err(refuse!("symbol {name} has unsupported type {kind:#x}", name, kind).into());
        }
    };
    Ok(Symbol {
        name,
        definition,
        external: nlist.n_type() & macho::N_EXT != 0,
        weak: desc & macho::N_WEAK_DEF != 0,
    })
}

fn fixed(name: &[u8; 16]) -> Result<String> {
    let end = name.iter().position(|&byte| byte == 0).unwrap_or(16);
    Ok(core::str::from_utf8(&name[..end])
        .map_err(|_| refuse!("a section or segment name is not UTF-8"))?
        .to_owned())
}

/// Decodes a section's relocations, folding `ARM64_RELOC_ADDEND` and
/// `ARM64_RELOC_SUBTRACTOR` into the relocation they modify.
fn decode(
    object: &Object<'_>,
    index: usize,
    relocations: &[macho::Relocation<LE>],
) -> Result<Vec<Relocation>> {
    let section = &object.sections[index];
    let mut decoded = Vec::with_capacity(relocations.len());
    let mut pending_addend = None;
    let mut pending_minus = None;
    for relocation in relocations {
        let info = relocation.info(LE);
        require!(
            info.r_address & macho::R_SCATTERED == 0,
            "scattered relocations are not arm64's"
        );
        let offset = u64::from(info.r_address);
        if info.r_type == macho::ARM64_RELOC_ADDEND {
            require!(!info.r_extern, "an extern ARM64_RELOC_ADDEND");
            // A 24-bit signed addend.
            pending_addend = Some(i64::from(((info.r_symbolnum << 8) as i32) >> 8));
            continue;
        }
        let target = if info.r_extern {
            let symbol = info.r_symbolnum as usize;
            require!(symbol < object.symbols.len(), "relocation names no symbol");
            Target::Symbol(symbol)
        } else {
            let ordinal = (info.r_symbolnum as usize)
                .checked_sub(1)
                .filter(|&section| section < object.sections.len())
                .ok_or(refuse!("relocation names no section"))?;
            Target::Section(ordinal)
        };
        if info.r_type == macho::ARM64_RELOC_SUBTRACTOR {
            pending_minus = Some((offset, target));
            continue;
        }
        let in_place = |bytes: usize| -> Result<i64> {
            let start: usize = fit(offset, "a relocation offset")?;
            let field = section
                .data
                .get(start..start + bytes)
                .ok_or(refuse!("relocation past its section"))?;
            Ok(match bytes {
                4 => i64::from(i32::from_le_bytes(
                    field.try_into().map_err(|_| refuse!("a short addend"))?,
                )),
                _ => i64::from_le_bytes(field.try_into().map_err(|_| refuse!("a short addend"))?),
            })
        };
        let width = 1usize << info.r_length;
        let (kind, addend) =
            match info.r_type {
                macho::ARM64_RELOC_UNSIGNED => {
                    if let Some((minus_offset, minus)) = pending_minus.take() {
                        require!(minus_offset == offset, "a subtractor without its pair");
                        let bytes: u8 = fit(width, "a relocation width")?;
                        require!(matches!(bytes, 4 | 8), "a {bytes}-byte difference", bytes);
                        (Kind::Difference { minus, bytes }, in_place(width)?)
                    } else {
                        require!(width == 8, "a {width}-byte pointer", width);
                        (Kind::Pointer, in_place(8)?)
                    }
                }
                macho::ARM64_RELOC_AUTHENTICATED_POINTER => {
                    require!(width == 8, "a {width}-byte authenticated pointer", width);
                    let raw = in_place(8)? as u64;
                    let kind = Kind::Authenticated {
                        key: ((raw >> 49) & 3) as u8,
                        address_diversity: raw >> 48 & 1 != 0,
                        diversity: (raw >> 32) as u16,
                    };
                    (kind, i64::from(raw as u32 as i32))
                }
                macho::ARM64_RELOC_BRANCH26 => (Kind::Branch26, 0),
                macho::ARM64_RELOC_PAGE21 => (Kind::Page21, 0),
                macho::ARM64_RELOC_PAGEOFF12 => (Kind::PageOffset12, 0),
                macho::ARM64_RELOC_GOT_LOAD_PAGE21 => (Kind::GotPage21, 0),
                macho::ARM64_RELOC_GOT_LOAD_PAGEOFF12 => (Kind::GotPageOffset12, 0),
                other => return Err(refuse!(
                    "{segment},{section} has relocation type {other}, which no linked code uses",
                    segment = section.segment,
                    section = section.name,
                    other
                )
                .into()),
            };
        let addend = match pending_addend.take() {
            Some(extra) => {
                require!(
                    matches!(kind, Kind::Branch26 | Kind::Page21 | Kind::PageOffset12),
                    "an ARM64_RELOC_ADDEND before {kind}",
                    ?kind
                );
                extra
            }
            None => addend,
        };
        decoded.push(Relocation {
            offset,
            target,
            kind,
            addend,
        });
    }
    require!(
        pending_addend.is_none() && pending_minus.is_none(),
        "a relocation pair without its second half"
    );
    Ok(decoded)
}
