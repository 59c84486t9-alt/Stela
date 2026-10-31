use ::object::{
    LittleEndian as LE, macho,
    read::macho::{MachHeader, Nlist, Section as _, Segment as _},
};

use super::*;
use crate::kernel_collection::tests::{BASE, Builder};
use anyhow::Result;
use sha2::{Digest, Sha256};
use stela_formats::der;

const BOOT_UUID: [u8; 16] = [0x5a; 16];
const IOLOG: u64 = BASE + 0x4100;
const VTABLE: u64 = BASE + 0x4200;
const HIDDEN: u64 = BASE + 0x4300;
/// A kernel class `Parent : Base` whose vtable overrides `Base::a` and
/// leaves its last slot reserved.
const PARENT_VTABLE: u64 = BASE + 0x4800;
const PARENT_META: u64 = BASE + 0x4900;
const BASE_A: u64 = BASE + 0x4a00;
const PARENT_A: u64 = BASE + 0x4a10;
const RESERVED: u64 = BASE + 0x4a20;
const BASE_B: u64 = BASE + 0x4a30;

pub(crate) fn words(values: &[u32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

fn nlist(strx: u32, kind: u8, section: u8, desc: u16, value: u64) -> Vec<u8> {
    let mut entry = strx.to_le_bytes().to_vec();
    entry.extend([kind, section]);
    entry.extend(desc.to_le_bytes());
    entry.extend(value.to_le_bytes());
    entry
}

/// A boot collection whose kernel defines `_IOLog`, an IOUserClient
/// vtable, a private-extern `_hidden` and the class `Parent`.
fn boot_collection() -> Vec<u8> {
    let exported = macho::N_SECT | macho::N_EXT;
    let symbols = [
        ("_IOLog", exported, IOLOG),
        ("__ZTV12IOUserClient", exported, VTABLE),
        ("_hidden", exported | macho::N_PEXT, HIDDEN),
        ("__ZTV6Parent", exported, PARENT_VTABLE),
        ("__ZN6Parent10gMetaClassE", exported, PARENT_META),
        ("__ZN4Base1aEv", exported, BASE_A),
        ("__ZN6Parent1aEv", exported, PARENT_A),
        ("__ZN4Base10_RESERVED0Ev", exported, RESERVED),
        ("__ZN4Base1bEv", exported, BASE_B),
    ];
    let mut table = Vec::new();
    let mut strings = vec![b' ', 0];
    for (name, kind, value) in symbols {
        table.extend(nlist(strings.len() as u32, kind, 1, 0, value));
        strings.extend(name.as_bytes());
        strings.push(0);
    }
    let symoff = 0x8000u32;
    let stroff = symoff + table.len() as u32;
    let mut kernel = words(&[
        macho::MH_MAGIC_64,
        macho::CPU_TYPE_ARM64,
        0xc000_0002,
        macho::MH_EXECUTE,
        1,
        24,
        0,
        0,
    ]);
    kernel.extend(words(&[
        macho::LC_SYMTAB,
        24,
        symoff,
        symbols.len() as u32,
        stroff,
        strings.len() as u32,
    ]));
    // Parent's vtable, as chained fixups: two null words, the destructors,
    // its own `a`, and the reserved slot.
    kernel.resize((PARENT_VTABLE - BASE - 0x4000) as usize, 0);
    for target in [
        None,
        None,
        Some(PARENT_A),
        Some(PARENT_A),
        Some(PARENT_A),
        Some(RESERVED),
    ] {
        let raw = target.map_or(0, |target| (target - BASE) | 1 << 63);
        kernel.extend(raw.to_le_bytes());
    }
    let mut linkedit = table;
    linkedit.extend(strings);
    let mut uuid = words(&[macho::LC_UUID, 24]);
    uuid.extend(BOOT_UUID);
    Builder::new(macho::MH_FILESET)
        .segment("__TEXT", 0x4000, &[0; 0x4000])
        .segment("__TEXT_EXEC", 0x4000, &kernel)
        .segment("__LINKEDIT", 0x4000, &linkedit)
        .fileset(boot::KERNEL, BASE + 0x4000)
        .thread(BASE + 0x4400)
        .command(uuid)
        .build()
}

pub(crate) struct InputSection {
    segment: &'static str,
    name: &'static str,
    flags: u32,
    align: u32,
    data: Vec<u8>,
    /// For zerofill sections, which have no data.
    size: u64,
    /// (offset, symbol or section ordinal, extern, type, log2 length)
    relocations: Vec<(u32, u32, bool, u8, u8)>,
}

impl InputSection {
    pub(crate) fn new(
        segment: &'static str,
        name: &'static str,
        flags: u32,
        data: Vec<u8>,
    ) -> Self {
        Self {
            segment,
            name,
            flags,
            align: 3,
            size: data.len() as u64,
            data,
            relocations: Vec::new(),
        }
    }

    pub(crate) fn zerofill(segment: &'static str, name: &'static str, size: u64) -> Self {
        let mut section = Self::new(segment, name, macho::S_ZEROFILL, Vec::new());
        section.size = size;
        section
    }

    pub(crate) fn relocate(mut self, offset: u32, symbol: u32, kind: u8, length: u8) -> Self {
        self.relocations.push((offset, symbol, true, kind, length));
        self
    }

    fn addend(mut self, offset: u32, addend: u32) -> Self {
        self.relocations
            .push((offset, addend, false, macho::ARM64_RELOC_ADDEND, 2));
        self
    }
}

enum Place {
    Section(usize, u64),
    Undefined { weak: bool },
}

pub(crate) struct InputSymbol {
    name: &'static str,
    external: bool,
    pub(crate) weak: bool,
    place: Place,
}

pub(crate) fn defined(
    name: &'static str,
    external: bool,
    section: usize,
    offset: u64,
) -> InputSymbol {
    InputSymbol {
        name,
        external,
        weak: false,
        place: Place::Section(section, offset),
    }
}

pub(crate) fn undefined(name: &'static str, weak: bool) -> InputSymbol {
    InputSymbol {
        name,
        external: true,
        weak: false,
        place: Place::Undefined { weak },
    }
}

/// An arm64e `MH_OBJECT` with one unnamed segment holding `sections`.
fn object_file(sections: &[InputSection], symbols: &[InputSymbol]) -> Vec<u8> {
    object_file_of(0x8000_0002, sections, symbols)
}

/// An `MH_OBJECT` of CPU subtype `subtype`.
pub(crate) fn object_file_of(
    subtype: u32,
    sections: &[InputSection],
    symbols: &[InputSymbol],
) -> Vec<u8> {
    let commands = 72 + 80 * sections.len() + 24;
    let mut addresses = Vec::new();
    let mut address = 0u64;
    for section in sections {
        address = address.next_multiple_of(1 << section.align);
        addresses.push(address);
        address += section.size;
    }
    let mut data = Vec::new();
    let mut offsets = Vec::new();
    let body = (32 + commands) as u64;
    for section in sections {
        offsets.push(body + data.len() as u64);
        data.extend(&section.data);
        data.resize(data.len().next_multiple_of(8), 0);
    }
    let mut relocation_offsets = Vec::new();
    for section in sections {
        relocation_offsets.push(body + data.len() as u64);
        for &(offset, symbol, external, kind, length) in &section.relocations {
            data.extend(offset.to_le_bytes());
            let info = symbol
                | u32::from(matches!(kind, 2 | 3 | 5)) << 24
                | u32::from(length) << 25
                | u32::from(external) << 27
                | u32::from(kind) << 28;
            data.extend(info.to_le_bytes());
        }
    }
    let symoff = body + data.len() as u64;
    let mut strings = vec![b' ', 0];
    for symbol in symbols {
        let (kind, section, value) = match symbol.place {
            Place::Section(section, offset) => (
                macho::N_SECT,
                section as u8 + 1,
                addresses[section] + offset,
            ),
            Place::Undefined { .. } => (macho::N_UNDF, 0, 0),
        };
        let kind = kind | if symbol.external { macho::N_EXT } else { 0 };
        let desc = match symbol.place {
            Place::Undefined { weak: true } => macho::N_WEAK_REF,
            _ if symbol.weak => macho::N_WEAK_DEF,
            _ => 0,
        };
        data.extend(nlist(strings.len() as u32, kind, section, desc, value));
        strings.extend(symbol.name.as_bytes());
        strings.push(0);
    }
    let stroff = body + data.len() as u64;
    data.extend(&strings);

    let mut file = words(&[
        macho::MH_MAGIC_64,
        macho::CPU_TYPE_ARM64,
        subtype,
        macho::MH_OBJECT,
        2,
        commands as u32,
        0,
        0,
    ]);
    file.extend(words(&[
        macho::LC_SEGMENT_64,
        (72 + 80 * sections.len()) as u32,
    ]));
    file.extend([0; 16]);
    for value in [0, address, body, address] {
        file.extend(value.to_le_bytes());
    }
    file.extend(words(&[7, 7, sections.len() as u32, 0]));
    for (index, section) in sections.iter().enumerate() {
        file.extend(commands::name16(section.name));
        file.extend(commands::name16(section.segment));
        file.extend(addresses[index].to_le_bytes());
        file.extend(section.size.to_le_bytes());
        let zerofill = section.flags & macho::SECTION_TYPE == macho::S_ZEROFILL;
        file.extend(words(&[
            if zerofill { 0 } else { offsets[index] as u32 },
            section.align,
            relocation_offsets[index] as u32,
            section.relocations.len() as u32,
            section.flags,
            0,
            0,
            0,
        ]));
    }
    file.extend(words(&[
        macho::LC_SYMTAB,
        24,
        symoff as u32,
        symbols.len() as u32,
        stroff as u32,
        strings.len() as u32,
    ]));
    assert_eq!(file.len() as u64, body);
    file.extend(data);
    file
}

const CODE: u32 = macho::S_ATTR_PURE_INSTRUCTIONS | macho::S_ATTR_SOME_INSTRUCTIONS;
/// `kmod_info`, `_local`, `_IOLog`, the vtable, `_maybe`, `_counter`.
const KMOD_INFO: u32 = 0;
const LOCAL: u32 = 1;
const IOLOG_SYMBOL: u32 = 2;
const VTABLE_SYMBOL: u32 = 3;
const MAYBE: u32 = 4;

pub(crate) fn auth(key: u64, diversity: u64) -> Vec<u8> {
    (diversity << 32 | 1 << 48 | key << 49 | 1 << 63)
        .to_le_bytes()
        .to_vec()
}

fn kext_object() -> Vec<u8> {
    let text = words(&[
        0x9400_0000, // bl _IOLog
        0x9000_0000, // adrp x0, vtable@GOTPAGE
        0xf940_0000, // ldr x0, [x0, vtable@GOTPAGEOFF]
        0x9000_0001, // adrp x1, kmod_info@PAGE + 8
        0x9100_0021, // add x1, x1, kmod_info@PAGEOFF + 8
        0x9400_0000, // bl _local
        0xd65f_03c0, // _local: ret
    ]);
    let sections = [
        InputSection::new("__TEXT", "__text", CODE, text)
            .relocate(0x0, IOLOG_SYMBOL, macho::ARM64_RELOC_BRANCH26, 2)
            .relocate(0x4, VTABLE_SYMBOL, macho::ARM64_RELOC_GOT_LOAD_PAGE21, 2)
            .relocate(0x8, VTABLE_SYMBOL, macho::ARM64_RELOC_GOT_LOAD_PAGEOFF12, 2)
            .addend(0xc, 8)
            .relocate(0xc, KMOD_INFO, macho::ARM64_RELOC_PAGE21, 2)
            .addend(0x10, 8)
            .relocate(0x10, KMOD_INFO, macho::ARM64_RELOC_PAGEOFF12, 2)
            .relocate(0x14, LOCAL, macho::ARM64_RELOC_BRANCH26, 2),
        // kmod_info, then a pointer to _local and one to the weak `_maybe`.
        InputSection::new(
            "__DATA",
            "__data",
            0,
            [vec![0xee; 8], vec![0; 0x10]].concat(),
        )
        .relocate(0x8, LOCAL, macho::ARM64_RELOC_UNSIGNED, 3)
        .relocate(0x10, MAYBE, macho::ARM64_RELOC_UNSIGNED, 3),
        InputSection::new(
            "__DATA",
            "__const",
            0,
            [auth(0, 0x1234), auth(1, 0)].concat(),
        )
        .relocate(
            0x0,
            IOLOG_SYMBOL,
            macho::ARM64_RELOC_AUTHENTICATED_POINTER,
            3,
        )
        .relocate(0x8, LOCAL, macho::ARM64_RELOC_AUTHENTICATED_POINTER, 3),
        InputSection::new(
            "__DATA",
            "__mod_init_func",
            macho::S_MOD_INIT_FUNC_POINTERS,
            vec![0; 8],
        )
        .relocate(0x0, LOCAL, macho::ARM64_RELOC_UNSIGNED, 3),
        InputSection::new("__TEXT", "__eh_frame", 0, vec![0; 8]).relocate(
            0x0,
            LOCAL,
            macho::ARM64_RELOC_UNSIGNED,
            3,
        ),
        InputSection {
            size: 0x20,
            ..InputSection::new("__DATA", "__bss", macho::S_ZEROFILL, Vec::new())
        },
    ];
    let symbols = [
        defined("_kmod_info", true, 1, 0),
        defined("_local", true, 0, 0x18),
        undefined("_IOLog", false),
        undefined("__ZTV12IOUserClient", false),
        undefined("_maybe", true),
        defined("_counter", false, 5, 0),
    ];
    object_file(&sections, &symbols)
}

const INFO: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.stela.Test</string>
<key>CFBundleExecutable</key><string>Test</string>
<key>CFBundleVersion</key><string>1.2.3</string>
<key>OSBundleLibraries</key><dict><key>com.apple.kpi.iokit</key><string>8.0.0</string></dict>
</dict></plist>"#;

fn kext(objects: Vec<&[u8]>) -> Kext<'_> {
    Kext {
        info: INFO,
        objects,
        bundle_path: "/Library/Extensions/Test.kext".into(),
    }
}

struct Section {
    address: u64,
    offset: u64,
    size: u64,
    flags: u32,
}

/// The collection's and each fileset entry's segments and sections, by
/// `segment,section` name (a segment alone under its own name).
fn sections(file: &[u8], offset: u64) -> BTreeMap<String, Section> {
    let header = macho::MachHeader64::<LE>::parse(file, offset).unwrap();
    let mut found = BTreeMap::new();
    let mut commands = header.load_commands(LE, file, offset).unwrap();
    while let Some(command) = commands.next().unwrap() {
        if let Some((segment, data)) = command.segment_64().unwrap() {
            let name = String::from_utf8_lossy(segment.name()).into_owned();
            found.insert(
                name.clone(),
                Section {
                    address: segment.vmaddr.get(LE),
                    offset: segment.fileoff.get(LE),
                    size: segment.vmsize.get(LE),
                    flags: segment.maxprot.get(LE),
                },
            );
            for section in segment.sections(LE, data).unwrap() {
                found.insert(
                    format!("{name},{}", String::from_utf8_lossy(section.name())),
                    Section {
                        address: section.addr.get(LE),
                        offset: u64::from(section.offset.get(LE)),
                        size: section.size.get(LE),
                        flags: section.flags.get(LE),
                    },
                );
            }
        }
    }
    found
}

/// Each chained fixup's address and raw value.
fn chains(file: &[u8]) -> BTreeMap<u64, u64> {
    let header = macho::MachHeader64::<LE>::parse(file, 0).unwrap();
    let mut commands = header.load_commands(LE, file, 0).unwrap();
    let mut payload = None;
    let mut segments = Vec::new();
    while let Some(command) = commands.next().unwrap() {
        if let Some((segment, _)) = command.segment_64().unwrap() {
            segments.push((segment.vmaddr.get(LE), segment.fileoff.get(LE)));
        }
        if command.cmd() == macho::LC_DYLD_CHAINED_FIXUPS {
            let data = command.data::<macho::LinkeditDataCommand<LE>>().unwrap();
            let start = data.dataoff.get(LE) as usize;
            payload = Some(&file[start..start + data.datasize.get(LE) as usize]);
        }
    }
    let payload = payload.unwrap();
    let word = |at: usize| u32::from_le_bytes(payload[at..at + 4].try_into().unwrap()) as usize;
    let half = |at: usize| u16::from_le_bytes(payload[at..at + 2].try_into().unwrap());
    let starts = word(4);
    let mut found = BTreeMap::new();
    for (index, &(address, file_offset)) in segments.iter().enumerate() {
        let info = word(starts + 4 + 4 * index);
        if info == 0 {
            continue;
        }
        let at = starts + info;
        assert_eq!(half(at + 6), 8, "DYLD_CHAINED_PTR_64_KERNEL_CACHE");
        for page in 0..half(at + 20) as u64 {
            let start = half(at + 22 + 2 * page as usize);
            if start == 0xffff {
                continue;
            }
            let mut offset = page * 0x4000 + u64::from(start);
            loop {
                let at = (file_offset + offset) as usize;
                let raw = u64::from_le_bytes(file[at..at + 8].try_into().unwrap());
                found.insert(address + offset, raw);
                let next = raw >> 51 & 0xfff;
                if next == 0 {
                    break;
                }
                offset += 4 * next;
            }
        }
    }
    found
}

fn read(file: &[u8], section: &Section, offset: u64, length: usize) -> Vec<u8> {
    let at = (section.offset + offset) as usize;
    file[at..at + length].to_vec()
}

fn instruction(file: &[u8], section: &Section, offset: u64) -> u32 {
    u32::from_le_bytes(read(file, section, offset, 4).try_into().unwrap())
}

fn branch_target(instruction: u32, place: u64) -> u64 {
    let imm = ((instruction << 6) as i32 >> 6) as i64;
    place.wrapping_add_signed(imm * 4)
}

fn page_target(adrp: u32, place: u64) -> u64 {
    let imm = ((adrp >> 29 & 3) | (adrp >> 5 & 0x7_ffff) << 2) as i64;
    let imm = (imm << 43) >> 43;
    (place & !0xfff).wrapping_add_signed(imm << 12)
}

#[test]
fn links_a_kext_against_the_boot_collection() -> Result<()> {
    let boot = boot_collection();
    let object = kext_object();
    let kexts = [kext(vec![&object])];
    let linked = link(&boot, &kexts)?;
    let source = linked.source(&kexts);
    assert_eq!(source.member, "Test.kext");
    assert_eq!(source.decoded_bytes, linked.collection.len() as u64);
    let file = linked.collection;

    let collection = sections(&file, 0);
    let order: Vec<_> = SEGMENTS
        .iter()
        .map(|(name, _)| collection[*name].address)
        .collect();
    assert!(order.is_sorted(), "segments run in address order");
    assert_eq!(collection["__PRELINK_INFO"].address, 0);
    assert_eq!(collection["__TEXT"].offset, 0);
    assert_eq!(collection["__TEXT_EXEC"].flags, 5);
    let section = &collection["__RECEIPT_INFO,__aux_kc_receipt"];
    let receipt = read(&file, section, 0, section.size as usize);
    let mut receipt = der::sequence(&receipt)?;
    assert_eq!(receipt.take(2)?.value, [1]);
    let mut entries = der::Cursor(receipt.take(16)?.value);
    receipt.end()?;
    let mut entry = der::Cursor(entries.take(16)?.value);
    entries.end()?;
    let cd_hash = Sha256::digest(&object);
    assert_eq!(entry.take(4)?.value, &cd_hash[..20]);
    assert!(entry.take(4)?.value.is_empty());
    assert_eq!(entry.take(4)?.value, &Sha256::digest("com.stela.Test")[..]);
    assert_eq!(
        entry.take(2)?.value,
        &1_000_200_039_000_u64.to_be_bytes()[2..]
    );
    entry.end()?;

    let header = macho::MachHeader64::<LE>::parse(&file[..], 0)?;
    assert_eq!(header.filetype(LE), macho::MH_FILESET);
    let mut entries = Vec::new();
    let mut commands = header.load_commands(LE, &file[..], 0)?;
    while let Some(command) = commands.next()? {
        if command.cmd() == macho::LC_FILESET_ENTRY {
            let entry = command.data::<macho::FilesetEntryCommand<LE>>()?;
            entries.push((entry.vmaddr.get(LE), entry.fileoff.get(LE)));
        }
    }
    let [(entry, entry_offset)] = entries[..] else {
        panic!("one fileset entry");
    };
    assert_eq!(entry % PAGE_BYTES, 0);
    let bundle = sections(&file, entry_offset);
    assert_eq!(bundle["__TEXT"].address, entry);
    assert_eq!(
        macho::MachHeader64::<LE>::parse(&file[..], entry_offset)?.filetype(LE),
        macho::MH_KEXT_BUNDLE
    );
    assert!(!bundle.keys().any(|name| name.ends_with("__eh_frame")));
    assert_eq!(
        bundle["__DATA_CONST,__mod_init_func"].flags,
        macho::S_MOD_INIT_FUNC_POINTERS
    );
    assert_eq!(read(&file, &bundle["__DATA,__bss"], 0, 0x20), [0; 0x20]);

    let text = &bundle["__TEXT_EXEC,__text"];
    let stubs = &bundle["__TEXT_EXEC,__auth_stubs"];
    let auth_got = &bundle["__DATA_CONST,__auth_got"];
    let got = &bundle["__DATA_CONST,__got"];
    let data = &bundle["__DATA,__data"];
    let constants = &bundle["__DATA_CONST,__const"];
    let initializers = &bundle["__DATA_CONST,__mod_init_func"];

    // bl _IOLog goes through a stub that loads and authenticates its slot.
    assert_eq!(
        branch_target(instruction(&file, text, 0), text.address),
        stubs.address
    );
    let adrp = instruction(&file, stubs, 0);
    let add = instruction(&file, stubs, 4);
    let slot = page_target(adrp, stubs.address) + u64::from(add >> 10 & 0xfff);
    assert_eq!(slot, auth_got.address);
    assert_eq!(instruction(&file, stubs, 8), 0xf940_0230);
    assert_eq!(instruction(&file, stubs, 12), 0xd71f_0a11);
    // The vtable comes from the GOT.
    let adrp = instruction(&file, text, 4);
    let ldr = instruction(&file, text, 8);
    let slot = page_target(adrp, text.address + 4) + 8 * u64::from(ldr >> 10 & 0xfff);
    assert_eq!(slot, got.address);
    // kmod_info + 8, from ADRP and ADD with their addends.
    let adrp = instruction(&file, text, 0xc);
    let add = instruction(&file, text, 0x10);
    assert_eq!(
        page_target(adrp, text.address + 0xc) + u64::from(add >> 10 & 0xfff),
        data.address + 8
    );
    assert_eq!(
        branch_target(instruction(&file, text, 0x14), text.address + 0x14),
        text.address + 0x18
    );
    // The weak reference to `_maybe` is null; kmod_info's bytes are intact.
    assert_eq!(read(&file, data, 0x10, 8), [0; 8]);
    assert_eq!(read(&file, data, 0, 8), [0xee; 8]);

    let local = text.address + 0x18;
    let target = |raw: u64| (raw & 0x3fff_ffff, raw >> 30 & 3);
    let fixups = chains(&file);
    assert_eq!(fixups.keys().copied().collect::<Vec<_>>(), {
        let mut expected = vec![
            data.address + 8,
            constants.address,
            constants.address + 8,
            initializers.address,
            auth_got.address,
            got.address,
        ];
        expected.sort();
        expected
    });
    assert_eq!(target(fixups[&(data.address + 8)]), (local, 3));
    assert_eq!(target(fixups[&initializers.address]), (local, 3));
    assert_eq!(target(fixups[&got.address]), (VTABLE - BASE, 0));
    let signed = fixups[&constants.address];
    assert_eq!(target(signed), (IOLOG - BASE, 0));
    assert_eq!(
        (
            signed >> 32 & 0xffff,
            signed >> 48 & 1,
            signed >> 49 & 3,
            signed >> 63
        ),
        (0x1234, 1, 0, 1)
    );
    let signed = fixups[&(constants.address + 8)];
    assert_eq!(target(signed), (local, 3));
    assert_eq!(signed >> 49 & 3, 1);
    let slot = fixups[&auth_got.address];
    assert_eq!(target(slot), (IOLOG - BASE, 0));
    assert_eq!((slot >> 48 & 1, slot >> 49 & 3, slot >> 63), (1, 0, 1));

    let info = &collection["__PRELINK_INFO,__info"];
    let xml = read(&file, info, 0, info.size as usize);
    assert_eq!(xml.last(), Some(&0));
    let root = ::plist::Value::from_reader_xml(&xml[..xml.len() - 1])?;
    let root = root.as_dictionary().unwrap();
    assert_eq!(root["_BootKCID"].as_data(), Some(&BOOT_UUID[..]));
    let prelinked = root["_PrelinkInfoDictionary"].as_array().unwrap()[0]
        .as_dictionary()
        .unwrap();
    assert_eq!(
        prelinked["_PrelinkExecutableLoadAddr"].as_unsigned_integer(),
        Some(entry)
    );
    assert_eq!(
        prelinked["_PrelinkExecutableSize"].as_unsigned_integer(),
        Some(bundle["__TEXT"].size)
    );
    assert_eq!(
        prelinked["_PrelinkKmodInfo"].as_unsigned_integer(),
        Some(data.address)
    );
    assert_eq!(
        prelinked["_PrelinkBundlePath"].as_string(),
        Some("/Library/Extensions/Test.kext")
    );

    // The symbol table names the external definitions and the named local.
    let header = macho::MachHeader64::<LE>::parse(&file[..], entry_offset)?;
    let mut commands = header.load_commands(LE, &file[..], entry_offset)?;
    let mut names = Vec::new();
    while let Some(command) = commands.next()? {
        if let Some(symtab) = command.symtab()? {
            let table = symtab.symbols::<macho::MachHeader64<LE>, _>(LE, &file[..])?;
            for symbol in table.iter() {
                let name = String::from_utf8_lossy(symbol.name(LE, table.strings())?).into_owned();
                names.push((
                    name,
                    symbol.n_type() & macho::N_EXT != 0,
                    symbol.n_value(LE),
                ));
            }
        }
    }
    assert_eq!(
        names,
        [
            ("_counter".into(), false, bundle["__DATA,__bss"].address),
            ("_kmod_info".into(), true, data.address),
            ("_local".into(), true, local),
        ]
    );

    assert_eq!(
        link(&boot, &[kext(vec![&object])])?.collection,
        file,
        "linking is deterministic"
    );
    Ok(())
}

#[test]
fn a_strong_definition_overrides_weak_ones() -> Result<()> {
    let weak = object_file(
        &[
            InputSection::new("__DATA", "__data", 0, vec![0; 16]).relocate(
                0x8,
                1,
                macho::ARM64_RELOC_UNSIGNED,
                3,
            ),
        ],
        &[
            defined("_kmod_info", true, 0, 0),
            InputSymbol {
                weak: true,
                ..defined("_shared", true, 0, 8)
            },
        ],
    );
    let strong = object_file(
        &[InputSection::new("__DATA", "__data", 0, vec![0; 8])],
        &[defined("_shared", true, 0, 0)],
    );
    let file = link(&boot_collection(), &[kext(vec![&weak, &strong])])?.collection;
    let entry_offset = {
        let collection = sections(&file, 0);
        collection["__PRELINK_TEXT"].offset
    };
    let data = &sections(&file, entry_offset)["__DATA,__data"];
    // The second object's 8 bytes follow the first's 16.
    assert_eq!(
        chains(&file)[&(data.address + 8)] & 0x3fff_ffff,
        data.address + 16
    );
    Ok(())
}

#[test]
fn refuses_what_it_cannot_link() {
    let boot = boot_collection();
    let missing = object_file(
        &[
            InputSection::new("__DATA", "__data", 0, vec![0; 16]).relocate(
                0x8,
                1,
                macho::ARM64_RELOC_UNSIGNED,
                3,
            ),
        ],
        &[
            defined("_kmod_info", true, 0, 0),
            undefined("_hidden", false),
        ],
    );
    let error = link(&boot, &[kext(vec![&missing])]).unwrap_err();
    assert!(
        format!("{error:#}").contains("_hidden is undefined"),
        "{error:#}"
    );

    let twice = object_file(
        &[InputSection::new("__DATA", "__data", 0, vec![0; 8])],
        &[defined("_kmod_info", true, 0, 0)],
    );
    let error = link(&boot, &[kext(vec![&twice, &twice])]).unwrap_err();
    assert!(format!("{error:#}").contains("defined twice"), "{error:#}");

    let no_kmod = object_file(
        &[InputSection::new("__DATA", "__data", 0, vec![0; 8])],
        &[defined("_other", true, 0, 0)],
    );
    assert!(link(&boot, &[kext(vec![&no_kmod])]).is_err());
    assert!(link(&boot, &[kext(vec![&twice]), kext(vec![&twice])]).is_err());

    let foreign = br#"<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.stela.Test</string>
<key>OSBundleLibraries</key><dict><key>com.example.Missing</key><string>1.0</string></dict>
</dict></plist>"#;
    let kext = Kext {
        info: foreign,
        objects: vec![&twice],
        bundle_path: "/Library/Extensions/Test.kext".into(),
    };
    let error = link(&boot, &[kext]).unwrap_err();
    assert!(
        format!("{error:#}").contains("com.example.Missing"),
        "{error:#}"
    );
}

/// A kext class `Child : Parent` built against headers in which `Parent`
/// inherits `Base::a`, with `last` in the slot the kernel reserves.
fn child_object(last: &'static str) -> Vec<u8> {
    let vtable = [
        vec![0; 16],
        [auth(0, 0x11), auth(0, 0x22), auth(0, 0x33), auth(0, 0x44)].concat(),
        vec![0; 8],
    ]
    .concat();
    let auth_pointer = macho::ARM64_RELOC_AUTHENTICATED_POINTER;
    let sections = [
        InputSection::new("__TEXT", "__text", CODE, words(&[0xd65f_03c0, 0xd65f_03c0])),
        InputSection::new("__DATA", "__data", 0, vec![0; 8]),
        InputSection::new("__DATA", "__const", 0, vtable)
            .relocate(0x10, 3, auth_pointer, 3)
            .relocate(0x18, 4, auth_pointer, 3)
            .relocate(0x20, 5, auth_pointer, 3)
            .relocate(0x28, 6, auth_pointer, 3)
            .relocate(0x30, 7, macho::ARM64_RELOC_UNSIGNED, 3),
    ];
    let symbols = [
        defined("_kmod_info", true, 1, 0),
        defined("__ZTV5Child", true, 2, 0),
        defined("__ZN5Child10superClassE", true, 2, 0x30),
        defined("__ZN5ChildD1Ev", true, 0, 0),
        defined("__ZN5ChildD0Ev", true, 0, 4),
        undefined("__ZN4Base1aEv", false),
        undefined(last, false),
        undefined("__ZN6Parent10gMetaClassE", false),
    ];
    object_file(&sections, &symbols)
}

#[test]
fn inherited_vtable_slots_take_the_kernel_superclass_entries() -> Result<()> {
    let object = child_object("__ZN4Base10_RESERVED0Ev");
    let file = link(&boot_collection(), &[kext(vec![&object])])?.collection;
    let entry_offset = sections(&file, 0)["__PRELINK_TEXT"].offset;
    let bundle = sections(&file, entry_offset);
    let vtable = bundle["__DATA_CONST,__const"].address;
    let text = bundle["__TEXT_EXEC,__text"].address;
    let fixups = chains(&file);
    let slot = |index: u64| {
        let raw = fixups[&(vtable + 8 * index)];
        (raw & 0x3fff_ffff, raw >> 30 & 3, raw >> 32 & 0xffff)
    };
    // The class's own destructors stay its own.
    assert_eq!(slot(2), (text, 3, 0x11));
    assert_eq!(slot(3), (text + 4, 3, 0x22));
    // Parent overrides `a` in this kernel; the slot keeps its discriminator.
    assert_eq!(slot(4), (PARENT_A - BASE, 0, 0x33));
    assert_eq!(slot(5), (RESERVED - BASE, 0, 0x44));
    Ok(())
}

#[test]
fn a_method_in_a_slot_the_kernel_reserves_is_refused() {
    let object = child_object("__ZN4Base1bEv");
    let error = link(&boot_collection(), &[kext(vec![&object])]).unwrap_err();
    assert!(
        format!("{error:#}").contains("reserves in this kernel"),
        "{error:#}"
    );
}
