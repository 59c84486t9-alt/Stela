//! One kext being linked: its objects' sections merged into the kext's
//! segments, its references resolved against itself and the boot
//! collection, and its relocations applied once the collection is laid out.
use alloc::{
    borrow::ToOwned,
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec,
    vec::Vec,
};
use core::ops::Range;

use super::fit;
use crate::{Result, Within};
use object::macho;
use sha2::{Digest, Sha256};
use stela_contracts::{refuse, require};

use super::plist::{self, Dictionary};
use super::{
    Kext,
    boot::{BootCollection, KERNEL},
    fixups::{Level, Pointer, Signature},
    relocatable::{self, Definition, Kind, Object, Target},
};

/// A kext's segments, in the order its Mach-O header lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Region {
    Text,
    TextExec,
    Data,
    DataConst,
}

impl Region {
    pub const ALL: [Self; 4] = [Self::Text, Self::TextExec, Self::Data, Self::DataConst];

    pub fn name(self) -> &'static str {
        match self {
            Self::Text => "__TEXT",
            Self::TextExec => "__TEXT_EXEC",
            Self::Data => "__DATA",
            Self::DataConst => "__DATA_CONST",
        }
    }

    /// The protection Apple's collections give the kext's own segment
    /// command; the collection's segment decides the mapping.
    pub fn protection(self) -> u32 {
        match self {
            Self::Text => 1,
            Self::TextExec => 5,
            Self::Data | Self::DataConst => 3,
        }
    }

    /// Where an object's section goes, or `None` for unwind and debug
    /// metadata, which kernel code carries none of.
    fn of(section: &relocatable::Section<'_>) -> Result<Option<Self>> {
        Ok(Some(
            match (section.segment.as_str(), section.name.as_str()) {
                ("__LD", "__compact_unwind") | ("__TEXT", "__eh_frame") | ("__DWARF", _) => {
                    return Ok(None);
                }
                ("__TEXT", _) if section.is_code() => Self::TextExec,
                ("__TEXT", _) => Self::Text,
                ("__DATA", "__const" | "__mod_init_func" | "__mod_term_func")
                | ("__DATA_CONST", _) => Self::DataConst,
                ("__DATA", _) => Self::Data,
                (segment, name) => {
                    return Err(
                        refuse!("{segment},{name} has no place in a kext", segment, name).into(),
                    );
                }
            },
        ))
    }
}

#[derive(Debug)]
pub struct Section {
    pub region: Region,
    pub name: String,
    pub flags: u32,
    /// log2 of its alignment.
    pub align: u32,
    pub bytes: Vec<u8>,
    /// Assigned by the collection's layout.
    pub address: u64,
}

/// What a reference resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Value {
    Local {
        section: usize,
        offset: u64,
    },
    /// An unslid boot-collection address.
    Boot(u64),
    Absolute(u64),
}

/// A vtable in an object section, between object addresses.
struct Vtable {
    object: usize,
    section: usize,
    start: u64,
    end: u64,
}

/// What a pointer-sized slot holds.
enum Slot {
    Fixup(Pointer),
    Raw(u64),
}

const AUTH_STUB_BYTES: usize = 16;
/// `ldr x16, [x17]`.
const LDR_X16_X17: u32 = 0xf940_0230;
/// `braa x16, x17`.
const BRAA_X16_X17: u32 = 0xd71f_0a11;
/// `adrp x17, 0`.
const ADRP_X17: u32 = 0x9000_0011;
/// `add x17, x17, #0`.
const ADD_X17_X17: u32 = 0x9100_0231;
/// Instruction key A: what `braa` authenticates with.
const KEY_IA: u8 = 0;

pub struct Unit<'a> {
    pub identifier: String,
    pub info: Dictionary,
    pub bundle_path: &'a str,
    pub uuid: [u8; 16],
    objects: Vec<Object<'a>>,
    /// Each object section's output section and offset, `None` if dropped.
    placements: Vec<Vec<Option<(usize, u64)>>>,
    pub sections: Vec<Section>,
    /// The definition each external name binds to: (object, symbol).
    globals: BTreeMap<String, (usize, usize)>,
    /// What the boot collection's entries this kext links against define.
    imports: BTreeMap<String, u64>,
    /// `__got` slots, by what they hold.
    got: Vec<Value>,
    /// Boot-collection functions branched to, each through an
    /// `__auth_stubs` entry and its `__auth_got` slot.
    stubs: Vec<u64>,
    got_section: Option<usize>,
    stub_sections: Option<(usize, usize)>,
    /// Vtable slots bound to the superclass's entry rather than the symbol
    /// the object names, by (object, section, relocation offset).
    inherited: BTreeMap<(usize, usize, u64), Value>,
    /// Each region's addresses, assigned by the collection's layout; the
    /// `__TEXT` region starts with the kext's Mach-O header.
    pub ranges: [Range<u64>; 4],
}

impl<'a> Unit<'a> {
    pub fn new(kext: &'a Kext<'a>, boot: &BootCollection<'_>) -> Result<Self> {
        let info = plist::parse(kext.info)?
            .into_dictionary()
            .ok_or(refuse!("Info.plist is not a dictionary"))?;
        let identifier = info
            .get("CFBundleIdentifier")
            .and_then(plist::Value::as_string)
            .ok_or(refuse!("Info.plist has no CFBundleIdentifier"))?
            .to_owned();
        let context = || refuse!("linking {identifier}", identifier);
        let objects = kext
            .objects
            .iter()
            .enumerate()
            .map(|(index, data)| {
                let object =
                    relocatable::parse(data).within(|| refuse!("reading object {index}", index))?;
                require!(object.is_arm64e(), "object {index} is not arm64e", index);
                Ok(object)
            })
            .collect::<Result<Vec<_>>>()
            .within(context)?;
        let mut unit = Self {
            imports: imports(&info, boot).within(context)?,
            identifier: identifier.clone(),
            info,
            bundle_path: &kext.bundle_path,
            uuid: kext.uuid(),
            objects,
            placements: Vec::new(),
            sections: Vec::new(),
            globals: BTreeMap::new(),
            got: Vec::new(),
            stubs: Vec::new(),
            got_section: None,
            stub_sections: None,
            inherited: BTreeMap::new(),
            ranges: Default::default(),
        };
        unit.place().within(context)?;
        unit.bind().within(context)?;
        unit.inherit(boot).within(context)?;
        unit.synthesize().within(context)?;
        Ok(unit)
    }

    /// Merges the objects' sections into the kext's, by region and name.
    fn place(&mut self) -> Result<()> {
        for object in &self.objects {
            let mut placements = Vec::with_capacity(object.sections.len());
            for input in &object.sections {
                let Some(region) = Region::of(input)? else {
                    placements.push(None);
                    continue;
                };
                let index = match self
                    .sections
                    .iter()
                    .position(|section| section.region == region && section.name == input.name)
                {
                    Some(index) => index,
                    None => {
                        let mut flags = input.flags;
                        if input.zerofill {
                            // The collection holds every byte.
                            flags &= !macho::SECTION_TYPE;
                        }
                        self.sections.push(Section {
                            region,
                            name: input.name.clone(),
                            flags,
                            align: 0,
                            bytes: Vec::new(),
                            address: 0,
                        });
                        self.sections.len() - 1
                    }
                };
                let output = &mut self.sections[index];
                require!(
                    input.align <= 14,
                    "{section} aligns past a page",
                    section = input.name
                );
                output.align = output.align.max(input.align);
                let offset = output.bytes.len().next_multiple_of(1 << input.align);
                output.bytes.resize(offset, 0);
                if input.zerofill {
                    output
                        .bytes
                        .resize(offset + fit::<usize, _>(input.size, "a section's size")?, 0);
                } else {
                    output.bytes.extend_from_slice(input.data);
                }
                placements.push(Some((index, offset as u64)));
            }
            self.placements.push(placements);
        }
        Ok(())
    }

    /// Binds each external name to one definition: a strong definition
    /// overrides weak ones, and the first weak one wins among them.
    fn bind(&mut self) -> Result<()> {
        for (object_index, object) in self.objects.iter().enumerate() {
            for (symbol_index, symbol) in object.symbols.iter().enumerate() {
                let defined = matches!(
                    symbol.definition,
                    Definition::Section { .. } | Definition::Absolute(_)
                );
                if !symbol.external || !defined {
                    continue;
                }
                match self.globals.get(&symbol.name) {
                    None => {}
                    Some(&(other, index)) => {
                        let existing = &self.objects[other].symbols[index];
                        require!(
                            existing.weak || symbol.weak,
                            "{symbol} is defined twice",
                            symbol = symbol.name
                        );
                        if symbol.weak || !existing.weak {
                            continue;
                        }
                    }
                }
                self.globals
                    .insert(symbol.name.clone(), (object_index, symbol_index));
            }
        }
        require!(
            self.globals.contains_key("_kmod_info"),
            "the kext defines no kmod_info"
        );
        Ok(())
    }

    /// Adds the `__got` slots and the `__auth_stubs` with their
    /// `__auth_got` slots its references need.
    fn synthesize(&mut self) -> Result<()> {
        for object in 0..self.objects.len() {
            for section in 0..self.objects[object].sections.len() {
                if self.placements[object][section].is_none() {
                    continue;
                }
                for relocation in &self.objects[object].sections[section].relocations {
                    match relocation.kind {
                        Kind::GotPage21 | Kind::GotPageOffset12 => {
                            let value = self.resolve(object, relocation.target)?;
                            if !self.got.contains(&value) {
                                self.got.push(value);
                            }
                        }
                        Kind::Branch26 => {
                            if let Value::Boot(address) = self.resolve(object, relocation.target)?
                                && !self.stubs.contains(&address)
                            {
                                self.stubs.push(address);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        let mut add = |region, name: &str, flags, align, length| {
            self.sections.push(Section {
                region,
                name: name.to_owned(),
                flags,
                align,
                bytes: vec![0; length],
                address: 0,
            });
            self.sections.len() - 1
        };
        if !self.stubs.is_empty() {
            let code = macho::S_ATTR_PURE_INSTRUCTIONS | macho::S_ATTR_SOME_INSTRUCTIONS;
            let stubs = add(
                Region::TextExec,
                "__auth_stubs",
                code,
                2,
                AUTH_STUB_BYTES * self.stubs.len(),
            );
            let slots = add(Region::DataConst, "__auth_got", 0, 3, 8 * self.stubs.len());
            self.stub_sections = Some((stubs, slots));
        }
        if !self.got.is_empty() {
            self.got_section = Some(add(Region::DataConst, "__got", 0, 3, 8 * self.got.len()));
        }
        Ok(())
    }

    /// The sections in the order the kext's header lists them.
    pub fn section_order(&self) -> Vec<usize> {
        let mut order: Vec<usize> = (0..self.sections.len()).collect();
        order.sort_by_key(|&index| self.sections[index].region);
        order
    }

    pub fn kmod_info(&self) -> Result<u64> {
        let (object, symbol) = self.globals["_kmod_info"];
        let value = self.define(object, symbol)?;
        self.address(value)
    }

    fn resolve(&self, object: usize, target: Target) -> Result<Value> {
        let Target::Symbol(index) = target else {
            return Err(
                refuse!("a section-relative reference where only pointers have them").into(),
            );
        };
        let symbol = &self.objects[object].symbols[index];
        if !symbol.external {
            return self.define(object, index);
        }
        if let Some(&(object, index)) = self.globals.get(&symbol.name) {
            return self.define(object, index);
        }
        if let Some(&address) = self.imports.get(&symbol.name) {
            return Ok(Value::Boot(address));
        }
        match symbol.definition {
            Definition::Undefined { weak: true } => Ok(Value::Absolute(0)),
            _ => Err(refuse!(
                "{symbol} is undefined: neither the kext nor the libraries it lists define it",
                symbol = symbol.name
            )
            .into()),
        }
    }

    fn define(&self, object: usize, index: usize) -> Result<Value> {
        let symbol = &self.objects[object].symbols[index];
        match symbol.definition {
            Definition::Section { section, address } => self
                .locate(object, section, address)
                .within(|| refuse!("defining {symbol}", symbol = symbol.name)),
            Definition::Absolute(value) => Ok(Value::Absolute(value)),
            Definition::Undefined { .. } | Definition::Debug => {
                Err(refuse!("{symbol} is not a definition", symbol = symbol.name).into())
            }
        }
    }

    /// The output location of `address` in an object's section.
    fn locate(&self, object: usize, section: usize, address: u64) -> Result<Value> {
        let input = &self.objects[object].sections[section];
        let (output, offset) = self.placements[object][section].ok_or_else(|| {
            refuse!(
                "a reference into {segment},{section}, which kexts drop",
                segment = input.segment,
                section = input.name
            )
        })?;
        let within = address
            .checked_sub(input.address)
            .filter(|&within| within <= input.size)
            .ok_or_else(|| {
                refuse!(
                    "{address:#x} lies outside {section}",
                    address,
                    section = input.name
                )
            })?;
        Ok(Value::Local {
            section: output,
            offset: offset + within,
        })
    }

    fn address(&self, value: Value) -> Result<u64> {
        match value {
            Value::Local { section, offset } => Ok(self.sections[section].address + offset),
            Value::Boot(_) | Value::Absolute(_) => {
                Err(refuse!("{value} is not in the kext", ?value).into())
            }
        }
    }

    fn slot(
        &self,
        value: Value,
        addend: i64,
        boot: u64,
        signature: Option<Signature>,
    ) -> Result<Slot> {
        let (level, target) = match value {
            Value::Local { .. } => (Level::Auxiliary, self.address(value)?),
            Value::Boot(address) => (Level::Boot, address - boot),
            Value::Absolute(address) => {
                let raw = address.wrapping_add_signed(addend);
                require!(
                    signature.is_none() || raw == 0,
                    "a signed pointer to the absolute address {raw:#x}",
                    raw
                );
                return Ok(Slot::Raw(raw));
            }
        };
        let target = target
            .checked_add_signed(addend)
            .ok_or(refuse!("a pointer before its collection"))?;
        Ok(Slot::Fixup(Pointer {
            level,
            target,
            signature,
        }))
    }

    fn stub(&self, address: u64) -> Result<u64> {
        let (stubs, _) = self.stub_sections.ok_or(refuse!("no stubs"))?;
        let index = self
            .stubs
            .iter()
            .position(|&stub| stub == address)
            .ok_or(refuse!("no stub"))?;
        Ok(self.sections[stubs].address + (AUTH_STUB_BYTES * index) as u64)
    }

    /// Applies every relocation now that the collection is laid out,
    /// recording the pointers XNU fixes up by their addresses.
    pub fn relocate(&mut self, boot: u64, pointers: &mut BTreeMap<u64, Pointer>) -> Result<()> {
        self.fill_tables(boot, pointers)
            .within(|| refuse!("linking {kext}", kext = self.identifier))?;
        for object in 0..self.objects.len() {
            for section in 0..self.objects[object].sections.len() {
                if self.placements[object][section].is_none() {
                    continue;
                }
                let input = &self.objects[object].sections[section];
                let name = format!("{},{}", input.segment, input.name);
                for relocation in input.relocations.clone() {
                    self.apply(object, section, relocation, boot, pointers)
                        .within(|| {
                            refuse!(
                                "relocating {name}+{offset:#x} in {kext}",
                                name,
                                offset = relocation.offset,
                                kext = self.identifier
                            )
                        })?;
                }
            }
        }
        Ok(())
    }

    fn fill_tables(&mut self, boot: u64, pointers: &mut BTreeMap<u64, Pointer>) -> Result<()> {
        if let Some(got) = self.got_section {
            for index in 0..self.got.len() {
                let slot = self.slot(self.got[index], 0, boot, None)?;
                self.store(got, 8 * index as u64, slot, pointers)?;
            }
        }
        if let Some((stubs, slots)) = self.stub_sections {
            for index in 0..self.stubs.len() {
                let slot_offset = 8 * index as u64;
                let signature = Signature {
                    key: KEY_IA,
                    address_diversity: true,
                    diversity: 0,
                };
                let slot = self.slot(Value::Boot(self.stubs[index]), 0, boot, Some(signature))?;
                self.store(slots, slot_offset, slot, pointers)?;
                let stub = self.sections[stubs].address + (AUTH_STUB_BYTES * index) as u64;
                let target = self.sections[slots].address + slot_offset;
                let code = [
                    page(ADRP_X17, stub, target)?,
                    page_offset(ADD_X17_X17, target)?,
                    LDR_X16_X17,
                    BRAA_X16_X17,
                ];
                let start = AUTH_STUB_BYTES * index;
                for (word, instruction) in code.into_iter().enumerate() {
                    let at = start + 4 * word;
                    self.sections[stubs].bytes[at..at + 4]
                        .copy_from_slice(&instruction.to_le_bytes());
                }
            }
        }
        Ok(())
    }

    fn store(
        &mut self,
        section: usize,
        offset: u64,
        slot: Slot,
        pointers: &mut BTreeMap<u64, Pointer>,
    ) -> Result<()> {
        let address = self.sections[section].address + offset;
        let at: usize = fit(offset, "a relocation offset")?;
        let field = self.sections[section]
            .bytes
            .get_mut(at..at + 8)
            .ok_or(refuse!("a pointer past its section"))?;
        match slot {
            Slot::Raw(raw) => field.copy_from_slice(&raw.to_le_bytes()),
            Slot::Fixup(pointer) => {
                field.fill(0);
                require!(
                    pointers.insert(address, pointer).is_none(),
                    "two pointers at {address:#x}",
                    address
                );
            }
        }
        Ok(())
    }

    fn apply(
        &mut self,
        object: usize,
        input: usize,
        relocation: relocatable::Relocation,
        boot: u64,
        pointers: &mut BTreeMap<u64, Pointer>,
    ) -> Result<()> {
        let (section, start) =
            self.placements[object][input].ok_or(refuse!("a dropped section"))?;
        let offset = start + relocation.offset;
        let place = self.sections[section].address + offset;
        let instruction = |unit: &Self| -> Result<u32> {
            let at: usize = fit(offset, "a relocation offset")?;
            let bytes = unit.sections[section]
                .bytes
                .get(at..at + 4)
                .ok_or(refuse!("an instruction past its section"))?;
            Ok(u32::from_le_bytes(
                bytes
                    .try_into()
                    .map_err(|_| refuse!("an instruction past its section"))?,
            ))
        };
        let patched = match relocation.kind {
            Kind::Pointer | Kind::Authenticated { .. } => {
                let signature = match relocation.kind {
                    Kind::Authenticated {
                        key,
                        address_diversity,
                        diversity,
                    } => Some(Signature {
                        key,
                        address_diversity,
                        diversity,
                    }),
                    _ => None,
                };
                let (value, addend) = match relocation.target {
                    // The bytes in place hold the target's object address.
                    Target::Section(target) => {
                        (self.locate(object, target, relocation.addend as u64)?, 0)
                    }
                    Target::Symbol(_) => {
                        let inherited = self.inherited.get(&(object, input, relocation.offset));
                        let value = match inherited {
                            Some(&value) => value,
                            None => self.resolve(object, relocation.target)?,
                        };
                        (value, relocation.addend)
                    }
                };
                let slot = self.slot(value, addend, boot, signature)?;
                return self.store(section, offset, slot, pointers);
            }
            Kind::Difference { minus, bytes } => {
                let plus = self.address(self.resolve(object, relocation.target)?)?;
                let minus = self.address(self.resolve(object, minus)?)?;
                let difference = (plus as i64)
                    .wrapping_sub(minus as i64)
                    .wrapping_add(relocation.addend);
                let at: usize = fit(offset, "a relocation offset")?;
                let field = &mut self.sections[section].bytes[at..at + usize::from(bytes)];
                if bytes == 4 {
                    let narrow: i32 = fit(difference, "a 32-bit difference")?;
                    field.copy_from_slice(&narrow.to_le_bytes());
                } else {
                    field.copy_from_slice(&difference.to_le_bytes());
                }
                return Ok(());
            }
            Kind::Branch26 => {
                let target = match self.resolve(object, relocation.target)? {
                    Value::Boot(address) => self.stub(address)?,
                    value => self.address(value)?,
                };
                branch(
                    instruction(self)?,
                    place,
                    target.wrapping_add_signed(relocation.addend),
                )?
            }
            Kind::Page21 | Kind::PageOffset12 => {
                let target = self
                    .address(self.resolve(object, relocation.target)?)
                    .within(|| refuse!("a page reference out of the kext"))?
                    .wrapping_add_signed(relocation.addend);
                if relocation.kind == Kind::Page21 {
                    page(instruction(self)?, place, target)?
                } else {
                    page_offset(instruction(self)?, target)?
                }
            }
            Kind::GotPage21 | Kind::GotPageOffset12 => {
                require!(relocation.addend == 0, "a GOT reference with an addend");
                let value = self.resolve(object, relocation.target)?;
                let got = self.got_section.ok_or(refuse!("no GOT"))?;
                let index = self
                    .got
                    .iter()
                    .position(|&slot| slot == value)
                    .ok_or(refuse!("no GOT slot"))?;
                let target = self.sections[got].address + 8 * index as u64;
                if relocation.kind == Kind::GotPage21 {
                    page(instruction(self)?, place, target)?
                } else {
                    page_offset(instruction(self)?, target)?
                }
            }
        };
        let at: usize = fit(offset, "a relocation offset")?;
        self.sections[section].bytes[at..at + 4].copy_from_slice(&patched.to_le_bytes());
        Ok(())
    }

    /// Binds each vtable slot a kext class inherits to its superclass's
    /// entry, as Apple's collection linker does: the kernel's classes may
    /// override methods, or fill reserved slots, that the kext's headers say
    /// they inherit. A method in a slot the kernel still reserves means the
    /// kext was built for a newer kernel, and is refused.
    fn inherit(&mut self, boot: &BootCollection<'_>) -> Result<()> {
        let vtables = self.vtables();
        let mut done = BTreeSet::new();
        let mut names: Vec<&String> = vtables.keys().collect();
        names.sort();
        for name in names {
            self.inherit_vtable(name, &vtables, boot, &mut done)?;
        }
        Ok(())
    }

    /// The kext's vtables by name, each ending at the next symbol in its
    /// section.
    fn vtables(&self) -> BTreeMap<String, Vtable> {
        let mut vtables = BTreeMap::new();
        for (object_index, object) in self.objects.iter().enumerate() {
            for (index, symbol) in object.symbols.iter().enumerate() {
                let Definition::Section { section, address } = symbol.definition else {
                    continue;
                };
                let bound = !symbol.external
                    || self.globals.get(&symbol.name) == Some(&(object_index, index));
                if !symbol.name.starts_with("__ZTV")
                    || !bound
                    || self.placements[object_index][section].is_none()
                {
                    continue;
                }
                let input = &object.sections[section];
                let end = object
                    .symbols
                    .iter()
                    .filter_map(|other| match other.definition {
                        Definition::Section {
                            section: other_section,
                            address: other_address,
                        } if other_section == section && other_address > address => {
                            Some(other_address)
                        }
                        _ => None,
                    })
                    .min()
                    .unwrap_or(input.address + input.size);
                vtables.insert(
                    symbol.name.clone(),
                    Vtable {
                        object: object_index,
                        section,
                        start: address,
                        end,
                    },
                );
            }
        }
        vtables
    }

    fn inherit_vtable(
        &mut self,
        name: &str,
        vtables: &BTreeMap<String, Vtable>,
        boot: &BootCollection<'_>,
        done: &mut BTreeSet<String>,
    ) -> Result<()> {
        if !done.insert(name.to_owned()) {
            return Ok(());
        }
        let Some(parent) = self.parent(name)? else {
            return Ok(());
        };
        let parent_address = if vtables.contains_key(&parent) {
            self.inherit_vtable(&parent, vtables, boot, done)?;
            None
        } else {
            Some(*self.imports.get(&parent).ok_or_else(|| {
                refuse!(
                    "{name} derives from {parent}, which no library the kext lists exports",
                    name,
                    parent
                )
            })?)
        };
        let vtable = &vtables[name];
        let input = &self.objects[vtable.object].sections[vtable.section];
        let slots: Vec<_> = input
            .relocations
            .iter()
            .filter(|relocation| {
                (vtable.start..vtable.end).contains(&(input.address + relocation.offset))
                    && matches!(relocation.kind, Kind::Pointer | Kind::Authenticated { .. })
            })
            .copied()
            .collect();
        for relocation in slots {
            let Target::Symbol(index) = relocation.target else {
                continue;
            };
            let symbol = &self.objects[vtable.object].symbols[index].name;
            // The class overrides the slot, or it is null or pure.
            let child = self.resolve(vtable.object, relocation.target)?;
            if !matches!(child, Value::Boot(_)) || symbol == "___cxa_pure_virtual" {
                continue;
            }
            let offset = input.address + relocation.offset - vtable.start;
            let slot = offset / 8;
            let inherited = match parent_address {
                Some(address) => boot.pointer(address + offset)?.map(Value::Boot),
                None => self.slot_value(&vtables[&parent], offset)?,
            }
            .ok_or_else(|| {
                refuse!(
                    "{name} inherits slot {slot} from {parent}, which has none",
                    name,
                    slot,
                    parent
                )
            })?;
            if inherited == child {
                continue;
            }
            if let Value::Boot(address) = inherited
                && !symbol.contains("_RESERVED")
                && self
                    .imports
                    .iter()
                    .any(|(other, &at)| at == address && other.contains("_RESERVED"))
            {
                return Err(refuse!(
                    "{name} puts {symbol} in slot {slot}, which {parent} reserves in this kernel: \
                     the kext was built for a newer one",
                    name,
                    symbol,
                    slot,
                    parent
                )
                .into());
            }
            self.inherited.insert(
                (vtable.object, vtable.section, relocation.offset),
                inherited,
            );
        }
        Ok(())
    }

    /// The vtable of the class `vtable`'s class derives from, through the
    /// class's `superClass`, which points at the superclass's `gMetaClass`;
    /// `None` for a class outside the OSObject hierarchy.
    fn parent(&self, vtable: &str) -> Result<Option<String>> {
        let Some(class) = vtable_class(vtable) else {
            return Ok(None);
        };
        if class.ends_with("9MetaClass") {
            return Ok(Some("__ZTV11OSMetaClass".into()));
        }
        let member = format!("__ZN{class}10superClassE");
        let Some((object, index)) = self.globals.get(&member).copied() else {
            return Ok(None);
        };
        let Definition::Section { section, address } =
            self.objects[object].symbols[index].definition
        else {
            return Err(refuse!("{member} is not in a section", member).into());
        };
        let input = &self.objects[object].sections[section];
        let target = input
            .relocations
            .iter()
            .find(|relocation| input.address + relocation.offset == address)
            .map(|relocation| relocation.target)
            .ok_or_else(|| refuse!("{member} points nowhere", member))?;
        let Target::Symbol(target) = target else {
            return Err(refuse!("{member} points into a section", member).into());
        };
        let target = &self.objects[object].symbols[target].name;
        let parent = target
            .strip_prefix("__ZN")
            .and_then(|rest| rest.strip_suffix("10gMetaClassE"))
            .ok_or_else(|| {
                refuse!(
                    "{member} points at {target}, which is no gMetaClass",
                    member,
                    target
                )
            })?;
        Ok(Some(vtable_name(parent)))
    }

    /// What a kext vtable's slot at `offset` holds, once inherited.
    fn slot_value(&self, vtable: &Vtable, offset: u64) -> Result<Option<Value>> {
        let input = &self.objects[vtable.object].sections[vtable.section];
        let Some(relocation) = input
            .relocations
            .iter()
            .find(|relocation| input.address + relocation.offset == vtable.start + offset)
        else {
            return Ok(None);
        };
        let key = (vtable.object, vtable.section, relocation.offset);
        match self.inherited.get(&key) {
            Some(&value) => Ok(Some(value)),
            None => self.resolve(vtable.object, relocation.target).map(Some),
        }
    }

    /// The kext's symbols for its symbol table: named locals, then the
    /// external definitions it binds to, each as (name, external, section
    /// index, address).
    pub fn symbols(&self) -> Result<Vec<(&str, bool, usize, u64)>> {
        let mut locals = Vec::new();
        let mut externals = Vec::new();
        for (object, symbols) in self
            .objects
            .iter()
            .map(|object| &object.symbols)
            .enumerate()
        {
            for (index, symbol) in symbols.iter().enumerate() {
                let Definition::Section { section, .. } = symbol.definition else {
                    continue;
                };
                let temporary = symbol.name.is_empty() || symbol.name.starts_with(['l', 'L']);
                if self.placements[object][section].is_none() || (!symbol.external && temporary) {
                    continue;
                }
                if symbol.external && self.globals.get(&symbol.name) != Some(&(object, index)) {
                    continue;
                }
                let value = self.define(object, index)?;
                let Value::Local { section, .. } = value else {
                    unreachable!("section symbols are local");
                };
                let entry = (
                    symbol.name.as_str(),
                    symbol.external,
                    section,
                    self.address(value)?,
                );
                if symbol.external {
                    externals.push(entry);
                } else {
                    locals.push(entry);
                }
            }
        }
        externals.sort_by_key(|entry| entry.0);
        locals.extend(externals);
        Ok(locals)
    }
}

/// The symbols the boot-collection entries a kext lists in
/// `OSBundleLibraries` define; every `com.apple.kpi.*` interface is the
/// kernel's.
fn imports(info: &Dictionary, boot: &BootCollection<'_>) -> Result<BTreeMap<String, u64>> {
    let libraries = info
        .get("OSBundleLibraries")
        .and_then(plist::Value::as_dictionary)
        .ok_or(refuse!("Info.plist has no OSBundleLibraries"))?;
    let mut entries = Vec::new();
    for library in libraries.keys() {
        if boot.contains(library) {
            entries.push(library.as_str());
        } else if library.starts_with("com.apple.kpi.") {
            entries.push(KERNEL);
        } else {
            return Err(refuse!(
                "it links against {library}, which the boot collection does not contain",
                library
            )
            .into());
        }
    }
    // The kernel's definitions come first, then each library's in name order.
    entries.sort_by_key(|&entry| (entry != KERNEL, entry));
    entries.dedup();
    let mut imports = BTreeMap::new();
    for entry in entries {
        for (name, address) in boot.exports(entry)? {
            imports.entry(name).or_insert(address);
        }
    }
    Ok(imports)
}

/// The mangled class a vtable symbol names: `8StelaGPU` for
/// `__ZTV8StelaGPU`, `3foo3Bar` for `__ZTVN3foo3BarE`.
fn vtable_class(vtable: &str) -> Option<&str> {
    let class = vtable.strip_prefix("__ZTV")?;
    Some(
        class
            .strip_prefix('N')
            .and_then(|nested| nested.strip_suffix('E'))
            .unwrap_or(class),
    )
}

/// The vtable symbol of a mangled class name.
fn vtable_name(class: &str) -> String {
    let digits = class.bytes().take_while(u8::is_ascii_digit).count();
    let simple = class[..digits]
        .parse::<usize>()
        .is_ok_and(|length| digits + length == class.len());
    if simple {
        format!("__ZTV{class}")
    } else {
        format!("__ZTVN{class}E")
    }
}

/// A name-based (version 8) UUID from a digest of its inputs.
pub fn uuid<'b>(parts: impl IntoIterator<Item = &'b [u8]>) -> [u8; 16] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let mut uuid: [u8; 16] = digest[..16].try_into().expect("16 of 32 bytes");
    uuid[6] = (uuid[6] & 0x0f) | 0x80;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    uuid
}

/// `B`/`BL` to `target`.
pub(crate) fn branch(instruction: u32, place: u64, target: u64) -> Result<u32> {
    let delta = target.wrapping_sub(place) as i64;
    require!(
        delta % 4 == 0 && (-(1 << 27)..1 << 27).contains(&delta),
        "a branch from {place:#x} cannot reach {target:#x}",
        place,
        target
    );
    Ok(instruction & 0xfc00_0000 | ((delta >> 2) as u32 & 0x03ff_ffff))
}

/// `ADRP` of `target`'s 4 KiB page.
pub(crate) fn page(instruction: u32, place: u64, target: u64) -> Result<u32> {
    let delta = ((target >> 12) as i64).wrapping_sub((place >> 12) as i64);
    require!(
        (-(1 << 20)..1 << 20).contains(&delta),
        "{target:#x} is out of ADRP's reach from {place:#x}",
        target,
        place
    );
    let delta = delta as u32;
    Ok(instruction & 0x9f00_001f | (delta & 3) << 29 | (delta >> 2 & 0x7_ffff) << 5)
}

/// The low 12 bits of `target` in an `ADD` or a load or store's scaled
/// unsigned offset.
pub(crate) fn page_offset(instruction: u32, target: u64) -> Result<u32> {
    let scale = if instruction & 0x1f00_0000 == 0x1100_0000 {
        0
    } else if instruction & 0x3b00_0000 == 0x3900_0000 {
        let vector = instruction >> 26 & 1 != 0;
        if vector && instruction >> 23 & 1 != 0 {
            4
        } else {
            instruction >> 30
        }
    } else {
        return Err(refuse!(
            "a page offset in {instruction:#010x}, which is neither an ADD nor a load or store",
            instruction
        )
        .into());
    };
    let offset = (target & 0xfff) as u32;
    require!(
        offset.trailing_zeros() >= scale,
        "{target:#x} is misaligned for its {bytes}-byte access",
        target,
        bytes = 1 << scale
    );
    Ok(instruction & !(0xfff << 10) | (offset >> scale) << 10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_branches_pages_and_scaled_offsets() -> Result<()> {
        // bl +0x100
        assert_eq!(branch(0x9400_0000, 0x1000, 0x1100)?, 0x9400_0040);
        // bl -4
        assert_eq!(branch(0x9400_0000, 0x1000, 0xffc)?, 0x97ff_ffff);
        assert!(branch(0x9400_0000, 0, 1 << 27).is_err());
        // adrp x17, +2 pages
        assert_eq!(page(ADRP_X17, 0x1000, 0x3abc)?, 0x9000_0011 | 2 << 29);
        // adrp x17, +4 pages
        assert_eq!(page(ADRP_X17, 0x1000, 0x5000)?, 0x9000_0011 | 1 << 5);
        assert_eq!(page_offset(ADD_X17_X17, 0x3abc)?, ADD_X17_X17 | 0xabc << 10);
        // ldr x0, [x1, #off] scales by 8.
        assert_eq!(page_offset(0xf940_0020, 0x2018)?, 0xf940_0020 | 3 << 10);
        assert!(page_offset(0xf940_0020, 0x2014).is_err());
        // ldr q0, [x1, #off] scales by 16.
        assert_eq!(page_offset(0x3dc0_0020, 0x2020)?, 0x3dc0_0020 | 2 << 10);
        // ldrb w0, [x1, #off] does not scale.
        assert_eq!(page_offset(0x3940_0020, 0x2003)?, 0x3940_0020 | 3 << 10);
        assert!(page_offset(0xd503_201f, 0).is_err());
        Ok(())
    }

    #[test]
    fn names_vtables_of_simple_and_nested_classes() {
        assert_eq!(vtable_class("__ZTV8StelaGPU"), Some("8StelaGPU"));
        assert_eq!(vtable_class("__ZTVN3foo3BarE"), Some("3foo3Bar"));
        assert_eq!(vtable_class("__ZN8StelaGPU4freeEv"), None);
        assert_eq!(vtable_name("13IOAccelerator"), "__ZTV13IOAccelerator");
        assert_eq!(vtable_name("3foo3Bar"), "__ZTVN3foo3BarE");
    }

    #[test]
    fn uuids_are_version_8() {
        let uuid = uuid([&b"input"[..]]);
        assert_eq!(uuid[6] >> 4, 8);
        assert_eq!(uuid[8] >> 6, 2);
    }
}
