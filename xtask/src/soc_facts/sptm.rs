//! SPTM's accesses to the CPU implementation blocks of each `/cpus` node
//! (`cpu-impl-reg`, `acc-impl-reg`, `cpm-impl-reg`), and the lockdown pairs
//! among them.
//!
//! Method, checked against the T8112 sequence `docs/design/system.md`
//! describes:
//!
//! 1. SPTM looks each property up by name and stores the block's mapped
//!    address in its per-CPU data: after the `cpu-impl-reg` lookup (an ADRP
//!    and ADD of the name string), the first three `STR X0, [Xn, #imm]`
//!    following a call are the `cpu-impl-reg`, `acc-impl-reg` and
//!    `cpm-impl-reg` fields, in the order SPTM looks the names up.
//! 2. Every `LDR Xd, [Xn, #field]` of one of those fields starts a block
//!    pointer. The pointer, constants (MOVZ, MOVN, MOVK, ORR immediate and
//!    the two alternatives of a conditional select) and loaded values are
//!    followed through `__text` in address order until a register is
//!    redefined or a call clobbers it, and each load or store through a
//!    block pointer is an access: its offset, width and, for a store, the
//!    value written (a constant, or the value read from the same register
//!    ORed with a constant).
//! 3. A lockdown pair is an offset C of one block where SPTM ORs bit 0 into
//!    C after writing C + 8 (`platform::apple::lockdown`).
//!
//! The trace is linear, so a value is what the instructions before it in
//! address order leave; values that reach a store through a branch from
//! elsewhere are reported as alternatives or not at all.
use super::{
    a64::{self, Insn, Logical, MoveKind, Select, ZR},
    macho,
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};

/// The ADT properties naming the blocks, in the order SPTM looks them up.
pub const BLOCKS: [&str; 3] = ["cpu-impl-reg", "acc-impl-reg", "cpm-impl-reg"];
/// How far after the `cpu-impl-reg` lookup the field stores must appear.
const FIELD_WINDOW: usize = 200;
/// The lockdown MASK's offset from its CONTROL.
const MASK_OFFSET: u64 = 8;
/// CONTROL's lock bit.
const LOCK: u64 = 1;
/// Calls clobber X0 to X18 (AAPCS64 caller-saved registers).
const CALLER_SAVED: usize = 19;
const REGISTERS: usize = 32;
/// Load/store register pair, every addressing form (Arm's
/// `op0 x0x1 op2` group, bits 29:27 = 101, bit 25 = 0).
const PAIR_MASK: u32 = 0x3a00_0000;
const PAIR: u32 = 0x2800_0000;

/// One block's per-CPU field and the instruction that fills it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub block: &'static str,
    pub offset: u64,
    pub address: u64,
}

/// What a store through a block pointer writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Written {
    /// One of these constants.
    Constant(Vec<u64>),
    /// The value read from this offset, ORed with one of these constants.
    OrRead(Vec<u64>),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Access {
    pub block: &'static str,
    pub offset: u64,
    pub bytes: u8,
    /// `None` for a load.
    pub written: Option<Written>,
    pub address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tracked {
    Unknown,
    Page(u64),
    Constant(Vec<u64>),
    Block(usize, u64),
    Loaded(usize, u64),
    OrRead(usize, u64, Vec<u64>),
}

fn constant_of(state: &[Tracked; REGISTERS], register: u8) -> Option<Vec<u64>> {
    if register == ZR {
        return Some(vec![0]);
    }
    match &state[usize::from(register)] {
        Tracked::Constant(values) => Some(values.clone()),
        _ => None,
    }
}

fn width_mask(wide: bool) -> u64 {
    if wide { u64::MAX } else { u64::from(u32::MAX) }
}

/// The virtual address of the first NUL-terminated `name` in the image's
/// `__TEXT,__cstring`.
fn string_address(image: &macho::Image, data: &[u8], name: &str) -> Result<u64> {
    let section = image
        .section("__TEXT", "__cstring")
        .context("SPTM has no __TEXT,__cstring")?;
    let start = section.offset as usize;
    let strings = &data[start..start + section.size as usize];
    let mut needle = name.as_bytes().to_vec();
    needle.push(0);
    let found = strings
        .windows(needle.len())
        .enumerate()
        .find(|(index, window)| *window == needle && (*index == 0 || strings[index - 1] == 0))
        .map(|(index, _)| index)
        .with_context(|| format!("SPTM has no {name} string"))?;
    Ok(section.address + found as u64)
}

fn text(image: &macho::Image, data: &[u8]) -> Result<Vec<(u64, u32, Insn)>> {
    let section = image
        .section("__TEXT_EXEC", "__text")
        .context("SPTM has no __TEXT_EXEC,__text")?;
    let start = section.offset as usize;
    Ok(data[start..start + section.size as usize]
        .as_chunks::<4>()
        .0
        .iter()
        .enumerate()
        .map(|(index, word)| {
            let address = section.address + 4 * index as u64;
            let word = u32::from_le_bytes(*word);
            (address, word, a64::decode(address, word))
        })
        .collect())
}

/// The per-CPU fields holding each block's mapped address.
pub fn fields(image: &macho::Image, data: &[u8]) -> Result<Vec<Field>> {
    let code = text(image, data)?;
    let name = string_address(image, data, BLOCKS[0])?;
    let mut pages = [None; REGISTERS];
    let mut lookup = None;
    for (index, (_, _, insn)) in code.iter().enumerate() {
        match *insn {
            Insn::Adrp { rd, page } => pages[usize::from(rd)] = Some(page),
            Insn::AddImmediate { rd, rn, imm, wide } => {
                let page = pages[usize::from(rn)].take();
                if wide && page.map(|page| page.wrapping_add_signed(imm)) == Some(name) {
                    lookup = Some(index);
                    break;
                }
                pages[usize::from(rd)] = None;
            }
            _ => {}
        }
    }
    let lookup = lookup.context("no ADRP/ADD of the cpu-impl-reg string")?;
    let mut called = false;
    let mut found = Vec::new();
    for (address, _, insn) in code.iter().skip(lookup).take(FIELD_WINDOW) {
        match *insn {
            Insn::Call { .. } => called = true,
            Insn::Store {
                rt: 0,
                offset,
                bytes: 8,
                ..
            } if called => {
                found.push(Field {
                    block: BLOCKS[found.len()],
                    offset: offset as u64,
                    address: *address,
                });
                called = false;
                if found.len() == BLOCKS.len() {
                    break;
                }
            }
            _ => {}
        }
    }
    ensure!(
        found.len() == BLOCKS.len(),
        "found {} of the impl-reg fields",
        found.len()
    );
    for pair in found.windows(2) {
        ensure!(
            pair[1].offset == pair[0].offset + 8,
            "impl-reg fields {:#x} and {:#x} are not adjacent",
            pair[0].offset,
            pair[1].offset
        );
    }
    Ok(found)
}

/// Every access through a block pointer, in address order.
pub fn accesses(image: &macho::Image, data: &[u8], fields: &[Field]) -> Result<Vec<Access>> {
    let code = text(image, data)?;
    let mut state: [Tracked; REGISTERS] = core::array::from_fn(|_| Tracked::Unknown);
    let mut found = Vec::new();
    for (address, word, insn) in code {
        let define = |state: &mut [Tracked; REGISTERS], register: u8, value: Tracked| {
            if register != ZR {
                state[usize::from(register)] = value;
            }
        };
        match insn {
            Insn::Adrp { rd, page } => define(&mut state, rd, Tracked::Page(page)),
            Insn::Move {
                rd,
                kind,
                imm16,
                hw,
                wide,
            } => {
                let shift = 16 * u32::from(hw);
                let field = u64::from(imm16) << shift;
                let value = match kind {
                    MoveKind::Zeroed => Some(vec![field]),
                    MoveKind::Inverted => Some(vec![!field & width_mask(wide)]),
                    MoveKind::Kept => constant_of(&state, rd).map(|values| {
                        values
                            .into_iter()
                            .map(|v| (v & !(0xffff << shift) | field) & width_mask(wide))
                            .collect()
                    }),
                };
                define(
                    &mut state,
                    rd,
                    value.map_or(Tracked::Unknown, Tracked::Constant),
                );
            }
            Insn::LogicalImmediate {
                rd,
                rn,
                op: Logical::Orr,
                imm,
                wide,
            } => {
                let value = if rn == ZR {
                    Tracked::Constant(vec![imm])
                } else {
                    match &state[usize::from(rn)] {
                        Tracked::Loaded(block, offset) => {
                            Tracked::OrRead(*block, *offset, vec![imm])
                        }
                        Tracked::Constant(values) => Tracked::Constant(
                            values
                                .iter()
                                .map(|v| (v | imm) & width_mask(wide))
                                .collect(),
                        ),
                        _ => Tracked::Unknown,
                    }
                };
                define(&mut state, rd, value);
            }
            Insn::LogicalRegister {
                rd,
                rn,
                rm,
                op: Logical::Orr,
                inverted: false,
                shifted: false,
            } => {
                let loaded = |register: u8| match &state[usize::from(register)] {
                    Tracked::Loaded(block, offset) if register != ZR => Some((*block, *offset)),
                    _ => None,
                };
                let value = match (loaded(rn), loaded(rm)) {
                    (Some((block, offset)), _) => constant_of(&state, rm)
                        .map_or(Tracked::Unknown, |c| Tracked::OrRead(block, offset, c)),
                    (_, Some((block, offset))) => constant_of(&state, rn)
                        .map_or(Tracked::Unknown, |c| Tracked::OrRead(block, offset, c)),
                    _ if rn == ZR => state[usize::from(rm)].clone(),
                    _ => Tracked::Unknown,
                };
                define(&mut state, rd, value);
            }
            Insn::Select { rd, rn, rm, op } => {
                let first = constant_of(&state, rn);
                let second = constant_of(&state, rm).map(|values| {
                    values
                        .into_iter()
                        .map(|v| match op {
                            Select::Csel => v,
                            Select::Csinc => v.wrapping_add(1),
                            Select::Csinv => !v,
                            Select::Csneg => v.wrapping_neg(),
                        })
                        .collect::<Vec<_>>()
                });
                let value = match (first, second) {
                    (Some(mut first), Some(second)) => {
                        for v in second {
                            if !first.contains(&v) {
                                first.push(v);
                            }
                        }
                        Tracked::Constant(first)
                    }
                    _ => Tracked::Unknown,
                };
                define(&mut state, rd, value);
            }
            Insn::AddImmediate { rd, rn, imm, .. } => {
                let value = match &state[usize::from(rn)] {
                    Tracked::Block(block, offset) if rn != ZR => {
                        Tracked::Block(*block, offset.wrapping_add_signed(imm))
                    }
                    Tracked::Page(page) if rn != ZR => Tracked::Page(page.wrapping_add_signed(imm)),
                    _ => Tracked::Unknown,
                };
                define(&mut state, rd, value);
            }
            Insn::AddRegister { rd, rn, rm, shift } => {
                let value = match (&state[usize::from(rn)], constant_of(&state, rm)) {
                    (Tracked::Block(block, offset), Some(values)) if values.len() == 1 => {
                        Tracked::Block(*block, offset + (values[0] << shift))
                    }
                    _ => Tracked::Unknown,
                };
                define(&mut state, rd, value);
            }
            Insn::Load {
                rt,
                rn,
                offset,
                bytes,
            } => {
                let base = if rn == ZR {
                    &Tracked::Unknown
                } else {
                    &state[usize::from(rn)]
                };
                let value = match *base {
                    Tracked::Block(block, at) => {
                        let at = at.wrapping_add_signed(offset);
                        found.push(Access {
                            block: BLOCKS[block],
                            offset: at,
                            bytes,
                            written: None,
                            address,
                        });
                        Tracked::Loaded(block, at)
                    }
                    _ => match fields
                        .iter()
                        .position(|field| field.offset as i64 == offset)
                    {
                        Some(block) if bytes == 8 => Tracked::Block(block, 0),
                        _ => Tracked::Unknown,
                    },
                };
                define(&mut state, rt, value);
            }
            Insn::Store {
                rt,
                rn,
                offset,
                bytes,
            } => {
                if rn != ZR
                    && let Tracked::Block(block, at) = state[usize::from(rn)]
                {
                    let at = at.wrapping_add_signed(offset);
                    let written = match (rt, &state[usize::from(rt)]) {
                        (ZR, _) => Written::Constant(vec![0]),
                        (_, Tracked::Constant(values)) => Written::Constant(values.clone()),
                        (_, Tracked::OrRead(read_block, read, values))
                            if (*read_block, *read) == (block, at) =>
                        {
                            Written::OrRead(values.clone())
                        }
                        _ => Written::Unknown,
                    };
                    found.push(Access {
                        block: BLOCKS[block],
                        offset: at,
                        bytes,
                        written: Some(written),
                        address,
                    });
                }
            }
            Insn::Call { .. } => {
                for register in state.iter_mut().take(CALLER_SAVED) {
                    *register = Tracked::Unknown;
                }
            }
            Insn::System { read: true, rt, .. }
            | Insn::SystemInstruction { read: true, rt, .. } => {
                define(&mut state, rt, Tracked::Unknown)
            }
            Insn::LogicalImmediate { rd, .. } | Insn::LogicalRegister { rd, .. } => {
                define(&mut state, rd, Tracked::Unknown)
            }
            Insn::System { .. } | Insn::SystemInstruction { .. } | Insn::Other => {
                // An unmodeled word may write Rd (bits 4:0, the destination
                // of nearly every A64 data-processing and load word) and,
                // for a register pair, Rt2: forget what they held.
                define(&mut state, (word & 0x1f) as u8, Tracked::Unknown);
                if word & PAIR_MASK == PAIR {
                    define(&mut state, (word >> 10 & 0x1f) as u8, Tracked::Unknown);
                }
            }
        }
    }
    Ok(found)
}

/// One lockdown pair: the block, its CONTROL offset, the MASK value and the
/// CONTROL write, each with the access that shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lockdown {
    pub block: &'static str,
    pub control: u64,
    pub mask: Access,
    pub lock: Access,
}

/// The lockdown pairs among `accesses`: a store ORing bit 0 into an offset
/// after a store to the offset 8 above it.
pub fn lockdown(accesses: &[Access]) -> Vec<Lockdown> {
    let mut pairs: Vec<Lockdown> = Vec::new();
    for (index, lock) in accesses.iter().enumerate() {
        if lock.written != Some(Written::OrRead(vec![LOCK])) || lock.bytes != 8 {
            continue;
        }
        let Some(mask) = accesses[..index].iter().rev().find(|access| {
            access.block == lock.block
                && access.offset == lock.offset + MASK_OFFSET
                && access.written.is_some()
        }) else {
            continue;
        };
        if !pairs
            .iter()
            .any(|pair| pair.block == lock.block && pair.control == lock.offset)
        {
            pairs.push(Lockdown {
                block: lock.block,
                control: lock.offset,
                mask: mask.clone(),
                lock: lock.clone(),
            });
        }
    }
    pairs
}

fn hex(value: u64) -> String {
    format!("{value:#x}")
}

fn written_json(written: &Option<Written>) -> Value {
    match written {
        None => json!({ "kind": "read" }),
        Some(Written::Constant(values)) => {
            json!({ "kind": "write", "values": values.iter().copied().map(hex).collect::<Vec<_>>() })
        }
        Some(Written::OrRead(values)) => {
            json!({ "kind": "or-read", "values": values.iter().copied().map(hex).collect::<Vec<_>>() })
        }
        Some(Written::Unknown) => json!({ "kind": "write", "values": "unresolved" }),
    }
}

/// The SPTM facts of one build as JSON, each with its `__text` offset.
pub fn facts(data: &[u8]) -> Result<Value> {
    let image = macho::parse(data, 0)?;
    let text = image
        .section("__TEXT_EXEC", "__text")
        .context("SPTM has no __text")?
        .address;
    let evidence = |address: u64| -> Value {
        json!({
            "text_offset": hex(address - text),
            "file_offset": image.file_offset(address).map(hex),
        })
    };
    let fields = fields(&image, data)?;
    let accesses = accesses(&image, data, &fields)?;
    let pairs = lockdown(&accesses);
    if pairs.is_empty()
        && accesses
            .iter()
            .any(|a| a.written == Some(Written::OrRead(vec![LOCK])))
    {
        bail!("a lock bit is set without a MASK write before it");
    }
    Ok(json!({
        "impl_reg_fields": fields.iter().map(|field| json!({
            "block": field.block,
            "per_cpu_offset": hex(field.offset),
            "evidence": evidence(field.address),
        })).collect::<Vec<_>>(),
        "lockdown": pairs.iter().map(|pair| json!({
            "block": pair.block,
            "control": hex(pair.control),
            "mask": hex(pair.control + MASK_OFFSET),
            "mask_write": written_json(&pair.mask.written),
            "mask_evidence": evidence(pair.mask.address),
            "lock_evidence": evidence(pair.lock.address),
        })).collect::<Vec<_>>(),
        "impl_reg_accesses": accesses.iter().map(|access| json!({
            "block": access.block,
            "offset": hex(access.offset),
            "bytes": access.bytes,
            "access": written_json(&access.written),
            "evidence": evidence(access.address),
        })).collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access(offset: u64, written: Option<Written>) -> Access {
        Access {
            block: BLOCKS[0],
            offset,
            bytes: 8,
            written,
            address: offset,
        }
    }

    #[test]
    fn a_lock_after_its_mask_is_a_pair_and_a_lone_lock_is_not() {
        let sequence = [
            access(0x5008, None),
            access(0x5008, Some(Written::OrRead(vec![!(1 << 54)]))),
            access(0x5000, None),
            access(0x5000, Some(Written::OrRead(vec![LOCK]))),
            access(0x7000, Some(Written::OrRead(vec![LOCK]))),
        ];
        let pairs = lockdown(&sequence);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].control, 0x5000);
        assert_eq!(pairs[0].mask.written, sequence[1].written);
    }
}
