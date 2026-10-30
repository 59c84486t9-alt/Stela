//! T6000's ordered native-program configuration effects.
//!
//! Original LLB 1337c/1366c/47090/471b8/49ec8/4b104 supplies a
//! different program family from T8112. Counted/emitted images and the
//! firmware binding flag are inputs. This installs their physical
//! configuration only; compilation's live AP reads/effects, later activation,
//! request-to-PC selection and native execution/retirement are not performed.
use super::{Error, History, Installation, NativeImage, Placement, Step, align, write};
use alloc::{rc::Rc, vec::Vec};
use stela_contracts::bus::Width;

pub mod activation;

use stela_soc_data::pmgr::t6000::{CODE_BASE, SRAM_BASE, SRAM_LIMIT, TABLE_BASE};
const GPCE_BINDINGS: u64 = 0x28e099040;
const GROUPS: u8 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sequence {
    pub id: u8,
    pub group: u8,
    pub slot: u8,
    pub shared: bool,
}

/// Every descriptor admitted by the original T6000 revision masks8/40/40000,
/// in the ascending object order used by its allocator and binder.
pub fn sequences() -> Vec<Sequence> {
    let mut rows = Vec::new();
    for (id, group, slot) in [
        (0, 0, 0),
        (1, 0, 1),
        (2, 0, 2),
        (3, 0, 3),
        (4, 1, 0),
        (6, 1, 1),
        (8, 1, 2),
        (10, 1, 3),
        (12, 2, 0),
        (14, 2, 2),
        (16, 2, 4),
        (18, 2, 1),
        (20, 2, 3),
        (22, 2, 5),
        (24, 3, 0),
        (26, 3, 2),
        (28, 3, 1),
        (30, 3, 3),
        (32, 4, 0),
        (34, 4, 1),
        (36, 4, 2),
        (40, 5, 2),
        (44, 6, 2),
        (48, 7, 2),
        (52, 8, 0),
        (54, 8, 1),
        (60, 9, 0),
        (62, 9, 1),
    ] {
        rows.push(Sequence {
            id,
            group,
            slot,
            shared: false,
        });
    }
    for (first, slot, shared) in [
        (64, 8, true),
        (80, 7, false),
        (96, 9, true),
        (112, 10, true),
        (128, 11, true),
        (144, 12, true),
        (160, 15, true),
        (176, 14, true),
        (192, 16, true),
        (208, 13, false),
        (224, 17, true),
    ] {
        for index in 0..4 {
            rows.push(Sequence {
                id: first + index,
                group: 2 + index,
                slot,
                shared: shared && index != 0,
            });
        }
    }
    rows
}

/// Source physical publication only. The caller exclusively owns the real
/// controller/SRAM while this transaction is held, including on refusal.
/// `binding_history` is the firmware flag (bit0), never a cold default.
/// The resulting legacy `history()` fields remain unknown: they describe the
/// separate T8112 constructor and are not T6000 firmware RAM observations.
pub fn programs(
    revision: u32,
    binding_history: Option<u8>,
    mut images: Vec<NativeImage>,
) -> Result<Installation, Error> {
    if !matches!(revision, 0x10 | 0x20 | 0x21) {
        return Err(Error::UnqualifiedRevision);
    }
    let mut bound = binding_history.ok_or(Error::UnknownHistory)? & 1 != 0;
    let rows = sequences();
    images.sort_by_key(|image| image.sequence);
    for pair in images.windows(2) {
        if pair[0].sequence == pair[1].sequence {
            return Err(Error::DuplicateImage(pair[0].sequence));
        }
    }
    for image in &images {
        if !rows
            .iter()
            .any(|row| row.id == image.sequence && !row.shared)
        {
            return Err(Error::UnexpectedImage(image.sequence));
        }
    }
    let mut placements = Vec::new();
    let mut code = CODE_BASE;
    let mut preceding = None;
    for row in &rows {
        let (address, bytes) = if row.shared {
            // Native ec==1 objects reserve no bytes and alias the preceding
            // owned start. They do not allocate or emit another terminator.
            (preceding.ok_or(Error::ImageGeometry(row.id))?, 0)
        } else {
            let image = images
                .iter()
                .find(|image| image.sequence == row.id)
                .ok_or(Error::MissingImage(row.id))?;
            let words = image
                .counted_words
                .checked_add(1)
                .ok_or(Error::ImageGeometry(row.id))?;
            if u64::from(words) * 4 != image.bytes.len() as u64
                || image.bytes.last_chunk::<4>() != Some(&[0; 4])
            {
                return Err(Error::ImageGeometry(row.id));
            }
            code = align(code, 32)?;
            let end = code
                .checked_add(image.bytes.len() as u64)
                .ok_or(Error::CodeExhausted(row.id))?;
            if end >= SRAM_LIMIT {
                return Err(Error::CodeExhausted(row.id));
            }
            let address = code;
            preceding = Some(address);
            code = end;
            (address, words * 4)
        };
        placements.push(Placement {
            sequence: row.id,
            group: row.group,
            slot: row.slot,
            table: TABLE_BASE + u64::from(row.group) * 0x100,
            code: address,
            bytes,
        });
    }
    let mut steps = Vec::new();
    // Native group initialization precedes every initial zero pointer/control
    // publication. The zeros here are source stores, not handoff inputs.
    for group in 0..GROUPS {
        let table = TABLE_BASE + u64::from(group) * 0x100;
        if group < 2 {
            let address = if group == 0 { 0x2925c0200 } else { 0x2922c0300 };
            write(&mut steps, address, Width::Word, table & 0x7ff00);
        } else {
            let address = 0x28e099000 + u64::from(group - 2) * 8;
            write(&mut steps, address, Width::Word, (table >> 40) & 3);
            write(
                &mut steps,
                address + 4,
                Width::Word,
                (table >> 8) & 0xffff_ffff,
            );
        }
    }
    for code in [false, true] {
        for placement in &placements {
            bind(
                &mut steps,
                *placement,
                if code { placement.code } else { 0 },
                &mut bound,
            );
        }
    }
    // Compilation and its live AP effects are separate supplied obligations.
    // This phase publishes only the counted/emitted immutable words.
    for placement in &placements {
        if placement.bytes == 0 {
            continue;
        }
        let image = images
            .iter()
            .find(|image| image.sequence == placement.sequence)
            .ok_or(Error::MissingImage(placement.sequence))?;
        for (index, word) in image.bytes.as_chunks::<4>().0.iter().enumerate() {
            write(
                &mut steps,
                placement.code + index as u64 * 4,
                Width::Word,
                u64::from(u32::from_le_bytes(*word)),
            );
        }
    }
    Ok(Installation {
        owner: Rc::new(()),
        ticket: 0,
        flight: None,
        blocked: None,
        suspended: false,
        steps,
        step: 0,
        placements,
        history: History::default(),
        committed_reads: 0,
        committed_writes: 0,
    })
}

fn bind(steps: &mut Vec<Step>, placement: Placement, code: u64, bound: &mut bool) {
    let (id, slot) = (placement.sequence, u32::from(placement.slot));
    let direct = match id {
        0 => Some((0x2925c0204, 0x100 | slot << 31)),
        1 => Some((0x2925c020c, 0x100 | slot)),
        2 => Some((0x2925c0210, 0x100 | slot)),
        3 => Some((0x2925c0208, 0x100 | slot)),
        4 => Some((0x2922c0304, slot)),
        6 => Some((0x2922c030c, slot)),
        8 => Some((0x2922c0310, slot)),
        10 => Some((0x2922c0308, slot)),
        _ => None,
    };
    if let Some((address, value)) = direct {
        write(steps, address, Width::Word, u64::from(value));
    }
    let field = match id {
        12 => Some((0, 0)),
        18 => Some((0, 16)),
        14 => Some((4, 0)),
        20 => Some((4, 16)),
        16 => Some((8, 0)),
        22 => Some((8, 16)),
        24 => Some((12, 0)),
        28 => Some((12, 16)),
        26 => Some((16, 0)),
        30 => Some((16, 16)),
        32 => Some((20, 0)),
        34 => Some((20, 16)),
        52 => Some((24, 0)),
        54 => Some((24, 16)),
        60 => Some((32, 0)),
        62 => Some((32, 16)),
        _ => None,
    };
    if let Some((offset, shift)) = field {
        // T6000 ORs the field; it does not use T8112's replace/enable rule.
        steps.push(Step::Modify {
            address: GPCE_BINDINGS + offset,
            clear: 0,
            set: slot << shift,
            latched: None,
        });
    }
    if matches!(id, 36 | 40 | 44 | 48) && !*bound {
        // Source sets its private firmware byte before this blind write. That
        // RAM write is not invented here. The supplied history owns entry;
        // this immutable plan keeps the pending physical write on refusal.
        *bound = true;
        write(steps, GPCE_BINDINGS + 0x28, Width::Word, u64::from(slot));
    }
    write(
        steps,
        placement.table + u64::from(placement.slot) * 8,
        Width::Double,
        (code >> 4) & ((1 << 38) - 1),
    );
}

#[cfg(test)]
mod tests;
