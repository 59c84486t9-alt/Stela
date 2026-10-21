//! Bounded original-source integrity checks; no production identity dispatch.
#![cfg(feature = "std")]

use sha2::{Digest, Sha256};

fn iboot() -> Vec<u8> {
    let path = std::env::var("STELA_TEST_PMGR_IBOOT").expect("pinned original J473 iBoot path");
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        "082cf7b48f9827daefcb5a58e7fd0038aae00b3fe6d36db9ff1528ba3f3a3a3b"
    );
    bytes
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn quad(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn branch_target(bytes: &[u8], offset: usize) -> usize {
    let opcode = word(bytes, offset);
    assert!(matches!(opcode >> 26, 0b000101 | 0b100101));
    let displacement = ((opcode << 6) as i32 >> 4) as isize;
    offset.wrapping_add_signed(displacement)
}

fn original_physical_ps() -> std::collections::BTreeSet<u64> {
    let path = std::env::var("STELA_TEST_PMGR_ADT").expect("pinned original J473 ADT path");
    let adt = std::fs::read(path).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&adt)),
        "a99fa2260f292236fbad210fcee380fc69f101e591125bce347819e84e68034c"
    );
    // The restore DT's /chosen chip-id is unprovisioned (zero), so do not
    // patch it or mount a fabricated board to inspect its original records.
    // Replay the pinned v1 placement fields only, using the public ADT reader.
    let root = stela_runtime::machine::adt::Node::root(&adt).unwrap();
    let io = root.child("arm-io").unwrap();
    let pmgr = io.child("pmgr").unwrap();
    assert!(pmgr.property("ps-groups").is_none());
    let records = pmgr.property("devices").unwrap();
    assert_eq!(records.len(), 303 * 48);
    let placements = pmgr.cells32("ps-regs").unwrap();
    let registers = pmgr.pairs("reg").unwrap();
    let ranges = io.ranges().unwrap();
    let mut physical = std::collections::BTreeSet::new();
    for record in records.as_chunks::<48>().0 {
        if record[0] & 0x10 != 0 {
            continue;
        }
        let placement = &placements[usize::from(record[11]) * 3..][..3];
        let (base, size) = registers[placement[0] as usize];
        let offset = u64::from(placement[1]) + u64::from(record[10]) * 8;
        assert!(offset + 8 <= size);
        let address = base + offset;
        let (child, parent, _) = ranges
            .iter()
            .find(|&&(child, _, size)| address >= child && address - child < size)
            .unwrap();
        physical.insert(parent + address - child);
    }
    assert_eq!(physical.len(), 153);
    physical
}

#[test]
#[ignore = "requires pinned original J473 iBoot and ADT; no Apple images are committed"]
fn original_policy_covers_every_physical_domain_without_encoding_initial_values() {
    use std::collections::BTreeSet;
    let bytes = iboot();
    let physical = original_physical_ps();
    assert_eq!(word(&bytes, 0x1b70f8), 254);
    let mut matched = BTreeSet::new();
    for index in 0..254 {
        let offset = 0x1b6118 + 16 * index;
        let packed = quad(&bytes, offset);
        let address = packed & ((1 << 51) - 1);
        if physical.contains(&address) {
            assert!(matched.insert(address), "duplicate physical policy row");
            assert_eq!((packed >> 51) & 63, 0, "revision minimum");
            assert_eq!((packed >> 57) & 63, 0, "revision span");
            assert_eq!(
                quad(&bytes, offset + 8),
                0,
                "no auxiliary initial-state payload"
            );
        }
    }
    assert_eq!(
        matched, physical,
        "full original physical register inventory"
    );
}

#[test]
#[ignore = "requires pinned original J473 iBoot; no Apple image is committed"]
fn original_eight_fixups_edit_distinct_dt_fields() {
    let bytes = iboot();
    for (index, expected) in [
        0x14210, 0x14720, 0x143a8, 0x14488, 0x14358, 0x147d0, 0x148f0, 0x14628,
    ]
    .into_iter()
    .enumerate()
    {
        let relative = word(&bytes, 0x14a6c + index * 4) as i32;
        assert_eq!(
            0x14204usize.checked_add_signed(relative as isize),
            Some(expected)
        );
    }
    // Preserve byte-level distinctions rather than assigning unrecovered
    // hardware meaning to bytes 1, 2, 8, 15 or the requested operation.
    for (offset, opcode) in [
        (0x143a0, 0x79000909), // operation 4: first u16 parent at +4
        (0x14440, 0x39003d09), // operation 2: low nibble at +15
        (0x1453c, 0x3900611f), // operation 3: clock count at +24
        (0x145f8, 0x38296917), // operation 3: clock indices at +28..31
        (0x14760, 0x3900012a), // operation 1: NO_PS flags
        (0x14894, 0x3900294b), // operation 5: v1 PS index at +10
        (0x149a4, 0x39002109), // operation 6: byte +8
        (0x146f0, 0x39000509), // operation 7: byte +1
        (0x14710, 0x3900091f), // operation 7: clear +2 for zero data
    ] {
        assert_eq!(word(&bytes, offset), opcode, "fixup at {offset:#x}");
    }
    let calls: Vec<_> = (0..0x16f000)
        .step_by(4)
        .filter(|&offset| {
            matches!(word(&bytes, offset) >> 26, 0b000101 | 0b100101)
                && branch_target(&bytes, offset) == 0x1414c
        })
        .collect();
    assert_eq!(
        calls,
        [0x11730],
        "direct calls in the bounded original code region"
    );
    assert_eq!(
        word(&bytes, 0x1172c),
        0x52800007,
        "only recovered caller chooses operation 0"
    );
}

#[test]
#[ignore = "requires pinned original J473 iBoot; no Apple image is committed"]
fn original_address_selectors_and_display_fuse_gate_are_exact() {
    let bytes = iboot();
    // The callback receives a selector object, not a physical-state value:
    // a nonzero first field compares PA; a zero first field compares ID.
    for (offset, opcode) in [
        (0x11708, 0xa93c23a8),  // build selector from selected table PA
        (0x11590, 0xeb13011f),  // compare selector PA against current PA
        (0x1166c, 0x6b15011f),  // zero-PA selector compares original domain ID
        (0x5d0a4, 0x370003e0),  // feature11 true skips display fixups
        (0x40084, 0x52a00608),  // feature11 mask 0x00300000
        (0x400f4, 0x6a29011f),  // (~fuseword & mask) != 0
        (0x124c94, 0x52800000), // extra display predicate is constant false
    ] {
        assert_eq!(word(&bytes, offset), opcode, "selector/fuse at {offset:#x}");
    }
    let selectors = [
        (0x5d078, 0x5d080, 0x41),
        (0x5d084, 0x5d08c, 0x23),
        (0x5d090, 0x5d098, 0x24),
        (0x5d0a8, 0x5d0b0, 0xa3),
        (0x5d0b4, 0x5d0bc, 0xa4),
        (0x5d0c0, 0x5d0c8, 0xa6),
        (0x5d0cc, 0x5d0d4, 0xa7),
        (0x5d0d8, 0x5d0e0, 0xb0),
        (0x5d0e4, 0x5d0ec, 0xa5),
        (0x5d0f0, 0x5d0f8, 0xb1),
        (0x5d0fc, 0x5d104, 0xb2),
        (0x5d108, 0x5d110, 0xb3),
        (0x5d114, 0x5d11c, 0xd3),
        (0x5d154, 0x5d15c, 0xa4),
        (0x5d160, 0x5d168, 0x5c),
        (0x5d16c, 0x5d174, 0x5d),
        (0x5d178, 0x5d180, 0x5e),
        (0x5d184, 0x5d18c, 0x5f),
        (0x5d190, 0x5d1bc, 0x60),
    ];
    for (load, call, index) in selectors {
        assert_eq!(word(&bytes, load), 0x52800000 | index << 5);
        assert_eq!(branch_target(&bytes, call), 0x116c0);
        assert_ne!(index, 188, "ISP_SYS is not an address-selector fixup");
    }
    assert_eq!(branch_target(&bytes, 0x39bc8), 0x5cf68);
    assert_eq!(quad(&bytes, 0x1ed420), 0x23b700000);
    // The named SoC-PS finalizer lists each contain exactly one write to
    // a controller-global offset, not a 153-register initial-state table.
    assert_eq!(quad(&bytes, 0x191730), 0x900183dd0);
    assert_eq!(quad(&bytes, 0x191738), 0);
    assert_eq!(quad(&bytes, 0x183dd0), 0x40017ffc);
    assert_eq!(quad(&bytes, 0x191740), 0x900191720);
    assert_eq!(quad(&bytes, 0x191748), 0);
    assert_eq!(quad(&bytes, 0x191720), 0x40017ff8);
}

#[test]
#[ignore = "requires pinned original J473 iBoot; no Apple image is committed"]
fn original_active_masks_choose_writes_without_defining_clear_bits_as_off() {
    let bytes = iboot();
    for (offset, opcode) in [
        (0x10e58, 0xb9400908), // auxiliary word compared with filter argument
        (0x10e5c, 0x71000a7f),
        (0x10e7c, 0xf8686aa8), // load selected bitmap word
        (0x10e80, 0x9ad62508), // select bit by static-table index
        (0x10e84, 0x36000228), // clear bit skips this register entirely
        (0x10ec0, 0x528001e2), // selected bit requests active, not bitmap value
        (0x110b0, 0xb9400109), // physical current/control read
        (0x110c4, 0x12037929), // clear auto enable
        (0x110d0, 0x121c6d29), // preserve all fields outside target
        (0x110d4, 0x2a130129),
        (0x110d8, 0xb9000109), // actual physical write
    ] {
        assert_eq!(
            word(&bytes, offset),
            opcode,
            "active mask/writer at {offset:#x}"
        );
    }
    for base in [0x1b7100, 0x1b7150] {
        assert_eq!(
            bytes[base + 188 / 8] & (1 << (188 % 8)),
            0,
            "ISP_SYS skipped, not initialized off"
        );
        assert_ne!(
            bytes[base + 86 / 8] & (1 << (86 % 8)),
            0,
            "AIC selected for an active write"
        );
    }
}

#[test]
#[ignore = "requires pinned original J473 26A434 iBoot; no Apple image is committed"]
fn original_policy_filters_physical_addresses_by_chip_revision() {
    let bytes = iboot();
    // The row is not an initial PS value: the predicate masks its PA,
    // extracts revision minimum/span, and compares the actual chip revision.
    for (offset, opcode) in [
        (0x115e0, 0xeb13011f), // compare decoded PA against requested PA
        (0x11634, 0xd373e309), // minimum revision [56:51]
        (0x118ac, 0x9240c908), // physical address [50:0]
        (0x118f0, 0xd379f908), // revision span [62:57]
        (0x11960, 0xd373e108), // minimum revision [56:51]
        (0x14298, 0x39400109), // read ADT record's flags byte
        (0x1429c, 0x321c0129), // set NO_PS on rejected records
        (0x142a0, 0x39000109), // write ADT record, not physical PS
        (0x14310, 0xb940092a), // read ps-regs inventory mask
        (0x14314, 0x0a280148), // clear rejected placement's mask bit
        (0x14318, 0xb9000928), // write inventory mask
    ] {
        assert_eq!(word(&bytes, offset), opcode, "iBoot file {offset:#x}");
    }
    let row = &bytes[0x1b6cd8..0x1b6ce8];
    let packed = u64::from_le_bytes(row[..8].try_into().unwrap());
    assert_eq!(packed & ((1 << 51) - 1), 0x23b700438); // ISP_SYS
    assert_eq!((packed >> 51) & 63, 0);
    assert_eq!((packed >> 57) & 63, 0);
    assert_eq!(u64::from_le_bytes(row[8..].try_into().unwrap()), 0);
    // This is table index 188, distinct from original ADT domain ID 0x7a.
    assert_eq!((0x1b6cd8 - 0x1b6118) / 16, 188);
}

#[test]
#[ignore = "requires pinned original J473 26A434 iBoot; no Apple image is committed"]
fn original_power_writer_samples_current_state_and_terminal_calls_are_separate() {
    let bytes = iboot();
    for (offset, opcode) in [
        (0x11480, 0xb94002a8), // load actual physical register
        (0x11490, 0x12037908), // clear auto enable bit 28
        (0x11494, 0xb90002a8),
        (0x1149c, 0x32000d09), // active target 0xf
        (0x114a0, 0x121c6d08), // off target zero
        (0x114c4, 0xb90002a8), // commit selected target
        (0x114d4, 0x4a481128), // compare actual target/current nibbles
        (0x114d8, 0x72000d1f),
        (0x445c, 0x9400d3b9),  // timeout/recovery caller -> 0x39340
        (0x393cc, 0x94008fa8), // -> serial-domain shutdown
        (0x393d0, 0x94008f8a), // -> MTP-domain shutdown
    ] {
        assert_eq!(word(&bytes, offset), opcode, "iBoot file {offset:#x}");
    }
    // The terminal routine explicitly stops MTP DMA (table index 0x54).
    assert_eq!(word(&bytes, 0x5d204), 0x52800a80); // mov w0, #0x54
    assert_eq!(word(&bytes, 0x5d208), 0x52800001); // mov w1, #0
    // Its table entry maps to MTP_DMA, not ISP_SYS or ADT ID 0x54.
    let offset = 0x1b6118 + 0x54 * 16;
    let packed = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    assert_eq!(packed & ((1 << 51) - 1), 0x23d28c050);
    // These writes establish that path's effects, not OS handoff values.
}

fn llb() -> Vec<u8> {
    let path = std::env::var("STELA_TEST_PMGR_LLB").expect("pinned original J473 LLB path");
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        "d6c695d26e5d816a2ecd523c0be20a15307af24c404b1603d74a970b53e75e77"
    );
    bytes
}

#[test]
#[ignore = "requires pinned original J473 LLB and ADT; no Apple images are committed"]
fn original_llb_reconfiguration_programs_retain_the_complete_physical_inventory() {
    use std::collections::BTreeSet;
    let bytes = llb();
    let physical = original_physical_ps();
    let policy: BTreeSet<u64> = (0..254)
        .map(|index| quad(&bytes, 0x1a0a88 + index * 16) & ((1 << 51) - 1))
        .filter(|address| physical.contains(address))
        .collect();
    assert_eq!(policy, physical);
    let mut operands = BTreeSet::new();
    let mut operand_rows = 0;
    for (index, start, end, rows, digest) in [
        (
            0,
            0x20ab10,
            0x22c7e8,
            5769,
            "8fd47694fb73e640f0726e3b4288ff9bd2c09507551b8970cc1e2ea287b3af75",
        ),
        (
            1,
            0x22c7e8,
            0x2434c8,
            3892,
            "cb15695f8d09321cbe7b1f2817820070a681cd99710f70b39425d115666070bd",
        ),
        (
            3,
            0x2434c8,
            0x2475f0,
            695,
            "3c04b44cb659d21965506ee25ac65239ea213945d6b80fe95ac6cea2d4ae9304",
        ),
        (
            4,
            0x2475f0,
            0x247b90,
            60,
            "ea440df41f177ff3108b1d2e178b2790c64811f64eaf44bc88f80b27955cc485",
        ),
    ] {
        assert_eq!(
            quad(&bytes, 0x160148 + index * 8),
            0x1fc050000 + start as u64
        );
        assert_eq!(quad(&bytes, 0x160120 + index * 8), 0x1fc050000 + end as u64);
        assert_eq!(word(&bytes, 0x1a30b4 + index * 4), rows);
        assert_eq!(end - start, rows as usize * 24);
        assert_eq!(hex::encode(Sha256::digest(&bytes[start..end])), digest);
        for row in bytes[start..end].as_chunks::<24>().0 {
            let address = quad(row, 8);
            let physical_word = if physical.contains(&address) {
                Some(address)
            } else {
                address
                    .checked_sub(4)
                    .filter(|address| physical.contains(address))
            };
            if let Some(address) = physical_word {
                operands.insert(address);
                operand_rows += 1;
                // Both control and adjacent-auto operands remain raw program
                // requirements. No physical fetch-write opcode occurs here.
                assert!(matches!(word(row, 0) >> 16, 0 | 3));
            }
        }
    }
    assert_eq!(word(&bytes, 0x1a30bc), 0); // type 2 has no serialized program
    assert_eq!(quad(&bytes, 0x160130), quad(&bytes, 0x160158));
    assert_eq!(operands.len(), 84);
    assert_eq!(operand_rows, 475);
    assert!(operands.contains(&0x23b700438));
    assert!(operands.is_subset(&physical));
    // The remaining 69 controls are still required; absence from these
    // programs cannot establish their target/current state at OS handoff.
    assert_eq!(physical.difference(&operands).count(), 69);
}

#[test]
#[ignore = "requires pinned original J473 LLB; no Apple image is committed"]
fn original_llb_isp_sequence_emission_is_distinct_from_a_physical_write() {
    let bytes = llb();
    // Callback registrations identify opcode 0's emitter and opcode 7's
    // separate fetch-write path. Preserve the original relocation words.
    for (offset, opcode, callback) in [
        (0x248b30, 0, 0x80400000000120ac),
        (0x2491f0, 7, 0x80400000000120d0),
    ] {
        assert_eq!(quad(&bytes, offset), opcode);
        assert_eq!(quad(&bytes, offset + 8), callback);
    }
    for (offset, opcode) in [
        (0x120bc, 0x52800003), // emitter passes full32 width to the compiler
        (0x120e0, 0xb9000022), // distinct fetch-write performs actual STR w2,[x1]
        (0x13904, 0x79400260), // low16 sequence operand passed as callback arg0
        (0x13908, 0xf9400661), // full address operand
        (0x1390c, 0xb9401262), // value operand
        (0x13910, 0xd63f091f), // registered callback, not raw data execution
    ] {
        assert_eq!(word(&bytes, offset), opcode, "LLB file {offset:#x}");
    }
    assert_eq!(branch_target(&bytes, 0x120c0), 0x10810);
    assert_eq!(branch_target(&bytes, 0x120ec), 0x10810);
    for (index, value) in [(655, 0x230f), (696, 0x2300)] {
        let offset = 0x22c7e8 + index * 24;
        assert_eq!(quad(&bytes, offset), 0x17); // sequence 23, opcode 0
        assert_eq!(quad(&bytes, offset + 8), 0x23b700438);
        assert_eq!(quad(&bytes, offset + 16), value);
    }
    // Both ISP writes belong to one construction-time conditional block.
    // Bit13's source value remains a runtime input, not a board-name default.
    assert_eq!(quad(&bytes, 0x230538), 0xab0017);
    assert_eq!(quad(&bytes, 0x230540), 0x2000);
    assert_eq!(quad(&bytes, 0x230548), 0);
    assert_eq!(quad(&bytes, 0x230970), 0xb00017);
    assert_eq!(quad(&bytes, 0x249170), 0xab);
    assert_eq!(quad(&bytes, 0x249178), 0x8040000000013bfc);
    assert_eq!(word(&bytes, 0x13c34), 0xf9401d08); // flags from context+38
    assert_eq!(word(&bytes, 0x13c38), 0xea13011f); // test supplied mask
    assert_eq!(word(&bytes, 0x13c3c), 0x1a9f07e0); // take block when nonzero
    assert_eq!(branch_target(&bytes, 0x13c60), 0x136e4);
    assert_eq!(branch_target(&bytes, 0x4dbe4), 0x16348);
    assert_eq!(word(&bytes, 0x4dbe0), 0x528001c0); // query14
    assert_eq!(word(&bytes, 0x4dbe8), 0x7100081f); // result2 clears bit13
    // Constructor/first pass, then mode change and second compilation pass.
    // Their existence does not prove either resulting program has executed.
    assert_eq!(branch_target(&bytes, 0x4ecdc), 0x142c0);
    assert_eq!(branch_target(&bytes, 0x4ecf4), 0x140ec);
    assert_eq!(branch_target(&bytes, 0x4ecf8), 0x1413c);
    assert_eq!(branch_target(&bytes, 0x4ed08), 0x14078);
    assert_eq!(branch_target(&bytes, 0x4ed10), 0x140ec);
}

// These fixture views preserve original construction data. They deliberately
// expose neither a hardware executor nor a default physical handoff state.
#[derive(Debug, PartialEq, Eq)]
struct LlbSequence {
    id: u32,
    group: u32,
    pointer_slot: u32,
    emission_mode: u32,
    revision_mask: u32,
}

fn llb_sequences(bytes: &[u8], kind: usize) -> Vec<LlbSequence> {
    let start = usize::try_from(quad(bytes, 0x160198 + kind * 8) - 0x1fc050000).unwrap();
    let end = usize::try_from(quad(bytes, 0x160170 + kind * 8) - 0x1fc050000).unwrap();
    // 4d8d0 uses the table only for kinds 0..3. Kind 4 returns sixteen
    // directly; reading the following group-count word would yield two.
    let count = if kind == 4 {
        16
    } else {
        word(bytes, 0x1a3090 + kind * 4) as usize
    };
    assert_eq!(end - start, count * 64);
    (0..count)
        .map(|index| {
            let offset = start + index * 64;
            for field in [8, 16, 24, 32, 48] {
                assert_eq!(quad(bytes, offset + field), 0);
            }
            LlbSequence {
                id: word(bytes, offset),
                group: word(bytes, offset + 4),
                pointer_slot: word(bytes, offset + 40),
                emission_mode: word(bytes, offset + 56),
                revision_mask: word(bytes, offset + 60),
            }
        })
        .collect()
}

fn relative_table(bytes: &[u8], table: usize, base: usize, count: usize) -> Vec<usize> {
    (0..count)
        .map(|index| base.wrapping_add_signed(word(bytes, table + index * 4) as i32 as isize))
        .collect()
}

#[test]
#[ignore = "requires pinned original J473 LLB; no Apple image is committed"]
fn original_llb_selection_binds_all_thirty_sequences_without_a_revision_default() {
    use std::collections::BTreeSet;
    let bytes = llb();
    let mut all = BTreeSet::new();
    let paired_slots = [3, 9, 4, 10, 5, 11, 0, 6, 1, 7, 2, 8];
    for (kind, count, groups) in [
        (0, 14, [0, 3]),
        (1, 16, [1, 2]),
        (2, 0, [0, 0]),
        (3, 12, [0, 3]),
        (4, 16, [1, 2]),
    ] {
        let sequences = llb_sequences(&bytes, kind);
        assert_eq!(sequences.len(), count);
        let odd = u32::from(matches!(kind, 1 | 4));
        for (index, sequence) in sequences.iter().enumerate() {
            let (id, group, pointer_slot) = if index < 12 {
                (index as u32 * 2 + odd, groups[0], paired_slots[index])
            } else if odd == 1 {
                (index as u32 + 12, groups[1], index as u32 - 12)
            } else {
                (index as u32 + 16, groups[1], index as u32 - 12)
            };
            assert_eq!(
                *sequence,
                LlbSequence {
                    id,
                    group,
                    pointer_slot,
                    emission_mode: 0,
                    revision_mask: 15,
                }
            );
            all.insert(sequence.id);
        }
        let source_start =
            usize::try_from(quad(&bytes, 0x160148 + kind * 8) - 0x1fc050000).unwrap();
        let source_rows = word(&bytes, 0x1a30b4 + kind * 4) as usize;
        for index in 0..source_rows {
            let id = word(&bytes, source_start + index * 24) & 0xffff;
            assert!(sequences.iter().any(|sequence| sequence.id == id));
        }
        assert_eq!(
            word(&bytes, 0x1a30a0 + kind * 4),
            if kind == 2 { 0 } else { 2 }
        );
    }
    assert_eq!(all, (0..30).collect());
    // Raw chip revision -> mask is separate from context+20's program kind.
    // Unknown chips/revisions branch to explicit failures, not mask 15.
    for (offset, opcode) in [
        (0x4d7ac, 0x52902248),
        (0x4d7b8, 0x52902208),
        (0x4d7c8, 0x7100441f),
        (0x4d7d0, 0x7100401f),
        (0x4d7d8, 0x7100041f),
        (0x4d7e0, 0x52800040),
        (0x4d7e8, 0x52800080),
        (0x4d7f0, 0x52800020),
        (0x4d7f8, 0x52800100),
        (0x4d830, 0xb9470108),
        (0x4d8ec, 0x52800209),
        (0x14490, 0xb9403e88),
        (0x14494, 0x6a13011f),
        (0x145a0, 0xb9403f48),
        (0x145a4, 0x6a13011f),
    ] {
        assert_eq!(word(&bytes, offset), opcode, "selection at {offset:#x}");
    }
    assert_eq!(branch_target(&bytes, 0x4d828), 0x22fc4);
    assert_eq!(word(&bytes, 0x14344), 0xb9002115); // caller kind -> context+20
    // Every source descriptor currently admits all four recognized revisions;
    // that does not resolve construction flags or actual hardware inputs.
    assert_eq!(word(&bytes, 0x14c18), 0xb9401508); // A4: raw revision
    assert_eq!(word(&bytes, 0x13ab8), 0xb9401108); // A5: chip ID
    assert_eq!(word(&bytes, 0x13b50), 0xb9402908); // B8: revision mask
    assert_eq!(word(&bytes, 0x13c34), 0xf9401d08); // AB: feature flags
}

#[test]
#[ignore = "requires pinned original J473 LLB; no Apple image is committed"]
fn original_llb_counts_allocates_emits_and_publishes_before_enable_readback() {
    let bytes = llb();
    for (call, target) in [
        (0x4ecdc, 0x142c0), // construct original descriptors/flags
        (0x14800, 0x4d2cc), // constructor publishes initial zero code pointers
        (0x4ecf4, 0x140ec),
        (0x4ecf8, 0x1413c),
        (0x4ecfc, 0x4ebdc),
        (0x4ed04, 0x4dcd8), // reserve actual SRAM after the count pass
        (0x4ed08, 0x14078),
        (0x4ed10, 0x140ec), // reset count, mode 0
        (0x4eedc, 0x1413c),
        (0x4eee0, 0x4ebdc), // emit and flush/terminate
        (0x4ddf8, 0x4d2cc), // bind allocated code and pointer table
        (0x4ec4c, 0x11be0), // every active sequence gets a terminator
    ] {
        assert_eq!(branch_target(&bytes, call), target);
    }
    assert_eq!(
        relative_table(&bytes, 0x4de58, 0x4dd28, 5),
        [0x4dd34, 0x4dd58, 0x4de48, 0x4dd34, 0x4dd58]
    );
    assert_eq!(
        relative_table(&bytes, 0x4f178, 0x4ed5c, 5),
        [0x4ed68, 0x4ee44, 0x4f16c, 0x4ed68, 0x4ee44]
    );
    assert_eq!(
        relative_table(&bytes, 0x4f18c, 0x4ef30, 5),
        [0x4ef3c, 0x4ef50, 0x4ef7c, 0x4ef3c, 0x4ef50]
    );
    assert_eq!(
        relative_table(&bytes, 0x4f1a0, 0x4efb8, 5),
        [0x4efc4, 0x4effc, 0x4f160, 0x4efc4, 0x4effc]
    );
    for (offset, opcode) in [
        (0x4ecf0, 0x52800020),
        (0x4ed0c, 0x52800000),
        (0x4ddbc, 0x927be908), // each sequence starts on a 32-byte boundary
        (0x4ddcc, 0x11000529), // one extra native word reserved for termination
        (0x4ddd4, 0xb900f2a9), // expected final native-word count
        (0x4ddd8, 0x531e7529), // allocated bytes = native words * 4
        (0x4d664, 0xd344a6c1), // code pointer is bits 41:4 of actual SRAM PA
        (0x4d668, 0x531d7288), // pointer slot * 8, not a 32-bit slot
        (0x4d66c, 0x8b0802a0),
        (0x4ef8c, 0x5280818a), // stages 2,3,10 only enter value-3 command path
        (0x4efdc, 0xb90002e8),
        (0x4efe4, 0xb94002e8),
        (0x4efe8, 0x71000d1f), // readback equals 3; not a sequence-PC read
        (0x4f018, 0xb90002c8),
        (0x4f020, 0xb94002c8),
        (0x4f024, 0x71000d1f),
    ] {
        assert_eq!(word(&bytes, offset), opcode, "pipeline at {offset:#x}");
    }
    assert_eq!(branch_target(&bytes, 0x4d690), 0x103a0); // actual 64-bit store
    // Runtime-dependent group1/2 allocation needs physical input metadata.
    assert_eq!(branch_target(&bytes, 0x4dd84), 0x4f304);
    assert_eq!(word(&bytes, 0x4f1e8), 0xb9400109);
    assert_eq!(word(&bytes, 0x4f1f0), 0xb85fc10a);
}

#[test]
#[ignore = "requires pinned original J473 LLB; no Apple image is committed"]
fn original_llb_complete_feature_filter_omits_the_isp_block_without_implying_off() {
    let bytes = llb();
    assert_eq!(
        hex::encode(Sha256::digest(&bytes[0x4d990..0x4db74])),
        "45c0ea994ab247b245d1b3830c0a175307220589794c7f0e01a3baffeabcde0c"
    );
    assert_eq!(
        hex::encode(Sha256::digest(&bytes[0x4db74..0x4dcd8])),
        "af5277a9d18d2756a6ca17b6561182496a796b6f1fcbcf3e66acae5861f16c25"
    );
    // Seven 48-byte stack descriptors, in original order. Names qualify the
    // predicate inputs, never functional hardware ownership or initial state.
    for (offset, name) in [
        (0x1e5987, "ANE"),
        (0x1e598b, "AVE"),
        (0x1e3d60, "GFX"),
        (0x1e598f, "ISP"),
        (0x1e5993, "SCodec"),
        (0x1e599a, "SIO"),
        (0x1e3e07, "PMP"),
    ] {
        assert_eq!(&bytes[offset..offset + name.len()], name.as_bytes());
        assert_eq!(bytes[offset + name.len()], 0);
    }
    for (offset, opcode) in [
        (0x4daf4, 0x528000f6), // seven descriptors
        (0x4db38, 0x9100c2f7), // descriptor stride 48
        (0x4da50, 0xa90b7fe8), // ISP type pointer + zero enable at stack+b0/b8
        (0x4da54, 0x5284000a), // ISP mask = 0x2000
        (0x4da60, 0xa90c2fea), // mask at stack+c0, next name at stack+c8
        (0x4db10, 0x394082e8), // load descriptor enable byte at +20
        (0x4db14, 0x7100051f), // require exact enable value 1
        (0x4db18, 0x540000a1), // otherwise skip predicate and clear mask
        (0x4db28, 0x37000060), // true predicate retains mask
        (0x4db2c, 0xf94016e8), // descriptor mask at +28
        (0x4db30, 0x8a280273), // BIC flags,flags,mask
        (0x4dc58, 0xf9000d00), // filtered flags replace context+38
        (0x137dc, 0x54000061), // false condition takes nested skip path
    ] {
        assert_eq!(
            word(&bytes, offset),
            opcode,
            "feature filter at {offset:#x}"
        );
    }
    assert_eq!(branch_target(&bytes, 0x4db24), 0x2df30);
    assert_eq!(branch_target(&bytes, 0x4dc4c), 0x4d990);
    assert_eq!(branch_target(&bytes, 0x143dc), 0x4db74);
    assert_eq!(branch_target(&bytes, 0x137e0), 0x13870); // taken: dispatch
    assert_eq!(branch_target(&bytes, 0x137e8), 0x13594); // omitted: nested skip
    assert_eq!(quad(&bytes, 0x230538), 0xab0017);
    assert_eq!(quad(&bytes, 0x230540), 0x2000);
    // Constructor filters run before both compilation passes. The source
    // constants 230f/2300 inside this block therefore supply no physical PS
    // write on that path, and neither constant becomes a handoff default.
}

#[test]
#[ignore = "requires pinned original J473 LLB; no Apple image is committed"]
fn original_llb_native_emission_retains_packing_fetches_and_termination_limits() {
    let bytes = llb();
    for (start, end, digest) in [
        (
            0x109ec,
            0x10e04,
            "fd75f3c33c297f1a36e94c3a97ceea938ed5859866a1bd12e51056f47a53a8b3",
        ),
        (
            0x10e04,
            0x112d8,
            "5d91af7f905f99f3c58ef69151dc5224ffd3c14a1faee61cfd6f90e01bc8d2d0",
        ),
        (
            0x11be0,
            0x11e0c,
            "eb69091852f80d18150e9a3fa75128a714a4ea4c813a2c8a3be983364d89a1cb",
        ),
        (
            0x4d2cc,
            0x4d730,
            "10f5489fda13c21946fb042436b562af057b999eccadce560e7c8825db5b1c9d",
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(&bytes[start..end])), digest);
    }
    for (offset, opcode) in [
        (0x124ec, 0xb9400022), // source opcode B fetches live peripheral data
        (0x12180, 0xf94006c8), // opcode 1 consumes the next row's constant
        (0x10c00, 0xd344ff8a), // native write header uses PA >> 4
        (0x10c14, 0xb8286b29), // actual header written into allocated SRAM
        (0x10c5c, 0xd364a689), // format 0 additionally emits PA bits 41:36
        (0x10d20, 0xb8286b29), // wide-value alignment padding is retained
        (0x10fac, 0xb8286b69), // poll header emitted; no physical poll here
        (0x11d6c, 0xb8286abf), // native zero terminator is actually stored
        (0x11db0, 0x6b0802bf), // final emitted word count must equal reservation
    ] {
        assert_eq!(
            word(&bytes, offset),
            opcode,
            "native emission at {offset:#x}"
        );
    }
    assert_eq!(branch_target(&bytes, 0x12194), 0x10810);
    // Hardware interpretation of these SRAM words, its trigger queue and
    // committed instruction/PS prefix still need an execution oracle. A zero
    // terminator or matching build count alone cannot retire native effects.
}

#[test]
#[ignore = "requires pinned original J473 LLB; no Apple image is committed"]
fn original_llb_controller_bindings_cover_every_sequence_and_preserve_field_geometry() {
    let bytes = llb();
    assert_eq!(
        relative_table(&bytes, 0x4d2a0, 0x4d228, 4),
        [0x4d268, 0x4d234, 0x4d23c, 0x4d250]
    );
    assert_eq!(
        relative_table(&bytes, 0x4d6d0, 0x4d370, 24),
        [
            0x4d37c, 0x4d53c, 0x4d4ec, 0x4d51c, 0x4d4a4, 0x4d570, 0x4d5b8, 0x4d524, 0x4d600,
            0x4d4d4, 0x4d5e8, 0x4d48c, 0x4d4bc, 0x4d5a0, 0x4d474, 0x4d504, 0x4d45c, 0x4d544,
            0x4d5d0, 0x4d634, 0x4d558, 0x4d588, 0x4d61c, 0x4d648,
        ]
    );
    assert_eq!(
        relative_table(&bytes, 0x4d6b8, 0x4d3b4, 6),
        [0x4d3c0, 0x4d420, 0x4d3ec, 0x4d404, 0x4d3d4, 0x4d43c]
    );
    // Native helpers replace only their selected five-bit field, preserving
    // the other sequence's field. The physical group2/3 cases instead OR
    // slots into their separately initialized registers; they are distinct.
    for (offset, opcode) in [
        (0x4e28c, 0x120b6808),
        (0x4e290, 0x2a144108),
        (0x4e298, 0x121b6808),
        (0x4e29c, 0x2a080288),
        (0x4d3e4, 0x12001289),
        (0x4d44c, 0x531b1289),
        (0x4d65c, 0x32080101), // high field enable bit 24
        (0x4d614, 0x32180101), // low field enable bit 8
        (0x4d64c, 0x91045260), // sequence23: base+114 = PA23d2d0318
    ] {
        assert_eq!(word(&bytes, offset), opcode, "binding at {offset:#x}");
    }
    // ISP source belongs to sequence23/group1/slot8, not physical domain ID23.
    let sequences = llb_sequences(&bytes, 1);
    assert_eq!(
        sequences.iter().find(|entry| entry.id == 23).unwrap(),
        &LlbSequence {
            id: 23,
            group: 1,
            pointer_slot: 8,
            emission_mode: 0,
            revision_mask: 15
        }
    );
    assert_eq!(branch_target(&bytes, 0x4d648), 0x4e244);
    assert_eq!(branch_target(&bytes, 0x4d654), 0x4e28c);
}

fn kernelcache() -> Vec<u8> {
    let path = std::env::var("STELA_TEST_PMGR_KERNELCACHE")
        .expect("pinned original 26A434 J473 kernelcache path");
    let bytes = std::fs::read(path).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        "06846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d"
    );
    bytes
}

#[test]
#[ignore = "requires pinned original J473 kernelcache; no Apple image is committed"]
fn original_kernel_restore_orders_gpce_readiness_before_the_complete_ps_sweep() {
    let bytes = kernelcache();
    for (start, end, digest) in [
        (
            0x2fa3c80,
            0x2fa3e18,
            "8bb99f1c33ae6f42df0db6937a58460a61646296fc52dab7bffa166e8920d1ea",
        ),
        (
            0x2f9cb9c,
            0x2f9cf8c,
            "a5b2ec3856fb14903ebc4d403351955835917808b92e102cdbb458670f5090d3",
        ),
        (
            0x2b87598,
            0x2b879d4,
            "640e72e8fc67dd0a81fce49007c94df1f507dbb54f66440767b6b1f499747ccd",
        ),
        (
            0x2b879d4,
            0x2b87dfc,
            "05c51bdfe2b2b51e09572bf8410c2ba7751c1e72db81d9420c977ea6bebe913e",
        ),
        (
            0x2f9cab4,
            0x2f9cb9c,
            "65983b228a6b30df77b909cb30b147958bcd7811676c4b43ab72e8adc38edbb8",
        ),
        (
            0x2ba060c,
            0x2ba0a2c,
            "8ba63d6ef699b74bfe9b2a38429022c957796ca6f13615a09b4ef5d5958d44ad",
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(&bytes[start..end])), digest);
    }
    // Static superclass tables include the two metadata words; instance
    // dispatch slots start after those words. Keep that distinction exact.
    assert_eq!(quad(&bytes, 0x134e3e8 + 0x8e0), 0x80115f0802f9cb9c);
    assert_eq!(quad(&bytes, 0x1266ef8 + 0x8e0), 0x80115f0802b87598);
    assert_eq!(quad(&bytes, 0x134f6e8 + 16 + 0xd30), 0x8011abb302b89d28);
    assert_eq!(quad(&bytes, 0x134f6e8 + 16 + 0xd28), 0x8011dc0802fa768c);
    assert_eq!(quad(&bytes, 0x134e3e8 + 0xd38), 0x8011dc0802f9cab4);
    for (offset, opcode) in [
        (0x2f9cbe8, 0x52800001), // enableCPUComplex(0,true)
        (0x2f9cbec, 0x52800022),
        (0x2f9cc28, 0x52800021), // enableCPUComplex(1,true)
        (0x2f9cc2c, 0x52800022),
        (0x2f9cb10, 0x528001e9), // low4 enable request f
        (0x2f9cb40, 0x121c6c08), // preserve all bits outside low4
        (0x2f9cb74, 0x52800202), // wait uses mask bit4
        (0x2f9cb78, 0x52800003), // expected masked value0
    ] {
        assert_eq!(
            word(&bytes, offset),
            opcode,
            "kernel restore at {offset:#x}"
        );
    }
    assert_eq!(branch_target(&bytes, 0x2b87674), 0x2b879d4);
    assert_eq!(branch_target(&bytes, 0x2b87c10), 0x2ba060c);
    // The readback contract is not a native instruction-retirement oracle,
    // and the later sweep's writes cannot supply earlier physical state.
}

#[test]
#[ignore = "requires pinned original J473 kernelcache; no Apple image is committed"]
fn original_kernel_isp_stop_is_a_restore_write_not_an_initial_state_or_admission_oracle() {
    let bytes = kernelcache();
    for (start, end, digest) in [
        (
            0x2ba0938,
            0x2ba0980,
            "1963c0417c6426cf589fe1cb819134abc021ce27e828610af819a5bd6f9c9f82",
        ),
        (
            0x2b7c55c,
            0x2b7c590,
            "bc96144768d8644bdf138450e6c3a04b359ab2fd4c20257980dc6cc5ae9e0f89",
        ),
        (
            0x2b7c650,
            0x2b7c680,
            "c95668d6597ce2dc8c63e6476467636ab2f97286a0667bc1673ceffb436ce81e",
        ),
        (
            0x2b7c69c,
            0x2b7c6b0,
            "cd5fd9ee504ed61adba684167569599b6b963442d7cf5571f7c6d8634ac683e6",
        ),
        (
            0x2b7c760,
            0x2b7c7f0,
            "0e0e8a160353d1fa02ad8546d07df1356ddea07cb9dfb3d7858de4581ba57e7e",
        ),
        (
            0x2b8c380,
            0x2b8c468,
            "8aa3f40d3b609754d7bef90dd76d041be5e011d1a89ccfb8f73b815bc2079cc0",
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(&bytes[start..end])), digest);
    }
    // V1 reverse sweep uses the driver's desired-level cache, not a live
    // target/current snapshot. Desired f is skipped in this pass.
    assert_eq!(word(&bytes, 0x2ba0958), 0x39400124);
    assert_eq!(word(&bytes, 0x2ba095c), 0x71003c9f);
    assert_eq!(word(&bytes, 0x2ba0974), 0x52800005); // auto=false
    assert_eq!(branch_target(&bytes, 0x2ba097c), 0x2b7c294);
    // _setPSLevel reads the real control before checking the existing target
    // and bits30/10. Its separate auto-enable comparison must also agree.
    for (offset, opcode) in [
        (0x2b7c574, 0x12000c1c),
        (0x2b7c578, 0x6b19039f),
        (0x2b7c57c, 0x12165008),
        (0x2b7c580, 0x12023108),
        (0x2b7c584, 0x7a400900),
        (0x2b7c69c, 0x12040368),
        (0x2b7c6a0, 0x4a4872e8),
        (0x2b7c65c, 0x128061e8), // clear mask 0x30f
        (0x2b7c664, 0x33000f3b), // insert requested low4
        (0x2b7c670, 0x3218077b), // requested<15 adds 0x300
        (0x2b7c794, 0x531c6f24), // expected current=requested<<4
        (0x2b7c7cc, 0x52801e03), // current readback mask f0
        (0x2b8c3a0, 0xaa0303f7), // preserve raw value in x23
        (0x2b8c458, 0xf9400c08), // resolved bank mapping
        (0x2b8c45c, 0xb8344917), // captured STR w23,[x8,w20,uxtw]
    ] {
        assert_eq!(word(&bytes, offset), opcode, "restore at {offset:#x}");
    }
    // This explains the captured write from the model's active fallback;
    // neither this calculation nor the setter establishes actual handoff.
    let supplied_old = 0xff_u32;
    let requested = 0_u32;
    assert_eq!((supplied_old & !0x30f) | requested | 0x300, 0x3f0);
    let capture_pc = 0xffff_fe00_381b_c45c_u64;
    let kernelcache_slide = 0x2e62_c000_u64;
    let image_base = 0xffff_fe00_0700_4000_u64;
    assert_eq!(capture_pc - kernelcache_slide - image_base, 0x2b8c45c);
    // A raw-zero target can take the no-store branch with auto=false; source
    // does not prove raw zero, and that branch does not test current bits7:4.
    assert_eq!(word(&bytes, 0x2b7c588), 0x540008a0);
    assert_eq!(word(&bytes, 0x2b7c6ac), 0x36081788);
}

#[test]
#[ignore = "requires pinned original J473 kernelcache; no Apple image is committed"]
fn original_kernel_cio_trigger_and_wait_preserve_the_unqualified_sram_boundary() {
    let bytes = kernelcache();
    for (start, end, digest) in [
        (
            0x2bb7188,
            0x2bb7224,
            "7dd0ae8590ddf759cb3f968e32642943d9529cb66ac9822465dd3b2393dc7769",
        ),
        (
            0x2fa5a44,
            0x2fa5b3c,
            "6a05ae9c464202826e4fa7f62fa5e55e7b6a31986531a1508232faedea06c034",
        ),
        (
            0x2ba6f4c,
            0x2ba6fd4,
            "aa69da33d41d23899cfbaed4514b7d1422f5f2f243d57791b454440421f29433",
        ),
        (
            0x2ba6fd4,
            0x2ba713c,
            "eed89f813082e4f44c25b6092f868fd5f7872a70bd339f5ae99e50ff31b0d788",
        ),
        (
            0x2fa31bc,
            0x2fa3620,
            "33e30d4cf0b5bb05b04e723778217f3a9075b778267755532b6bba8503658d10",
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(&bytes[start..end])), digest);
    }
    assert_eq!(quad(&bytes, 0x134f6e8 + 16 + 0xa78), 0x8011233a02fa5a44);
    assert_eq!(quad(&bytes, 0x1351a98), 0x8011000002ba6f4c);
    for (offset, opcode) in [
        (0x2fa5a60, 0x52900008), // nonzero index offset8000
        (0x2fa5a64, 0x52880009), // index0 offset4000
        (0x2fa5a8c, 0x52800c61), // original RegMap63
        (0x2fa5ad0, 0x32000003), // preserve original control, set bit0
        (0x2fa5b10, 0x52800042), // wait mask2
        (0x2ba704c, 0x6a15001f), // test actual physical read against mask
        (0x2fa35ac, 0x52800c61), // initRegMaps63 -> original reg41
        (0x2fa35b0, 0x52800522),
    ] {
        assert_eq!(word(&bytes, offset), opcode, "CIO trigger at {offset:#x}");
    }
    assert_eq!(branch_target(&bytes, 0x2fa5b34), 0x2fb2380);
    assert_eq!(branch_target(&bytes, 0x2ba7048), 0x2bcd7ec);
    // Mask clearance, timeout and workloop wake behavior are actual driver
    // requirements. None identifies a completed native sequence or its final
    // PS values without physical trigger-to-sequence and retirement evidence.
}

#[test]
#[ignore = "requires pinned original J473 kernelcache; no Apple image is committed"]
fn original_kernel_gpce_maps_and_cio_sleep_do_not_imply_native_retirement() {
    let bytes = kernelcache();
    for (start, end, digest) in [
        (
            0x2b8d394,
            0x2b8d654,
            "8305d646a1c18a2e0d7b412edf1ee7dd1e570d6d3f791bf9d0131da7bd87c02b",
        ),
        (
            0x2fa59ac,
            0x2fa5a44,
            "b509233456d0f966478abb1d3ad6b9fb871a1d1b020992238bddccdaa71af9a8",
        ),
        (
            0x2fa5c18,
            0x2fa5cd8,
            "2303d612ff4d74d3e9ce70b77d7aa8c65574d9850a40e620515411185374408f",
        ),
        (
            0x2ba7770,
            0x2ba77d8,
            "9940fef4c5ccf5a498e55e6c1bafe0fc59db4712c1e68b81c23f6976f620deaa",
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(&bytes[start..end])), digest);
    }
    // Follow the actual IOCommandGate allocation and authenticated sleep slot.
    // The local byte is an event identity, not a proven sleep output parameter.
    for (start, end, digest) in [
        (
            0x2b683c4,
            0x2b683d8,
            "7713ba40d3e92126ecaf22aa3ad5e40b8d08b68f554749e9e2ef979345e49b2e",
        ),
        (
            0x2bcd96c,
            0x2bcd97c,
            "efc542f6c249c31c5be8f2923477f13328fd24cac874732213c98a1ffbf87465",
        ),
        (
            0x540c2c0,
            0x540c358,
            "a3f5befa875a295ee275b5a411d1e5f02fb161e6ba2fa1247cb58ef95320e42a",
        ),
        (
            0x540abc0,
            0x540ac9c,
            "5c4cc17efc223b04396a661aab1a5a97add08c35b8486c38b655565bb2dd08cf",
        ),
        (
            0x54077b8,
            0x5407904,
            "8b3e40e93319a726ee9ed2918309acbcd3a3dbfa05323e0a8c0da2db6d4a5606",
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(&bytes[start..end])), digest);
    }
    assert_eq!(quad(&bytes, 0x12778d0), 0x801100000540d5ac);
    assert_eq!(quad(&bytes, 0xf02f10 + 16 + 0x210), 0x801110e10540c2c0);
    assert_eq!(branch_target(&bytes, 0x540c338), 0x540abc0);
    assert_eq!(branch_target(&bytes, 0x5407868), 0x4c07e20);
    // All read/write/wait wrappers preserve their actual map and die argument;
    // a request register is not a substitute for SRAM/PC or every PS register.
    for offset in [0x2b8d3d8, 0x2b8d44c, 0x2b8d4c8] {
        assert_eq!(word(&bytes, offset), 0x52800c41); // RegMap62
    }
    for offset in [0x2b8d538, 0x2b8d5ac, 0x2b8d628] {
        assert_eq!(word(&bytes, offset), 0x52800c61); // RegMap63
    }
    for (offset, opcode) in [
        (0x2b8d3a4, 0xb9400108), // actual die count object+631c
        (0x2b8d3ac, 0x54000242), // invalid die rejects before register dispatch
        (0x2fa59f4, 0x52800259), // separate diagnostic capture: eighteen words
        (0x2fa5a10, 0xb9000b40), // retain actual read result in diagnostic row
        (0x2fa5a28, 0x3707fdf6), // second diagnostic cluster, not PS table
        (0x2fa5c6c, 0x12000c08), // VDD CIO sync tests actual low4
        (0x2fa5c7c, 0x71003d1f), // first word f or inspect second word
        (0x2fa5c88, 0x1a9f17e1), // actual PS comparison becomes VDD CIO argument
        (0x2ba7010, 0x3900ffff), // local event byte starts zero
        (0x540c2e0, 0xaa0103f5), // commandSleep preserves event pointer
        (0x5407860, 0xaa1503e2), // workloop passes event identity to lock sleep
        (0x2ba70e8, 0x3940ffe8), // read local event byte after commandSleep
        (0x2ba70ec, 0x3607fa88), // zero event byte retries actual physical read
        (0x2ba7104, 0xd65f0fff), // syntactic nonzero-byte fallthrough; no writer qualified
    ] {
        assert_eq!(word(&bytes, offset), opcode, "controller at {offset:#x}");
    }
    // TBZ's signed imm14 identifies the actual retry target independently of
    // the source-window hash. A syntactic fallthrough exists, but sleep takes
    // the byte address as an event key; no writer making it nonzero is qualified.
    let test_branch = word(&bytes, 0x2ba70ec);
    let displacement = ((((test_branch >> 5) & 0x3fff) << 18) as i32 >> 16) as isize;
    assert_eq!(0x2ba70ecusize.wrapping_add_signed(displacement), 0x2ba703c);
    // Neither a clear mask nor commandSleep returning qualifies a selected
    // native sequence, end retirement or the complete initial handoff state.
}

#[test]
#[ignore = "requires pinned original J473 LLB; no Apple image is committed"]
fn original_llb_group_table_publication_retains_actual_metadata_and_pointer_widths() {
    let bytes = llb();
    for (start, end, digest) in [
        (
            0x4d1b4,
            0x4d2cc,
            "5200f1b2c54fc7f4310d7484018b4e9ff996be3f1f12736d113508071ec87fd1",
        ),
        (
            0x4e244,
            0x4e2ec,
            "e345dc6d8feacf8d182b4cb8ceb12f5f5e4b86cefbb2e7982156461cf4e301b4",
        ),
        (
            0x4f1b4,
            0x4f304,
            "4e1d756207b5a578e9aef39bee4d420bb6204f7eafafbba227d6bc6bff2922a6",
        ),
        (
            0x4f304,
            0x4f398,
            "6ecd82ed2d4dad1d4e1d517291a5341e7d3ab3de4fce3d5c66c10c122ddf1709",
        ),
    ] {
        assert_eq!(hex::encode(Sha256::digest(&bytes[start..end])), digest);
    }
    for (offset, opcode) in [
        (0x4d20c, 0x321827ea), // groups0/1 table base fragment mask3ff00
        (0x4d248, 0xd348fd29), // groups2/3 table PA shifted eight
        (0x4d250, 0xd348fd29),
        (0x4d264, 0x12be000a), // groups2/3 retain twenty-eight base bits
        (0x4d268, 0x0a090141), // selected base fragment, no guessed high bits
        (0x4d664, 0xd344a6c1), // actual code PA bits41:4
        (0x4d668, 0x531d7288), // pointer-table slot stride eight
        (0x4d66c, 0x8b0802a0), // actual group table PA plus slot offset
        (0x103a0, 0xf9000001), // pointer store is64-bit
        (0x103a8, 0xb9000001), // controller field store is32-bit
        (0x4f1e8, 0xb9400109), // metadata word1 is a physical input
        (0x4f1ec, 0x53144d29), // word1 shift uses32-bit arithmetic
        (0x4f1f0, 0xb85fc10a), // separate metadata word0 read
        (0x4f1f4, 0xd3741d4a), // word0 low8 supplies page offset
        (0x4f208, 0xeb17001f), // actual region end bounds before allocation
        (0x4f238, 0x52802001), // table alignment256
        (0x4f250, 0xa901fd00), // publish actual allocated group table PA
        (0x4f254, 0x91040000), // reserve256 bytes per actual group
        (0x4f268, 0x52800401), // code pool alignment32
    ] {
        assert_eq!(word(&bytes, offset), opcode, "table/SRAM at {offset:#x}");
    }
    assert_eq!(branch_target(&bytes, 0x4d284), 0x103a8);
    assert_eq!(branch_target(&bytes, 0x4d690), 0x103a0);
    // These encode actual installation effects, not a hardware decoder for
    // request->table->selected PC. Metadata and supplied SRAM stay required.
}
