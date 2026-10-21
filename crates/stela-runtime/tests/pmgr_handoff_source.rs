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
                assert_ne!(word(row, 0) >> 16, 7);
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
