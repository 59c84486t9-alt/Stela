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
