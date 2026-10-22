use super::super::{Error, KeySlot, PacketNumber};
use sha2::{Digest, Sha256};

fn value(i: u64) -> u64 {
    match i {
        0 => 0,
        1 => 1,
        2 => (1 << 48) - 1,
        3 => (1 << 48) - 2,
        _ => (i * 0x0102_0304_0507) & ((1 << 48) - 1),
    }
}

#[test]
fn parent_replay_counter_projection_matches_complete_mt76_qos_helper() {
    // Counter-primitive model only: no installed physical key, DMA or RX users.
    // Full unchanged C helper/flags are emitted by wifi_group_replay_oracle.py.
    // The complete unchanged helper ASan/UBSan trace covers 1,048,576 cases.
    // This does not establish grouping, BA, integrity or hardware authority.
    let mut slot = unsafe { KeySlot::new(8).unwrap() };
    let mut digest = Sha256::new();
    for tid in 0..16 {
        for i in 0..256 {
            for j in 0..256 {
                slot.rx_pn = [0; 17];
                slot.rx_pn[tid] = value(i);
                let result = slot.commit_receive(tid, PacketNumber::new(value(j)).unwrap());
                assert!(result.is_ok() || result == Err(Error::Replay));
                digest.update([u8::from(result.is_ok())]);
                digest.update(&slot.rx_pn[tid].to_be_bytes()[2..]);
                digest.update([u8::from(result.is_ok())]);
            }
        }
    }
    assert_eq!(
        digest.finalize().as_slice(),
        &[
            0x93, 0x9a, 0xfb, 0xc6, 0x62, 0x90, 0x0e, 0x35, 0x27, 0x7d, 0x94, 0x59, 0x73, 0x87,
            0xd2, 0xf5, 0x58, 0xd5, 0xcb, 0x6a, 0x58, 0xd0, 0xba, 0x41, 0x83, 0x3d, 0x05, 0x0a,
            0xcb, 0x6a, 0xa7, 0xc3,
        ]
    );
}
