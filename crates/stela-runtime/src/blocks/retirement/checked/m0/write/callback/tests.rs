use super::*;
use crate::memory::domain::m0_write::M0WriteSource;
use stela_compiler::{GuestAddress, GuestState, Lifter, aarch64::Decoder};
#[test]
fn every_narrow_store_validates_original_full_staging_before_publication() {
    for word in [
        0x39000020_u32,
        0x79000020,
        0xb9000020,
        0xf9000020,
        0xa9000440,
    ] {
        let instruction = Decoder.lift(GuestAddress(0x1000), word).unwrap();
        let source = M0WriteSource::from_source(&instruction, word).unwrap();
        let mut registers = GuestState::default();
        registers.x[0] = 0x8899aabbccddeeff;
        registers.x[1] = 0x123456789abcdef0;
        let intent = source.intent(&registers);
        let mut staging = intent.data.map(u64::to_le);
        // SAFETY: own two private stack slots; metadata only, no effect/loan.
        assert!(unsafe { staged_values_match(intent, staging.as_ptr().cast()) });
        staging[0] ^= 1;
        // Width1/2/4 MUST validate their sole full staging slot; dividing
        // guestbytes by8 would silently accept this corruption.
        assert!(!unsafe { staged_values_match(intent, staging.as_ptr().cast()) });
        staging[0] ^= 1;
        staging[1] ^= 1;
        assert_eq!(
            unsafe { staged_values_match(intent, staging.as_ptr().cast()) },
            intent.member_count() == 1
        );
    }
}
