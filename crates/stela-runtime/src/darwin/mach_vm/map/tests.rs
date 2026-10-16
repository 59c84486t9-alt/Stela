use super::*;
use crate::darwin::GUEST_PAGE_BYTES;

const READ_WRITE: u64 = (PROTECTION_READ | PROTECTION_WRITE) as u64;
const ALIAS_TAG: u8 = 60;
const BASE: u64 = 0x100000000;
const UNKNOWN_FLAG: u64 = 0x100;
const TASK_NAME: u64 = 257;
const ADDRESS_POINTER: u64 = 0x9000000f428;
const OBSERVED_BYTES: u64 = 8 * GUEST_PAGE_BYTES;

fn arguments(size: u64, mask: u64, flags: u64, protection: u64) -> [u64; ARGUMENT_COUNT] {
    [TASK_NAME, ADDRESS_POINTER, size, mask, flags, protection]
}

fn completion(arguments: [u64; ARGUMENT_COUNT], initial: u64) -> i32 {
    match plan(arguments, initial).unwrap() {
        Plan::Complete(result) => result,
        Plan::Allocate(_) => panic!("expected a completed validation error"),
    }
}

#[test]
fn observed_request_preserves_alias_maximum_and_implicit_inheritance() -> Result<()> {
    let flags = u64::from(FLAGS_ANYWHERE) | (u64::from(ALIAS_TAG) << FLAGS_ALIAS_SHIFT);
    let Plan::Allocate(request) = plan(
        arguments(OBSERVED_BYTES, GUEST_PAGE_MASK, flags, READ_WRITE),
        BASE,
    )?
    else {
        panic!("valid observed request declined");
    };
    assert!(matches!(
        request.placement,
        DataPlacement::Anywhere { hint: BASE }
    ));
    assert_eq!(request.bytes, OBSERVED_BYTES);
    assert_eq!(request.alignment_mask, GUEST_PAGE_MASK);
    assert_eq!(request.alias_tag, ALIAS_TAG);
    assert!(request.current.readable && request.current.writable && !request.current.executable);
    assert!(request.maximum.readable && request.maximum.writable && request.maximum.executable);
    assert!(matches!(request.inheritance, DataInheritance::Copy));
    Ok(())
}

#[test]
fn low32_flags_and_protection_do_not_truncate_size_or_mask() -> Result<()> {
    let Plan::Allocate(request) = plan(
        arguments(
            GUEST_PAGE_BYTES + 1,
            1 << 40,
            (1 << 48) | u64::from(FLAGS_ANYWHERE),
            (1 << 48) | READ_WRITE,
        ),
        BASE + 1,
    )?
    else {
        panic!("low32 truncation failed")
    };
    assert!(matches!(
        request.placement,
        DataPlacement::Anywhere { hint: BASE }
    ));
    assert_eq!(request.bytes, 2 * GUEST_PAGE_BYTES);
    assert_eq!(request.alignment_mask, (1 << 40) | GUEST_PAGE_MASK);
    assert_eq!(
        completion(
            arguments(1 << 63, 0, u64::from(FLAGS_ANYWHERE), READ_WRITE),
            BASE
        ),
        KERN_NO_SPACE
    );
    Ok(())
}

#[test]
fn fixed_start_is_realigned_before_adding_size_and_mask_precedes_bounds() -> Result<()> {
    let Plan::Allocate(request) = plan(
        arguments(GUEST_PAGE_BYTES, 0, 0, READ_WRITE),
        BASE + GUEST_PAGE_MASK,
    )?
    else {
        panic!("unaligned fixed request failed");
    };
    assert!(matches!(request.placement, DataPlacement::Fixed(BASE)));
    assert_eq!(request.bytes, GUEST_PAGE_BYTES);
    assert_eq!(
        completion(
            arguments(1, DIRECT_RAM_USER_END, 0, READ_WRITE),
            DIRECT_RAM_USER_END
        ),
        KERN_NO_SPACE
    );
    assert_eq!(
        completion(arguments(1, 0, 0, READ_WRITE), DIRECT_RAM_USER_END),
        KERN_INVALID_ADDRESS
    );
    Ok(())
}

#[test]
fn invalid_flags_protections_zero_and_overflow_complete_without_allocation() {
    for (size, mask, flags, protection, initial) in [
        (0, 0, 0, READ_WRITE, BASE),
        (1, 0, UNKNOWN_FLAG, READ_WRITE, BASE),
        (1, 0, 0, 0x10, BASE),
        (u64::MAX, 0, u64::from(FLAGS_ANYWHERE), READ_WRITE, BASE),
        (u64::MAX, 0, 0, READ_WRITE, BASE),
    ] {
        assert_eq!(
            completion(arguments(size, mask, flags, protection), initial),
            KERN_INVALID_ARGUMENT
        );
    }
}

#[test]
fn valid_unimplemented_mapping_policies_explicitly_decline() {
    for (flags, protection) in [
        (FLAGS_PURGABLE, READ_WRITE),
        (FLAGS_TPRO, READ_WRITE),
        (FLAGS_OVERWRITE, READ_WRITE),
        (FLAGS_RETURN_DATA_ADDRESS, READ_WRITE),
        (0, u64::from(PROTECTION_EXECUTE)),
        (0, u64::from(PROTECTION_IS_MASK)),
        (0, u64::from(PROTECTION_WRITE)),
    ] {
        assert!(plan(arguments(1, 0, u64::from(flags), protection), BASE).is_err());
    }
    for initial in [GUEST_PAGE_BYTES, DIRECT_RAM_USER_END] {
        assert!(
            plan(
                arguments(1, initial, u64::from(FLAGS_SUPERPAGE_MASK), READ_WRITE),
                initial
            )
            .is_err()
        );
    }
}
