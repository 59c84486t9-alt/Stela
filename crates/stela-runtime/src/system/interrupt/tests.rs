use super::*;

fn request(key: u16, access: AccessKind, rt: u8) -> Request {
    let encoding = Encoding::new(
        (key >> SELECTOR_OP0_SHIFT) as u8,
        ((key >> SELECTOR_OP1_SHIFT) & 0b111) as u8,
        ((key >> SELECTOR_CRN_SHIFT) & 0b1111) as u8,
        ((key >> SELECTOR_CRM_SHIFT) & 0b1111) as u8,
        (key & 0b111) as u8,
    );
    match access {
        AccessKind::Read => Request::read(encoding, rt),
        AccessKind::Write { value } => Request::write(encoding, rt, value),
    }
}

#[test]
fn acknowledge_eoi_and_sgi_are_operations_not_register_storage() {
    let context = Context::default();
    for (key, access, operation) in [
        (
            ICC_IAR0_EL1,
            AccessKind::Read,
            Operation::Acknowledge(Group::Group0),
        ),
        (
            ICC_IAR1_EL1,
            AccessKind::Read,
            Operation::Acknowledge(Group::Group1),
        ),
        (
            ICC_HPPIR1_EL1,
            AccessKind::Read,
            Operation::HighestPending(Group::Group1),
        ),
        (
            ICC_EOIR0_EL1,
            AccessKind::Write { value: u64::MAX },
            Operation::EndOfInterrupt(Group::Group0, u64::MAX),
        ),
        (
            ICC_EOIR1_EL1,
            AccessKind::Write { value: u64::MAX },
            Operation::EndOfInterrupt(Group::Group1, u64::MAX),
        ),
        (
            ICC_DIR_EL1,
            AccessKind::Write { value: u64::MAX },
            Operation::Deactivate(u64::MAX),
        ),
        (
            ICC_SGI0R_EL1,
            AccessKind::Write { value: u64::MAX },
            Operation::GenerateSgi(SgiKind::Group0, u64::MAX),
        ),
        (
            ICC_SGI1R_EL1,
            AccessKind::Write { value: u64::MAX },
            Operation::GenerateSgi(SgiKind::Group1, u64::MAX),
        ),
        (
            ICC_ASGI1R_EL1,
            AccessKind::Write { value: u64::MAX },
            Operation::GenerateSgi(SgiKind::OtherSecurityGroup1, u64::MAX),
        ),
    ] {
        assert_eq!(
            resolve(request(key, access, 0), &context),
            Resolution::BackendRequired(BackendRequest {
                interface: Interface::Physical,
                bank: Bank::Unbanked,
                operation
            })
        );
    }
}

#[test]
fn xzr_read_keeps_acknowledge_effect_and_xzr_write_supplies_zero() {
    let context = Context::default();
    assert_eq!(
        resolve(request(ICC_IAR1_EL1, AccessKind::Read, 31), &context),
        Resolution::BackendRequired(BackendRequest {
            interface: Interface::Physical,
            bank: Bank::Unbanked,
            operation: Operation::Acknowledge(Group::Group1)
        })
    );
    assert_eq!(
        resolve(
            request(ICC_EOIR1_EL1, AccessKind::Write { value: u64::MAX }, 31),
            &context
        ),
        Resolution::BackendRequired(BackendRequest {
            interface: Interface::Physical,
            bank: Bank::Unbanked,
            operation: Operation::EndOfInterrupt(Group::Group1, 0)
        })
    );
}

#[test]
fn wrong_direction_is_not_an_ordinary_register_access() {
    for key in [
        ICC_IAR0_EL1,
        ICC_IAR1_EL1,
        ICC_HPPIR0_EL1,
        ICC_HPPIR1_EL1,
        ICC_RPR_EL1,
        ICC_NMIAR1_EL1,
    ] {
        assert_eq!(
            resolve(
                request(key, AccessKind::Write { value: 0 }, 0),
                &Context::default()
            ),
            Resolution::NotHandled
        );
    }
    for key in [
        ICC_EOIR0_EL1,
        ICC_EOIR1_EL1,
        ICC_DIR_EL1,
        ICC_SGI0R_EL1,
        ICC_SGI1R_EL1,
        ICC_ASGI1R_EL1,
    ] {
        assert_eq!(
            resolve(request(key, AccessKind::Read, 0), &Context::default()),
            Resolution::NotHandled
        );
    }
    assert_eq!(
        resolve(
            request(selector(3, 0, 12, 9, 4), AccessKind::Read, 0),
            &Context::default()
        ),
        Resolution::NotHandled
    );
}

#[test]
fn priority_register_index_boundaries_and_banked_routing() {
    for priority_bits in 5..=7 {
        for index in 0..4 {
            for key in [ICC_AP0R0_EL1 + index, ICC_AP1R0_EL1 + index] {
                let context = Context {
                    priority_bits,
                    ..Context::default()
                };
                let expected_present =
                    index == 0 || (index == 1 && priority_bits >= 6) || priority_bits >= 7;
                assert_eq!(
                    matches!(
                        resolve(request(key, AccessKind::Read, 0), &context),
                        Resolution::BackendRequired(_)
                    ),
                    expected_present
                );
            }
        }
    }
    for security in [
        SecurityState::Secure,
        SecurityState::NonSecure,
        SecurityState::Realm,
    ] {
        let context = Context {
            profile: Profile {
                el3_present: true,
                security,
                ..Context::default().profile
            },
            ..Context::default()
        };
        let bank = if security == SecurityState::Secure {
            Bank::Secure
        } else {
            Bank::NonSecure
        };
        assert_eq!(
            resolve(request(ICC_BPR1_EL1, AccessKind::Read, 0), &context),
            Resolution::BackendRequired(BackendRequest {
                interface: Interface::Physical,
                bank,
                operation: Operation::ReadConfiguration(ConfigurationRegister::BinaryPoint(
                    Group::Group1
                ))
            })
        );
    }
}

#[test]
fn extended_gcie_registers_are_not_claimed_or_silently_stored() {
    for key in [
        ICC_PPI_HMR0_EL1,
        ICC_IDR0_EL1,
        ICC_HPPIR_EL1,
        ICC_IAFFIDR_EL1,
    ] {
        assert_eq!(
            resolve(
                request(key, AccessKind::Write { value: 0 }, 0),
                &Context::default()
            ),
            Resolution::NotHandled
        );
    }

    for key in [
        ICC_APR_EL1,
        ICC_CR0_EL1,
        ICC_PCR_EL1,
        ICC_PPI_HMR0_EL1,
        ICC_IDR0_EL1,
        ICC_PPI_PRIORITYR15_EL1,
    ] {
        assert_eq!(
            resolve(request(key, AccessKind::Read, 0), &Context::default()),
            Resolution::Undefined
        );
        let context = Context {
            gcie: true,
            ..Context::default()
        };
        assert!(matches!(
            resolve(request(key, AccessKind::Read, 0), &context),
            Resolution::Unsupported(_)
        ));
        let context = Context {
            profile: Profile {
                current_el: ExceptionLevel::El0,
                ..context.profile
            },
            ..context
        };
        assert_eq!(
            resolve(request(key, AccessKind::Read, 0), &context),
            Resolution::Undefined
        );
    }
}
