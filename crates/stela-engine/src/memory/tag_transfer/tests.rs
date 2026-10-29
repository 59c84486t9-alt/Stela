use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Effect {
    Read(Access),
    Tag(Access, AllocationTag),
    Data(Access, [u8; TAG_GRANULE_BYTES]),
}

#[derive(Default)]
struct Observer {
    effects: Vec<Effect>,
    fault_at: Option<usize>,
}

impl Observer {
    fn record(&mut self, effect: Effect) -> Result<(), &'static str> {
        if self.fault_at == Some(self.effects.len()) {
            return Err("access fault");
        }
        self.effects.push(effect);
        Ok(())
    }
}

impl Memory for Observer {
    type Error = &'static str;

    fn read_tag(&mut self, access: Access) -> Result<AllocationTag, Self::Error> {
        self.record(Effect::Read(access))?;
        Ok(AllocationTag::new(((access.address >> TAG_BITS) & TAG_MASK) as u8).unwrap())
    }

    fn write_tag(&mut self, access: Access, tag: AllocationTag) -> Result<(), Self::Error> {
        self.record(Effect::Tag(access, tag))
    }

    fn write_data16(
        &mut self,
        access: Access,
        data: [u8; TAG_GRANULE_BYTES],
    ) -> Result<(), Self::Error> {
        self.record(Effect::Data(access, data))
    }
}

fn profile(privileged: bool, check_sp: bool) -> Profile {
    Profile::new(privileged, check_sp, 64, 64).unwrap()
}

fn state() -> GuestState {
    let mut state = GuestState::default();
    state.x.fill(0xa500_0000_0000_2000);
    state.sp = 0xb300_0000_0000_3040;
    state.nzcv = 0xf000_0000;
    state.reserved = 0xa5a5_5a5a;
    state.v.fill([0x1234_5678_9abc_def0, 0xfedc_ba98_7654_3210]);
    state.fpcr = 0x0300_0000;
    state.fpsr = 0x0800_009f;
    state
}

fn register(value: u8, sp: bool) -> Register {
    if value == REGISTER_31 {
        if sp { Register::Sp } else { Register::Zero }
    } else {
        Register::X(value)
    }
}

#[test]
fn load_merges_old_destination_and_zero_still_accesses_memory() {
    for destination in [Register::X(0), Register::X(1), Register::Zero] {
        let mut registers = state();
        registers.x[1] = 0xc900_1234_5678_9abc;
        let initial = registers.clone();
        let mut observer = Observer::default();
        let result = complete(
            Operand::LoadTag {
                destination,
                base: Register::Sp,
                displacement: -16,
            },
            &mut registers,
            profile(false, true),
            &mut observer,
        )
        .unwrap();
        assert_eq!(result.effective_address, initial.sp - 16);
        assert_eq!(result.completed.tag_reads, 1);
        let mut expected = initial.clone();
        let tag = AllocationTag::new(3).unwrap();
        write(
            &mut expected,
            destination,
            tag.apply_to_address(read(&initial, destination)),
        );
        assert_eq!(registers, expected);
        assert!(matches!(&observer.effects[..], [Effect::Read(access)]
            if access.address == initial.sp - 16 && !access.tag_checked));
    }
}

#[test]
fn tag_store_all_register_aliases_stage_old_sources_before_writeback() {
    for source in 0..=REGISTER_31 {
        for base in 0..=REGISTER_31 {
            for mode in [
                AddressMode::Offset,
                AddressMode::PreIndex,
                AddressMode::PostIndex,
            ] {
                for kind in [
                    StoreKind::Tag,
                    StoreKind::TagPair,
                    StoreKind::ZeroTag,
                    StoreKind::ZeroTagPair,
                ] {
                    let source = register(source, true);
                    let base = register(base, true);
                    let mut registers = state();
                    let initial = registers.clone();
                    let mut observer = Observer::default();
                    complete(
                        Operand::StoreTags {
                            kind,
                            source,
                            base,
                            displacement: -16,
                            mode,
                        },
                        &mut registers,
                        profile(false, true),
                        &mut observer,
                    )
                    .unwrap();
                    let mut expected = initial.clone();
                    writeback(&mut expected, base, read(&initial, base), -16, mode);
                    assert_eq!(registers, expected);
                    let expected_tag = AllocationTag::from_address(read(&initial, source));
                    for effect in &observer.effects {
                        if let Effect::Tag(access, tag) = effect {
                            assert_eq!(*tag, expected_tag);
                            assert_eq!(access.pair, kind == StoreKind::ZeroTagPair);
                            assert!(!access.zero_bulk);
                            assert_eq!(
                                access.data_registers,
                                [
                                    Some(index(source)),
                                    if kind == StoreKind::ZeroTagPair {
                                        Some(index(source))
                                    } else {
                                        None
                                    }
                                ]
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn pair_uses_address_tag_and_snapshots_both_data_aliases() {
    for mode in [
        AddressMode::Offset,
        AddressMode::PreIndex,
        AddressMode::PostIndex,
    ] {
        for data in [
            [Register::X(0), Register::X(0)],
            [Register::X(0), Register::Zero],
            [Register::Zero, Register::X(0)],
        ] {
            let mut registers = state();
            let initial = registers.clone();
            let mut observer = Observer::default();
            complete(
                Operand::StorePair {
                    data,
                    base: Register::X(0),
                    displacement: 16,
                    mode,
                },
                &mut registers,
                profile(false, true),
                &mut observer,
            )
            .unwrap();
            let address = effective(initial.x[0], 16, mode);
            let packed = u128::from(read(&initial, data[0]))
                | (u128::from(read(&initial, data[1])) << u64::BITS);
            assert!(
                matches!(&observer.effects[..], [Effect::Data(access, bytes), Effect::Tag(tag_access, tag)]
                if *bytes == packed.to_le_bytes() && access.address == address && access.pair
                && tag_access.address == address && *tag == AllocationTag::from_address(address))
            );
            let mut expected = initial.clone();
            writeback(&mut expected, Register::X(0), initial.x[0], 16, mode);
            assert_eq!(registers, expected);
        }
    }
}

#[test]
fn faults_preserve_registers_and_report_successful_callbacks() {
    for operand in [
        Operand::StoreTags {
            kind: StoreKind::ZeroTagPair,
            source: Register::X(0),
            base: Register::X(0),
            displacement: 16,
            mode: AddressMode::PreIndex,
        },
        Operand::StoreTags {
            kind: StoreKind::TagPair,
            source: Register::Sp,
            base: Register::Sp,
            displacement: -16,
            mode: AddressMode::PostIndex,
        },
        Operand::StorePair {
            data: [Register::X(0), Register::X(1)],
            base: Register::X(0),
            displacement: -16,
            mode: AddressMode::PreIndex,
        },
        Operand::BulkTags {
            kind: BulkKind::Load,
            data: Register::X(0),
            base: Register::X(0),
        },
        Operand::BulkTags {
            kind: BulkKind::StoreZero,
            data: Register::X(0),
            base: Register::Sp,
        },
    ] {
        let mut successful = Observer::default();
        complete(operand, &mut state(), profile(true, true), &mut successful).unwrap();
        for fault_at in 0..successful.effects.len() {
            let mut registers = state();
            let initial = registers.clone();
            let mut observer = Observer {
                effects: Vec::new(),
                fault_at: Some(fault_at),
            };
            let fault =
                complete(operand, &mut registers, profile(true, true), &mut observer).unwrap_err();
            assert_eq!(registers, initial);
            assert_eq!(observer.effects, successful.effects[..fault_at]);
            assert_eq!(
                fault.completed.tag_reads as usize
                    + fault.completed.tag_writes as usize
                    + fault.completed.data_granules as usize,
                fault_at
            );
            assert!(matches!(
                fault.cause,
                Cause::Access {
                    error: "access fault",
                    ..
                }
            ));
        }
    }
}

#[test]
fn bulk_load_places_nibbles_by_address_and_commits_after_all_reads() {
    for start in [0, 4, 8, 12] {
        let mut registers = state();
        registers.x[0] = 0xd700_0000_0000_2000 + start * u64::from(TAG_GRANULE_BYTES_U32);
        let initial = registers.clone();
        let mut observer = Observer::default();
        let completion = complete(
            Operand::BulkTags {
                kind: BulkKind::Load,
                data: Register::X(0),
                base: Register::X(0),
            },
            &mut registers,
            profile(true, true),
            &mut observer,
        )
        .unwrap();
        let mut expected = initial;
        expected.x[0] =
            (start..start + 4).fold(0, |value, tag| value | tag << (tag as u32 * TAG_BITS));
        assert_eq!(registers, expected);
        assert_eq!(completion.completed.tag_reads, 4);
        assert_eq!(observer.effects.len(), 4);
    }
}

#[test]
fn privilege_precedes_sp_and_profile_controls_alignment() {
    let mut registers = state();
    registers.sp |= 1;
    let initial = registers.clone();
    let bulk = Operand::BulkTags {
        kind: BulkKind::Load,
        data: Register::X(0),
        base: Register::Sp,
    };
    let mut observer = Observer::default();
    let fault = complete(bulk, &mut registers, profile(false, true), &mut observer).unwrap_err();
    assert_eq!(fault.cause, Cause::UndefinedPrivilege);
    let fault = complete(bulk, &mut registers, profile(true, true), &mut observer).unwrap_err();
    assert_eq!(
        fault.cause,
        Cause::StackAlignment {
            stack_pointer: initial.sp
        }
    );
    assert!(observer.effects.is_empty());
    assert_eq!(registers, initial);
    let load = Operand::LoadTag {
        destination: Register::Zero,
        base: Register::Sp,
        displacement: 0,
    };
    let result = complete(load, &mut registers, profile(false, false), &mut observer).unwrap();
    assert_eq!(result.effective_address, initial.sp & !TAG_GRANULE_MASK);
    assert_eq!(registers, initial);
}

#[test]
fn malformed_blocks_are_profile_errors_and_random_tag_is_not_memory() {
    for bytes in [0, 4, 15, 17, 512] {
        assert_eq!(
            Profile::new(false, true, bytes, 64),
            Err(ProfileError::GmidBlockSize)
        );
    }
    for bytes in [0, 4, 15, 17, u32::MAX] {
        assert_eq!(
            Profile::new(false, true, 64, bytes),
            Err(ProfileError::DczidBlockSize)
        );
    }
    let mut registers = state();
    let initial = registers.clone();
    let mut observer = Observer::default();
    let result = complete(
        Operand::RandomTag {
            destination: Register::Sp,
            address: Register::Sp,
            mask: Register::Zero,
        },
        &mut registers,
        profile(false, true),
        &mut observer,
    );
    assert_eq!(result.unwrap_err().cause, Cause::NotMemoryInstruction);
    assert_eq!(registers, initial);
    assert!(observer.effects.is_empty());
}

#[test]
fn malformed_public_operands_leave_every_state_and_callback_untouched() {
    let mut operands = vec![
        Operand::LoadTag {
            destination: Register::Sp,
            base: Register::Sp,
            displacement: 0,
        },
        Operand::StoreTags {
            kind: StoreKind::ZeroTagPair,
            source: Register::Zero,
            base: Register::Sp,
            displacement: 0,
            mode: AddressMode::PreIndex,
        },
        Operand::BulkTags {
            kind: BulkKind::StoreZero,
            data: Register::Sp,
            base: Register::Sp,
        },
        Operand::StorePair {
            data: [Register::Sp, Register::Zero],
            base: Register::Sp,
            displacement: 0,
            mode: AddressMode::PostIndex,
        },
        Operand::StorePair {
            data: [Register::Zero; 2],
            base: Register::Zero,
            displacement: 0,
            mode: AddressMode::Offset,
        },
    ];
    for invalid in REGISTER_31..=u8::MAX {
        operands.push(Operand::LoadTag {
            destination: Register::X(invalid),
            base: Register::Sp,
            displacement: 0,
        });
        operands.push(Operand::BulkTags {
            kind: BulkKind::StoreZero,
            data: Register::Zero,
            base: Register::X(invalid),
        });
    }
    for displacement in [i32::MIN, -1, 1, i32::MAX] {
        operands.push(Operand::LoadTag {
            destination: Register::Zero,
            base: Register::Sp,
            displacement,
        });
        operands.push(Operand::StorePair {
            data: [Register::Zero; 2],
            base: Register::Sp,
            displacement,
            mode: AddressMode::PreIndex,
        });
    }
    for operand in operands {
        let mut registers = state();
        let before = registers.clone();
        let mut observer = Observer::default();
        let fault =
            complete(operand, &mut registers, profile(false, true), &mut observer).unwrap_err();
        assert_eq!(fault.cause, Cause::InvalidOperands);
        assert_eq!(fault.completed, Progress::default());
        assert_eq!(registers, before);
        assert!(observer.effects.is_empty());
    }
}

#[test]
fn zero_tag_pair_preserves_original_tag_descriptor_and_splits_data_pair() {
    let mut registers = state();
    let mut observer = Observer::default();
    complete(
        Operand::StoreTags {
            kind: StoreKind::ZeroTagPair,
            source: Register::Sp,
            base: Register::Sp,
            displacement: 0,
            mode: AddressMode::Offset,
        },
        &mut registers,
        profile(false, true),
        &mut observer,
    )
    .unwrap();
    assert_eq!(observer.effects.len(), 4);
    for (index, effect) in observer.effects.iter().enumerate() {
        let access = match effect {
            Effect::Data(access, _) | Effect::Tag(access, _) => access,
            Effect::Read(_) => panic!("STZ2G must not read tags"),
        };
        assert_eq!(access.pair, index >= 2);
        assert_eq!(access.data_registers, [Some(REGISTER_31); 2]);
    }
}
