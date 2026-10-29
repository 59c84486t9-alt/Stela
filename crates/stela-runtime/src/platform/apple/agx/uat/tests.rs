use super::*;
use stela_contracts::dma::test_support::Ram;

#[test]
fn leaf_flags_round_trip_and_match_the_kext_constants() {
    // encodePTEFlags(kind=1, ap=GPU(2), pxn=1, uxn=1, gpu=1, attr=uncached)
    let flags = Flags {
        access: Access::Gpu,
        memory: MemoryAttr::Uncached,
        global: true,
        pxn: true,
        uxn: true,
        gpu_access: true,
    };
    let bits = flags.encode();
    // Global base 0x403, AP 2 << 6, attr 2 << 2, PXN|UXN|GPU high bits.
    assert_eq!(
        bits,
        0x403 | (2 << 6) | (2 << 2) | (1 << 53) | (1 << 54) | (1 << 55)
    );
    assert_eq!(Flags::decode(bits), Some(flags));
    // kind 0 clears bit 0x400 route but sets non-global 0xc03.
    let ng = Flags {
        global: false,
        ..flags
    };
    assert_eq!(ng.encode() & 0xc03, 0xc03);
    assert!(!Flags::decode(ng.encode()).unwrap().global);
}

#[test]
fn descriptor_and_gptbat_encodings_match_the_kext() {
    assert_eq!(
        encode_pte(0x1_2345_c000, &demo_flags()) & output_mask(40),
        0x12345c000
    );
    assert_eq!(encode_table(0x8_0100_7fff), 0x8_0100_4000 | 3);
    assert_eq!(
        encode_gptbat(5, 0x8_0040_0123, 0x8_0080_0000),
        [0x8_0040_0000 | (5 << 48) | 1, 0x8_0080_0000 | (5 << 48) | 1]
    );
}

fn demo_flags() -> Flags {
    Flags {
        access: Access::FirmwareGpu,
        memory: MemoryAttr::Cached,
        global: true,
        pxn: false,
        uxn: false,
        gpu_access: true,
    }
}

#[test]
fn indices_split_the_input_and_select_the_half() {
    let (half, idx) = indices(0);
    assert_eq!(half, Half::Ttbr0);
    assert_eq!(idx, [0, 0, 0]);
    // Set one bit in each level field and the TTBR1 select.
    let input = TTBR_SELECT_BIT | (1 << 36) | (2 << 25) | (3 << 14) | 0x3ab;
    let (half, idx) = indices(input);
    assert_eq!(half, Half::Ttbr1);
    assert_eq!(idx, [1, 2, 3]);
}

#[test]
fn a_three_level_walk_reaches_a_mapped_page_and_reports_faults() {
    // Build PCE -> PDE -> PTE tables in RAM for input 0.
    let mut ram = Ram::new(0x8_0000_0000, 0x1_0000 * 4);
    let pce = 0x8_0000_0000;
    let pde = 0x8_0000_4000;
    let pte = 0x8_0000_8000;
    let page = 0x8_0000_c000;
    ram.put_u64(pce, encode_table(pde));
    ram.put_u64(pde, encode_table(pte));
    let flags = demo_flags();
    ram.put_u64(pte, encode_pte(page, &flags));
    let got = translate(&mut ram, pce, 0x20, 40).unwrap();
    assert_eq!(got.physical, page | 0x20);
    assert_eq!(got.flags, flags);
    // An unmapped sibling leaf faults as not-present at the leaf level.
    assert_eq!(
        translate(&mut ram, pce, PAGE_BYTES, 40),
        Err(Fault::NotPresent { level: 2 })
    );
    // Bits above the 39-bit space must repeat the TTBR-select bit.
    assert_eq!(
        translate(&mut ram, pce, 1 << 40, 40),
        Err(Fault::OutOfRange)
    );
    assert_eq!(
        translate(&mut ram, pce, TTBR_SELECT_BIT, 40),
        Err(Fault::OutOfRange)
    );
    // A missing top-level table reads as zero and faults present at 0.
    ram.put_u64(pce, 0);
    assert_eq!(
        translate(&mut ram, pce, 0, 40),
        Err(Fault::NotPresent { level: 0 })
    );
}

#[test]
fn a_table_outside_ram_faults_on_memory() {
    let mut ram = Ram::new(0x8_0000_0000, 0x4000);
    // PCE points at a table far outside the RAM region.
    ram.put_u64(0x8_0000_0000, encode_table(0x9_0000_0000));
    assert_eq!(
        translate(&mut ram, 0x8_0000_0000, 0, 40),
        Err(Fault::Memory { level: 1 })
    );
}

/// RAM holding a TTBAT at its base and one firmware page mapped at the
/// TTBR1 VA `0xffff_ffa0_0000_4000` of context 0 with `flags`.
fn firmware_space(flags: Flags) -> (Ram, Uat, u64, u64) {
    let base = 0x8_0000_0000;
    let mut ram = Ram::new(base, 0x4000 * 6);
    let (ttbat, pce, pde, pte, page) = (
        base,
        base + 0x4000,
        base + 0x8000,
        base + 0xc000,
        base + 0x1_0000,
    );
    let [ttbr0, ttbr1] = encode_gptbat(0, 0, pce);
    ram.put_u64(ttbat, ttbr0 & !VALID);
    ram.put_u64(ttbat + 8, ttbr1);
    let va = 0xffff_ffa0_0000_4000;
    let (_, idx) = indices(va);
    ram.put_u64(pce + idx[0] as u64 * 8, encode_table(pde));
    ram.put_u64(pde + idx[1] as u64 * 8, encode_table(pte));
    ram.put_u64(pte + idx[2] as u64 * 8, encode_pte(page, &flags));
    let mut uat = Uat::new(40);
    uat.configure(ttbat).unwrap();
    (ram, uat, va, page)
}

fn port_read(
    uat: &mut Uat,
    agent: Agent,
    ram: &mut Ram,
    context: usize,
    va: u64,
) -> Result<u64, DmaError> {
    use stela_contracts::dma::Port;
    use stela_contracts::interrupt::InterruptLatch;
    let mut latch = InterruptLatch::new();
    let mut access = BusAccess::new(0, 0, &mut latch);
    let mut view = uat.agent(agent);
    let mut port = Port {
        iommu: &mut view,
        stream: context,
        memory: ram,
        access: &mut access,
    };
    let mut word = [0; 8];
    port.read(va, &mut word)?;
    Ok(u64::from_le_bytes(word))
}

fn shared(access: Access, uxn: bool, pxn: bool) -> Flags {
    Flags {
        access,
        memory: MemoryAttr::Uncached,
        global: true,
        pxn,
        uxn,
        gpu_access: true,
    }
}

#[test]
fn the_firmware_reads_its_ttbr1_objects_through_the_ttbat() {
    let (mut ram, mut uat, va, page) = firmware_space(shared(Access::Firmware, true, false));
    ram.put_u64(page + 0x10, 0x0c8a_6342_8392_04c8);
    // The 44-bit address the kext sends widens to the TTBR1 VA.
    assert_eq!(canonical_firmware_va(va & ((1 << 44) - 1)), va);
    assert_eq!(
        port_read(
            &mut uat,
            Agent::Firmware,
            &mut ram,
            FIRMWARE_CONTEXT,
            va + 0x10
        ),
        Ok(0x0c8a_6342_8392_04c8)
    );
    // Context 0's TTBR0 is invalid: a user-half access faults and is recorded.
    assert_eq!(
        port_read(&mut uat, Agent::Firmware, &mut ram, 0, 0x4000),
        Err(DmaError::Fault(FAULT_TRANSLATION))
    );
    let fault = uat.last_fault().unwrap();
    assert_eq!((fault.context, fault.address), (0, 0x4000));
    // A firmware-RW page denies GPU accesses.
    assert_eq!(
        port_read(&mut uat, Agent::Gpu, &mut ram, 0, va),
        Err(DmaError::Fault(FAULT_PERMISSION))
    );
    // A context past the TTBAT refuses.
    assert!(matches!(
        port_read(&mut uat, Agent::Firmware, &mut ram, CONTEXTS, va),
        Err(DmaError::Unsupported(_))
    ));
}

#[test]
fn every_context_shares_the_kernel_window_through_the_shared_l2() {
    // Contexts 0 and 3 with empty TTBR1 roots; the shared L2 maps one
    // page of the window for both, firmware and GPU alike.
    let base = 0x8_0000_0000;
    let mut ram = Ram::new(base, 0x4000 * 6);
    let (ttbat, root0, root3, l2, pte, page) = (
        base,
        base + 0x4000,
        base + 0x8000,
        base + 0xc000,
        base + 0x1_0000,
        base + 0x1_4000,
    );
    for (context, root) in [(0u16, root0), (3, root3)] {
        let [ttbr0, ttbr1] = encode_gptbat(context, root, root);
        ram.put_u64(ttbat + u64::from(context) * 16, ttbr0);
        ram.put_u64(ttbat + u64::from(context) * 16 + 8, ttbr1);
    }
    let va = 0xffff_ffa0_0000_4000;
    let (_, idx) = indices(va);
    assert_eq!(idx[0], SHARED_INDEX);
    let flags = Flags {
        access: Access::FirmwareGpu,
        uxn: true,
        pxn: true,
        ..demo_flags()
    };
    ram.put_u64(l2 + idx[1] as u64 * 8, encode_table(pte));
    ram.put_u64(pte + idx[2] as u64 * 8, encode_pte(page, &flags));
    ram.put_u64(page, 0x5157_e1a0);
    let mut uat = Uat::new(40);
    uat.configure(ttbat).unwrap();
    // Before the boot stage names the shared L2, the window faults.
    assert_eq!(
        port_read(&mut uat, Agent::Firmware, &mut ram, 0, va),
        Err(DmaError::Fault(FAULT_TRANSLATION))
    );
    uat.share_kernel_window(l2).unwrap();
    assert_eq!(uat.shared_l2(), Some(l2));
    assert_eq!(
        port_read(&mut uat, Agent::Firmware, &mut ram, 0, va),
        Ok(0x5157_e1a0)
    );
    assert_eq!(
        port_read(&mut uat, Agent::Gpu, &mut ram, 3, va),
        Ok(0x5157_e1a0)
    );
    // TTBR1 outside the window still walks the context's own root.
    assert_eq!(
        port_read(
            &mut uat,
            Agent::Firmware,
            &mut ram,
            0,
            0xffff_ff80_0000_4000
        ),
        Err(DmaError::Fault(FAULT_TRANSLATION))
    );
    assert_eq!(
        uat.last_fault().map(|fault| fault.fault),
        Some(Fault::NotPresent { level: 0 })
    );
    // An invalid TTBAT entry still refuses the context.
    ram.put_u64(ttbat + 3 * 16 + 8, 0);
    assert_eq!(
        port_read(&mut uat, Agent::Gpu, &mut ram, 3, va),
        Err(DmaError::Fault(FAULT_TRANSLATION))
    );
    assert!(uat.share_kernel_window(0).is_err());
    assert!(uat.share_kernel_window(1 << 40).is_err());
}

#[test]
fn physical_gate_prevents_a_real_agent_walk_and_retains_the_mapping() {
    let (mut ram, mut uat, va, page) = firmware_space(shared(Access::FirmwareGpu, true, true));
    ram.put_u64(page, 0x12345678);
    assert_eq!(
        port_read(&mut uat, Agent::Firmware, &mut ram, FIRMWARE_CONTEXT, va),
        Ok(0x12345678)
    );
    uat.set_available(false);
    for agent in [Agent::Firmware, Agent::Gpu] {
        assert_eq!(
            port_read(&mut uat, agent, &mut ram, FIRMWARE_CONTEXT, va),
            Err(DmaError::Unsupported(
                "SGX DMA while PMGR inhibits execution"
            ))
        );
    }
    uat.set_available(true);
    assert_eq!(
        port_read(&mut uat, Agent::Firmware, &mut ram, FIRMWARE_CONTEXT, va),
        Ok(0x12345678)
    );
}

#[test]
fn the_coprocessor_port_reaches_a_context_with_gpu_permissions() {
    // Context 0's TTBR0 maps a GPU-RW page (AP 2, UXN 1, PXN 0): the
    // firmware's own accesses are denied there, while the GPU stream
    // of the same context reads it.
    let base = 0x8_0000_0000;
    let mut ram = Ram::new(base, 0x4000 * 6);
    let (ttbat, pce, pde, pte, page) = (
        base,
        base + 0x4000,
        base + 0x8000,
        base + 0xc000,
        base + 0x1_0000,
    );
    let [ttbr0, ttbr1] = encode_gptbat(5, pce, pce);
    ram.put_u64(ttbat + 5 * 16, ttbr0);
    ram.put_u64(ttbat + 5 * 16 + 8, ttbr1);
    let va = 0x11_0000_4000;
    let (_, idx) = indices(va);
    ram.put_u64(pce + idx[0] as u64 * 8, encode_table(pde));
    ram.put_u64(pde + idx[1] as u64 * 8, encode_table(pte));
    let flags = shared(Access::Gpu, true, false);
    ram.put_u64(pte + idx[2] as u64 * 8, encode_pte(page, &flags));
    ram.put_u64(page + 8, 0xa6e5);
    let mut uat = Uat::new(40);
    uat.configure(ttbat).unwrap();
    assert_eq!(
        port_read(&mut uat, Agent::Firmware, &mut ram, 5, va + 8),
        Err(DmaError::Fault(FAULT_PERMISSION))
    );
    assert_eq!(
        port_read(
            &mut uat,
            Agent::Firmware,
            &mut ram,
            gpu_stream(5).unwrap(),
            va + 8
        ),
        Ok(0xa6e5)
    );
    // An unmapped GPU address faults and is recorded as the GPU's.
    assert_eq!(
        port_read(
            &mut uat,
            Agent::Firmware,
            &mut ram,
            gpu_stream(5).unwrap(),
            0x4000
        ),
        Err(DmaError::Fault(FAULT_TRANSLATION))
    );
    let fault = uat.last_fault().unwrap();
    assert_eq!(
        (fault.agent, fault.context, fault.address),
        (Agent::Gpu, 5, 0x4000)
    );
    // The context tag must still match, and the context fit the TTBAT.
    assert!(matches!(
        port_read(
            &mut uat,
            Agent::Firmware,
            &mut ram,
            gpu_stream(4).unwrap(),
            va
        ),
        Err(DmaError::Fault(FAULT_TRANSLATION))
    ));
    assert!(matches!(
        gpu_stream(CONTEXTS),
        Err(DmaError::Unsupported(_))
    ));
}

#[test]
fn leaf_permissions_follow_the_established_encodings() {
    let fw_ro = shared(Access::Firmware, false, false);
    assert_eq!(permits(&fw_ro, Agent::Firmware), RO);
    let fw_rw_gpu_ro = shared(Access::Firmware, true, true);
    assert_eq!(permits(&fw_rw_gpu_ro, Agent::Gpu), RO);
    assert_eq!(permits(&shared(Access::Gpu, false, true), Agent::Gpu), WO);
    assert_eq!(
        permits(&shared(Access::FirmwareGpu, true, true), Agent::Firmware),
        RW
    );
    // Without the GPU-access bit no source states the meaning.
    let hidden = Flags {
        gpu_access: false,
        ..fw_ro
    };
    assert_eq!(permits(&hidden, Agent::Firmware), None);
    // A firmware write to a read-only page faults on permission.
    let (mut ram, mut uat, va, _) = firmware_space(fw_ro);
    use stela_contracts::interrupt::InterruptLatch;
    let mut latch = InterruptLatch::new();
    let mut access = BusAccess::new(0, 0, &mut latch);
    let mut view = uat.agent(Agent::Firmware);
    assert_eq!(
        view.translate(&mut ram, 0, va, va + 7, true, &mut access),
        Err(DmaError::Fault(FAULT_PERMISSION))
    );
    assert_eq!(uat.last_fault().unwrap().fault, Fault::Permission);
}

#[test]
fn an_unconfigured_or_misaligned_ttbat_refuses() {
    let mut uat = Uat::new(40);
    let mut ram = Ram::new(0x8_0000_0000, 0x4000);
    assert!(matches!(
        port_read(&mut uat, Agent::Firmware, &mut ram, 0, 0),
        Err(DmaError::Unsupported(_))
    ));
    assert!(uat.configure(0x8_0000_0100).is_err());
    assert!(uat.configure(1 << 40).is_err());
    assert!(Uat::new(42).configure(1 << 40).is_ok());
}

/// T600x and T602x DRAM lies at 1 TiB: their 42-bit entries reach it,
/// where a 40-bit translator would drop the address's top bits.
#[test]
fn a_42_bit_translator_reaches_dram_above_one_tebibyte() {
    let base = 0x100_0000_0000;
    let mut ram = Ram::new(base, 0x4000 * 4);
    let (pce, pde, pte, page) = (base, base + 0x4000, base + 0x8000, base + 0xc000);
    ram.put_u64(pce, encode_table(pde));
    ram.put_u64(pde, encode_table(pte));
    ram.put_u64(pte, encode_pte(page, &demo_flags()));
    assert_eq!(
        translate(&mut ram, pce, 0x10, 42).unwrap().physical,
        page | 0x10
    );
    assert!(translate(&mut ram, pce, 0x10, 40).is_err());
}

#[test]
fn an_output_address_past_the_profile_never_aliases_a_lower_page() {
    // This catches masking a malformed high PA down to a valid table
    // or target. Exercise every descriptor level on both profile widths.
    for bits in [40, 42] {
        let base = 0x8_0000_0000;
        let mut ram = Ram::new(base, 4 * PAGE_BYTES as usize);
        let entries = [base, base + PAGE_BYTES, base + 2 * PAGE_BYTES];
        let valid = [
            encode_table(entries[1]),
            encode_table(entries[2]),
            encode_pte(base + 3 * PAGE_BYTES, &demo_flags()),
        ];
        for (address, entry) in entries.into_iter().zip(valid) {
            ram.put_u64(address, entry);
        }
        for (level, address) in entries.into_iter().enumerate() {
            ram.put_u64(address, valid[level] | 1 << bits);
            assert_eq!(
                translate(&mut ram, base, 0, bits),
                Err(Fault::BadAddress {
                    level: level as u32
                })
            );
            ram.put_u64(address, valid[level]);
        }
        for root in [base | 8, base | 1 << bits] {
            assert_eq!(
                translate(&mut ram, root, 0, bits),
                Err(Fault::BadAddress { level: 0 })
            );
        }
        assert_eq!(
            translate(&mut ram, base, 0, bits).unwrap().physical,
            base + 3 * PAGE_BYTES
        );
    }
}

#[test]
fn unsupported_descriptors_are_not_successful_page_mappings() {
    let base = 0x8_0000_0000;
    let mut ram = Ram::new(base, 4 * PAGE_BYTES as usize);
    let entries = [base, base + PAGE_BYTES, base + 2 * PAGE_BYTES];
    let valid = [
        encode_table(entries[1]),
        encode_table(entries[2]),
        encode_pte(base + 3 * PAGE_BYTES, &demo_flags()),
    ];
    for (address, entry) in entries.into_iter().zip(valid) {
        ram.put_u64(address, entry);
    }
    for (level, address) in entries.into_iter().enumerate() {
        // Block descriptors, unknown low flags, and unknown high flags
        // have no implemented effects. Keep them explicit model limits.
        for bad in [
            valid[level] & !2,
            valid[level] | 1 << 12,
            valid[level] | 1 << 63,
        ] {
            ram.put_u64(address, bad);
            assert_eq!(
                translate(&mut ram, base, 0, 40),
                Err(Fault::UnsupportedDescriptor {
                    level: level as u32
                })
            );
        }
        ram.put_u64(address, valid[level]);
    }
    for bad in [valid[2] & !ACCESS_FLAG, valid[2] | ATTR_MASK] {
        ram.put_u64(entries[2], bad);
        assert_eq!(
            translate(&mut ram, base, 0, 40),
            Err(Fault::UnsupportedDescriptor { level: 2 })
        );
    }
}

#[test]
fn malformed_roots_and_unreadable_tables_preserve_fault_diagnostics() {
    let flags = shared(Access::FirmwareGpu, true, true);
    for level in 0..3 {
        let (mut ram, mut uat, va, _) = firmware_space(flags);
        let ttbat = ram.base;
        let root = ttbat + PAGE_BYTES;
        let (_, idx) = indices(va);
        let missing = ttbat + 10 * PAGE_BYTES;
        let at = match level {
            0 => {
                uat.configure(missing).unwrap();
                None
            }
            1 => Some(root + idx[0] as u64 * ENTRY_BYTES),
            _ => Some(root + PAGE_BYTES + idx[1] as u64 * ENTRY_BYTES),
        };
        if let Some(at) = at {
            ram.put_u64(at, encode_table(missing));
        }
        assert_eq!(
            port_read(&mut uat, Agent::Gpu, &mut ram, 0, va),
            Err(DmaError::Memory)
        );
        assert_eq!(
            uat.last_fault(),
            Some(FaultRecord {
                agent: Agent::Gpu,
                context: 0,
                address: va,
                write: false,
                fault: Fault::Memory { level },
            })
        );
    }
    let (mut ram, mut uat, va, _) = firmware_space(flags);
    let root_word = ram.base + 8;
    let valid = encode_gptbat(0, 0, ram.base + PAGE_BYTES)[1];
    ram.put_u64(root_word, valid | 1 << 40);
    assert_eq!(
        port_read(&mut uat, Agent::Firmware, &mut ram, 0, va),
        Err(DmaError::Fault(FAULT_TRANSLATION))
    );
    assert_eq!(
        uat.last_fault().unwrap().fault,
        Fault::BadAddress { level: 0 }
    );
    for invalid in [valid | 2, valid | 1 << 56] {
        ram.put_u64(root_word, invalid);
        assert!(matches!(
            port_read(&mut uat, Agent::Firmware, &mut ram, 0, va),
            Err(DmaError::Unsupported(_))
        ));
    }
}

#[test]
fn noncanonical_inputs_are_rejected_before_any_memory_access() {
    struct Inaccessible;
    impl Memory for Inaccessible {
        fn read(&mut self, _: u64, _: &mut [u8]) -> bool {
            panic!("a malformed VA must not reach physical memory");
        }
        fn write(&mut self, _: u64, _: &[u8]) -> bool {
            panic!("a malformed VA must not reach physical memory");
        }
    }
    let mut memory = Inaccessible;
    let mut uat = Uat::new(40);
    uat.configure(0x8_0000_0000).unwrap();
    for va in [
        TTBR_SELECT_BIT,
        1 << 40,
        0xffff_ffff_ffff & !TTBR_SELECT_BIT,
    ] {
        assert_eq!(
            uat.walk(&mut memory, Agent::Gpu, 0, va, true),
            Err(DmaError::Fault(FAULT_TRANSLATION))
        );
        assert_eq!(
            uat.last_fault(),
            Some(FaultRecord {
                agent: Agent::Gpu,
                context: 0,
                address: va,
                write: true,
                fault: Fault::OutOfRange,
            })
        );
    }
}

#[test]
fn firmware_owned_mappings_never_grant_gpu_access() {
    for access in [
        Access::FirmwareGpu,
        Access::Firmware,
        Access::Gpu,
        Access::None,
    ] {
        for xn in 0..4 {
            let flags = Flags {
                gpu_access: false,
                ..shared(access, xn & 2 != 0, xn & 1 != 0)
            };
            let (mut ram, mut uat, va, _) = firmware_space(flags);
            assert_eq!(
                port_read(&mut uat, Agent::Gpu, &mut ram, 0, va),
                Err(DmaError::Fault(FAULT_PERMISSION))
            );
        }
    }
}

#[test]
fn protection_table_enforces_each_agent_and_direction_without_writing_denied_memory() {
    use stela_contracts::dma::Port;
    use stela_contracts::interrupt::InterruptLatch;
    // Independent permission tables in m1n1 PTE.access_fw/access_gpu,
    // OS=1, AP rows and (UXN << 1 | PXN) columns. 1=read, 2=write;
    // None is its uncertain firmware "-?" entry.
    let firmware = [
        [Some(0), Some(1), None, Some(3)],
        [Some(1), Some(0), Some(3), Some(3)],
        [Some(0); 4],
        [Some(0); 4],
    ];
    let gpu = [[0, 1, 2, 3], [0, 0, 0, 1], [1, 2, 3, 0], [0; 4]];
    for ap in 0..4 {
        for xn in 0..4 {
            for agent in [Agent::Firmware, Agent::Gpu] {
                let expected = match agent {
                    Agent::Firmware => firmware[ap][xn],
                    Agent::Gpu => Some(gpu[ap][xn]),
                };
                for write in [false, true] {
                    let flags = shared(
                        Access::from_bits(ap as u64).unwrap(),
                        xn & 2 != 0,
                        xn & 1 != 0,
                    );
                    let (mut ram, mut uat, va, page) = firmware_space(flags);
                    ram.put_u64(page, 0xaabb_ccdd);
                    let before = ram.bytes.clone();
                    let mut latch = InterruptLatch::new();
                    let mut access = BusAccess::new(0, 0, &mut latch);
                    let mut view = uat.agent(agent);
                    let mut port = Port {
                        iommu: &mut view,
                        stream: 0,
                        memory: &mut ram,
                        access: &mut access,
                    };
                    let mut buffer = [0; 8];
                    let result = if write {
                        port.write(va, &0x1234u64.to_le_bytes())
                    } else {
                        port.read(va, &mut buffer)
                    };
                    match expected {
                        None => assert!(matches!(result, Err(DmaError::Unsupported(_)))),
                        Some(bits) if bits & if write { 2 } else { 1 } == 0 => {
                            assert_eq!(result, Err(DmaError::Fault(FAULT_PERMISSION)));
                            assert_eq!(uat.last_fault().unwrap().write, write);
                        }
                        Some(_) => {
                            assert_eq!(result, Ok(()));
                            if !write {
                                assert_eq!(u64::from_le_bytes(buffer), 0xaabb_ccdd);
                            }
                        }
                    }
                    if result.is_err() || !write {
                        assert_eq!(ram.bytes, before);
                    }
                }
            }
        }
    }
}
