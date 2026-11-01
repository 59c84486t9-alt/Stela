use super::*;
use alloc::collections::BTreeSet;

/// The T8112's own lookups.
fn lookup(encoding: Encoding) -> Option<&'static Entry> {
    super::lookup(encoding, Chip::AppleM2)
}

/// Every entry has a value of its own, at an address that a later write
/// keeps, for native code to reach.
#[test]
fn each_register_keeps_its_value_at_its_own_address() {
    let slots = TABLE.iter().map(|entry| entry.encoding).fold(
        BTreeSet::new(),
        |mut slots: BTreeSet<_>, encoding| {
            slots.insert((slot(encoding), encoding.selector()));
            slots
        },
    );
    assert!(slots.iter().all(|&(at, _)| at < SLOTS));
    let distinct: BTreeSet<_> = slots.iter().map(|&(at, _)| at).collect();
    assert_eq!(distinct.len(), slots.len());
    let entry = TABLE
        .iter()
        .find(|entry| entry.class == Class::Storage && entry.scope == Scope::Pe)
        .unwrap();
    let mut registers = Registers::default();
    let address = registers.storage(entry);
    assert!(registers.read(entry).is_err());
    registers.write(entry, 7).unwrap();
    assert_eq!(registers.storage(entry), address);
    // SAFETY: the address is of the registers' live value.
    assert_eq!(unsafe { *(address as *const u64) }, 7);
    assert_eq!(registers.read(entry), Ok(7));
}

/// A store alone completes the writes of registers that have no more to
/// them, and of values without the bits that say otherwise.
#[test]
fn stored_writes_leave_out_what_the_engine_decides() {
    let of = |encoding| TABLE.iter().find(|entry| entry.encoding == encoding).unwrap();
    assert_eq!(of(THREAD_KEY_0).stored_write(), Some(0));
    assert_eq!(of(SWITCH_CLEARED).stored_write(), Some(u64::MAX));
    assert_eq!(of(SIQ_CFG_EL1).stored_write(), None);
    assert_eq!(of(PMCR1_GL1).stored_write(), None);
    assert!(of(SIQ_CFG_EL1).reads_storage());
    assert!(!of(TRACE_VA_C5_7).reads_storage());
}

/// The table is the M2's: its components access every entry, and each
/// chip's census is sorted for its search. An entry another chip never
/// accesses is not looked up there.
#[test]
fn the_table_applies_where_each_chips_census_shows_the_encoding() {
    for entry in TABLE {
        assert!(
            Chip::ALL.iter().any(|&chip| consumed(entry.encoding, chip)),
            "{}",
            entry.name
        );
    }
    for selectors in census::CONSUMED {
        assert!(selectors.windows(2).all(|pair| pair[0] < pair[1]));
    }
    let absent = TABLE
        .iter()
        .find(|entry| !consumed(entry.encoding, Chip::AppleM1))
        .expect("an M2 entry the M1's components never access");
    assert!(super::lookup(absent.encoding, Chip::AppleM1).is_none());
    assert!(super::lookup(absent.encoding, Chip::AppleM2).is_some());
    // HID18 is accessed on every chip.
    for chip in Chip::ALL {
        assert!(super::lookup(HID18, chip).is_some(), "{}", chip.name());
    }
}

/// Independent bit ranges from the pinned header: every named field is
/// preserved, while every hole refuses without changing state or counts.
#[test]
fn objc_prediction_fields_are_checked_on_each_consuming_chip() {
    for chip in Chip::ALL {
        for (encoding, ranges) in [
            (BP_OBJC_ADR_EL1, &[(0, 55)][..]),
            (BP_OBJC_CTL_EL1, &[(0, 6), (12, 21), (27, 52)][..]),
        ] {
            let found = super::lookup(encoding, chip);
            if chip == Chip::AppleM1 {
                assert!(found.is_none());
                continue;
            }
            let entry = found.unwrap();
            assert_eq!(entry.class, Class::Prediction);
            assert_eq!(entry.scope, Scope::Pe);
            let mut registers = Registers::default();
            assert_eq!(registers.read(entry), Ok(0)); // Model reset choice.
            let mut all_fields = 0;
            for bit in 0..64 {
                let value = 1 << bit;
                if ranges
                    .iter()
                    .any(|&(low, high)| (low..=high).contains(&bit))
                {
                    registers.write(entry, value).unwrap();
                    assert_eq!(registers.read(entry), Ok(value));
                    all_fields |= value;
                }
            }
            registers.write(entry, all_fields).unwrap();
            let writes = registers.writes.clone();
            for bit in 0..64 {
                if !ranges
                    .iter()
                    .any(|&(low, high)| (low..=high).contains(&bit))
                {
                    assert!(registers.write(entry, all_fields | (1 << bit)).is_err());
                    assert_eq!(registers.read(entry), Ok(all_fields));
                    assert_eq!(registers.writes, writes);
                }
            }
            assert_eq!(entry.unmodeled_effect(all_fields), None);
        }
    }
}

/// Joining a cluster must never turn prediction configuration into shared
/// state. SPTM's temporary zero and restore affect only the current PE.
#[test]
fn objc_prediction_save_clear_restore_stays_per_pe() {
    for chip in &Chip::ALL[1..] {
        let address = super::lookup(BP_OBJC_ADR_EL1, *chip).unwrap();
        let control = super::lookup(BP_OBJC_CTL_EL1, *chip).unwrap();
        let mut first = Registers::default();
        first.write(address, 0x00ab_cdef_1234_5678).unwrap();
        first.write(control, 0x001a_bcde_f83b_107f).unwrap();
        let mut second = Registers::default();
        second.join(&first);
        assert_eq!(second.read(address), Ok(0));
        assert_eq!(second.read(control), Ok(0));
        second.write(address, 0x1234).unwrap();
        second.write(control, 0x107f).unwrap();
        let saved = first.read(control).unwrap();
        first.write(control, 0).unwrap();
        assert_eq!(first.read(address), Ok(0x00ab_cdef_1234_5678));
        assert_eq!(first.read(control), Ok(0));
        assert_eq!(second.read(control), Ok(0x107f));
        first.write(control, saved).unwrap();
        assert_eq!(first.read(control), Ok(saved));
        assert_eq!(second.read(address), Ok(0x1234));
    }
}

#[test]
fn siq_cfg_owner_rejects_unqualified_fields_before_mutation() {
    for chip in Chip::ALL {
        let Some(entry) = super::lookup(SIQ_CFG_EL1, chip) else {
            continue;
        };
        assert_eq!(entry.class, Class::Control);
        assert_eq!(entry.permitted, SIQ_CFG_MODE);
        assert_eq!(entry.scope, Scope::Pe);
        let mut registers = Registers::default();
        for mode in [0, 2, 3] {
            registers.write(entry, mode).unwrap();
            assert_eq!(registers.read(entry), Ok(mode));
        }
        let values = registers.values.clone();
        let reads = registers.reads.clone();
        let writes = registers.writes.clone();
        for value in [1, u64::MAX].into_iter().chain((2..64).map(|bit| 1 << bit)) {
            assert_eq!(
                registers.write(entry, value),
                Err("SIQ_CFG_EL1 mode 1 or nonzero upper bits lack source-qualified effects")
            );
            assert_eq!(registers.values, values);
            assert_eq!(registers.reads, reads);
            assert_eq!(registers.writes, writes);
        }
    }
}

#[test]
fn storage_refuses_reads_before_writes_and_tuning_starts_at_zero() {
    let mut registers = Registers::default();
    let storage = lookup(SPTM_KEY_0).unwrap();
    assert!(registers.read(storage).is_err());
    registers.write(storage, 2).unwrap();
    assert_eq!(registers.read(storage), Ok(2));
    let control = lookup(THREAD_CONTROL).unwrap();
    assert_eq!(registers.read(control), Ok(0));
    registers.write(control, 0).unwrap();
    assert!(registers.write(control, 2).is_err());
    let tuning = entry(
        Encoding::new(3, 5, IMPDEF_CRN, 15, 7),
        "S3_5_C15_C15_7 (outside the table)",
        Class::Tuning,
        "test",
    );
    assert_eq!(registers.read(&tuning), Ok(0));
    assert_eq!(
        registers.used().count(),
        2,
        "only table entries are reported"
    );
}

#[test]
fn every_entry_is_a_distinct_impdef_encoding_on_each_chip_with_evidence() {
    let mut seen = BTreeSet::new();
    for entry in TABLE {
        assert_eq!(entry.encoding.op0(), 3);
        assert!(matches!(entry.encoding.crn(), 11 | 15), "{}", entry.name);
        assert!(!entry.evidence.is_empty());
        for chip in entry.chips {
            assert!(
                seen.insert((*chip as usize, entry.encoding.selector())),
                "{} {}",
                entry.name,
                chip.name()
            );
        }
        assert!(entry.permitted == 0 || matches!(entry.class, Class::Control | Class::Prediction));
        assert!(entry.handoff == 0 || entry.class == Class::Status);
    }
}

/// Error records report no error and take their clearing writes; the
/// information registers refuse writes.
#[test]
fn error_records_read_zero_and_clearing_writes_change_nothing() {
    let mut registers = Registers::default();
    let status = lookup(L2C_ERR_STS).unwrap();
    assert_eq!(status.scope, Scope::Cluster);
    // _llcErrorHandler's write-one-to-clear of the bit it handled.
    registers.write(status, 1).unwrap();
    assert_eq!(registers.read(status), Ok(L2C_ERR_STS_HANDOFF));
    for encoding in [LSU_ERR_STS, E_FED_ERR_STS, MMU_ERR_STS, DPC_ERR_STS] {
        assert_eq!(registers.read(lookup(encoding).unwrap()), Ok(0));
    }
    let record = lookup(L2C_ERR_ADR).unwrap();
    assert_eq!(registers.read(record), Ok(0));
    assert!(registers.write(record, 0).is_err());
}

/// XNU's uncore initialization value is taken; counting is not. The
/// counters and selections are one per cluster.
#[test]
fn the_uncore_monitor_takes_xnus_initialization_and_shares_a_cluster() {
    const XNU_UPMCR0: u64 = 0xf_fff4_0000;
    let mut first = Registers::default();
    let control = lookup(UPMCR0).unwrap();
    first.write(control, XNU_UPMCR0).unwrap();
    assert_eq!(first.read(control), Ok(XNU_UPMCR0));
    // A counter enable, or AIC interrupt mode 2.
    assert!(first.write(control, XNU_UPMCR0 | 1).is_err());
    assert!(first.write(control, 2 << 16).is_err());
    let counter = lookup(UPMC3).unwrap();
    assert_eq!(first.read(counter), Ok(0));
    first.write(counter, 0x1234).unwrap();
    let mut second = Registers::default();
    second.join(&first);
    assert_eq!(second.read(counter), Ok(0x1234));
    let status = lookup(UPMSR).unwrap();
    second.write(status, 0).unwrap();
    assert_eq!(second.read(status), Ok(0));
    // A PE of another cluster has its own.
    let mut other = Registers::default();
    assert_eq!(other.read(counter), Ok(0));
}

/// The JIT box's mode and range are held. A task without a box (mode 2)
/// and SPTM's own context (bit 0 cleared) need nothing more; an enabled
/// box's enforcement is reported as unmodeled.
#[test]
fn jit_box_holds_mode_and_range() {
    let mut registers = Registers::default();
    let mode = lookup(JIT_BOX_MODE).unwrap();
    let range = lookup(JIT_RANGE).unwrap();
    registers.write(mode, 2).unwrap();
    assert_eq!(registers.read(mode), Ok(2));
    registers.write(range, 0x0000_0001_0200_0006).unwrap();
    assert_eq!(registers.read(range), Ok(0x0000_0001_0200_0006));
    assert_eq!(mode.unmodeled_effect(2), None);
    for enabled in [0x061e_0c5b, 0x0e1e_0c5b, JIT_BOX_ENABLE] {
        registers.write(mode, enabled).unwrap();
        assert_eq!(registers.read(mode), Ok(enabled));
        assert_eq!(mode.unmodeled_effect(enabled), Some(JIT_BOX_UNMODELED));
    }
    assert_eq!(range.unmodeled_effect(u64::MAX), None);
    // A thread's JCTL_EL0 mode is held and reported.
    let control = lookup(JCTL_EL0).unwrap();
    registers.write(control, 1 << 14).unwrap();
    assert_eq!(registers.read(control), Ok(1 << 14));
    assert_eq!(control.unmodeled_effect(1 << 14), Some(JCTL_UNMODELED));
    assert_eq!(control.unmodeled_effect(0), None);
    // The M1 kernels have no JIT box.
    assert!(super::lookup(JIT_RANGE, Chip::AppleM1).is_none());
    for chip in &Chip::ALL[1..] {
        assert!(super::lookup(JIT_RANGE, *chip).is_some(), "{}", chip.name());
    }
}

/// CLPC's sampler enables and selectors are held, and starting a
/// sampler reports its uncounted events; the counters, the cluster
/// counters among them, hold what software writes.
#[test]
fn clpc_samplers_hold_their_enables_and_report_uncounted_events() {
    let mut registers = Registers::default();
    let enable = lookup(AON_ENABLE).unwrap();
    registers.write(enable, 0).unwrap();
    assert_eq!(enable.unmodeled_effect(0), None);
    registers.write(enable, AON_ENABLED).unwrap();
    assert_eq!(registers.read(enable), Ok(AON_ENABLED));
    assert_eq!(
        enable.unmodeled_effect(AON_ENABLED),
        Some(CORE_COUNTERS_UNMODELED)
    );
    assert!(registers.write(enable, 2).is_err());
    registers
        .write(lookup(AON_SELECT_0).unwrap(), 0x8000)
        .unwrap();
    // The fourth core counter of the M1 and M2 Pro and Max CLPCs.
    for chip in [Chip::AppleM1, Chip::AppleM2] {
        let select = super::lookup(AON_SELECT_3, chip).unwrap();
        registers.write(select, 0x8700).unwrap();
        let counter = super::lookup(AON_COUNTER_3, chip).unwrap();
        assert_eq!(registers.read(counter), Ok(0));
    }
    // enableCore's two selectors in one register, then its stop.
    let select = lookup(MEM_STALL_SELECT_0).unwrap();
    let started = 0x805 << 32 | 0x801;
    registers.write(select, started).unwrap();
    assert_eq!(registers.read(select), Ok(started));
    assert_eq!(select.unmodeled_effect(started), Some(MEM_STALL_UNMODELED));
    registers.write(select, 0).unwrap();
    assert_eq!(select.unmodeled_effect(0), None);
    let counter = lookup(MEM_STALL_COUNTER_2).unwrap();
    assert_eq!(registers.read(counter), Ok(0));
    registers.write(counter, 0).unwrap();
    // ClusterPerfSampler's overflow clear; the counter then holds it.
    let cluster = lookup(CLUSTER_COUNTER_C6).unwrap();
    assert_eq!(cluster.scope, Scope::Cluster);
    assert_eq!(registers.read(cluster), Ok(0));
    registers.write(cluster, 0).unwrap();
    assert_eq!(registers.read(cluster), Ok(0));
}

/// The core rail accumulates the core type's modeled power in CLPC's
/// 1/40 nJ from the PE's first reading and never decreases; the SRAM
/// rail draws nothing, and neither takes a write.
#[test]
fn energy_accumulates_the_modeled_core_power_in_clpc_units() {
    const FREQUENCY: u64 = 24_000_000;
    const E_CORE: u64 = 0x8000_0000;
    const P_CORE: u64 = 0x8001_0100;
    let core = lookup(CORE_NRG_ACC_DAT).unwrap();
    let sram = lookup(CORE_SRM_NRG_ACC_DAT).unwrap();
    let at = |count, mpidr| Activity {
        count,
        frequency: FREQUENCY,
        mpidr,
    };
    let mut registers = Registers::default();
    assert_eq!(registers.energy(core, at(1_000, E_CORE)), Ok(0));
    // One second at 250 mW: 0.25 J, 2.5e8 nJ, 1e10 counts.
    let second = registers
        .energy(core, at(1_000 + FREQUENCY, E_CORE))
        .unwrap();
    assert_eq!(second, 10_000_000_000);
    assert!(
        registers
            .energy(core, at(1_000 + 2 * FREQUENCY, E_CORE))
            .unwrap()
            > second
    );
    assert_eq!(registers.energy(sram, at(1_000 + FREQUENCY, E_CORE)), Ok(0));
    // A P core's second at 1 W.
    let mut p = Registers::default();
    p.energy(core, at(0, P_CORE)).unwrap();
    assert_eq!(p.energy(core, at(FREQUENCY, P_CORE)), Ok(40_000_000_000));
    for entry in [core, sram] {
        assert!(registers.write(entry, 0).is_err());
        assert!(registers.read(entry).is_err());
    }
    let hid = lookup(HID4).unwrap();
    assert!(registers.energy(hid, at(0, E_CORE)).is_err());
}

#[test]
fn nonzero_guest_state_is_reported() {
    let mut registers = Registers::default();
    assert!(registers.guest_state().is_none());
    let guest = lookup(SPRR_CONFIG_EL12).unwrap();
    assert!(guest.el2);
    // SPTM's host-restore clears and the hypervisor's zero loads.
    registers.write(guest, 0).unwrap();
    assert!(registers.guest_state().is_none());
    registers.write(guest, 0x3b).unwrap();
    assert_eq!(
        registers.guest_state().map(|entry| entry.encoding),
        Some(SPRR_CONFIG_EL12)
    );
    // The VM keys follow the PAC regime: stored, not guest state.
    registers.write(lookup(APVMKEYLO_EL2).unwrap(), 5).unwrap();
    registers.write(guest, 0).unwrap();
    assert!(registers.guest_state().is_none());
}

/// Each layout's UPMCR0 takes its XNU's initialization value and refuses
/// the other's; the report names the encoding once.
#[test]
fn the_m6_uncore_monitor_has_its_own_upmcr0_layout() {
    const XNU_UPMCR0_16: u64 = 0xf_fff4_0000;
    const XNU_UPMCR0_24: u64 = 0xffff_ff00_0000;
    let mut registers = Registers::default();
    let m2 = super::lookup(UPMCR0, Chip::AppleM2).unwrap();
    let m6 = super::lookup(UPMCR0, Chip::AppleM6).unwrap();
    registers.write(m6, XNU_UPMCR0_24).unwrap();
    assert!(registers.write(m6, XNU_UPMCR0_16).is_err());
    assert!(registers.write(m6, XNU_UPMCR0_24 | 1 << 23).is_err());
    assert!(registers.write(m2, XNU_UPMCR0_24).is_err());
    assert_eq!(registers.read(m2), Ok(XNU_UPMCR0_24));
    assert_eq!(registers.used().count(), 1);
    for encoding in [UNCORE_COUNTER_23, UNCORE_MASK_5, UNCORE_CONTROL_1] {
        assert_eq!(
            super::lookup(encoding, Chip::AppleM6).unwrap().scope,
            Scope::Cluster
        );
        assert!(super::lookup(encoding, Chip::AppleM5).is_none());
    }
}

/// The later chips' entries apply where their census shows them, CRn 11
/// among them, and never on the M1 or M2.
#[test]
fn the_later_chips_entries_follow_their_census() {
    for (encoding, chips) in [
        (AHCR_EL2, &[Chip::AppleM3][..]),
        (INIT_C0_7, &[Chip::AppleM6]),
        (PL2_ERR_STS, &[Chip::AppleM5, Chip::AppleM6]),
        (IRG_KEY_4, &[Chip::AppleM6]),
        (CLUSTER_COUNTER_C6_6, &Chip::ALL[3..]),
        (AON_COUNTER_9, &[Chip::AppleM5]),
        (PROD_TRACE_BASE_0, &Chip::ALL[2..]),
        (SW_TRACE_DATA, &Chip::ALL[3..]),
    ] {
        for chip in Chip::ALL {
            let found = super::lookup(encoding, chip).is_some();
            assert_eq!(found, chips.contains(&chip), "{encoding:?} {}", chip.name());
        }
    }
    let status = super::lookup(PL2_ERR_STS, Chip::AppleM5).unwrap();
    let mut registers = Registers::default();
    registers.write(status, 0x57f).unwrap();
    assert_eq!(registers.read(status), Ok(0));
    let record = super::lookup(PL2_ERR_ADR, Chip::AppleM5).unwrap();
    assert!(registers.write(record, 0).is_err());
}

/// Registers whose effect is not established hold every value and
/// report a nonzero one; XNU's boot-time trace configuration and the M3
/// SPTMs' P-core trace mask are silent, any other trace bit is not.
#[test]
fn unestablished_effects_are_held_and_reported() {
    let mut registers = Registers::default();
    let ahcr = super::lookup(AHCR_EL2, Chip::AppleM3).unwrap();
    assert!(ahcr.el2);
    assert_eq!(registers.read(ahcr), Ok(0));
    registers.write(ahcr, 0x1e).unwrap();
    assert_eq!(registers.read(ahcr), Ok(0x1e));
    assert_eq!(ahcr.unmodeled_effect(0x1e), Some(AHCR_UNMODELED));
    assert_eq!(ahcr.unmodeled_effect(0), None);
    let core = super::lookup(PROD_TRACE_CORE, Chip::AppleM5).unwrap();
    assert_eq!(core.unmodeled_effect(0x1c00_0000), None);
    assert_eq!(core.unmodeled_effect(1), Some(TRACE_UNMODELED));
    let mask = super::lookup(PROD_TRACE_MASK, Chip::AppleM3).unwrap();
    assert_eq!(mask.unmodeled_effect(2), None);
    assert_eq!(mask.unmodeled_effect(1), Some(TRACE_UNMODELED));
    let control = super::lookup(TRACE_C3_4, Chip::AppleM4).unwrap();
    registers.write(control, 0x8000_0001).unwrap();
    assert_eq!(registers.read(control), Ok(0x8000_0001));
    assert_eq!(control.unmodeled_effect(0x8000_0001), Some(TRACE_UNMODELED));
    // XNU's per-switch messages are stored.
    let messages = super::lookup(SW_TRACE_DATA, Chip::AppleM4).unwrap();
    registers.write(messages, u64::MAX).unwrap();
    assert_eq!(messages.unmodeled_effect(u64::MAX), None);
    // The M6 SPTM's bring-up clears take only 0.
    let cleared = super::lookup(SPTM_CLEARED_C9_7, Chip::AppleM6).unwrap();
    registers.write(cleared, 0).unwrap();
    assert!(registers.write(cleared, 1).is_err());
}
