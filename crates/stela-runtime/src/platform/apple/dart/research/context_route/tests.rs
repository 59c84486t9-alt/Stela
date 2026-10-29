use super::*;
use alloc::{vec, vec::Vec};
use {
    stela_contracts::bus::MmioDevice, stela_contracts::bus::Width, stela_contracts::dma::Port,
    stela_contracts::dma::test_support::Ram, stela_contracts::interrupt::AicInput,
    stela_contracts::interrupt::InterruptLatch, stela_contracts::interrupt::Wire,
    stela_soc_data::dart::Profile,
};

const ROOT: u64 = 0x8_0000_0000;
const FRAME: u64 = ROOT + 4 * PAGE;
const IOVA: u64 = 0x0200_4000;
const CONTEXT: usize = 1;
const ERROR: u64 = 0x40;
const ERROR_ADDRESS: u64 = 0x50;
const WRITE_PROTECT: u64 = 1 << 2;
const IRQ: AicInput = AicInput::new(0, 1194);

fn pte(physical: u64) -> u64 {
    physical >> 4 | 1
}

fn setup() -> (Vec<Dart>, Ram, InterruptLatch) {
    let mut banks = Dart::group_for_profile(Profile::T6000, 16, Some(IRQ), 2).unwrap();
    let mut ram = Ram::new(ROOT, (8 * PAGE) as usize);
    let mut sink = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut sink);
    for (index, bank) in banks.iter_mut().enumerate() {
        let root = ROOT + index as u64 * 2 * PAGE;
        let leaf = root + PAGE;
        ram.put_u64(root + 8, pte(leaf));
        ram.put_u64(leaf + 8, pte(FRAME) | 0xfff << 40);
        ram.put_u64(leaf + 16, pte(FRAME + PAGE) | 0xfff << 40);
        for (offset, value) in [
            (0xfc, 2),
            (0x104, 1 << 7),
            (0x210, root >> 12 | 1 << 31),
            (0x80, 0x0302_0101),
        ] {
            bank.write(offset, Width::Word, value, &mut access).unwrap();
        }
    }
    (banks, ram, sink)
}

fn assign(banks: &[Dart]) -> T6000ContextRoute {
    T6000ContextRoute::assign_native_usb(0xd4, 0xd3, CONTEXT, &[&banks[0], &banks[1]]).unwrap()
}

fn transfer(
    route: &T6000ContextRoute,
    banks: &[Dart],
    ram: &mut dyn Memory,
    sink: &mut InterruptLatch,
    address: u64,
    bytes: &[u8],
) -> Result<(), DmaError> {
    let refs = [&banks[0], &banks[1]];
    let mut cohort = route.bind(&refs).unwrap();
    let mut access = Access::new(0, 0, sink);
    Port {
        iommu: &mut cohort,
        stream: CONTEXT,
        memory: ram,
        access: &mut access,
    }
    .write(address, bytes)
}

fn assert_empty_faults(banks: &mut [Dart], sink: &mut InterruptLatch) {
    let mut access = Access::new(0, 0, sink);
    for bank in banks {
        assert_eq!(bank.read(ERROR, Width::Word, &mut access), Ok(0));
    }
    assert!(!sink.is_asserted(Wire::Aic(IRQ)));
}

#[test]
fn assigned_context_reaches_real_ram_through_all_banks_and_preimages() {
    let (mut banks, mut ram, mut sink) = setup();
    let route = assign(&banks);
    assert_eq!(route.owners(), (0xd4, 0xd3));
    assert_eq!(route.context(), CONTEXT);
    let data = [0x31, 0x57, 0x79, 0x9b];
    transfer(&route, &banks, &mut ram, &mut sink, IOVA + PAGE - 2, &data).unwrap();
    let mut physical = [0; 4];
    assert!(ram.read(FRAME + PAGE - 2, &mut physical));
    assert_eq!(physical, data);
    let refs = [&banks[0], &banks[1]];
    let mut cohort = route.bind(&refs).unwrap();
    let mut access = Access::new(0, 0, &mut sink);
    let mut actual = [0; 4];
    Port {
        iommu: &mut cohort,
        stream: CONTEXT,
        memory: &mut ram,
        access: &mut access,
    }
    .read(IOVA + PAGE - 2, &mut actual)
    .unwrap();
    assert_eq!(actual, data);
    assert_empty_faults(&mut banks, &mut sink);
}

#[test]
fn divergent_later_page_preserves_only_completed_bytes_and_read_buffer_prefix() {
    let (mut banks, mut ram, mut sink) = setup();
    let route = assign(&banks);
    ram.put_u64(ROOT + 3 * PAGE + 16, pte(FRAME + 2 * PAGE) | 0xfff << 40);
    assert_eq!(
        transfer(
            &route,
            &banks,
            &mut ram,
            &mut sink,
            IOVA + PAGE - 2,
            &[1, 3, 5, 7],
        ),
        Err(DmaError::Unsupported(
            "T6000 native USB TRAD alternatives have divergent DMA targets"
        ))
    );
    let mut actual = [0; 4];
    assert!(ram.read(FRAME + PAGE - 2, &mut actual));
    assert_eq!(actual, [1, 3, 0, 0]);
    assert!(ram.read(FRAME + 2 * PAGE, &mut actual));
    assert_eq!(actual, [0; 4]);
    let refs = [&banks[0], &banks[1]];
    let mut cohort = route.bind(&refs).unwrap();
    let mut access = Access::new(0, 0, &mut sink);
    let mut buffer = [0x99; 4];
    assert!(
        Port {
            iommu: &mut cohort,
            stream: CONTEXT,
            memory: &mut ram,
            access: &mut access,
        }
        .read(IOVA + PAGE - 2, &mut buffer)
        .is_err()
    );
    assert_eq!(buffer, [1, 3, 0x99, 0x99]);
    assert_empty_faults(&mut banks, &mut sink);
}

#[test]
fn permission_and_subpage_alternatives_are_checked_before_payload_bytes() {
    let (mut banks, mut ram, mut sink) = setup();
    let route = assign(&banks);
    let leaf = ROOT + 3 * PAGE + 8;
    ram.put_u64(leaf, pte(FRAME) | 0xfff << 40 | WRITE_PROTECT);
    assert!(transfer(&route, &banks, &mut ram, &mut sink, IOVA, &[1, 2]).is_err());
    let mut bytes = [0; 2];
    assert!(ram.read(FRAME, &mut bytes));
    assert_eq!(bytes, [0, 0]);
    // Different permissions are harmless for a read allowed by every
    // alternative. They must still deny a write without a guessed fault.
    let refs = [&banks[0], &banks[1]];
    let mut cohort = route.bind(&refs).unwrap();
    let mut access = Access::new(0, 0, &mut sink);
    Port {
        iommu: &mut cohort,
        stream: CONTEXT,
        memory: &mut ram,
        access: &mut access,
    }
    .read(IOVA, &mut bytes)
    .unwrap();
    ram.put_u64(leaf, pte(FRAME) | 3 << 40);
    // Only bytes0..15 are permitted in bank1. The complete chunk is
    // checked before writing its permitted prefix at byte14.
    assert!(transfer(&route, &banks, &mut ram, &mut sink, IOVA + 14, &[1; 4]).is_err());
    let mut bytes = [0; 4];
    assert!(ram.read(FRAME + 14, &mut bytes));
    assert_eq!(bytes, [0; 4]);
    assert_empty_faults(&mut banks, &mut sink);
}

#[test]
fn changed_remaps_are_recomputed_and_an_absent_preimage_refuses() {
    let (mut banks, mut ram, mut sink) = setup();
    let route = assign(&banks);
    let mut access = Access::new(0, 0, &mut sink);
    // Source0 leaves context1; source2 enters it. Identity source1 is
    // still another preimage. No incoming SID is permanently selected.
    banks[1]
        .write(0x80, Width::Word, 0x0301_0102, &mut access)
        .unwrap();
    transfer(&route, &banks, &mut ram, &mut sink, IOVA, &[0xa5]).unwrap();
    let mut access = Access::new(0, 0, &mut sink);
    // Remove both remaining preimages; do not reuse a prior proof.
    banks[1]
        .write(0x80, Width::Word, 0x0302_0202, &mut access)
        .unwrap();
    assert_eq!(
        transfer(&route, &banks, &mut ram, &mut sink, IOVA + 1, &[0x5a]),
        Err(DmaError::Unsupported(
            "T6000 context route has no current incoming SID preimage"
        ))
    );
    let mut bytes = [0; 2];
    assert!(ram.read(FRAME, &mut bytes));
    assert_eq!(bytes, [0xa5, 0]);
    assert_empty_faults(&mut banks, &mut sink);
}

#[test]
fn lifecycle_unknown_tables_and_faulting_alternatives_never_create_captures() {
    let (mut banks, mut ram, mut sink) = setup();
    let route = assign(&banks);
    banks[1].set_clock(false);
    assert_eq!(
        transfer(&route, &banks, &mut ram, &mut sink, IOVA, &[1]),
        Err(DmaError::Unsupported("DART functional clock is gated"))
    );
    banks[1].set_clock(true);
    banks[1].set_quiesced(true);
    assert!(transfer(&route, &banks, &mut ram, &mut sink, IOVA, &[1]).is_err());
    banks[1].set_quiesced(false);
    {
        let mut access = Access::new(0, 0, &mut sink);
        banks[1].set_power(false, true, &mut access);
    }
    assert!(transfer(&route, &banks, &mut ram, &mut sink, IOVA, &[1]).is_err());
    {
        let mut access = Access::new(0, 0, &mut sink);
        banks[1].set_power(true, true, &mut access);
    }
    transfer(&route, &banks, &mut ram, &mut sink, IOVA, &[0xa5]).unwrap();
    let leaf = ROOT + 3 * PAGE + 8;
    // Reserved descriptor bits and inaccessible tables stay unknown;
    // neither is converted into a successful mapping or a made-up IRQ.
    ram.put_u64(leaf, pte(FRAME) | 0xfff << 40 | 1 << 9);
    assert!(transfer(&route, &banks, &mut ram, &mut sink, IOVA + 1, &[1]).is_err());
    ram.put_u64(ROOT + 2 * PAGE + 8, pte(ROOT + 0x100000));
    assert_eq!(
        transfer(&route, &banks, &mut ram, &mut sink, IOVA + 1, &[1]),
        Err(DmaError::Unsupported(
            "T6000 context route has an inaccessible table alternative"
        ))
    );
    {
        let mut access = Access::new(0, 0, &mut sink);
        banks[1].set_reset(true, &mut access);
    }
    assert!(transfer(&route, &banks, &mut ram, &mut sink, IOVA + 1, &[1]).is_err());
    {
        let mut access = Access::new(0, 0, &mut sink);
        banks[1].set_reset(false, &mut access);
    }
    assert_eq!(
        transfer(&route, &banks, &mut ram, &mut sink, IOVA + 1, &[1]),
        Err(DmaError::Unsupported(
            "T6000 context route has a faulting incoming SID alternative"
        ))
    );
    let mut bytes = [0; 2];
    assert!(ram.read(FRAME, &mut bytes));
    assert_eq!(bytes, [0xa5, 0]);
    assert_empty_faults(&mut banks, &mut sink);
}

#[test]
fn prior_bank_faults_and_shared_irq_survive_success_and_cohort_refusal() {
    let (mut banks, mut ram, mut sink) = setup();
    {
        let mut access = Access::new(0, 0, &mut sink);
        for bank in &mut banks {
            assert_eq!(
                bank.translate(&mut ram, 3, IOVA + 0x80, IOVA + 0x80, false, &mut access),
                Err(DmaError::Fault(1))
            );
        }
    }
    let route = assign(&banks);
    transfer(&route, &banks, &mut ram, &mut sink, IOVA, &[0xa5]).unwrap();
    ram.put_u64(ROOT + 3 * PAGE + 8, 0);
    assert!(transfer(&route, &banks, &mut ram, &mut sink, IOVA + 1, &[1]).is_err());
    let mut access = Access::new(0, 0, &mut sink);
    for bank in &mut banks {
        assert_eq!(bank.read(ERROR, Width::Word, &mut access), Ok(0x8300_0001));
        assert_eq!(
            bank.read(ERROR_ADDRESS, Width::Word, &mut access),
            Ok(IOVA + 0x80)
        );
    }
    banks[0]
        .write(ERROR, Width::Word, 0x8300_0001, &mut access)
        .unwrap();
    assert!(sink.is_asserted(Wire::Aic(IRQ)));
    let mut access = Access::new(0, 0, &mut sink);
    banks[1]
        .write(ERROR, Width::Word, 0x8300_0001, &mut access)
        .unwrap();
    assert!(!sink.is_asserted(Wire::Aic(IRQ)));
}

#[test]
fn assignment_and_binding_preserve_owners_geometry_and_bank_identity() {
    let (banks, mut ram, mut sink) = setup();
    let refs = [&banks[0], &banks[1]];
    for (client, mapper, context) in [(0, 0xd3, 1), (0xd4, 0, 1), (1, 1, 1), (0xd4, 0xd3, 16)] {
        assert!(T6000ContextRoute::assign_native_usb(client, mapper, context, &refs).is_err());
    }
    for bad in [vec![], vec![&banks[0]], vec![&banks[0], &banks[0]]] {
        assert!(T6000ContextRoute::assign_native_usb(0xd4, 0xd3, 1, &bad).is_err());
    }
    let wrong = Dart::for_profile(Profile::T8110, 16, None).unwrap();
    let short = Dart::for_profile(Profile::T6000, 8, None).unwrap();
    let filter = Dart::for_profile(Profile::T6000, 16, None)
        .unwrap()
        .with_apf(1);
    for bad in [&wrong, &short, &filter] {
        assert!(T6000ContextRoute::assign_native_usb(0xd4, 0xd3, 1, &[&banks[0], bad]).is_err());
    }
    let route = assign(&banks);
    assert!(route.bind(&[&banks[1], &banks[0]]).is_err());
    let replacement = Dart::for_profile(Profile::T6000, 16, None).unwrap();
    assert!(route.bind(&[&banks[0], &replacement]).is_err());
    let mut bound = route.bind(&refs).unwrap();
    let mut access = Access::new(0, 0, &mut sink);
    assert!(
        bound
            .translate(&mut ram, 0, IOVA, IOVA, false, &mut access)
            .is_err()
    );
    for (first, last) in [(IOVA + 1, IOVA), (IOVA, IOVA + PAGE)] {
        assert!(
            bound
                .translate(&mut ram, CONTEXT, first, last, false, &mut access)
                .is_err()
        );
    }
}

#[test]
fn convergent_targets_still_require_real_ram_and_tables_are_checked_again() {
    let (mut banks, mut ram, mut sink) = setup();
    let route = assign(&banks);
    // The checked translations agree, but a target outside RAM is not
    // a successful transfer. The Memory boundary remains authoritative.
    for leaf in [ROOT + PAGE + 8, ROOT + 3 * PAGE + 8] {
        ram.put_u64(leaf, pte(ROOT + 0x100000) | 0xfff << 40);
    }
    assert_eq!(
        transfer(&route, &banks, &mut ram, &mut sink, IOVA, &[0xa5]),
        Err(DmaError::Memory)
    );
    // Correcting both live tables permits a later transfer without
    // rebuilding the resource or reusing a cached address/proof.
    for leaf in [ROOT + PAGE + 8, ROOT + 3 * PAGE + 8] {
        ram.put_u64(leaf, pte(FRAME) | 0xfff << 40);
    }
    transfer(&route, &banks, &mut ram, &mut sink, IOVA, &[0xa5]).unwrap();
    let mut byte = [0];
    assert!(ram.read(FRAME, &mut byte));
    assert_eq!(byte, [0xa5]);
    assert_empty_faults(&mut banks, &mut sink);
}

#[test]
fn checked_work_is_bounded_by_bank_and_current_preimage_count() {
    struct CountRam {
        ram: Ram,
        reads: usize,
        writes: usize,
    }
    impl Memory for CountRam {
        fn read(&mut self, physical: u64, bytes: &mut [u8]) -> bool {
            self.reads += 1;
            self.ram.read(physical, bytes)
        }
        fn write(&mut self, physical: u64, bytes: &[u8]) -> bool {
            self.writes += 1;
            self.ram.write(physical, bytes)
        }
    }
    let (banks, ram, mut sink) = setup();
    let route = assign(&banks);
    let mut ram = CountRam {
        ram,
        reads: 0,
        writes: 0,
    };
    transfer(&route, &banks, &mut ram, &mut sink, IOVA, &[0x5a; 64]).unwrap();
    // Two independent banks * two incoming preimages * two levels;
    // the payload is written exactly once after all checks.
    assert_eq!((ram.reads, ram.writes), (8, 1));
}
