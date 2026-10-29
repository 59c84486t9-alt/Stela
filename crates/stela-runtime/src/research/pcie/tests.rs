use super::config::{MemoryBar, Register};
use super::port::{APP_CLOCK, LTSSM, Layout, REF_CLOCK};
use super::*;
use alloc::rc::Rc;
use core::cell::RefCell;
use stela_contracts::interrupt::{AicInput, InterruptLatch};
use {
    stela_contracts::dma::Iommu, stela_contracts::dma::Memory,
    stela_contracts::dma::test_support::Ram,
};

struct NativeState {
    state: LifecycleState,
    value: u32,
    owned: usize,
    resets: usize,
    advances: usize,
    refuse_pause: bool,
    fail_advance: bool,
}
struct NativeBank(Rc<RefCell<NativeState>>);
fn native() -> (Box<dyn MmioDevice>, Rc<RefCell<NativeState>>) {
    let shared = Rc::new(RefCell::new(NativeState {
        state: LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: true,
        },
        value: 0,
        owned: 0,
        resets: 0,
        advances: 0,
        refuse_pause: false,
        fail_advance: false,
    }));
    (Box::new(NativeBank(shared.clone())), shared)
}
impl Lifecycle for NativeBank {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<(), &'static str> {
        let current = self.0.borrow();
        if current.refuse_pause && (!proposed.clocked || proposed.quiesced) {
            return Err("native endpoint cannot suspend its current external transaction");
        }
        if ((proposed.reset && !current.state.reset) || (!proposed.powered && !proposed.retention))
            && current.owned != 0
        {
            return Err("native endpoint still owns work before physical reset");
        }
        Ok(())
    }
    fn set_lifecycle(&mut self, proposed: LifecycleState, _: &mut Access<'_>) {
        let mut current = self.0.borrow_mut();
        if proposed.reset && !current.state.reset {
            current.value = 0;
            current.resets += 1;
        }
        current.state = proposed;
    }
}
impl MmioDevice for NativeBank {
    fn name(&self) -> &'static str {
        "native PCIe fixture bank"
    }
    fn advance(&mut self, access: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
        let mut state = self.0.borrow_mut();
        if state.fail_advance {
            return Err(refuse(
                self.name(),
                0x104,
                Width::Word,
                Direction::Read,
                "native service could not advance",
            ));
        }
        state.advances += 1;
        Ok(Some(access.now + 24))
    }
    fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
        Some(self)
    }
    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        if offset != 0x100 || width != Width::Word {
            return Err(refuse(
                self.name(),
                offset,
                width,
                Direction::Read,
                "no native register at this BAR offset",
            ));
        }
        Ok(u64::from(self.0.borrow().value))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        if offset != 0x100 || width != Width::Word {
            return Err(refuse(
                self.name(),
                offset,
                width,
                Direction::Write,
                "no native register at this BAR offset",
            ));
        }
        self.0.borrow_mut().value = value as u32;
        Ok(())
    }
}
fn attach(
    root: &mut RootComplex,
    port: usize,
    function: u8,
    access: &mut Access<'_>,
) -> Rc<RefCell<NativeState>> {
    let (backend, shared) = native();
    root.attach(
        port,
        function,
        endpoint_config(),
        backend,
        alloc::vec![BarMapping {
            bar: 0,
            device_offset: 0x100
        }],
        access,
    )
    .unwrap();
    shared
}

fn register(offset: u16, reset: u32, writable: u32) -> Register {
    Register {
        offset,
        reset,
        writable,
        clear: 0,
    }
}
// Synthetic identities are test fixtures, never production Apple IDs.
fn root_config() -> ConfigSpace {
    ConfigSpace::new(
        &[
            register(0, 0x1234_abcd, 0),
            register(4, 0, 0x406),
            register(0xc, 1 << 16, 0),
            register(0x18, 0, 0x00ff_ffff),
            register(0x20, 0x0000_fff0, 0xfff0_fff0),
            register(0x24, 0x0001_fff1, 0xfff0_fff0),
            register(0x28, 0, u32::MAX),
            register(0x2c, 0, u32::MAX),
            register(0x3c, 0, (SECONDARY_RESET as u32) << 16),
        ],
        Vec::new(),
    )
    .unwrap()
}
fn endpoint_config() -> ConfigSpace {
    ConfigSpace::new(
        &[
            register(0, 0xf00d_1234, 0),
            register(4, 0, 0x406),
            register(0xc, 0, 0),
        ],
        alloc::vec![MemoryBar::new(0, 0x4000, true, false).unwrap()],
    )
    .unwrap()
}
fn machine() -> RootComplex {
    let p = Port::new(
        Layout::T8103,
        64,
        AicInput::new(0, 1),
        (0..32).map(|i| AicInput::new(0, 32 + i)).collect(),
    )
    .unwrap();
    let mut root = RootComplex::new(0, 3, alloc::vec![(p, root_config())]).unwrap();
    attach(
        &mut root,
        0,
        0,
        &mut Access::new(0, 0, &mut InterruptLatch::new()),
    );
    root
}
fn enable(root: &mut RootComplex, a: &mut Access<'_>) {
    root.set_port_inputs(
        0,
        Inputs {
            powered: true,
            reference_clock: true,
            external_reset_released: true,
            peer: true,
            link_trained: true,
        },
        a,
    )
    .unwrap();
    for (offset, value) in [(APP_CLOCK, 1), (REF_CLOCK, 1), (0x814, 1), (LTSSM, 1)] {
        root.write(PORT_BASE + offset, Width::Word, value, a)
            .unwrap();
    }
    root.write(0x18, Width::Word, 0x0001_0100, a).unwrap();
}
#[test]
fn ecam_enumeration_is_gated_by_link_and_programmed_bridge_bus() {
    let mut root = machine();
    let mut l = InterruptLatch::new();
    let mut a = Access::new(0, 0, &mut l);
    assert_eq!(root.read(1 << 20, Width::Word, &mut a), Ok(0xffff_ffff));
    enable(&mut root, &mut a);
    assert_eq!(root.read(0, Width::Word, &mut a), Ok(0x1234_abcd));
    assert_eq!(root.read(1 << 20, Width::Word, &mut a), Ok(0xf00d_1234));
    assert_eq!(
        root.read((1 << 20) + 0x1000, Width::Word, &mut a),
        Ok(0xffff_ffff)
    );
    assert!(root.read(2, Width::Word, &mut a).is_err());
    assert!(root.read(4 << 20, Width::Word, &mut a).is_err());
    root.write(0x18, Width::Word, 0x0002_0200, &mut a).unwrap();
    assert_eq!(root.read(1 << 20, Width::Word, &mut a), Ok(0xffff_ffff));
    assert_eq!(root.read(2 << 20, Width::Word, &mut a), Ok(0xf00d_1234));
}
#[test]
fn memory_requires_both_bridge_window_and_endpoint_bar_decode() {
    let mut root = machine();
    let mut l = InterruptLatch::new();
    let mut a = Access::new(0, 0, &mut l);
    enable(&mut root, &mut a);
    let endpoint = 1 << 20;
    root.write(endpoint + 0x10, Width::Word, 0xc000_0000, &mut a)
        .unwrap();
    root.write(endpoint + 0x14, Width::Word, 0, &mut a).unwrap();
    root.write(endpoint + 4, Width::Half, 6, &mut a).unwrap();
    assert!(root.memory_route(0xc000_0010, 4).is_err());
    root.write(4, Width::Half, 6, &mut a).unwrap();
    root.write(0x20, Width::Word, 0xc000_c000, &mut a).unwrap();
    assert_eq!(root.memory_route(0xc000_0010, 4), Ok((0, 0, 0x10)));
    assert!(root.memory_route(0xc000_3fff, 2).is_err());
    // A 64-bit prefetch window, with exact upper-base/limit handling.
    root.write(endpoint + 0x14, Width::Word, 6, &mut a).unwrap();
    root.write(0x24, Width::Word, 0xc001_c001, &mut a).unwrap();
    root.write(0x28, Width::Word, 6, &mut a).unwrap();
    root.write(0x2c, Width::Word, 6, &mut a).unwrap();
    assert_eq!(root.memory_route(0x6_c000_0010, 4), Ok((0, 0, 0x10)));
}
struct CheckedIommu {
    seen: Vec<usize>,
}
impl Iommu for CheckedIommu {
    fn page(&self) -> u64 {
        0x1000
    }
    fn translate(
        &mut self,
        _: &mut dyn Memory,
        stream: usize,
        iova: u64,
        last: u64,
        _: bool,
        _: &mut Access<'_>,
    ) -> Result<u64, DmaError> {
        self.seen.push(stream);
        if stream != 7 || last >= 0x2000 {
            return Err(DmaError::Fault(0x123));
        }
        Ok(iova + 0x10000)
    }
}
#[test]
fn dma_requires_busmaster_rid_mapping_matching_dart_and_propagates_faults() {
    let mut root = machine();
    let mut l = InterruptLatch::new();
    let mut a = Access::new(0, 0, &mut l);
    enable(&mut root, &mut a);
    assert!(root.dma_stream(0x100, &mut a).is_err());
    root.write((1 << 20) + 4, Width::Half, 6, &mut a).unwrap();
    assert!(root.dma_stream(0x100, &mut a).is_err());
    root.write(4, Width::Half, 6, &mut a).unwrap();
    assert!(root.dma_stream(0x100, &mut a).is_err());
    root.write(PORT_BASE + 0x828, Width::Word, 0x8007_0100, &mut a)
        .unwrap();
    assert_eq!(root.dma_stream(0x100, &mut a), Ok(7));
    let mut ram = Ram::new(0x10000, 0x3000);
    let mut iommu = CheckedIommu { seen: Vec::new() };
    let mut dma = DmaPort {
        iommu: &mut iommu,
        stream: 6,
        memory: &mut ram,
        access: &mut a,
    };
    assert!(root.dma_write(0x100, 0, &[1, 2, 3, 4], &mut dma).is_err());
    dma.stream = 7;
    root.dma_write(0x100, 0xffe, &[1, 2, 3, 4], &mut dma)
        .unwrap();
    let mut result = [0; 4];
    root.dma_read(0x100, 0xffe, &mut result, &mut dma).unwrap();
    assert_eq!(result, [1, 2, 3, 4]);
    assert_eq!(
        root.dma_read(0x100, 0x2000, &mut result, &mut dma),
        Err(DmaError::Fault(0x123))
    );
    assert_eq!(
        root.dma_write(0x100, 0x1ffe, &[9, 8, 7, 6], &mut dma),
        Err(DmaError::Fault(0x123))
    );
    let mut committed = [0; 4];
    assert!(dma.memory.read(0x11ffe, &mut committed));
    assert_eq!(committed, [9, 8, 0, 0]);
    assert!(iommu.seen.iter().all(|&sid| sid == 7));
}
#[test]
fn secondary_reset_reaches_native_owner_and_unqualified_port_power_loss_refuses() {
    let mut root = machine();
    let mut l = InterruptLatch::new();
    let mut a = Access::new(0, 0, &mut l);
    enable(&mut root, &mut a);
    root.write((1 << 20) + 4, Width::Half, 6, &mut a).unwrap();
    root.write(0x3e, Width::Half, SECONDARY_RESET, &mut a)
        .unwrap();
    assert_eq!(root.read(1 << 20, Width::Word, &mut a), Ok(0xffff_ffff));
    root.write(0x3e, Width::Half, 0, &mut a).unwrap();
    assert_eq!(root.read((1 << 20) + 4, Width::Half, &mut a), Ok(0));
    assert!(root.set_port_inputs(0, Inputs::default(), &mut a).is_err());
    assert_eq!(root.read(PORT_BASE + APP_CLOCK, Width::Word, &mut a), Ok(1));
}
#[test]
fn overlapping_root_bus_numbers_refuse_instead_of_routing_by_function() {
    let mut root = machine();
    root.ports.push(
        Port::new(
            Layout::T8103,
            64,
            AicInput::new(0, 2),
            (0..32).map(|i| AicInput::new(0, 32 + i)).collect(),
        )
        .unwrap(),
    );
    root.roots.push(root_config());
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    attach(&mut root, 1, 0, &mut access);
    enable(&mut root, &mut access);
    root.set_port_inputs(
        1,
        Inputs {
            powered: true,
            reference_clock: true,
            external_reset_released: true,
            peer: true,
            link_trained: true,
        },
        &mut access,
    )
    .unwrap();
    for (offset, value) in [(APP_CLOCK, 1), (REF_CLOCK, 1), (0x814, 1), (LTSSM, 1)] {
        root.write(
            PORT_BASE + PORT_STRIDE + offset,
            Width::Word,
            value,
            &mut access,
        )
        .unwrap();
    }
    root.write((1 << 15) + 0x18, Width::Word, 0x0001_0100, &mut access)
        .unwrap();
    // Matching endpoints on two roots cannot resolve overlapping bus windows.
    assert!(root.read(1 << 20, Width::Word, &mut access).is_err());
    assert!(root.write(1 << 20, Width::Word, 0, &mut access).is_err());
    assert!(root.dma_stream(0x100, &mut access).is_err());
}
#[test]
fn shared_intx_sources_hold_the_pin_until_all_enabled_functions_deassert() {
    let mut root = machine();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    attach(&mut root, 0, 1, &mut access);
    enable(&mut root, &mut access);
    root.set_intx(0x100, 0, true, &mut access).unwrap();
    root.set_intx(0x101, 0, true, &mut access).unwrap();
    root.set_intx(0x100, 0, false, &mut access).unwrap();
    assert_eq!(
        root.read(PORT_BASE + port::INT_STATUS, Width::Word, &mut access)
            .unwrap()
            & 1,
        1
    );
    root.write(
        (1 << 20) + 0x1000 + 4,
        Width::Half,
        u64::from(INTX_DISABLE),
        &mut access,
    )
    .unwrap();
    assert_eq!(
        root.read(PORT_BASE + port::INT_STATUS, Width::Word, &mut access)
            .unwrap()
            & 1,
        0
    );
    root.write((1 << 20) + 0x1000 + 4, Width::Half, 0, &mut access)
        .unwrap();
    assert_eq!(
        root.read(PORT_BASE + port::INT_STATUS, Width::Word, &mut access)
            .unwrap()
            & 1,
        1
    );
    root.write(0x3e, Width::Half, SECONDARY_RESET, &mut access)
        .unwrap();
    assert_eq!(
        root.read(PORT_BASE + port::INT_STATUS, Width::Word, &mut access)
            .unwrap()
            & 1,
        0
    );
}
fn map_memory(root: &mut RootComplex, access: &mut Access<'_>) {
    root.write((1 << 20) + 0x10, Width::Word, 0xc000_0000, access)
        .unwrap();
    root.write((1 << 20) + 0x14, Width::Word, 0, access)
        .unwrap();
    root.write((1 << 20) + 4, Width::Half, 6, access).unwrap();
    root.write(4, Width::Half, 6, access).unwrap();
    root.write(0x20, Width::Word, 0xc000_c000, access).unwrap();
}
#[test]
fn bar_bank_and_service_receive_effects_and_preserve_native_errors() {
    let mut root = machine();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 120, &mut latch);
    enable(&mut root, &mut access);
    map_memory(&mut root, &mut access);
    root.write_memory(0xc000_0000, Width::Word, 0x1234, &mut access)
        .unwrap();
    assert_eq!(
        root.read_memory(0xc000_0000, Width::Word, &mut access),
        Ok(0x1234)
    );
    assert!(matches!(
        root.write_memory(0xc000_0004, Width::Word, 5, &mut access),
        Err(MmioError::Unsupported {
            device: "native PCIe fixture bank",
            offset: 0x104,
            ..
        })
    ));
    assert_eq!(
        root.read_memory(0xc000_0000, Width::Word, &mut access),
        Ok(0x1234)
    );
    assert_eq!(root.advance(&mut access), Ok(Some(144)));
}
#[test]
fn whole_port_preflight_preserves_bridge_config_and_every_native_owner_on_refusal() {
    let mut root = machine();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let second = attach(&mut root, 0, 1, &mut access);
    enable(&mut root, &mut access);
    map_memory(&mut root, &mut access);
    root.write_memory(0xc000_0000, Width::Word, 0xbeef, &mut access)
        .unwrap();
    second.borrow_mut().owned = 1;
    let resets = second.borrow().resets;
    assert!(
        root.write(0x3e, Width::Half, SECONDARY_RESET, &mut access)
            .is_err()
    );
    assert_eq!(root.read(0x3e, Width::Half, &mut access), Ok(0));
    assert_eq!(
        root.read_memory(0xc000_0000, Width::Word, &mut access),
        Ok(0xbeef)
    );
    assert_eq!(second.borrow().resets, resets);
    assert_eq!(second.borrow().owned, 1);
    assert!(
        root.write(PORT_BASE + 0x814, Width::Word, 0, &mut access)
            .is_err()
    );
    assert_eq!(
        root.read(PORT_BASE + 0x814, Width::Word, &mut access),
        Ok(1)
    );
    assert_eq!(
        root.read_memory(0xc000_0000, Width::Word, &mut access),
        Ok(0xbeef)
    );
    second.borrow_mut().owned = 0;
    root.write(0x3e, Width::Half, SECONDARY_RESET, &mut access)
        .unwrap();
    assert_eq!(second.borrow().resets, resets + 1);
    root.write(0x3e, Width::Half, SECONDARY_RESET, &mut access)
        .unwrap();
    assert_eq!(second.borrow().resets, resets + 1);
    root.write(0x3e, Width::Half, 0, &mut access).unwrap();
    assert_eq!(root.read((1 << 20) + 4, Width::Half, &mut access), Ok(0));
    map_memory(&mut root, &mut access);
    assert_eq!(
        root.read_memory(0xc000_0000, Width::Word, &mut access),
        Ok(0)
    );
}
#[test]
fn kept_clock_quiesce_and_peer_loss_pause_without_resetting_work() {
    let mut root = machine();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let second = attach(&mut root, 0, 1, &mut access);
    enable(&mut root, &mut access);
    map_memory(&mut root, &mut access);
    root.write_memory(0xc000_0000, Width::Word, 91, &mut access)
        .unwrap();
    second.borrow_mut().owned = 7;
    let resets = second.borrow().resets;
    let running = root.lifecycle;
    for paused in [
        LifecycleState {
            clocked: false,
            ..running
        },
        LifecycleState {
            quiesced: true,
            ..running
        },
    ] {
        root.check_lifecycle(paused).unwrap();
        root.set_lifecycle(paused, &mut access);
        assert_eq!(second.borrow().state.clocked, paused.clocked);
        assert_eq!(second.borrow().state.quiesced, paused.quiesced);
        assert_eq!(root.advance(&mut access), Ok(None));
        assert!(
            root.read_memory(0xc000_0000, Width::Word, &mut access)
                .is_err()
        );
        assert!(root.dma_stream(0x100, &mut access).is_err());
        root.check_lifecycle(running).unwrap();
        root.set_lifecycle(running, &mut access);
        assert_eq!(
            root.read_memory(0xc000_0000, Width::Word, &mut access),
            Ok(91)
        );
        assert_eq!(second.borrow().owned, 7);
        assert_eq!(second.borrow().resets, resets);
    }
    root.write(PORT_BASE + APP_CLOCK, Width::Word, 0, &mut access)
        .unwrap();
    assert!(!second.borrow().state.clocked);
    assert!(!second.borrow().state.reset);
    root.write(PORT_BASE + APP_CLOCK, Width::Word, 1, &mut access)
        .unwrap();
    assert_eq!(
        root.read_memory(0xc000_0000, Width::Word, &mut access),
        Ok(91)
    );
    let inputs = root.ports[0].inputs();
    root.set_port_inputs(
        0,
        Inputs {
            peer: false,
            ..inputs
        },
        &mut access,
    )
    .unwrap();
    assert!(second.borrow().state.quiesced);
    assert!(!second.borrow().state.reset);
    root.set_port_inputs(0, inputs, &mut access).unwrap();
    assert_eq!(second.borrow().owned, 7);
    assert_eq!(second.borrow().resets, resets);
    assert_eq!(root.advance(&mut access), Ok(Some(24)));
    assert_eq!(second.borrow().advances, 1);
}
#[test]
fn armed_irq_pause_and_cold_root_reset_refuse_without_dropping_pending_levels() {
    let mut root = machine();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    enable(&mut root, &mut access);
    root.write(
        PORT_BASE + port::INT_MASK_CLEAR,
        Width::Word,
        1,
        &mut access,
    )
    .unwrap();
    root.set_intx(0x100, 0, true, &mut access).unwrap();
    assert!(
        root.check_lifecycle(LifecycleState {
            quiesced: true,
            ..root.lifecycle
        })
        .is_err()
    );
    assert!(
        root.check_lifecycle(LifecycleState {
            reset: true,
            ..root.lifecycle
        })
        .is_err()
    );
    assert!(
        root.check_lifecycle(LifecycleState {
            powered: false,
            retention: false,
            ..root.lifecycle
        })
        .is_err()
    );
    assert_eq!(
        root.read(PORT_BASE + port::INT_STATUS, Width::Word, &mut access)
            .unwrap()
            & 1,
        1
    );
    assert!(latch.is_asserted(stela_contracts::interrupt::Wire::Aic(AicInput::new(0, 1))));
}
#[test]
fn peer_presence_requires_complete_bar_and_lifecycle_ownership() {
    let p = Port::new(
        Layout::T8103,
        16,
        AicInput::new(0, 1),
        alloc::vec![AicInput::new(0, 2)],
    )
    .unwrap();
    let mut root = RootComplex::new(0, 3, alloc::vec![(p, root_config())]).unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    assert!(
        root.set_port_inputs(
            0,
            Inputs {
                peer: true,
                ..Inputs::default()
            },
            &mut access
        )
        .is_err()
    );
    let (backend, _) = native();
    assert!(
        root.attach(0, 0, endpoint_config(), backend, Vec::new(), &mut access)
            .is_err()
    );
    let (backend, _) = native();
    assert!(
        root.attach(
            0,
            0,
            endpoint_config(),
            backend,
            alloc::vec![BarMapping {
                bar: 0,
                device_offset: u64::MAX
            }],
            &mut access
        )
        .is_err()
    );
    struct ConfigOnly;
    impl MmioDevice for ConfigOnly {
        fn name(&self) -> &'static str {
            "config-only fixture"
        }
        fn read(&mut self, _: u64, _: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
            unreachable!()
        }
        fn write(&mut self, _: u64, _: Width, _: u64, _: &mut Access<'_>) -> Result<(), MmioError> {
            unreachable!()
        }
    }
    assert!(
        root.attach(
            0,
            0,
            endpoint_config(),
            Box::new(ConfigOnly),
            alloc::vec![BarMapping {
                bar: 0,
                device_offset: 0
            }],
            &mut access
        )
        .is_err()
    );
}
#[test]
fn whole_fabric_pause_preflight_and_native_service_failure_preserve_prior_effects() {
    let p = Port::new(
        Layout::T8103,
        16,
        AicInput::new(0, 1),
        alloc::vec![AicInput::new(0, 2)],
    )
    .unwrap();
    let mut root = RootComplex::new(0, 3, alloc::vec![(p, root_config())]).unwrap();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let first = attach(&mut root, 0, 0, &mut access);
    let second = attach(&mut root, 0, 1, &mut access);
    enable(&mut root, &mut access);
    second.borrow_mut().refuse_pause = true;
    let running = root.lifecycle;
    assert!(
        root.check_lifecycle(LifecycleState {
            clocked: false,
            ..running
        })
        .is_err()
    );
    assert_eq!(root.lifecycle, running);
    assert_eq!(first.borrow().state, running);
    assert_eq!(second.borrow().state, running);
    second.borrow_mut().fail_advance = true;
    assert!(matches!(
        root.advance(&mut access),
        Err(MmioError::Unsupported {
            device: "native PCIe fixture bank",
            offset: 0x104,
            ..
        })
    ));
    assert_eq!(first.borrow().advances, 1);
    assert_eq!(second.borrow().advances, 0);
}
#[test]
fn an_ambiguous_bar_cannot_disappear_and_select_another_native_function() {
    let mut root = machine();
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    enable(&mut root, &mut access);
    map_memory(&mut root, &mut access);
    let config = ConfigSpace::new(
        &[
            register(0, 0x1234, 0),
            register(4, 2, 0x406),
            register(0xc, 0, 0),
        ],
        alloc::vec![
            MemoryBar::new(0, 0x4000, false, false).unwrap(),
            MemoryBar::new(1, 0x4000, false, false).unwrap()
        ],
    )
    .unwrap();
    let (bank, _) = native();
    root.attach(
        0,
        1,
        config,
        bank,
        alloc::vec![
            BarMapping {
                bar: 0,
                device_offset: 0x100
            },
            BarMapping {
                bar: 1,
                device_offset: 0x100
            }
        ],
        &mut access,
    )
    .unwrap();
    for offset in [0x10, 0x14] {
        root.write(
            (1 << 20) + 0x1000 + offset,
            Width::Word,
            0xc000_0000,
            &mut access,
        )
        .unwrap();
    }
    assert_eq!(
        root.memory_route(0xc000_0000, 4),
        Err("PCIe memory BAR decoders overlap")
    );
    assert!(
        root.read_memory(0xc000_0000, Width::Word, &mut access)
            .is_err()
    );
}
#[cfg(feature = "std")]
use sha2::{Digest, Sha256};

#[cfg(feature = "std")]
#[test]
#[ignore = "oracle: STELA_PCIE_KERNELCACHE"]
fn original_msi_vector_delegation_and_port_decoder_are_pinned() {
    let bytes = std::fs::read(
        std::env::var_os("STELA_PCIE_KERNELCACHE").expect("original KernelCache path"),
    )
    .unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        "06846c718a67715f540c7f5a5d5a183da6185d94b6fc01f1ce57a30b601be44d"
    );
    // KC affine VA = file offset + 0xfffffe0007004000. Original
    // ApplePCIEMSIController dispatches to its parent, not a guessed local
    // MSI status/ack bank. Vtable slots alone do not check electrical
    // capture or retirement behavior in that parent.
    for (offset, opcode) in [
        (0x24285d0, 0x9400ca13u32), // handleInterrupt: assertion call
        (0x24287a8, 0xf9406100),    // initVector: parent at +0xc0
        (0x24287c8, 0xd2811911),    // initVector: slot 0x8c8
        (0x24289bc, 0xf9406100),    // enableVector: same parent
        (0x24289dc, 0xd2811c11),    // enableVector: slot 0x8e0
        (0x2428bd0, 0xf9406100),    // disableVectorHard: same parent
        (0x2428bf0, 0xd2811b11),    // disableVectorHard: slot 0x8d8
        (0x2f81198, 0x12001109),    // configMSIRange: base & 0x1f
        (0x2f811a4, 0x2a094108),    // pack low16 and low5 << 16
        (0x2f811d0, 0x52802481),    // write decoder at 0x124
        (0x2f81204, 0x52802501),    // write packed base at 0x128
        (0x2f81270, 0x52802d01),    // write doorbell at 0x168
    ] {
        assert_eq!(
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()),
            opcode,
            "original opcode at {offset:#x}"
        );
    }
}
