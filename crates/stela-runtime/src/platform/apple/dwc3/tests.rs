use super::*;
use alloc::vec;
use {
    crate::platform::apple::dart::Dart, stela_contracts::dma::Memory,
    stela_contracts::dma::test_support::Ram, stela_contracts::interrupt::InterruptLatch,
};
const RAM: u64 = 0x1_0000_0000;
const TRB: u64 = RAM + 0x1000;
const PAYLOAD: u64 = RAM + 0x2000;
const EVENTS: u64 = RAM + 0x4000;
const DART_TCR: u64 = 0x1000;
const DART_ENABLE: u64 = 0xc00;
const SID: usize = 1;
fn irqs() -> [AicInput; RINGS] {
    core::array::from_fn(|i| AicInput::new(0, 1031 + i as u16))
}
struct Attached(u64, bool);
impl PortState for Attached {
    fn generation(&self) -> u64 {
        self.0
    }
    fn high_speed_device_ready(&self) -> bool {
        self.1
    }
}
fn write(dwc: &mut Dwc3, at: u64, value: u32, access: &mut Access<'_>) {
    dwc.write(at, Width::Word, u64::from(value), access)
        .unwrap();
}
fn configure(dwc: &mut Dwc3, n: usize, ring: usize, access: &mut Access<'_>) {
    let base = DEP + n as u64 * STRIDE;
    write(dwc, base, 0, access);
    write(
        dwc,
        base + 4,
        (n as u32) << 25 | CFG_COMPLETE | CFG_PROGRESS | CFG_NOT_READY | ring as u32,
        access,
    );
    let packet = if n < 2 { 64 } else { 512 };
    write(
        dwc,
        base + 8,
        packet << 3 | if n < 2 { 0 } else { 2 << 1 },
        access,
    );
    write(dwc, base + 12, CMDACT | 1, access);
    write(dwc, base + 8, 1, access);
    write(dwc, base + 4, 0, access);
    write(dwc, base + 12, CMDACT | 2, access);
}
fn start(dwc: &mut Dwc3, n: usize, address: u64, access: &mut Access<'_>) {
    let base = DEP + n as u64 * STRIDE;
    write(dwc, base, 0, access);
    write(dwc, base + 4, address as u32, access);
    write(dwc, base + 8, (address >> 32) as u32, access);
    write(dwc, base + 12, CMDACT | 6, access);
    assert_eq!(dwc.read(base + 12, Width::Word, access).unwrap() >> 16, 1);
}
fn trb(ram: &mut Ram, at: u64, bytes: u32, ctrl: u32) {
    let mut trb = [0; 16];
    trb[..8].copy_from_slice(&PAYLOAD.to_le_bytes());
    trb[8..12].copy_from_slice(&bytes.to_le_bytes());
    trb[12..].copy_from_slice(&ctrl.to_le_bytes());
    assert!(ram.write(at, &trb));
}
fn setup() -> (Dwc3, Dart, Ram, InterruptLatch) {
    let mut latch = InterruptLatch::new();
    let mut access = Access::new(0, 0, &mut latch);
    let mut dart = Dart::new(16, Some(AicInput::new(0, 1035)));
    write_dart(&mut dart, DART_ENABLE, 1 << SID, &mut access);
    write_dart(&mut dart, DART_TCR + SID as u64 * 4, 6, &mut access);
    let mut dwc = Dwc3::new(irqs());
    dwc.set_phy_state(false, true, true, false, &mut access);
    dwc.sync_port(&Attached(1, true)).unwrap();
    write(&mut dwc, DCTL, RUN, &mut access);
    let mut ram = Ram::new(RAM, 0x10000);
    {
        let mut port = Port {
            iommu: &mut dart,
            stream: SID,
            memory: &mut ram,
            access: &mut access,
        };
        dwc.peer(&mut port).reset().unwrap();
    }
    write(&mut dwc, GEVNT, EVENTS as u32, &mut access);
    write(&mut dwc, GEVNT + 4, (EVENTS >> 32) as u32, &mut access);
    write(&mut dwc, GEVNT + 8, 0x800, &mut access);
    write(&mut dwc, DALEPENA, u32::MAX, &mut access);
    (dwc, dart, ram, latch)
}
fn write_dart(dart: &mut Dart, at: u64, value: u32, access: &mut Access<'_>) {
    dart.write(at, Width::Word, u64::from(value), access)
        .unwrap();
}
#[test]
fn a_host_command_completion_raises_its_interrupters_shared_wire() {
    let (mut dwc, mut dart, mut ram, mut latch) = setup();
    let (erst, ring, commands) = (RAM + 0x8000, RAM + 0x9000, RAM + 0xa000);
    assert!(ram.write(erst, &ring.to_le_bytes()));
    assert!(ram.write(erst + 8, &16u64.to_le_bytes()));
    let command = (23u64 << 42) | 1 << 32; // No Op, cycle one
    assert!(ram.write(commands + 8, &command.to_le_bytes()));
    let mut access = Access::new(0, 0, &mut latch);
    // Interrupter 0 at runtime offset 0x20 (RTSOFF 0x440).
    write(&mut dwc, 0x468, 1, &mut access);
    write(&mut dwc, 0x478, ring as u32, &mut access);
    write(&mut dwc, 0x47c, (ring >> 32) as u32, &mut access);
    write(&mut dwc, 0x470, erst as u32, &mut access);
    write(&mut dwc, 0x474, (erst >> 32) as u32, &mut access);
    write(&mut dwc, 0x460, 2, &mut access);
    write(&mut dwc, 0x38, commands as u32 | 1, &mut access);
    write(&mut dwc, 0x3c, (commands >> 32) as u32, &mut access);
    write(&mut dwc, 0x20, 1 | 4, &mut access);
    write(&mut dwc, 0x4e0, 0, &mut access);
    assert!(dwc.host_pending());
    let mut port = Port {
        iommu: &mut dart,
        stream: SID,
        memory: &mut ram,
        access: &mut access,
    };
    dwc.service_host(&mut port, None).unwrap();
    assert!(!dwc.host_pending());
    assert!(latch.is_asserted(Wire::Aic(irqs()[0])));
}

#[test]
fn power_loss_keeps_partial_dma_and_cancels_reset_work() {
    for retention in [false, true] {
        let (mut dwc, mut dart, mut ram, mut latch) = setup();
        let mut access = Access::new(0, 0, &mut latch);
        configure(&mut dwc, 2, 0, &mut access);
        trb(&mut ram, TRB, 1024, HWO | LST | IOC | 1 << 4);
        start(&mut dwc, 2, TRB, &mut access);
        let mut packet = [0x5a; 512];
        let mut port = Port {
            iommu: &mut dart,
            stream: SID,
            memory: &mut ram,
            access: &mut access,
        };
        assert_eq!(
            dwc.peer(&mut port).packet(1, Token::Out, &mut packet),
            Ok(Reply::Ack(512))
        );
        assert_eq!(dwc.endpoints[2].active.unwrap().done, 512);
        dwc.set_clock(false, port.access);
        assert!(dwc.read(DCTL, Width::Word, port.access).is_err());
        assert!(
            dwc.peer(&mut port)
                .packet(1, Token::Out, &mut packet)
                .is_err()
        );
        assert!(dwc.flush(&mut port).is_err());
        assert_eq!(dwc.endpoints[2].active.unwrap().done, 512);
        dwc.set_clock(true, port.access);
        dwc.set_quiesced(true);
        assert_eq!(dwc.read(DCTL, Width::Word, port.access), Ok(RUN.into()));
        assert!(
            dwc.peer(&mut port)
                .packet(1, Token::Out, &mut packet)
                .is_err()
        );
        dwc.set_quiesced(false);
        dwc.set_power(false, retention, port.access);
        assert!(dwc.flush(&mut port).is_err());
        dwc.set_power(true, retention, port.access);
        let mut committed = [0; 512];
        assert!(port.memory.read(PAYLOAD, &mut committed));
        assert_eq!(committed, [0x5a; 512]);
        if retention {
            assert_eq!(dwc.endpoints[2].active.unwrap().done, 512);
            packet.fill(0xa5);
            assert_eq!(
                dwc.peer(&mut port).packet(1, Token::Out, &mut packet),
                Ok(Reply::Ack(512))
            );
            dwc.flush(&mut port).unwrap();
            assert_eq!(dwc.rings[0].count, 4);
            assert!(port.memory.read(PAYLOAD + 512, &mut committed));
            assert_eq!(committed, [0xa5; 512]);
            // Another real, still-owned transfer is canceled by reset,
            // regardless of retention. Its committed prefix stays RAM.
            trb(&mut ram, TRB, 1024, HWO | LST | IOC | 1 << 4);
            let mut port = Port {
                iommu: &mut dart,
                stream: SID,
                memory: &mut ram,
                access: &mut access,
            };
            start(&mut dwc, 2, TRB, port.access);
            assert_eq!(
                dwc.peer(&mut port).packet(1, Token::Out, &mut packet),
                Ok(Reply::Ack(512))
            );
            dwc.set_reset(true, port.access);
            assert!(dwc.read(DCTL, Width::Word, port.access).is_err());
            assert!(
                dwc.peer(&mut port)
                    .packet(1, Token::Out, &mut packet)
                    .is_err()
            );
            dwc.set_reset(false, port.access);
            assert!(dwc.endpoints[2].active.is_none());
            assert!(dwc.pending.is_empty());
            assert_eq!(dwc.rings[0].count, 0);
            assert_eq!(dwc.read(DCTL, Width::Word, port.access), Ok(0));
            assert!(dwc.take_session_reset());
            assert!(!dwc.take_session_reset());
            assert!(port.memory.read(PAYLOAD, &mut committed));
            assert_eq!(committed, [0xa5; 512]);
            dwc.flush(&mut port).unwrap();
            let mut owned = [0; 4];
            assert!(port.memory.read(TRB + 12, &mut owned));
            assert_ne!(u32::from_le_bytes(owned) & HWO, 0);
        } else {
            assert!(dwc.endpoints[2].active.is_none());
            assert_eq!(dwc.read(DCTL, Width::Word, port.access), Ok(0));
            assert!(dwc.take_session_reset());
            assert_eq!(dwc.rings[0].address, 0);
        }
    }
}

#[test]
fn software_core_reset_keeps_globals_readable_and_physical_reset_keeps_phy_configuration() {
    let (mut dwc, _, _, mut latch) = setup();
    let mut access = Access::new(0, 0, &mut latch);
    let gctl = dwc.gctl;
    write(&mut dwc, GCTL, gctl | CORE_RESET, &mut access);
    assert_eq!(dwc.read(GSNPSID, Width::Word, &mut access), Ok(0x5533_300a));
    assert_eq!(
        dwc.read(GCTL, Width::Word, &mut access),
        Ok((gctl | CORE_RESET).into())
    );
    write(&mut dwc, GUID, 0x1234, &mut access);
    assert_eq!(dwc.read(GUID, Width::Word, &mut access), Ok(0x1234));
    write(&mut dwc, GCTL, gctl, &mut access);
    dwc.set_phy_state(true, false, true, false, &mut access);
    // XDCI power-on clears SUSPHY in both PHY configuration words while
    // the PHY holds the reset; they keep it past the release.
    for offset in [GUSB2PHYCFG, GUSB3PIPECTL] {
        write(&mut dwc, offset, 0, &mut access);
        assert_eq!(dwc.read(offset, Width::Word, &mut access), Ok(0));
    }
    write(&mut dwc, GUSB2PHYCFG, 1 << 3, &mut access);
    for offset in [GSNPSID, GCTL, DCTL] {
        assert!(matches!(dwc.read(offset, Width::Word, &mut access),
                Err(MmioError::Unsupported { reason, .. }) if reason.to_string().contains("unqualified")));
    }
    assert!(
        matches!(dwc.write(GCTL, Width::Word, gctl.into(), &mut access),
            Err(MmioError::Unsupported { reason, .. }) if reason.to_string().contains("unqualified"))
    );
    dwc.set_phy_state(false, true, true, false, &mut access);
    assert_eq!(dwc.read(GSNPSID, Width::Word, &mut access), Ok(0x5533_300a));
    assert_eq!(dwc.read(GUSB2PHYCFG, Width::Word, &mut access), Ok(1 << 3));
}

#[test]
fn phy_electrical_edges_preserve_transfer_resources_and_reset_sources_are_ored() {
    let (mut dwc, mut dart, mut ram, mut latch) = setup();
    let mut access = Access::new(0, 0, &mut latch);
    configure(&mut dwc, 2, 0, &mut access);
    trb(&mut ram, TRB, 1024, HWO | LST | IOC | 1 << 4);
    start(&mut dwc, 2, TRB, &mut access);
    let mut port = Port {
        iommu: &mut dart,
        stream: SID,
        memory: &mut ram,
        access: &mut access,
    };
    dwc.peer(&mut port).reset().unwrap();
    let mut packet = [0x37; 512];
    assert_eq!(
        dwc.peer(&mut port).packet(1, Token::Out, &mut packet),
        Ok(Reply::Ack(512))
    );
    dwc.pending.clear();
    dwc.devten = 1; // Disconnect event enabled.
    dwc.set_phy_state(false, false, true, false, port.access);
    dwc.set_phy_state(false, true, true, false, port.access);
    // Final-ready must not swallow the edge.
    assert_eq!(
        dwc.unavailable(),
        Some(refuse!("a PHY disconnect is pending service"))
    );
    assert!(dwc.take_session_reset());
    // Backpressure preserves both the connection and its pending edge.
    for _ in 0..MAX_PENDING_EVENTS {
        dwc.queue(0, 7).unwrap();
    }
    assert!(dwc.sync_port(&Attached(1, true)).is_err());
    assert!(dwc.connected);
    assert!(dwc.pending_phy_disconnect);
    dwc.pending.clear();
    dwc.sync_port(&Attached(1, true)).unwrap();
    assert!(!dwc.connected);
    assert_eq!(dwc.pending.len(), 1);
    assert_eq!(dwc.pending[0].value, device_event(0));
    assert!(dwc.endpoints[2].resource);
    assert_eq!(dwc.endpoints[2].active.unwrap().done, 512);
    dwc.peer(&mut port).reset().unwrap();
    packet.fill(0x73);
    assert_eq!(
        dwc.peer(&mut port).packet(1, Token::Out, &mut packet),
        Ok(Reply::Ack(512))
    );
    dwc.set_phy_state(true, false, true, false, port.access);
    dwc.set_reset(true, port.access);
    dwc.set_phy_state(false, true, true, false, port.access);
    assert!(dwc.read(DCTL, Width::Word, port.access).is_err());
    dwc.set_reset(false, port.access);
    assert_eq!(dwc.read(DCTL, Width::Word, port.access), Ok(0));
    assert!(dwc.endpoints[2].active.is_none());
    assert!(!dwc.endpoints[2].resource);
    // Reversing the release order cannot clear the PHY's reset either.
    dwc.set_reset(true, port.access);
    dwc.set_phy_state(true, false, true, false, port.access);
    dwc.set_reset(false, port.access);
    assert!(dwc.read(DCTL, Width::Word, port.access).is_err());
    dwc.set_phy_state(false, true, true, false, port.access);
    assert_eq!(dwc.read(DCTL, Width::Word, port.access), Ok(0));
    let mut committed = [0; 512];
    assert!(port.memory.read(PAYLOAD, &mut committed));
    assert_eq!(committed, [0x37; 512]);
    assert!(port.memory.read(PAYLOAD + 512, &mut committed));
    assert_eq!(committed, [0x73; 512]);
}

#[test]
fn lifecycle_keeps_real_host_rings_freezes_microframes_and_reset_prevents_stale_completion() {
    let (mut dwc, mut dart, mut ram, mut latch) = setup();
    let (erst, ring, commands) = (RAM + 0x8000, RAM + 0x9000, RAM + 0xa000);
    ram.put_u64(erst, ring);
    ram.put_u64(erst + 8, 16);
    ram.put_u64(commands + 8, (23u64 << 42) | 1 << 32);
    let mut access = Access::new(0, 0, &mut latch);
    write(&mut dwc, 0x468, 1, &mut access);
    write(&mut dwc, 0x478, ring as u32, &mut access);
    write(&mut dwc, 0x47c, (ring >> 32) as u32, &mut access);
    write(&mut dwc, 0x470, erst as u32, &mut access);
    write(&mut dwc, 0x474, (erst >> 32) as u32, &mut access);
    write(&mut dwc, 0x460, 2, &mut access);
    write(&mut dwc, 0x38, commands as u32 | 1, &mut access);
    write(&mut dwc, 0x3c, (commands >> 32) as u32, &mut access);
    write(&mut dwc, 0x20, 1 | 4, &mut access);
    write(&mut dwc, 0x4e0, 0, &mut access);
    access.now = 15_000; // five microframes
    assert_eq!(dwc.read(0x440, Width::Word, &mut access), Ok(5));
    // The PHY clock freezes time without blocking the independently
    // clocked DWC register bank. Quiesce stops DMA only.
    dwc.set_phy_state(false, true, false, false, &mut access);
    access.now = 900_000;
    assert_eq!(dwc.read(0x440, Width::Word, &mut access), Ok(5));
    dwc.set_phy_state(false, true, true, true, &mut access);
    access.now = 915_000;
    assert_eq!(dwc.read(0x440, Width::Word, &mut access), Ok(10));
    let mut port = Port {
        iommu: &mut dart,
        stream: SID,
        memory: &mut ram,
        access: &mut access,
    };
    assert!(dwc.service_host(&mut port, None).is_err());
    dwc.set_phy_state(false, true, true, false, port.access);
    dwc.set_clock(false, port.access);
    port.access.now = 999_000;
    assert!(dwc.service_host(&mut port, None).is_err());
    let mut event = [0; 16];
    assert!(port.memory.read(ring, &mut event));
    assert_eq!(event, [0; 16]);
    dwc.set_clock(true, port.access);
    assert_eq!(dwc.read(0x440, Width::Word, port.access), Ok(10));
    dwc.service_host(&mut port, None).unwrap();
    assert!(port.memory.read(ring, &mut event));
    assert_eq!(
        u32::from_le_bytes(event[8..12].try_into().unwrap()) >> 24,
        1
    );
    dwc.set_power(false, true, port.access);
    assert!(dwc.read(0x440, Width::Word, port.access).is_err());
    port.access.now = 1_999_000;
    dwc.set_power(true, true, port.access);
    assert_eq!(dwc.read(0x440, Width::Word, port.access), Ok(10));
    // Queue another command; reset cancels it while preserving
    // the previous event already committed to guest RAM.
    assert!(
        port.memory
            .write(commands + 24, &((23u64 << 42) | 1 << 32).to_le_bytes())
    );
    write(&mut dwc, 0x4e0, 0, port.access);
    assert!(dwc.host_pending());
    dwc.set_reset(true, port.access);
    assert!(!dwc.host_pending());
    dwc.set_reset(false, port.access);
    dwc.service_host(&mut port, None).unwrap();
    let mut kept = [0; 16];
    assert!(port.memory.read(ring, &mut kept));
    assert_eq!(kept, event);
    assert!(port.memory.read(ring + 16, &mut kept));
    assert_eq!(kept, [0; 16]);
    assert_eq!(dwc.read(0x20, Width::Word, port.access), Ok(0));
    assert!(dwc.take_session_reset());
}

#[test]
fn the_host_driver_selects_host_mode_which_idles_the_device() {
    let (mut dwc, _, _, mut latch) = setup();
    let mut access = Access::new(0, 0, &mut latch);
    dwc.connected = true;
    // AppleT8112USBXHCI::start: clear PRTCAPDIR, select host.
    let gctl = dwc.read(GCTL, Width::Word, &mut access).unwrap() as u32;
    write(&mut dwc, GCTL, gctl & !PRTCAP | PRTCAP_HOST, &mut access);
    assert_eq!(
        dwc.read(GCTL, Width::Word, &mut access),
        Ok(u64::from(PRTCAP_HOST))
    );
    assert!(!dwc.connected && !dwc.available());
    for reserved in [0, PRTCAP] {
        assert!(
            dwc.write(GCTL, Width::Word, u64::from(reserved), &mut access)
                .is_err()
        );
    }
    write(&mut dwc, GCTL, PRTCAP_DEVICE, &mut access);
    assert_eq!(dwc.gctl, PRTCAP_DEVICE);
}
#[test]
fn registers_commands_widths_and_failures_have_real_state() {
    let (mut dwc, _, _, mut latch) = setup();
    let mut access = Access::new(0, 0, &mut latch);
    assert_eq!(dwc.read(GSNPSID, Width::Word, &mut access), Ok(0x5533_300a));
    assert!(dwc.read(GSNPSID, Width::Double, &mut access).is_err());
    assert_eq!(dwc.read(0xcd38, Width::Word, &mut access), Ok(0));
    assert!(dwc.read(0xcd44, Width::Word, &mut access).is_err());
    // initDeviceController's GUCTL1 and GUID accesses.
    assert_eq!(dwc.read(GUCTL1, Width::Word, &mut access), Ok(0));
    assert!(dwc.write(GUCTL1, Width::Word, 0x8000, &mut access).is_err());
    write(&mut dwc, GUCTL1, 1 << 31, &mut access);
    assert_eq!(dwc.read(GUCTL1, Width::Word, &mut access), Ok(1 << 31));
    write(&mut dwc, GUID, 0x1234_5678, &mut access);
    assert_eq!(dwc.read(GUID, Width::Word, &mut access), Ok(0x1234_5678));
    assert!(
        dwc.write(GTXFIFOPRIDEV, Width::Word, 1 << 16, &mut access)
            .is_err()
    );
    // A SuperSpeed maximum connects at high speed; full speed refuses.
    write(&mut dwc, DCFG, 4 | 1 << 22, &mut access);
    assert!(dwc.write(DCFG, Width::Word, 1, &mut access).is_err());
    // DCTL test control refuses; the LPM threshold is held.
    assert!(
        dwc.write(DCTL, Width::Word, u64::from(RUN | 1 << 1), &mut access)
            .is_err()
    );
    write(&mut dwc, DCTL, RUN | 6 << 20, &mut access);
    write(&mut dwc, DCTL, RUN, &mut access);
    assert_eq!(dwc.dctl, RUN);
    write(&mut dwc, DEP + 12, CMDACT | 6, &mut access);
    assert_eq!(dwc.endpoints[0].command & CMD_FAILURE, CMD_FAILURE);
    write(&mut dwc, DEVTEN, 1 << 10, &mut access);
    write(&mut dwc, DGCMD, CMDACT | CMDIOC | 0x0a, &mut access);
    assert_eq!(dwc.read(DGCMD, Width::Word, &mut access), Ok(0));
    assert_eq!(dwc.pending.front().unwrap().value, device_event(10));
    configure(&mut dwc, 2, 0, &mut access);
    write(&mut dwc, DEP + 2 * STRIDE + 12, CMDACT | 4, &mut access);
    assert!(dwc.endpoints[2].stalled);
    write(&mut dwc, DEP + 2 * STRIDE + 12, CMDACT | 5, &mut access);
    assert!(!dwc.endpoints[2].stalled);
    let command = dwc.endpoints[2].command;
    assert!(
        dwc.write(
            DEP + 2 * STRIDE + 12,
            Width::Word,
            u64::from(CMDACT | 3),
            &mut access
        )
        .is_err()
    );
    assert_eq!(dwc.endpoints[2].command, command);
    // An interrupt IN endpoint (EP 2 IN, number 5) with its interval;
    // the interval field is reserved on bulk endpoints.
    let base = DEP + 5 * STRIDE;
    write(&mut dwc, base, 0, &mut access);
    write(
        &mut dwc,
        base + 4,
        5 << 25 | CFG_COMPLETE | 3 << 16,
        &mut access,
    );
    write(&mut dwc, base + 8, 16 << 3 | INTERRUPT << 1, &mut access);
    write(&mut dwc, base + 12, CMDACT | 1, &mut access);
    assert_eq!(dwc.endpoints[5].command & CMD_FAILURE, 0);
    assert!(dwc.endpoints[5].configured);
    write(&mut dwc, base + 8, 16 << 3 | 2 << 1, &mut access);
    assert!(
        dwc.write(base + 12, Width::Word, u64::from(CMDACT | 1), &mut access)
            .is_err()
    );
    // A bulk endpoint keeps its SuperSpeed burst; an interrupt
    // endpoint's burst field refuses.
    write(&mut dwc, base + 4, 5 << 25 | CFG_COMPLETE, &mut access);
    write(&mut dwc, base + 8, BURST | 512 << 3 | 2 << 1, &mut access);
    write(&mut dwc, base + 12, CMDACT | 1, &mut access);
    assert_eq!(dwc.endpoints[5].command & CMD_FAILURE, 0);
    write(
        &mut dwc,
        base + 8,
        BURST | 16 << 3 | INTERRUPT << 1,
        &mut access,
    );
    assert!(
        dwc.write(base + 12, Width::Word, u64::from(CMDACT | 1), &mut access)
            .is_err()
    );
}

#[test]
fn ep0_configures_for_superspeed_then_modifies_to_the_connected_speed() {
    let (mut dwc, _, _, mut latch) = setup();
    let mut access = Access::new(0, 0, &mut latch);
    for (packet, action) in [(512, 0), (64, 2 << 30)] {
        write(&mut dwc, DEP, 0, &mut access);
        write(&mut dwc, DEP + 4, CFG_COMPLETE | CFG_NOT_READY, &mut access);
        write(&mut dwc, DEP + 8, action | packet << 3, &mut access);
        write(&mut dwc, DEP + 12, CMDACT | 1, &mut access);
        assert_eq!(dwc.endpoints[0].command & CMD_FAILURE, 0);
        assert_eq!(dwc.endpoints[0].packet, packet as usize);
    }
    write(&mut dwc, DEP + 8, 1024 << 3, &mut access);
    write(&mut dwc, DEP + 12, CMDACT | 1, &mut access);
    assert_eq!(dwc.endpoints[0].command & CMD_FAILURE, CMD_FAILURE);
}
#[test]
fn bulk_dma_partial_short_and_events_precede_aic() {
    let (mut dwc, mut dart, mut ram, mut latch) = setup();
    let mut access = Access::new(0, 0, &mut latch);
    configure(&mut dwc, 2, 0, &mut access);
    trb(&mut ram, TRB, 1024, HWO | LST | IOC | 1 << 4);
    start(&mut dwc, 2, TRB, &mut access);
    let mut port = Port {
        iommu: &mut dart,
        stream: SID,
        memory: &mut ram,
        access: &mut access,
    };
    assert_eq!(
        dwc.peer(&mut port).packet(1, Token::Out, &mut [0x5a; 512]),
        Ok(Reply::Ack(512))
    );
    assert_eq!(
        dwc.peer(&mut port).packet(1, Token::Out, &mut [0x6b; 7]),
        Ok(Reply::Ack(7))
    );
    assert_eq!(dwc.rings[0].count, 0);
    dwc.flush(&mut port).unwrap();
    assert_eq!(dwc.rings[0].count, 4);
    let mut back = [0; 16];
    port.read(TRB, &mut back).unwrap();
    assert_eq!(u32::from_le_bytes(back[8..12].try_into().unwrap()), 505);
    assert_eq!(u32::from_le_bytes(back[12..].try_into().unwrap()) & HWO, 0);
    let mut data = [0; 519];
    port.read(PAYLOAD, &mut data).unwrap();
    assert_eq!(data[..512], [0x5a; 512]);
    assert_eq!(data[512..], [0x6b; 7]);
    let mut event = [0; 4];
    port.read(EVENTS, &mut event).unwrap();
    assert_eq!(
        u32::from_le_bytes(event),
        ep_event(2, XFER_COMPLETE, EV_SHORT | EV_IOC | EV_LST, 0)
    );
    assert!(latch.take_aic_inputs().contains(&(irqs()[0], true)));
    let mut access = Access::new(0, 0, &mut latch);
    write(&mut dwc, GEVNT + 12, 4, &mut access);
    assert_eq!(latch.take_aic_inputs(), [(irqs()[0], false)]);
}
#[test]
fn programmed_ring_wrap_mask_and_overflow_backpressure() {
    let (mut dwc, mut dart, mut ram, mut latch) = setup();
    let mut access = Access::new(0, 0, &mut latch);
    write(&mut dwc, GEVNT + 8, 8 | INTMASK, &mut access);
    for value in [11, 22, 33] {
        dwc.queue(0, value).unwrap();
    }
    {
        let mut port = Port {
            iommu: &mut dart,
            stream: SID,
            memory: &mut ram,
            access: &mut access,
        };
        dwc.flush(&mut port).unwrap();
    }
    assert_eq!(dwc.rings[0].count, 8);
    assert_eq!(dwc.pending.len(), 1);
    assert!(latch.take_aic_inputs().is_empty());
    let mut access = Access::new(0, 0, &mut latch);
    write(&mut dwc, GEVNT + 8, 8, &mut access);
    assert!(dwc.write(GEVNT + 12, Width::Word, 12, &mut access).is_err());
    assert_eq!(dwc.rings[0].count, 8);
    write(&mut dwc, GEVNT + 12, 4, &mut access);
    {
        let mut port = Port {
            iommu: &mut dart,
            stream: SID,
            memory: &mut ram,
            access: &mut access,
        };
        dwc.flush(&mut port).unwrap();
        let mut event = [0; 4];
        port.read(EVENTS, &mut event).unwrap();
        assert_eq!(u32::from_le_bytes(event), 33);
    }
    assert_eq!(dwc.rings[0].producer, 4);
    assert_eq!(dwc.rings[0].count, 8);
}
#[test]
fn a_completed_trb_follows_its_link_before_software_reuses_the_block() {
    let (mut dwc, mut dart, mut ram, mut latch) = setup();
    let mut access = Access::new(0, 0, &mut latch);
    configure(&mut dwc, 3, 0, &mut access);
    let resting = TRB + 0x100;
    trb(&mut ram, TRB, 3, HWO | IOC | 1 << 4);
    ram.put_u64(TRB + 16, resting);
    assert!(ram.write(TRB + 24, &[0, 0, 0, 0, 0x81, 0, 0, 0]));
    trb(&mut ram, resting, 2, LST | 1 << 4);
    start(&mut dwc, 3, TRB, &mut access);
    let mut bytes = [0; 512];
    let mut packet = |dwc: &mut Dwc3, ram: &mut Ram| {
        let mut port = Port {
            iommu: &mut dart,
            stream: SID,
            memory: ram,
            access: &mut access,
        };
        dwc.peer(&mut port).packet(0x81, Token::In, &mut bytes)
    };
    assert_eq!(packet(&mut dwc, &mut ram), Ok(Reply::Ack(3)));
    // The pool hands the finished block to another ring, then software
    // queues this ring's next request in its resting TRB.
    trb(&mut ram, TRB + 16, 7, HWO | 1 << 4);
    trb(&mut ram, resting, 2, HWO | LST | 1 << 4);
    assert_eq!(packet(&mut dwc, &mut ram), Ok(Reply::Ack(2)));
}

#[test]
fn in_link_trbs_stall_update_end_and_detach_leaves_transfers_to_software() {
    let (mut dwc, mut dart, mut ram, mut latch) = setup();
    let mut access = Access::new(0, 0, &mut latch);
    configure(&mut dwc, 3, 0, &mut access);
    ram.put_u64(TRB, TRB + 16);
    assert!(ram.write(TRB + 8, &[0, 0, 0, 0, 0x81, 0, 0, 0]));
    trb(&mut ram, TRB + 16, 3, HWO | LST | IOC | 1 << 4);
    assert!(ram.write(PAYLOAD, b"abc"));
    start(&mut dwc, 3, TRB, &mut access);
    let mut bytes = [0; 512];
    {
        let mut port = Port {
            iommu: &mut dart,
            stream: SID,
            memory: &mut ram,
            access: &mut access,
        };
        assert_eq!(
            dwc.peer(&mut port).packet(0x81, Token::In, &mut bytes),
            Ok(Reply::Ack(3))
        );
    }
    assert_eq!(&bytes[..3], b"abc");
    trb(&mut ram, TRB, 512, HWO | LST | 1 << 4);
    start(&mut dwc, 3, TRB, &mut access);
    write(
        &mut dwc,
        DEP + 3 * STRIDE + 12,
        CMDACT | 7 | 1 << 16,
        &mut access,
    );
    assert!(dwc.endpoints[3].active.is_some());
    write(
        &mut dwc,
        DEP + 3 * STRIDE + 12,
        CMDACT | 8 | 1 << 11 | 1 << 16,
        &mut access,
    );
    assert!(dwc.endpoints[3].active.is_none());
    start(&mut dwc, 3, TRB, &mut access);
    dwc.sync_port(&Attached(2, false)).unwrap();
    // Detach leaves the started transfer to software's End Transfer.
    assert!(dwc.endpoints[3].active.is_some());
    assert!(dwc.endpoints[3].resource);
    {
        let mut port = Port {
            iommu: &mut dart,
            stream: SID,
            memory: &mut ram,
            access: &mut access,
        };
        assert_eq!(
            dwc.peer(&mut port).packet(0x81, Token::In, &mut bytes),
            Ok(Reply::Nak)
        );
    }
    write(
        &mut dwc,
        DEP + 3 * STRIDE + 12,
        CMDACT | 8 | 1 << 11 | 1 << 16,
        &mut access,
    );
    assert!(dwc.endpoints[3].active.is_none());
    assert_eq!(dwc.endpoints[3].command & CMD_FAILURE, 0);
}
#[test]
fn usb_reset_keeps_ep0_transfer_resources_for_the_next_setup_transfer() {
    let (mut dwc, mut dart, mut ram, mut latch) = setup();
    let mut access = Access::new(0, 0, &mut latch);
    configure(&mut dwc, 0, 0, &mut access);
    configure(&mut dwc, 1, 0, &mut access);
    trb(&mut ram, TRB, 8, HWO | LST | IOC | 2 << 4);
    start(&mut dwc, 0, TRB, &mut access);
    {
        let mut port = Port {
            iommu: &mut dart,
            stream: SID,
            memory: &mut ram,
            access: &mut access,
        };
        dwc.peer(&mut port).reset().unwrap();
    }
    // The SETUP transfer started before the reset is still armed.
    assert!(dwc.endpoints[0].active.is_some());
    // The driver ends it and restarts EP0 OUT on the same resource.
    write(
        &mut dwc,
        DEP + 12,
        CMDACT | 8 | 1 << 11 | 1 << 16,
        &mut access,
    );
    assert_eq!(dwc.endpoints[0].command & CMD_FAILURE, 0);
    start(&mut dwc, 0, TRB, &mut access);
    assert_eq!(dwc.endpoints[0].command & CMD_FAILURE, 0);
    // A detach and reattach also keeps the resource.
    write(
        &mut dwc,
        DEP + 12,
        CMDACT | 8 | 1 << 11 | 1 << 16,
        &mut access,
    );
    dwc.sync_port(&Attached(2, true)).unwrap();
    start(&mut dwc, 0, TRB, &mut access);
    // Only Start Configuration or a core reset releases it.
    write(
        &mut dwc,
        DEP + 12,
        CMDACT | 8 | 1 << 11 | 1 << 16,
        &mut access,
    );
    let gctl = dwc.gctl;
    write(&mut dwc, GCTL, gctl | CORE_RESET, &mut access);
    assert!(!dwc.endpoints[0].resource);
}
#[test]
fn setup_data_status_trbs_and_zero_length_packet() {
    let (mut dwc, mut dart, mut ram, mut latch) = setup();
    let mut access = Access::new(0, 0, &mut latch);
    configure(&mut dwc, 0, 0, &mut access);
    configure(&mut dwc, 1, 0, &mut access);
    for (endpoint, token, kind, mut bytes) in [
        (0, Token::Setup, 2, vec![0x80, 6, 0, 1, 0, 0, 18, 0]),
        (0x80, Token::In, 5, vec![0; 18]),
        (0, Token::Out, 4, vec![]),
    ] {
        let n = usize::from(endpoint & 0xf) * 2 + usize::from(endpoint & 0x80 != 0);
        trb(&mut ram, TRB, bytes.len() as u32, HWO | LST | kind << 4);
        start(&mut dwc, n, TRB, &mut access);
        let length = bytes.len();
        let mut port = Port {
            iommu: &mut dart,
            stream: SID,
            memory: &mut ram,
            access: &mut access,
        };
        assert_eq!(
            dwc.peer(&mut port).packet(endpoint, token, &mut bytes),
            Ok(Reply::Ack(length))
        );
    }
}
#[test]
fn dart_fault_poisoning_and_software_reset_prevent_stale_completion() {
    let (mut dwc, mut dart, mut ram, mut latch) = setup();
    let mut access = Access::new(0, 0, &mut latch);
    configure(&mut dwc, 2, 0, &mut access);
    trb(&mut ram, TRB, 512, HWO | LST | 1 << 4);
    start(&mut dwc, 2, TRB, &mut access);
    write_dart(&mut dart, DART_TCR + SID as u64 * 4, 0, &mut access);
    {
        let mut port = Port {
            iommu: &mut dart,
            stream: SID,
            memory: &mut ram,
            access: &mut access,
        };
        assert!(
            dwc.peer(&mut port)
                .packet(1, Token::Out, &mut [1; 512])
                .is_err()
        );
        assert!(dwc.flush(&mut port).is_err());
    }
    assert!(dwc.poisoned.is_some());
    assert_eq!(dwc.rings[0].count, 0);
    assert!(
        latch
            .take_aic_inputs()
            .iter()
            .any(|&(irq, level)| irq.irq == 1035 && level)
    );
    let mut access = Access::new(0, 0, &mut latch);
    write(&mut dwc, DCTL, RESET, &mut access);
    assert!(dwc.poisoned.is_none());
    assert!(dwc.endpoints.iter().all(|ep| ep.active.is_none()));
    assert_eq!(dwc.read(DCTL, Width::Word, &mut access), Ok(0));
}
#[test]
fn translated_dma_crosses_pages_and_stops_at_dart_write_permission() {
    const IOVA: u64 = 0x20000000;
    const PAGE: u64 = 0x4000;
    const LEAVES: u64 = RAM + PAGE;
    const FRAME: u64 = RAM + 2 * PAGE;
    let entry = |pa: u64| ((pa >> 4) & 0x3f_ffff_fc00) | 1;
    for writable in [true, false] {
        let (mut dwc, mut dart, mut ram, mut latch) = setup();
        let mut access = Access::new(0, 0, &mut latch);
        ram.put_u64(RAM + 8 * (IOVA >> 25), entry(LEAVES));
        ram.put_u64(LEAVES, entry(FRAME) | 0xfff << 40);
        ram.put_u64(
            LEAVES + 8,
            entry(FRAME + PAGE) | 0xfff << 40 | if writable { 0 } else { 1 << 2 },
        );
        write_dart(
            &mut dart,
            0x1400 + SID as u64 * 4,
            ((RAM >> 14) << 2) as u32 | 1,
            &mut access,
        );
        write_dart(&mut dart, DART_TCR + SID as u64 * 4, 1, &mut access);
        configure(&mut dwc, 2, 0, &mut access);
        trb(&mut ram, FRAME + 0x1000, 512, HWO | LST | IOC | 1 << 4);
        ram.put_u64(FRAME + 0x1000, IOVA + PAGE - 16);
        write(&mut dwc, GEVNT, (IOVA + 0x100) as u32, &mut access);
        write(&mut dwc, GEVNT + 4, 0, &mut access);
        start(&mut dwc, 2, IOVA + 0x1000, &mut access);
        let result = {
            let mut port = Port {
                iommu: &mut dart,
                stream: SID,
                memory: &mut ram,
                access: &mut access,
            };
            let result = dwc.peer(&mut port).packet(1, Token::Out, &mut [0x7c; 512]);
            if result.is_ok() {
                dwc.flush(&mut port).unwrap();
            }
            result
        };
        assert_eq!(
            &ram.bytes[(3 * PAGE - 16) as usize..(3 * PAGE) as usize],
            &[0x7c; 16]
        );
        if writable {
            assert_eq!(result, Ok(Reply::Ack(512)));
            assert_eq!(
                &ram.bytes[(3 * PAGE) as usize..(3 * PAGE + 496) as usize],
                &[0x7c; 496]
            );
            assert_eq!(dwc.rings[0].count, 4);
        } else {
            assert!(result.is_err());
            assert!(dwc.poisoned.is_some());
            assert_eq!(dwc.rings[0].count, 0);
            assert_eq!(
                &ram.bytes[(3 * PAGE) as usize..(3 * PAGE + 496) as usize],
                &[0; 496]
            );
        }
    }
}

#[test]
fn host_enumeration_reaches_real_control_trb_dma_and_event_buffers() {
    use crate::platform::usb::host::Host;
    // A small synthetic guest driver: posts TRBs between host
    // steps. It supplies test descriptors; production has no descriptors.
    let device = vec![18, 1, 0, 2, 0, 0, 0, 64, 0x34, 0x12, 0, 1, 0, 1, 0, 0, 0, 1];
    let config = vec![
        9, 2, 32, 0, 1, 7, 0, 0x80, 50, 9, 4, 3, 0, 2, 0xff, 0xfe, 2, 0, 7, 5, 0x85, 2, 0, 2, 0, 7,
        5, 9, 2, 0, 2, 0,
    ];
    let (mut dwc, mut dart, mut ram, mut latch) = setup();
    let mut host = Host::new();
    host.attach(1);
    {
        let mut access = Access::new(0, 0, &mut latch);
        let mut port = Port {
            iommu: &mut dart,
            stream: SID,
            memory: &mut ram,
            access: &mut access,
        };
        host.advance(&mut dwc.peer(&mut port), 0).unwrap();
    }
    let mut access = Access::new(0, 0, &mut latch);
    configure(&mut dwc, 0, 0, &mut access);
    configure(&mut dwc, 1, 0, &mut access);
    trb(&mut ram, TRB, 8, HWO | LST | IOC | 2 << 4);
    start(&mut dwc, 0, TRB, &mut access);
    // (posted endpoint, phase): setup=0, data=1, status=2.
    let mut posted = (0, 0);
    let mut address = 0;
    let mut configuration = 0;
    let mut request = [0; 8];
    for step in 1..100 {
        let now = step * 24000;
        let mut access = Access::new(0, now, &mut latch);
        {
            let mut port = Port {
                iommu: &mut dart,
                stream: SID,
                memory: &mut ram,
                access: &mut access,
            };
            host.advance(&mut dwc.peer(&mut port), now).unwrap();
            dwc.flush(&mut port).unwrap();
        }
        if dwc.endpoints[posted.0].active.is_none() {
            let (n, kind, bytes) = match posted.1 {
                0 => {
                    assert!(ram.read(PAYLOAD, &mut request));
                    let length = usize::from(u16::from_le_bytes([request[6], request[7]]));
                    if length == 0 {
                        (1, 3, vec![])
                    } else {
                        let mut response = match request[3] {
                            1 => device.clone(),
                            2 => config.clone(),
                            _ => panic!("unexpected fixture descriptor"),
                        };
                        response.truncate(length);
                        (1, 5, response)
                    }
                }
                1 => (0, 4, vec![]),
                _ => {
                    if request[1] == 5 {
                        address = u16::from_le_bytes([request[2], request[3]]);
                        write(&mut dwc, DCFG, u32::from(address) << 3, &mut access);
                    }
                    if request[1] == 9 {
                        configuration = request[2];
                    }
                    (0, 2, vec![0; 8])
                }
            };
            assert!(ram.write(PAYLOAD, &bytes));
            trb(
                &mut ram,
                TRB,
                bytes.len() as u32,
                HWO | LST | IOC | kind << 4,
            );
            start(&mut dwc, n, TRB, &mut access);
            posted = (
                n,
                if kind == 2 {
                    0
                } else if kind == 5 {
                    1
                } else {
                    2
                },
            );
        }
        let count = dwc.rings[0].count;
        if count != 0 {
            write(&mut dwc, GEVNT + 12, count, &mut access);
        }
        if host.ready() {
            break;
        }
    }
    assert!(host.ready());
    assert_eq!(address, 1);
    assert_eq!(configuration, 7);
    assert_eq!(
        host.descriptors()
            .iter()
            .map(|d| d.bytes.clone())
            .collect::<alloc::vec::Vec<_>>(),
        [device, config]
    );
    assert!(dwc.rings[0].producer > 0);
    assert!(dwc.poisoned.is_none());
}
#[test]
fn one_full_ring_does_not_block_another_interrupt_buffer() {
    let (mut dwc, mut dart, mut ram, mut latch) = setup();
    let mut access = Access::new(0, 0, &mut latch);
    write(&mut dwc, GEVNT + 8, 4, &mut access);
    write(
        &mut dwc,
        GEVNT + STRIDE,
        (EVENTS + 0x800) as u32,
        &mut access,
    );
    write(
        &mut dwc,
        GEVNT + STRIDE + 4,
        ((EVENTS + 0x800) >> 32) as u32,
        &mut access,
    );
    write(&mut dwc, GEVNT + STRIDE + 8, 0x800, &mut access);
    dwc.queue(0, 11).unwrap();
    dwc.queue(0, 22).unwrap();
    dwc.queue(1, 33).unwrap();
    let mut port = Port {
        iommu: &mut dart,
        stream: SID,
        memory: &mut ram,
        access: &mut access,
    };
    dwc.flush(&mut port).unwrap();
    assert_eq!(dwc.rings[0].count, 4);
    assert_eq!(dwc.rings[1].count, 4);
    assert_eq!(dwc.pending.len(), 1);
    let mut back = [0; 4];
    port.read(EVENTS + 0x800, &mut back).unwrap();
    assert_eq!(u32::from_le_bytes(back), 33);
    let wires = latch.take_aic_inputs();
    assert!(wires.contains(&(irqs()[0], true)));
    assert!(wires.contains(&(irqs()[1], true)));
}
#[test]
fn start_configuration_preserves_ep0_resources_and_short_events_have_no_fake_stream() {
    let (mut dwc, mut dart, mut ram, mut latch) = setup();
    let mut access = Access::new(0, 0, &mut latch);
    for n in 0..3 {
        configure(&mut dwc, n, 0, &mut access);
    }
    write(&mut dwc, DEP + 12, CMDACT | 9 | 2 << 16, &mut access);
    assert!(dwc.endpoints[0].resource);
    assert!(dwc.endpoints[1].resource);
    assert!(!dwc.endpoints[2].resource);
    configure(&mut dwc, 2, 0, &mut access);
    trb(&mut ram, TRB, 512, HWO | IOC | 1 << 4);
    start(&mut dwc, 2, TRB, &mut access);
    let mut port = Port {
        iommu: &mut dart,
        stream: SID,
        memory: &mut ram,
        access: &mut access,
    };
    assert_eq!(
        dwc.peer(&mut port).packet(1, Token::Out, &mut [1; 3]),
        Ok(Reply::Ack(3))
    );
    dwc.flush(&mut port).unwrap();
    let mut back = [0; 4];
    port.read(EVENTS, &mut back).unwrap();
    assert_eq!(
        u32::from_le_bytes(back),
        ep_event(2, XFER_COMPLETE, EV_SHORT | EV_IOC, 0)
    );
}
#[test]
fn unowned_trb_reports_active_not_ready_once_and_update_rearms_it() {
    let (mut dwc, mut dart, mut ram, mut latch) = setup();
    let mut access = Access::new(0, 0, &mut latch);
    configure(&mut dwc, 2, 0, &mut access);
    trb(&mut ram, TRB, 512, LST | 1 << 4);
    start(&mut dwc, 2, TRB, &mut access);
    {
        let mut port = Port {
            iommu: &mut dart,
            stream: SID,
            memory: &mut ram,
            access: &mut access,
        };
        for _ in 0..2 {
            assert_eq!(
                dwc.peer(&mut port).packet(1, Token::Out, &mut [1; 512]),
                Ok(Reply::Nak)
            );
        }
        dwc.flush(&mut port).unwrap();
        let mut event = [0; 4];
        port.read(EVENTS, &mut event).unwrap();
        assert_eq!(u32::from_le_bytes(event), ep_event(2, XFER_NOT_READY, 8, 0));
    }
    assert_eq!(dwc.rings[0].count, 4);
    write(
        &mut dwc,
        DEP + 2 * STRIDE + 12,
        CMDACT | 7 | 1 << 16,
        &mut access,
    );
    {
        let mut port = Port {
            iommu: &mut dart,
            stream: SID,
            memory: &mut ram,
            access: &mut access,
        };
        assert_eq!(
            dwc.peer(&mut port).packet(1, Token::Out, &mut [1; 512]),
            Ok(Reply::Nak)
        );
        dwc.flush(&mut port).unwrap();
    }
    assert_eq!(dwc.rings[0].count, 8);
}
