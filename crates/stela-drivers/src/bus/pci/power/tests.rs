use super::*;
use crate::bus::pci::Address;
use alloc::{rc::Rc, vec::Vec};
use core::cell::RefCell;

const PM: u16 = 0x60;
const CSR: u16 = PM + 4;
const ID: u32 = 0x1234_5678;
const BARS: [u32; 7] = [0x8000_0004, 1, 0x9000_0000, 0, 0x1001, 0, 0x9800_0000];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Effect {
    Word(u16, u16),
    Dword(u16, u32),
    Wait(u64),
}
struct Device {
    bytes: [u8; 256],
    effects: Vec<Effect>,
    reads: usize,
    fail_read: Option<usize>,
    fail_effect: Option<usize>,
    lose_after_effect: Option<usize>,
    inaccessible: bool,
    reset_bars: bool,
    readiness_us: u64,
    pending_readiness: u64,
    elapsed: u64,
    config_drops: usize,
    timer_drops: usize,
    platform_drops: usize,
    clock_ok: bool,
}
impl Device {
    fn word(&self, offset: u16) -> u16 {
        u16::from_le_bytes(
            self.bytes[usize::from(offset)..usize::from(offset) + 2]
                .try_into()
                .unwrap(),
        )
    }
    fn put_word(&mut self, offset: u16, value: u16) {
        self.bytes[usize::from(offset)..usize::from(offset) + 2]
            .copy_from_slice(&value.to_le_bytes());
    }
    fn put_dword(&mut self, offset: u16, value: u32) {
        self.bytes[usize::from(offset)..usize::from(offset) + 4]
            .copy_from_slice(&value.to_le_bytes());
    }
    fn effect(&mut self, effect: Effect) -> bool {
        self.effects.push(effect);
        let number = self.effects.len();
        if self.lose_after_effect == Some(number) {
            self.inaccessible = true;
        }
        self.fail_effect != Some(number)
    }
    fn read(&mut self, offset: u16, width: usize) -> u32 {
        self.reads += 1;
        if self.inaccessible || self.fail_read == Some(self.reads) {
            return match width {
                1 => 0xff,
                2 => 0xffff,
                _ => u32::MAX,
            };
        }
        if self.pending_readiness != 0 && offset == 0 {
            return 0xffff_0001;
        }
        if self.pending_readiness != 0 && offset == 4 {
            return u32::MAX;
        }
        (0..width).fold(0, |value, index| {
            value | u32::from(self.bytes[usize::from(offset) + index]) << (8 * index)
        })
    }
}
struct Config(Rc<RefCell<Device>>);
impl Drop for Config {
    fn drop(&mut self) {
        self.0.borrow_mut().config_drops += 1;
    }
}
impl ConfigSpace for Config {
    fn read8(&self, offset: u16) -> u8 {
        self.0.borrow_mut().read(offset, 1) as u8
    }
    fn read16(&self, offset: u16) -> u16 {
        self.0.borrow_mut().read(offset, 2) as u16
    }
    fn read32(&self, offset: u16) -> u32 {
        self.0.borrow_mut().read(offset, 4)
    }
    fn write32(&mut self, offset: u16, value: u32) {
        let mut d = self.0.borrow_mut();
        assert!(
            (0x10..=0x30).contains(&offset),
            "only actual BAR dwords may be written"
        );
        assert_eq!(d.word(4) & 7, 0, "no BAR write under decoding or BME");
        if d.effect(Effect::Dword(offset, value)) {
            d.put_dword(offset, value);
        }
    }
    fn write16(&mut self, offset: u16, value: u16) {
        let mut d = self.0.borrow_mut();
        assert!(offset == 4 || offset == CSR);
        if !d.effect(Effect::Word(offset, value)) {
            return;
        }
        if offset == CSR {
            let old = d.word(CSR);
            // Real PMCSR behavior: status W1C, No_Soft_Reset RO, reserved RO,
            // Data_Select/PME_Enable/PowerState RW. This is not plain RAM.
            let status = old & PME_STATUS & !(value & PME_STATUS);
            let next = (old & !(STATE | PME_ENABLE | DATA_SELECT | PME_STATUS))
                | (value & (STATE | PME_ENABLE | DATA_SELECT))
                | status;
            d.put_word(CSR, next);
            if old & STATE == 3 && next & STATE == 0 {
                if old & NO_SOFT_RESET == 0 && d.reset_bars {
                    for index in 0..7 {
                        d.put_dword(bar_offset(index), 0);
                    }
                    d.put_word(4, 0);
                }
                d.pending_readiness = d.readiness_us;
            }
        } else {
            d.put_word(offset, value);
        }
    }
}
// SAFETY: this independent device model implements real-width PCI writes and
// PMCSR W1C/RO/reset behavior; no production hardware authority is fabricated.
unsafe impl MsiConfigSpace for Config {}
struct ModelTimer(Rc<RefCell<Device>>);
impl Drop for ModelTimer {
    fn drop(&mut self) {
        self.0.borrow_mut().timer_drops += 1;
    }
}
// SAFETY: deterministic time advances the same device's readiness state. The
// fixture is an explicit independent model, not a physical timing provider.
unsafe impl Timer for ModelTimer {
    fn check(&self) -> Result<(), Error> {
        if self.0.borrow().clock_ok {
            Ok(())
        } else {
            Err(Error::Clock)
        }
    }
    fn wait_us(&self, us: u64) -> Result<(), Error> {
        let mut d = self.0.borrow_mut();
        if !d.effect(Effect::Wait(us)) {
            return Err(Error::Clock);
        }
        d.elapsed += us;
        d.pending_readiness = d.pending_readiness.saturating_sub(us);
        Ok(())
    }
}
/// Original fixture's stable-rail/exclusion reservation. This separately
/// proves the power grant stays owned when a config access/transition fails.
struct Platform(Rc<RefCell<Device>>);
impl Drop for Platform {
    fn drop(&mut self) {
        self.0.borrow_mut().platform_drops += 1;
    }
}
type Owner = Power<Config, ModelTimer, Platform>;
fn fixture(no_reset: bool) -> (Function<Config>, ModelTimer, Rc<RefCell<Device>>) {
    let mut d = Device {
        bytes: [0; 256],
        effects: Vec::new(),
        reads: 0,
        fail_read: None,
        fail_effect: None,
        lose_after_effect: None,
        inaccessible: false,
        reset_bars: true,
        readiness_us: 0,
        pending_readiness: 0,
        elapsed: 0,
        config_drops: 0,
        timer_drops: 0,
        platform_drops: 0,
        clock_ok: true,
    };
    d.put_dword(0, ID);
    d.put_dword(8, 0x0200_0001);
    d.put_word(4, 3);
    d.put_word(6, 0xa510);
    d.bytes[0x34] = PM as u8;
    d.put_word(PM, 1);
    d.put_word(PM + 2, 3 | (1 << 11) | (1 << 14));
    d.put_word(CSR, PME_STATUS | if no_reset { NO_SOFT_RESET } else { 0 });
    for (i, value) in BARS.iter().copied().enumerate() {
        d.put_dword(bar_offset(i), value);
    }
    let d = Rc::new(RefCell::new(d));
    let function = Function::new(
        Address {
            segment: 2,
            bus: 7,
            device: 3,
            function: 1,
        },
        Config(d.clone()),
    )
    .unwrap();
    (function, ModelTimer(d.clone()), d)
}
fn owner(no_reset: bool) -> (Owner, Rc<RefCell<Device>>) {
    let (function, timer, device) = fixture(no_reset);
    // SAFETY: one actual independent model with original exclusively owned
    // config/timing handles; stable modeled rails and no concurrent actors.
    let power = unsafe { Power::attach(function, timer, Platform(device.clone()), D3_DELAY) }
        .unwrap_or_else(|(error, _, _, _)| panic!("valid model: {error:?}"));
    device.borrow_mut().reads = 0;
    (power, device)
}
fn suspend(power: &mut Owner) -> Result<(), Error> {
    // SAFETY: fixture engines/DMA/IRQ/work do not run; test owns all effects.
    unsafe { power.suspend() }
}
fn released(power: Owner) {
    match power.release() {
        Ok((function, timer, platform)) => {
            drop(function);
            drop(timer);
            drop(platform);
        }
        Err(_) => panic!("expected verified D0 release"),
    }
}
fn assert_retained(power: Owner, d: &Rc<RefCell<Device>>) {
    let reads = d.borrow().reads;
    drop(power);
    let d = d.borrow();
    assert_eq!(d.config_drops, 0);
    assert_eq!(d.timer_drops, 0);
    assert_eq!(d.platform_drops, 0);
    assert_eq!(d.reads, reads, "Drop performs no unsafe config access");
}

#[test]
fn repeated_real_d3_reset_restores_bars_and_stopped_decoding() {
    let (mut power, d) = owner(false);
    for _ in 0..3 {
        suspend(&mut power).unwrap();
        assert_eq!(power.state(), State::D3hot);
        assert_eq!(d.borrow().word(4), INTX_DISABLE);
        assert_eq!(d.borrow().word(CSR) & (STATE | PME_STATUS), 3 | PME_STATUS);
        power.resume().unwrap();
        assert_eq!(power.state(), State::D0);
        let mut d = d.borrow_mut();
        assert_eq!(d.word(4), 3 | INTX_DISABLE);
        assert_eq!(d.word(6), 0xa510, "adjacent status W1C untouched");
        assert_eq!(d.word(CSR) & (STATE | PME_ENABLE | PME_STATUS), PME_STATUS);
        for (i, value) in BARS.iter().copied().enumerate() {
            assert_eq!(d.read(bar_offset(i), 4), value);
        }
    }
    assert_eq!(d.borrow().elapsed, 6 * D3_DELAY);
    assert_eq!(
        d.borrow()
            .effects
            .iter()
            .filter(|e| matches!(e, Effect::Dword(..)))
            .count(),
        21
    );
    released(power);
    assert_eq!(d.borrow().config_drops, 1);
    assert_eq!(d.borrow().timer_drops, 1);
    assert_eq!(d.borrow().platform_drops, 1);
}

#[test]
fn no_soft_reset_checks_bars_without_writing_them() {
    let (mut power, d) = owner(true);
    suspend(&mut power).unwrap();
    power.resume().unwrap();
    assert!(
        !d.borrow()
            .effects
            .iter()
            .any(|e| matches!(e, Effect::Dword(..)))
    );
    released(power);
    let (mut power, d) = owner(true);
    suspend(&mut power).unwrap();
    d.borrow_mut().put_dword(0x10, 0xa000_0004);
    assert_eq!(power.resume(), Err(Error::Bars));
    assert_eq!(power.state(), State::Unknown);
    assert_eq!(d.borrow().word(4) & 7, 0);
    assert_retained(power, &d);
}

#[test]
fn pme_ack_is_explicit_and_transition_never_replays_pending_w1c() {
    let (mut power, d) = owner(true);
    // SAFETY: explicit modeled wake route/device setup, no racing consumers.
    unsafe { power.configure_pme(WakeState::D3hot, true) }.unwrap();
    assert_eq!(d.borrow().word(CSR) & (PME_ENABLE | PME_STATUS), PME_ENABLE);
    {
        let mut d = d.borrow_mut();
        let csr = d.word(CSR);
        d.put_word(CSR, csr | PME_STATUS);
    }
    suspend(&mut power).unwrap();
    assert_eq!(
        d.borrow().word(CSR) & (PME_ENABLE | PME_STATUS),
        PME_ENABLE | PME_STATUS
    );
    power.resume().unwrap();
    assert_eq!(d.borrow().word(CSR) & (PME_ENABLE | PME_STATUS), PME_STATUS);
    released(power);
}

#[test]
fn unsupported_wake_and_bus_master_refuse_before_effects() {
    let (mut power, d) = owner(true);
    d.borrow_mut().put_word(4, 7);
    assert_eq!(suspend(&mut power), Err(Error::BusMaster));
    assert_eq!(power.state(), State::D0);
    assert!(d.borrow().effects.is_empty());
    d.borrow_mut().put_word(4, 3);
    released(power);
    let (function, timer, d) = fixture(true);
    d.borrow_mut().put_word(PM + 2, 3 | (1 << 11));
    // SAFETY: same isolated original-owner model contract as owner().
    let mut power = unsafe { Power::attach(function, timer, Platform(d.clone()), D3_DELAY) }
        .unwrap_or_else(|_| panic!("valid D0-only wake capability"));
    // SAFETY: D0 wake route is modeled, without claiming D3hot wake support.
    unsafe { power.configure_pme(WakeState::D0, true) }.unwrap();
    let effects = d.borrow().effects.len();
    assert_eq!(suspend(&mut power), Err(Error::Unsupported));
    assert_eq!(d.borrow().effects.len(), effects);
    released(power);
}

#[test]
fn d3hot_only_pme_is_armed_in_d0_for_the_actual_target_state() {
    let (function, timer, d) = fixture(true);
    d.borrow_mut().put_word(PM + 2, 3 | (1 << 14));
    // SAFETY: same actual isolated original configuration/platform owner.
    let mut power = unsafe { Power::attach(function, timer, Platform(d.clone()), D3_DELAY) }
        .unwrap_or_else(|_| panic!("D3hot-only wake capability"));
    // SAFETY: fixture's actual D3hot wake setup and route are prepared in D0.
    unsafe { power.configure_pme(WakeState::D3hot, true) }.unwrap();
    assert_eq!(d.borrow().word(CSR) & (STATE | PME_ENABLE), PME_ENABLE);
    suspend(&mut power).unwrap();
    assert_eq!(d.borrow().word(CSR) & (STATE | PME_ENABLE), 3 | PME_ENABLE);
    power.resume().unwrap();
    released(power);
}

#[test]
fn inaccessible_states_refuse_function_access_and_release_without_effects() {
    let (mut power, d) = owner(true);
    suspend(&mut power).unwrap();
    let reads = d.borrow().reads;
    // SAFETY: action does nothing; it must never run outside D0.
    assert_eq!(
        unsafe { power.with_d0(|_| panic!("must refuse")) },
        Err::<(), _>(Error::State)
    );
    let mut power = match power.release() {
        Err(power) => power,
        Ok(_) => panic!("D3hot release"),
    };
    assert_eq!(d.borrow().reads, reads);
    assert_eq!(power.state(), State::D3hot);
    power.resume().unwrap();
    released(power);
}

#[test]
fn every_refused_transition_store_or_wait_retains_original_owners() {
    let (mut power, d) = owner(false);
    suspend(&mut power).unwrap();
    power.resume().unwrap();
    let count = d.borrow().effects.len();
    released(power);
    for failure in 1..=count {
        let (mut power, d) = owner(false);
        d.borrow_mut().fail_effect = Some(failure);
        let result = suspend(&mut power).and_then(|()| power.resume());
        // Refusing a BAR store of zero into an already-zero BAR is harmless;
        // every nontrivial failed effect must instead refuse publication.
        if result.is_ok() {
            let effect = d.borrow().effects[failure - 1];
            assert!(matches!(
                effect,
                Effect::Dword(_, 0) | Effect::Word(4, 0x400)
            ));
            released(power);
        } else {
            assert_eq!(power.state(), State::Unknown, "effect {failure}");
            assert_retained(power, &d);
        }
    }
}

#[test]
fn every_effect_followed_by_config_loss_quarantines_without_retry() {
    let (mut power, d) = owner(false);
    suspend(&mut power).unwrap();
    power.resume().unwrap();
    let count = d.borrow().effects.len();
    released(power);
    for failure in 1..=count {
        let (mut power, d) = owner(false);
        d.borrow_mut().lose_after_effect = Some(failure);
        assert!(
            suspend(&mut power).and_then(|()| power.resume()).is_err(),
            "effect {failure}"
        );
        assert_eq!(power.state(), State::Unknown);
        let reads = d.borrow().reads;
        let effects = d.borrow().effects.len();
        assert_eq!(power.resume(), Err(Error::State));
        // SAFETY: even a benign callback must be refused after uncertainty.
        assert_eq!(unsafe { power.with_d0(|_| ()) }, Err(Error::State));
        assert_eq!(d.borrow().reads, reads);
        assert_eq!(d.borrow().effects.len(), effects);
        assert_retained(power, &d);
    }
}

#[test]
fn every_failed_configuration_observation_refuses_or_reestablishes_readiness() {
    let (mut power, d) = owner(false);
    suspend(&mut power).unwrap();
    power.resume().unwrap();
    let count = d.borrow().reads;
    released(power);
    for failure in 1..=count {
        let (mut power, d) = owner(false);
        d.borrow_mut().fail_read = Some(failure);
        let result = suspend(&mut power).and_then(|()| power.resume());
        if result.is_ok() {
            // Readiness may recover from a failed observation, but only after
            // the subsequent complete identity/capability/PMCSR/BAR checks.
            assert_eq!(power.state(), State::D0);
            let mut d = d.borrow_mut();
            assert_eq!(d.word(4), 3 | INTX_DISABLE);
            for (i, value) in BARS.iter().copied().enumerate() {
                assert_eq!(d.read(bar_offset(i), 4), value);
            }
            drop(d);
            released(power);
        } else {
            assert_eq!(power.state(), State::Unknown, "read {failure}");
            assert_retained(power, &d);
        }
    }
}

#[test]
fn config_readiness_waits_for_rrs_and_timeout_keeps_decoding_off() {
    let (mut power, d) = owner(false);
    d.borrow_mut().readiness_us = 55_000;
    suspend(&mut power).unwrap();
    power.resume().unwrap();
    assert!(d.borrow().elapsed >= D3_DELAY + 55_000);
    released(power);
    let (mut power, d) = owner(false);
    d.borrow_mut().readiness_us = READY_TIMEOUT + 2 * D3_DELAY;
    suspend(&mut power).unwrap();
    assert_eq!(power.resume(), Err(Error::NotReady));
    assert_eq!(d.borrow().elapsed, 2 * D3_DELAY + READY_TIMEOUT);
    assert_eq!(d.borrow().word(4) & 7, 0);
    assert_retained(power, &d);
}

#[test]
fn malformed_capability_bodies_versions_and_cycles_have_no_effects() {
    for case in 0..7 {
        let (function, timer, d) = fixture(true);
        {
            let mut d = d.borrow_mut();
            match case {
                0 => d.put_word(PM + 2, 4),
                1 => d.put_word(PM + 2, 0),
                2 => d.put_word(PM, 0x6001), // repeated header
                3 => d.put_word(PM, 0x6401), // next header in PMCSR body
                4 => {
                    d.bytes[0x34] = 0xfc;
                    d.put_word(0xfc, 1);
                }
                5 => {
                    d.bytes[0x34] = 0x40;
                    d.put_word(0x40, 0x6009);
                    d.bytes[0x42] = 0x28;
                }
                _ => d.put_word(PM, 0x7f),
            }
        }
        // SAFETY: read-only attach against the same isolated owner fixture.
        let result = unsafe { Power::attach(function, timer, Platform(d.clone()), D3_DELAY) };
        assert!(result.is_err(), "case {case}");
        drop(result);
        assert!(d.borrow().effects.is_empty());
        assert_eq!(d.borrow().config_drops, 1);
        assert_eq!(d.borrow().timer_drops, 1);
        assert_eq!(d.borrow().platform_drops, 1);
    }
}

#[test]
fn lost_clock_and_changed_identity_refuse_before_power_writes() {
    let (mut power, d) = owner(true);
    d.borrow_mut().clock_ok = false;
    assert_eq!(suspend(&mut power), Err(Error::Clock));
    assert_eq!(power.state(), State::D0);
    assert!(d.borrow().effects.is_empty());
    d.borrow_mut().clock_ok = true;
    d.borrow_mut().put_dword(0, ID ^ 1);
    assert_eq!(suspend(&mut power), Err(Error::Identity));
    assert_retained(power, &d);
    assert_eq!(
        crate::Clock {
            ticks_per_microsecond: 0
        }
        .check(),
        Err(Error::Clock)
    );
}

#[test]
fn native_pm_timer_uses_canonical_clock_checked_duration() {
    for rate in [0, u64::MAX, u64::MAX / 4 / READY_TIMEOUT + 1] {
        let clock = crate::Clock {
            ticks_per_microsecond: rate,
        };
        assert_eq!(clock.check(), Err(Error::Clock));
        assert_eq!(clock.wait_us(1), Err(Error::Clock));
    }
    let largest = crate::Clock {
        ticks_per_microsecond: u64::MAX / 4 / READY_TIMEOUT,
    };
    assert_eq!(largest.check(), Ok(()));
    let ordinary = crate::Clock {
        ticks_per_microsecond: 3_000,
    };
    assert_eq!(ordinary.wait_us(0), Ok(()));
    assert_eq!(ordinary.wait_us(u64::MAX), Err(Error::Clock));
}

#[test]
fn unwinding_original_function_access_keeps_its_owner_quarantined() {
    extern crate std;
    let (mut power, d) = owner(true);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: no extraction, resource change or concurrent consumer. The
        // test deliberately unwinds before the callback can return normally.
        let _ = unsafe { power.with_d0::<()>(|_| panic!("device callback failure")) };
    }));
    assert!(result.is_err());
    assert_eq!(power.state(), State::Unknown);
    assert_retained(power, &d);
}

#[test]
fn unfinished_d0_drop_does_not_revoke_original_platform_grants() {
    let (power, d) = owner(true);
    assert_retained(power, &d);
}

#[test]
fn owned_native_config_is_the_same_original_mapping_through_d0_release() {
    use crate::bus::pci::owned::tests::fixture;
    use core::sync::atomic::Ordering;
    let address = Address {
        segment: 0,
        bus: 0,
        device: 1,
        function: 0,
    };
    let (mut config, counters) = fixture(address);
    config.write32(0, ID);
    config.write32(8, 0x0200_0001);
    config.write16(6, 0x10);
    config.write8(0x34, PM as u8);
    config.write16(PM, 1);
    config.write16(PM + 2, 3);
    let function = Function::new(address, config).unwrap();
    let (_, timer, d) = super::tests::fixture(true);
    // SAFETY: owned native volatile-RAM mapping fixture, no physical power
    // effects. Only D0 accesses are tested; PMCSR hardware is modeled above.
    let mut power = unsafe { Power::attach(function, timer, Platform(d), D3_DELAY) }
        .unwrap_or_else(|_| panic!("valid original native owner"));
    // SAFETY: retain the actual function, change only native Command.
    unsafe { power.with_d0(|f| f.config().write16(4, INTX_DISABLE)) }.unwrap();
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 0);
    let (function, _, _) = power.release().unwrap_or_else(|_| panic!("verified D0"));
    let mut mapping = function.into_config().into_mapping();
    // SAFETY: every synchronous fixture consumer has stopped; no device/IRQ.
    unsafe { mapping.retire() }.unwrap();
    assert_eq!(counters.unmaps.load(Ordering::Relaxed), 1);
    assert_eq!(counters.resource_drops.load(Ordering::Relaxed), 1);
}

#[test]
#[ignore = "requires integrity-checked unchanged Linux PCI PM oracle trace"]
fn unchanged_linux_pm_functions_match_3072_source_cases() {
    extern crate std;
    let path = std::env::var("STELA_PCI_POWER_TRACE").expect("pinned PCI PM oracle trace path");
    let trace = std::fs::read_to_string(path).unwrap();
    let mut cases = 0;
    for line in trace.lines() {
        let fields: Vec<_> = line.split(',').collect();
        assert_eq!(fields.len(), 7);
        let number = |index: usize| fields[index].parse::<u16>().unwrap();
        let before = number(1);
        let raw = number(3);
        let after = number(4);
        let (mut power, d) = owner(before & NO_SOFT_RESET != 0);
        d.borrow_mut().put_word(CSR, before & !STATE);
        if before & STATE == 3 {
            suspend(&mut power).unwrap();
            assert_eq!(d.borrow().word(CSR), before);
            let mut d = d.borrow_mut();
            d.effects.clear();
            d.elapsed = 0;
        }
        match fields[0] {
            "pme" => {
                // SAFETY: fixture owns modeled device/wake route, no actors.
                unsafe {
                    power.configure_pme(
                        if before & STATE == 0 {
                            WakeState::D0
                        } else {
                            WakeState::D3hot
                        },
                        number(2) != 0,
                    )
                }
                .unwrap();
                assert_eq!(d.borrow().word(CSR), after);
                let Effect::Word(offset, written) = d.borrow().effects[0] else {
                    panic!("exact native word store");
                };
                assert_eq!(offset, CSR);
                // Native omits RO/reserved bits; all actual writable effects
                // and the complete resulting hardware image match Linux.
                let writable = STATE | PME_ENABLE | DATA_SELECT | PME_STATUS;
                assert_eq!(written & writable, raw & writable);
                assert_eq!(number(5), 0);
                assert_eq!(number(6), 0);
            }
            "low" => {
                suspend(&mut power).unwrap();
                let d = d.borrow();
                // Linux's ordinary low-power RMW replays PME_Status. The
                // native transition deliberately preserves a pending event.
                assert_eq!(d.word(CSR), after | (before & PME_STATUS));
                let Effect::Word(offset, written) = d.effects[1] else {
                    panic!("native PMCSR store after decoding containment");
                };
                assert_eq!(offset, CSR);
                let rw = STATE | PME_ENABLE | DATA_SELECT;
                assert_eq!(written & rw, raw & rw);
                assert_eq!(written & PME_STATUS, 0);
                assert_eq!(raw & PME_STATUS, before & PME_STATUS);
                assert_eq!(d.elapsed, u64::from(number(5)));
                assert_eq!(number(6), 0);
            }
            "up" => {
                power.resume().unwrap();
                let d = d.borrow();
                assert_eq!(d.word(CSR), after);
                assert_eq!(d.effects[0], Effect::Word(CSR, raw));
                assert_eq!(raw, 0, "whole-word zero preserves pending status");
                assert_eq!(d.elapsed, u64::from(number(5)));
                assert_eq!(number(6), u16::from(before & NO_SOFT_RESET == 0));
                assert_eq!(
                    d.effects
                        .iter()
                        .filter(|effect| matches!(effect, Effect::Dword(..)))
                        .count(),
                    if number(6) == 1 { 7 } else { 0 },
                );
            }
            _ => panic!("unexpected source operation"),
        }
        if power.state() == State::D3hot {
            power.resume().unwrap();
        }
        released(power);
        cases += 1;
    }
    assert_eq!(cases, 3072);
}
