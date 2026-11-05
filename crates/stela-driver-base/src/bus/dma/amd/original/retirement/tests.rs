extern crate std;
use super::*;
use alloc::{
    sync::{Arc, Weak},
    vec,
};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::{
    collections::BTreeMap,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Mutex,
};

#[derive(Default)]
struct Counts {
    frames: AtomicUsize,
    queue: AtomicUsize,
}
struct Frames {
    cpu: Mutex<BTreeMap<u64, u64>>,
    device: Mutex<BTreeMap<u64, u64>>,
    counts: Arc<Counts>,
}
impl Drop for Frames {
    fn drop(&mut self) {
        self.counts.frames.fetch_add(1, Ordering::Relaxed);
    }
}
struct Buffers {
    cpu: Mutex<BTreeMap<usize, Command>>,
    device: Mutex<BTreeMap<usize, Command>>,
    completion: AtomicU64,
    counts: Arc<Counts>,
}
impl Drop for Buffers {
    fn drop(&mut self) {
        self.counts.queue.fetch_add(1, Ordering::Relaxed);
    }
}
struct Hardware {
    registers: BTreeMap<usize, u64>,
    frames: Weak<Frames>,
    queue: Weak<Buffers>,
    upstream: Vec<(u64, u32)>,
    translated: Vec<(u64, u32)>,
    master: bool,
    effects: Vec<&'static str>,
    ticks: u64,
    withhold_store: bool,
    future_store: bool,
    panic_effect: bool,
    context_bad: bool,
    fail_data: bool,
    withhold_sequence: Option<u64>,
}
struct R {
    hardware: Arc<Mutex<Hardware>>,
    entered: AtomicBool,
}
struct Access<'a>(&'a AtomicBool);
impl Drop for Access<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
// SAFETY: one real synchronous model unit/root owner, checked affine guard;
// hardware effects access actual retained frame/buffer objects via Weak only.
unsafe impl Registers for R {
    type Access<'a> = Access<'a>;
    fn enter(&self) -> Result<Access<'_>, Error> {
        if self.hardware.lock().unwrap().context_bad {
            return Err(Error::Context);
        }
        self.entered
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::Context)?;
        Ok(Access(&self.entered))
    }
    fn read(&self, at: usize) -> Result<u64, Error> {
        Ok(*self
            .hardware
            .lock()
            .unwrap()
            .registers
            .get(&at)
            .unwrap_or(&0))
    }
    unsafe fn write(&self, at: usize, value: u64) -> Result<(), Error> {
        let mut h = self.hardware.lock().unwrap();
        assert_ne!(
            at, 0,
            "must ADOPT original DeviceTableBase, never replace it"
        );
        if h.panic_effect {
            h.panic_effect = false;
            drop(h);
            panic!("hardware write unwind");
        }
        h.effects.push(match at {
            8 => "new_queue",
            24 => "command_enable",
            0x2008 => "tail",
            _ => "head",
        });
        if at == 24 {
            assert_ne!(
                value & IOMMU,
                0,
                "data handoff cannot disable IRQ interpretation"
            );
            h.registers.insert(0x2020, COMMAND_RUN);
        }
        h.registers.insert(at, value);
        if at == 0x2008 && value != 0 {
            let q = h
                .queue
                .upgrade()
                .expect("actual queue backing must remain owned");
            let frames = h
                .frames
                .upgrade()
                .expect("actual original root backing must remain owned");
            let offset = *h.registers.get(&0x2000).unwrap() as usize;
            let commands = q.device.lock().unwrap();
            for slot in (offset..value as usize).step_by(16) {
                let command = commands.get(&slot).expect("actual DMA-published command");
                let bytes = command.bytes();
                let words: Vec<u32> = bytes
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|b| u32::from_le_bytes(*b))
                    .collect();
                match words[1] >> 28 {
                    8 => {
                        h.effects.push("matched_payload_fence");
                        let writes = core::mem::take(&mut h.translated);
                        for (pa, value) in writes {
                            frames.cpu.lock().unwrap().insert(pa, u64::from(value));
                        }
                    }
                    1 => {
                        let sequence = u64::from(words[2]) | (u64::from(words[3]) << 32);
                        if !h.withhold_store && h.withhold_sequence != Some(sequence) {
                            q.completion
                                .store(sequence + u64::from(h.future_store), Ordering::Release);
                            h.effects.push("completion_store");
                        }
                    }
                    _ => panic!("unsupported model command"),
                }
            }
            // Head is fetch progress even if a completion store is delayed.
            h.registers.insert(0x2000, value);
        }
        Ok(())
    }
    fn ticks(&self) -> u64 {
        let mut h = self.hardware.lock().unwrap();
        h.ticks += 1;
        h.ticks
    }
    fn timeout_ticks(&self) -> u64 {
        8
    }
}
struct Q {
    buffers: Arc<Buffers>,
    base: u64,
}
// SAFETY: actual isolated fresh owned model buffers, published coherently,
// not a descriptor-only address; hardware has only Weak references.
unsafe impl Queue for Q {
    fn command_base(&self) -> u64 {
        self.base
    }
    fn command_bytes(&self) -> usize {
        4096
    }
    fn completion_base(&self) -> u64 {
        self.base + 4096
    }
    fn completion_bytes(&self) -> usize {
        4096
    }
    fn initialize(&self) -> Result<(), Error> {
        self.buffers.completion.store(0, Ordering::Release);
        Ok(())
    }
    fn command(&self, offset: usize, command: Command) -> Result<(), Error> {
        self.buffers.cpu.lock().unwrap().insert(offset, command);
        Ok(())
    }
    fn publish(&self) -> Result<(), Error> {
        *self.buffers.device.lock().unwrap() = self.buffers.cpu.lock().unwrap().clone();
        Ok(())
    }
    fn completion(&self) -> Result<u64, Error> {
        Ok(self.buffers.completion.load(Ordering::Acquire))
    }
}
struct M {
    frames: Arc<Frames>,
    hardware: Arc<Mutex<Hardware>>,
    base: u64,
}
// SAFETY: exact owned frame objects, no firmware/hardware writer; actual OS
// transfer in this model owns1000h..4FFFh, not the separate fresh queue buffers.
unsafe impl tables::Memory for M {
    fn contains(&self, p: u64, n: u64) -> bool {
        p >= self.base + 0x1000 && p.checked_add(n).is_some_and(|e| e <= self.base + 0x5000)
    }
    fn owns_os_ram(&self, p: u64, n: u64) -> bool {
        self.contains(p, n)
    }
    fn read(&self, p: u64) -> Result<u64, tables::Error> {
        Ok(*self.frames.cpu.lock().unwrap().get(&p).unwrap_or(&0))
    }
}
// SAFETY: real serialized pair compare/store model; IRQ half is never written.
// CPU publication explicitly reaches the hardware model's visible word map.
unsafe impl Memory for M {
    fn replace_data(&self, at: u64, old: [u64; 2], new: [u64; 2]) -> Result<(), Error> {
        if self.hardware.lock().unwrap().fail_data {
            return Err(Error::Epoch);
        }
        let mut words = self.frames.cpu.lock().unwrap();
        if [
            *words.get(&at).unwrap_or(&0),
            *words.get(&(at + 8)).unwrap_or(&0),
        ] != old
        {
            return Err(Error::Epoch);
        }
        words.insert(at, new[0]);
        words.insert(at + 8, new[1]);
        self.hardware.lock().unwrap().effects.push("data_half_only");
        Ok(())
    }
    fn publish_data(&self) -> Result<(), Error> {
        *self.frames.device.lock().unwrap() = self.frames.cpu.lock().unwrap().clone();
        Ok(())
    }
}
struct Observation {
    hardware: Arc<Mutex<Hardware>>,
    frames: Weak<Frames>,
    queue: Weak<Buffers>,
    counts: Arc<Counts>,
}
struct Function {
    hardware: Arc<Mutex<Hardware>>,
}
impl Function {
    fn contain_and_read(&mut self) {
        let mut h = self.hardware.lock().unwrap();
        assert!(h.master);
        // Packet issued immediately before actual BME containment.
        h.upstream.push((0, 0xfeed_beef));
        h.master = false;
        h.effects.push("bme_clear");
        let frames = h.frames.upgrade().unwrap();
        let d = frames.device.lock().unwrap();
        for (iova, value) in core::mem::take(&mut h.upstream) {
            let low = d[&((h.registers[&0] & ADDRESS) + 8 * 32)];
            assert_eq!(low & 3, 3);
            let root = low & ADDRESS;
            let leaf = d[&(d[&root] & ADDRESS)];
            h.translated.push(((leaf & ADDRESS) + iova, value));
        }
        h.effects.push("ordinary_read_push");
    }
}
fn fixture() -> (Input<R, Q, M>, Function, Observation) {
    fixture_at(0)
}
fn fixture_at(delta: u64) -> (Input<R, Q, M>, Function, Observation) {
    let counts = Arc::new(Counts::default());
    let mut words = BTreeMap::new();
    for rid in 0..128u64 {
        words.insert(delta + 0x1000 + rid * 32, 1);
    }
    let irq = 1 | (1 << 60) | (1 << 58);
    words.extend([
        (
            delta + 0x1000 + 8 * 32,
            1 | 2 | (2 << 9) | (1 << 61) | (1 << 62) | (delta + 0x2000),
        ),
        (delta + 0x1000 + 8 * 32 + 8, 1),
        (delta + 0x1000 + 8 * 32 + 16, irq),
        (
            delta + 0x2000,
            1 | (1 << 9) | (1 << 61) | (1 << 62) | (delta + 0x3000),
        ),
        (delta + 0x3000, 1 | (1 << 61) | (1 << 62) | (delta + 0x4000)),
    ]);
    let frames = Arc::new(Frames {
        cpu: Mutex::new(words.clone()),
        device: Mutex::new(words),
        counts: counts.clone(),
    });
    let queue = Arc::new(Buffers {
        cpu: Mutex::new(BTreeMap::new()),
        device: Mutex::new(BTreeMap::new()),
        completion: AtomicU64::new(0),
        counts: counts.clone(),
    });
    let h = Arc::new(Mutex::new(Hardware {
        registers: BTreeMap::from([
            (0, delta + 0x1000),
            (24, IOMMU | COHERENT),
            (0x30, 1 << 6),
            (0x2000, 0),
            (0x2008, 0),
            (0x2020, 0),
        ]),
        frames: Arc::downgrade(&frames),
        queue: Arc::downgrade(&queue),
        upstream: vec![],
        translated: vec![],
        master: true,
        effects: vec![],
        ticks: 0,
        withhold_store: false,
        future_store: false,
        panic_effect: false,
        context_bad: false,
        fail_data: false,
        withhold_sequence: None,
    }));
    let input = Input {
        registers: R {
            hardware: h.clone(),
            entered: AtomicBool::new(false),
        },
        queue: Q {
            buffers: queue.clone(),
            base: delta + 0x10000,
        },
        memory: M {
            frames: frames.clone(),
            hardware: h.clone(),
            base: delta,
        },
        sources: vec![8],
        physical_bits: 48,
        maximum_levels: 4,
    };
    (
        input,
        Function {
            hardware: h.clone(),
        },
        Observation {
            hardware: h,
            frames: Arc::downgrade(&frames),
            queue: Arc::downgrade(&queue),
            counts,
        },
    )
}
fn preflight(input: Input<R, Q, M>) -> Plan<R, Q, M> {
    // SAFETY: complete actual bounded unit/source/allocation model, one owner.
    unsafe { Plan::preflight(vec![input]) }.ok().unwrap()
}
#[test]
fn actual_old_payload_and_same_root_irq_policy_survive_real_two_fence_adoption() {
    let (input, mut function, o) = fixture();
    let p = preflight(input);
    function.contain_and_read();
    // SAFETY: same actual contained source owner and its ordinary read push.
    let retired = unsafe { p.retire_after_containment() }.ok().unwrap();
    let f = o.frames.upgrade().unwrap();
    let words = f.cpu.lock().unwrap();
    assert_eq!(words[&0x4000], 0xfeed_beef);
    assert_eq!(words[&(0x1000 + 8 * 32)], 1);
    assert_eq!(words[&(0x1000 + 8 * 32 + 16)], 1 | (1 << 60) | (1 << 58));
    drop(words);
    drop(f);
    let h = o.hardware.lock().unwrap();
    assert_eq!(h.registers[&0], 0x1000);
    assert_ne!(h.registers[&24] & IOMMU, 0);
    assert_eq!(
        h.effects
            .iter()
            .filter(|e| **e == "completion_store")
            .count(),
        2
    );
    drop(h);
    drop(retired.into_adopted());
    assert!(o.frames.upgrade().is_some() && o.queue.upgrade().is_some());
    assert_eq!(o.counts.frames.load(Ordering::Relaxed), 0);
    assert_eq!(o.counts.queue.load(Ordering::Relaxed), 0);
}
#[test]
fn fetched_head_without_exact_completion_and_future_store_never_grant_adoption() {
    for future in [false, true] {
        let (input, mut function, o) = fixture();
        let p = preflight(input);
        function.contain_and_read();
        {
            let mut h = o.hardware.lock().unwrap();
            h.withhold_store = !future;
            h.future_store = future;
        }
        // SAFETY: same real source containment and read push; force bad hardware completion.
        let result = unsafe { p.retire_after_containment() };
        assert!(matches!(
            result,
            Err(Failure {
                error: Error::Timeout | Error::Queue,
                ..
            })
        ));
        drop(result);
        assert!(o.frames.upgrade().is_some() && o.queue.upgrade().is_some());
        assert!(
            !o.hardware
                .lock()
                .unwrap()
                .effects
                .contains(&"data_half_only")
        );
    }
}
#[test]
fn unsupported_active_old_queue_and_late_root_change_fail_before_new_queue_effects() {
    let (input, _function, o) = fixture();
    o.hardware
        .lock()
        .unwrap()
        .registers
        .insert(24, IOMMU | COHERENT | COMMAND);
    // SAFETY: complete actual model, deliberately unsupported active original queue.
    assert!(unsafe { Plan::preflight(vec![input]) }.is_err());
    assert!(o.hardware.lock().unwrap().effects.is_empty());
    assert!(o.frames.upgrade().is_some());
    let (input, mut function, o) = fixture();
    let p = preflight(input);
    function.contain_and_read();
    o.hardware.lock().unwrap().registers.insert(0, 0x2000);
    // SAFETY: actual contained source, but original unit changed and must refuse.
    let result = unsafe { p.retire_after_containment() };
    assert!(matches!(
        result,
        Err(Failure {
            error: Error::Epoch,
            ..
        })
    ));
    assert!(!o.hardware.lock().unwrap().effects.contains(&"new_queue"));
}
#[test]
fn hardware_effect_unwind_keeps_actual_not_just_numeric_backing() {
    let (input, mut function, o) = fixture();
    let p = preflight(input);
    function.contain_and_read();
    o.hardware.lock().unwrap().panic_effect = true;
    // SAFETY: same actual source proof, with modeled hardware callback unwind.
    assert!(catch_unwind(AssertUnwindSafe(|| unsafe { p.retire_after_containment() })).is_err());
    assert!(o.frames.upgrade().is_some() && o.queue.upgrade().is_some());
    assert_eq!(o.counts.frames.load(Ordering::Relaxed), 0);
    assert_eq!(o.counts.queue.load(Ordering::Relaxed), 0);
}

#[test]
fn second_unit_fence_failure_keeps_both_original_roots_and_actual_backings() {
    let (a, mut fa, oa) = fixture_at(0);
    let (b, mut fb, ob) = fixture_at(0x20000);
    // SAFETY: complete two-unit actual model cohort, disjoint owned backing.
    let p = unsafe { Plan::preflight(vec![a, b]) }.ok().unwrap();
    fa.contain_and_read();
    fb.contain_and_read();
    ob.hardware.lock().unwrap().withhold_store = true;
    // SAFETY: both actual source prefix operations completed, seals stay held.
    let result = unsafe { p.retire_after_containment() };
    assert!(matches!(
        result,
        Err(Failure {
            error: Error::Timeout,
            ..
        })
    ));
    drop(result);
    for (o, base) in [(&oa, 0x1000), (&ob, 0x21000)] {
        assert!(o.frames.upgrade().is_some() && o.queue.upgrade().is_some());
        let h = o.hardware.lock().unwrap();
        assert_eq!(h.registers[&0], base);
        assert_ne!(h.registers[&24] & IOMMU, 0);
        assert!(!h.effects.contains(&"data_half_only"));
    }
    assert_eq!(
        oa.frames.upgrade().unwrap().cpu.lock().unwrap()[&0x4000],
        0xfeed_beef
    );
}

#[test]
fn failed_second_fence_or_atomic_store_never_releases_active_table_or_irq_half() {
    for atomic_failure in [false, true] {
        let (input, mut function, o) = fixture();
        let p = preflight(input);
        function.contain_and_read();
        {
            let mut h = o.hardware.lock().unwrap();
            h.fail_data = atomic_failure;
            if !atomic_failure {
                h.withhold_sequence = Some(2);
            }
        }
        // SAFETY: same actual contained cohort; inject post-first-fence failure.
        let result = unsafe { p.retire_after_containment() };
        assert!(matches!(
            result,
            Err(Failure {
                error: Error::Epoch | Error::Timeout,
                ..
            })
        ));
        drop(result);
        let f = o.frames.upgrade().unwrap();
        let words = f.cpu.lock().unwrap();
        assert_eq!(words[&(0x1000 + 8 * 32 + 16)], 1 | (1 << 60) | (1 << 58));
        assert_eq!(words[&0x4000], 0xfeed_beef);
        drop(words);
        drop(f);
        assert!(o.queue.upgrade().is_some());
        assert_eq!(o.counts.frames.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn shared_mutable_original_table_and_lost_context_refuse_before_control_effects() {
    let (a, _fa, oa) = fixture();
    let (b, _fb, ob) = fixture();
    // SAFETY: adversarial duplicate candidate roots must be refused; no effects permitted.
    let result = unsafe { Plan::preflight(vec![a, b]) };
    assert!(matches!(
        result,
        Err(Failure {
            error: Error::SharedDeviceTable,
            ..
        })
    ));
    drop(result);
    assert!(oa.hardware.lock().unwrap().effects.is_empty());
    assert!(ob.hardware.lock().unwrap().effects.is_empty());
    let (input, mut function, o) = fixture();
    let p = preflight(input);
    function.contain_and_read();
    o.hardware.lock().unwrap().context_bad = true;
    // SAFETY: actual source proof persists; original execution context was lost.
    let result = unsafe { p.retire_after_containment() };
    assert!(matches!(
        result,
        Err(Failure {
            error: Error::Context,
            ..
        })
    ));
    drop(result);
    assert!(!o.hardware.lock().unwrap().effects.contains(&"new_queue"));
    assert!(o.frames.upgrade().is_some() && o.queue.upgrade().is_some());
}

#[test]
fn implemented_reset_log_lengths_are_not_nonzero_ram_pointers_or_msi_register_reads() {
    let (input, mut function, o) = fixture();
    {
        let mut h = o.hardware.lock().unwrap();
        h.registers
            .insert(0x30, (1 << 6) | (1 << 1) | (1 << 7) | (1 << 24) | (1 << 28));
        for offset in [0x38, 0xe0, 0xf0, 0xf8] {
            h.registers.insert(offset, 8 << 56);
        }
        // MSI MMIO header normally has read-only bits set. It is NOT a log.
        h.registers.insert(0x150, u64::MAX);
        h.registers.insert(0x158, u64::MAX);
    }
    let p = preflight(input);
    function.contain_and_read();
    // SAFETY: complete actual source model, only implemented reset aux fields.
    assert!(unsafe { p.retire_after_containment() }.is_ok());
}
