//! The board's devices shared by the PE threads: the locked board and its
//! device-bus calls.

use super::super::LocalRegisters;
use super::*;

pub(super) struct Board<D> {
    pub(super) devices: Mutex<D>,
    pub(super) hub: Arc<Hub>,
    /// Calls that found the devices' lock held, by [`Call`].
    pub(super) waits: [AtomicU64; Call::ALL.len()],
    /// The latest count any machine passed, which every later call sees at
    /// least: the PEs' counters agree only to within their reads.
    pub(super) now: AtomicU64,
    /// Each PE's device lines as last seen.
    pub(super) lines: Mutex<Vec<Lines>>,
    /// Each PE's latched pins as every call left them ([`pack`]), which
    /// another PE's machine reads without the lock: only the home machine
    /// advances the devices with time.
    pub(super) pins: Box<[AtomicU8]>,
    /// The devices' DMA deadline (`u64::MAX`: none) and a reset they
    /// requested, as each call left them: the home machine asks at every
    /// step, without the lock.
    pub(super) dma: AtomicU64,
    pub(super) reset: Mutex<Option<Reset>>,
    pub(super) resetting: AtomicBool,
    /// PE starts the devices made, which every machine asks for at every
    /// wait, without the lock; `starting` changes only under `starts`.
    pub(super) starts: Mutex<VecDeque<Start>>,
    pub(super) starting: AtomicBool,
    /// The SoC sleeps until the host's power button
    /// ([`Devices::waits_on_host`]).
    pub(super) asleep: AtomicBool,
    /// The IMPLEMENTATION DEFINED registers (op0 3, CRn 15) the devices
    /// serve, by op1, CRm and op2 ([`register_bit`]): a PE's machine asks
    /// for every one it reaches, and the others take no lock.
    pub(super) registers: [u64; 16],
}

/// Pins as [`Board::pins`] holds them: IRQ and FIQ, or [`UNLATCHED`] for
/// devices whose lines need an advance to read.
pub(super) fn pack(pins: Option<Lines>) -> u8 {
    pins.map_or(UNLATCHED, |lines| {
        u8::from(lines.irq) | u8::from(lines.fiq) << 1
    })
}

pub(super) const UNLATCHED: u8 = u8::MAX;

pub(super) fn unpack(pins: u8) -> Option<Lines> {
    (pins != UNLATCHED).then_some(Lines {
        irq: pins & 1 != 0,
        fiq: pins & 2 != 0,
    })
}

/// The bit of `registers` for an IMPLEMENTATION DEFINED encoding.
pub(super) fn register_bit(encoding: Encoding) -> Option<usize> {
    (encoding.op0() == 3 && encoding.crn() == 15).then(|| {
        usize::from(encoding.op1()) << 7
            | usize::from(encoding.crm()) << 3
            | usize::from(encoding.op2())
    })
}

impl<D: Devices> Board<D> {
    pub(super) fn lock(&self, call: Call) -> Held<'_, D> {
        let devices = match self.devices.try_lock() {
            Ok(devices) => devices,
            Err(_) => {
                self.waits[call as usize].fetch_add(1, Ordering::Relaxed);
                self.devices.lock().unwrap_or_else(|e| e.into_inner())
            }
        };
        Held {
            board: self,
            devices,
        }
    }

    /// Record what the machines ask of `devices` at every step: the home
    /// machine its resets, DMA and host inputs, and any its starts and the
    /// host's service. Every call's release runs it, so it writes only what
    /// changed: the machines read these without the lock, and an unchanged
    /// store would still take each one's cache line from every reader.
    pub(super) fn publish(&self, devices: &mut D) {
        if let Some(reset) = devices.take_reset() {
            self.reset
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_or_insert(reset);
            self.resetting.store(true, Ordering::Release);
        }
        if let Some(start) = devices.take_start() {
            let mut starts = self.starts.lock().unwrap_or_else(|e| e.into_inner());
            starts.push_back(start);
            starts.extend(core::iter::from_fn(|| devices.take_start()));
            self.starting.store(true, Ordering::Release);
        }
        // A deadline earlier than the last, such as a host transfer that
        // completed on another core, wakes the home machine if it sleeps.
        let dma = devices.dma_deadline().unwrap_or(u64::MAX);
        let published = self.dma.load(Ordering::Acquire);
        if published != dma {
            self.dma.store(dma, Ordering::Release);
            if published > dma {
                self.hub.wake(self.hub.home.load(Ordering::Acquire));
            }
        }
        for pe in 0..self.pins.len() {
            self.publish_pins(pe, devices.pins(pe));
        }
        let asleep = devices.waits_on_host();
        if self.asleep.load(Ordering::Relaxed) != asleep {
            self.asleep.store(asleep, Ordering::Release);
        }
        if devices.take_host_service() {
            self.hub.request_service();
        }
    }

    /// Publish the snapshot a remote PE reads without the devices' lock.
    pub(super) fn publish_pins(&self, pe: usize, lines: Option<Lines>) {
        let pins = &self.pins[pe];
        let packed = pack(lines);
        if pins.load(Ordering::Relaxed) != packed {
            pins.store(packed, Ordering::Release);
        }
    }

    /// The oldest start [`Self::publish`] kept.
    pub(super) fn take_start(&self) -> Option<Start> {
        if !self.starting.load(Ordering::Acquire) {
            return None;
        }
        let mut starts = self.starts.lock().unwrap_or_else(|e| e.into_inner());
        let start = starts.pop_front();
        self.starting.store(!starts.is_empty(), Ordering::Release);
        start
    }
}

/// The devices while a call holds their lock; its release publishes what
/// the call left for the home machine ([`Board::publish`]).
pub(super) struct Held<'a, D: Devices> {
    pub(super) board: &'a Board<D>,
    pub(super) devices: crate::platform::sync::MutexGuard<'a, D>,
}

impl<D: Devices> core::ops::Deref for Held<'_, D> {
    type Target = D;
    fn deref(&self) -> &D {
        &self.devices
    }
}

impl<D: Devices> core::ops::DerefMut for Held<'_, D> {
    fn deref_mut(&mut self) -> &mut D {
        &mut self.devices
    }
}

impl<D: Devices> Drop for Held<'_, D> {
    fn drop(&mut self) {
        self.board.publish(&mut self.devices);
    }
}

// SAFETY: the devices are reached only under `devices`' lock, so state they
// share through `Rc` or `RefCell` is never touched by two cores at once, and
// no reference into them outlives the guard.
unsafe impl<D> Send for Board<D> {}
// SAFETY: shared references rely on the same argument as `Send` above.
unsafe impl<D> Sync for Board<D> {}

/// The board's devices, shared by every PE's machine.
pub struct SharedDevices<D> {
    pub(super) board: Arc<Board<D>>,
    /// The machine that serves resets and DMA.
    pub(super) home: bool,
    /// Each PE's [`Devices::local_registers`], once asked for.
    local: Vec<Option<Option<Arc<dyn LocalRegisters>>>>,
}

impl<D: Devices> SharedDevices<D> {
    /// The home machine's handle.
    pub fn new(devices: D, hub: Arc<Hub>) -> Self {
        let pes = hub.pes();
        let mut registers = [0u64; 16];
        for bit in 0..1 << 10 {
            let (op1, crm, op2) = ((bit >> 7) as u8, (bit >> 3 & 15) as u8, (bit & 7) as u8);
            if devices.serves_register(Encoding::new(3, op1, 15, crm, op2)) {
                registers[bit / 64] |= 1 << (bit % 64);
            }
        }
        let board = Board {
            devices: Mutex::new(devices),
            hub,
            waits: Default::default(),
            now: AtomicU64::new(0),
            lines: Mutex::new(alloc::vec![Lines::default(); pes]),
            pins: (0..pes).map(|_| AtomicU8::new(UNLATCHED)).collect(),
            dma: AtomicU64::new(u64::MAX),
            reset: Mutex::new(None),
            resetting: AtomicBool::new(false),
            starts: Mutex::new(VecDeque::new()),
            starting: AtomicBool::new(false),
            asleep: AtomicBool::new(false),
            registers,
        };
        drop(board.lock(Call::Other));
        Self {
            board: Arc::new(board),
            home: true,
            local: Vec::new(),
        }
    }

    /// A handle for another PE's machine.
    pub fn worker(&self) -> Self {
        Self {
            board: Arc::clone(&self.board),
            home: false,
            local: Vec::new(),
        }
    }

    pub fn hub(&self) -> &Arc<Hub> {
        &self.board.hub
    }

    /// Run `f` on the devices while no PE reaches them.
    pub fn with<R>(&self, f: impl FnOnce(&mut D) -> R) -> R {
        self.call(Call::Other, f)
    }

    pub(super) fn call<R>(&self, call: Call, f: impl FnOnce(&mut D) -> R) -> R {
        f(&mut self.board.lock(call))
    }

    /// Calls that found the devices' lock held since the board was made, by
    /// [`Call`].
    pub fn waits(&self) -> [u64; Call::ALL.len()] {
        self.board
            .waits
            .each_ref()
            .map(|waits| waits.load(Ordering::Relaxed))
    }

    /// Serve the host's inputs with `f`, which can change any PE's lines.
    pub fn serve<R>(&self, f: impl FnOnce(&mut D) -> R) -> R {
        let now = self.board.now.load(Ordering::Acquire);
        self.changing(Call::Home, usize::MAX, now, |devices, _| f(devices))
    }

    /// The count the devices see for a call at `now`, which no earlier
    /// call's passes. Taken under the devices' lock, so calls see counts in
    /// the order they reach the devices.
    pub(super) fn now(&self, now: u64) -> u64 {
        self.board.now.fetch_max(now, Ordering::AcqRel).max(now)
    }

    /// Run `f` on the devices at `now`, as [`Self::now`] gives it.
    pub(super) fn at<R>(&self, call: Call, now: u64, f: impl FnOnce(&mut D, u64) -> R) -> R {
        let mut devices = self.board.lock(call);
        let now = self.now(now);
        f(&mut devices, now)
    }

    /// PE `cpu`'s own register, without the devices' lock once it has its
    /// handle.
    fn local_register(
        &mut self,
        cpu: usize,
        encoding: Encoding,
        write: Option<u64>,
    ) -> Option<u64> {
        if self.local.len() <= cpu {
            self.local.resize_with(cpu + 1, || None);
        }
        if self.local[cpu].is_none() {
            self.local[cpu] = Some(self.with(|devices| devices.local_registers(cpu)));
        }
        self.local[cpu]
            .as_ref()?
            .as_ref()?
            .register(encoding, write)
    }

    /// A call that can change devices: run it, then tell every other PE
    /// whose lines it changed.
    pub(super) fn changing<R>(
        &self,
        call: Call,
        cpu: usize,
        now: u64,
        f: impl FnOnce(&mut D, u64) -> R,
    ) -> R {
        let mut devices = self.board.lock(call);
        let now = self.now(now);
        let result = f(&mut devices, now);
        self.notify(&mut devices, cpu, now);
        result
    }

    /// Tell every PE but `cpu` whose lines changed since it last saw them.
    /// Every change reaches the devices under their lock, so a PE learns of
    /// each from the call that made it, and needs no device deadline of its
    /// own: only the home machine advances the devices with time.
    pub(super) fn notify(&self, devices: &mut D, cpu: usize, now: u64) {
        let mut seen = self.board.lines.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(own) = seen.get_mut(cpu)
            && let Some(lines) = devices.pins(cpu)
        {
            // The caller reads its own lines after the call.
            *own = lines;
        }
        for pe in self.board.hub.others(cpu) {
            let pins = devices.pins(pe);
            let lines = match pins {
                Some(lines) => lines,
                None => devices.lines(pe, now),
            };
            // The receiver may read its pins as soon as the epoch changes,
            // before this call releases the devices' lock.
            self.board.publish_pins(pe, pins);
            if lines != seen[pe] {
                seen[pe] = lines;
                self.board.hub.lines_changed(pe);
            }
        }
    }
}

impl<D: Devices> Devices for SharedDevices<D> {
    fn pc_sample_target(&self, physical: u64, bytes: u8) -> Option<usize> {
        self.with(|devices| devices.pc_sample_target(physical, bytes))
    }
    fn observe_pc_sample(&mut self, physical: u64, pc: u64) {
        self.with(|devices| devices.observe_pc_sample(physical, pc));
    }
    fn read(&mut self, cpu: usize, physical: u64, bytes: u8, now: u64) -> Result<u64, DeviceError> {
        self.changing(Call::Access, cpu, now, |devices, now| {
            devices.read(cpu, physical, bytes, now)
        })
    }
    fn read_scalar(&mut self, cpu: usize, physical: u64, bytes: u8, now: u64) -> ScalarRead {
        self.changing(Call::Access, cpu, now, |devices, now| {
            devices.read_scalar(cpu, physical, bytes, now)
        })
    }
    fn requires_canonical_read(&self, cpu: usize, physical: u64, shape: DeviceReadShape) -> bool {
        self.with(|devices| devices.requires_canonical_read(cpu, physical, shape))
    }
    fn requires_canonical_write(&self, cpu: usize, physical: u64, bytes: u8) -> bool {
        self.with(|devices| devices.requires_canonical_write(cpu, physical, bytes))
    }
    fn read_canonical(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        now: u64,
        memory: &mut dyn CanonicalDeviceMemory,
    ) -> Result<ConsumedScalar, DeviceError> {
        self.changing(Call::Access, cpu, now, |devices, now| {
            devices.read_canonical(cpu, physical, bytes, now, memory)
        })
    }
    fn read_pair_canonical(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        now: u64,
        memory: &mut dyn CanonicalDeviceMemory,
    ) -> Result<ConsumedPair, DeviceError> {
        self.changing(Call::Access, cpu, now, |devices, now| {
            devices.read_pair_canonical(cpu, physical, bytes, now, memory)
        })
    }
    fn write_canonical(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        value: u64,
        now: u64,
        owners: &mut dyn CanonicalDeviceWrite,
    ) -> Result<ConsumedWrite, DeviceError> {
        self.changing(Call::Access, cpu, now, |devices, now| {
            devices.write_canonical(cpu, physical, bytes, value, now, owners)
        })
    }
    fn write_pair_canonical(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        values: [u64; 2],
        now: u64,
        owners: &mut dyn CanonicalDeviceWrite,
    ) -> Result<ConsumedWrite, DeviceError> {
        self.changing(Call::Access, cpu, now, |devices, now| {
            devices.write_pair_canonical(cpu, physical, bytes, values, now, owners)
        })
    }
    fn read_pair(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        now: u64,
    ) -> Result<Option<ConsumedPair>, DeviceError> {
        self.changing(Call::Access, cpu, now, |devices, now| {
            devices.read_pair(cpu, physical, bytes, now)
        })
    }
    fn write(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        value: u64,
        now: u64,
    ) -> Result<(), DeviceError> {
        self.changing(Call::Access, cpu, now, |devices, now| {
            devices.write(cpu, physical, bytes, value, now)
        })
    }
    fn write_with_processors(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        value: u64,
        now: u64,
        processors: super::super::ProcessorWrite<'_>,
    ) -> Result<(), DeviceError> {
        self.changing(Call::Access, cpu, now, |devices, now| {
            devices.write_with_processors(cpu, physical, bytes, value, now, processors)
        })
    }
    fn write_plain(
        &mut self,
        cpu: usize,
        physical: u64,
        bytes: u8,
        value: u64,
        now: u64,
        processors: super::super::ProcessorWrite<'_>,
    ) -> Option<Result<(), DeviceError>> {
        self.changing(Call::Access, cpu, now, |devices, now| {
            devices.write_plain(cpu, physical, bytes, value, now, processors)
        })
    }
    /// The home machine's asking advances the devices to `now`, which can
    /// change any PE's lines; another PE's machine reads its latched pins.
    fn lines(&mut self, cpu: usize, now: u64) -> Lines {
        if !self.home
            && let Some(lines) = self.pins(cpu)
        {
            return lines;
        }
        let mut devices = self.board.lock(Call::Lines);
        let now = self.now(now);
        let lines = devices.lines(cpu, now);
        self.board.lines.lock().unwrap_or_else(|e| e.into_inner())[cpu] = lines;
        self.notify(&mut devices, cpu, now);
        lines
    }
    fn pins(&mut self, cpu: usize) -> Option<Lines> {
        unpack(self.board.pins.get(cpu)?.load(Ordering::Acquire))
    }
    /// The home machine advances the devices with time and tells the other
    /// PEs what that changes ([`Self::notify`]); their machines wait for
    /// those changes instead.
    fn deadline(&mut self, now: u64) -> Option<u64> {
        if !self.home {
            return None;
        }
        self.changing(Call::Deadline, usize::MAX, now, |devices, now| {
            devices.deadline(now)
        })
    }
    /// The home machine's [`Self::lines`] and [`Self::deadline`] under one
    /// lock, from one advance of the devices.
    fn lines_and_deadline(&mut self, cpu: usize, now: u64) -> (Lines, Option<u64>) {
        if !self.home {
            return (self.lines(cpu, now), None);
        }
        let mut devices = self.board.lock(Call::Lines);
        let now = self.now(now);
        let (lines, deadline) = devices.lines_and_deadline(cpu, now);
        self.board.lines.lock().unwrap_or_else(|e| e.into_inner())[cpu] = lines;
        self.notify(&mut devices, cpu, now);
        (lines, deadline)
    }
    fn system_register(
        &mut self,
        cpu: usize,
        encoding: Encoding,
        write: Option<u64>,
        now: u64,
    ) -> Option<Result<u64, &'static str>> {
        if let Some(bit) = register_bit(encoding)
            && self.board.registers[bit / 64] & 1 << (bit % 64) == 0
        {
            return None;
        }
        if let Some(value) = self.local_register(cpu, encoding, write) {
            return Some(Ok(value));
        }
        if write.is_none() {
            return self.at(Call::Register, now, |devices, now| {
                devices.system_register(cpu, encoding, None, now)
            });
        }
        self.changing(Call::Register, cpu, now, |devices, now| {
            devices.system_register(cpu, encoding, write, now)
        })
    }
    /// Only the home machine takes a reset, which stops every PE.
    fn take_reset(&mut self) -> Option<Reset> {
        if !self.home || !self.board.resetting.swap(false, Ordering::Acquire) {
            return None;
        }
        self.board
            .reset
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }
    fn take_start(&mut self) -> Option<Start> {
        self.board.take_start()
    }
    fn reset_vector(&self, cpu: usize) -> Option<u64> {
        self.with(|devices| devices.reset_vector(cpu))
    }
    fn processor_power(&mut self, cpu: usize, on: bool) {
        let now = self.board.now.load(Ordering::Acquire);
        self.changing(Call::Other, cpu, now, |devices, _| {
            devices.processor_power(cpu, on)
        });
    }
    fn irq_steering(&mut self, cpu: usize, refuses: bool, now: u64) {
        self.changing(Call::Other, cpu, now, |devices, now| {
            devices.irq_steering(cpu, refuses, now)
        });
    }
    /// Only the home machine takes the host's power button.
    fn waits_on_host(&self) -> bool {
        self.home && self.board.asleep.load(Ordering::Acquire)
    }
    /// Any PE that waits for an interrupt can serve the host.
    fn take_host_service(&mut self) -> bool {
        self.board.hub.take_service()
    }
    fn memory_lock(&self) -> mmu::MemoryLocks {
        self.with(|devices| devices.memory_lock())
    }
    fn serves_register(&self, encoding: Encoding) -> bool {
        register_bit(encoding)
            .is_none_or(|bit| self.board.registers[bit / 64] & 1 << (bit % 64) != 0)
    }
    /// Only the home machine moves devices' asynchronous DMA, through its
    /// host's canonical RAM owner.
    fn dma_deadline(&self) -> Option<u64> {
        if !self.home {
            return None;
        }
        let dma = self.board.dma.load(Ordering::Acquire);
        (dma != u64::MAX).then_some(dma)
    }
    fn transfer(
        &mut self,
        cpu: usize,
        memory: &mut dyn super::super::Memory,
        now: u64,
    ) -> Result<(), DeviceError> {
        self.changing(Call::Access, cpu, now, |devices, now| {
            devices.transfer(cpu, memory, now)
        })
    }
}
