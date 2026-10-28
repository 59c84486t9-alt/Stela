//! Actual cold checked entry and consuming device reads on one physical BSP.
//! No ARM warmup/legacy V1 instruction runs before canonical conversion.
use super::*;
use machine::engine::{CanonicalDeviceMemory, ConsumedPair, ConsumedScalar, DeviceReadShape};
mod mcc;
mod tree;
const STR_X0_X1: u32 = 0xf9000020;
const LDR_X6_X1: u32 = 0xf9400026;
const LDR_W10_X9: u32 = 0xb940012a;
const STR_W11_X12: u32 = 0xb900018b;
const LDRSW_X3_X2: u32 = 0xb9800043;
const LDP_X4_X5_X2_POST16: u32 = 0xa8c11444;
const LDP_X7_X8_X2_POST16: u32 = 0xa8c12047;
const LDR_Q0_X1: u32 = 0x3dc00020;
const LD4_V4_V7_X1: u32 = 0x4c400024;
const TBL_V16_V4_V0: u32 = 0x4e000090;
const DSB_SY: u32 = 0xd5033f9f;
const BRANCH_SELF: u32 = 0x14000000;
const VALUE: u64 = 0x1122334455667788;
struct Device {
    ram: Arc<RegisteredSystemRam>,
    memory: machine::apple::AppleDevices,
    drains: usize,
    reads: usize,
    observed_ram: Option<u64>,
}
impl Device {
    fn held(&self, memory: &mut dyn CanonicalDeviceMemory) -> Result<(), DeviceError> {
        memory.fence_cpu_memory();
        if !memory.memory().belongs_to(&self.ram) || memory.memory().validate_current().is_err() {
            return Err(DeviceError::TransferRefused(
                "cold fixture lost actual canonical owner".into(),
            ));
        }
        Ok(())
    }
}
impl Devices for Device {
    fn read(&mut self, _: usize, _: u64, _: u8, _: u64) -> Result<u64, DeviceError> {
        Err(DeviceError::TransferRefused(
            "cold fixture rejects raw read".into(),
        ))
    }
    fn write(&mut self, _: usize, _: u64, _: u8, _: u64, _: u64) -> Result<(), DeviceError> {
        Err(DeviceError::NoDevice)
    }
    fn write_canonical(
        &mut self,
        pe: usize,
        physical: u64,
        bytes: u8,
        value: u64,
        now: u64,
        owners: &mut dyn engine::CanonicalDeviceWrite,
    ) -> Result<engine::ConsumedWrite, DeviceError> {
        if physical != mcc::FLUSH || bytes != 4 || value != 1 {
            return Err(DeviceError::NoDevice);
        }
        self.memory
            .write_canonical(pe, physical, bytes, value, now, owners)
    }
    fn lines(&mut self, _: usize, _: u64) -> Lines {
        Lines::default()
    }
    fn requires_canonical_read(&self, _: usize, physical: u64, _: DeviceReadShape) -> bool {
        (source::READY..source::READY + 32).contains(&physical) || physical == mcc::DRAIN
    }
    fn read_canonical(
        &mut self,
        pe: usize,
        physical: u64,
        bytes: u8,
        now: u64,
        memory: &mut dyn CanonicalDeviceMemory,
    ) -> Result<ConsumedScalar, DeviceError> {
        self.held(memory)?;
        if physical == mcc::DRAIN {
            let mut result = self
                .memory
                .read_canonical(pe, physical, bytes, now, memory)?;
            if result.value != 0 || result.settlement.is_err() || self.drains != 0 {
                result.settlement = Err(DeviceError::TransferRefused(
                    "actual MCC fixture drain failed".into(),
                ));
            }
            self.drains += 1;
            return Ok(result);
        }
        if (pe, physical, bytes, self.reads) != (0, source::READY, 4, 0) {
            return Err(DeviceError::NoDevice);
        }
        self.reads += 1;
        Ok(ConsumedScalar {
            value: 0x80000001,
            settlement: Ok(()),
        })
    }
    fn read_pair_canonical(
        &mut self,
        pe: usize,
        physical: u64,
        bytes: u8,
        _: u64,
        memory: &mut dyn CanonicalDeviceMemory,
    ) -> Result<ConsumedPair, DeviceError> {
        self.held(memory)?;
        if pe != 0
            || bytes != 8
            || !((self.reads == 1 && physical == source::READY)
                || (self.reads == 2 && physical == source::READY + 16))
        {
            return Err(DeviceError::NoDevice);
        }
        // Exact native scalar observation under the same all-writer guard,
        // before the deliberately failed final board settlement poisons it.
        let mut bytes = [0; 8];
        // SAFETY: private output, actual canonical RAM, all frames held and no
        // external producer. This read grants no new writer/device authority.
        unsafe { self.ram.read_physical(source::DATA, &mut bytes) }
            .map_err(|_| DeviceError::TransferRefused("cold RAM observation refused".into()))?;
        self.observed_ram = Some(u64::from_le_bytes(bytes));
        self.reads += 1;
        Ok(if self.reads == 2 {
            ConsumedPair {
                values: [0xaaaa, 0xbbbb],
                settlement: Ok(()),
            }
        } else {
            ConsumedPair {
                values: [0xcccc, 0xdddd],
                settlement: Err(DeviceError::TransferRefused(
                    "bounded post-consume settlement fault".into(),
                )),
            }
        })
    }
}
/// # Safety
/// Same pinned one-BSP physical resources and closed synchronous source owner
/// as the outer kernel check. The caller terminates after this fault fixture.
pub(super) unsafe fn check(
    handoff: &'static Handoff,
    capture: &'static Capture,
    executors: &Executors,
    owner: &mut host::HostOwner,
    sender: &Apic,
) -> Result<(), &'static str> {
    let reservation = handoff.guest[..handoff.guest_count]
        .iter()
        .find(|region| region.bytes >= source::BYTES as u64)
        .ok_or("cold fixture has no actual loader RAM reservation")?;
    let range = host::RamRange {
        guest: source::BASE,
        host: reservation.physical,
        bytes: source::BYTES as u64,
    };
    // SAFETY: bounded loader-owned scratch reservation, before registration or
    // any guest frame/publisher; this check does not enter original macOS.
    unsafe {
        core::ptr::write_bytes(
            crate::layout::physical(range.host) as *mut u8,
            0,
            source::BYTES,
        )
    };
    let ram = unsafe { super::super::canonical::reserve(handoff, &[range]) }?;
    // SAFETY: before any frame, guest entry or other publisher; this exact
    // registered allocation is retained by the following Machine.
    unsafe { tree::check(&ram) }?;
    let mut words = Vec::new();
    source::constant(&mut words, 0, VALUE);
    source::constant(&mut words, 1, source::DATA);
    words.extend_from_slice(&[STR_X0_X1, LDR_X6_X1, DSB_SY]);
    source::constant(&mut words, 11, 1);
    source::constant(&mut words, 12, mcc::FLUSH);
    words.push(STR_W11_X12);
    source::constant(&mut words, 9, mcc::DRAIN);
    words.push(LDR_W10_X9);
    // Exercise one mixed native prefix through the real cold policy, callback
    // ABI and host recovery entry, rather than only a standalone LD4 body.
    words.extend_from_slice(&[LDR_Q0_X1, LD4_V4_V7_X1, TBL_V16_V4_V0]);
    source::constant(&mut words, 2, source::READY);
    words.extend_from_slice(&[LDRSW_X3_X2, LDP_X4_X5_X2_POST16, LDP_X7_X8_X2_POST16]);
    let done = source::CODE + words.len() as u64 * 4;
    words.push(BRANCH_SELF);
    let code: Vec<_> = words.iter().copied().flat_map(u32::to_le_bytes).collect();
    // SAFETY: before first guest entry, actual fixture owns the whole RAM.
    unsafe { ram.publish_physical(source::CODE, &code) }
        .map_err(|_| "cold source publication refused")?;
    let mut cpu = Cpu::of(Chip::AppleM1, source::CODE, Pstate::reset(2));
    for (index, vector) in cpu.state.v.iter_mut().enumerate() {
        *vector = [0x10203040 + index as u64, !(index as u64)];
    }
    let before = cpu.state.clone();
    let devices = Device {
        ram: Arc::clone(&ram),
        memory: mcc::devices(Arc::clone(&ram))?,
        drains: 0,
        reads: 0,
        observed_ram: None,
    };
    // SAFETY: true one-PE diagnostic interface and same actual BSP allocation.
    // All bytes/providers are closed and synchronous; no original guest/DMA.
    let mut machine = unsafe {
        super::super::canonical::prepare(
            handoff,
            capture,
            executors,
            sender,
            owner,
            Arc::clone(&ram),
            cpu,
            devices,
            profile(1)?,
            0,
            &[WorkerBinding {
                pe: 0,
                worker: WorkerId(0),
            }],
            &[],
        )
    }?;
    crate::output::arguments(format_args!(
        "NATIVE COLD source pc={:#x} bytes={code:02x?} warmup=none profile=system-mode+checked-memory\n",
        source::CODE
    ));
    // SAFETY: same real one-BSP mount adapter, closed providers and source
    // identity. Its consumed terminal error must retain the final read prefix.
    let stopped = unsafe { super::super::canonical::run_slice(&mut machine, 16) };
    if !matches!(stopped, Stop::Unsupported(_)) || machine.devices.reads != 3 {
        crate::output::arguments(format_args!(
            "NATIVE COLD unexpected {stopped:?} reads={}\n",
            machine.devices.reads
        ));
        return Err("cold source did not reach expected post-consume settlement failure");
    }
    let mut expected = before;
    expected.x[0] = VALUE;
    expected.x[1] = source::DATA;
    expected.x[2] = source::READY + 32;
    expected.x[3] = 0xffffffff80000001;
    expected.x[4] = 0xaaaa;
    expected.x[5] = 0xbbbb;
    expected.x[6] = VALUE;
    expected.v[0] = [VALUE, 0];
    let mut input = [0; 64];
    input[..8].copy_from_slice(&VALUE.to_le_bytes());
    for register in 0..4 {
        let bytes: [u8; 16] = core::array::from_fn(|lane| input[lane * 4 + register]);
        expected.v[4 + register] = [
            u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            u64::from_le_bytes(bytes[8..].try_into().unwrap()),
        ];
    }
    let table: [u8; 16] = core::array::from_fn(|lane| input[lane * 4]);
    let indices = [VALUE.to_le_bytes(), [0; 8]].concat();
    let selected: Vec<u8> = indices
        .iter()
        .map(|&index| table.get(index as usize).copied().unwrap_or(0))
        .collect();
    expected.v[16] = [
        u64::from_le_bytes(selected[..8].try_into().unwrap()),
        u64::from_le_bytes(selected[8..].try_into().unwrap()),
    ];
    expected.x[7] = 0xcccc;
    expected.x[8] = 0xdddd;
    expected.x[9] = mcc::DRAIN;
    expected.x[10] = 0;
    expected.x[11] = 1;
    expected.x[12] = mcc::FLUSH;
    crate::output::arguments(format_args!(
        "NATIVE COLD frame pc={:#x} retired={} pstate={:?} state={:?}\n",
        machine.cpu.pc, machine.cpu.retired, machine.cpu.pstate, machine.cpu.state
    ));
    if machine.cpu.state != expected
        || machine.cpu.pc != done
        || machine.cpu.retired != words.len() as u64 - 1
        || machine.devices.reads != 3
        || machine.devices.drains != 1
        || machine.devices.observed_ram != Some(VALUE)
        || machine
            .devices
            .memory
            .t8112_cache_progress()
            .is_none_or(|progress| {
                progress.completed_flushes != 1 || progress.latest_flush.is_none()
            })
        || machine.cpu.pstate != Pstate::reset(2)
    {
        return Err("cold complete frame/data/writeback/retirement mismatch");
    }
    if unsafe { machine.complete_device_read() }.is_ok()
        || machine.devices.reads != 3
        || unsafe { machine.native_round() }.is_ok()
        || machine
            .devices
            .memory
            .t8112_cache_progress()
            .map(|progress| progress.completed_flushes)
            != Some(1)
    {
        return Err("cold consumed read replayed or resumed after failed settlement");
    }
    crate::output::arguments(format_args!(
        "CHECK native-cold PASS actual_BSP=1 warmup=none live_ADT_publish=canonical checked_Device_RAM=store+load CPU_DSB=1 actual_MCC_drain=1 actual_empty_cache_flush=1 consumed_reads=4 scalar_signextend=1 pair_writeback=2 postfailure_retired=1 full_frame=preserved replay=refused; no macOS/SMP/DRAM completion claim\n"
    ));
    Ok(())
}
