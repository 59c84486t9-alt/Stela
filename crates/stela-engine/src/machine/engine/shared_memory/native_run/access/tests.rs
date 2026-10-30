use super::*;
use crate::machine::engine::shared_memory::host::tests::{Local, OneWorker};
use crate::machine::engine::{self, CanonicalDeviceMemory};
use crate::machine::{DeviceError, Lines, Stop, exception::Pstate};
use crate::memory::domain::{DataOperation, DataRequest};
use stela_compiler::aarch64::{MemoryTransfer, Operation};
use stela_compiler::context::memory::FaultAccess;
use stela_contracts::refuse;
const PC: u64 = 0x14000;
const DEVICE: u64 = 0x90000;
const LDR: u32 = 0xf9400020; // LDR X0,[X1]
const LDP_POST: u32 = 0xa8c10440; // LDP X0,X1,[X2],#16
struct Device {
    reads: usize,
    fail: bool,
    shape: Option<engine::DeviceReadShape>,
    writes: Vec<(engine::DeviceWriteShape, [u64; 2])>,
    committed: Vec<u8>,
    write_result: Option<Result<engine::ConsumedWrite, DeviceError>>,
    clock: bool,
    clock_commits: usize,
}
impl Devices for Device {
    fn read(&mut self, _: usize, _: u64, _: u8, _: u64) -> Result<u64, DeviceError> {
        panic!("raw/replayed read")
    }
    fn write(&mut self, _: usize, _: u64, _: u8, _: u64, _: u64) -> Result<(), DeviceError> {
        Err(DeviceError::NoDevice)
    }
    fn lines(&mut self, _: usize, _: u64) -> Lines {
        Lines::default()
    }
    fn read_canonical(
        &mut self,
        _: usize,
        physical: u64,
        bytes: u8,
        _: u64,
        memory: &mut dyn engine::CanonicalDeviceMemory,
    ) -> Result<engine::ConsumedScalar, DeviceError> {
        assert_eq!(physical, DEVICE);
        assert!(matches!(bytes, 1 | 2 | 4 | 8));
        memory.fence_cpu_memory();
        memory.memory().validate_current().unwrap();
        self.reads += 1;
        self.shape = Some(engine::DeviceReadShape::Scalar { bytes });
        Ok(engine::ConsumedScalar {
            value: 0x8877665544332211,
            settlement: self.settlement(),
        })
    }
    fn write_canonical(
        &mut self,
        _: usize,
        physical: u64,
        bytes: u8,
        value: u64,
        _: u64,
        owners: &mut dyn engine::CanonicalDeviceWrite,
    ) -> Result<engine::ConsumedWrite, DeviceError> {
        self.consume_write(
            physical,
            engine::DeviceWriteShape::Scalar { bytes },
            [value, 0],
            owners,
        )
    }
    fn write_pair_canonical(
        &mut self,
        _: usize,
        physical: u64,
        bytes: u8,
        values: [u64; 2],
        _: u64,
        owners: &mut dyn engine::CanonicalDeviceWrite,
    ) -> Result<engine::ConsumedWrite, DeviceError> {
        self.consume_write(
            physical,
            engine::DeviceWriteShape::Pair { bytes },
            values,
            owners,
        )
    }
    fn read_pair_canonical(
        &mut self,
        _: usize,
        physical: u64,
        bytes: u8,
        _: u64,
        memory: &mut dyn engine::CanonicalDeviceMemory,
    ) -> Result<engine::ConsumedPair, DeviceError> {
        assert_eq!(physical, DEVICE);
        assert!(matches!(bytes, 1 | 2 | 4 | 8));
        memory.fence_cpu_memory();
        memory.memory().validate_current().unwrap();
        self.reads += 1;
        self.shape = Some(engine::DeviceReadShape::Pair { bytes });
        Ok(engine::ConsumedPair {
            values: [0x8877665544332211, 0xffeeddccbbaa0099],
            settlement: self.settlement(),
        })
    }
}
impl Device {
    fn consume_write(
        &mut self,
        physical: u64,
        shape: engine::DeviceWriteShape,
        values: [u64; 2],
        owners: &mut dyn engine::CanonicalDeviceWrite,
    ) -> Result<engine::ConsumedWrite, DeviceError> {
        use engine::{ConsumedWrite, DeviceWriteShape};
        assert_eq!(physical, DEVICE);
        {
            let mut memory = owners.memory()?;
            memory.memory().validate_current().unwrap();
            memory.fence_cpu_memory();
        }
        let result = self.write_result.clone().unwrap_or_else(|| {
            Ok(ConsumedWrite::Complete {
                settlement: self.settlement(),
            })
        })?;
        if self.clock {
            use engine::ProcessorChange;
            let active = stela_contracts::bus::LifecycleState {
                powered: true,
                clocked: true,
                quiesced: false,
                reset: false,
                retention: false,
            };
            let paused = owners
                .processors()?
                .apply(&[ProcessorChange {
                    domain: 1,
                    state: stela_contracts::bus::LifecycleState {
                        clocked: false,
                        ..active
                    },
                }])
                .map_err(|e| DeviceError::TransferRefused(refuse!("clock preflight {e}", ?e)))?;
            assert_eq!(paused.paused(0), Some(true));
            self.clock_commits += 1;
            drop(paused);
            match owners.processors()?.apply(&[ProcessorChange {
                domain: 1,
                state: active,
            }]) {
                Ok(resumed) => {
                    assert_eq!(resumed.paused(0), Some(false));
                    self.clock_commits += 1;
                    drop(resumed);
                }
                Err(error) => {
                    return Ok(ConsumedWrite::Unknown {
                        error: DeviceError::TransferRefused(refuse!(
                            "clock post-effect {error}",
                            ?error
                        )),
                    });
                }
            }
            // The CPU lease ended before taking the all-writer gates.
            owners.memory()?.memory().validate_current().unwrap();
        }
        let (bytes, count) = match shape {
            DeviceWriteShape::Scalar { bytes } => (bytes, 1),
            DeviceWriteShape::Pair { bytes } => (bytes, 2),
        };
        let all: Vec<_> = values
            .into_iter()
            .take(count)
            .flat_map(|v| v.to_le_bytes().into_iter().take(usize::from(bytes)))
            .collect();
        let consumed = match &result {
            ConsumedWrite::Complete { .. } => all.len(),
            ConsumedWrite::Prefix { bytes, .. } => usize::from(*bytes),
            ConsumedWrite::Unknown { .. } => 1,
        };
        self.committed.extend_from_slice(&all[..consumed]);
        self.writes.push((shape, values));
        Ok(result)
    }
    fn settlement(&self) -> Result<(), DeviceError> {
        if self.fail {
            Err(DeviceError::TransferRefused(
                "model post-consume failure".into(),
            ))
        } else {
            Ok(())
        }
    }
}
type TestMachine = Machine<ServiceHost<Local, OneWorker>, Device>;
/// Protocol model only: the real publication loan is returned
/// after CPL0 refusal on this POSIX runner. Its failure diagnostics are
/// replaced ONLY here to drive continuation adversaries. No native memory
/// callback/CPL0 execution is claimed by these tests.
fn pending(word: u32, fail: bool) -> (TestMachine, Arc<RegisteredSystemRam>) {
    pending_at(word, fail, DEVICE)
}
fn pending_at(word: u32, fail: bool, base: u64) -> (TestMachine, Arc<RegisteredSystemRam>) {
    let instruction = stela_compiler::Lifter::lift(
        &stela_compiler::aarch64::Decoder,
        stela_compiler::GuestAddress(PC),
        word,
    )
    .unwrap();
    let write = matches!(
        instruction.operation,
        Operation::MemoryPair {
            transfer: MemoryTransfer::Store,
            ..
        }
    ) || engine::ScalarStore::from_instruction(&instruction).is_some();
    let (mut cpu, profile, missing, ram) =
        crate::machine::engine::shared_memory::policy::tests::fixture();
    cpu.pstate = Pstate::reset(2);
    cpu.registers
        .set_raw(crate::machine::system::Register::SCTLR_EL2, 0, 0);
    cpu.pc = PC;
    cpu.state.x[0] = 0x8877665544332211;
    cpu.state.x[3] = if write { 0xffeeddccbbaa0099 } else { 0 };
    cpu.state.x[1] = base;
    cpu.state.x[2] = base;
    cpu.state.sp = base;
    let mut source = word.to_le_bytes().to_vec();
    source.extend_from_slice(&0x14000000u32.to_le_bytes());
    // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
    // registered.
    unsafe { ram.publish_physical(PC, &source) }.unwrap();
    let native_host = ServiceHost::new(Local, OneWorker(None), Arc::clone(&ram));
    let mut machine = Machine::new(
        cpu,
        native_host,
        Device {
            reads: 0,
            fail,
            shape: None,
            writes: Vec::new(),
            committed: Vec::new(),
            write_result: None,
            clock: false,
            clock_commits: 0,
        },
        profile,
        ram.target(),
    );
    machine.profile_missing = missing;
    machine
        .install_shared_memory_for_active_processors(
            Arc::clone(&ram),
            &crate::system::events::EventDomain::new(),
        )
        .unwrap();
    let binding = publication::WorkerBinding {
        pe: 0,
        worker: publication::WorkerId(17),
    };
    let owners = machine.bind_active_native_workers(&[binding]).unwrap();
    machine.initialize_native_transport(owners);
    let cohort = machine.native_cohort(&[binding], true).unwrap();
    let controls = cohort.frames[0].identity().controls_sha256.clone();
    let required_flags = cohort.frames[0].identity().requirements.required_flags;

    let mut reports =
        cohort
            .host
            .transport
            .execute(&mut cohort.host.local, cohort.inventory, cohort.frames);
    let mut settlement = reports.pop().unwrap().settlement.take().unwrap();
    assert!(settlement.status.is_err()); // CPL0 refusal, never a success substitute
    let (pair, bytes) = match instruction.operation {
        Operation::MemoryPair { bytes, .. } => (true, usize::from(bytes) * 2),
        _ => (
            false,
            usize::from(if write {
                engine::ScalarStore::from_instruction(&instruction)
                    .unwrap()
                    .bytes()
            } else {
                stela_compiler::block::scalar::ScalarLoad::from_instruction(&instruction)
                    .unwrap()
                    .bytes()
            }),
        ),
    };
    let request = DataRequest {
        address: DEVICE,
        bytes,
        flags: required_flags
            | if pair {
                stela_compiler::context::memory::flags::PAIR
            } else {
                0
            }
            | if write {
                stela_compiler::context::memory::flags::WRITE
            } else {
                0
            },
        pc: Some(PC),
        operation: DataOperation::Ordinary,
    };
    settlement.status = Ok(());
    settlement.fault_word = Some(word);
    settlement.controls_sha256 = Some(controls);
    settlement.memory_fault = Some(crate::memory::domain::MemoryFault {
        status: MemoryStatus::Unsupported,
        address: DEVICE,
        pc: PC,
        completed_bytes: 0,
        access: if write {
            FaultAccess::Write
        } else {
            FaultAccess::Read
        },
    });
    settlement.source_failure = Some(if write {
        policy::Failure::DeviceWrite {
            request,
            address: DEVICE,
            physical: DEVICE,
            bytes,
        }
    } else {
        policy::Failure::DeviceRead {
            request,
            address: DEVICE,
            physical: DEVICE,
            bytes,
        }
    });
    let held = machine.hold_native_services().unwrap();
    if write {
        machine.native_source_pe(binding).unwrap();
        machine
            .bind_processor_power(&[engine::ProcessorBinding {
                domain: 1,
                target: stela_contracts::processor::ProcessorTarget::Core { pe: 0 },
                initial: stela_contracts::bus::LifecycleState {
                    powered: true,
                    clocked: true,
                    quiesced: false,
                    reset: false,
                    retention: false,
                },
            }])
            .unwrap();
        assert!(matches!(
            machine.queue_device_write(settlement.into_write(), held),
            Stop::DeviceWrite(_)
        ));
    } else {
        assert!(matches!(
            machine.queue_device_read(settlement.into_read(), held),
            Stop::DeviceRead(_)
        ));
    }
    (machine, ram)
}
#[test]
fn settlement_failure_keeps_consumed_data() {
    for word in [LDR, LDP_POST] {
        for fail in [false, true] {
            let (mut machine, ram) = pending(word, fail);
            let before = machine.cpu.state.clone();
            let retired = machine.cpu.retired;
            // SAFETY: this single-threaded test machine owns its registered RAM, with no DMA,
            // device worker or other writer admitted.
            let result = unsafe { machine.complete_device_read() };
            assert_eq!(result.is_err(), fail);
            assert_eq!(machine.devices.reads, 1);
            assert_eq!(machine.cpu.pc, PC + 4);
            assert_eq!(machine.cpu.retired, retired + 1);
            let mut expected = before;
            expected.x[0] = 0x8877665544332211;
            if word == LDP_POST {
                expected.x[1] = 0xffeeddccbbaa0099;
                expected.x[2] = DEVICE + 16;
            }
            assert_eq!(machine.cpu.state, expected);
            // SAFETY: this single-threaded test machine owns its registered RAM, with no DMA,
            // device worker or other writer admitted.
            assert!(unsafe { machine.complete_device_read() }.is_err());
            assert_eq!(machine.devices.reads, 1);
            assert!(matches!(machine.run(1), Stop::Unsupported(_)));
            assert_eq!(ram.check_physical(PC, 4).is_err(), fail);
        }
    }
}
#[test]
fn every_addressing_mode_keeps_writeback() {
    // Unchanged source encodings through the shared decoder; closed model
    // only. The QEMU cold fixture separately executes the real pair path.
    for (word, base, first, second, writeback) in [
        (
            0xf8408420,
            DEVICE,
            0x8877665544332211,
            None,
            Some((1, DEVICE + 8)),
        ), // LDR X0,[X1],#8
        (0xb89fcc20, DEVICE + 4, 0x44332211, None, Some((1, DEVICE))), // LDRSW X0,[X1,#-4]!
        (
            0x29ff0440,
            DEVICE + 8,
            0x44332211,
            Some(0xbbaa0099),
            Some((2, DEVICE)),
        ), // LDP W0,W1,[X2,#-8]!
        (
            0x68c10440,
            DEVICE,
            0x44332211,
            Some(0xffffffffbbaa0099),
            Some((2, DEVICE + 8)),
        ), // LDPSW X0,X1,[X2],#8
        (0xf8636820, DEVICE, 0x8877665544332211, None, None),          // LDR X0,[X1,X3]
        (0x583e0000, DEVICE, 0x8877665544332211, None, None),          // LDR X0,literal(Device)
    ] {
        let (mut machine, _) = pending_at(word, false, base);
        let mut expected = machine.cpu.state.clone();
        expected.x[0] = first;
        if let Some(value) = second {
            expected.x[1] = value;
        }
        if let Some((register, value)) = writeback {
            expected.x[register] = value;
        }
        // SAFETY: this single-threaded test machine owns its registered RAM, with no DMA,
        // device worker or other writer admitted.
        unsafe { machine.complete_device_read() }.unwrap();
        assert_eq!(machine.cpu.state, expected, "word={word:#x}");
        assert_eq!(machine.cpu.pc, PC + 4);
        assert_eq!(machine.cpu.retired, 1);
        assert_eq!(machine.devices.reads, 1);
    }
}
#[test]
fn changed_frame_controls_or_source_refuses_before_device_consumption() {
    for tamper in 0..5 {
        let (mut machine, ram) = pending(LDR, false);
        match tamper {
            0 => machine.cpu.state.x[3] ^= 1,
            1 => machine.cpu.pc += 4,
            2 => machine.cpu.pstate.daif ^= 1,
            3 => machine
                .cpu
                .registers
                .set_raw(crate::machine::system::Register::SCTLR_EL2, 0, 1),
            _ => {
                // SAFETY: the buffers are private locals, disjoint from the registered RAM,
                // which stays registered.
                unsafe { ram.publish_physical(PC, &0xd503201fu32.to_le_bytes()) }.unwrap();
            }
        }
        let before = (
            machine.cpu.state.clone(),
            machine.cpu.pc,
            machine.cpu.retired,
        );
        // SAFETY: this single-threaded test machine owns its registered RAM, with no DMA,
        // device worker or other writer admitted.
        assert!(unsafe { machine.complete_device_read() }.is_err());
        assert_eq!(machine.devices.reads, 0);
        assert_eq!(
            (
                machine.cpu.state.clone(),
                machine.cpu.pc,
                machine.cpu.retired
            ),
            before
        );
        // SAFETY: this single-threaded test machine owns its registered RAM, with no DMA,
        // device worker or other writer admitted.
        assert!(unsafe { machine.native_round() }.is_err());
        assert_eq!(machine.devices.reads, 0);
    }
}
#[test]
fn consuming_stores_preserve_full_frame_and_retire_writeback_even_after_settlement_failure() {
    const STR_X0_X1: u32 = 0xf9000020;
    const STR_POST: u32 = 0xf8008420;
    const STP_POST: u32 = 0xa8810c40;
    for (word, bytes, pair, writeback) in [
        (STR_X0_X1, 8, false, None),
        (0xb9000020, 4, false, None),
        (0x79000020, 2, false, None),
        (0x39000020, 1, false, None),
        (STR_POST, 8, false, Some((1, DEVICE + 8))),
        (STP_POST, 8, true, Some((2, DEVICE + 16))),
    ] {
        for fail in [false, true] {
            let (mut machine, ram) = pending(word, fail);
            let mut expected = machine.cpu.state.clone();
            if let Some((base, value)) = writeback {
                expected.x[base] = value;
            }
            // SAFETY: this single-threaded test machine owns its registered RAM, with no DMA,
            // device worker or other writer admitted.
            let result = unsafe { machine.complete_device_write() };
            assert_eq!(result.is_ok(), !fail);
            assert_eq!(machine.cpu.state, expected);
            assert_eq!((machine.cpu.pc, machine.cpu.retired), (PC + 4, 1));
            assert_eq!(machine.devices.writes.len(), 1);
            let expected_shape = if pair {
                engine::DeviceWriteShape::Pair { bytes }
            } else {
                engine::DeviceWriteShape::Scalar { bytes }
            };
            assert_eq!(machine.devices.writes[0].0, expected_shape);
            let mut expected_bytes =
                0x8877665544332211u64.to_le_bytes()[..usize::from(bytes)].to_vec();
            if pair {
                expected_bytes
                    .extend_from_slice(&0xffeeddccbbaa0099u64.to_le_bytes()[..usize::from(bytes)]);
            }
            assert_eq!(machine.devices.committed, expected_bytes);

            assert_eq!(
                machine.devices.committed.len(),
                usize::from(bytes) * if pair { 2 } else { 1 }
            );
            // SAFETY: this single-threaded test machine owns its registered RAM, with no DMA,
            // device worker or other writer admitted.
            assert!(unsafe { machine.complete_device_write() }.is_err());
            assert_eq!(machine.devices.writes.len(), 1);
            if fail {
                assert!(ram.try_service().is_err());
            }
        }
    }
}
#[test]
fn new_host_points_preserve_an_already_entered_bus_continuation() {
    for word in [LDR, 0xf9000020] {
        let (mut machine, _) = pending(word, false);
        let queued = machine.pending_native_device_access().unwrap();
        machine.set_breakpoints(&[PC]);
        machine.set_traces(&[PC]);
        // These points cannot retroactively replace this already entered
        // instruction's linear continuation. No native frame is executed.
        // SAFETY: this single-threaded test machine owns its registered RAM, with no DMA,
        // device worker or other writer admitted.
        assert_eq!(unsafe { machine.native_round() }, Err(queued));
        assert!(machine.take_trace_hits().is_empty());
        assert_eq!(machine.pending_native_device_access_count(), 1);
        // SAFETY: this single-threaded test machine owns its registered RAM, with no DMA,
        // device worker or other writer admitted.
        unsafe { machine.complete_native_device_access() }.unwrap();
        assert_eq!((machine.cpu.pc, machine.cpu.retired), (PC + 4, 1));
        assert_eq!(machine.devices.reads + machine.devices.writes.len(), 1);
        assert_eq!(machine.pending_native_device_access_count(), 0);
        assert!(machine.take_trace_hits().is_empty());
        // SAFETY: this single-threaded test machine owns its registered RAM, with no DMA,
        // device worker or other writer admitted.
        assert!(unsafe { machine.complete_native_device_access() }.is_err());
        assert_eq!(machine.devices.reads + machine.devices.writes.len(), 1);
    }
}
#[test]
fn sequential_memory_and_processor_leases_complete_under_one_stop() {
    let (mut machine, _) = pending(0xf9000020, false);
    machine.devices.clock = true;
    // SAFETY: this single-threaded test machine owns its registered RAM, with no DMA, device
    // worker or other writer admitted.
    unsafe { machine.complete_device_write() }.unwrap();
    assert_eq!(machine.devices.clock_commits, 2);
    assert_eq!(machine.processors().paused(0), Some(false));
    assert_eq!((machine.cpu.pc, machine.cpu.retired), (PC + 4, 1));
}
#[test]
fn prefix_unknown_and_effect_free_errors_never_retire_or_replay_a_store() {
    use engine::ConsumedWrite;
    for result in [
        Ok(ConsumedWrite::Prefix {
            bytes: 4,
            error: DeviceError::Refused("retained prefix".into()),
        }),
        Ok(ConsumedWrite::Unknown {
            error: DeviceError::Refused("unknown prefix".into()),
        }),
        Err(DeviceError::Refused("effect-free preflight".into())),
    ] {
        let (mut machine, ram) = pending(0xf8008420, false);
        machine.devices.write_result = Some(result.clone());
        let before = machine.cpu.state.clone();
        // SAFETY: this single-threaded test machine owns its registered RAM, with no DMA,
        // device worker or other writer admitted.
        let first = unsafe { machine.complete_native_device_access() }.unwrap_err();
        assert_eq!(
            // SAFETY: this single-threaded test machine owns its registered RAM, with no DMA,
            // device worker or other writer admitted.
            unsafe { machine.complete_native_device_access() },
            Err(first)
        );
        assert_eq!(machine.cpu.state, before);
        assert_eq!((machine.cpu.pc, machine.cpu.retired), (PC, 0));
        assert_eq!(machine.devices.writes.len(), usize::from(result.is_ok()));
        assert!(ram.try_service().is_err());
        // SAFETY: this single-threaded test machine owns its registered RAM, with no DMA,
        // device worker or other writer admitted.
        assert!(unsafe { machine.native_round() }.is_err());
        // SAFETY: this single-threaded test machine owns its registered RAM, with no DMA,
        // device worker or other writer admitted.
        assert!(unsafe { machine.complete_native_device_access() }.is_err());
        assert_eq!(machine.devices.writes.len(), usize::from(result.is_ok()));
    }
}
#[test]
fn altered_source_frame_or_controls_refuse_before_store_effects() {
    for tamper in 0..4 {
        let (mut machine, ram) = pending(0xf9000020, false);
        match tamper {
            0 => machine.cpu.state.x[0] ^= 1,
            1 => machine.cpu.pc += 4,
            2 => machine
                .cpu
                .registers
                .set_raw(crate::machine::system::Register::SCTLR_EL2, 0, 1),
            // SAFETY: the buffers are private locals, disjoint from the registered RAM, which
            // stays registered.
            _ => unsafe { ram.publish_physical(PC, &0xd503201fu32.to_le_bytes()) }.unwrap(),
        }
        let before = (
            machine.cpu.state.clone(),
            machine.cpu.pc,
            machine.cpu.retired,
        );
        // SAFETY: this single-threaded test machine owns its registered RAM, with no DMA,
        // device worker or other writer admitted.
        assert!(unsafe { machine.complete_device_write() }.is_err());
        assert!(machine.devices.writes.is_empty() && machine.devices.committed.is_empty());
        assert_eq!(
            (
                machine.cpu.state.clone(),
                machine.cpu.pc,
                machine.cpu.retired
            ),
            before
        );
    }
}
#[test]
fn zero_register_and_preindexed_sp_stores_use_old_values() {
    let (mut zero, _) = pending(0xf900003f, false);
    let before = zero.cpu.state.clone();
    // SAFETY: this single-threaded test machine owns its registered RAM, with no DMA, device
    // worker or other writer admitted.
    unsafe { zero.complete_device_write() }.unwrap();
    assert_eq!(zero.cpu.state, before);
    assert_eq!(zero.devices.committed, [0; 8]);
    let (mut sp, _) = pending_at(0xf8008fe0, false, DEVICE - 8);
    let mut expected = sp.cpu.state.clone();
    expected.sp = DEVICE;
    // SAFETY: this single-threaded test machine owns its registered RAM, with no DMA, device
    // worker or other writer admitted.
    unsafe { sp.complete_device_write() }.unwrap();
    assert_eq!(sp.cpu.state, expected);
    assert_eq!(sp.devices.committed, 0x8877665544332211u64.to_le_bytes());
}
