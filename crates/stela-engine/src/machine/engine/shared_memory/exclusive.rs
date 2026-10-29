//! Stopped system-service exclusives use the native lane's actual owner.
use super::*;
use crate::{
    memory::domain::{CheckedMemoryEntry, MemoryFault},
    platform::cpu::system::NativeSystemTarget,
};
use stela_compiler::context::memory::{
    FaultAccess, MemoryRequest, MemoryRequirements, exclusive::ExclusiveData, flags,
    profile_requirements,
};

pub(super) struct ExclusiveResult {
    pub(super) data: ExclusiveData,
    pub(super) fault: Option<MemoryFault>,
    pub(super) source: Option<policy::Failure>,
}
impl SharedMemory {
    fn exclusive(
        &mut self,
        controls: Controls,
        request: MemoryRequest,
        data: ExclusiveData,
    ) -> Result<ExclusiveResult, MemoryStatus> {
        let authority = NativeSystemTarget::capture().map_err(|_| MemoryStatus::Unsupported)?;
        self.memory.policy_mut().reset_controls(controls);
        let requirements = MemoryRequirements {
            required_flags: request.flags,
            required_profile: profile_requirements::NATIVE_ACCESS,
            ..MemoryRequirements::default()
        };
        let entry = self
            .memory
            .prepare_native_system(requirements, &authority)?;
        let mut outcome = invoke(entry, request, data)?;
        outcome.source = self.memory.policy_mut().failure;
        Ok(outcome)
    }
}
fn invoke(
    entry: CheckedMemoryEntry<'_, Policy>,
    mut request: MemoryRequest,
    mut data: ExclusiveData,
) -> Result<ExclusiveResult, MemoryStatus> {
    request.data = core::ptr::from_mut(&mut data).cast();
    let mut fault = None;
    // SAFETY: the typed prepared owner retains the actual native target, RAM
    // and source policy. All 32 staging bytes are initialized/private/disjoint;
    // only the existing validated callback can access them during this borrow.
    unsafe {
        entry.with_checked_view(|view| {
            let returned = (view.callback)(view, &request);
            let status = MemoryStatus::from_code(view.fault_kind).ok_or(MemoryStatus::Domain)?;
            let access = FaultAccess::from_code(view.fault_access).ok_or(MemoryStatus::Domain)?;
            if returned != status as u32 {
                return Err(MemoryStatus::Domain);
            }
            if status != MemoryStatus::Success {
                fault = Some(MemoryFault {
                    status,
                    access,
                    address: view.fault_address,
                    pc: view.fault_pc,
                    completed_bytes: view.completed_bytes,
                });
            }
            Ok(())
        })
    }??;
    Ok(ExclusiveResult {
        data,
        fault,
        source: None,
    })
}
impl<H: Host, D: Devices> Machine<H, D> {
    pub(in crate::machine::engine) fn shared_exclusive(
        &mut self,
        operand: stela_compiler::aarch64::exclusive::Operand,
    ) -> super::super::Step {
        use super::super::RequirementKind;
        use crate::machine::{cpu::Exception, exception::Class};
        use stela_compiler::{
            aarch64::{
                Register,
                exclusive::{Data, Kind, Operand},
            },
            context::memory::{
                MemoryOrder,
                exclusive::{ExclusiveOperation, ExclusiveShape},
            },
        };
        if let Some(publication) = &self.native_publication {
            publication
                .require_stopped(self.peers.len(), &[self.current])
                .map_err(|_| {
                    self.unsupported(RequirementKind::Native(
                        "shared exclusive service requires the recovered held worker cohort",
                    ))
                })?;
        }
        let Operand::Transfer {
            element_bytes,
            base,
            data,
            kind,
        } = operand
        else {
            self.cpu.clear_exclusive().map_err(|_| {
                self.unsupported(RequirementKind::Native(
                    "canonical local monitor clear failed",
                ))
            })?;
            return self.next();
        };
        let controls = Controls::capture(&self.cpu, self.profile.name, &self.profile_missing)
            .map_err(|_| {
                self.unsupported(RequirementKind::Native(
                    "shared exclusive source controls are unqualified",
                ))
            })?;
        let address = self.read_register(base);
        if base == Register::Sp
            && controls.sp == stela_compiler::block::CheckedMemoryProfile::SpAlignmentEnabled
            && !address.is_multiple_of(16)
        {
            self.cpu.clear_exclusive().map_err(|_| {
                self.unsupported(RequirementKind::Native(
                    "canonical monitor failed before SP alignment fault",
                ))
            })?;
            self.take(Exception::synchronous(Class::SpAlignment, 0, self.cpu.pc));
            return Ok(());
        }
        let registers = match data {
            Data::Scalar(register) => [Some(register), None],
            Data::Pair(pair) => pair.map(Some),
        };
        let count = registers.iter().flatten().count();
        let bytes = u32::from(element_bytes) * count as u32;
        let write = matches!(kind, Kind::Store { .. });
        let mut staged = ExclusiveData {
            operation: if write {
                ExclusiveOperation::Store
            } else {
                ExclusiveOperation::Load
            } as u32,
            order: match kind {
                Kind::Load { acquire: true } => MemoryOrder::AcquireRcsc,
                Kind::Store { release: true, .. } => MemoryOrder::Release,
                _ => MemoryOrder::Relaxed,
            } as u32,
            shape: if count == 2 {
                ExclusiveShape::Pair
            } else {
                ExclusiveShape::Scalar
            } as u32,
            ..ExclusiveData::default()
        };
        if write {
            let mut packed = [0; 16];
            for (index, register) in registers.iter().flatten().enumerate() {
                let value = self.read_register(*register).to_le_bytes();
                let start = index * usize::from(element_bytes);
                packed[start..start + usize::from(element_bytes)]
                    .copy_from_slice(&value[..usize::from(element_bytes)]);
            }
            staged.value = [
                u64::from_le_bytes(packed[..8].try_into().unwrap()),
                u64::from_le_bytes(packed[8..].try_into().unwrap()),
            ];
        }
        let pc = self.cpu.pc;
        let memory = self
            .cpu
            .canonical_memory
            .as_mut()
            .expect("canonical branch");
        let request = MemoryRequest {
            address,
            pc,
            bytes,
            flags: flags::EXCLUSIVE
                | if write { flags::WRITE } else { 0 }
                | if base != Register::Sp {
                    flags::TAG_CHECKED
                } else {
                    0
                },
            // The adapter installs its own private staging after the move.
            data: core::ptr::null_mut(),
        };
        let outcome = memory.exclusive(controls, request, staged).map_err(|_| {
            self.unsupported(RequirementKind::Native(
                "canonical exclusive service target/storage/finalization refused",
            ))
        })?;
        if let Some(fault) = outcome.fault {
            match outcome.source {
                Some(policy::Failure::Fault {
                    address,
                    access,
                    fault,
                    ..
                }) => {
                    let exception = self.data_abort_exception(
                        address,
                        fault,
                        access == crate::memory::backing::AccessKind::Write,
                        false,
                    );
                    self.take(exception);
                    return Ok(());
                }
                _ if fault.status == MemoryStatus::Alignment => {
                    return self.alignment_fault(fault.address, write);
                }
                _ => {
                    return Err(self.unsupported(RequirementKind::Native(
                        "canonical exclusive source mapping or memory operation is unsupported",
                    )));
                }
            }
        }
        match kind {
            Kind::Store { status, .. } => {
                self.write_register(status, u64::from(outcome.data.status))
            }
            Kind::Load { .. } => {
                let packed = (u128::from(outcome.data.value[0])
                    | (u128::from(outcome.data.value[1]) << 64))
                    .to_le_bytes();
                for (index, register) in registers.iter().flatten().enumerate() {
                    let start = index * usize::from(element_bytes);
                    let mut value = [0; 8];
                    value[..usize::from(element_bytes)]
                        .copy_from_slice(&packed[start..start + usize::from(element_bytes)]);
                    self.write_register(*register, u64::from_le_bytes(value));
                }
            }
        }
        self.next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::context::memory::{
        MemoryOrder,
        exclusive::{ExclusiveOperation, ExclusiveShape},
    };
    const VA: u64 = 0x4000;
    const PA: u64 = 0x14000;
    fn request(bytes: u32, write: bool) -> MemoryRequest {
        MemoryRequest {
            address: VA,
            pc: 0x8000,
            bytes,
            flags: flags::EXCLUSIVE | if write { flags::WRITE } else { 0 },
            data: core::ptr::null_mut(),
        }
    }
    fn payload(operation: ExclusiveOperation, pair: bool, value: u64) -> ExclusiveData {
        ExclusiveData {
            operation: operation as u32,
            order: MemoryOrder::Relaxed as u32,
            shape: if pair {
                ExclusiveShape::Pair
            } else {
                ExclusiveShape::Scalar
            } as u32,
            value: [value, 0],
            ..ExclusiveData::default()
        }
    }
    #[test]
    fn actual_prepared_adapter_keeps_dense_w_pairs_and_every_scalar_width_exact() {
        for (bytes, pair) in [(1, false), (2, false), (4, false), (8, false), (8, true)] {
            let (mut machine, ram, events) = super::super::tests::machine();
            machine
                .install_shared_memory_for_processors(Arc::clone(&ram), &events)
                .unwrap();
            let original = core::array::from_fn::<_, 64, _>(|i| i as u8 ^ 0xa5);
            // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
            // registered.
            unsafe { ram.publish_physical(PA, &original) }.unwrap();
            let memory = machine.cpu.canonical_memory.as_mut().unwrap();
            // This is the actual POSIX model's prepared authority, not a
            // forged production CPL0/current-worker proof.
            let entry = memory
                .memory
                .prepare(MemoryRequirements::default())
                .unwrap();
            let loaded = invoke(
                entry,
                request(bytes, false),
                payload(ExclusiveOperation::Load, pair, 0),
            )
            .unwrap();
            assert!(loaded.fault.is_none());
            let mut old = [0; 8];
            old[..bytes as usize].copy_from_slice(&original[..bytes as usize]);
            assert_eq!(loaded.data.value, [u64::from_le_bytes(old), 0]);
            let bits = bytes * 8;
            let value = 0x1234_abcd_0123_fedcu64 >> (64 - bits);
            let entry = memory
                .memory
                .prepare(MemoryRequirements::default())
                .unwrap();
            let stored = invoke(
                entry,
                request(bytes, true),
                payload(ExclusiveOperation::Store, pair, value),
            )
            .unwrap();
            assert!(stored.fault.is_none());
            assert_eq!(stored.data.status, 0);
            let mut actual = [0; 64];
            // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
            // registered.
            unsafe { ram.read_physical(PA, &mut actual) }.unwrap();
            let mut expected = original;
            expected[..bytes as usize].copy_from_slice(&value.to_le_bytes()[..bytes as usize]);
            assert_eq!(actual, expected);
        }
    }
    #[test]
    fn reached_readonly_fault_keeps_private_payload_pc_access_and_all_ram_bytes() {
        let (mut machine, ram, events) = super::super::tests::machine();
        machine
            .install_shared_memory_for_processors(Arc::clone(&ram), &events)
            .unwrap();
        const LEAF: u64 = 0x10000 + 3 * 4096 + 4 * 8;
        const READ_ONLY: u64 = PA | 3 | (1 << 10) | (3 << 8) | (1 << 7);
        // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
        // registered.
        unsafe { ram.publish_physical(LEAF, &READ_ONLY.to_le_bytes()) }.unwrap();
        let memory = machine.cpu.canonical_memory.as_mut().unwrap();
        let input = payload(ExclusiveOperation::Store, false, 0x1234);
        let entry = memory
            .memory
            .prepare(MemoryRequirements::default())
            .unwrap();
        let result = invoke(entry, request(8, true), input).unwrap();
        assert_eq!(result.data, input);
        let fault = result.fault.unwrap();
        assert_eq!(
            (
                fault.status,
                fault.access,
                fault.pc,
                fault.address,
                fault.completed_bytes
            ),
            (
                MemoryStatus::Permission,
                FaultAccess::OriginalSource,
                0x8000,
                VA,
                0
            )
        );
        assert!(matches!(
            memory.memory.policy_mut().failure,
            Some(policy::Failure::Fault {
                fault: mmu::Fault {
                    kind: mmu::FaultKind::Permission,
                    ..
                },
                ..
            })
        ));
        let mut actual = [0; 64];
        // SAFETY: the buffers are private locals, disjoint from the registered RAM, which stays
        // registered.
        unsafe { ram.read_physical(PA, &mut actual) }.unwrap();
        assert_eq!(actual, [0; 64]);
    }
}
