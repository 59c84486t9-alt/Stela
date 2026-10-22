//! Checked native rounds with stopped, owner-local source services. This is a
//! candidate scheduler, not admission of a boot device/DMA/reset resource graph.
use super::super::{RequirementKind, Step, Stop, processors::Peer, publication};
use super::*;
use stela_compiler::{block::ExitKind, context::memory::MemoryStatus};

fn fault_write(
    access: stela_compiler::context::memory::FaultAccess,
    operation: crate::memory::domain::DataOperation,
    original: crate::memory::backing::AccessKind,
) -> bool {
    use stela_compiler::context::memory::FaultAccess;
    match access {
        FaultAccess::Read => false,
        FaultAccess::Write => true,
        FaultAccess::OriginalSource => {
            operation != crate::memory::domain::DataOperation::Atomic
                && original == crate::memory::backing::AccessKind::Write
        }
    }
}

fn completing<H: Host, D: Devices>(
    machine: &mut Machine<H, D>,
    complete: impl FnOnce(&mut Machine<H, D>) -> Step,
) -> Step {
    let retired = machine.cpu.retired;
    let step = machine.completing(machine.cpu.pc, complete);
    // A refused stopped service has not completed the source instruction.
    // Keep the actual native prefix's retirement; never count a denied word.
    if matches!(step, Err(Stop::Unsupported(_))) {
        machine.cpu.retired = retired;
    }
    step
}

impl<H: Host, T: NativeTransport, D: Devices> Machine<ServiceHost<H, T>, D> {
    /// Publish the assigned physical owners before the first native round.
    pub fn initialize_native_transport(&mut self, owners: Vec<publication::WorkerOwner>) {
        let Some(inventory) = &mut self.native_publication else {
            self.host
                .transport
                .fail_stopped("native initialization requires the actual inventory");
        };
        self.host
            .transport
            .initialize(&mut self.host.local, inventory, owners);
    }

    pub(super) fn hold_native_services(&mut self) -> Result<publication::StoppedWorkers, Stop> {
        let Some(inventory) = &mut self.native_publication else {
            return Err(self.unsupported(RequirementKind::Native(
                "native publication inventory is absent",
            )));
        };
        let held = self
            .host
            .transport
            .hold_all(&mut self.host.local, inventory);
        let members: Vec<_> = inventory.bindings().map(|binding| binding.pe).collect();
        if inventory.require_all_held(&held).is_err() {
            self.host
                .transport
                .fail_stopped("native source services lack actual held workers");
        }
        let mut services = Vec::with_capacity(members.len());
        for pe in members {
            match inventory.open_services(&held, pe) {
                Ok(service) => services.push(service),
                Err(_) => self
                    .host
                    .transport
                    .fail_stopped("native source Host session admission refused"),
            }
        }
        if self.host.begin_services(services).is_err() {
            self.host
                .transport
                .fail_stopped("native source Host sessions already active");
        }
        Ok(held)
    }

    fn release_native_services(&mut self, held: publication::StoppedWorkers) {
        let inventory = self
            .native_publication
            .as_mut()
            .expect("held native inventory");
        for services in self.host.end_services() {
            if inventory.close_services(services).is_err() {
                self.host
                    .transport
                    .fail_stopped("native Host service did not actually finish");
            }
        }
        self.host
            .transport
            .release(&mut self.host.local, inventory, held);
    }

    pub(in crate::machine::engine) fn native_source_pe(
        &mut self,
        binding: publication::WorkerBinding,
    ) -> Step {
        if !self.host.select_native_service(binding.worker) {
            return Err(self.unsupported(RequirementKind::Native(
                "source PE has no held physical Host service owner",
            )));
        }
        if binding.pe != self.current {
            if !matches!(self.peers.get(binding.pe), Some(Peer::Parked(_))) {
                return Err(self.unsupported(RequirementKind::Native(
                    "source PE reset/rebind ownership is not active",
                )));
            }
            self.switch_to(binding.pe);
        }
        self.device_lines = None;
        Ok(())
    }

    /// Execute one bounded round on fixed physical workers and settle every
    /// reached source boundary while all actual workers are recovered and held.
    /// No old direct-RAM execution or copied monitor/event state is used.
    ///
    /// # Safety
    /// The full shared_native_run RAM/control/publication contract applies.
    /// External DMA/device jobs and code/MMU writers are excluded or retain the
    /// canonical all-writer authority through this whole call. Host counter and
    /// IRQ delivery are qualified for these assigned workers. Reset/rebind,
    /// Device/MMIO completion, debug/PMU/AMX/scalable resources remain explicit
    /// refusals until their actual platform owners join this candidate. Calling
    /// this method does not enable production SMP or qualify original macOS.
    pub unsafe fn native_round(&mut self) -> Result<usize, Stop> {
        if let Some(pending) = &self.pending_device_read {
            return Err(pending.stop());
        }
        let bindings: Vec<_> = self
            .native_publication
            .as_ref()
            .map(|inventory| inventory.bindings().collect())
            .ok_or_else(|| {
                self.unsupported(RequirementKind::Native("native workers are not bound"))
            })?;
        if bindings.len() != self.peers.len()
            || self.peers.iter().enumerate().any(|(pe, peer)| {
                let cpu = match peer {
                    Peer::Running if pe == self.current => &self.cpu,
                    Peer::Parked(parked) => parked.cpu(),
                    Peer::Off => return false,
                    _ => return true,
                };
                !cpu.has_canonical_memory()
            })
        {
            return Err(self.unsupported(RequirementKind::Native(
                "native scheduler requires every assigned PE's actual canonical owner",
            )));
        }
        let held = self.hold_native_services()?;
        // Serial fair-share lag cannot represent concurrently executing cores.
        // This lane observes the qualified common host counter without drift.
        self.clock.follow_host();
        let current = bindings
            .iter()
            .find(|binding| binding.pe == self.current)
            .copied()
            .ok_or_else(|| {
                self.unsupported(RequirementKind::Native(
                    "current PE has no assigned physical worker",
                ))
            })?;
        self.native_source_pe(current)?;
        self.take_starts()?;
        for binding in &bindings {
            if matches!(self.peers[binding.pe], Peer::Off) {
                continue;
            }
            self.native_source_pe(*binding)?;
            let now = self.now();
            self.poll_devices(now)?;
            self.take_starts()?;
            if let Some(reset) = self.devices.take_reset() {
                return Err(Stop::Reset(reset));
            }
            if !self.ready(binding.pe, now) {
                continue;
            }
            self.wake()?;
            self.deliver_interrupts();
            self.sync_monitor();
            let debug = self.debug_mode();
            if debug.breakpoints || debug.step || self.cpu.pstate.pacm || self.cpu.pstate.btype != 0
            {
                return Err(self.unsupported(RequirementKind::Native(
                    "native debug/single-step/PACM/guarded-branch entry is not joined",
                )));
            }
            if !self.cpu.pc.is_multiple_of(4) {
                let mut exception = crate::machine::cpu::Exception::synchronous(
                    crate::machine::exception::Class::PcAlignment,
                    0,
                    self.cpu.pc,
                );
                exception.fault_address = Some(self.cpu.pc);
                self.take(exception);
            } else if self.cpu.pstate.il {
                self.take(crate::machine::cpu::Exception::undefined(self.cpu.pc));
            }
            if self.breakpoints.binary_search(&self.cpu.pc).is_ok() {
                return Err(Stop::Breakpoint(self.cpu.pc));
            }
        }
        self.release_native_services(held);
        let preparation_refused = self.unsupported(RequirementKind::Native(
            "checked native source/control preparation refused before execution",
        ));
        let cohort = self
            .native_cohort(&bindings, true)
            .map_err(|_| preparation_refused)?;
        let expected: Vec<_> = cohort
            .frames
            .iter()
            .map(|frame| frame.identity().pe)
            .collect();
        let reports = {
            let host = cohort.host;
            host.transport
                .execute(&mut host.local, cohort.inventory, cohort.frames)
        };
        let held = self.hold_native_services()?;
        if reports.len() != expected.len() {
            self.host
                .transport
                .fail_stopped("native transport returned an incomplete actual cohort");
        }
        let mut pending_read = None;
        let mut seen = Vec::with_capacity(reports.len());
        for mut report in reports {
            let Some(settlement) = report.settlement.take() else {
                self.host
                    .transport
                    .fail_stopped("native source report has no actual recovered frame authority");
            };
            if !expected.contains(&settlement.binding.pe) || seen.contains(&settlement.binding.pe) {
                self.host
                    .transport
                    .fail_stopped("native source report has duplicate/wrong PE authority");
            }
            seen.push(settlement.binding.pe);
            if matches!(
                settlement.source_failure,
                Some(policy::Failure::DeviceRead { .. })
            ) {
                self.validate_native_source(&settlement)?;
                if pending_read.is_some() {
                    return Err(self.unsupported(RequirementKind::Native(
                        "multiple concurrent device-read continuations are not yet admitted",
                    )));
                }
                pending_read = Some(settlement.into_read());
            } else {
                self.settle_native_source(settlement)?;
            }
        }
        if let Some(read) = pending_read {
            return Err(self.queue_device_read(read, held));
        }
        self.release_native_services(held);
        Ok(expected.len())
    }

    fn validate_native_source(&mut self, settlement: &native_run::Settlement) -> Step {
        if !Arc::ptr_eq(&settlement.machine, &self.native_memory_identity)
            || self.native_publication.as_ref().is_none_or(|inventory| {
                inventory
                    .require_recovered(settlement.binding, settlement.generation)
                    .is_err()
            })
        {
            return Err(self.unsupported(RequirementKind::Native(
                "stale/foreign native source settlement",
            )));
        }
        self.native_source_pe(settlement.binding)?;
        if self.cpu.pc != settlement.pc || self.cpu.retired != settlement.retired {
            return Err(self.unsupported(RequirementKind::Native(
                "native source frame changed before stopped settlement",
            )));
        }
        if settlement.status.is_err() {
            return Err(self.unsupported(RequirementKind::Native(
                "native target/context/return finalization refused",
            )));
        }
        self.statistics.blocks += 1;
        self.cpu.pstate.btype = 0;
        self.sync_monitor();
        Ok(())
    }

    fn settle_native_source(&mut self, settlement: native_run::Settlement) -> Step {
        self.validate_native_source(&settlement)?;
        if let Some(fault) = settlement.memory_fault {
            return match settlement.source_failure {
                Some(policy::Failure::Fault {
                    request,
                    address,
                    access,
                    fault: source_fault,
                    ..
                }) => self.data_abort(
                    address,
                    source_fault,
                    fault_write(fault.access, request.operation, access),
                    false,
                ),
                _ if fault.status == MemoryStatus::Alignment => {
                    let Some(word) = settlement.fault_word else {
                        return Err(self.unsupported(RequirementKind::Native(
                            "checked alignment fault lacks its exact source instruction",
                        )));
                    };
                    if super::super::stack_based(word)
                        && self.stack_alignment_checked()
                        && !self.cpu.state.sp.is_multiple_of(16)
                    {
                        self.take(crate::machine::cpu::Exception::synchronous(
                            crate::machine::exception::Class::SpAlignment,
                            0,
                            self.cpu.pc,
                        ));
                        Ok(())
                    } else {
                        let exclusive =
                            stela_compiler::block::decode_system_mode_instruction(
                                stela_compiler::GuestAddress(self.cpu.pc),
                                word,
                            )
                            .ok()
                            .flatten()
                            .and_then(|instruction| match instruction.operation {
                                super::super::SystemOperation::Exclusive(Ok(
                                    stela_compiler::aarch64::exclusive::Operand::Transfer {
                                        base,
                                        kind,
                                        ..
                                    },
                                )) if self.read_register(base) == fault.address => Some(matches!(
                                    kind,
                                    stela_compiler::aarch64::exclusive::Kind::Store { .. }
                                )),
                                _ => None,
                            });
                        if let Some(write) = exclusive {
                            return self.alignment_fault(fault.address, match fault.access {
                                stela_compiler::context::memory::FaultAccess::Read => false,
                                stela_compiler::context::memory::FaultAccess::Write => true,
                                stela_compiler::context::memory::FaultAccess::OriginalSource => write,
                            });
                        }
                        let accesses = self.data_accesses(self.cpu.pc, word).map_err(|detail| {
                            self.unsupported(RequirementKind::Instruction {
                                word,
                                detail: detail.into(),
                            })
                        })?;
                        let Some((access, _)) = accesses
                            .iter()
                            .find(|(access, _)| access.address == fault.address)
                        else {
                            return Err(self.unsupported(RequirementKind::Native(
                                "checked alignment fault does not match its original source access",
                            )));
                        };
                        let write = match fault.access {
                            stela_compiler::context::memory::FaultAccess::Read => false,
                            stela_compiler::context::memory::FaultAccess::Write => true,
                            stela_compiler::context::memory::FaultAccess::OriginalSource => {
                                access.write && !access.read
                            }
                        };
                        self.alignment_fault(fault.address, write)
                    }
                }
                _ => Err(self.unsupported(RequirementKind::Native(
                    "native Device/MMIO or unsupported source memory service remains unexecuted",
                ))),
            };
        }
        let Some(super::super::NativeExit::Exit { kind, .. }) = settlement.native else {
            return Err(self.unsupported(RequirementKind::Native(
                "native Host fault is terminal, not an ARM memory completion",
            )));
        };
        match ExitKind::try_from(kind) {
            Ok(
                ExitKind::Fallthrough
                | ExitKind::Direct
                | ExitKind::Indirect
                | ExitKind::Call
                | ExitKind::Return,
            ) => Ok(()),
            Ok(ExitKind::System) => {
                self.statistics.system_exits += 1;
                use super::super::{Synchronization, SystemOperation};
                if stela_compiler::block::decode_system_mode_instruction(
                    stela_compiler::GuestAddress(self.cpu.pc),
                    settlement.terminal,
                )
                .is_ok_and(|instruction| {
                    instruction.is_some_and(|instruction| {
                        matches!(
                            instruction.operation,
                            SystemOperation::Synchronization(
                                Synchronization::DataCompletion { .. }
                                    | Synchronization::StoreBypassBarrier { .. }
                            )
                        )
                    })
                }) {
                    // All native owners are actually held after their CPU
                    // fences; fence this PE and BSP helper copyout as well.
                    // External Device/DMA/MCC completion remains unqualified.
                    self.host.memory_barrier();
                }
                completing(self, |machine| {
                    machine.system_instruction(settlement.terminal)
                })
            }
            Ok(ExitKind::PointerAuthentication) => completing(self, |machine| {
                machine.pointer_authentication(settlement.terminal)
            }),
            _ => Err(self.unsupported(RequirementKind::Instruction {
                word: settlement.terminal,
                detail: alloc::string::String::from(
                    "source boundary is unexecuted; native AMX/FP/trap service is not joined",
                ),
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_fault_access_overrides_original_atomic_or_write_intent() {
        use crate::memory::{backing::AccessKind, domain::DataOperation};
        use stela_compiler::context::memory::FaultAccess;
        for operation in [
            DataOperation::Atomic,
            DataOperation::Exclusive,
            DataOperation::Ordered,
            DataOperation::Ordinary,
        ] {
            assert!(!fault_write(
                FaultAccess::Read,
                operation,
                AccessKind::Write
            ));
            assert!(fault_write(FaultAccess::Write, operation, AccessKind::Read));
            assert_eq!(
                fault_write(FaultAccess::OriginalSource, operation, AccessKind::Write),
                operation != DataOperation::Atomic
            );
            assert!(!fault_write(
                FaultAccess::OriginalSource,
                operation,
                AccessKind::Read
            ));
        }
    }
    #[test]
    fn refused_source_clear_does_not_retire_or_change_the_actual_cpu_prefix() {
        let (mut machine, ram, events) = super::super::tests::machine();
        machine
            .install_shared_memory_for_processors(ram, &events)
            .unwrap();
        let memory = machine.cpu.canonical_memory.as_mut().unwrap();
        // Terminal corrupted-owner finalization is an implementation refusal,
        // never an ARM source fault or a completed CLREX.
        let failed = unsafe { memory.memory.with_checked_view(|view| view.version = 0) };
        assert_eq!(failed, Err(MemoryStatus::Domain));
        let before = (
            machine.cpu.state.clone(),
            machine.cpu.pc,
            machine.cpu.retired,
        );
        const CLREX: u32 = 0xd503305f;
        assert!(matches!(
            completing(&mut machine, |machine| machine.system_instruction(CLREX)),
            Err(Stop::Unsupported(_))
        ));
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
