//! Repeated scalable entry on one retained CPU.
use super::fixture::{Fixture, access};
use crate::{
    memory::{domain::MemoryThread, policy::MemoryControls},
    scalable::{
        ScalableState,
        leaf::{PreparedScalableLeaf, ScalableLeafExit},
    },
    system::{
        process_memory::{FixedProcessMemoryControls, ScalableExecutionError},
        scalable_controls::ScalableControlOwner,
        state::SystemState,
    },
};
use stela_compiler::{GuestState, context::ExecutionContext};

pub(super) struct RetainedEntry<'a> {
    access: ScalableControlOwner<'a>,
    controls: &'a FixedProcessMemoryControls,
    prepared: &'a PreparedScalableLeaf,
    system: &'a mut SystemState,
    registers: &'a mut GuestState,
    scalable: &'a mut ScalableState,
    memory: &'a mut MemoryThread<MemoryControls>,
    context: &'a mut ExecutionContext,
}
impl<'a> RetainedEntry<'a> {
    pub(super) fn new(fixture: &'a mut Fixture) -> Self {
        Self {
            access: access(
                &fixture.ids,
                fixture.sca16,
                fixture.cpacr,
                fixture.svl_bytes,
            ),
            controls: &fixture.controls,
            prepared: &fixture.prepared,
            system: &mut fixture.system,
            registers: &mut fixture.registers,
            scalable: &mut fixture.scalable,
            memory: &mut fixture.memory,
            context: &mut fixture.context,
        }
    }
    pub(super) fn execute(&mut self) -> Result<ScalableLeafExit, ScalableExecutionError> {
        // SAFETY: the exclusive fixture borrow keeps its pinned disjoint
        // backing, the snapshot, the domain and the fixed prepared source.
        // Native entry is synchronous, with no raw writer or state alias.
        unsafe {
            self.controls.execute_scalable_leaf(
                &self.access,
                self.prepared,
                self.system,
                self.registers,
                self.scalable,
                self.memory,
                self.context,
            )
        }
    }
}

#[test]
fn retained_owner_rechecks_actual_state_before_each_native_call() {
    use super::fixture::{LD1B_Z1_P0_X5, VL, banks};
    use crate::system::{process_memory::ProcessMemoryError, state::PSTATE_IL_MASK};
    use stela_compiler::TargetCpu;
    let mut fixture = Fixture::new(
        LD1B_Z1_P0_X5,
        TargetCpu::Baseline,
        TargetCpu::Baseline,
        None,
    );
    {
        let mut entry = RetainedEntry::new(&mut fixture);
        assert_eq!(entry.execute().unwrap(), ScalableLeafExit::Returned);
        let registers = entry.registers.clone();
        let before = banks(entry.registers, entry.scalable);
        let pstate = entry.system.pstate(entry.registers) | PSTATE_IL_MASK;
        entry
            .system
            .transition_pstate(entry.registers, pstate)
            .unwrap();
        assert!(matches!(
            entry.execute(),
            Err(ScalableExecutionError::MemoryAuthority {
                cause: ProcessMemoryError::IllegalExecutionState,
                ..
            })
        ));
        assert_eq!(*entry.registers, registers);
        assert_eq!(banks(entry.registers, entry.scalable), before);
        assert_eq!(entry.scalable.vector_length().bytes(), VL);
    }
}
