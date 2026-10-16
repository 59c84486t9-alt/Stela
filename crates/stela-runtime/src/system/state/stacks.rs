//! Inactive stack pointers. The active one lives only in `GuestState::sp`.
use super::{StackBank, StateError};
use stela_compiler::GuestState;

const STACK_BANK_COUNT: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InactiveStacks {
    values: [Option<u64>; STACK_BANK_COUNT],
}

impl InactiveStacks {
    /// Base constructor: EL0/EL1 are present, exactly the selected one is active.
    pub(super) fn lower(active: StackBank, inactive: u64) -> Self {
        let mut values = [None; STACK_BANK_COUNT];
        let other = match active {
            StackBank::El0 => StackBank::El1,
            StackBank::El1 => StackBank::El0,
            StackBank::El2 | StackBank::El3 => unreachable!("base constructor checks lower mode"),
        };
        values[other.index()] = Some(inactive);
        Self { values }
    }

    /// Additional fresh banks are explicit inputs. An absent bank is None;
    /// initialization never creates an architectural zero for missing storage.
    pub(super) fn initialize_higher(&mut self, el2: Option<u64>, el3: Option<u64>) {
        self.values[StackBank::El2.index()] = el2;
        self.values[StackBank::El3.index()] = el3;
    }

    pub(super) fn read(
        &self,
        active: StackBank,
        requested: StackBank,
        registers: &GuestState,
    ) -> Result<u64, StateError> {
        if self.values[active.index()].is_some() {
            return Err(StateError::StackOwnership);
        }
        if requested == active {
            Ok(registers.sp)
        } else {
            self.values[requested.index()].ok_or(StateError::UnavailableStack(requested))
        }
    }

    pub(super) fn read_inactive(
        &self,
        active: StackBank,
        requested: StackBank,
    ) -> Result<u64, StateError> {
        if active == requested || self.values[active.index()].is_some() {
            return Err(StateError::StackOwnership);
        }
        self.values[requested.index()].ok_or(StateError::UnavailableStack(requested))
    }

    pub(super) fn write_inactive(
        &mut self,
        active: StackBank,
        requested: StackBank,
        value: u64,
    ) -> Result<(), StateError> {
        if requested == active || self.values[active.index()].is_some() {
            return Err(StateError::StackOwnership);
        }
        let slot = self.values[requested.index()]
            .as_mut()
            .ok_or(StateError::UnavailableStack(requested))?;
        *slot = value;
        Ok(())
    }

    /// Every failure precedes mutation. There is one actual active SP exchange,
    /// including lower-to-higher, higher-to-lower and higher-to-higher paths.
    pub(super) fn select(
        &mut self,
        active: StackBank,
        destination: StackBank,
        registers: &mut GuestState,
    ) -> Result<(), StateError> {
        if self.values[active.index()].is_some() {
            return Err(StateError::StackOwnership);
        }
        if destination == active {
            return Ok(());
        }
        let selected =
            self.values[destination.index()].ok_or(StateError::UnavailableStack(destination))?;
        self.values[active.index()] = Some(registers.sp);
        self.values[destination.index()] = None;
        registers.sp = selected;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
