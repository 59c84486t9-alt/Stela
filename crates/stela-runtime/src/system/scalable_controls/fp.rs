//! CPACR_EL1 storage shared by FP/AdvSIMD and scalable controls.

use super::{
    A64_FP_ISS, Error, ExceptionLevel, FP_EC, FPEN_SHIFT, Origin, SMEN_SHIFT, Snapshot,
    SystemState, ZEN_SHIFT, check_state, disabled, features, trap,
};
use stela_compiler::GuestAddress;

/// The software behavior chosen for CPACR fields of absent features. The
/// scalable owner keeps its writable readback; a new ordinary FP owner makes
/// absent SMEN/ZEN RAZ/WI.
#[derive(Clone, Copy)]
enum AbsentFieldPolicy {
    WritableReadback,
    RazWi,
}

pub struct FpControlOwner<'id> {
    ids: &'id Snapshot,
    cpacr_el1: u64,
    generation: u64,
    absent_fields: AbsentFieldPolicy,
}

impl<'id> FpControlOwner<'id> {
    pub fn new_declared_el10(ids: &'id Snapshot, cpacr_el1: u64) -> Result<Self, Error> {
        Self::declared(ids, cpacr_el1, AbsentFieldPolicy::RazWi)
    }

    pub(super) fn new_declared_scalable_el10(
        ids: &'id Snapshot,
        cpacr_el1: u64,
    ) -> Result<Self, Error> {
        Self::declared(ids, cpacr_el1, AbsentFieldPolicy::WritableReadback)
    }

    fn declared(
        ids: &'id Snapshot,
        cpacr_el1: u64,
        absent_fields: AbsentFieldPolicy,
    ) -> Result<Self, Error> {
        if ids.provenance().origin() != Origin::DeclaredGuest {
            return Err(Error::CapturedImplementationUnavailable);
        }
        features::check_control_subset(ids)?;
        if matches!(absent_fields, AbsentFieldPolicy::RazWi)
            && cpacr_el1 & Self::absent_scalable_fields(ids)? != 0
        {
            return Err(Error::InitialRazReadback);
        }
        Ok(Self {
            ids,
            cpacr_el1,
            generation: 0,
            absent_fields,
        })
    }

    pub const fn identification_snapshot(&self) -> &Snapshot {
        self.ids
    }

    pub const fn cpacr_el1(&self) -> u64 {
        self.cpacr_el1
    }

    /// Advances for successful CPACR writes, including same-value writes.
    /// A scalable wrapper separately tracks its combined CPACR/SMCR generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Evaluate the CheckFPEnabled subset for the current EL0/EL1 state; the
    /// snapshot shows EL2 and EL3 absent. Returns the trap decision; the caller
    /// delivers it.
    pub fn check_fp_enabled(&self, state: &SystemState, pc: GuestAddress) -> Result<(), Error> {
        check_state(state)?;
        self.check_fp_at_el(state.current_el(), pc)
    }

    /// CPACR writes require AArch64 EL1. Optional consumers follow the same
    /// subset as ScalableControlOwner. New generic owners make absent SMEN/ZEN
    /// RAZ/WI, existing scalable owners keep their writable readback, and other
    /// reserved bits stay writable.
    pub fn prepare_write<'loan>(
        &'loan mut self,
        value: u64,
        state: &'loan SystemState,
    ) -> Result<PreparedWrite<'loan, 'id>, Error> {
        check_state(state)?;
        if state.current_el() != ExceptionLevel::El1 {
            return Err(Error::Undefined);
        }
        let value = match self.absent_fields {
            AbsentFieldPolicy::WritableReadback => value,
            AbsentFieldPolicy::RazWi => value & !Self::absent_scalable_fields(self.ids)?,
        };
        let next = self.next_generation()?;
        Ok(PreparedWrite {
            owner: self,
            value,
            next,
            _state: state,
        })
    }

    fn absent_scalable_fields(ids: &Snapshot) -> Result<u64, Error> {
        let mut mask = 0;
        if features::sme(ids)? == 0 {
            mask |= super::ENABLE_MASK << SMEN_SHIFT;
        }
        if !features::sve(ids)? {
            mask |= super::ENABLE_MASK << ZEN_SHIFT;
        }
        Ok(mask)
    }

    pub(super) fn check_fp_at_el(&self, el: ExceptionLevel, pc: GuestAddress) -> Result<(), Error> {
        if disabled(self.cpacr_el1, FPEN_SHIFT, el) {
            return Err(trap(pc, FP_EC, A64_FP_ISS));
        }
        Ok(())
    }

    pub(super) fn next_generation(&self) -> Result<u64, Error> {
        self.generation
            .checked_add(1)
            .ok_or(Error::GenerationExhausted)
    }

    /// Only the two prepared-write owners call this after their complete
    /// preflight. No fallible step follows the first architectural mutation.
    pub(super) fn commit_prepared(&mut self, value: u64, next: u64) {
        self.cpacr_el1 = value;
        self.generation = next;
    }
}

pub struct PreparedWrite<'loan, 'id> {
    owner: &'loan mut FpControlOwner<'id>,
    value: u64,
    next: u64,
    _state: &'loan SystemState,
}

impl PreparedWrite<'_, '_> {
    pub fn commit(self) -> super::RequalificationRequired {
        self.owner.commit_prepared(self.value, self.next);
        super::RequalificationRequired {
            generation: self.next,
        }
    }
}
