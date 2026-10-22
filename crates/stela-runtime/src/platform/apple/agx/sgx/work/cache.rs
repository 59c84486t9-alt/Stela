//! Actual SGX configuration owner for the stock buffer-cache selector.
//! Native words become known only after source stores; no reset readback,
//! auxiliary-cache data execution or physical flush completion is invented.

use super::{FirmwareWork, Register};
use crate::platform::apple::agx::sgx::resources::FirmwareResources;
use crate::platform::apple::agx::work_decode::{
    Frame, Submission,
    cache_pool::{Access, CONFIGURATION, RECORDS, SELECTORS},
    cl,
    ownership::Identity,
    render_context::Program,
    render_resources,
    resources::{Lease, Policy},
};
use crate::platform::dma::Port;
use alloc::vec::Vec;
use core::cell::Cell;

#[derive(Debug, Default)]
pub(super) struct Registers {
    pub(super) configuration: [Option<u64>; RECORDS],
    // CL118e0 is the existing physical Register::Resource state.
    render_selector: [Option<u64>; 2],
    owners: [[Option<Owner>; 6]; 3],
    pool: Option<Identity>,
}
#[derive(Debug)]
struct Owner {
    program: Program,
    submission: Submission,
    identity: Identity,
}
impl Registers {
    fn owner(&self, lease: Lease) -> Result<&Option<Owner>, &'static str> {
        self.owners
            .get(usize::from(lease.pipe))
            .and_then(|pipe| pipe.get(usize::from(lease.slot)))
            .ok_or("GFX buffer-cache native owner exceeds its execution-slot table")
    }
    fn check_owner(
        &self,
        program: Program,
        sub: &Submission,
        lease: Lease,
        identity: &Identity,
    ) -> Result<(), &'static str> {
        if self.owner(lease)?.as_ref().is_some_and(|old| {
            old.program != program || old.submission != *sub || !old.identity.same(identity)
        }) {
            return Err("GFX buffer-cache native slot still belongs to its committed owner");
        }
        Ok(())
    }
    fn bind_owner(
        &mut self,
        program: Program,
        sub: &Submission,
        lease: Lease,
        identity: &Identity,
        pool: &Identity,
    ) -> Result<(), &'static str> {
        self.check_owner(program, sub, lease, identity)?;
        if self.pool.as_ref().is_some_and(|old| !old.same(pool)) {
            return Err("GFX buffer-cache native bank belongs to another initialized private pool");
        }
        self.pool.get_or_insert_with(|| pool.clone());
        self.owners[usize::from(lease.pipe)][usize::from(lease.slot)].get_or_insert_with(|| {
            Owner {
                program,
                submission: sub.clone(),
                identity: identity.clone(),
            }
        });
        Ok(())
    }
    pub(super) fn active(&self) -> bool {
        self.owners.iter().flatten().any(Option::is_some)
    }
    pub(super) fn check_cancel(&self, lease: Lease) -> Result<(), &'static str> {
        if self.owner(lease)?.is_some() {
            return Err("GFX buffer-cache native drain/abort effects are not qualified");
        }
        Ok(())
    }
}
#[cfg(test)]
impl Registers {
    pub(super) fn first_configuration(&self) -> Option<u64> {
        self.configuration[0]
    }
    pub(super) fn render_selector(&self, pipe: usize) -> Option<u64> {
        self.render_selector[pipe]
    }
}
pub(super) fn native_words() -> Vec<(u32, u32)> {
    (0..RECORDS as u32)
        .map(|i| (CONFIGURATION + i * 8, 8))
        .chain(SELECTORS.into_iter().map(|p| (p, 8)))
        .collect()
}
#[derive(Clone, Copy)]
pub enum PreparedResources<'a> {
    Cl(&'a cl::attachments::Attachments),
    Render(&'a render_resources::Attachments),
}
impl<'a> PreparedResources<'a> {
    fn identity(
        self,
    ) -> Result<(&'a Submission, &'a Frame, Lease, Policy, &'a Identity), &'static str> {
        match self {
            Self::Cl(attachments) => Ok(attachments.held_parameters()?.identity()),
            Self::Render(attachments) => {
                let parameters = attachments.held_parameters()?;
                let (sub, frame, lease, policy) = parameters.identity();
                Ok((sub, frame, lease, policy, parameters.phase_identity()))
            }
        }
    }
}
pub struct CacheAccess<'a, 'p, 'm> {
    owner: &'a FirmwareWork,
    port: &'a mut Port<'p, 'm>,
    prepared: PreparedResources<'a>,
    program: Cell<Option<Program>>,
}
impl FirmwareWork {
    pub fn buffer_cache_access<'a, 'p, 'm>(
        &'a self,
        resources: &'a FirmwareResources,
        prepared: PreparedResources<'a>,
        port: &'a mut Port<'p, 'm>,
    ) -> Result<CacheAccess<'a, 'p, 'm>, &'static str> {
        // Qualify the actual shared SGX and MCC instances, not just geometry.
        self.attachment_access(resources, port)?;
        Ok(CacheAccess {
            owner: self,
            port,
            prepared,
            program: Cell::new(None),
        })
    }
}
impl Access for CacheAccess<'_, '_, '_> {
    fn check_available(&self) -> Result<(), &'static str> {
        self.owner.available()
    }
    fn check_owner(
        &self,
        program: Program,
        submission: &Submission,
        lease: Lease,
        pool: &Identity,
    ) -> Result<(), &'static str> {
        self.owner.available()?;
        let (sub, frame, held_lease, policy, identity) = self.prepared.identity()?;
        if sub != submission
            || lease != held_lease
            || policy != self.owner.policy
            || program.policy() != policy
        {
            return Err("GFX buffer-cache selector differs from its held source resources");
        }
        if self
            .owner
            .power
            .native
            .borrow()
            .work
            .source_program
            .is_some_and(|old| old != program)
        {
            return Err(
                "GFX buffer-cache selector belongs to another initialized firmware program",
            );
        }
        match self.prepared {
            PreparedResources::Cl(attachments) => {
                program.require_cl_parameters(attachments.held_parameters()?.selected_program())?;
                self.owner
                    .check_setup_owner(sub, frame, lease, policy, identity)
            }
            PreparedResources::Render(attachments) => {
                self.owner
                    .check_render_setup_owner(attachments.held_parameters()?)?;
                self.owner.check_render_context_program(program)
            }
        }?;
        let mut native = self.owner.power.native.borrow_mut();
        native
            .work
            .cache
            .bind_owner(program, sub, lease, identity, pool)?;
        native.work.source_program = Some(program);
        self.program.set(Some(program));
        Ok(())
    }
    fn owner_identity(&self) -> Result<Identity, &'static str> {
        Ok(self.prepared.identity()?.4.clone())
    }
    fn write_native(&mut self, offset: u32, value: u64) -> Result<(), &'static str> {
        let program = self
            .program
            .get()
            .ok_or("GFX buffer-cache native store has no qualified source program")?;
        let (sub, frame, lease, policy, identity) = self.prepared.identity()?;
        // Recheck the exact live setup at each fallible physical boundary.
        match self.prepared {
            PreparedResources::Cl(_) => self
                .owner
                .check_setup_owner(sub, frame, lease, policy, identity)?,
            PreparedResources::Render(attachments) => self
                .owner
                .check_render_setup_owner(attachments.held_parameters()?)?,
        }
        self.owner
            .power
            .native
            .borrow()
            .work
            .cache
            .check_owner(program, sub, lease, identity)?;
        let config = if (CONFIGURATION..CONFIGURATION + RECORDS as u32 * 8).contains(&offset)
            && (offset - CONFIGURATION).is_multiple_of(8)
        {
            if value & !0x07ff_03ff != 0 {
                return Err("GFX buffer-cache configuration has unknown native fields");
            }
            Some(((offset - CONFIGURATION) / 8) as usize)
        } else {
            None
        };
        if config.is_none() && SELECTORS.get(usize::from(lease.pipe)) != Some(&offset) {
            return Err("GFX buffer-cache selector targets another pipeline or native word");
        }
        self.owner.target_word(self.port, offset, 8, true)?;
        let mut native = self.owner.power.native.borrow_mut();
        if native.work.source_program.is_some_and(|old| old != program) {
            return Err("GFX buffer-cache native store changed initialized program");
        }
        if let Some(index) = config {
            native.work.cache.configuration[index] = Some(value);
        } else if lease.pipe == 2 {
            native.work.write(policy, Register::Resource, value)?;
        } else {
            native.work.cache.render_selector[usize::from(lease.pipe)] = Some(value);
        }
        native.work.source_program = Some(program);
        Ok(())
    }
    fn check_quiesced(
        &self,
        _program: Program,
        _submission: &Submission,
        _lease: Lease,
        _pool: &Identity,
    ) -> Result<(), &'static str> {
        self.owner.available()?;
        Err("GFX buffer-cache physical data/flush completion is not qualified")
    }
}
