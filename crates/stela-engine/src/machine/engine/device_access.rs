//! One recovered cohort, one stop, and ordered consuming bus accesses.
use super::*;
use shared_memory::RecoveredDeviceAccess;

/// The most instructions a machine completes as device sites: one past
/// them takes the fault path, as before it learned any.
const DEVICE_SITES: usize = 4096;
/// A device site whose accesses reach RAM this many times, and eight times
/// as often as a device, is left to native code again for good.
const RAM_SITE_ACCESSES: u32 = 64;

/// An instruction that reached a device register from native code. The
/// engine completes it, as the fault would have, without the fault: blocks
/// end before it, and the block at it is a stub that exits to the engine
/// (`Machine::complete_device_site`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct DeviceSite {
    /// The engine completed a device access there, and its access reached
    /// RAM instead (run natively, one instruction).
    device: u32,
    ram: u32,
    /// Left to native code again: it reaches RAM far more often.
    retired: bool,
}

/// A load or store the engine completes at a device site: its address,
/// direction and the bytes from it it reaches. Others run natively.
struct SiteAccess {
    address: u64,
    write: bool,
    bytes: u64,
}

impl<H: Host, D: Devices> Machine<H, D> {
    /// The physical address of the instruction at `pc` of block `index`,
    /// unless the block is a single instruction's.
    pub(super) fn device_site_of(&self, index: usize, pc: u64) -> Option<u64> {
        let block = &self.code.blocks[index];
        (!self.variants[block.variant.0 as usize].single)
            .then(|| block.physical.wrapping_add(pc.wrapping_sub(block.pc)))
    }

    /// Learn that the instruction at `physical` reached a device register,
    /// after the engine completed it: its page's blocks compile again,
    /// ending before it.
    pub(super) fn learn_device_site(&mut self, physical: u64) {
        if self.device_sites.contains_key(&physical) || self.device_sites.len() >= DEVICE_SITES {
            return;
        }
        self.device_sites.insert(physical, DeviceSite::default());
        self.invalidate_code_page(physical);
    }

    /// Whether the instruction at `physical` is a device site.
    pub(super) fn device_site(&self, physical: u64) -> bool {
        !self.device_sites.is_empty()
            && self
                .device_sites
                .get(&physical)
                .is_some_and(|site| !site.retired)
    }

    /// The bytes of the window at `physical` before its first device site,
    /// when one lies in its first `bytes` past its first instruction.
    pub(super) fn before_device_site(&self, physical: u64, bytes: usize) -> Option<usize> {
        if self.device_sites.is_empty() {
            return None;
        }
        self.device_sites
            .range(physical + INSTRUCTION..physical + bytes as u64)
            .find(|(_, site)| !site.retired)
            .map(|(&site, _)| (site - physical) as usize)
    }

    /// Whether the fetch page holding `physical` has a device site: its
    /// blocks end in ways no entry context names, so the store neither gives
    /// nor takes them.
    pub(super) fn page_has_device_sites(&self, physical: u64) -> bool {
        let frame = physical & !(FETCH_PAGE - 1);
        !self.device_sites.is_empty()
            && self
                .device_sites
                .range(frame..frame + FETCH_PAGE)
                .any(|(_, site)| !site.retired)
    }

    /// Whether block `index`, exiting with a System exit at `pc`, is a device
    /// site's stub. The block says so, not this PE's sites: on a shared
    /// board a PE runs the stubs of sites other PEs learnt.
    pub(super) fn device_stub(&self, index: usize, pc: u64) -> bool {
        let block = &self.code.blocks[index];
        block.device_stub && block.pc == pc
    }

    /// Install the stub of the device site at `pc` and `physical`: native
    /// code that exits to the engine at once, with the site's word, admitted,
    /// as its one instruction.
    pub(super) fn install_device_stub(
        &mut self,
        pc: u64,
        physical: u64,
        variant: Variant,
        source: &[u8],
    ) -> Result<Fetched, Stop> {
        let block = stela_compiler::block::CompiledBlock {
            native: stela_compiler::NativeBlock {
                x86_64_code: chain::direct_exit(GuestAddress(pc), ExitKind::System).to_vec(),
                source_map: alloc::vec![(GuestAddress(pc), 0)],
                // A device stub is never stored.
                relocations: None,
            },
            source_bytes: INSTRUCTION as usize,
            direct_exits: Vec::new(),
            fault_recovery: Vec::new(),
            self_loop: false,
        };
        let preparation = self.preparation(variant);
        let emission = Arc::new(super::stored::Emission::new(
            source[..INSTRUCTION as usize].to_vec(),
            block,
            preparation,
        ));
        self.installing_stub = true;
        let installed = self.install(
            pc,
            physical,
            variant,
            source,
            recovery::Template::compiled(emission),
        );
        self.installing_stub = false;
        installed
    }

    /// The access the instruction `word` at `pc` makes, when the engine can
    /// complete it at a device as the fault path would: a scalar or pair
    /// integer load or store through a register other than SP, which is not
    /// unprivileged (LDTR, STTR).
    fn site_access(&self, pc: u64, word: u32) -> Option<SiteAccess> {
        // LDTR*, STTR*: their permission checks are EL0's.
        if word & 0x3b20_0c00 == 0x3800_0800 {
            return None;
        }
        let instruction = Decoder.lift(GuestAddress(pc), word).ok()?;
        let base = |address: &ScalarLoadAddress| match *address {
            ScalarLoadAddress::Immediate { base, .. }
            | ScalarLoadAddress::RegisterOffset { base, .. } => Some(base),
            ScalarLoadAddress::Literal { .. } => None,
        };
        let (address, write, bytes, base) =
            if let Some(load) = ScalarLoad::from_instruction(&instruction) {
                let address = load.address();
                (
                    self.scalar_address(address).0,
                    false,
                    u64::from(load.bytes()),
                    base(&address)?,
                )
            } else if let Some(store) = ScalarStore::from_instruction(&instruction) {
                let address = store.address();
                (
                    self.scalar_address(address).0,
                    true,
                    u64::from(store.bytes()),
                    base(&address)?,
                )
            } else if let Operation::MemoryPair {
                transfer,
                bytes,
                base,
                displacement,
                mode,
                ..
            } = instruction.operation
            {
                let write = matches!(transfer, MemoryTransfer::Store);
                let address = self.immediate_address(base, displacement, mode);
                (address, write, 2 * u64::from(bytes), base)
            } else {
                return None;
            };
        (base != Register::Sp).then_some(SiteAccess {
            address,
            write,
            bytes,
        })
    }

    /// Complete the instruction at the device site `pc`, block `index`'s
    /// only one, as its native fault would have: when its access reaches a
    /// device, through [`Self::device_access`]; else (RAM, a fault, a
    /// watchpoint, or a form the engine does not complete) by running it
    /// natively as a block of its own, which takes that path itself.
    pub(super) fn complete_device_site(&mut self, index: usize, pc: u64) -> Step {
        let physical = self.code.blocks[index].physical;
        let word = self.code.blocks[index].terminal;
        let access = self.site_access(pc, word);
        let device = access.and_then(|access| {
            let kind = if access.write {
                mmu::Access::Write
            } else {
                mmu::Access::Read
            };
            let Translated::Mapped(translation) = self.translate_data(access.address, kind) else {
                return None;
            };
            let last = access.address.wrapping_add(access.bytes - 1);
            let page = translation.physical & !(FETCH_PAGE - 1);
            let ram = self.host.read_ram(page, &mut [0]);
            (!ram && !self.watch.overlaps(access.address, last))
                .then_some((access, translation.physical))
        });
        let site = self.device_sites.entry(physical).or_default();
        match device {
            Some((access, target)) => {
                site.device = site.device.saturating_add(1);
                self.outside_run(|machine| {
                    machine.completing(pc, |machine| {
                        machine.device_access(word, access.address, target, access.write)
                    })
                })
            }
            None => {
                site.ram = site.ram.saturating_add(1);
                if site.ram >= RAM_SITE_ACCESSES && site.ram / 8 > site.device {
                    site.retired = true;
                    self.invalidate_code_page(physical);
                }
                self.run_one_natively(pc)
            }
        }
    }

    /// Run the instruction at `pc` as a block of its own, as the step of a
    /// single instruction does.
    fn run_one_natively(&mut self, pc: u64) -> Step {
        match self.fetch_block(pc, true)? {
            Fetched::Block(index) => self.execute(index, 0),
            Fetched::Exception(exception) => {
                self.take(exception);
                Ok(())
            }
            Fetched::Checked(word) => self.checked_instruction(pc, word),
        }
    }

    pub fn pending_native_device_access_count(&self) -> usize {
        usize::from(self.pending_device_read.is_some() || self.pending_device_write.is_some())
            + self.pending_device_tail.len()
    }
    /// Diagnostic only; the frame/generation remains private.
    pub fn pending_native_device_access(&self) -> Option<Stop> {
        self.pending_device_read
            .as_ref()
            .map(device_read::Pending::stop)
            .or_else(|| {
                self.pending_device_write
                    .as_ref()
                    .map(device_write::Pending::stop)
            })
    }
}
impl<H: Host, T: NativeTransport, D: Devices> Machine<ServiceHost<H, T>, D> {
    pub(super) fn queue_device_accesses(
        &mut self,
        accesses: Vec<RecoveredDeviceAccess>,
        held: publication::StoppedWorkers,
    ) -> Stop {
        self.pending_device_tail = accesses.into();
        self.queue_next_device_access(held)
    }
    fn queue_next_device_access(&mut self, held: publication::StoppedWorkers) -> Stop {
        match self
            .pending_device_tail
            .pop_front()
            .expect("actual pending cohort")
        {
            RecoveredDeviceAccess::Read(read) => self.queue_device_read(read, held),
            RecoveredDeviceAccess::Write(write) => self.queue_device_write(write, held),
        }
    }
    pub(super) fn finish_device_access(&mut self, held: publication::StoppedWorkers) -> Step {
        if self.pending_device_tail.is_empty() {
            self.release_native_services(held);
            Ok(())
        } else {
            Err(self.queue_next_device_access(held))
        }
    }
    /// Consume only the current front; no caller-supplied request,
    /// recovered frame, data or worker generation is accepted.
    ///
    /// # Safety
    /// The complete closed synchronous native producer contract remains valid
    /// through every pending request. Each backend keeps its prepared effect
    /// and ACK inside the same real worker generation.
    pub unsafe fn complete_native_device_access(&mut self) -> Step {
        if self.pending_device_read.is_some() {
            // SAFETY: same pending source and producer contract.
            unsafe { self.complete_device_read() }
        } else if self.pending_device_write.is_some() {
            // SAFETY: same pending source and producer contract.
            unsafe { self.complete_device_write() }
        } else {
            Err(self.unsupported(RequirementKind::Native(
                "no recovered device access is pending",
            )))
        }
    }
}

#[cfg(test)]
mod tests;
