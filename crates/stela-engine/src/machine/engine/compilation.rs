//! Compiling, installing and patching blocks, and the exits native code takes
//! to the engine.

use super::*;

impl<H: Host, D: Devices> Machine<H, D> {
    pub(super) fn fetch_block(&mut self, pc: u64, single: bool) -> Result<Fetched, Stop> {
        let physical = match self.fetch_physical(pc) {
            Ok(physical) => physical,
            Err(Ok(exception)) => return Ok(Fetched::Exception(exception)),
            Err(Err(stop)) => return Err(stop),
        };
        let guarded = self.fetch_guarded(pc);
        let current = self.current_variant(single, guarded);
        let variant = self.page_variant(current, physical);
        let el = self.cpu.pstate.el | u8::from(self.cpu.pstate.guarded) << 4;
        let context = Variant {
            guarded_page: false,
            ..current
        };
        let contexts = self.contexts(el, context);
        self.chain.set_contexts(contexts);
        let slot = (pc / INSTRUCTION) as usize % JUMP_CACHE;
        if let Some(entry) = self.jump[slot]
            && entry.pc == pc
            && entry.physical == physical
            && entry.variant == variant
            && entry.generation == self.code_generation
        {
            self.remember_target(pc, entry.block);
            return Ok(Fetched::Block(entry.block));
        }
        let indexed = self
            .known_variant(variant)
            .and_then(|id| self.index.get(&(pc, physical, id)));
        let index = match indexed {
            Some(&index) => index,
            None => {
                let generation = self.code_generation;
                self.reclaim_for_memory();
                let compiled = self.compile(pc, physical, variant)?;
                // Compiling may have reclaimed code, whose lookup entries
                // the old context still names: the thunks look up in a new
                // one.
                if self.code_generation != generation {
                    let contexts = self.contexts(el, context);
                    self.chain.set_contexts(contexts);
                }
                match compiled {
                    Fetched::Block(index) => index,
                    other => return Ok(other),
                }
            }
        };
        self.jump[slot] = Some(JumpEntry {
            pc,
            physical,
            variant,
            generation: self.code_generation,
            block: index,
        });
        self.remember_target(pc, index);
        Ok(Fetched::Block(index))
    }

    /// Record that a fetch at `pc` runs block `index` in the current
    /// context, for lookup thunks: not single-instruction blocks, which
    /// debug checks precede, nor trace points, which the engine records.
    /// The fetch translated `pc`, so its page's entry is in the fetch cache.
    pub(super) fn remember_target(&mut self, pc: u64, index: usize) {
        let block = &self.blocks[index];
        if self.variants[block.variant.0 as usize].single || self.traces.binary_search(&pc).is_ok()
        {
            return;
        }
        let (entry, first) = (block.code.0 as u64, block.first);
        let page = pc & !(FETCH_PAGE - 1);
        let guarded = self.fetch[(page / FETCH_PAGE) as usize % FETCH_CACHE]
            .is_some_and(|fetched| fetched.page == page && fetched.guarded);
        let targets = (0..4u8)
            .filter(|&btype| !guarded || btype == 0 || self.branch_target_accepts(first, btype))
            .fold(0, |targets, btype| targets | 1 << btype);
        self.targets[chain::lookup_slot(pc)] = chain::LookupEntry {
            pc,
            context: self.chain.contexts()[chain::half(pc)],
            entry,
            block: index as u32,
            targets,
        };
    }

    /// Compile the block at `pc`, unless its first instruction is a
    /// trapped FP/SIMD instruction or one whose access checks the engine
    /// applies.
    pub(super) fn compile(
        &mut self,
        pc: u64,
        physical: u64,
        variant: Variant,
    ) -> Result<Fetched, Stop> {
        let window = source_window(pc, variant);
        if window > FIRST_WINDOW_BYTES
            && let Some(fetched) = self.compile_window(pc, physical, variant, FIRST_WINDOW_BYTES)?
        {
            return Ok(fetched);
        }
        Ok(self
            .compile_window(pc, physical, variant, window)?
            .expect("a block of the whole window"))
    }

    /// [`Self::compile`] from the first `available` bytes of the block's
    /// source window, or nothing when the block may run past them (it
    /// takes them all, or they are refused) and they are not the whole
    /// window.
    pub(super) fn compile_window(
        &mut self,
        pc: u64,
        physical: u64,
        variant: Variant,
        available: usize,
    ) -> Result<Option<Fetched>, Stop> {
        let whole = available == source_window(pc, variant);
        let page = pc & !(FETCH_PAGE - 1);
        let offset = (pc - page) as usize;
        let mut source = vec![0u8; available];
        if !self.host.read_ram(physical, &mut source) {
            // The fetch takes the external abort the fabric raises outside
            // memory (IFSC 0b010000).
            self.degrade(self.requirement(RequirementKind::Fetch { physical }));
            return Ok(Some(Fetched::Exception(self.external_abort_exception(
                [Class::InstructionAbortLower, Class::InstructionAbortSame],
                SYNCHRONOUS_EXTERNAL_ABORT,
                pc,
            ))));
        }
        // A block from elsewhere is used only when its bytes are among
        // those read, and so validated against the stored page.
        let within =
            |compiled: &stela_compiler::block::CompiledBlock| compiled.source_bytes <= available;
        let reading = self.host.counter();
        let stored = match variant.single {
            true => None,
            false => self
                .stored_page(pc, physical, &source)
                .map(|stored| (stored.key, stored.record.clone())),
        };
        self.statistics.page_ticks += self.host.counter().wrapping_sub(reading);
        let preparation = self.preparation(variant);
        preparation.admit(&mut source);
        let context = stored
            .is_some()
            .then(|| self.stored_context(variant, &preparation, page));
        if let (Some((key, record)), Some(context)) = (&stored, &context) {
            let found = record
                .as_ref()
                .and_then(|record| record.find(offset as u16, context))
                .and_then(|entry| {
                    entry
                        .rebase(page, &source)
                        .map(|block| (block, entry.input.clone()))
                });
            if let Some((compiled, input)) = found {
                if compiled.source_bytes > available {
                    return Ok(None);
                }
                self.statistics.stored += 1;
                return self
                    .install(
                        pc,
                        physical,
                        variant,
                        &source,
                        recovery::Template::stored(compiled, input, preparation.clone()),
                    )
                    .map(Some);
            }
            let looking = self.host.counter();
            if let Some(compiled) = self
                .host
                .translations()
                .and_then(|translations| translations.prepared(key, pc, context))
            {
                if !within(compiled.block()) {
                    return Ok(None);
                }
                if compiled.matches(key, pc, context, &source) {
                    self.statistics.shared += 1;
                    self.statistics.shared_ticks += self.host.counter().wrapping_sub(looking);
                    return self
                        .install(
                            pc,
                            physical,
                            variant,
                            &source,
                            recovery::Template::compiled(compiled.emission.clone()),
                        )
                        .map(Some);
                }
            }
        }
        let started = self.host.counter();
        // No block runs into a host breakpoint or trace point: one ends
        // before it.
        let limit = self
            .breakpoints
            .iter()
            .chain(&self.traces)
            .filter(|&&stop| stop > pc && stop < pc + source.len() as u64)
            .min()
            .map_or(source.len(), |&stop| (stop - pc) as usize);
        let prepared = preparation.prepare(&source, pc, limit);
        let past = match &prepared {
            Ok(Prepared::Block { consumed, .. }) => *consumed == available,
            Ok(Prepared::Checked(_) | Prepared::FloatingPointTrap) => false,
            Err(_) => true,
        };
        #[cfg(all(feature = "std", feature = "native-profile"))]
        if let Some(metrics) = &mut self.preparation_metrics {
            let ticks = self.host.counter().wrapping_sub(started);
            metrics.record(&prepared, ticks, past && !whole);
        }
        if past && !whole {
            return Ok(None);
        }
        let (compiled, input, successors) = match prepared {
            Ok(Prepared::Block {
                compiled,
                input,
                successors,
                ..
            }) => (compiled, input, successors),
            Ok(Prepared::Checked(word)) => return Ok(Some(Fetched::Checked(word))),
            Ok(Prepared::FloatingPointTrap) => {
                return Ok(Some(Fetched::Exception(self.floating_point_exception(pc))));
            }
            Err(refused) => {
                return Err(self.unsupported_word(
                    &source,
                    pc,
                    refused.pc,
                    refused.error.to_string(),
                ));
            }
        };
        self.statistics.compiled += 1;
        self.statistics.compiled_instructions += (compiled.source_bytes as u64) / INSTRUCTION;
        self.statistics.compile_ticks += self.host.counter().wrapping_sub(started);
        let emission = Arc::new(super::stored::Emission::new(
            source[..input].to_vec(),
            compiled,
            preparation,
        ));
        // An offer is kept until the store proves it; with memory low the
        // block is only compiled, as one the store cannot hold.
        if let (Some((key, _)), Some(context)) = (stored, context)
            && !self.host.memory_low()
            && let Some(translations) = self.host.translations()
        {
            translations.offer(Offer {
                key,
                page,
                pc,
                context,
                emission: emission.clone(),
                successors,
            });
            self.statistics.offered += 1;
        }
        self.install(
            pc,
            physical,
            variant,
            &source,
            recovery::Template::compiled(emission),
        )
        .map(Some)
    }

    /// How the next fetch compiles its block, in the PE's current state:
    /// for preparing blocks elsewhere as this machine would compile them.
    pub fn current_preparation(&mut self) -> Arc<Preparation> {
        let variant = self.current_variant(false, false);
        self.preparation(variant)
    }

    /// The variant a fetch compiles for in the PE's current state.
    pub(super) fn current_variant(&mut self, single: bool, guarded_page: bool) -> Variant {
        Variant {
            fp: self.floating_point_enabled(),
            checks: self.memory_checks(),
            single,
            scalable: self
                .cpu
                .scalable
                .is_some()
                .then(|| self.cpu.svcr() & 1 != 0),
            system: self.native_system(),
            guarded_page,
            timing: self.cpu.pstate.dit && self.timing_target().is_some(),
            translated: false,
        }
    }

    /// `variant`'s id, added to [`Self::variants`] the first time.
    pub(super) fn variant_id(&mut self, variant: Variant) -> VariantId {
        if let Some(id) = self.known_variant(variant) {
            return id;
        }
        let id = u32::try_from(self.variants.len()).expect("a bounded set of variants");
        self.variants.push(variant);
        VariantId(id)
    }

    /// `variant`'s id, once a block was compiled for it.
    pub(super) fn known_variant(&self, variant: Variant) -> Option<VariantId> {
        self.variants
            .iter()
            .position(|known| *known == variant)
            .map(|at| VariantId(at as u32))
    }

    /// What block `index` was compiled for.
    pub(super) fn block_variant(&self, index: usize) -> Variant {
        self.variants[self.blocks[index].variant.0 as usize]
    }

    /// How blocks of `variant` are compiled, made once per variant.
    pub(super) fn preparation(&mut self, variant: Variant) -> Arc<Preparation> {
        let variant = Variant {
            guarded_page: false,
            ..variant
        };
        if let Some(preparation) = self.preparations.get(&variant) {
            return preparation.clone();
        }
        let target = match variant.timing {
            true => self
                .timing_target()
                .expect("a timing variant has its target"),
            false => self.target,
        };
        let preparation = Arc::new(Preparation::new(
            self.profile.chip,
            self.admit_table.clone(),
            target,
            variant.fp,
            variant.checks,
            variant.scalable,
            variant.system,
        ));
        self.preparations.insert(variant, preparation.clone());
        preparation
    }

    /// Install `compiled`, the block at `pc` of `variant` compiled from the
    /// admitted `source`, and its thunks, and index it.
    pub(super) fn install(
        &mut self,
        pc: u64,
        physical: u64,
        variant: Variant,
        source: &[u8],
        compiled: recovery::Template,
    ) -> Result<Fetched, Stop> {
        let started = self.host.counter();
        let installed = self.place(pc, physical, variant, source, compiled);
        self.statistics.install_ticks += self.host.counter().wrapping_sub(started);
        installed
    }

    fn place(
        &mut self,
        pc: u64,
        physical: u64,
        variant: Variant,
        source: &[u8],
        compiled: recovery::Template,
    ) -> Result<Fetched, Stop> {
        let single = variant.single;
        if compiled.portable_requires_unavailable_capture() {
            return Err(self.unsupported(RequirementKind::Native(
                "native spill/extended-register invocation capture is not qualified",
            )));
        }
        if !compiled.matches_source(source)
            || compiled.source_bytes() < INSTRUCTION as usize
            || compiled.source_bytes() > source.len()
            || pc.checked_add(compiled.source_bytes() as u64).is_none()
        {
            return Err(self.unsupported(RequirementKind::Native(
                "native template has no matching admitted source extent",
            )));
        }
        let last = compiled.source_bytes() - INSTRUCTION as usize;
        let terminal = u32::from_le_bytes(source[last..last + 4].try_into().expect("a word"));
        // A heap without room for the block table's next chunk reuses the
        // oldest code's slots instead, or, when none of this machine's
        // blocks lay there, every slot.
        if self.free_blocks.is_empty() && !self.blocks.try_reserve_one() {
            self.reclaim_code();
            if self.free_blocks.is_empty() && !self.blocks.try_reserve_one() {
                self.discard_code(Discard::Table);
            }
        }
        let code = match self.host.install(&compiled.native().x86_64_code) {
            Ok(code) => code,
            Err(InstallError::Full) => {
                self.reclaim_code();
                self.host
                    .install(&compiled.native().x86_64_code)
                    .map_err(|_| {
                        self.unsupported(RequirementKind::Native("block exceeds the code arena"))
                    })?
            }
        };
        let terminal_pc = pc + compiled.source_bytes() as u64 - INSTRUCTION;
        let mut successors: Vec<Successor> = compiled
            .direct_exits()
            .iter()
            .map(|exit| Successor {
                site: code.0 as u64 + exit.offset as u64,
                target: exit.target,
                kind: exit.kind,
            })
            .collect();
        // RET, BR and BLR end the code with their exit to the target in
        // RAX; the PAC thunk of a RETA*, BRA* or BLRA* has one too.
        let code_bytes = &compiled.native().x86_64_code;
        let mut dynamic_site = (!single
            && terminal & 0xff9f_fc1f == 0xd61f_0000
            && dynamic_branch(terminal)
                .is_some_and(|(kind, _)| code_bytes.ends_with(&chain::dynamic_exit(kind))))
        .then(|| (code.0 + code_bytes.len() - chain::DYNAMIC_EXIT_BYTES) as u64);
        let first = self.admit(u32::from_le_bytes(source[..4].try_into().expect("a word")));
        if !single {
            let (successor, dynamic) = self
                .complete_pointer_natively(
                    code,
                    &compiled.native().x86_64_code,
                    terminal_pc,
                    terminal,
                )
                .unwrap_or_default();
            successors.extend(successor);
            dynamic_site = dynamic_site.or(dynamic);
            successors.extend(self.complete_mirrored_read_natively(
                code,
                &compiled.native().x86_64_code,
                terminal_pc,
                terminal,
            ));
        }
        let id = self.variant_id(variant);
        let block = Block {
            pc,
            physical,
            code,
            source_map: compiled
                .native()
                .source_map
                .iter()
                .map(|(guest, offset)| (guest.0, *offset))
                .collect(),
            variant: id,
            successors,
            dynamic_site,
            first,
            terminal: (terminal_pc, terminal),
            taken: 0,
            source_bytes: compiled.source_bytes(),
            source_hash: source_hash(&source[..compiled.source_bytes()]),
        };
        let index = match self.free_blocks.pop() {
            Some(slot) => {
                self.blocks[slot] = block;
                slot
            }
            None => self.blocks.push(block),
        };
        self.fault_recovery.insert(index, compiled.installed());
        self.index.insert((pc, physical, id), index);
        self.code_pages
            .entry(physical & !(FETCH_PAGE - 1))
            .or_default()
            .push((pc, physical, id));
        Ok(Fetched::Block(index))
    }

    pub(super) fn patch_native(&mut self, code: NativeCode, bytes: &[u8]) {
        self.host.patch(code, bytes);
    }

    /// Redirect the PAC exit ending a block's `native` code, installed at
    /// `code`, through a thunk that completes the PAC instruction `word` at
    /// `pc` from the memo when it can (`x86_64::pointer`); the thunk's
    /// direct exit to the next instruction, if it has one.
    pub(super) fn complete_pointer_natively(
        &mut self,
        code: NativeCode,
        native: &[u8],
        pc: u64,
        word: u32,
    ) -> Option<(Option<Successor>, Option<u64>)> {
        let exit = chain::direct_exit(GuestAddress(pc), ExitKind::PointerAuthentication);
        let site = native.len().checked_sub(chain::DIRECT_EXIT_BYTES)?;
        if native[site..] != exit {
            return None;
        }
        let instruction = block::decode_pointer_authentication(GuestAddress(pc), word).ok()??;
        let thunk = match instruction.operation {
            PointerAuthenticationOperation::Strip { data, destination } => {
                x86_64_pointer::strip::thunk(
                    GuestAddress(pc),
                    destination,
                    self.pointer.strip_address(data),
                )?
            }
            operation => {
                let form = x86_64_pointer::Form::of(operation)?;
                let (memo, tags, service) = self.pointer.addresses();
                x86_64_pointer::thunk(form, GuestAddress(pc), memo, tags, service)
            }
        };
        let installed = self.host.install(&thunk.code).ok()?;
        let site = code.0 as u64 + site as u64;
        let jump = chain::jump(site, installed.0 as u64)?;
        self.patch_native(NativeCode(site as usize), &jump);
        let successor = thunk.next.map(|next| Successor {
            site: installed.0 as u64 + next as u64,
            target: GuestAddress(pc + INSTRUCTION),
            kind: ExitKind::Fallthrough,
        });
        let dynamic = thunk
            .dynamic
            .map(|dynamic| installed.0 as u64 + dynamic as u64);
        Some((successor, dynamic))
    }

    /// Redirect the System exit ending a block's `native` code, installed at
    /// `code`, through a thunk that completes `word` at `pc`, if it is MRS
    /// of a [`MIRRORED`] register, from its cell in [`Self::mirrors`] while
    /// it is readable (`x86_64::register_read`); the thunk's direct exit to
    /// the next instruction.
    pub(super) fn complete_mirrored_read_natively(
        &mut self,
        code: NativeCode,
        native: &[u8],
        pc: u64,
        word: u32,
    ) -> Option<Successor> {
        let exit = chain::direct_exit(GuestAddress(pc), ExitKind::System);
        let site = native.len().checked_sub(chain::DIRECT_EXIT_BYTES)?;
        if native[site..] != exit {
            return None;
        }
        let (index, rt) = mirrored_read(pc, word)?;
        let cell = &self.mirrors[index] as *const register_read::Cell as u64;
        let thunk = if COUNT_MIRRORS.contains(&index) {
            let count = self.clock.native(self.host.tsc_counter()?);
            register_read::count_thunk(GuestAddress(pc), rt, cell, count)
        } else {
            register_read::thunk(GuestAddress(pc), rt, cell)
        };
        let installed = self.host.install(&thunk.code).ok()?;
        let site = code.0 as u64 + site as u64;
        let jump = chain::jump(site, installed.0 as u64)?;
        self.patch_native(NativeCode(site as usize), &jump);
        thunk.next.map(|next| Successor {
            site: installed.0 as u64 + next as u64,
            target: GuestAddress(pc + INSTRUCTION),
            kind: ExitKind::Fallthrough,
        })
    }

    /// The target PSTATE.DIT code compiles for
    /// (`TargetCpu::data_independent_timing_target`). Without one,
    /// ID_AA64PFR0_EL1.DIT reads 0 (`identification::Basis::Timing`) and
    /// PSTATE.DIT changes no code.
    pub(super) fn timing_target(&self) -> Option<TargetCpu> {
        self.target.data_independent_timing_target()
    }

    pub(super) fn unsupported_word(
        &self,
        source: &[u8],
        base: u64,
        pc: u64,
        detail: String,
    ) -> Stop {
        let offset = (pc - base) as usize;
        let word = source.get(offset..offset + 4).map_or(0, |bytes| {
            u32::from_le_bytes(bytes.try_into().expect("four bytes"))
        });
        Stop::Unsupported(Requirement {
            pc,
            el: self.cpu.pstate.el,
            link: self.cpu.state.x[30],
            kind: RequirementKind::Instruction { word, detail },
            syndrome: Some(super::super::exception::syndrome(Class::Unknown, 0)),
            address: None,
            written: None,
        })
    }

    /// The word an exit at `pc` executes, counted in [`Self::exit_words`]:
    /// the block's last instruction, as it was compiled, or one it reads.
    pub(super) fn exit_word(&mut self, index: usize, pc: u64) -> Result<u32, Stop> {
        let block = &mut self.blocks[index];
        if pc == block.terminal.0 {
            block.taken += 1;
            return Ok(block.terminal.1);
        }
        let word = self.word(index, pc)?;
        *self.exit_words.entry(word).or_default() += 1;
        Ok(word)
    }

    /// Exits to the engine from compiled code (System, FP, PAC and AMX), by
    /// the instruction word that took them: which words to compile inline.
    pub fn exit_words(&self) -> BTreeMap<u32, u64> {
        let mut words = self.exit_words.clone();
        for block in self.blocks.iter().filter(|block| block.taken != 0) {
            *words.entry(block.terminal.1).or_default() += block.taken;
        }
        words
    }

    /// The word an instruction inside a compiled block executes as: its
    /// original word, or the UDF or NOP of a form the chip lacks. The
    /// block's last is kept as it was compiled; others are read again.
    pub(super) fn word(&mut self, index: usize, pc: u64) -> Result<u32, Stop> {
        let block = &self.blocks[index];
        if pc == block.terminal.0 {
            return Ok(block.terminal.1);
        }
        let physical = block.physical + (pc - block.pc);
        let mut bytes = [0; 4];
        if !self.host.read_ram(physical, &mut bytes) {
            return Err(self.unsupported(RequirementKind::Fetch { physical }));
        }
        Ok(self.admit(u32::from_le_bytes(bytes)))
    }

    /// The word the profile's chip executes for `word` (`Chip::admit`).
    pub(super) fn admit(&self, word: u32) -> u32 {
        self.admit_table.admit(word)
    }

    pub(super) fn exit(&mut self, index: usize, next_pc: u64, kind: u64) -> Step {
        let kind = ExitKind::try_from(kind);
        // BTYPE belongs to the block's first instruction until it completes;
        // a branch ending the block gives the next one (Arm `BTypeNext`).
        if next_pc != self.blocks[index].pc {
            self.cpu.pstate.btype = 0;
        }
        match kind {
            Ok(
                ExitKind::Fallthrough
                | ExitKind::Direct
                | ExitKind::Indirect
                | ExitKind::Call
                | ExitKind::Return,
            ) => {
                // The block's last instruction is the branch that ends it.
                self.cpu.retired += self.blocks[index].source_map.len() as u64;
                self.cpu.pstate.btype = self.native_branch_type(index, kind)?;
                self.cpu.pc = next_pc;
                Ok(())
            }
            Ok(ExitKind::System) => {
                self.retire_before(index, next_pc);
                self.cpu.pc = next_pc;
                self.statistics.system_exits += 1;
                let word = self.exit_word(index, next_pc)?;
                self.completing(next_pc, |machine| machine.system_instruction(word))
            }
            Ok(ExitKind::FloatingPoint) => {
                self.retire_before(index, next_pc);
                self.cpu.pc = next_pc;
                let word = self.exit_word(index, next_pc)?;
                let Some(Ok(operation)) = FloatingPointOperation::decode(word) else {
                    return Err(self.unsupported(RequirementKind::Native(
                        "numerical exit at a word that is not numerical FP",
                    )));
                };
                match self.complete_floating_point(word, &operation) {
                    Ok(()) => self.completing(next_pc, Self::next),
                    Err(_) => Err(self.unsupported(RequirementKind::Instruction {
                        word,
                        detail: format!(
                            "FPCR {:#x} enables a trapped FP exception",
                            self.cpu.state.fpcr
                        ),
                    })),
                }
            }
            Ok(ExitKind::PointerAuthentication) => {
                self.retire_before(index, next_pc);
                self.cpu.pc = next_pc;
                let word = self.exit_word(index, next_pc)?;
                self.completing(next_pc, |machine| machine.pointer_authentication(word))
            }
            Ok(ExitKind::Amx) => {
                self.retire_before(index, next_pc);
                self.cpu.pc = next_pc;
                let word = self.exit_word(index, next_pc)?;
                self.completing(next_pc, |machine| machine.amx(word))
            }
            _ => Err(self.unsupported(RequirementKind::Native("unknown block exit kind"))),
        }
    }
}
