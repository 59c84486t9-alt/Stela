//! Compiling, installing and patching blocks, and the exits native code takes
//! to the engine.

use super::*;

impl<H: Host, D: Devices> Machine<H, D> {
    pub(super) fn fetch_block(&mut self, pc: u64, single: bool) -> Result<Fetched, Stop> {
        let context = self.current_variant(single, false);
        let el = self.cpu.pstate.el | u8::from(self.cpu.pstate.guarded) << 4;
        let contexts = self.contexts(el, context);
        self.chain.set_contexts(contexts);
        // What a lookup dispatcher would enter, in the context that keeps its
        // translation current. The engine checks BTYPE against the fetch's
        // translation, which this leaves uncached.
        let context_number = contexts[chain::half(pc)];
        let slot = chain::lookup_slot(pc, context_number);
        let target = self.targets.find(slot, pc, context_number);
        if target.pc == pc
            && target.context == context_number
            && !single
            && self.cpu.pstate.btype == 0
        {
            return Ok(Fetched::Block(target.block as usize));
        }
        let physical = match self.fetch_physical(pc) {
            Ok(physical) => physical,
            Err(Ok(exception)) => return Ok(Fetched::Exception(exception)),
            Err(Err(stop)) => return Err(stop),
        };
        let current = Variant {
            guarded_page: self.fetch_guarded(pc),
            ..context
        };
        let variant = self.page_variant(current, physical);
        // The entry of a context forgotten since, whose translation this
        // fetch confirms: what TLBI ALL leaves of the kernel's text.
        if target.pc == pc && target.context >= self.code_floor {
            let block = &self.blocks[target.block as usize];
            if block.pc == pc
                && block.physical == physical
                && self.variants[block.variant.0 as usize] == variant
            {
                self.remember_target_page(pc, target.block as usize);
                return Ok(Fetched::Block(target.block as usize));
            }
        }
        let slot = (pc / INSTRUCTION) as usize % JUMP_CACHE;
        if let Some(entry) = self.jump[slot]
            && entry.pc == pc
            && entry.physical == physical
            && entry.variant == variant
            && entry.generation == self.code_generation
        {
            self.remember_target_page(pc, entry.block);
            return Ok(Fetched::Block(entry.block));
        }
        let indexed = self
            .known_variant(variant)
            .and_then(|id| self.index.get(&self.blocks, pc, physical, id));
        let index = match indexed {
            Some(index) => index,
            None => {
                let generation = self.code_generation;
                self.reclaim_for_memory();
                if let Some(hub) = &self.parallel {
                    hub.compiling(physical);
                }
                let (compiled, mail) = self.compile_aside(pc, physical, variant);
                let compiled = compiled?;
                // Compiling may have reclaimed code, whose lookup entries
                // the old context still names: the thunks look up in a new
                // one.
                if self.code_generation != generation {
                    let contexts = self.contexts(el, context);
                    self.chain.set_contexts(contexts);
                }
                // What came meanwhile may undo this fetch's translation or
                // the code it compiled; the block stays for the next one.
                if mail {
                    self.read_mail()?;
                    return self.fetch_block(pc, single);
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
        self.remember_target_page(pc, index);
        Ok(Fetched::Block(index))
    }

    /// [`Self::remember_target`], and, the first time this context reaches
    /// the page of `pc`, every block of the page a fetch reached in any
    /// context: a process runs what its libraries' other processes ran, and
    /// learning it one exit at a time costs more than the blocks' code.
    pub(super) fn remember_target_page(&mut self, pc: u64, index: usize) {
        self.blocks[index].fetched = true;
        self.remember_target(pc, index);
        let page = pc & !(FETCH_PAGE - 1);
        let context = self.chain.contexts()[chain::half(pc)];
        let visit = ((page / FETCH_PAGE) ^ context).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        let visit = &mut self.visited_pages[(visit >> 48) as usize % VISITED_PAGES];
        if *visit == (page, context) {
            return;
        }
        *visit = (page, context);
        let variant = self.blocks[index].variant;
        let mut blocks = core::mem::take(&mut self.page_blocks);
        blocks.extend(self.index.page(self.blocks[index].physical));
        for &other in &blocks {
            let block = &self.blocks[other];
            if block.fetched && block.variant == variant && block.pc & !(FETCH_PAGE - 1) == page {
                self.remember_target(block.pc, other);
            }
        }
        blocks.clear();
        self.page_blocks = blocks;
    }

    /// Record that a fetch at `pc` runs block `index` in the current
    /// context, for lookup dispatchers. The fetch translated `pc`, so its page's
    /// entry is in the fetch cache.
    /// Not for single-instruction blocks, which debug checks precede, nor trace
    /// points, which the engine records.
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
        let targets = match guarded {
            true => (0..4u8)
                .filter(|&btype| btype == 0 || self.branch_target_accepts(first, btype))
                .fold(0, |targets, btype| targets | 1 << btype),
            false => 0b1111,
        };
        let context = self.chain.contexts()[chain::half(pc)];
        let slot = chain::lookup_slot(pc, context);
        let target = chain::LookupEntry {
            pc,
            context,
            entry,
            block: index as u32,
            targets,
        };
        self.targets.insert(slot, target);
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
                let origin = self.stored_origin(physical, page, *key, *context, &preparation);
                return self
                    .install(
                        pc,
                        physical,
                        variant,
                        &source,
                        recovery::Template::stored(
                            compiled,
                            input,
                            preparation.clone(),
                            Some((origin, offset as u16)),
                        ),
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
        // An offer is kept until the store proves it. With memory low the
        // store holds no more for proof, but the other PEs still take the
        // block: this one retains the emission anyway, and each reuse saves
        // a compile and a copy.
        if let (Some((key, _)), Some(context)) = (stored, context)
            && let low = self.host.memory_low()
            && let Some(translations) = self.host.translations()
        {
            let offer = Offer {
                key,
                page,
                pc,
                context,
                emission: emission.clone(),
                successors,
            };
            if low {
                translations.lend(offer);
            } else {
                translations.offer(offer);
                self.statistics.offered += 1;
            }
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
                word: exit.word(),
                slot: chain::link_slot(Some(pc), exit.target, exit.kind),
            })
            .collect();
        // RET, BR and BLR end the code with their exit to the target in
        // RAX; the PAC thunk of a RETA*, BRA* or BLRA* has one too. Only
        // side exits follow a terminal's, and of the direct exits only a
        // terminal that has one precedes them: what a thunk completes has
        // none, whatever a side exit just before it leaves unrun.
        let code_bytes = &compiled.native().x86_64_code;
        let terminal_end = compiled
            .direct_exits()
            .iter()
            .map(|exit| exit.offset - chain::link_slot(Some(pc), exit.target, exit.kind))
            .min()
            .unwrap_or(chain::without_failures(code_bytes).len());
        let code_bytes = &code_bytes[..terminal_end];
        let mut dynamic_site = (!single
            && terminal & 0xff9f_fc1f == 0xd61f_0000
            && dynamic_branch(terminal)
                .is_some_and(|(kind, _)| code_bytes.ends_with(&chain::dynamic_exit(kind))))
        .then(|| (code.0 + code_bytes.len() - chain::DYNAMIC_EXIT_BYTES) as u64);
        let first = self.admit(u32::from_le_bytes(source[..4].try_into().expect("a word")));
        if !single {
            let (successor, dynamic) = self
                .complete_pointer_natively(code, code_bytes, terminal_pc, terminal)
                .unwrap_or_default();
            successors.extend(successor);
            dynamic_site = dynamic_site.or(dynamic);
            successors.extend(self.complete_mirrored_read_natively(
                code,
                code_bytes,
                terminal_pc,
                terminal,
            ));
        }
        let id = self.variant_id(variant);
        let block = Block {
            pc,
            physical,
            code,
            instructions: compiled.native().source_map.len() as u16,
            variant: id,
            successors: successors.into_boxed_slice(),
            dynamic_site: dynamic_site.and_then(NonZeroU64::new),
            first,
            terminal,
            taken: 0,
            fetched: false,
            source_bytes: compiled.source_bytes() as u16,
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
        self.index.insert(&self.blocks, index);
        self.mirrors.close_code_page();
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
                    strip_place(data),
                )?
            }
            operation => {
                let form = x86_64_pointer::Form::of(operation)?;
                x86_64_pointer::thunk(form, GuestAddress(pc), TAGS, SERVICE as usize as u64)
            }
        };
        let installed = self.host.install(&thunk.code).ok()?;
        let site = code.0 as u64 + site as u64;
        let jump = chain::jump(site, installed.0 as u64)?;
        self.patch_native(NativeCode(site as usize), &jump);
        let successor = thunk.next.map(|next| Successor {
            site: installed.0 as u64 + next as u64,
            slot: 0,
            target: GuestAddress(pc + INSTRUCTION),
            word: ExitKind::Fallthrough.into(),
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
        let masks = register_read::MaskWrite::of(word).filter(|_| self.native_system().exclusive);
        let thunk = if let Some(write) = masks {
            let cell = cell_place(MASK_WRITES);
            register_read::mask_thunk(write, GuestAddress(pc), cell)
        } else if let Some(pan) = pan_write(word).filter(|_| self.host.pan_in_flags()) {
            let cell = cell_place(PAN_WRITES);
            register_read::pan_thunk(GuestAddress(pc), pan, cell)
        } else if data_barrier(pc, word) {
            let cell = cell_place(DATA_BARRIER);
            register_read::barrier_thunk(GuestAddress(pc), cell)
        } else if let Some(rt) = code_page_invalidation(word).filter(|&rt| rt != ZERO_REGISTER) {
            let cell = cell_place(CODE_PAGE);
            register_read::code_page_thunk(GuestAddress(pc), rt, cell)
        } else if let Some(select) = stack_select(word) {
            let cell = cell_place(STACK_SELECT);
            let current = SELECTED;
            let sp0 = Place::new(Anchor::StackZero, 0);
            register_read::stack_select_thunk(GuestAddress(pc), select, cell, current, sp0)
        } else if let Some((index, rt)) = written_register(pc, word) {
            self.stored_write_thunk(GuestAddress(pc), index, rt)
        } else if let Some((index, rt)) = guarded_written_register(pc, word) {
            let cell = cell_place(index);
            let all = register_read::Written {
                keep: u64::MAX,
                set: 0,
            };
            register_read::stored_write_thunk(GuestAddress(pc), rt, cell, all)
        } else if let Some((index, rt)) = mirrored_read(pc, word) {
            let cell = cell_place(index);
            if GUARDED_MIRRORS.contains(&index) {
                register_read::stored_thunk(GuestAddress(pc), rt, cell)
            } else if COUNT_MIRRORS.contains(&index) {
                self.clock.native(self.host.tsc_counter()?);
                let count = Place::new(Anchor::Count, 0);
                register_read::count_thunk(GuestAddress(pc), rt, cell, count)
            } else if index == DAIF_MIRROR && self.native_system().exclusive {
                register_read::mask_read_thunk(GuestAddress(pc), rt, cell)
            } else {
                register_read::thunk(GuestAddress(pc), rt, cell)
            }
        } else if let Some(access) = mrs_access(pc, word) {
            self.stored_read_thunk(pc, access)?
        } else {
            let access = msr_access(pc, word)?;
            let (index, refused) = self.stored_write_cell(access.encoding())?;
            let cell = cell_place(stored_write_cell(index));
            register_read::checked_write_thunk(GuestAddress(pc), access.rt(), cell, refused)
        };
        let installed = self.host.install(&thunk.code).ok()?;
        let site = code.0 as u64 + site as u64;
        let jump = chain::jump(site, installed.0 as u64)?;
        self.patch_native(NativeCode(site as usize), &jump);
        thunk.next.map(|next| Successor {
            site: installed.0 as u64 + next as u64,
            slot: 0,
            target: GuestAddress(pc + INSTRUCTION),
            word: ExitKind::Fallthrough.into(),
        })
    }

    /// The thunk completing MSR of `WRITTEN[index]` from Xt at `pc`.
    fn stored_write_thunk(&self, pc: GuestAddress, index: usize, rt: u8) -> x86_64_pointer::Thunk {
        let (_, register) = WRITTEN[index];
        let cell = cell_place(written_cell(index));
        let written = self.register_fixed_bits(register);
        if register == SystemRegister::FPSR {
            let offset = core::mem::offset_of!(GuestState, fpsr);
            return register_read::frame_write_thunk(pc, rt, cell, offset, written);
        }
        if register == SystemRegister::SP_EL0 {
            let selected = SELECTED;
            return register_read::selected_write_thunk(pc, rt, cell, selected, written);
        }
        register_read::stored_write_thunk(pc, rt, cell, written)
    }

    /// The bits of `register` a write takes and those it holds.
    pub(super) fn register_fixed_bits(&self, register: SystemRegister) -> register_read::Written {
        let (res0, res1) = (
            self.cpu.registers.res0(register),
            self.cpu.registers.res1(register),
        );
        register_read::Written {
            keep: !(res0 | res1),
            set: res1,
        }
    }

    /// The cell of MRS of `encoding`, made if there is room.
    fn stored_cell(&mut self, encoding: Encoding) -> Option<usize> {
        let known = self.stored_reads.iter().position(|&read| read == encoding);
        let cell = known.or_else(|| {
            let storable = storable(encoding)
                || self
                    .cpu
                    .impdef(encoding)
                    .is_some_and(|entry| entry.reads_storage())
                || self
                    .devices
                    .register_storage(self.current, encoding)
                    .is_some();
            (storable && self.stored_reads.len() < STORED_CELLS).then(|| {
                self.stored_reads.push(encoding);
                self.stored_reads.len() - 1
            })
        })?;
        Some(MIRRORED.len() + cell)
    }

    /// The index of `encoding` in [`Self::stored_writes`], made if there is
    /// room, and the bits of a value its writes leave to the engine.
    fn stored_write_cell(&mut self, encoding: Encoding) -> Option<(usize, u64)> {
        let refused = self.cpu.impdef(encoding)?.stored_write()?;
        let known = self.stored_writes.iter().position(|&write| write == encoding);
        let index = known.or_else(|| {
            (self.stored_writes.len() < STORED_WRITES).then(|| {
                self.stored_writes.push(encoding);
                self.stored_writes.len() - 1
            })
        })?;
        Some((index, refused))
    }

    /// The thunk completing `access` at `pc` from its stored cell.
    fn stored_read_thunk(
        &mut self,
        pc: u64,
        access: RegisterAccess,
    ) -> Option<x86_64_pointer::Thunk> {
        use registers::encodings::{FPCR, FPSR};
        let encoding = access.encoding();
        let index = self.stored_cell(encoding)?;
        let cell = cell_place(index);
        let (pc, rt) = (GuestAddress(pc), access.rt());
        if encoding == STACK_ZERO {
            let selected = SELECTED;
            return Some(register_read::selected_stored_thunk(pc, rt, cell, selected));
        }
        Some(match encoding {
            FPCR => {
                register_read::frame_thunk(pc, rt, cell, core::mem::offset_of!(GuestState, fpcr))
            }
            FPSR => {
                register_read::frame_thunk(pc, rt, cell, core::mem::offset_of!(GuestState, fpsr))
            }
            _ => register_read::stored_thunk(pc, rt, cell),
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
        if pc == block.terminal_pc() {
            block.taken = block.taken.saturating_add(1);
            return Ok(block.terminal);
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
            *words.entry(block.terminal).or_default() += u64::from(block.taken);
        }
        words
    }

    /// Device accesses by the physical address they reached: which
    /// device registers to serve faster.
    pub fn system_words(&self) -> &BTreeMap<u32, DeviceRegister> {
        &self.system_words
    }

    pub fn device_registers(&self) -> &BTreeMap<u64, DeviceRegister> {
        &self.device_registers
    }

    /// Count a device access at `physical`, the register its native fault's
    /// handling is timed for.
    pub(super) fn count_device_access(&mut self, physical: u64) {
        self.statistics.device_accesses += 1;
        self.device_registers.entry(physical).or_default().accesses += 1;
        self.timed_device = Some(physical);
    }

    /// The word an instruction inside a compiled block executes as: its
    /// original word, or the UDF or NOP of a form the chip lacks. The
    /// block's last is kept as it was compiled; others are read again.
    pub(super) fn word(&mut self, index: usize, pc: u64) -> Result<u32, Stop> {
        let block = &self.blocks[index];
        if pc == block.terminal_pc() {
            return Ok(block.terminal);
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
                // What a side exit skipped has come off `retired` already.
                self.cpu.retired = self
                    .cpu
                    .retired
                    .wrapping_add(u64::from(self.blocks[index].instructions));
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
