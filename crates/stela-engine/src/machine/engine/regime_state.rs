//! Derived regime state: what System register writes and EL changes make the
//! engine forget.

use super::*;

impl<H: Host, D: Devices> Machine<H, D> {
    /// A write of `register`: a [`stored`] one closes only its own cells,
    /// any other forgets everything derived.
    pub(super) fn register_written(&mut self, register: SystemRegister) {
        if !stored(register) {
            return self.derived_changed();
        }
        use registers::encodings as e;
        let encoding = match register {
            SystemRegister::TPIDR_EL0 => e::TPIDR_EL0,
            SystemRegister::TPIDRRO_EL0 => e::TPIDRRO_EL0,
            SystemRegister::TPIDR_EL1 => e::TPIDR_EL1,
            SystemRegister::TPIDR_EL2 => e::TPIDR_EL2,
            _ => return,
        };
        if let Some(index) = MIRRORED.iter().position(|&mirrored| mirrored == encoding) {
            self.mirrors.close(index);
        }
    }

    /// Forget state derived from System registers and PSTATE.
    pub(super) fn derived_changed(&mut self) {
        self.forget_derived();
        self.device_lines = None;
        // A closed cell keeps no value a mispredicted native read could use
        // (FEAT_CSV3's System register rule).
        *self.mirrors = Mirrors::default();
    }

    /// An exception entry or return, GENTER or GEXIT moved the PE from EL
    /// and GXF state `from`: what derives from PSTATE goes, but the mirrored
    /// reads keep their cells per state ([`Mirrors`]), and an open DAIF
    /// cell reads the new masks and open GL1 exception register cells what
    /// the entry wrote.
    pub(super) fn transitioned(&mut self, from: usize) {
        self.forget_derived();
        let pstate = self.cpu.pstate;
        self.mirrors
            .transition(from, mirror_state(pstate.el, pstate.guarded));
        let daif = &mut self.mirrors[DAIF_MIRROR];
        if daif.readable != 0 {
            daif.value = daif_register(pstate.daif);
        }
        for index in GUARDED_MIRRORS {
            if self.mirrors[index].readable == 0 {
                continue;
            }
            let read = decode_register(read_word(MIRRORED[index])).expect("an MRS word");
            let physical = self.now();
            self.mirrors[index] = match self.cpu.apple_access(read, physical) {
                RegisterOutcome::Read(value) => register_read::Cell {
                    readable: 1,
                    value: self.degraded_read(read, value),
                },
                _ => register_read::Cell::default(),
            };
        }
        self.sync_host_regime();
    }

    /// What [`Self::derived_changed`] forgets but the mirrored reads and
    /// the device lines.
    pub(super) fn forget_derived(&mut self) {
        self.timers = None;
        self.floating_point = None;
        self.memory_checks = None;
        self.native_system = None;
        self.debug = None;
        self.reopen_pointers();
    }

    /// The PAC service after a derived-state change: what native code had
    /// open reopens under the new keys, version, layout, enables and traps,
    /// exactly as the PAC exits that opened it would now decide, so the
    /// change costs no exit of its own. PACM changes the next instruction's
    /// operands, which no thunk applies: everything stays closed.
    pub(super) fn reopen_pointers(&mut self) {
        if !self.pointer.any_open() || self.cpu.pstate.pacm {
            self.pointer.close();
            return;
        }
        let Ok(version) = self.pointer_version() else {
            self.pointer.close();
            return;
        };
        let inputs = PointerInputs {
            keys: self.pointer_keys(),
            version,
            tcr: self.cpu.regime_tcr(),
        };
        let stripping = self.pointer.revalidate(inputs);
        let trapped = self.pointer_authentication_trapped();
        for (key, block) in [
            (
                stela_contracts::pauth::Key::Ia,
                PointerAuthenticationKey::Ia,
            ),
            (
                stela_contracts::pauth::Key::Ib,
                PointerAuthenticationKey::Ib,
            ),
            (
                stela_contracts::pauth::Key::Da,
                PointerAuthenticationKey::Da,
            ),
            (
                stela_contracts::pauth::Key::Db,
                PointerAuthenticationKey::Db,
            ),
        ] {
            let enabled = self.key_enabled(block);
            self.pointer.reopen(key, enabled, trapped);
        }
        for (data, open) in [false, true].into_iter().zip(stripping) {
            if open {
                self.pointer.reopen_stripping(data);
            }
        }
    }

    /// Whether loads and stores through SP check its 16-byte alignment (Arm
    /// `CheckSPAlignment`): SCTLR_ELx.SA0 at EL0 and SA otherwise, of the
    /// current translation regime.
    pub(super) fn stack_alignment_checked(&mut self) -> bool {
        self.memory_checks().stack_alignment
    }

    /// The checks native code makes for the current regime's SCTLR_ELx: SP
    /// alignment, A (Arm `AlignmentEnforced`) and nAA; and, where
    /// ID_AA64PFR0_EL1.CSV3 discloses FEAT_CSV3, the guest range check at
    /// every access (`identification::Speculation::faulting_data`).
    pub(super) fn memory_checks(&mut self) -> MemoryChecks {
        *self.memory_checks.get_or_insert_with(|| {
            let sctlr = self.cpu.regime_sctlr();
            let bit = if self.cpu.pstate.el == 0 { 4 } else { 3 };
            MemoryChecks::system(
                sctlr & (1 << bit) != 0,
                sctlr & mmu::alignment::SCTLR_A != 0,
                sctlr & mmu::alignment::SCTLR_NAA == 0,
                self.cpu
                    .field(SystemRegister::ID_AA64PFR0_EL1, CSV3_SHIFT, 4)
                    != 0,
            )
            .with_range(self.host.placement().check())
        })
    }

    pub(super) fn native_system(&mut self) -> NativeSystem {
        *self.native_system.get_or_insert_with(|| NativeSystem {
            zero_block: system::native_zero_block(&self.cpu, &self.profile_missing),
            cache_clean: system::native_cache_clean(&self.cpu),
        })
    }

    pub(super) fn sync_regime(&mut self) {
        self.derived_changed();
        self.sync_host_regime();
    }

    /// The host's view of the regime (shadow root, requester, watchpoints and
    /// tag checks) and the PMU's and prediction contexts follow the PE, with
    /// state derived from System registers left as it is.
    pub(super) fn sync_host_regime(&mut self) {
        self.sync_monitor();
        let watch = Watch {
            pass: self.watch.pass,
            ..Watch::from_ranges(&debug::watched(&self.cpu))
        };
        if watch.ranges != self.watch.ranges {
            // Newly watched pages must leave the shadow tables.
            self.advance_translation_generation();
            self.host.invalidate_translations();
        }
        self.watch = watch;
        self.tag_checks = self.cpu.tag_checks();
        let regime = Regime {
            controls: self.cpu.controls(self.cpu.regime()),
            requester: self.cpu.requester(),
            watch,
            tag_checks: self.tag_checks,
        };
        self.host.set_regime(&regime);
        let context = PredictionContext::of(&self.cpu);
        if self.prediction_context != Some(context) {
            self.prediction_context = Some(context);
            self.statistics.prediction_isolations += 1;
            self.host.isolate_predictions();
        }
    }
}
