//! Native faults: recovery footers, abandoned blocks, page faults and native
//! exceptions.

use super::*;

// In the owning host stack through native/context execution.
// recovery_rsp points to the complete image, never to a naked GPR snapshot.
// The adjacent footer preserves both original stack ownership and BlockExit's
// two result registers across scalar-only state restoration.
#[repr(C)]
pub(super) struct RecoveryFooter {
    pub(super) xstate: super::super::xstate::EntryMetadata,
    pub(super) saved_stack: u64,
    pub(super) result_rax: u64,
    pub(super) result_rdx: u64,
    pub(super) context: u64,
}

global_asm!(
    r#"
.global stela_enter_block
stela_enter_block:
    xor r10d, r10d
    jmp stela_enter_owned
.global stela_enter_context_block
stela_enter_context_block:
    mov r10d, 1
stela_enter_owned:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rdi
    push rsi
    push rdx
    mov rbx, rsp
    cmp qword ptr gs:[{recovery}], 0
    jne {refuse}
    cmp qword ptr gs:[{helper}], 0
    jne {refuse}
    mov r11, gs:[{image_bytes}]
    sub rsp, r11
    sub rsp, {footer_bytes}
    and rsp, -64
    lea rsi, [rsp + r11]
    mov [rsi + {saved_stack}], rbx
    mov [rsi + {context}], r10
    mov rdi, rsp
    call {save}
    fninit
    ldmxcsr [rip + {default_mxcsr}]
    // Publish only a complete owned image. IRQs use separate IST images;
    // a terminal NMI can never return through a half-published recovery frame.
    mov gs:[{recovery}], rsp
    mov r11, gs:[{image_bytes}]
    mov rbx, [rsp + r11 + {saved_stack}]
    mov rdi, [rbx + 16]
    mov rsi, [rbx + 8]
    cmp qword ptr [rsp + r11 + {context}], 0
    jne stela_enter_owned_context
    // Preserve the legacy generated-block entry alignment (RSP%16=0 in the
    // block); the separate context ABI remains SysV (RSP%16=8 in the block).
    sub rsp, 8
    call rsi
    add rsp, 8
    jmp stela_native_owned_return
stela_enter_owned_context:
    mov rdx, [rbx]
    call rdx
stela_native_owned_return:
    cmp qword ptr gs:[{helper}], 0
    jne {refuse}
    mov rsp, gs:[{recovery}]
    test rsp, rsp
    jz {refuse}
    mov r11, gs:[{image_bytes}]
    mov [rsp + r11 + {result_rax}], rax
    mov [rsp + r11 + {result_rdx}], rdx
    jmp stela_native_restore_host
.global stela_native_recover
stela_native_recover:
    mov rsp, gs:[{recovery}]
    test rsp, rsp
    jz {refuse}
    mov r11, gs:[{image_bytes}]
    mov qword ptr [rsp + r11 + {result_rax}], 0
    mov qword ptr [rsp + r11 + {result_rdx}], 0xffff
stela_native_restore_host:
    mov rdi, rsp
    lea rsi, [rsp + r11]
    call {restore}
    // No Rust runs between exact restoration and returning to the original
    // host stack. An abandoned helper has no surviving borrowed state/image.
    mov r11, gs:[{image_bytes}]
    mov rbx, [rsp + r11 + {saved_stack}]
    mov rax, [rsp + r11 + {result_rax}]
    mov rdx, [rsp + r11 + {result_rdx}]
    mov qword ptr gs:[{helper}], 0
    mov qword ptr gs:[{recovery}], 0
    mov rsp, rbx
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
"#,
    recovery = const local::RECOVERY_RSP_OFFSET,
    helper = const local::HELPER_RSP_OFFSET,
    image_bytes = const local::XSTATE_IMAGE_BYTES_OFFSET,
    footer_bytes = const size_of::<RecoveryFooter>(),
    saved_stack = const core::mem::offset_of!(RecoveryFooter, saved_stack),
    result_rax = const core::mem::offset_of!(RecoveryFooter, result_rax),
    result_rdx = const core::mem::offset_of!(RecoveryFooter, result_rdx),
    context = const core::mem::offset_of!(RecoveryFooter, context),
    save = sym super::super::xstate::stela_xstate_save_owned,
    restore = sym super::super::xstate::stela_xstate_restore_owned,
    refuse = sym super::super::xstate::stela_xstate_boundary_refuse,
    default_mxcsr = sym super::super::xstate::DEFAULT_MXCSR,
);

unsafe extern "sysv64" {
    pub(super) fn stela_enter_block(state: *mut GuestState, code: usize) -> BlockExit;
    pub(super) fn stela_enter_context_block(
        state: *mut GuestState,
        context: *mut stela_compiler::context::ExecutionContext,
        code: usize,
    ) -> BlockExit;
    pub(super) fn stela_native_recover();
}

pub(super) fn in_code(state: &State, rip: u64) -> bool {
    state.native && (state.code_virtual..state.code_virtual + state.code_bytes).contains(&rip)
}

/// End the native block at `frame` and report `cause` to the engine.
pub(super) fn abandon(
    state: &mut State,
    frame: &mut Frame,
    address: u64,
    write: bool,
    cause: FaultCause,
    saved: &super::super::interrupts::SavedState<'_>,
) {
    state.recorded = Some(Recorded {
        rip: frame.rip,
        origin: stela_engine::machine::NativeFaultOrigin::Exception,
        trap: u16::try_from(frame.vector).unwrap_or(u16::MAX),
        error_code: frame.error,
        address,
        write,
        cause,
        registers: saved.registers().unwrap_or_else(|_| {
            crate::output::fatal("native fault has no valid owned interrupt register image")
        }),
    });
    frame.rip = stela_native_recover as *const () as u64;
}

/// The guest's translation of the access at `address`, through the same
/// software walk for shadow faults and the translation helper: the
/// translation and the host physical address of its RAM page, or why the
/// engine must take the access (Arm checks watchpoints after translation,
/// `AArch64_TranslateAddress`, then Tag Checks).
pub(super) fn resolve(
    state: &mut State,
    address: u64,
    write: bool,
    unprivileged: bool,
) -> Result<(mmu::Translation, u64), FaultCause> {
    let regime = state.regime.ok_or(FaultCause::NonCanonical)?;
    let access = if write { Access::Write } else { Access::Read };
    let requester = mmu::Requester {
        unprivileged: regime.requester.unprivileged || unprivileged,
        ..regime.requester
    };
    let translation = match mmu::translate(
        &regime.controls,
        address,
        access,
        requester,
        &mut GuestTables(state),
    ) {
        Outcome::Mapped(translation) => translation,
        Outcome::Fault(fault) => return Err(FaultCause::Guest(fault)),
        Outcome::Unsupported(unsupported) => return Err(FaultCause::Translation(unsupported)),
    };
    if regime.watch.blocks(address & !(PAGE - 1)) {
        return Err(FaultCause::Watched);
    }
    if regime.tag_blocks(address, translation.attributes) {
        return Err(FaultCause::TagChecked);
    }
    let page = translation.physical & !(PAGE - 1);
    let host = state.host_physical(page).ok_or(FaultCause::Device {
        physical: translation.physical,
    })?;
    Ok((translation, host))
}

/// #PF: fill the shadow from the guest's tables or end the block precisely.
pub(crate) fn page_fault(
    frame: &mut Frame,
    address: u64,
    saved: &super::super::interrupts::SavedState<'_>,
) {
    let state = state();
    if !in_code(state, frame.rip) {
        super::super::interrupts::fatal(frame);
    }
    let write = frame.error & 2 != 0;
    let Some(regime) = state.regime else {
        super::super::interrupts::fatal(frame);
    };
    // Only the native ranges are shadow; the rest is the engine's. An
    // access past a check an earlier one stood for may reach the guard
    // (`mmu::placement`): its own check finds where it goes.
    if !state.placement.native(address) {
        state.guard_faults += u64::from(state.placement.in_guard(address));
        return abandon(
            state,
            frame,
            address,
            write,
            FaultCause::NonCanonical,
            saved,
        );
    }
    let (translation, host) = match resolve(state, address, write, false) {
        Ok(resolved) => resolved,
        Err(cause) => return abandon(state, frame, address, write, cause, saved),
    };
    let rights = PRESENT | NX | if translation.writable { WRITABLE } else { 0 };
    let root = state.roots[state.current];
    let virtual_page = address & !(PAGE - 1);
    let half = if address >> 63 == 0 { LOWER } else { UPPER };
    state.pool.half = half;
    // A failed allocation can already have installed intermediate tables.
    state.legacy_translations_dirty = true;
    if tables::map_page(&mut state.pool, root, virtual_page, host, rights).is_err() {
        // The half's frames are exhausted: start it over and map again. The
        // lower half's kept halves hold frames until it is emptied.
        state.exhausted += 1;
        if half == LOWER {
            state.reset_lower();
        } else {
            state.reset_shadow(Cause::Exhausted);
        }
        state.pool.half = half;
        state.legacy_translations_dirty = true;
        if tables::map_page(&mut state.pool, root, virtual_page, host, rights).is_err() {
            super::super::interrupts::fatal(frame);
        }
    }
    invlpg(virtual_page);
    if half == LOWER {
        let entry = tables::index(virtual_page, layout::top_level());
        state.lower_used[entry / 64] |= 1 << (entry % 64);
    }
    state.extents[half].record(address, translation.size, translation.global);
    // The rest of the leaf's window has the same translation and rights:
    // map its RAM pages that are not watched now, as a TLB entry covers
    // the whole leaf. Pages that were absent need no flush. A Tagged leaf
    // whose tags are checked maps only the passed page.
    if regime.tag_checks[half] && translation.attributes == mmu::attributes::TAGGED {
        state.fills += 1;
        return;
    }
    let (first, last) = shadow::window(address, translation.size, FILL_WINDOW);
    let mut page = first;
    loop {
        if page != virtual_page && !regime.watch.blocks(page) {
            let physical = translation
                .physical
                .wrapping_sub(address)
                .wrapping_add(page);
            if let Some(host) = state.host_physical(physical) {
                state.legacy_translations_dirty = true;
                if tables::map_page(&mut state.pool, root, page, host, rights).is_err() {
                    // Out of frames: the rest stays to fault.
                    break;
                }
                state.prefills += 1;
            }
        }
        if page >= last & !(PAGE - 1) {
            break;
        }
        page += PAGE;
    }
    state.fills += 1;
}

/// #GP or #UD inside native code ends the block; elsewhere it is fatal.
pub(crate) fn native_exception(
    frame: &mut Frame,
    saved: &super::super::interrupts::SavedState<'_>,
) {
    let state = state();
    if !in_code(state, frame.rip) {
        super::super::interrupts::fatal(frame);
    }
    let cause = if frame.vector == 13 {
        FaultCause::NonCanonical
    } else {
        FaultCause::InvalidOpcode
    };
    abandon(state, frame, 0, false, cause, saved);
}
