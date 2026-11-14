//! Faults that only the faulting context may serve
//! (`stela_boot_core::process_fault`): a GPU client's mapping that Linux
//! moved. The #PF handler stores a call to [`stela_process_fault`] at the
//! faulting instruction; the entry runs the server on the faulting stack,
//! with the interrupt image released and the faulting IF, as a call made
//! there would, and returns to the instruction.
//!
//! The server runs Linux, which uses the vector registers, so the entry keeps
//! the whole enabled extended state as the translation helper does, and every
//! general register and RFLAGS.
use super::super::interrupts::Frame;
use core::arch::global_asm;
use stela_boot_core::process_fault::{Redirect, Refused, WORDS};

const IF: u64 = 1 << 9;

// At entry: [rsp] the fault's address, [rsp + 8] its write flag and
// [rsp + 16] the faulting instruction, where the final RET goes.
global_asm!(
    r#"
.global stela_process_fault
stela_process_fault:
    pushfq
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rdi
    push rsi
    push rbp
    push rbx
    push rdx
    push rcx
    push rax
    mov rbx, rsp
    cli
    cld
    mov r11, gs:[{image_bytes}]
    sub rsp, r11
    sub rsp, {footer_bytes}
    and rsp, -64
    lea rsi, [rsp + r11]
    mov rdi, rsp
    call {save}
    fninit
    ldmxcsr [rip + {default_mxcsr}]
    test qword ptr [rbx + {flags}], {interrupt_flag}
    jz stela_process_fault_masked
    sti
stela_process_fault_masked:
    mov rdi, [rbx + {address}]
    mov rsi, [rbx + {write}]
    mov rdx, [rbx + {ret}]
    call {serve}
    cli
    mov r11, gs:[{image_bytes}]
    mov rdi, rsp
    lea rsi, [rsp + r11]
    call {restore}
    mov rsp, rbx
    pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rbp
    pop rsi
    pop rdi
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
    popfq
    // Past the address and write flag, keeping the restored flags.
    lea rsp, [rsp + 16]
    ret
.global stela_process_fault_end
stela_process_fault_end:
"#,
    image_bytes = const super::local::XSTATE_IMAGE_BYTES_OFFSET,
    footer_bytes = const size_of::<super::super::xstate::EntryMetadata>(),
    flags = const 15 * 8,
    address = const 16 * 8,
    write = const 17 * 8,
    ret = const 18 * 8,
    interrupt_flag = const IF,
    save = sym super::super::xstate::stela_xstate_save_owned,
    restore = sym super::super::xstate::stela_xstate_restore_owned,
    default_mxcsr = sym super::super::xstate::DEFAULT_MXCSR,
    serve = sym serve,
);

unsafe extern "sysv64" {
    fn stela_process_fault();
    static stela_process_fault_end: u8;
}

const _: () = assert!(WORDS == 3);

extern "sysv64" fn serve(address: u64, write: u64, rip: u64) {
    super::super::gpu::client::serve_moved(address, write != 0, rip);
}

/// Make the faulting code of `frame` call the server for `address`.
pub(crate) fn redirect(frame: &mut Frame, address: u64) -> Result<(), Refused> {
    let entry = stela_process_fault as *const () as u64;
    let end = (&raw const stela_process_fault_end).addr() as u64;
    let redirect = Redirect::plan(frame, address, entry..end)?;
    // SAFETY: the words go just below the faulting CPL0 stack's RSP, where
    // no host code keeps anything (no red zone), on a page other than the
    // faulting one; the handler returns to that stack.
    unsafe { (redirect.rsp as *mut [u64; WORDS]).write(redirect.words) };
    redirect.apply(frame, entry);
    Ok(())
}
