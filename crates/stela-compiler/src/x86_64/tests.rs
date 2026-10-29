use super::*;
use crate::aarch64::system::synchronization::{
    Operation as Synchronization, Requirement, Scope, WaitKind,
};

/// The capture runs on the host after 64-bit additions and subtractions
/// of edge values, with RDX holding other bits, and packs Arm's NZCV.
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn the_flag_capture_packs_arm_flags_of_host_arithmetic() {
    use core::ffi::c_void;
    unsafe extern "C" {
        fn mmap(
            address: *mut c_void,
            bytes: usize,
            protection: i32,
            flags: i32,
            fd: i32,
            offset: i64,
        ) -> *mut c_void;
        fn mprotect(address: *mut c_void, bytes: usize, protection: i32) -> i32;
        fn munmap(address: *mut c_void, bytes: usize) -> i32;
    }
    #[cfg(target_os = "macos")]
    const MAP_ANONYMOUS: i32 = 0x1000;
    #[cfg(target_os = "linux")]
    const MAP_ANONYMOUS: i32 = 0x20;
    const PAGE: usize = 4096;
    const OTHER_BITS: u64 = 0xa5a5_5a5a_c3c3_3c3c;
    const VALUES: [u64; 8] = [
        0,
        1,
        0x7fff,
        0x8000_0000,
        0x7fff_ffff_ffff_ffff,
        0x8000_0000_0000_0000,
        0xffff_ffff_ffff_fffe,
        u64::MAX,
    ];
    let arm = |left: u64, right: u64, borrow: bool| {
        let (result, carry, overflow) = if borrow {
            let (result, borrowed) = left.overflowing_sub(right);
            (
                result,
                !borrowed,
                (left as i64).overflowing_sub(right as i64).1,
            )
        } else {
            let (result, carried) = left.overflowing_add(right);
            (
                result,
                carried,
                (left as i64).overflowing_add(right as i64).1,
            )
        };
        let [n, z, c, v] = [result >> 63 == 1, result == 0, carry, overflow].map(u32::from);
        n << 31 | z << 30 | c << 29 | v << 28
    };
    for borrow in [false, true] {
        let mut code = Code::new();
        code.asm()
            .mov(asm::Size::Qword, asm::Gpr::Rax, asm::Gpr::Rdi);
        code.asm().mov_imm64(asm::Gpr::Rdx, OTHER_BITS);
        code.asm().alu(
            if borrow { asm::Alu::Sub } else { asm::Alu::Add },
            asm::Size::Qword,
            asm::Gpr::Rax,
            asm::Gpr::Rsi,
        );
        capture_nzcv(&mut code, borrow);
        code.asm().ret();
        // SAFETY: private anonymous memory, RX after the copy and
        // unmapped after the calls; the code touches no memory.
        unsafe {
            let page = mmap(core::ptr::null_mut(), PAGE, 3, 2 | MAP_ANONYMOUS, -1, 0);
            assert_ne!(page as usize, usize::MAX);
            core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
            assert_eq!(mprotect(page, PAGE, 5), 0);
            let entry: unsafe extern "sysv64" fn(u64, u64) -> u32 = core::mem::transmute(page);
            for left in VALUES {
                for right in VALUES {
                    assert_eq!(
                        entry(left, right),
                        arm(left, right, borrow),
                        "{left:#x} {right:#x} borrow {borrow}"
                    );
                }
            }
            assert_eq!(munmap(page, PAGE), 0);
        }
    }
}

/// Every condition runs on the host against every NZCV value, with and
/// without bits below it set, from the frame and from EAX.
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn conditions_hold_exactly_as_arm_defines_them() {
    use core::ffi::c_void;
    unsafe extern "C" {
        fn mmap(
            address: *mut c_void,
            bytes: usize,
            protection: i32,
            flags: i32,
            fd: i32,
            offset: i64,
        ) -> *mut c_void;
        fn mprotect(address: *mut c_void, bytes: usize, protection: i32) -> i32;
        fn munmap(address: *mut c_void, bytes: usize) -> i32;
    }
    #[cfg(target_os = "macos")]
    const MAP_ANONYMOUS: i32 = 0x1000;
    #[cfg(target_os = "linux")]
    const MAP_ANONYMOUS: i32 = 0x20;
    const PAGE: usize = 4096;
    const LOW_BITS: u32 = 0x0fff_ffff;
    let holds = |condition: u8, nzcv: u32| {
        let (n, z, c, v) = (nzcv & 8 != 0, nzcv & 4 != 0, nzcv & 2 != 0, nzcv & 1 != 0);
        let result = match condition >> 1 {
            0 => z,
            1 => c,
            2 => n,
            3 => v,
            4 => c && !z,
            5 => n == v,
            _ => n == v && !z,
        };
        result != (condition & 1 == 1)
    };
    for loaded in [false, true] {
        for condition in 0..14 {
            let mut code = Code::new();
            if loaded {
                code.asm().mov_load(
                    asm::Size::Dword,
                    asm::Gpr::Rax,
                    asm::Mem::base_disp32(
                        asm::Gpr::Rdi,
                        core::mem::offset_of!(crate::GuestState, nzcv) as i32,
                    ),
                );
            }
            let host = condition_holds(&mut code, condition, loaded).unwrap();
            code.asm().setcc(host, asm::Gpr::Rax);
            code.asm().movzx(
                asm::Size::Dword,
                asm::Gpr::Rax,
                asm::Size::Byte,
                asm::Gpr::Rax,
            );
            code.asm().ret();
            // SAFETY: private anonymous memory, RX after the copy and
            // unmapped after the calls; the code reads only `state`.
            unsafe {
                let page = mmap(core::ptr::null_mut(), PAGE, 3, 2 | MAP_ANONYMOUS, -1, 0);
                assert_ne!(page as usize, usize::MAX);
                core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
                assert_eq!(mprotect(page, PAGE, 5), 0);
                let entry: unsafe extern "sysv64" fn(*const crate::GuestState) -> u32 =
                    core::mem::transmute(page);
                for nzcv in 0..16 {
                    for low in [0, LOW_BITS] {
                        let state = crate::GuestState {
                            nzcv: nzcv << 28 | low,
                            ..Default::default()
                        };
                        assert_eq!(
                            entry(&state) == 1,
                            holds(condition, nzcv),
                            "condition {condition} NZCV {nzcv:#x} low {low:#x}"
                        );
                    }
                }
                assert_eq!(munmap(page, PAGE), 0);
            }
        }
    }
}

/// The shared address additions run on the host against a guest frame:
/// every immediate form leaves the access address in RAX and, with
/// writeback, the new base in RDX; every index extension and shift,
/// scaled or shifted first, and a ZR index add modulo 2^64.
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn address_additions_compute_the_access_address_and_writeback() {
    use crate::aarch64::register_offset::IndexExtend;
    use core::ffi::c_void;
    unsafe extern "C" {
        fn mmap(
            address: *mut c_void,
            bytes: usize,
            protection: i32,
            flags: i32,
            fd: i32,
            offset: i64,
        ) -> *mut c_void;
        fn mprotect(address: *mut c_void, bytes: usize, protection: i32) -> i32;
        fn munmap(address: *mut c_void, bytes: usize) -> i32;
    }
    #[cfg(target_os = "macos")]
    const MAP_ANONYMOUS: i32 = 0x1000;
    #[cfg(target_os = "linux")]
    const MAP_ANONYMOUS: i32 = 0x20;
    const PAGE: usize = 4096;
    const BASE: u64 = 0xffff_ffff_ffff_ff00;
    // Bit 31 set, so UXTW and SXTW differ, and high bits SXTW drops.
    const INDEX: u64 = 0x8000_0001_fedc_ba98;
    const INDEX_REGISTER: u8 = 5;
    #[repr(C)]
    struct Result {
        rax: u64,
        rdx: u64,
    }
    let run = |body: &dyn Fn(&mut Code)| -> Result {
        let mut code = Code::new();
        code.asm()
            .mov(asm::Size::Qword, asm::Gpr::Rax, asm::Gpr::Rsi);
        body(&mut code);
        code.asm().ret();
        let mut state = crate::GuestState::default();
        state.x[usize::from(INDEX_REGISTER)] = INDEX;
        // SAFETY: private anonymous memory, RX after the copy and
        // unmapped after the call; the code reads only `state`.
        unsafe {
            let page = mmap(core::ptr::null_mut(), PAGE, 3, 2 | MAP_ANONYMOUS, -1, 0);
            assert_ne!(page as usize, usize::MAX);
            core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
            assert_eq!(mprotect(page, PAGE, 5), 0);
            let entry: unsafe extern "sysv64" fn(*const crate::GuestState, u64) -> Result =
                core::mem::transmute(page);
            let result = entry(&state, BASE);
            assert_eq!(munmap(page, PAGE), 0);
            result
        }
    };
    for displacement in [0, 8, -256, 0x1000, i32::MIN] {
        let added = BASE.wrapping_add_signed(i64::from(displacement));
        for (mode, address, writeback) in [
            (AddressMode::Offset, added, None),
            (AddressMode::PreIndex, added, Some(added)),
            (AddressMode::PostIndex, BASE, Some(added)),
        ] {
            let result = run(&|code| address_add(code, displacement, mode));
            assert_eq!(result.rax, address, "{mode:?} {displacement}");
            if let Some(writeback) = writeback {
                assert_eq!(result.rdx, writeback, "{mode:?} {displacement}");
            }
        }
    }
    for extend in [
        IndexExtend::Uxtw,
        IndexExtend::Sxtw,
        IndexExtend::Lsl,
        IndexExtend::Sxtx,
    ] {
        let extended = match extend {
            IndexExtend::Uxtw => u64::from(INDEX as u32),
            IndexExtend::Sxtw => i64::from(INDEX as i32) as u64,
            IndexExtend::Lsl | IndexExtend::Sxtx => INDEX,
        };
        for shift in 0..=4 {
            let index = Register::X(INDEX_REGISTER);
            let result = run(&|code| register_offset::index_add(code, index, extend, shift));
            let expected = BASE.wrapping_add(extended << shift);
            assert_eq!(result.rax, expected, "{extend:?} {shift}");
            let zero = run(&|code| register_offset::index_add(code, Register::Zero, extend, shift));
            assert_eq!(zero.rax, BASE, "ZR {extend:?} {shift}");
        }
    }
}

/// The check of each placement runs on the host and passes exactly the
/// guest's native ranges: with five-level paging the addresses whose
/// bits 63:48 are all clear or all set, with four-level paging the lower
/// half and `[U, 2^64)`. Past a mispredicted branch the mask alone
/// replaces every other address.
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn the_guest_range_check_passes_exactly_the_native_ranges() {
    use core::ffi::c_void;
    unsafe extern "C" {
        fn mmap(
            address: *mut c_void,
            bytes: usize,
            protection: i32,
            flags: i32,
            fd: i32,
            offset: i64,
        ) -> *mut c_void;
        fn mprotect(address: *mut c_void, bytes: usize, protection: i32) -> i32;
        fn munmap(address: *mut c_void, bytes: usize) -> i32;
    }
    #[cfg(target_os = "macos")]
    const MAP_ANONYMOUS: i32 = 0x1000;
    #[cfg(target_os = "linux")]
    const MAP_ANONYMOUS: i32 = 0x20;
    const PAGE: usize = 4096;
    const LOWER_TOP: u64 = 1 << 47;
    let five = |address: u64| matches!(address >> 48, 0 | 0xffff);
    for slices in [None, Some(2), Some(3), Some(63)] {
        let range = slices.map_or(RangeCheck::FIVE_LEVEL, RangeCheck::four_level);
        let upper = slices.map_or(0, |slices| UPPER_HALF + (u64::from(slices) << SLICE_SHIFT));
        let native = |address: u64| match slices {
            None => five(address),
            Some(_) => address < LOWER_TOP || address >= upper,
        };
        let full = range.code();
        let (bytes, ends) = RangeCheck::at(&full).expect("a check");
        assert_eq!(bytes, full.len());
        let (check, rest) = full.split_at(ends[4]);
        let (trap, mask) = rest.split_at(ends[5] - ends[4]);
        assert_eq!(trap, [0x0f, 0x0b]);
        assert_eq!(full.len(), if range.bias == 1 { 30 } else { 31 });
        // mov rax,rdi; the check with `xor eax,eax` (a failure, also two
        // bytes, whose flags the mask then leaves alone) where its UD2
        // is; the mask; ret. Then the same with the branch replaced by a
        // two-byte NOP, as a mispredicted check runs it.
        let mut code = vec![0x48, 0x89, 0xf8];
        code.extend(check);
        code.extend([0x31, 0xc0]);
        code.extend(mask);
        code.push(0xc3);
        let speculated = code.len();
        code.extend([0x48, 0x89, 0xf8]);
        code.extend(&check[..check.len() - 2]);
        code.extend([0x66, 0x90]);
        code.extend(mask);
        code.push(0xc3);
        // SAFETY: private anonymous memory, RX after the copy and
        // unmapped after the calls; the code touches no memory.
        unsafe {
            let page = mmap(core::ptr::null_mut(), PAGE, 3, 2 | MAP_ANONYMOUS, -1, 0);
            assert_ne!(page as usize, usize::MAX);
            core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
            assert_eq!(mprotect(page, PAGE, 5), 0);
            let passes = |address: u64| {
                let entry: unsafe extern "sysv64" fn(u64) -> u64 = core::mem::transmute(page);
                let result = entry(address);
                assert!(result == address || result == 0);
                let masked: unsafe extern "sysv64" fn(u64) -> u64 =
                    core::mem::transmute(page.cast::<u8>().add(speculated));
                let expected = if result == address {
                    address
                } else {
                    range.masked
                };
                assert_eq!(masked(address), expected, "{address:#x}");
                result == address
            };
            let mut edges = vec![
                1,
                LOWER_TOP - 1,
                LOWER_TOP,
                0x0000_ffff_ffff_ffff,
                0x0001_0000_0000_0000,
                // The five-level window, PML5 entry 64.
                0x0040_0000_0000_0000,
                0x00ff_ffff_ffff_ffff,
                0x7fff_ffff_ffff_ffff,
                0x8000_0000_0000_0000,
                0xff00_0000_0000_0000,
                0xfffe_ffff_ffff_ffff,
                0xffff_0000_0000_0000,
                UPPER_HALF - 1,
                // The four-level window's start.
                UPPER_HALF,
                u64::MAX,
                // A tagged pointer.
                0x0f00_0000_0000_1234,
            ];
            if slices.is_some() {
                edges.extend([upper - 1, upper, range.masked, upper - (1 << 35)]);
            }
            for address in edges {
                assert_eq!(passes(address), native(address), "{range:?} {address:#x}");
            }
            assert!(!native(range.masked) && !five(range.masked) || slices.is_some());
            let mut seed = 0x9e37_79b9_7f4a_7c15u64;
            for _ in 0..4096 {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                // Bias most samples to the ranges' edges.
                let near = [0, LOWER_TOP, UPPER_HALF, upper, 1 << 48, 0xffff_u64 << 48];
                let offset = (seed.rotate_left(17) & 0xffff_ffff) as i64 - (1 << 31);
                let address = match seed >> 61 {
                    0 => seed,
                    top => near[(top as usize) % near.len()].wrapping_add_signed(offset << 9),
                };
                assert_eq!(passes(address), native(address), "{range:?} {address:#x}");
            }
            assert_eq!(munmap(page, PAGE), 0);
        }
    }
}

/// The translated variant's check runs on the host: a native address
/// passes unchanged, and any other calls the helper, which finds the
/// guest address in RCX and the access after its return address, and
/// whose host address the access then uses unmasked. A mispredicted
/// branch past the call still masks.
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn translated_checks_call_the_helper_outside_the_native_ranges() {
    use core::ffi::c_void;
    unsafe extern "C" {
        fn mmap(
            address: *mut c_void,
            bytes: usize,
            protection: i32,
            flags: i32,
            fd: i32,
            offset: i64,
        ) -> *mut c_void;
        fn mprotect(address: *mut c_void, bytes: usize, protection: i32) -> i32;
        fn munmap(address: *mut c_void, bytes: usize) -> i32;
    }
    #[cfg(target_os = "macos")]
    const MAP_ANONYMOUS: i32 = 0x1000;
    #[cfg(target_os = "linux")]
    const MAP_ANONYMOUS: i32 = 0x20;
    const PAGE: usize = 4096;
    const KEY: u32 = 0x5a5a_0000;
    let range = RangeCheck::four_level(2);
    let upper = UPPER_HALF + (2 << SLICE_SHIFT);
    let access = Access::write(24).atomic();
    // The helper: the access's two bytes into the key's low half, the
    // return address past them, RAX the guest address with the key.
    // mov rdx,[rsp]; movzx edx,word [rdx]; add qword [rsp],2;
    // mov rax,rcx; xor rax,KEY; xor rax,rdx; ret.
    let mut helper = vec![0x48, 0x8b, 0x14, 0x24, 0x0f, 0xb7, 0x12];
    helper.extend([0x48, 0x83, 0x04, 0x24, 0x02, 0x48, 0x89, 0xc8, 0x48, 0x35]);
    helper.extend(KEY.to_le_bytes());
    helper.extend([0x48, 0x31, 0xd0, 0xc3]);
    // SAFETY: private anonymous memory, RX after the copy and unmapped
    // after the calls; the code touches only the stack.
    unsafe {
        let page = mmap(core::ptr::null_mut(), PAGE, 3, 2 | MAP_ANONYMOUS, -1, 0);
        assert_ne!(page as usize, usize::MAX);
        let slot = alloc::boxed::Box::new(page as u64);
        // mov rax,rdi; the check; ret, then the same with the branch
        // always taken, as a misprediction runs it.
        let mut check = Code::new();
        range.emit_translated(&mut check, &*slot as *const u64 as u64, access);
        let (bytes, ends) = RangeCheck::at(&check).unwrap();
        assert_eq!(bytes, check.len());
        let mut code = helper.clone();
        let entry = code.len();
        code.extend([0x48, 0x89, 0xf8]);
        code.extend(&check);
        code.push(0xc3);
        let speculated = code.len();
        code.extend([0x48, 0x89, 0xf8]);
        let branch = code.len() + ends[4] - 2;
        code.extend(&check);
        code[branch] = 0xeb; // jmp in place of jbe
        code.push(0xc3);
        core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast(), code.len());
        assert_eq!(mprotect(page, PAGE, 5), 0);
        let run = |at: usize, address: u64| {
            let function: unsafe extern "sysv64" fn(u64) -> u64 =
                core::mem::transmute(page.cast::<u8>().add(at));
            function(address)
        };
        let called = |address: u64| {
            address ^ u64::from(KEY) ^ u64::from(u16::from_le_bytes([access.bytes, access.flags]))
        };
        for address in [
            0,
            0x1234,
            (1 << 47) - 1,
            upper,
            u64::MAX,
            1 << 47,
            UPPER_HALF,
            upper - 1,
            range.masked,
            0x0040_0000_0000_0000,
        ] {
            let native = address < 1 << 47 || address >= upper;
            let expected = if native { address } else { called(address) };
            assert_eq!(run(entry, address), expected, "{address:#x}");
            let masked = if native { address } else { range.masked };
            assert_eq!(run(speculated, address), masked, "{address:#x}");
        }
        assert_eq!(munmap(page, PAGE), 0);
    }
}

/// A four-level placement's masked address lies in its guard, which no
/// access extent leaves, and its fields fit the encoding.
#[test]
fn four_level_checks_mask_into_the_guard_below_the_upper_range() {
    for slices in 2..HALF_SLICES {
        let range = RangeCheck::four_level(slices);
        let upper = UPPER_HALF + (u64::from(slices) << SLICE_SHIFT);
        assert!(range.valid());
        assert!(range.masked >= upper - (1 << SLICE_SHIFT) && range.masked < upper);
        assert!(upper - range.masked >= 1 << 35);
        let mut code = Code::new();
        range.emit(&mut code);
        // A bias of 1 (63 slices) is INC, as five-level paging's.
        let ends = if slices == HALF_SLICES - 1 {
            [3, 7, 9, 12, 14, 16, 26, 30]
        } else {
            [3, 7, 10, 13, 15, 17, 27, 31]
        };
        assert_eq!(RangeCheck::at(&code), Some((ends[7], &ends[..])));
    }
    assert_eq!(
        RangeCheck::at(&RangeCheck::FIVE_LEVEL.code()).unwrap().1,
        [3, 7, 9, 12, 14, 16, 26, 30]
    );
    let refused = MemoryChecks::DEFAULT.with_range(RangeCheck::four_level(2));
    assert_eq!(refused.range.bias, 62);
    assert_eq!(refused.range.bound, 125);
}

#[test]
fn constructed_context_operations_return_an_explicit_error() {
    const BARRIER_OPTION_OSH: u8 = 3;
    const BARRIER_OPTION_SY: u8 = 15;
    const BTI_JC_TARGETS: u8 = 3;
    const RESERVED_HINT_IMMEDIATE: u8 = 127;
    let pc = GuestAddress(0x1000);
    for operation in [
        Synchronization::DataCompletion {
            option: BARRIER_OPTION_OSH,
            scope: Scope::OuterShareable,
            requirement: Requirement::All,
            nxs: false,
        },
        Synchronization::InstructionSynchronization {
            option: BARRIER_OPTION_SY,
        },
        Synchronization::StoreBypassBarrier { physical: false },
        Synchronization::StoreBypassBarrier { physical: true },
        Synchronization::BranchTarget {
            targets: BTI_JC_TARGETS,
        },
        Synchronization::Wait {
            kind: WaitKind::Event,
            timeout_register: None,
        },
        Synchronization::SendEvent { local: false },
        Synchronization::ErrorSynchronization,
        Synchronization::TraceSynchronization,
        Synchronization::OtherHint {
            immediate: RESERVED_HINT_IMMEDIATE,
        },
    ] {
        let instructions = [
            Instruction {
                pc,
                operation: Operation::Nop,
            },
            Instruction {
                pc: GuestAddress(pc.0 + size_of::<u32>() as u64),
                operation: Operation::Synchronization(operation),
            },
        ];
        assert!(
            matches!(Emitter.emit_for_target(&instructions, crate::TargetCpu::Baseline),
        Err(UnsupportedReason::PrivilegedOperation { address }) if address == instructions[1].pc)
        );
    }
}

/// The capture's arithmetic on every flag combination: the SETcc bytes
/// at their register positions, shifted, combined, multiplied and masked.
#[test]
fn the_flag_capture_packs_every_combination_into_nzcv() {
    for flags in 0u32..16 {
        let [n, z, c, v] = [3, 2, 1, 0].map(|bit| (flags >> bit) & 1);
        let accumulator = (n | z << 8) & CAPTURED_BITS;
        let data = (c | v << 8) & CAPTURED_BITS;
        let combined = accumulator | data << CAPTURE_CARRY_SHIFT;
        let packed = combined.wrapping_mul(CAPTURE_MULTIPLIER) & CAPTURE_NZCV_MASK;
        assert_eq!(packed, flags << 28, "NZCV {flags:#06b}");
    }
    let mut code = Code::new();
    capture_nzcv(&mut code, false);
    let mut borrow = Code::new();
    capture_nzcv(&mut borrow, true);
    // Only the carry's SETcc differs: SETB or SETAE DL.
    assert_eq!(code.len(), borrow.len());
    assert_eq!(code[6..9], [0x0f, 0x92, 0xc2]);
    assert_eq!(borrow[6..9], [0x0f, 0x93, 0xc2]);
    assert_eq!(code[12..15], CAPTURE_COMBINE);
    assert_eq!((code.instructions(), borrow.instructions()), (7, 7));
}

/// The checks emit the bytes the region cost gates find them by, one
/// counted instruction for each end.
#[test]
fn checks_emit_the_patterns_the_cost_gates_match() {
    let mut code = Code::new();
    stack_alignment_check(&mut code);
    assert_eq!(code, STACK_ALIGNMENT_CHECK);
    assert_eq!(code.instructions(), STACK_ALIGNMENT_CHECK_ENDS.len());
    for range in [RangeCheck::FIVE_LEVEL, RangeCheck::four_level(2)] {
        let mut code = Code::new();
        range.emit(&mut code);
        let (_, ends) = RangeCheck::at(&code).unwrap();
        assert_eq!(code.instructions(), ends.len());
        let mut code = Code::new();
        range.emit_translated(&mut code, 0x1000, Access::read(8));
        let (bytes, ends) = RangeCheck::at(&code).unwrap();
        assert_eq!(bytes, code.len());
        // The access's two bytes after the call are data.
        assert_eq!(code.instructions(), ends.len() - 1);
    }
}
