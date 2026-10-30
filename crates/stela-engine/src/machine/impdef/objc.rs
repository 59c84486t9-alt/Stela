//! Source-checked ObjC branch-predictor configuration fields.
//!
//! Apple XNU xnu-12377.121.6 `pexpert/pexpert/arm64/apple_arm64_regs.h`,
//! lines 72–87, SHA-256
//! `7a1bd8e62ae790ec5a4e3cc278c5ad6da11c48229a34294dbe10ade3c7564ff1`.
//! These masks check the fields Stela preserves, not hardware RES0 bits.
//! Unknown fields refuse; in particular a tagged address's high byte is not
//! silently removed. All values of each named field are preserved verbatim:
//! syscall validation policy is not a register's architectural behavior.
//!
//! The original 26A434 M2–M6 kernels save/restore the pair and the matching
//! SPTMs save, clear and restore CTL (coordinates and immutable input hashes in
//! `docs/research/objc-predictor.md`). M1 has no original accesses and keeps
//! the existing census-based unallocated inference, not a hardware claim.

/// Address bits [55:0].
pub(super) const ADDRESS: u64 = 0x00ff_ffff_ffff_ffff;
/// Class mask bits [52:27].
const MASK: u64 = 0x001f_ffff_f800_0000;
/// Class-pointer architectural register index bits [21:17].
const CLASS_POINTER_REGISTER: u64 = 0x003e_0000;
/// Selector architectural register index bits [16:12].
const SELECTOR_REGISTER: u64 = 0x0001_f000;
/// Branch offset bits [6:0]; the source does not establish an execution effect.
const BRANCH_OFFSET: u64 = 0x007f;
/// All fields named by the pinned header; gaps are unchecked, not masked off.
pub(super) const CONTROL: u64 = MASK | CLASS_POINTER_REGISTER | SELECTOR_REGISTER | BRANCH_OFFSET;

pub(super) const EVIDENCE: &str = "Apple XNU xnu-12377.121.6 apple_arm64_regs.h:72–87 \
    names the ObjC predictor address and four control fields; original 26A434 M2–M6 \
    kernels save/restore the pair and SPTMs save/clear/restore control. Only named \
    fields are preserved; other bits refuse. Per-PE prediction hint, with no \
    architectural result, access-permission or speculative-timing enforcement \
    claim; reset zero is a model inference. See docs/research/objc-predictor.md";
