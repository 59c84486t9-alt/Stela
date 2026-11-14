//! A page fault that only the faulting context may serve: one on a mapping
//! Linux moved, whose refault may sleep, as Linux's fault handler does in
//! the faulting task. The #PF handler runs on its IST stack with its image
//! slot active, where nothing may wait for Linux. It makes the faulting code
//! call a server instead: as a CALL at the faulting instruction would, it
//! stores the instruction's address below the faulting RSP, and the server's
//! arguments below that, and resumes at the server's entry. The server keeps
//! every register and returns to the instruction, which runs again.
//!
//! Nothing lives below a host stack's RSP: every C target builds with
//! `-mno-red-zone`, and the UEFI target has no red zone.
use crate::interrupt_image::Frame;
use core::ops::Range;

const PAGE: u64 = 4096;
const PAGE_FAULT: u64 = 14;
/// The page-fault error code's write bit.
const WRITE: u64 = 1 << 1;

/// The words a redirect stores below the faulting RSP, lowest first: the
/// fault's address, 1 when it wrote, and the faulting instruction's address.
pub const WORDS: usize = 3;

/// Where the faulting code calls the server from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Redirect {
    /// The faulting stack's RSP at the server's entry, where `words` go.
    pub rsp: u64,
    pub words: [u64; WORDS],
}

/// Why a fault cannot call the server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refused {
    NotPageFault,
    /// Only host code runs at CPL0 here.
    User,
    /// The fault came from the server's own entry, before it saved the
    /// faulting context: a second redirect would lose the first.
    Server,
    /// The faulting RSP is not a stack pointer the words fit below.
    Stack,
    /// The words would land on the faulting page: the stack ran into it.
    OwnStack,
}

impl Redirect {
    /// The call `frame`'s faulting instruction makes to the server, whose
    /// entry code is `server`.
    pub fn plan(frame: &Frame, address: u64, server: Range<u64>) -> Result<Self, Refused> {
        if frame.vector != PAGE_FAULT {
            return Err(Refused::NotPageFault);
        }
        if frame.cs & 3 != 0 {
            return Err(Refused::User);
        }
        if server.contains(&frame.rip) {
            return Err(Refused::Server);
        }
        if !frame.rsp.is_multiple_of(8) {
            return Err(Refused::Stack);
        }
        let rsp = frame
            .rsp
            .checked_sub(8 * WORDS as u64)
            .ok_or(Refused::Stack)?;
        if (rsp / PAGE..=(frame.rsp - 1) / PAGE).contains(&(address / PAGE)) {
            return Err(Refused::OwnStack);
        }
        Ok(Self {
            rsp,
            words: [address, u64::from(frame.error & WRITE != 0), frame.rip],
        })
    }

    /// Resume `frame` at the server's `entry`, once the caller stored
    /// `words` at `rsp`.
    pub fn apply(&self, frame: &mut Frame, entry: u64) {
        frame.rsp = self.rsp;
        frame.rip = entry;
    }
}

#[cfg(test)]
mod tests;
