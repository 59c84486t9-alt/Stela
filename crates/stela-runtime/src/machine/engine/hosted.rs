//! What a kernel the host runs in place of guest EL1 needs from the engine:
//! returning from the exception it took at its vector, and dropping compiled
//! code for guest memory the host itself changed. The hosted Darwin process
//! (`crate::hosted`) takes every EL0 exception at a host breakpoint on the
//! EL1 vector, services it in Rust and returns here, as XNU's exception
//! return would.
use super::{Devices, FETCH_PAGE, Host, Machine, Stop};
use crate::pauth;

impl<H: Host, D: Devices> Machine<H, D> {
    /// ERET from the current EL through its ELR and SPSR, as the host's
    /// kernel returns from the exception the engine took to it. System
    /// registers the host changed meanwhile take effect for the next fetch.
    pub fn return_from_exception(&mut self) {
        let target = self.cpu.exception_link();
        self.cpu.exception_return(target);
        self.pacm_written = true;
        self.sync_regime();
    }

    /// The pointer-authentication context the PE's own PAC instructions
    /// use: its keys, its PAC version and the current regime's layout. A
    /// kernel that signs pointers for the guest signs them with it.
    pub fn pointer_signer(&self) -> Result<pauth::Context, Stop> {
        self.pointer_context()
    }

    /// Forget the blocks compiled from guest memory in `[address,
    /// address + bytes)`, which the host wrote or remapped without the
    /// guest's own IC maintenance.
    pub fn invalidate_code(&mut self, address: u64, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let first = address & !(FETCH_PAGE - 1);
        let last = address.saturating_add(bytes - 1) & !(FETCH_PAGE - 1);
        if (last - first) / FETCH_PAGE >= self.code_pages.len() as u64 {
            let pages: alloc::vec::Vec<u64> = self
                .code_pages
                .range(first..=last)
                .map(|(&page, _)| page)
                .collect();
            for page in pages {
                self.invalidate_code_page(page);
            }
            return;
        }
        let mut page = first;
        loop {
            self.invalidate_code_page(page);
            if page == last {
                break;
            }
            page += FETCH_PAGE;
        }
    }
}
