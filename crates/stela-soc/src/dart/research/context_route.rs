//! A Stela-owned native USB endpoint assigned to a logical T6000 context.
//!
//! Original SPTM270bcf08..bcfac restores each bank's used TTBR0 from a common
//! per-SID record;270bd234..bd290 similarly restores its TCR. Independent
//! banks can nevertheless diverge through MMIO, lifecycle or table memory.
//! Recheck successful translations before each DMA page/chunk.
//!
//! This resource is an explicit native fabric assignment at controller
//! construction, keeping client and mapper owners. DT properties alone
//! are not that assignment. It does not recover Apple's physical USB
//! LLT/BLK classifier: all banks and every current remap preimage of the
//! assigned context must agree. A fault cannot identify its physical bank
//! or incoming SID here and therefore refuses without latching metadata.
use super::super::{Dart, Model};
use crate::Result;
use stela_contracts::refuse;
use {
    stela_contracts::bus::Access, stela_contracts::dma::DmaError, stela_contracts::dma::Iommu,
    stela_contracts::dma::Memory,
};

const USB_TRADS: usize = 2;
const STREAMS: usize = 16;
const PAGE: u64 = 0x4000;

/// An explicitly assigned native USB DMA owner, independent of any claimed
/// Apple physical traffic classifier. Root placement must supply the full
/// ordered pair of TRAD owners and keep them for this resource's
/// lifetime. Moving/replacing a bank requires assigning a new resource.
pub struct T6000ContextRoute {
    client_phandle: u32,
    mapper_phandle: u32,
    context: usize,
    banks: [*const Dart; USB_TRADS],
}

impl T6000ContextRoute {
    /// Assign one Stela-owned native USB endpoint to its validated logical
    /// mapper context at controller creation. This is not DT admission.
    /// The parent keeps the client/mapper and bank device IDs.
    pub fn assign_native_usb(
        client_phandle: u32,
        mapper_phandle: u32,
        context: usize,
        banks: &[&Dart],
    ) -> Result<Self> {
        if client_phandle == 0 || mapper_phandle == 0 || client_phandle == mapper_phandle {
            return Err(refuse!(
                "T6000 native USB context route needs distinct client and mapper owners"
            ));
        }
        if context >= STREAMS {
            return Err(refuse!(
                "T6000 native USB mapper context exceeds its native profile"
            ));
        }
        validate_banks(banks)?;
        Ok(Self {
            client_phandle,
            mapper_phandle,
            context,
            banks: [core::ptr::from_ref(banks[0]), core::ptr::from_ref(banks[1])],
        })
    }

    pub const fn owners(&self) -> (u32, u32) {
        (self.client_phandle, self.mapper_phandle)
    }

    pub const fn context(&self) -> usize {
        self.context
    }

    /// Borrow the same full bank cohort for the existing DMA Port. These
    /// borrows prevent MMIO/lifecycle changes while a chunk is checked and
    /// transferred. A proof is never cached across DMA calls.
    pub fn bind<'a>(&'a self, banks: &'a [&'a Dart]) -> Result<T6000ContextDma<'a>> {
        validate_banks(banks)?;
        if banks
            .iter()
            .zip(self.banks)
            .any(|(bank, assigned)| !core::ptr::eq(*bank, assigned))
        {
            return Err(refuse!(
                "T6000 native USB context route bank ownership changed"
            ));
        }
        Ok(T6000ContextDma { route: self, banks })
    }
}

fn validate_banks(banks: &[&Dart]) -> Result<()> {
    if banks.len() != USB_TRADS || core::ptr::eq(banks[0], banks[1]) {
        return Err(refuse!(
            "T6000 native USB context route needs its two distinct TRAD banks"
        ));
    }
    for bank in banks {
        if !matches!(&bank.model, Model::Legacy(model) if model.context_route_geometry()) {
            return Err(refuse!(
                "T6000 native USB context route requires plain 16-SID T6000 TRAD geometry"
            ));
        }
    }
    Ok(())
}

/// A live context-route borrow. Its stream argument is the assigned logical
/// context, never a guessed incoming hardware SID.
pub struct T6000ContextDma<'a> {
    route: &'a T6000ContextRoute,
    banks: &'a [&'a Dart],
}

impl Iommu for T6000ContextDma<'_> {
    fn page(&self) -> u64 {
        PAGE
    }

    fn translate(
        &mut self,
        memory: &mut dyn Memory,
        stream: usize,
        iova: u64,
        last: u64,
        write: bool,
        _: &mut Access<'_>,
    ) -> Result<u64, DmaError> {
        if stream != self.route.context {
            return Err(DmaError::Unsupported(refuse!(
                "T6000 native USB DMA does not name its assigned logical context"
            )));
        }
        if last < iova || iova / PAGE != last / PAGE {
            return Err(DmaError::Unsupported(refuse!(
                "T6000 context route translation must cover one ordered page chunk"
            )));
        }
        let mut physical = None;
        for bank in self.banks {
            let Model::Legacy(model) = &bank.model else {
                unreachable!("checked immutable bank borrow")
            };
            let candidate =
                model.checked_context_translation(memory, self.route.context, iova, last, write)?;
            if physical.is_some_and(|previous| previous != candidate) {
                return Err(DmaError::Unsupported(refuse!(
                    "T6000 native USB TRAD alternatives have divergent DMA targets"
                )));
            }
            physical = Some(candidate);
        }
        Ok(physical.expect("checked nonempty bank cohort"))
    }
}

#[cfg(test)]
mod tests;
