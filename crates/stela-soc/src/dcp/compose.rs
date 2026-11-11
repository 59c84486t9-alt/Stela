//! A present composed outside the devices' lock.
//!
//! Composing a swap reads its surfaces' rows (to find the changed ones, then
//! to compose them) and writes the host scanout: milliseconds a frame, which
//! held every PE's device access while the step ran under the devices' lock.
//! On a board shared between PEs ([`super::Coprocessor::defer_compose`]) the
//! step instead resolves every DART page the latched layers can reach, under
//! the lock and without a fault's effects ([`crate::dart::Dart::resolve`]),
//! and leaves the compose to the PE that released the lock ([`Compose::run`])
//! with the scanout and its kept rows. The next transfer takes them back and
//! finishes the present as one in place would have at the same vblank: the
//! swaps it showed complete, in order, after the frame is on the scanout.
//!
//! The surfaces stay mapped through the compose: the AP takes a swap's
//! surfaces back only after its completion (D594), which follows the
//! compose. A layer with any page that does not resolve, and a read the
//! resolved pages do not cover, are presented in place under the lock
//! instead, where a DART fault has its effects as before. Calls that drop
//! queued swaps (an abort, a link shutdown, a sleep) first wait for a
//! compose in flight to end, so they act on the swaps as they were after it.
use super::super::scanout::{self, Composed, Layer, PixelFormat, Scanout};
use crate::Result;
use crate::handoff::Handoff;
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::ops::Range;
use stela_contracts::dma::{DmaError, Memory};

/// The physical address of every page a present's layers can read, from
/// the DART of the display pipe, by I/O address.
pub(crate) struct Pages {
    page: u64,
    /// Each reachable span's first page's I/O address and every page's
    /// physical address, in order.
    spans: Vec<(u64, Vec<u64>)>,
}

impl Pages {
    /// The pages `layers` can read, each resolved by `resolve` (the I/O
    /// address of a page to its physical address); `None` when one does not
    /// resolve or an address overflows, which leaves the present in place.
    pub(crate) fn resolve(
        layers: &[Layer],
        page: u64,
        mut resolve: impl FnMut(u64) -> core::result::Result<u64, DmaError>,
    ) -> Option<Self> {
        if !page.is_power_of_two() {
            return None;
        }
        let mut spans = Vec::new();
        for layer in layers {
            for span in layer_spans(layer)? {
                if span.is_empty() {
                    continue;
                }
                let first = span.start & !(page - 1);
                let mut pages = Vec::new();
                let mut at = first;
                while at < span.end {
                    pages.push(resolve(at).ok()?);
                    at = at.checked_add(page)?;
                }
                spans.push((first, pages));
            }
        }
        Some(Self { page, spans })
    }

    /// The physical address of the page holding `iova`, if resolved.
    fn physical(&self, iova: u64) -> Option<u64> {
        self.spans.iter().find_map(|(first, pages)| {
            let index = iova.checked_sub(*first)? / self.page;
            pages
                .get(usize::try_from(index).ok()?)
                .map(|physical| physical + iova % self.page)
        })
    }

    /// Read `bytes` at `iova` from guest RAM `memory` through the resolved
    /// pages, a page at a time as a port does; false when a page is not
    /// among them or not RAM.
    fn read(&self, memory: &mut dyn Memory, iova: u64, bytes: &mut [u8]) -> Result<bool, Missed> {
        let mut done = 0;
        while done < bytes.len() {
            let Some(address) = iova.checked_add(done as u64) else {
                return Err(Missed);
            };
            let chunk = ((self.page - address % self.page) as usize).min(bytes.len() - done);
            let Some(physical) = self.physical(address) else {
                return Err(Missed);
            };
            if memory
                .read_progress(physical, &mut bytes[done..done + chunk])
                .is_err()
            {
                return Ok(false);
            }
            done += chunk;
        }
        Ok(true)
    }
}

/// A read past the resolved pages: the present is made again in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Missed;

/// The I/O address ranges `layer`'s source rows occupy in each of its
/// surface's planes: from its first row's first pixel to its last row's
/// last; `None` on overflow.
fn layer_spans(layer: &Layer) -> Option<Vec<Range<u64>>> {
    let source = layer.source;
    if source.width == 0 || source.height == 0 {
        return Some(Vec::new());
    }
    let span = |base: u64, stride: u32, size: u64| {
        let first = u64::from(source.y)
            .checked_mul(stride.into())?
            .checked_add(u64::from(source.x).checked_mul(size)?)?
            .checked_add(base)?;
        let last_row = u64::from(source.y) + u64::from(source.height) - 1;
        let end = last_row
            .checked_mul(stride.into())?
            .checked_add((u64::from(source.x) + u64::from(source.width)).checked_mul(size)?)?
            .checked_add(base)?;
        Some(first..end)
    };
    let surface = layer.surface;
    let mut spans = alloc::vec![span(surface.iova, surface.stride, 4)?];
    if let PixelFormat::Xr10A8 {
        alpha,
        alpha_stride,
    } = surface.format
    {
        spans.push(span(alpha, alpha_stride, 1)?);
    }
    Some(spans)
}

/// What a compose hands back: the scanout and its kept rows, what the
/// present came to, and whether a read missed the resolved pages.
pub(crate) struct Composition {
    pub sink: Box<dyn Scanout>,
    pub composed: Composed,
    pub result: Result<()>,
    pub missed: bool,
}

/// A present's compose, run outside the devices' lock ([`Self::run`]).
pub struct Compose {
    sink: Box<dyn Scanout>,
    composed: Composed,
    layers: Vec<Layer>,
    damage: Option<Range<usize>>,
    pages: Pages,
    done: Arc<Handoff<Composition>>,
}

impl Compose {
    pub(crate) fn new(
        sink: Box<dyn Scanout>,
        composed: Composed,
        layers: Vec<Layer>,
        damage: Option<Range<usize>>,
        pages: Pages,
    ) -> (Self, Arc<Handoff<Composition>>) {
        let done = Handoff::new();
        (
            Self {
                sink,
                composed,
                layers,
                damage,
                pages,
                done: Arc::clone(&done),
            },
            done,
        )
    }

    /// Compose the present onto the scanout, reading guest RAM `memory`.
    pub fn run(self, memory: &mut dyn Memory) {
        let Self {
            mut sink,
            mut composed,
            layers,
            damage,
            pages,
            done,
        } = self;
        let mut missed = false;
        let read = |iova: u64, bytes: &mut [u8]| match pages.read(memory, iova, bytes) {
            Ok(reached) => reached,
            Err(Missed) => {
                missed = true;
                false
            }
        };
        let result = scanout::present(sink.as_mut(), &layers, damage, read, &mut composed);
        done.put(Composition {
            sink,
            composed,
            result,
            missed,
        });
    }
}
