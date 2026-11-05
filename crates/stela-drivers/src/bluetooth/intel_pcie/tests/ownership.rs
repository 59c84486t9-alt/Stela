//! Cold preparation and native DMA lifetime models; no physical validation.
use super::*;
use crate::bus::{
    dma::{
        DomainAllocator,
        mapping::{Direction, DmaDomain, DmaError, DomainMapping},
        memory::{CacheAttribute, MemoryError, PageBacking, PageGeometry, PageSource, PinnedPages},
        pages::DmaPages,
    },
    irq,
    mmio::owned::PhysicalSpan,
    pci::{
        ConfigSpace, Function,
        owned::test_support::{Counters, fixture},
        requester::{
            FunctionRole, RequesterBinding,
            preparation::{self, Root},
        },
    },
};
use alloc::{boxed::Box, sync::Arc};
use core::{
    ops::Range,
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering},
};
extern crate std;
use std::sync::Mutex;
const BASE: u64 = 0x1400_0000;
const BAR_BYTES: u64 = 0x10000;
const CLOCK: crate::Clock = crate::Clock {
    ticks_per_microsecond: 1000,
};
mod model;
use model::*;
mod cold;
mod lifetime;
