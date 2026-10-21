//! T6000's UMMS companion to a legacy TRAD, not the t8110 capture layout.
//!
//! Original 26A434 mac13j AppleT6000DART reads BUILD_PARAMS low16, selects
//! pages through the SPTM at UMMS5c, and reads 2048 words at2000..3ffc.
//! The native translator is synchronous/cacheless: it owns no UMMS context
//! cache, capture store or enabled performance counters. Those resource
//! declarations are not physical-chip reset/capability measurements.
//!
//! SPTM VA270bb5ec..bb600 admits no selection for count0. The kernel's
//! count*4 allocation permits zero through IOMallocTypeVarImpl (VA c3e25dc)
//! and the minimum allocator zone (bc21ae8..af4); its capture loop returns
//! before selection when count0 (9ec1acc..ad0). Diagnostic register capture
//! is a separate contract: unqualified auxiliary words still refuse.
//!
//! No UMMS-stage fault can occur while context selection refuses in TRAD.
//! Its empty error slot and disabled counter status are actual native state,
//! not mirrors of the paired TRAD fault. Nonzero counter control, hardware
//! lock, metadata and capture payloads remain explicit requirements.

const BUILD_PARAMS: u64 = 0;
const CONFIG: u64 = 0x20;
const AUTO_CLOCK_GATING: u32 = 1 << 31;
const ERROR: u64 = 0x40;
const ERROR_CODES: u32 = 0x27c;
const SELECT_WINDOW: u64 = 0x5c;
const PERF_CONTROL: u64 = 0x1000;
const PERF_STATUS: u64 = 0x1008;
const PERF_OVERFLOW: u32 = 1 << 20;

/// The only implemented performance state. Enabling events is refused until
/// their actual counts, control, overflow and interrupt effects are known.
#[derive(Default)]
pub(super) enum Performance {
    #[default]
    Disabled,
}

impl Performance {
    pub(super) fn control(&self) -> u32 {
        match self {
            Self::Disabled => 0,
        }
    }

    pub(super) fn disable(&mut self, value: u32) -> Result<(), &'static str> {
        if value != 0 {
            return Err("T6000 DART enabled performance event/count/overflow semantics");
        }
        *self = Self::Disabled;
        Ok(())
    }

    pub(super) fn status(&self) -> u32 {
        match self {
            Self::Disabled => 0,
        }
    }

    pub(super) fn acknowledge(&mut self, value: u32, mask: u32) -> Result<(), &'static str> {
        if value & !mask != 0 {
            return Err("unknown T6000 DART performance acknowledgement bits");
        }
        // No event is enabled and no overflow is pending. A valid W1C cannot
        // create an event, enable counting or acknowledge an ordinary fault.
        Ok(())
    }
}

pub(super) struct Umms {
    automatic_clock_gating: Option<bool>,
    performance: Performance,
}

impl Default for Umms {
    fn default() -> Self {
        // A newly created Stela resource starts with automatic gating off.
        // This is an owned handoff, not an Apple power-on reset value.
        Self {
            automatic_clock_gating: Some(false),
            performance: Performance::Disabled,
        }
    }
}

impl Umms {
    pub(super) fn clear(&mut self) {
        // No original reset value for CONFIG20 is recovered. A destructive
        // reset/loss invalidates that observation until software writes it;
        // retaining a power domain preserves the previous observation.
        self.automatic_clock_gating = None;
        self.performance = Performance::Disabled;
    }

    pub(super) fn read(&self, offset: u64) -> Result<u32, &'static str> {
        match offset {
            // No context/capture store and no hardware configuration lock.
            BUILD_PARAMS => Ok(0),
            CONFIG => self
                .automatic_clock_gating
                .map(|enabled| if enabled { AUTO_CLOCK_GATING } else { 0 })
                .ok_or("T6000 UMMS CONFIG reset value requires reprogramming or qualification"),
            // Context activation is refused before DMA; the UMMS error slot
            // is empty. A TRAD translation fault belongs to TRAD40 instead.
            ERROR => Ok(0),
            PERF_CONTROL => Ok(self.performance.control()),
            PERF_STATUS => Ok(self.performance.status()),
            0x44 | 0x48 | 0x4c | 0x50 | 0x58 | 0x60 | 0x64 => {
                Err("T6000 UMMS auxiliary fault/capture field encoding is unqualified")
            }
            0x1004 | 0x1020 => Err("T6000 UMMS performance configuration encoding is unqualified"),
            SELECT_WINDOW | 0x2000..=0x3ffc => {
                Err("cacheless T6000 UMMS has no capture selector or payload")
            }
            _ => Err("unknown T6000 UMMS register"),
        }
    }

    pub(super) fn write(&mut self, offset: u64, value: u32) -> Result<(), &'static str> {
        match offset {
            CONFIG => {
                if value & !AUTO_CLOCK_GATING != 0 {
                    return Err("T6000 UMMS hardware lock or unknown CONFIG effects");
                }
                // All work is synchronous: automatic clock gating only gates
                // idle internal work, not functional MMIO or a parent clock.
                self.automatic_clock_gating = Some(value & AUTO_CLOCK_GATING != 0);
                Ok(())
            }
            ERROR if value == 0 => Ok(()),
            // Original SPTM270bb324..bb358 selects one error code and does
            // a write/readback. With no UMMS-stage error it remains empty.
            ERROR if value & !ERROR_CODES == 0 && value.count_ones() == 1 => Ok(()),
            ERROR => Err("unqualified T6000 UMMS fault acknowledgement encoding"),
            PERF_CONTROL => self.performance.disable(value),
            PERF_STATUS => self.performance.acknowledge(value, PERF_OVERFLOW),
            BUILD_PARAMS => Err("T6000 UMMS capture capability is read-only"),
            SELECT_WINDOW | 0x2000..=0x3ffc => {
                Err("cacheless T6000 UMMS has no capture selector or payload")
            }
            _ => Err("unknown T6000 UMMS writable register or unqualified field effects"),
        }
    }
}
