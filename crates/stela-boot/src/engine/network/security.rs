//! Native TLS admission requires the boot owner's UTC-correlated clock.
use alloc::sync::Arc;
use stela_runtime::net::TlsUnavailable;

pub(super) fn native() -> Result<Arc<stela_tls::ClientConfig>, TlsUnavailable> {
    // Captured wall_seconds/wall_tsc and bootstrap frequency cannot establish
    // the epoch/lifetime contract of a continuously checked source.
    Err(TlsUnavailable::CorrelatedClock)
}
