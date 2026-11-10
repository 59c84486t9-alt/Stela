//! One heap owner's live bytes and high-water mark, kept by the owner's
//! allocation entry points, for the heartbeat's per-owner heap line.
use core::sync::atomic::{AtomicUsize, Ordering};

pub struct Tally {
    live: AtomicUsize,
    peak: AtomicUsize,
}

impl Tally {
    pub const fn new() -> Self {
        Self {
            live: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }

    /// Count `bytes` the owner got.
    pub fn allocated(&self, bytes: usize) {
        let live = self.live.fetch_add(bytes, Ordering::Relaxed) + bytes;
        if live > self.peak.load(Ordering::Relaxed) {
            self.peak.fetch_max(live, Ordering::Relaxed);
        }
    }

    /// Count `bytes` the owner gave back. An allocation's count happens
    /// before its release's: the pointer passes between them.
    pub fn released(&self, bytes: usize) {
        self.live.fetch_sub(bytes, Ordering::Relaxed);
    }

    /// The bytes held now and the most held at once.
    pub fn usage(&self) -> (usize, usize) {
        (
            self.live.load(Ordering::Relaxed),
            self.peak.load(Ordering::Relaxed),
        )
    }
}

impl Default for Tally {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_keeps_the_live_bytes_and_their_most() {
        let tally = Tally::new();
        tally.allocated(100);
        tally.allocated(50);
        tally.released(100);
        tally.allocated(20);
        assert_eq!(tally.usage(), (70, 150));
    }
}
