//! A remote install image (`payload::Layout::Remote`): the IPSW on Apple's
//! CDN, read by URL-aware byte ranges over the mount's own network. HTTPS
//! requires the native owner's admitted TLS time and entropy capabilities.
//!
//! Each request carries `If-Range` with the entity tag setup recorded, so a
//! changed object fails instead of mixing two versions; the restore store
//! then checks the bytes as the manifest says (`payload::Member::sha256`).
//! One range at a time, from where the restore reads to the image's end
//! (an ordinary download from there), streams into a read-ahead buffer: a
//! read at or just past the buffer continues it, and a read elsewhere
//! starts one there, abandoning only what the TCP window has in flight.
//! [`Remote::pump`] keeps the buffer filling while the engine runs the
//! guest, so the download overlaps the restore's own writes. A range that
//! fails resumes from its last byte received, a few times.
use super::network::Shared;
use crate::Result;
use crate::output;
use alloc::{collections::VecDeque, string::String};
use stela_contracts::refuse;
use {
    stela_formats::payload::Layout, stela_formats::payload::PayloadManifest,
    stela_formats::payload::ReadAt, stela_runtime::net::HttpTransfer, stela_runtime::net::NetError,
    stela_runtime::net::http::Ranged,
};

/// How far [`Remote::pump`] fills ahead of the restore.
const AHEAD: usize = 32 << 20;
/// A read up to this far past the buffered bytes continues the open range.
const SKIP: u64 = 8 << 20;
/// Bytes already read that stay buffered for a re-read.
const KEEP: usize = 8 << 20;
/// Consecutive failures of one range's progress before a read fails; the
/// waits between them double from a second, about a minute in all.
const ATTEMPTS: u32 = 7;
/// The longest one wait for an open range's next frame lasts.
const WAIT_US: u64 = 100_000;

pub struct Remote {
    network: Shared,
    url: String,
    etag: String,
    len: u64,
    /// Image bytes from `start`; the open range continues at their end.
    start: u64,
    buffer: VecDeque<u8>,
    range: Option<(HttpTransfer, Ranged)>,
    /// Ranges requested so far.
    ranges: u64,
    /// Whether [`Remote::pump`] reads ahead: from a read that succeeded
    /// until a read-ahead fails.
    ahead: bool,
}

impl Remote {
    pub fn new(network: Shared, manifest: &PayloadManifest) -> Result<Self> {
        let Layout::Remote { url, etag } = &manifest.layout else {
            return Err(refuse!("the install payload is not a remote image"));
        };
        network
            .0
            .borrow()
            .check_url(url)
            .map_err(|error| refuse!("remote image URL: {error}", %error))?;
        let last = manifest
            .source
            .bytes
            .checked_sub(1)
            .ok_or_else(|| refuse!("the remote image is empty"))?;
        Ranged::with_identity(0, last, etag, manifest.source.bytes)
            .map_err(|error| refuse!("remote image range: {error}", %error))?;
        output::arguments(format_args!(
            "REMOTE IMAGE {url} bytes={} etag={etag}\n",
            manifest.source.bytes
        ));
        Ok(Self {
            network,
            url: url.clone(),
            etag: etag.clone(),
            len: manifest.source.bytes,
            start: 0,
            // Room for the read-ahead, what stays for a re-read and a
            // socket's worth more, so the ring rarely grows.
            buffer: VecDeque::with_capacity(AHEAD + KEEP + (8 << 20)),
            range: None,
            ranges: 0,
            ahead: false,
        })
    }

    fn end(&self) -> u64 {
        self.start + self.buffer.len() as u64
    }

    fn stop(&mut self) {
        if let Some((transfer, _)) = self.range.take() {
            self.network.0.borrow_mut().close_download(transfer);
        }
    }

    /// Takes what has arrived, opening a range at the buffer's end first
    /// when none is open.
    fn step(&mut self) -> Result<(), NetError> {
        if self.range.is_none() {
            let (first, last) = (self.end(), self.len - 1);
            let ranged = Ranged::with_identity(first, last, &self.etag, self.len)?;
            let transfer = self
                .network
                .0
                .borrow_mut()
                .download(&self.url, first, last, &self.etag)?;
            self.range = Some((transfer, ranged));
            self.ranges += 1;
            output::arguments(format_args!(
                "REMOTE IMAGE range {} bytes={first}-{last}\n",
                self.ranges
            ));
        }
        let (transfer, ranged) = self.range.as_mut().expect("opened above");
        let buffer = &mut self.buffer;
        let done = self
            .network
            .0
            .borrow_mut()
            .read_download(transfer, |bytes, closed| {
                ranged.feed(bytes, closed, |body| buffer.extend(body))
            })?;
        if done {
            self.stop();
        }
        Ok(())
    }

    /// Fills the buffer up to `until`.
    fn fill(&mut self, until: u64) -> Result<(), NetError> {
        let mut failures = 0;
        while self.end() < until {
            let before = self.end();
            if let Err(error) = self.step() {
                self.stop();
                if !error.retryable() {
                    return Err(error);
                }
                failures += 1;
                output::arguments(format_args!(
                    "REMOTE IMAGE range at {before} failed ({failures}/{ATTEMPTS}): {error}\n"
                ));
                if failures == ATTEMPTS {
                    return Err(error);
                }
                let started = output::now();
                while output::millis_since(started) < 1000 << (failures - 1) {
                    core::hint::spin_loop();
                }
            } else if self.end() > before {
                failures = 0;
            } else if self.range.is_some() {
                let result = self.network.0.borrow_mut().wait(WAIT_US);
                if let Err(error) = result {
                    self.stop();
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    /// Without waiting, takes what has arrived while less than [`AHEAD`] is
    /// buffered, opening the next range when one ends. A failure leaves the
    /// next read to retry.
    pub fn pump(&mut self) {
        if self.ahead && self.buffer.len() < AHEAD && self.end() < self.len && self.step().is_err()
        {
            self.stop();
            self.ahead = false;
        }
    }
}

impl ReadAt for Remote {
    type Error = NetError;

    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&mut self, offset: u64, out: &mut [u8]) -> Result<(), NetError> {
        let until = offset
            .checked_add(out.len() as u64)
            .ok_or(NetError::Invalid("remote image offset overflow"))?;
        if until > self.len {
            return Err(NetError::Invalid("read past the remote image's end"));
        }
        if offset < self.start || offset > self.end() + SKIP {
            self.stop();
            self.buffer.clear();
            self.start = offset;
        }
        self.fill(until)?;
        self.ahead = true;
        // The ring's two halves, from the read's first byte.
        let (mut at, mut filled) = ((offset - self.start) as usize, 0);
        for part in <[&[u8]; 2]>::from(self.buffer.as_slices()) {
            if at < part.len() {
                let take = (part.len() - at).min(out.len() - filled);
                out[filled..filled + take].copy_from_slice(&part[at..at + take]);
                filled += take;
                at = 0;
            } else {
                at -= part.len();
            }
        }
        // Bytes before this read are done with, but the last few stay for
        // a re-read.
        let done = (until - self.start) as usize;
        if done > KEEP {
            self.buffer.drain(..done - KEEP);
            self.start = until - KEEP as u64;
        }
        Ok(())
    }
}
