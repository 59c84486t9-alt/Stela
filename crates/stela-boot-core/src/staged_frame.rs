//! The newest frame a display model presented, kept in RAM until the screen
//! takes it.
//!
//! A model presents under its devices' lock, which every processor's device
//! accesses wait for, and the screen's video memory is slow to write: a
//! hypervisor that tracks the writes takes a fault for each page, and real
//! video memory is write-combined or uncached. So a present only fills the
//! frame here, and the rows it changed reach the screen later, outside that
//! lock ([`StagedFrame::take`]). Frames presented before the screen took the
//! last one merge: the screen gets the newest pixels of every changed row.
//! A frame that took long holds the next one back in proportion
//! ([`StagedFrame::due`]), so the screen's writes take a bounded share of
//! the processors that have guest code to run, and each such processor
//! bounds its own part with a [`Share`].
use alloc::{boxed::Box, vec};
use core::ops::Range;

/// The screen's frames may take at most one part in this of the busy
/// processors' time: the next frame waits this many times the last one's
/// cost, less the cost itself.
const FLUSH_SHARE: u64 = 3;

/// At most one part in `parts` of a processor's time for some work: after
/// work that cost `cost`, it waits `parts - 1` times that before more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Share {
    parts: u64,
    next: u64,
}

impl Share {
    pub const fn new(parts: u64) -> Self {
        Self { parts, next: 0 }
    }

    /// Whether the work may run at time `now`.
    pub fn allows(&self, now: u64) -> bool {
        now >= self.next
    }

    /// The work took `cost`, ending at `finished`.
    pub fn spent(&mut self, cost: u64, finished: u64) {
        self.next = finished.saturating_add(cost.saturating_mul(self.parts.saturating_sub(1)));
    }
}

/// Fills one row, given its index; an error stops the frame's fill.
pub type FillRow<'a, E> = dyn FnMut(usize, &mut [u8]) -> Result<(), E> + 'a;

/// A frame of `rows` rows of `row_bytes` bytes, the rows the screen lacks,
/// and when the screen may next take them.
pub struct StagedFrame {
    frame: Box<[u8]>,
    row_bytes: usize,
    rows: usize,
    /// The rows that changed since the screen last took the frame.
    pending: Range<usize>,
    /// When a processor with other work may give the screen a frame.
    share: Share,
    /// Since when a frame has been due without a processor taking it.
    due_since: Option<u64>,
}

impl StagedFrame {
    /// A frame of zeros, which the screen lacks whole.
    pub fn new(row_bytes: usize, rows: usize) -> Self {
        Self {
            frame: vec![0; row_bytes * rows].into_boxed_slice(),
            row_bytes,
            rows,
            pending: 0..rows,
            share: Share::new(FLUSH_SHARE),
            due_since: None,
        }
    }

    /// Where the frame's bytes are, rows top to bottom.
    pub fn address(&self) -> usize {
        self.frame.as_ptr() as usize
    }

    pub fn bytes(&self) -> usize {
        self.frame.len()
    }

    /// Fill the rows of `damage` (`None`: every row) from `fill`, called
    /// with a row index and that row to fill, rows in increasing order,
    /// stopping on its first error. The rows filled, an error's included,
    /// are pending for the screen.
    pub fn fill<E>(
        &mut self,
        damage: Option<Range<usize>>,
        fill: &mut FillRow<'_, E>,
    ) -> Result<(), E> {
        let damage = damage.unwrap_or(0..self.rows);
        let damage = damage.start.min(self.rows)..damage.end.min(self.rows);
        for y in damage.clone() {
            let row = &mut self.frame[y * self.row_bytes..(y + 1) * self.row_bytes];
            if let Err(error) = fill(y, row) {
                self.add(damage.start..y + 1);
                return Err(error);
            }
        }
        self.add(damage);
        Ok(())
    }

    /// Take a whole frame's `rows`, as many as fit; all are pending.
    pub fn store(&mut self, rows: &[u8]) {
        let bytes = rows.len().min(self.frame.len());
        self.frame[..bytes].copy_from_slice(&rows[..bytes]);
        self.add(0..self.rows);
    }

    fn add(&mut self, rows: Range<usize>) {
        self.pending = match (self.pending.is_empty(), rows.is_empty()) {
            (true, _) => rows,
            (_, true) => self.pending.clone(),
            _ => self.pending.start.min(rows.start)..self.pending.end.max(rows.end),
        };
    }

    /// Whether the screen lacks rows.
    pub fn pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Whether the screen lacks rows that a processor with other work may
    /// give it at time `now`: one with none need not wait.
    pub fn due(&self, now: u64) -> bool {
        self.pending() && self.share.allows(now)
    }

    /// Whether a frame has been [`Self::due`] for `limit` at time `now`
    /// without being taken: the processors that may take one lately had
    /// none of their share left.
    pub fn overdue(&mut self, now: u64, limit: u64) -> bool {
        if !self.due(now) {
            self.due_since = None;
            return false;
        }
        now.saturating_sub(*self.due_since.get_or_insert(now)) >= limit
    }

    /// The rows that changed since the last call, for the screen: it keeps
    /// which of them it has yet to write.
    pub fn take(&mut self) -> Range<usize> {
        self.due_since = None;
        core::mem::replace(&mut self.pending, 0..0)
    }

    /// Row `y`, for the screen.
    pub fn row(&self, y: usize) -> &[u8] {
        &self.frame[y * self.row_bytes..(y + 1) * self.row_bytes]
    }

    /// The whole frame, for a screen that takes nothing less.
    pub fn frame(&self) -> &[u8] {
        &self.frame
    }

    /// Giving the screen a frame took a processor `cost` of time, ending at
    /// `finished`: one with other work waits its share before the next.
    pub fn spent(&mut self, cost: u64, finished: u64) {
        self.share.spent(cost, finished);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filled(frame: &mut StagedFrame, damage: Option<Range<usize>>, value: u8) {
        frame
            .fill::<()>(damage, &mut |_, row| {
                row.fill(value);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn a_new_frame_is_pending_whole_until_the_screen_takes_it() {
        let mut frame = StagedFrame::new(4, 6);
        assert_eq!(frame.bytes(), 24);
        assert!(frame.pending() && frame.due(0));
        assert_eq!(frame.take(), 0..6);
        assert!(!frame.pending() && !frame.due(u64::MAX));
        assert_eq!(frame.take(), 0..0);
    }

    #[test]
    fn presents_before_the_screen_takes_them_merge_and_keep_the_newest_pixels() {
        let mut frame = StagedFrame::new(2, 8);
        frame.take();
        filled(&mut frame, Some(1..3), 1);
        filled(&mut frame, Some(5..6), 2);
        filled(&mut frame, Some(2..3), 3);
        assert_eq!(frame.take(), 1..6);
        assert_eq!(frame.row(1), [1, 1]);
        assert_eq!(frame.row(2), [3, 3]);
        assert_eq!(frame.row(4), [0, 0]);
        assert_eq!(frame.row(5), [2, 2]);
        // Damage past the frame is clipped; none at all fills every row.
        filled(&mut frame, Some(7..20), 4);
        assert_eq!(frame.take(), 7..8);
        filled(&mut frame, None, 5);
        assert_eq!(frame.take(), 0..8);
        assert!(frame.frame().iter().all(|&byte| byte == 5));
    }

    #[test]
    fn a_refused_row_leaves_the_rows_before_it_pending() {
        let mut frame = StagedFrame::new(1, 8);
        frame.take();
        let refused = frame.fill(Some(2..7), &mut |y, row| {
            row[0] = 9;
            if y == 4 { Err("unreachable") } else { Ok(()) }
        });
        assert_eq!(refused, Err("unreachable"));
        assert_eq!(frame.take(), 2..5);
    }

    #[test]
    fn a_whole_frame_stored_is_pending_whole() {
        let mut frame = StagedFrame::new(2, 2);
        frame.take();
        frame.store(&[1, 2, 3, 4, 5, 6]);
        assert_eq!(frame.frame(), [1, 2, 3, 4]);
        assert_eq!(frame.take(), 0..2);
    }

    #[test]
    fn a_costly_frame_holds_the_next_back_by_its_share() {
        let mut frame = StagedFrame::new(1, 2);
        frame.take();
        // A frame that cost 10 leaves a busy processor two more of its
        // length; the rows stay pending for one with nothing else to do.
        frame.spent(10, 110);
        filled(&mut frame, Some(0..1), 1);
        assert!(frame.pending());
        assert!(!frame.due(129));
        assert!(frame.due(130));
        // A free one holds nothing back.
        frame.spent(0, 200);
        assert!(frame.due(200));
    }

    #[test]
    fn a_due_frame_nobody_takes_becomes_overdue() {
        let mut frame = StagedFrame::new(1, 2);
        frame.take();
        assert!(!frame.overdue(100, 10), "nothing pending");
        filled(&mut frame, Some(0..1), 1);
        // Due from 105 on, when it is first seen so.
        assert!(!frame.overdue(105, 10));
        assert!(!frame.overdue(114, 10));
        assert!(frame.overdue(115, 10));
        // Taken, it starts over; held back by the share, it is not due.
        frame.take();
        filled(&mut frame, Some(1..2), 2);
        frame.spent(10, 120);
        assert!(!frame.overdue(130, 0));
        assert!(!frame.overdue(140, 10));
        assert!(frame.overdue(150, 10));
    }

    #[test]
    fn a_share_holds_work_back_by_its_parts_less_one() {
        let mut share = Share::new(16);
        assert!(share.allows(0));
        share.spent(10, 100);
        assert!(!share.allows(249));
        assert!(share.allows(250));
        share.spent(0, 300);
        assert!(share.allows(300));
    }
}
