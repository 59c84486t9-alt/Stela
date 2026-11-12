//! What jobs made outside the service's turn for their calls' next runs,
//! by key, oldest first: the backend's pipelines and images, and the
//! compiler's stitched libraries.
use alloc::collections::VecDeque;

/// Values jobs made, each under its call's key and the generation its key
/// was taken at; past `limit` the oldest goes back to its owner.
pub(crate) struct Kept<T> {
    entries: VecDeque<([u8; 32], u64, T)>,
    limit: usize,
}

/// What a call's run finds kept under its key ([`Kept::take`]).
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Taken<T> {
    /// Made for a key of the same generation: the call's.
    Fresh(T),
    /// Made for a key of an older generation, which may name something
    /// else now: for its owner to destroy.
    Stale(T),
    Missing,
}

impl<T> Kept<T> {
    pub(crate) const fn new(limit: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            limit,
        }
    }

    /// Keeps `value` under `key` taken at `generation`; answers the oldest
    /// value past the limit, for its owner to destroy.
    pub(crate) fn keep(&mut self, key: [u8; 32], generation: u64, value: T) -> Option<T> {
        self.entries.push_back((key, generation, value));
        (self.entries.len() > self.limit)
            .then(|| self.entries.pop_front().map(|(_, _, oldest)| oldest))
            .flatten()
    }

    /// Takes the oldest value under `key`, fresh when it was made at
    /// `generation`.
    pub(crate) fn take(&mut self, key: &[u8; 32], generation: u64) -> Taken<T> {
        let Some(at) = self.entries.iter().position(|(kept, ..)| kept == key) else {
            return Taken::Missing;
        };
        match self.entries.remove(at) {
            Some((_, made, value)) if made == generation => Taken::Fresh(value),
            Some((_, _, value)) => Taken::Stale(value),
            None => Taken::Missing,
        }
    }

    /// Every value kept, for the owner's drop.
    pub(crate) fn drain(&mut self) -> impl Iterator<Item = T> + '_ {
        self.entries.drain(..).map(|(_, _, value)| value)
    }
}

#[cfg(test)]
mod tests {
    use super::{Kept, Taken};
    use alloc::vec::Vec;

    #[test]
    fn a_kept_value_is_taken_once_by_its_key_and_generation() {
        let mut kept = Kept::new(2);
        assert_eq!(kept.keep([1; 32], 7, "a"), None);
        assert_eq!(kept.keep([2; 32], 7, "b"), None);
        assert_eq!(kept.take(&[3; 32], 7), Taken::Missing);
        assert_eq!(kept.take(&[1; 32], 7), Taken::Fresh("a"));
        assert_eq!(kept.take(&[1; 32], 7), Taken::Missing, "taken once");
        // A generation passed since the key was taken: the value may be
        // another's, and goes back to its owner.
        assert_eq!(kept.take(&[2; 32], 8), Taken::Stale("b"));
    }

    #[test]
    fn past_the_limit_the_oldest_goes_back() {
        let mut kept = Kept::new(2);
        assert_eq!(kept.keep([1; 32], 0, 1), None);
        assert_eq!(kept.keep([2; 32], 0, 2), None);
        assert_eq!(kept.keep([3; 32], 0, 3), Some(1));
        assert_eq!(kept.take(&[1; 32], 0), Taken::Missing);
        // Two of one key are taken oldest first.
        assert_eq!(kept.keep([3; 32], 0, 4), Some(2));
        assert_eq!(kept.take(&[3; 32], 0), Taken::Fresh(3));
        assert_eq!(kept.drain().collect::<Vec<_>>(), [4]);
    }
}
