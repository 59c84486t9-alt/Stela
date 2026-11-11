//! A bounded table of datagram mappings (RFC 4787): each lives while it
//! carries traffic, ends after its idle timeout, and the one idle longest
//! makes room when the table is full.
use std::{
    collections::HashMap,
    hash::Hash,
    time::{Duration, Instant},
};

struct Entry<V> {
    value: V,
    last_activity: Instant,
}

pub struct Flows<K, V> {
    capacity: usize,
    entries: HashMap<K, Entry<V>>,
}

impl<K: Copy + Eq + Hash, V> Flows<K, V> {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "a flow table holds at least one mapping");
        Self {
            capacity,
            entries: HashMap::new(),
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub fn contains(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    /// The mapping for `key`, its idle time restarted at `now`.
    pub fn touch(&mut self, key: &K, now: Instant) -> Option<&mut V> {
        let entry = self.entries.get_mut(key)?;
        entry.last_activity = entry.last_activity.max(now);
        Some(&mut entry.value)
    }

    /// Adds a mapping active at `now`. A full table first gives up the
    /// mapping idle longest, which is returned.
    pub fn insert(&mut self, key: K, value: V, now: Instant) -> Option<(K, V)> {
        let evicted = if !self.entries.contains_key(&key) && self.entries.len() >= self.capacity {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_activity)
                .map(|(key, _)| *key);
            oldest.and_then(|oldest| self.remove(&oldest).map(|value| (oldest, value)))
        } else {
            None
        };
        self.entries.insert(
            key,
            Entry {
                value,
                last_activity: now,
            },
        );
        evicted
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.entries.remove(key).map(|entry| entry.value)
    }

    /// Removes and returns the mappings idle for at least `idle(key)` at
    /// `now`.
    pub fn expire(&mut self, now: Instant, idle: impl Fn(&K) -> Duration) -> Vec<(K, V)> {
        let expired: Vec<K> = self
            .entries
            .iter()
            .filter(|(key, entry)| now.saturating_duration_since(entry.last_activity) >= idle(key))
            .map(|(key, _)| *key)
            .collect();
        expired
            .into_iter()
            .filter_map(|key| self.remove(&key).map(|value| (key, value)))
            .collect()
    }

    /// Removes and returns every mapping.
    pub fn drain(&mut self) -> Vec<(K, V)> {
        self.entries
            .drain()
            .map(|(key, entry)| (key, entry.value))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_table_evicts_the_mapping_idle_longest() {
        let start = Instant::now();
        let at = |seconds| start + Duration::from_secs(seconds);
        let mut flows = Flows::new(3);
        assert!(flows.insert(1u16, "a", at(0)).is_none());
        assert!(flows.insert(2, "b", at(1)).is_none());
        assert!(flows.insert(3, "c", at(2)).is_none());
        // Traffic on the oldest makes the second the one idle longest.
        assert_eq!(flows.touch(&1, at(3)), Some(&mut "a"));
        assert_eq!(flows.insert(4, "d", at(4)), Some((2, "b")));
        assert_eq!(flows.len(), 3);
        assert!(flows.contains(&1) && flows.contains(&3) && flows.contains(&4));
        // Replacing a present key evicts nothing.
        assert!(flows.insert(4, "e", at(5)).is_none());
        assert_eq!(flows.len(), 3);
    }

    #[test]
    fn mappings_expire_after_their_own_idle_time() {
        let start = Instant::now();
        let at = |seconds| start + Duration::from_secs(seconds);
        let mut flows = Flows::new(8);
        flows.insert(1u16, (), at(0));
        flows.insert(2, (), at(0));
        flows.insert(3, (), at(0));
        flows.touch(&3, at(50));
        // Key 1 has a 60 s timeout, the others 120 s.
        let idle = |key: &u16| Duration::from_secs(if *key == 1 { 60 } else { 120 });
        assert!(flows.expire(at(59), idle).is_empty());
        assert_eq!(flows.expire(at(60), idle), [(1, ())]);
        assert!(flows.expire(at(119), idle).is_empty());
        assert_eq!(flows.expire(at(120), idle), [(2, ())]);
        assert_eq!(flows.expire(at(170), idle), [(3, ())]);
        assert_eq!(flows.len(), 0);
        // A touch never moves activity back in time.
        flows.insert(4, (), at(200));
        flows.touch(&4, at(100));
        assert!(flows.expire(at(250), idle).is_empty());
    }
}
