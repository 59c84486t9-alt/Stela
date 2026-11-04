//! Hosted cache misses share one publisher per canonical entry path. The
//! registry lock covers membership changes only, so unrelated keys compile
//! and publish in parallel.
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

static FLIGHTS: Mutex<BTreeMap<Arc<Path>, Arc<Mutex<()>>>> = Mutex::new(BTreeMap::new());

/// Holds a participant's reference while it waits for or owns the key.
pub(super) struct Flight {
    directory: Arc<Path>,
    gate: Option<Arc<Mutex<()>>>,
}

impl Flight {
    pub(super) fn join(directory: &Path) -> Self {
        let mut flights = FLIGHTS.lock().unwrap_or_else(PoisonError::into_inner);
        let (directory, gate) = if let Some((directory, gate)) = flights.get_key_value(directory) {
            (Arc::clone(directory), Arc::clone(gate))
        } else {
            let directory = Arc::<Path>::from(directory);
            let gate = Arc::new(Mutex::new(()));
            flights.insert(Arc::clone(&directory), Arc::clone(&gate));
            (directory, gate)
        };
        Self {
            directory,
            gate: Some(gate),
        }
    }

    pub(super) fn wait(&self) -> MutexGuard<'_, ()> {
        // A panicking publisher cannot leave a partial published entry. The
        // next owner checks the directory again and may try to publish.
        self.gate
            .as_ref()
            .unwrap()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    #[cfg(test)]
    pub(super) fn participants(directory: &Path) -> usize {
        FLIGHTS
            .lock()
            .unwrap()
            .get(directory)
            .map_or(0, |gate| Arc::strong_count(gate) - 1)
    }
}

impl Drop for Flight {
    fn drop(&mut self) {
        let mut flights = FLIGHTS.lock().unwrap_or_else(PoisonError::into_inner);
        // Drop the participant reference under the registry lock, so
        // concurrent departures agree on who removes the last entry.
        drop(self.gate.take());
        if Arc::strong_count(&flights[&self.directory]) == 1 {
            flights.remove(&self.directory);
        }
    }
}
