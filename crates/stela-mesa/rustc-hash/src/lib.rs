//! `rustc-hash`'s map aliases, which upstream defines only over real `std`.
pub use upstream::{FxBuildHasher, FxHasher};

pub type FxHashMap<K, V> = std::collections::HashMap<K, V, FxBuildHasher>;
pub type FxHashSet<V> = std::collections::HashSet<V, FxBuildHasher>;
