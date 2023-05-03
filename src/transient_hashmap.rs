//! HashMap with entries living for limited period of time.

use lazy_static::lazy_static;
use std::cmp;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::hash::Hash;
use std::mem;
use std::ops::{Deref, DerefMut};
use std::time::Duration;
use std::time::Instant;

/// Time provider.
pub trait Timer {
  /// Returns current timestamp in seconds.
  fn get_time(&self) -> i128;
}

/// Standard time provider returning time since first call to get_time since program startup.
#[derive(Default)]
pub struct StandardTimer;
impl Timer for StandardTimer {
  fn get_time(&self) -> i128 {
    lazy_static! {
      static ref FIRST: Instant = Instant::now();
    }
    Instant::now().duration_since(*FIRST).as_millis() as i128
  }
}

/// `HashMap` with entries that will be garbage collected (pruned)
/// after not being used for specified time.
///
/// Pruning does not occur automatically, make sure to call `prune` method
/// to remove old entries.
#[derive(Debug, Clone)]
pub struct TransientHashMap<K, V, T = StandardTimer>
where
  T: Timer,
{
  backing: HashMap<K, V>,
  timestamps: HashMap<K, i128>,
  lifetime: i128,
  timer: T,
}

impl<K, V> TransientHashMap<K, V, StandardTimer>
where
  K: Eq + Hash + Clone,
{
  /// Creates new `TransientHashMap` with standard timer and specified entries lifetime.
  pub fn new(lifetime: Duration) -> Self {
    TransientHashMap::new_with_timer(lifetime, Default::default())
  }
}

impl<K, V, T> TransientHashMap<K, V, T>
where
  K: Eq + Hash + Clone,
  T: Timer,
{
  /// Creates new `TransientHashMap` with given timer and specfied entries lifetime.
  pub fn new_with_timer(lifetime: Duration, t: T) -> Self {
    TransientHashMap {
      backing: HashMap::new(),
      timestamps: HashMap::new(),
      lifetime: lifetime.as_millis() as i128,
      timer: t,
    }
  }

  /// Insert new entry to this map overwriting any previous entry.
  ///
  /// Prolongs lifetime of `key`.
  pub fn insert(&mut self, key: K, value: V) -> Option<V> {
    self.note_used_if(true, &key);
    self.backing.insert(key, value)
  }

  /// Insert new entry to this map overwriting any previous entry.
  ///
  /// Always prolongs the lifetime of `key`.
  /// TODO [ToDr] Should only prolong if new item is inserted or entry is occupied.
  pub fn entry(&mut self, key: K) -> Entry<K, V> {
    // TODO [ToDr] note used only if occupied or inserted!
    self.note_used_if(true, &key);
    self.backing.entry(key)
  }

  /// Gets reference to stored value.
  ///
  /// Prolongs lifetime of `key` if is in the map.
  pub fn get(&mut self, key: &K) -> Option<&V> {
    let has_key = self.backing.contains_key(key);
    self.note_used_if(has_key, key);
    self.backing.get(key)
  }

  /// Gets mutable reference to stored value.
  ///
  /// Prolongs lifetime of `key` if is in the map.
  pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
    // This will invoke `note_used` if the key exists
    self.contains_key(key);
    self.backing.get_mut(key)
  }

  /// Checks if `key` is contained.
  ///
  /// Prolongs lifetime of `key` if is in the map.
  pub fn contains_key(&mut self, key: &K) -> bool {
    let contains = self.backing.contains_key(key);
    self.note_used_if(contains, key);
    contains
  }

  /// Removes `key` from the map if present.
  ///
  /// Also removes associated lifetime.
  pub fn remove(&mut self, k: &K) -> Option<V> {
    self.timestamps.remove(k);
    self.backing.remove(k)
  }

  /// Returns remaining lifetime of `key` without altering it.
  pub fn remaining_lifetime(&mut self, key: &K) -> Option<Duration> {
    self.timestamps.get(key).map(|time| {
      let time = self.timer.get_time() - time;
      let millis = cmp::max(0, self.lifetime - time);
      let secs = millis / 1000;
      let sub_sec_millis = (millis - secs * 1000) as u32;
      let sub_sec_nanos = sub_sec_millis * 1_000_000;
      Duration::new(secs as u64, sub_sec_nanos)
    })
  }

  #[inline]
  fn note_used_if(&mut self, condition: bool, key: &K) {
    if condition {
      self.timestamps.insert(key.clone(), self.timer.get_time());
    }
  }

  /// Clear overdue entries from the `TransientHashMap`.
  pub fn prune(&mut self) -> Vec<(K, V)> {
    let now = self.timer.get_time();

    let timestamps = mem::replace(&mut self.timestamps, HashMap::new());
    let (ok, removed) = timestamps
      .into_iter()
      .partition(|entry| now - entry.1 < self.lifetime);
    self.timestamps = ok;

    removed
      .into_iter()
      .map(|(k, _)| {
        let item = self.backing.remove(&k).unwrap();
        (k, item)
      })
      .collect()
  }

  /// Get a reference to backing `HashMap`.
  pub fn direct(&self) -> &HashMap<K, V> {
    &self.backing
  }

  /// Get the mutable reference to backing `HashMap`.
  pub fn direct_mut(&mut self) -> &mut HashMap<K, V> {
    &mut self.backing
  }
}

impl<K, V, T> Deref for TransientHashMap<K, V, T>
where
  T: Timer,
{
  type Target = HashMap<K, V>;

  fn deref(&self) -> &Self::Target {
    &self.backing
  }
}

impl<K, V, T> DerefMut for TransientHashMap<K, V, T>
where
  T: Timer,
{
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.backing
  }
}

#[cfg(test)]
mod test {
  use super::{Timer, TransientHashMap};
  use std::{cell::Cell, time::Duration};

  struct TestTimer<'a> {
    time: &'a Cell<i128>,
  }

  impl<'a> Timer for TestTimer<'a> {
    fn get_time(&self) -> i128 {
      self.time.get()
    }
  }

  #[test]
  fn should_remove_lifetime_when_calling_remove() {
    // given
    let time = Cell::new(0);
    let timer = TestTimer { time: &time };
    let mut t_map: TransientHashMap<u64, (), _> =
      TransientHashMap::new_with_timer(Duration::from_millis(2), timer);
    t_map.insert(2, ());
    assert_eq!(t_map.remaining_lifetime(&2), Some(Duration::from_millis(2)));

    // when
    t_map.remove(&2);

    // then
    assert_eq!(t_map.remaining_lifetime(&2), None);
  }

  #[test]
  fn should_not_track_lifetime_if_key_is_not_present() {
    // given
    let time = Cell::new(0);
    let timer = TestTimer { time: &time };
    let mut t_map: TransientHashMap<u64, (), _> =
      TransientHashMap::new_with_timer(Duration::from_millis(2), timer);

    // when
    t_map.contains_key(&2);

    // then
    assert_eq!(t_map.remaining_lifetime(&2), None);
  }

  #[test]
  fn should_return_correct_lifetime_when_negative() {
    // given
    let time = Cell::new(0);
    let timer = TestTimer { time: &time };
    let mut t_map = TransientHashMap::new_with_timer(Duration::from_millis(2), timer);
    t_map.insert(1, 0);

    // when
    time.set(10);

    // then
    assert_eq!(t_map.remaining_lifetime(&1), Some(Duration::from_millis(0)));
  }

  #[test]
  fn should_return_pruned_keys_and_values() {
    // given
    let time = Cell::new(0);
    let timer = TestTimer { time: &time };

    let mut t_map = TransientHashMap::new_with_timer(Duration::from_millis(2), timer);
    t_map.insert(1, 5);
    t_map.insert(2, 6);
    t_map.insert(3, 7);
    time.set(1);
    t_map.insert(4, 8);
    assert_eq!(t_map.direct().len(), 4);

    // when
    time.set(2);
    let keys = t_map.prune();

    // then
    assert_eq!(t_map.direct().len(), 1);
    assert_eq!(t_map.get(&4), Some(&8));
    assert_eq!(keys.len(), 3);
    assert!(keys.contains(&(1, 5)));
    assert!(keys.contains(&(2, 6)));
    assert!(keys.contains(&(3, 7)));
  }

  #[test]
  fn it_works() {
    let time = Cell::new(0);
    let timer = TestTimer { time: &time };

    let mut t_map = TransientHashMap::new_with_timer(Duration::from_millis(2), timer);
    assert_eq!(t_map.remaining_lifetime(&1), None);

    t_map.insert(1, 1);
    assert_eq!(t_map.remaining_lifetime(&1), Some(Duration::from_millis(2)));

    time.set(1);
    assert_eq!(t_map.remaining_lifetime(&1), Some(Duration::from_millis(1)));

    time.set(2);
    assert_eq!(t_map.remaining_lifetime(&1), Some(Duration::from_millis(0)));

    time.set(1);
    assert_eq!(t_map.remaining_lifetime(&1), Some(Duration::from_millis(1)));

    t_map.prune();
    assert_eq!(t_map.remaining_lifetime(&1), Some(Duration::from_millis(1)));

    time.set(2);
    assert_eq!(t_map.remaining_lifetime(&1), Some(Duration::from_millis(0)));

    t_map.prune();
    assert_eq!(t_map.remaining_lifetime(&1), None);

    time.set(1);
    assert_eq!(t_map.remaining_lifetime(&1), None);
  }
}
