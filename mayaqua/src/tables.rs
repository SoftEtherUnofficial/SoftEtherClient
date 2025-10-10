//! Data structure utilities for SoftEther VPN
//!
//! Provides LIST, QUEUE, and TABLE abstractions matching SoftEther C implementation
//! (Memory.h, Table.h)

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

/// Generic list with optional sorting
/// Matches SoftEther C LIST structure
pub struct List<T> {
    items: Vec<T>,
    sorted: bool,
}

impl<T> List<T> {
    /// Create a new empty list
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            sorted: false,
        }
    }
    
    /// Create a new list with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity),
            sorted: false,
        }
    }
    
    /// Create a single-item list
    pub fn single(item: T) -> Self {
        Self {
            items: vec![item],
            sorted: false,
        }
    }
    
    /// Add item to list
    pub fn add(&mut self, item: T) {
        self.items.push(item);
        self.sorted = false;
    }
    
    /// Insert item at index
    pub fn insert(&mut self, index: usize, item: T) {
        self.items.insert(index, item);
        self.sorted = false;
    }
    
    /// Remove item at index
    pub fn remove(&mut self, index: usize) -> Option<T> {
        if index < self.items.len() {
            Some(self.items.remove(index))
        } else {
            None
        }
    }
    
    /// Get item at index
    pub fn get(&self, index: usize) -> Option<&T> {
        self.items.get(index)
    }
    
    /// Get mutable item at index
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.items.get_mut(index)
    }
    
    /// Get number of items
    pub fn len(&self) -> usize {
        self.items.len()
    }
    
    /// Check if list is empty
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
    
    /// Clear all items
    pub fn clear(&mut self) {
        self.items.clear();
        self.sorted = false;
    }
    
    /// Check if item exists in list
    pub fn contains(&self, item: &T) -> bool
    where
        T: PartialEq,
    {
        self.items.contains(item)
    }
    
    /// Find index of item
    pub fn find(&self, item: &T) -> Option<usize>
    where
        T: PartialEq,
    {
        self.items.iter().position(|x| x == item)
    }
    
    /// Sort list
    pub fn sort(&mut self)
    where
        T: Ord,
    {
        self.items.sort();
        self.sorted = true;
    }
    
    /// Sort list by key function
    pub fn sort_by<F>(&mut self, compare: F)
    where
        F: FnMut(&T, &T) -> std::cmp::Ordering,
    {
        self.items.sort_by(compare);
        self.sorted = true;
    }
    
    /// Get iterator
    pub fn iter(&self) -> std::slice::Iter<T> {
        self.items.iter()
    }
    
    /// Get mutable iterator
    pub fn iter_mut(&mut self) -> std::slice::IterMut<T> {
        self.items.iter_mut()
    }
    
    /// Convert to Vec
    pub fn to_vec(self) -> Vec<T> {
        self.items
    }
    
    /// Get as slice
    pub fn as_slice(&self) -> &[T] {
        &self.items
    }
    
    /// Clone list (requires T: Clone)
    pub fn clone_list(&self) -> Self
    where
        T: Clone,
    {
        Self {
            items: self.items.clone(),
            sorted: self.sorted,
        }
    }
}

impl<T> Default for List<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> From<Vec<T>> for List<T> {
    fn from(vec: Vec<T>) -> Self {
        Self {
            items: vec,
            sorted: false,
        }
    }
}

/// Thread-safe FIFO queue
/// Matches SoftEther C QUEUE structure
pub struct Queue<T> {
    items: Arc<Mutex<VecDeque<T>>>,
}

impl<T> Queue<T> {
    /// Create a new empty queue
    pub fn new() -> Self {
        Self {
            items: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
    
    /// Create a new queue with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            items: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
        }
    }
    
    /// Add item to queue (enqueue)
    pub fn push(&self, item: T) {
        self.items.lock().unwrap().push_back(item);
    }
    
    /// Remove item from queue (dequeue)
    pub fn pop(&self) -> Option<T> {
        self.items.lock().unwrap().pop_front()
    }
    
    /// Peek at front item without removing
    pub fn peek(&self) -> Option<T>
    where
        T: Clone,
    {
        self.items.lock().unwrap().front().cloned()
    }
    
    /// Get number of items
    pub fn len(&self) -> usize {
        self.items.lock().unwrap().len()
    }
    
    /// Check if queue is empty
    pub fn is_empty(&self) -> bool {
        self.items.lock().unwrap().is_empty()
    }
    
    /// Clear all items
    pub fn clear(&self) {
        self.items.lock().unwrap().clear();
    }
    
    /// Clone queue (requires T: Clone)
    pub fn clone_queue(&self) -> Self
    where
        T: Clone,
    {
        let cloned_items = self.items.lock().unwrap().clone();
        Self {
            items: Arc::new(Mutex::new(cloned_items)),
        }
    }
}

impl<T> Default for Queue<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Clone for Queue<T> {
    fn clone(&self) -> Self {
        Self {
            items: Arc::clone(&self.items),
        }
    }
}

/// Hash table (string key → value)
/// Matches SoftEther C TABLE/STRMAP concept
pub struct Table<T> {
    map: HashMap<String, T>,
}

impl<T> Table<T> {
    /// Create a new empty table
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
    
    /// Create a new table with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(capacity),
        }
    }
    
    /// Insert key-value pair
    pub fn insert(&mut self, key: String, value: T) -> Option<T> {
        self.map.insert(key, value)
    }
    
    /// Get value by key
    pub fn get(&self, key: &str) -> Option<&T> {
        self.map.get(key)
    }
    
    /// Get mutable value by key
    pub fn get_mut(&mut self, key: &str) -> Option<&mut T> {
        self.map.get_mut(key)
    }
    
    /// Remove value by key
    pub fn remove(&mut self, key: &str) -> Option<T> {
        self.map.remove(key)
    }
    
    /// Check if key exists
    pub fn contains_key(&self, key: &str) -> bool {
        self.map.contains_key(key)
    }
    
    /// Get number of entries
    pub fn len(&self) -> usize {
        self.map.len()
    }
    
    /// Check if table is empty
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    
    /// Clear all entries
    pub fn clear(&mut self) {
        self.map.clear();
    }
    
    /// Get all keys
    pub fn keys(&self) -> Vec<String> {
        self.map.keys().cloned().collect()
    }
    
    /// Get all values
    pub fn values(&self) -> Vec<&T> {
        self.map.values().collect()
    }
    
    /// Get iterator over key-value pairs
    pub fn iter(&self) -> std::collections::hash_map::Iter<String, T> {
        self.map.iter()
    }
    
    /// Get mutable iterator over key-value pairs
    pub fn iter_mut(&mut self) -> std::collections::hash_map::IterMut<String, T> {
        self.map.iter_mut()
    }
}

impl<T> Default for Table<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone> Clone for Table<T> {
    fn clone(&self) -> Self {
        Self {
            map: self.map.clone(),
        }
    }
}

/// Specialized integer list (sorted)
pub type IntList = List<u32>;

/// Specialized integer list (sorted)
pub type Int64List = List<u64>;

/// Specialized string list
pub type StrList = List<String>;

/// Create new integer list
pub fn new_int_list(sorted: bool) -> IntList {
    let mut list = IntList::new();
    if sorted {
        list.sorted = true;
    }
    list
}

/// Create new i64 list
pub fn new_int64_list(sorted: bool) -> Int64List {
    let mut list = Int64List::new();
    if sorted {
        list.sorted = true;
    }
    list
}

/// Create new string list
pub fn new_str_list() -> StrList {
    StrList::new()
}

/// Create new string map (table)
pub fn new_str_map<T>() -> Table<T> {
    Table::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_basic() {
        let mut list = List::new();
        assert_eq!(list.len(), 0);
        assert!(list.is_empty());
        
        list.add(1);
        list.add(2);
        list.add(3);
        
        assert_eq!(list.len(), 3);
        assert!(!list.is_empty());
        assert_eq!(list.get(0), Some(&1));
        assert_eq!(list.get(1), Some(&2));
        assert_eq!(list.get(2), Some(&3));
    }

    #[test]
    fn test_list_remove() {
        let mut list = List::from(vec![1, 2, 3, 4, 5]);
        
        assert_eq!(list.remove(2), Some(3));
        assert_eq!(list.len(), 4);
        assert_eq!(list.get(2), Some(&4));
        
        assert_eq!(list.remove(0), Some(1));
        assert_eq!(list.len(), 3);
        assert_eq!(list.get(0), Some(&2));
    }

    #[test]
    fn test_list_contains() {
        let list = List::from(vec![1, 2, 3, 4, 5]);
        
        assert!(list.contains(&3));
        assert!(!list.contains(&10));
        
        assert_eq!(list.find(&3), Some(2));
        assert_eq!(list.find(&10), None);
    }

    #[test]
    fn test_list_sort() {
        let mut list = List::from(vec![5, 2, 8, 1, 9, 3]);
        list.sort();
        
        assert_eq!(list.as_slice(), &[1, 2, 3, 5, 8, 9]);
    }

    #[test]
    fn test_list_insert() {
        let mut list = List::from(vec![1, 2, 4, 5]);
        list.insert(2, 3);
        
        assert_eq!(list.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_list_clear() {
        let mut list = List::from(vec![1, 2, 3]);
        list.clear();
        
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn test_queue_basic() {
        let queue = Queue::new();
        assert_eq!(queue.len(), 0);
        assert!(queue.is_empty());
        
        queue.push(1);
        queue.push(2);
        queue.push(3);
        
        assert_eq!(queue.len(), 3);
        assert!(!queue.is_empty());
    }

    #[test]
    fn test_queue_fifo() {
        let queue = Queue::new();
        queue.push(1);
        queue.push(2);
        queue.push(3);
        
        assert_eq!(queue.pop(), Some(1));
        assert_eq!(queue.pop(), Some(2));
        assert_eq!(queue.pop(), Some(3));
        assert_eq!(queue.pop(), None);
    }

    #[test]
    fn test_queue_peek() {
        let queue = Queue::new();
        queue.push(1);
        queue.push(2);
        
        assert_eq!(queue.peek(), Some(1));
        assert_eq!(queue.len(), 2); // Peek doesn't remove
        assert_eq!(queue.pop(), Some(1));
    }

    #[test]
    fn test_queue_clear() {
        let queue = Queue::new();
        queue.push(1);
        queue.push(2);
        queue.clear();
        
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn test_table_basic() {
        let mut table = Table::new();
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
        
        table.insert("key1".to_string(), 100);
        table.insert("key2".to_string(), 200);
        table.insert("key3".to_string(), 300);
        
        assert_eq!(table.len(), 3);
        assert!(!table.is_empty());
    }

    #[test]
    fn test_table_get() {
        let mut table = Table::new();
        table.insert("name".to_string(), "Alice".to_string());
        table.insert("age".to_string(), "30".to_string());
        
        assert_eq!(table.get("name"), Some(&"Alice".to_string()));
        assert_eq!(table.get("age"), Some(&"30".to_string()));
        assert_eq!(table.get("unknown"), None);
    }

    #[test]
    fn test_table_remove() {
        let mut table = Table::new();
        table.insert("key1".to_string(), 100);
        table.insert("key2".to_string(), 200);
        
        assert_eq!(table.remove("key1"), Some(100));
        assert_eq!(table.len(), 1);
        assert!(!table.contains_key("key1"));
        assert!(table.contains_key("key2"));
    }

    #[test]
    fn test_table_keys_values() {
        let mut table = Table::new();
        table.insert("a".to_string(), 1);
        table.insert("b".to_string(), 2);
        table.insert("c".to_string(), 3);
        
        let keys = table.keys();
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&"a".to_string()));
        assert!(keys.contains(&"b".to_string()));
        assert!(keys.contains(&"c".to_string()));
        
        let values = table.values();
        assert_eq!(values.len(), 3);
    }

    #[test]
    fn test_table_update() {
        let mut table = Table::new();
        table.insert("key".to_string(), 100);
        
        assert_eq!(table.get("key"), Some(&100));
        
        table.insert("key".to_string(), 200);
        assert_eq!(table.get("key"), Some(&200));
    }

    #[test]
    fn test_int_list() {
        let mut list = new_int_list(false);
        list.add(5);
        list.add(2);
        list.add(8);
        
        assert_eq!(list.len(), 3);
        list.sort();
        assert_eq!(list.as_slice(), &[2, 5, 8]);
    }

    #[test]
    fn test_str_list() {
        let mut list = new_str_list();
        list.add("hello".to_string());
        list.add("world".to_string());
        
        assert_eq!(list.len(), 2);
        assert!(list.contains(&"hello".to_string()));
    }

    #[test]
    fn test_str_map() {
        let mut map = new_str_map::<i32>();
        map.insert("one".to_string(), 1);
        map.insert("two".to_string(), 2);
        
        assert_eq!(map.get("one"), Some(&1));
        assert_eq!(map.get("two"), Some(&2));
    }
}
