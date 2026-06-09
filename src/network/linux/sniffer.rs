use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::types::PacketSnippet;

pub struct PacketSniffer {
    pub snippets: Arc<Mutex<VecDeque<PacketSnippet>>>,
    pub max_snippets: usize,
    pub active: Arc<AtomicBool>,
    pub error_msg: Arc<Mutex<Option<String>>>,
    handle: Option<thread::JoinHandle<()>>,
    total_added: Arc<AtomicUsize>,
    consumed_count: usize,
}

impl PacketSniffer {
    pub fn new(max_snippets: usize) -> Self {
        Self {
            snippets: Arc::new(Mutex::new(VecDeque::with_capacity(max_snippets))),
            max_snippets,
            active: Arc::new(AtomicBool::new(false)),
            error_msg: Arc::new(Mutex::new(None)),
            handle: None,
            total_added: Arc::new(AtomicUsize::new(0)),
            consumed_count: 0,
        }
    }

    pub fn start(&mut self) {}
    pub fn stop(&mut self) {
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
    pub fn drain_new(&mut self) -> Vec<PacketSnippet> {
        let total = self.total_added.load(Ordering::Relaxed);
        if total <= self.consumed_count {
            return Vec::new();
        }
        let new_count = total - self.consumed_count;
        self.consumed_count = total;
        let lock = match self.snippets.lock() {
            Ok(guard) => guard,
            Err(_) => return Vec::new(),
        };
        let len = lock.len();
        let skip = len.saturating_sub(new_count);
        lock.iter().skip(skip).cloned().collect()
    }
    pub fn recent(&self, count: usize) -> Vec<PacketSnippet> {
        let lock = match self.snippets.lock() {
            Ok(guard) => guard,
            Err(_) => return Vec::new(),
        };
        lock.iter()
            .rev()
            .take(count)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }
    pub fn get_error(&self) -> Option<String> {
        self.error_msg.lock().ok().and_then(|e| e.clone())
    }
}

impl Drop for PacketSniffer {
    fn drop(&mut self) {
        self.stop();
    }
}
