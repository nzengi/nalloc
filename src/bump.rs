//! Core bump allocator for nalloc.
//!
//! A bump allocator is the fastest possible allocator: it simply increments
//! a pointer. This module provides a thread-safe, atomic bump allocator
//! optimized for ZK prover workloads.

use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A fast, lock-free bump allocator.
///
/// Thread-safety is achieved via atomic compare-and-swap on the cursor.
/// This allows multiple threads to allocate concurrently without locks,
/// though there may be occasional retries on contention.
pub struct BumpAlloc {
    base: *mut u8,
    limit: *mut u8,
    cursor: AtomicUsize,
}

impl BumpAlloc {
    /// Create a new bump allocator from a raw memory block.
    ///
    /// # Safety
    /// The memory block `[base, base+size)` must be valid and writable.
    #[inline]
    pub unsafe fn new(base: *mut u8, size: usize) -> Self {
        debug_assert!(!base.is_null());
        debug_assert!(size > 0);
        Self {
            base,
            limit: base.add(size),
            cursor: AtomicUsize::new(base as usize),
        }
    }

    /// Allocate memory with the given size and alignment.
    ///
    /// Returns a null pointer if there is not enough space.
    #[inline(always)]
    pub fn alloc(&self, size: usize, align: usize) -> *mut u8 {
        debug_assert!(size > 0);
        debug_assert!(align > 0);
        debug_assert!(align.is_power_of_two());

        loop {
            let current = self.cursor.load(Ordering::Relaxed);
            let aligned = (current + align - 1) & !(align - 1);
            let next = aligned + size;

            if next > self.limit as usize {
                return ptr::null_mut();
            }

            if self
                .cursor
                .compare_exchange_weak(current, next, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                return aligned as *mut u8;
            }
            // Contention: another thread allocated concurrently. Retry.
        }
    }

    /// Reset the bump pointer to the base.
    ///
    /// # Safety
    /// All previously allocated memory becomes invalid after this call.
    #[inline]
    pub unsafe fn reset(&self) {
        self.cursor.store(self.base as usize, Ordering::SeqCst);
    }

    /// Zero out all memory in the arena and reset the cursor.
    ///
    /// This is critical for security-sensitive applications like ZK provers,
    /// where witness data must be wiped after use to prevent leakage.
    ///
    /// # Safety
    /// All previously allocated memory becomes invalid after this call.
    #[inline]
    pub unsafe fn secure_reset(&self) {
        let size = self.limit as usize - self.base as usize;
        // Use volatile writes to prevent the compiler from optimizing away the zeroing
        ptr::write_bytes(self.base, 0, size);
        self.reset();
    }

    /// Returns the total capacity in bytes.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.limit as usize - self.base as usize
    }

    /// Returns the number of bytes currently allocated.
    #[inline]
    pub fn used(&self) -> usize {
        self.cursor.load(Ordering::Relaxed) - self.base as usize
    }

    /// Returns the number of bytes remaining.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.capacity() - self.used()
    }
}

// Safety: BumpAlloc can be shared across threads because cursor uses AtomicUsize.
unsafe impl Send for BumpAlloc {}
unsafe impl Sync for BumpAlloc {}
