//! Core bump allocator for nalloc.
//!
//! A bump allocator is the fastest possible allocator: it simply increments
//! a pointer. This module provides a thread-safe, atomic bump allocator
//! optimized for ZK prover workloads.

use std::ptr::NonNull;
use std::sync::atomic::{compiler_fence, AtomicBool, AtomicUsize, Ordering};

use crate::config::SECURE_WIPE_PATTERN;

/// A fast, lock-free bump allocator.
///
/// Thread-safety is achieved via atomic compare-and-swap on the cursor.
/// This allows multiple threads to allocate concurrently without locks,
/// though there may be occasional retries on contention.
pub struct BumpAlloc {
    /// Base pointer of the memory region (never changes after init).
    base: NonNull<u8>,
    /// End pointer of the memory region (never changes after init).
    limit: NonNull<u8>,
    /// Current allocation cursor (atomically updated).
    cursor: AtomicUsize,
    /// Tracks whether the arena has been recycled (reset after use).
    /// Used to optimize zero-initialization in WitnessArena.
    is_recycled: AtomicBool,
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

        let base_nn = NonNull::new_unchecked(base);
        let limit_nn = NonNull::new_unchecked(base.add(size));

        Self {
            base: base_nn,
            limit: limit_nn,
            cursor: AtomicUsize::new(base as usize),
            is_recycled: AtomicBool::new(false),
        }
    }

    /// Get the base pointer of this allocator.
    #[inline]
    pub fn base_ptr(&self) -> *mut u8 {
        self.base.as_ptr()
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

            if next > self.limit.as_ptr() as usize {
                // Arena exhausted - log in debug mode
                #[cfg(debug_assertions)]
                {
                    eprintln!(
                        "[nalloc] Arena exhausted: requested {} bytes (align {}), remaining {} bytes",
                        size, align, self.remaining()
                    );
                }
                return std::ptr::null_mut();
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

    /// Check if this arena has been recycled (reset after initial use).
    #[inline]
    pub fn is_recycled(&self) -> bool {
        self.is_recycled.load(Ordering::Relaxed)
    }

    /// Reset the bump pointer to the base.
    ///
    /// # Safety
    /// All previously allocated memory becomes invalid after this call.
    #[inline]
    pub unsafe fn reset(&self) {
        self.cursor
            .store(self.base.as_ptr() as usize, Ordering::SeqCst);
        self.is_recycled.store(true, Ordering::Release);
    }

    /// Zero out all memory in the arena and reset the cursor.
    ///
    /// This is critical for security-sensitive applications like ZK provers,
    /// where witness data must be wiped after use to prevent leakage.
    ///
    /// Uses volatile writes to prevent the compiler from optimizing away
    /// the zeroing operation (dead store elimination).
    ///
    /// # Safety
    /// All previously allocated memory becomes invalid after this call.
    #[inline]
    pub unsafe fn secure_reset(&self) {
        let base = self.base.as_ptr();
        let size = self.limit.as_ptr() as usize - base as usize;

        // Use volatile writes to prevent dead store elimination.
        // This ensures the memory is actually zeroed even if it's never read again.
        Self::volatile_memset(base, SECURE_WIPE_PATTERN, size);

        // Compiler fence to ensure the wipe completes before any subsequent operations.
        compiler_fence(Ordering::SeqCst);

        self.reset();
    }

    /// Volatile memset implementation that cannot be optimized away.
    ///
    /// This is critical for cryptographic security - we need to guarantee
    /// that sensitive data is actually erased from memory.
    #[inline(never)]
    unsafe fn volatile_memset(ptr: *mut u8, value: u8, len: usize) {
        // Method 1: Use platform-specific secure zeroing where available
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            // explicit_bzero is guaranteed not to be optimized away
            extern "C" {
                fn explicit_bzero(s: *mut libc::c_void, n: libc::size_t);
            }
            if value == 0 {
                explicit_bzero(ptr as *mut libc::c_void, len);
            }
        }

        #[cfg(target_vendor = "apple")]
        {
            // memset_s is guaranteed not to be optimized away (C11)
            extern "C" {
                fn memset_s(
                    s: *mut libc::c_void,
                    smax: libc::size_t,
                    c: libc::c_int,
                    n: libc::size_t,
                ) -> libc::c_int;
            }
            let _ = memset_s(ptr as *mut libc::c_void, len, value as libc::c_int, len);
        }

        // Fallback: Volatile write loop (works everywhere, slightly slower)
        #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
        {
            for i in 0..len {
                std::ptr::write_volatile(ptr.add(i), value);
            }
        }
    }

    /// Returns the total capacity in bytes.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.limit.as_ptr() as usize - self.base.as_ptr() as usize
    }

    /// Returns the number of bytes currently allocated.
    #[inline]
    pub fn used(&self) -> usize {
        self.cursor.load(Ordering::Relaxed) - self.base.as_ptr() as usize
    }

    /// Returns the number of bytes remaining.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.capacity() - self.used()
    }
}

// Safety: BumpAlloc can be shared across threads because:
// - `base` and `limit` are never modified after construction
// - `cursor` uses atomic operations for thread-safe updates
// - `is_recycled` uses atomic operations
unsafe impl Send for BumpAlloc {}
unsafe impl Sync for BumpAlloc {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonnull_safety() {
        let mut buffer = vec![0u8; 1024];
        let alloc = unsafe { BumpAlloc::new(buffer.as_mut_ptr(), buffer.len()) };

        assert_eq!(alloc.capacity(), 1024);
        assert_eq!(alloc.used(), 0);
        assert_eq!(alloc.remaining(), 1024);
        assert!(!alloc.is_recycled());
    }

    #[test]
    fn test_recycled_flag() {
        let mut buffer = vec![0u8; 1024];
        let alloc = unsafe { BumpAlloc::new(buffer.as_mut_ptr(), buffer.len()) };

        assert!(!alloc.is_recycled());

        let _ = alloc.alloc(64, 8);
        assert!(!alloc.is_recycled());

        unsafe { alloc.reset() };
        assert!(alloc.is_recycled());
    }

    #[test]
    fn test_secure_reset_zeroes_memory() {
        let mut buffer = vec![0xFFu8; 1024];
        let alloc = unsafe { BumpAlloc::new(buffer.as_mut_ptr(), buffer.len()) };

        // Allocate and write data
        let ptr = alloc.alloc(512, 8);
        assert!(!ptr.is_null());
        unsafe {
            std::ptr::write_bytes(ptr, 0xAB, 512);
        }

        // Secure reset
        unsafe { alloc.secure_reset() };

        // Verify memory is zeroed
        for i in 0..1024 {
            assert_eq!(buffer[i], 0, "Byte {} not zeroed", i);
        }
    }
}
