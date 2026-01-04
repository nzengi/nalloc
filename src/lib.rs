//! nalloc: A ZK-Proof optimized memory allocator.
//!
//! This crate provides a high-performance, deterministic memory allocator
//! specifically designed for Zero-Knowledge proof systems like zkSNARKs,
//! zkSTARKs, Plonk, and Groth16.
//!
//! # Features
//!
//! - **Arena-based allocation**: Pre-reserved memory pools for different workload types
//! - **Bump allocation**: O(1) allocation via atomic pointer increment
//! - **Security-first**: Volatile secure wiping for witness data
//! - **Cache-optimized**: 64-byte alignment for FFT/NTT SIMD operations
//! - **Cross-platform**: Linux, macOS, Windows, and Unix support
//!
//! # Usage
//!
//! As a global allocator:
//! ```rust,no_run
//! use zk_nalloc::NAlloc;
//!
//! #[global_allocator]
//! static ALLOC: NAlloc = NAlloc::new();
//!
//! fn main() {
//!     let data = vec![0u64; 1000];
//!     println!("Allocated {} elements", data.len());
//! }
//! ```
//!
//! Using specialized arenas directly:
//! ```rust
//! use zk_nalloc::NAlloc;
//!
//! let alloc = NAlloc::new();
//! let witness = alloc.witness();
//! let ptr = witness.alloc(1024, 8);
//! assert!(!ptr.is_null());
//!
//! // Securely wipe when done
//! unsafe { witness.secure_wipe(); }
//! ```

pub mod arena;
pub mod bump;
pub mod config;
pub mod platform;
pub mod polynomial;
pub mod witness;

pub use arena::{ArenaManager, ArenaStats};
pub use bump::BumpAlloc;
pub use config::*;
pub use platform::sys;
pub use polynomial::PolynomialArena;
pub use witness::WitnessArena;

use std::alloc::{GlobalAlloc, Layout};
use std::ptr::{copy_nonoverlapping, null_mut};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

/// The global ZK-optimized allocator.
///
/// `NAlloc` provides a drop-in replacement for the standard Rust global allocator,
/// with special optimizations for ZK-Proof workloads.
///
/// # Memory Strategy
///
/// - **Large allocations (>1MB)**: Routed to Polynomial Arena (FFT vectors)
/// - **Small allocations**: Routed to Scratch Arena (temporary buffers)
/// - **Witness data**: Use `NAlloc::witness()` for security-critical allocations
///
/// # Thread Safety
///
/// This allocator uses lock-free atomic operations for initialization and
/// allocation. It's safe to use from multiple threads concurrently.
pub struct NAlloc {
    /// Pointer to the ArenaManager (null until initialized)
    arenas: AtomicPtr<ArenaManager>,
    /// Flag to prevent re-initialization
    initializing: AtomicBool,
}

impl NAlloc {
    /// Create a new `NAlloc` instance.
    ///
    /// The arenas are lazily initialized on the first allocation.
    pub const fn new() -> Self {
        Self {
            arenas: AtomicPtr::new(null_mut()),
            initializing: AtomicBool::new(false),
        }
    }

    /// Initialize the arenas if not already done.
    ///
    /// This uses a spin-lock pattern with atomic bool to avoid
    /// the thread-local storage issues that OnceLock has.
    #[cold]
    #[inline(never)]
    fn init_arenas(&self) -> *mut ArenaManager {
        // Fast path: already initialized
        let ptr = self.arenas.load(Ordering::Acquire);
        if !ptr.is_null() {
            return ptr;
        }

        // Try to acquire initialization lock
        if self
            .initializing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            // We won the race - initialize
            match ArenaManager::new() {
                Ok(manager) => {
                    // Use system allocator to avoid recursive allocation
                    use std::alloc::{GlobalAlloc, Layout, System};
                    let layout = Layout::new::<ArenaManager>();
                    let raw = unsafe { System.alloc(layout) as *mut ArenaManager };
                    if raw.is_null() {
                        self.initializing.store(false, Ordering::Release);
                        panic!("Failed to allocate ArenaManager");
                    }
                    unsafe {
                        std::ptr::write(raw, manager);
                    }
                    self.arenas.store(raw, Ordering::Release);
                    return raw;
                }
                Err(_) => {
                    // Initialization failed - allow retry
                    self.initializing.store(false, Ordering::Release);
                    panic!("Failed to initialize nalloc arenas");
                }
            }
        }

        // Another thread is initializing - spin wait
        loop {
            std::hint::spin_loop();
            let ptr = self.arenas.load(Ordering::Acquire);
            if !ptr.is_null() {
                return ptr;
            }
        }
    }

    #[inline(always)]
    fn get_arenas(&self) -> &ArenaManager {
        let ptr = self.arenas.load(Ordering::Acquire);
        if ptr.is_null() {
            let ptr = self.init_arenas();
            unsafe { &*ptr }
        } else {
            unsafe { &*ptr }
        }
    }

    /// Access the witness arena directly.
    ///
    /// Use this for allocating sensitive private inputs that need
    /// zero-initialization and secure wiping.
    ///
    /// # Example
    ///
    /// ```rust
    /// use zk_nalloc::NAlloc;
    ///
    /// let alloc = NAlloc::new();
    /// let witness = alloc.witness();
    /// let secret_ptr = witness.alloc(256, 8);
    /// assert!(!secret_ptr.is_null());
    ///
    /// // Securely wipe when done
    /// unsafe { witness.secure_wipe(); }
    /// ```
    #[inline]
    pub fn witness(&self) -> WitnessArena {
        WitnessArena::new(self.get_arenas().witness())
    }

    /// Access the polynomial arena directly.
    ///
    /// Use this for FFT/NTT-friendly polynomial coefficient vectors.
    /// Provides 64-byte alignment by default for SIMD operations.
    ///
    /// # Example
    ///
    /// ```rust
    /// use zk_nalloc::NAlloc;
    ///
    /// let alloc = NAlloc::new();
    /// let poly = alloc.polynomial();
    /// let coeffs = poly.alloc_fft_friendly(1024); // 1K coefficients
    /// assert!(!coeffs.is_null());
    /// assert_eq!((coeffs as usize) % 64, 0); // 64-byte aligned
    /// ```
    #[inline]
    pub fn polynomial(&self) -> PolynomialArena {
        PolynomialArena::new(self.get_arenas().polynomial())
    }

    /// Access the scratch arena directly.
    ///
    /// Use this for temporary computation space.
    #[inline]
    pub fn scratch(&self) -> std::sync::Arc<BumpAlloc> {
        self.get_arenas().scratch()
    }

    /// Reset all arenas, freeing all allocated memory.
    ///
    /// The witness arena is securely wiped before reset.
    ///
    /// # Safety
    /// This will invalidate all previously allocated memory.
    pub unsafe fn reset_all(&self) {
        self.get_arenas().reset_all();
    }

    /// Get statistics about arena usage.
    ///
    /// Useful for monitoring memory consumption and tuning arena sizes.
    pub fn stats(&self) -> ArenaStats {
        self.get_arenas().stats()
    }
}

impl Default for NAlloc {
    fn default() -> Self {
        Self::new()
    }
}

// Safety: NAlloc uses atomic operations for all shared state
unsafe impl Send for NAlloc {}
unsafe impl Sync for NAlloc {}

unsafe impl GlobalAlloc for NAlloc {
    #[inline(always)]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        debug_assert!(layout.size() > 0);
        debug_assert!(layout.align() > 0);
        debug_assert!(layout.align().is_power_of_two());

        let arenas = self.get_arenas();

        // Strategy:
        // 1. Large allocations (> threshold) go to Polynomial Arena (likely vectors)
        // 2. Smaller allocations go to Scratch Arena
        // 3. User can explicitly use Witness Arena via NAlloc::witness()

        if layout.size() > LARGE_ALLOC_THRESHOLD {
            arenas.polynomial().alloc(layout.size(), layout.align())
        } else {
            arenas.scratch().alloc(layout.size(), layout.align())
        }
    }

    #[inline(always)]
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Individual deallocation is a no-op in a bump allocator.
        // Memory is reclaimed by calling reset() on the arena.
    }

    #[inline(always)]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        debug_assert!(!ptr.is_null());
        debug_assert!(layout.size() > 0);
        debug_assert!(new_size > 0);

        let old_size = layout.size();

        // If the new size is smaller or equal, just return the same pointer.
        // (The bump allocator doesn't shrink.)
        if new_size <= old_size {
            return ptr;
        }

        // Allocate a new block
        let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
        let new_ptr = self.alloc(new_layout);

        if new_ptr.is_null() {
            return null_mut();
        }

        // Copy the old data
        copy_nonoverlapping(ptr, new_ptr, old_size);

        // Dealloc the old pointer (no-op for bump allocator, but semantically correct)
        self.dealloc(ptr, layout);

        new_ptr
    }

    #[inline(always)]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = self.alloc(layout);
        if !ptr.is_null() {
            // Note: mmap'd memory is already zeroed, but we zero anyway for
            // recycled memory or if user specifically requested zeroed allocation.
            std::ptr::write_bytes(ptr, 0, layout.size());
        }
        ptr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::GlobalAlloc;

    #[test]
    fn test_global_alloc_api() {
        let alloc = NAlloc::new();
        let layout = Layout::from_size_align(1024, 8).unwrap();
        unsafe {
            let ptr = alloc.alloc(layout);
            assert!(!ptr.is_null());
            // Check that we can write to it
            ptr.write(42);
            assert_eq!(ptr.read(), 42);
        }
    }

    #[test]
    fn test_realloc() {
        let alloc = NAlloc::new();
        let layout = Layout::from_size_align(64, 8).unwrap();
        unsafe {
            let ptr = alloc.alloc(layout);
            assert!(!ptr.is_null());

            // Write some data
            for i in 0..64 {
                ptr.add(i).write(i as u8);
            }

            // Realloc to a larger size
            let new_ptr = alloc.realloc(ptr, layout, 128);
            assert!(!new_ptr.is_null());

            // Verify data was copied
            for i in 0..64 {
                assert_eq!(new_ptr.add(i).read(), i as u8);
            }
        }
    }

    #[test]
    fn test_alloc_zeroed() {
        let alloc = NAlloc::new();
        let layout = Layout::from_size_align(1024, 8).unwrap();
        unsafe {
            let ptr = alloc.alloc_zeroed(layout);
            assert!(!ptr.is_null());

            // Verify memory is zeroed
            for i in 0..1024 {
                assert_eq!(*ptr.add(i), 0);
            }
        }
    }

    #[test]
    fn test_stats() {
        let alloc = NAlloc::new();

        // Trigger arena initialization with an allocation
        let layout = Layout::from_size_align(1024, 8).unwrap();
        unsafe {
            let _ = alloc.alloc(layout);
        }

        let stats = alloc.stats();
        assert!(stats.scratch_used >= 1024);
        assert!(stats.total_capacity() > 0);
    }

    #[test]
    fn test_large_allocation_routing() {
        let alloc = NAlloc::new();

        // Small allocation (< 1MB) should go to scratch
        let small_layout = Layout::from_size_align(1024, 8).unwrap();
        unsafe {
            let _ = alloc.alloc(small_layout);
        }

        let stats_after_small = alloc.stats();
        assert!(stats_after_small.scratch_used >= 1024);

        // Large allocation (> 1MB) should go to polynomial
        let large_layout = Layout::from_size_align(2 * 1024 * 1024, 64).unwrap();
        unsafe {
            let _ = alloc.alloc(large_layout);
        }

        let stats_after_large = alloc.stats();
        assert!(stats_after_large.polynomial_used >= 2 * 1024 * 1024);
    }

    #[test]
    fn test_concurrent_init() {
        use std::sync::Arc;
        use std::thread;

        let alloc = Arc::new(NAlloc::new());
        let mut handles = vec![];

        // Spawn multiple threads that try to initialize simultaneously
        for _ in 0..8 {
            let alloc = Arc::clone(&alloc);
            handles.push(thread::spawn(move || {
                let layout = Layout::from_size_align(64, 8).unwrap();
                unsafe {
                    let ptr = alloc.alloc(layout);
                    assert!(!ptr.is_null());
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }
    }
}
