//! nalloc: A ZK-Proof optimized memory allocator.
//!
//! This crate provides a high-performance, deterministic memory allocator
//! specifically designed for Zero-Knowledge proof systems like zkSNARKs,
//! zkSTARKs, Plonk, and Groth16.
//!
//! # Usage
//!
//! As a global allocator:
//! ```rust,ignore
//! use nalloc::NAlloc;
//!
//! #[global_allocator]
//! static ALLOC: NAlloc = NAlloc::new();
//! ```
//!
//! Using specialized arenas directly:
//! ```rust,ignore
//! let alloc = NAlloc::new();
//! let witness = alloc.witness();
//! let ptr = witness.alloc(1024, 8);
//! // ... compute ...
//! witness.secure_wipe();
//! ```

pub mod arena;
pub mod bump;
pub mod platform;
pub mod polynomial;
pub mod witness;

pub use arena::ArenaManager;
pub use bump::BumpAlloc;
pub use platform::sys;
pub use polynomial::PolynomialArena;
pub use witness::WitnessArena;

use std::alloc::{GlobalAlloc, Layout};
use std::ptr::{copy_nonoverlapping, null_mut};
use std::sync::OnceLock;

/// The global ZK-optimized allocator.
///
/// `NAlloc` provides a drop-in replacement for the standard Rust global allocator,
/// with special optimizations for ZK-Proof workloads.
pub struct NAlloc {
    arenas: OnceLock<ArenaManager>,
}

impl NAlloc {
    /// Create a new `NAlloc` instance.
    ///
    /// The arenas are lazily initialized on the first allocation.
    pub const fn new() -> Self {
        Self {
            arenas: OnceLock::new(),
        }
    }

    #[inline(always)]
    fn get_arenas(&self) -> &ArenaManager {
        self.arenas
            .get_or_init(|| ArenaManager::new().expect("Failed to initialize nalloc arenas"))
    }

    /// Access the witness arena directly.
    ///
    /// Use this for allocating sensitive private inputs that need
    /// zero-initialization and secure wiping.
    #[inline]
    pub fn witness(&self) -> WitnessArena {
        WitnessArena::new(self.get_arenas().witness())
    }

    /// Access the polynomial arena directly.
    ///
    /// Use this for FFT/NTT-friendly polynomial coefficient vectors.
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
    /// # Safety
    /// This will invalidate all previously allocated memory.
    pub unsafe fn reset_all(&self) {
        self.get_arenas().reset_all();
    }
}

impl Default for NAlloc {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl GlobalAlloc for NAlloc {
    #[inline(always)]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        debug_assert!(layout.size() > 0);
        debug_assert!(layout.align() > 0);
        debug_assert!(layout.align().is_power_of_two());

        let arenas = self.get_arenas();

        // Strategy:
        // 1. Large allocations (> 1MB) go to Polynomial Arena (likely vectors)
        // 2. Smaller allocations go to Scratch Arena
        // 3. User can explicitly use Witness Arena via NAlloc::witness()

        if layout.size() > 1024 * 1024 {
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
}
