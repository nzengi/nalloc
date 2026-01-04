//! Arena Manager for nalloc.
//!
//! The `ArenaManager` pre-allocates large, specialized memory pools
//! during initialization. This avoids system call overhead during
//! hot proof computation paths.

use crate::bump::BumpAlloc;
use crate::config::{POLY_ARENA_SIZE, SCRATCH_ARENA_SIZE, WITNESS_ARENA_SIZE};
use crate::sys;
use std::sync::Arc;

/// Manages multiple specialized memory arenas.
///
/// Each arena is optimized for a specific purpose:
/// - **Witness Arena**: For private ZK inputs, with secure wiping.
/// - **Polynomial Arena**: For FFT/NTT coefficient vectors.
/// - **Scratch Arena**: For temporary computation buffers.
pub struct ArenaManager {
    witness: Arc<BumpAlloc>,
    polynomial: Arc<BumpAlloc>,
    scratch: Arc<BumpAlloc>,
}

impl ArenaManager {
    /// Create a new ArenaManager with default sizes.
    ///
    /// This will allocate a total of ~1.4 GB of virtual memory.
    /// Note: On modern OSes, virtual memory is cheap; physical pages
    /// are only allocated when touched.
    pub fn new() -> Result<Self, crate::platform::AllocFailed> {
        let witness_ptr = sys::alloc(WITNESS_ARENA_SIZE)?;
        let poly_ptr = sys::alloc(POLY_ARENA_SIZE)?;
        let scratch_ptr = sys::alloc(SCRATCH_ARENA_SIZE)?;

        Ok(Self {
            witness: Arc::new(unsafe { BumpAlloc::new(witness_ptr, WITNESS_ARENA_SIZE) }),
            polynomial: Arc::new(unsafe { BumpAlloc::new(poly_ptr, POLY_ARENA_SIZE) }),
            scratch: Arc::new(unsafe { BumpAlloc::new(scratch_ptr, SCRATCH_ARENA_SIZE) }),
        })
    }

    /// Create a new ArenaManager with custom sizes.
    ///
    /// Use this for fine-tuned configurations based on your circuit size.
    pub fn with_sizes(
        witness_size: usize,
        poly_size: usize,
        scratch_size: usize,
    ) -> Result<Self, crate::platform::AllocFailed> {
        let witness_ptr = sys::alloc(witness_size)?;
        let poly_ptr = sys::alloc(poly_size)?;
        let scratch_ptr = sys::alloc(scratch_size)?;

        Ok(Self {
            witness: Arc::new(unsafe { BumpAlloc::new(witness_ptr, witness_size) }),
            polynomial: Arc::new(unsafe { BumpAlloc::new(poly_ptr, poly_size) }),
            scratch: Arc::new(unsafe { BumpAlloc::new(scratch_ptr, scratch_size) }),
        })
    }

    /// Get a handle to the witness arena.
    #[inline]
    pub fn witness(&self) -> Arc<BumpAlloc> {
        self.witness.clone()
    }

    /// Get a handle to the polynomial arena.
    #[inline]
    pub fn polynomial(&self) -> Arc<BumpAlloc> {
        self.polynomial.clone()
    }

    /// Get a handle to the scratch arena.
    #[inline]
    pub fn scratch(&self) -> Arc<BumpAlloc> {
        self.scratch.clone()
    }

    /// Reset all arenas.
    ///
    /// The witness arena is securely wiped (zeroed) before reset.
    ///
    /// # Safety
    /// This will invalidate all memory previously allocated from these arenas.
    pub unsafe fn reset_all(&self) {
        self.witness.secure_reset();
        self.polynomial.reset();
        self.scratch.reset();
    }

    /// Get statistics about arena usage.
    pub fn stats(&self) -> ArenaStats {
        ArenaStats {
            witness_used: self.witness.used(),
            witness_capacity: self.witness.capacity(),
            polynomial_used: self.polynomial.used(),
            polynomial_capacity: self.polynomial.capacity(),
            scratch_used: self.scratch.used(),
            scratch_capacity: self.scratch.capacity(),
        }
    }
}

/// Statistics about arena memory usage.
#[derive(Debug, Clone, Copy)]
pub struct ArenaStats {
    pub witness_used: usize,
    pub witness_capacity: usize,
    pub polynomial_used: usize,
    pub polynomial_capacity: usize,
    pub scratch_used: usize,
    pub scratch_capacity: usize,
}

impl ArenaStats {
    /// Total memory currently in use.
    pub fn total_used(&self) -> usize {
        self.witness_used + self.polynomial_used + self.scratch_used
    }

    /// Total memory capacity across all arenas.
    pub fn total_capacity(&self) -> usize {
        self.witness_capacity + self.polynomial_capacity + self.scratch_capacity
    }
}

impl Drop for ArenaManager {
    fn drop(&mut self) {
        // Deallocate all arena memory back to the OS.
        // Note: For global allocator usage, this rarely runs (program exit).
        // But for library usage, proper cleanup is essential.

        let witness_ptr = self.witness.base_ptr();
        let poly_ptr = self.polynomial.base_ptr();
        let scratch_ptr = self.scratch.base_ptr();

        let witness_size = self.witness.capacity();
        let poly_size = self.polynomial.capacity();
        let scratch_size = self.scratch.capacity();

        // Best-effort deallocation - ignore errors on shutdown
        let _ = sys::dealloc(witness_ptr, witness_size);
        let _ = sys::dealloc(poly_ptr, poly_size);
        let _ = sys::dealloc(scratch_ptr, scratch_size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arena_manager_creation() {
        // Use smaller sizes for testing
        let manager = ArenaManager::with_sizes(1024 * 1024, 2 * 1024 * 1024, 1024 * 1024).unwrap();

        let stats = manager.stats();
        assert_eq!(stats.witness_capacity, 1024 * 1024);
        assert_eq!(stats.polynomial_capacity, 2 * 1024 * 1024);
        assert_eq!(stats.scratch_capacity, 1024 * 1024);
        assert_eq!(stats.total_used(), 0);
    }

    #[test]
    fn test_arena_stats() {
        let manager = ArenaManager::with_sizes(1024 * 1024, 2 * 1024 * 1024, 1024 * 1024).unwrap();

        // Allocate some memory
        let _ = manager.witness().alloc(1024, 8);
        let _ = manager.polynomial().alloc(2048, 64);
        let _ = manager.scratch().alloc(512, 8);

        let stats = manager.stats();
        assert!(stats.witness_used >= 1024);
        assert!(stats.polynomial_used >= 2048);
        assert!(stats.scratch_used >= 512);
    }

    #[test]
    fn test_drop_deallocates() {
        // This test verifies that Drop runs without panicking
        {
            let _manager = ArenaManager::with_sizes(1024 * 1024, 1024 * 1024, 1024 * 1024).unwrap();
            // manager goes out of scope here, triggering Drop
        }
        // If we get here without crashing, deallocation worked
    }
}
