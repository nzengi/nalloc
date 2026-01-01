//! Arena Manager for nalloc.
//!
//! The `ArenaManager` pre-allocates large, specialized memory pools
//! during initialization. This avoids system call overhead during
//! hot proof computation paths.

use crate::bump::BumpAlloc;
use crate::sys;
use std::sync::Arc;

/// Default sizes for specialized arenas.
/// These can be tuned based on typical ZK circuit sizes.
pub const WITNESS_ARENA_SIZE: usize = 128 * 1024 * 1024; // 128 MB
pub const POLY_ARENA_SIZE: usize = 1024 * 1024 * 1024; // 1 GB
pub const SCRATCH_ARENA_SIZE: usize = 256 * 1024 * 1024; // 256 MB

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
}
