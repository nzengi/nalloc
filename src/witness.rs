//! Witness Arena for nalloc.
//!
//! The `WitnessArena` provides a security-hardened interface for allocating
//! private ZK inputs (witnesses). Key features:
//!
//! - **Auto-zero on allocation**: Prevents reading uninitialized data.
//! - **Secure wipe on reset**: Zeroes all memory before recycling.

use crate::bump::BumpAlloc;
use std::sync::Arc;

/// Specialized handle for Witness memory.
///
/// Ensures zeroing on allocation and secure wiping on reset.
pub struct WitnessArena {
    inner: Arc<BumpAlloc>,
}

impl WitnessArena {
    /// Create a new `WitnessArena` wrapping a `BumpAlloc`.
    #[inline]
    pub fn new(inner: Arc<BumpAlloc>) -> Self {
        Self { inner }
    }

    /// Allocate witness data.
    ///
    /// The returned memory is **always zero-initialized** for security.
    #[inline]
    pub fn alloc(&self, size: usize, align: usize) -> *mut u8 {
        debug_assert!(size > 0);
        debug_assert!(align > 0);

        let ptr = self.inner.alloc(size, align);
        if !ptr.is_null() {
            // Safety: We just allocated this block, and we know its size.
            unsafe {
                std::ptr::write_bytes(ptr, 0, size);
            }
        }
        ptr
    }

    /// Securely wipe all witness data and reset the arena.
    ///
    /// # Safety
    /// All previously allocated witness memory becomes invalid.
    #[inline]
    pub unsafe fn secure_wipe(&self) {
        self.inner.secure_reset();
    }

    /// Get the remaining capacity in bytes.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.inner.remaining()
    }
}
