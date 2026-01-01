//! Polynomial Arena for nalloc.
//!
//! The `PolynomialArena` is optimized for FFT/NTT operations:
//!
//! - **64-byte alignment**: Ensures data fits cache lines for SIMD operations.
//! - **4KB page alignment**: Optionally available for huge vector allocations.
//! - **Massive capacity**: Pre-reserved for 1GB+ polynomial vectors.

use crate::bump::BumpAlloc;
use std::sync::Arc;

/// Cache line size on most modern architectures.
pub const CACHE_LINE_ALIGN: usize = 64;

/// Page size on Linux/Windows (Apple is 16KB, but 4KB works everywhere).
pub const PAGE_ALIGN: usize = 4096;

/// Specialized handle for Polynomial and FFT data.
///
/// Optimized for cache-line alignment and massive vectors.
pub struct PolynomialArena {
    inner: Arc<BumpAlloc>,
}

impl PolynomialArena {
    /// Create a new `PolynomialArena` wrapping a `BumpAlloc`.
    #[inline]
    pub fn new(inner: Arc<BumpAlloc>) -> Self {
        Self { inner }
    }

    /// Allocate polynomial data with 64-byte alignment for optimal FFT/NTT performance.
    ///
    /// This alignment is critical for SIMD-accelerated operations.
    #[inline]
    pub fn alloc_fft_friendly(&self, size: usize) -> *mut u8 {
        debug_assert!(size > 0);
        self.inner.alloc(size, CACHE_LINE_ALIGN)
    }

    /// Allocate huge vectors with page alignment (4096 bytes).
    ///
    /// Use this for vectors exceeding a few megabytes.
    #[inline]
    pub fn alloc_huge(&self, size: usize) -> *mut u8 {
        debug_assert!(size > 0);
        self.inner.alloc(size, PAGE_ALIGN)
    }

    /// Allocate with custom alignment.
    #[inline]
    pub fn alloc(&self, size: usize, align: usize) -> *mut u8 {
        debug_assert!(size > 0);
        debug_assert!(align > 0);
        self.inner.alloc(size, align)
    }

    /// Reset the polynomial arena.
    ///
    /// # Safety
    /// All previously allocated polynomial memory becomes invalid.
    #[inline]
    pub unsafe fn reset(&self) {
        self.inner.reset();
    }

    /// Get the remaining capacity in bytes.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.inner.remaining()
    }
}
