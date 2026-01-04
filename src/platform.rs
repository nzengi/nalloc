//! Platform-specific memory allocation interface.
//!
//! This module provides an abstraction over the operating system's
//! virtual memory allocation APIs:
//! - **Linux**: `mmap` via `rustix`
//! - **macOS**: `mach_vm_allocate` via `mach2`
//! - **Windows**: `VirtualAlloc` via `windows-sys`
//! - **Other Unix**: `mmap` via `libc`

use std::fmt;

/// Error type for system memory allocation failures.
#[derive(Debug, Clone, Copy)]
pub struct AllocFailed {
    /// The size that was requested.
    pub requested_size: usize,
    /// Platform-specific error code, if available.
    pub error_code: Option<i32>,
}

impl std::error::Error for AllocFailed {}

impl fmt::Display for AllocFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.error_code {
            Some(code) => write!(
                f,
                "System memory allocation failed: requested {} bytes, error code {}",
                self.requested_size, code
            ),
            None => write!(
                f,
                "System memory allocation failed: requested {} bytes",
                self.requested_size
            ),
        }
    }
}

impl AllocFailed {
    /// Create a new allocation failure error.
    pub fn new(size: usize) -> Self {
        Self {
            requested_size: size,
            error_code: None,
        }
    }

    #[allow(dead_code)]
    fn with_code(size: usize, code: i32) -> Self {
        Self {
            requested_size: size,
            error_code: Some(code),
        }
    }
}

/// Platform-specific memory allocation functions.
pub mod sys {
    use super::AllocFailed;

    // ========================================================================
    // Linux Implementation (using rustix)
    // ========================================================================

    /// Allocate `size` bytes of virtual memory from the OS.
    ///
    /// The memory is:
    /// - Read/Write accessible
    /// - Not backed by physical pages until touched (on most OSes)
    /// - Aligned to at least the system page size
    #[cfg(target_os = "linux")]
    #[inline]
    pub fn alloc(size: usize) -> Result<*mut u8, AllocFailed> {
        use rustix::mm::{mmap_anonymous, MapFlags, ProtFlags};
        use std::ptr;

        debug_assert!(size > 0);

        unsafe {
            match mmap_anonymous(
                ptr::null_mut(),
                size,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::PRIVATE | MapFlags::NORESERVE,
            ) {
                Ok(ptr) => Ok(ptr as *mut u8),
                Err(_) => Err(AllocFailed::new(size)),
            }
        }
    }

    /// Deallocate memory previously allocated with `alloc`.
    #[cfg(target_os = "linux")]
    #[inline]
    pub fn dealloc(ptr: *mut u8, size: usize) -> Result<(), AllocFailed> {
        use rustix::mm::munmap;

        if ptr.is_null() {
            return Ok(());
        }

        unsafe {
            match munmap(ptr as *mut _, size) {
                Ok(()) => Ok(()),
                Err(_) => Err(AllocFailed::new(size)),
            }
        }
    }

    // ========================================================================
    // macOS Implementation (using mach2)
    // ========================================================================

    #[cfg(target_vendor = "apple")]
    #[inline]
    pub fn alloc(size: usize) -> Result<*mut u8, AllocFailed> {
        use mach2::kern_return::KERN_SUCCESS;
        use mach2::traps::mach_task_self;
        use mach2::vm::mach_vm_allocate;
        use mach2::vm_statistics::VM_FLAGS_ANYWHERE;
        use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t};

        debug_assert!(size > 0);

        let task = unsafe { mach_task_self() };
        let mut address: mach_vm_address_t = 0;
        let vm_size: mach_vm_size_t = size as mach_vm_size_t;

        let retval = unsafe { mach_vm_allocate(task, &mut address, vm_size, VM_FLAGS_ANYWHERE) };

        if retval == KERN_SUCCESS {
            Ok(address as *mut u8)
        } else {
            Err(AllocFailed::with_code(size, retval))
        }
    }

    /// Deallocate memory previously allocated with `alloc`.
    #[cfg(target_vendor = "apple")]
    #[inline]
    pub fn dealloc(ptr: *mut u8, size: usize) -> Result<(), AllocFailed> {
        use mach2::kern_return::KERN_SUCCESS;
        use mach2::traps::mach_task_self;
        use mach2::vm::mach_vm_deallocate;
        use mach2::vm_types::mach_vm_size_t;

        if ptr.is_null() {
            return Ok(());
        }

        let task = unsafe { mach_task_self() };
        let retval = unsafe { mach_vm_deallocate(task, ptr as u64, size as mach_vm_size_t) };

        if retval == KERN_SUCCESS {
            Ok(())
        } else {
            Err(AllocFailed::with_code(size, retval))
        }
    }

    // ========================================================================
    // Windows Implementation
    // ========================================================================

    #[cfg(target_os = "windows")]
    #[inline]
    pub fn alloc(size: usize) -> Result<*mut u8, AllocFailed> {
        use std::ptr;

        const MEM_COMMIT: u32 = 0x00001000;
        const MEM_RESERVE: u32 = 0x00002000;
        const PAGE_READWRITE: u32 = 0x04;

        extern "system" {
            fn VirtualAlloc(
                lpAddress: *mut u8,
                dwSize: usize,
                flAllocationType: u32,
                flProtect: u32,
            ) -> *mut u8;
        }

        debug_assert!(size > 0);

        let result = unsafe {
            VirtualAlloc(
                ptr::null_mut(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };

        if result.is_null() {
            Err(AllocFailed::new(size))
        } else {
            Ok(result)
        }
    }

    /// Deallocate memory previously allocated with `alloc`.
    #[cfg(target_os = "windows")]
    #[inline]
    pub fn dealloc(ptr: *mut u8, _size: usize) -> Result<(), AllocFailed> {
        const MEM_RELEASE: u32 = 0x00008000;

        extern "system" {
            fn VirtualFree(lpAddress: *mut u8, dwSize: usize, dwFreeType: u32) -> i32;
        }

        if ptr.is_null() {
            return Ok(());
        }

        // For MEM_RELEASE, dwSize must be 0
        let result = unsafe { VirtualFree(ptr, 0, MEM_RELEASE) };

        if result != 0 {
            Ok(())
        } else {
            Err(AllocFailed::new(0))
        }
    }

    // ========================================================================
    // Unix Fallback (using libc mmap)
    // ========================================================================

    /// Fallback for other Unix-like systems.
    #[cfg(all(
        not(target_os = "linux"),
        not(target_vendor = "apple"),
        not(target_os = "windows"),
        unix
    ))]
    #[inline]
    pub fn alloc(size: usize) -> Result<*mut u8, AllocFailed> {
        use libc::{mmap, MAP_ANON, MAP_FAILED, MAP_PRIVATE, PROT_READ, PROT_WRITE};
        use std::ptr;

        debug_assert!(size > 0);

        let result = unsafe {
            mmap(
                ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            )
        };

        if result == MAP_FAILED {
            Err(AllocFailed::new(size))
        } else {
            Ok(result as *mut u8)
        }
    }

    /// Deallocate memory previously allocated with `alloc`.
    #[cfg(all(
        not(target_os = "linux"),
        not(target_vendor = "apple"),
        not(target_os = "windows"),
        unix
    ))]
    #[inline]
    pub fn dealloc(ptr: *mut u8, size: usize) -> Result<(), AllocFailed> {
        use libc::munmap;

        if ptr.is_null() {
            return Ok(());
        }

        let result = unsafe { munmap(ptr as *mut _, size) };

        if result == 0 {
            Ok(())
        } else {
            Err(AllocFailed::new(size))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alloc_dealloc_roundtrip() {
        let size = 4096;
        let ptr = sys::alloc(size).expect("allocation should succeed");

        assert!(!ptr.is_null());

        // Write to verify it's accessible
        unsafe {
            std::ptr::write_bytes(ptr, 0xAB, size);
        }

        sys::dealloc(ptr, size).expect("deallocation should succeed");
    }

    #[test]
    fn test_large_allocation() {
        let size = 64 * 1024 * 1024; // 64 MB
        let ptr = sys::alloc(size).expect("large allocation should succeed");

        assert!(!ptr.is_null());

        // Touch first and last pages
        unsafe {
            *ptr = 0x42;
            *ptr.add(size - 1) = 0x42;
        }

        sys::dealloc(ptr, size).expect("deallocation should succeed");
    }

    #[test]
    fn test_alloc_failed_display() {
        let err = AllocFailed::new(1024);
        let msg = format!("{}", err);
        assert!(msg.contains("1024"));
    }
}
