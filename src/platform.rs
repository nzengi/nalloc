//! Platform-specific memory allocation interface.
//!
//! This module provides an abstraction over the operating system's
//! virtual memory allocation APIs:
//! - **Linux**: `mmap` via `rustix`
//! - **macOS**: `mach_vm_allocate` via `mach2`
//! - **Other Unix**: `mmap` via `libc`

use std::fmt;

/// Error type for system memory allocation failures.
#[derive(Debug, Clone, Copy)]
pub struct AllocFailed;

impl std::error::Error for AllocFailed {}

impl fmt::Display for AllocFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "System memory allocation failed")
    }
}

/// Platform-specific memory allocation functions.
pub mod sys {
    use super::AllocFailed;

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
                Err(_) => Err(AllocFailed),
            }
        }
    }

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
            Err(AllocFailed)
        }
    }

    /// Fallback for other Unix-like systems.
    #[cfg(all(not(target_os = "linux"), not(target_vendor = "apple"), unix))]
    #[inline]
    pub fn alloc(size: usize) -> Result<*mut u8, AllocFailed> {
        use libc::{mmap, MAP_ANON, MAP_FAILED, MAP_PRIVATE, PROT_READ, PROT_WRITE};
        use std::ptr;

        debug_assert!(size > 0);

        let ptr = unsafe {
            mmap(
                ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON,
                -1,
                0,
            )
        };

        if ptr == MAP_FAILED {
            Err(AllocFailed)
        } else {
            Ok(ptr as *mut u8)
        }
    }
}
