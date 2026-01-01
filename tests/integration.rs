use nalloc::NAlloc;
use std::alloc::{GlobalAlloc, Layout};

#[test]
fn test_determinism() {
    let alloc = NAlloc::new();
    let layout = Layout::from_size_align(1024, 64).unwrap();

    unsafe {
        let ptr1 = alloc.alloc(layout);
        let ptr2 = alloc.alloc(layout);

        let diff = (ptr2 as usize) - (ptr1 as usize);
        assert_eq!(
            diff, 1024,
            "Allocations should be sequential in a bump allocator"
        );
    }
}

#[test]
fn test_witness_security() {
    let alloc = NAlloc::new();
    let witness = alloc.witness();

    let size = 100;
    let ptr = witness.alloc(size, 8);

    unsafe {
        // Verify it was zeroed
        for i in 0..size {
            assert_eq!(*ptr.add(i), 0);
        }

        // Write some "secret" data
        for i in 0..size {
            *ptr.add(i) = 0xFF;
        }

        // Secure reset
        witness.secure_wipe();

        // Verify it was wiped
        for i in 0..size {
            assert_eq!(*ptr.add(i), 0);
        }
    }
}

#[test]
fn test_alignment() {
    let alloc = NAlloc::new();
    let poly = alloc.polynomial();

    let ptr = poly.alloc_fft_friendly(1024);
    assert_eq!(
        (ptr as usize) % 64,
        0,
        "FFT-friendly allocation must be 64-byte aligned"
    );

    let ptr_huge = poly.alloc_huge(4096);
    assert_eq!(
        (ptr_huge as usize) % 4096,
        0,
        "Huge allocation must be 4096-byte aligned"
    );
}
