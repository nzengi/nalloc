# nalloc

A high-performance, security-focused memory allocator optimized for Zero-Knowledge Proof (ZKP) systems.

[![Crates.io](https://img.shields.io/crates/v/zk-nalloc.svg)](https://crates.io/crates/zk-nalloc)
[![Documentation](https://docs.rs/zk-nalloc/badge.svg)](https://docs.rs/zk-nalloc)
[![License](https://img.shields.io/crates/l/zk-nalloc.svg)](LICENSE)

## The Problem: Why General-Purpose Allocators Fail for ZKP

Zero-Knowledge Proof systems represent one of the heaviest computational burdens in modern cryptography. The primary bottleneck is often not just raw CPU cycles, but how data moves and is managed within memory. Conventional allocators (like `malloc` or `jemalloc`) fail to address the unique demands of ZK provers:

1. **Fragmentation:** Allocating gigabytes for polynomials shatters the memory map, leading to inefficiency
2. **Alignment Loss:** FFT/NTT operations require precise cache-line alignment for SIMD operations
3. **Security Overhead:** Cryptographic witness data leaves traces in memory that must be securely erased
4. **Lack of Determinism:** Proof reproducibility requires predictable memory layouts

## The nalloc Solution

`nalloc` manages ZK prover workloads through specialized arenas:

### Arena Partitioning

Memory is pre-reserved in large blocks (Arenas). Polynomials, witness data, and scratch computation spaces are strictly isolated:

| Arena | Size | Purpose | Security |
|-------|------|---------|----------|
| **Witness** | 128 MB | Private inputs | Secure wipe, zero-on-alloc |
| **Polynomial** | 1 GB | FFT/NTT vectors | 64-byte aligned |
| **Scratch** | 256 MB | Temp buffers | Fast reset |

### Atomic Bump Allocation

Allocation is reduced to a simple, lock-free atomic pointer increment — the fastest theoretical method for batch workloads:

```rust
let alloc = NAlloc::new();
let poly = alloc.polynomial();

// O(1) allocation with guaranteed 64-byte alignment
let coeffs = poly.alloc_fft_friendly(1024 * 1024);
```

### Guaranteed Alignment

- **64-byte alignment** for FFT data (AVX-512 optimal)
- **4KB page alignment** for massive vectors (TLB efficient)
- Custom alignment support for specialized needs

### Secure Wiping

The Witness Arena is zeroed using platform-specific secure functions that cannot be optimized away by the compiler:

- **Linux**: `explicit_bzero()` — guaranteed non-removable
- **macOS**: `memset_s()` — C11 secure memory set
- **Other**: Volatile write loop with compiler fences

```rust
let witness = alloc.witness();
let secret_ptr = witness.alloc(256, 8);

// ... compute ZK proof using secret data ...

// Securely erase all witness data
unsafe { witness.secure_wipe(); }
```

## Usage

### As a Global Allocator

```rust
use zk_nalloc::NAlloc;

#[global_allocator]
static ALLOC: NAlloc = NAlloc::new();

fn main() {
    // All allocations now use nalloc
    let data: Vec<u64> = vec![0; 1_000_000];
}
```

### Using Specialized Arenas Directly

```rust
use zk_nalloc::NAlloc;

fn compute_proof() {
    let alloc = NAlloc::new();
    
    // Polynomial coefficients with SIMD-friendly alignment
    let poly = alloc.polynomial();
    let coeffs = poly.alloc_fft_friendly(1024 * 1024);
    
    // Sensitive witness data with security guarantees
    let witness = alloc.witness();
    let secret = witness.alloc(1024, 8);
    
    // ... compute proof ...
    
    // Secure cleanup
    unsafe {
        witness.secure_wipe();
        alloc.reset_all();
    }
}
```

### Monitoring Memory Usage

```rust
let alloc = NAlloc::new();

// ... allocate memory ...

let stats = alloc.stats();
println!("Witness: {}/{} bytes used", stats.witness_used, stats.witness_capacity);
println!("Polynomial: {}/{} bytes used", stats.polynomial_used, stats.polynomial_capacity);
println!("Total: {} bytes in use", stats.total_used());
```

## Platform Support

| Platform | Allocation | Secure Wipe | Status |
|----------|------------|-------------|--------|
| Linux | `mmap` | `explicit_bzero` | ✅ Full support |
| macOS | `mach_vm_allocate` | `memset_s` | ✅ Full support |
| Windows | `VirtualAlloc` | Volatile loop | ✅ Full support |
| Other Unix | `mmap` (libc) | Volatile loop | ✅ Full support |

## Performance

`nalloc` is designed for the batch allocation patterns typical in ZK proving:

| Operation | Time | Notes |
|-----------|------|-------|
| Small alloc (32B) | ~5 ns | Atomic pointer increment |
| Large alloc (1MB) | ~10 ns | Same bump mechanism |
| Reset 10K allocs | O(1) | Single pointer reset |
| Secure wipe (128MB) | ~20 ms | Sequential memory write |

Compared to system allocators, `nalloc` provides:
- **1000x+ faster** batch deallocation (reset vs free-one-by-one)
- **Deterministic** allocation patterns for reproducible proofs
- **Zero fragmentation** within arenas

## Configuration

Arena sizes can be customized for your circuit:

```rust
use zk_nalloc::ArenaManager;

// Custom arena sizes for large circuits
let manager = ArenaManager::with_sizes(
    256 * 1024 * 1024,  // 256 MB witness
    2 * 1024 * 1024 * 1024,  // 2 GB polynomial
    512 * 1024 * 1024,  // 512 MB scratch
)?;
```

## Safety

`nalloc` is designed with security-critical applications in mind:

- ✅ **Witness data is zeroed** on allocation (recycled memory only, for performance)
- ✅ **Secure wipe uses volatile writes** that cannot be optimized away
- ✅ **Memory is properly deallocated** when `ArenaManager` is dropped
- ✅ **Thread-safe** via lock-free atomic operations
- ✅ **No undefined behavior** in safe API (unsafe only for reset/wipe)

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
