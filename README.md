# nalloc: ZK-Optimized Memory Allocator

A high-performance, deterministic, and security-hardened memory allocator specifically engineered for Zero-Knowledge Proof (ZKP) systems and cryptographic provers.

[![Crates.io](https://img.shields.io/crates/v/zk-nalloc.svg)](https://crates.io/crates/zk-nalloc)
[![Documentation](https://docs.rs/zk-nalloc/badge.svg)](https://docs.rs/zk-nalloc)
[![License](https://img.shields.io/crates/l/zk-nalloc.svg)](LICENSE)

## Why nalloc?

General-purpose allocators (malloc, jemalloc) are designed for long-lived, heterogeneous workloads. ZK provers, however, exhibit extreme memory patterns: massive short-lived vectors, sensitive witness data, and performance-critical FFT/NTT operations. 

`nalloc` addresses these unique requirements:

- **Performance**: O(1) allocation via Atomic Bump Allocation.
- **Cache-Friendliness**: Guaranteed 64-byte alignment (AVX-512/SIMD optimal) for polynomials.
- **Security**: Hardened volatile wiping of witness data to prevent leakage.
- **Stability**: Robust global allocator initialization compatible with complex ZK libraries like **Halo2**.

---

## Architecture: Specialized Arenas

`nalloc` partitions memory into three specialized pools to eliminate fragmentation and enforce security boundaries:

| Arena | Purpose | Optimization | Security |
|-------|---------|--------------|-----------|
| **Witness** | Secret inputs / Witnesses | Zero-on-recycled-alloc | **Secure Wipe** (Volatile) |
| **Polynomial** | FFT / NTT Vectors | 64-byte & Page Alignment | Isolated from scratch |
| **Scratch** | Temp computation space | High-speed bump allocation | O(1) Batch Reset |

---

## Core Features

### 1. Hardened Witness Security
Witness data is handled with extreme caution. The `secure_wipe()` method uses platform-specific primitives that the compiler cannot optimize away:
- **Linux**: `explicit_bzero`
- **macOS**: `memset_s`
- **Fallback**: Atomic volatile write loops with memory fences.

### 2. Halo2 & ZKP Ready
Tested with real-world Halo2 circuits. Unlike standard allocators, `nalloc` uses a lock-free `AtomicPtr` initialization strategy, preventing recursive allocation deadlocks during prover startup.

### 3. Monitoring & Stats
Easily track your circuit's memory footprint:
```rust
let stats = ALLOC.stats();
println!("Witness used: {} bytes", stats.witness_used);
println!("Polynomial used: {} bytes", stats.polynomial_used);
```

---

## Usage

### As a Global Allocator
Add to your `Cargo.toml`:
```toml
[dependencies]
zk-nalloc = "0.1.1"
```

In your `main.rs` or `lib.rs`:
```rust
use zk_nalloc::NAlloc;

#[global_allocator]
static ALLOC: NAlloc = NAlloc::new();

fn main() {
    // All allocations are now routed to specialized arenas
    let data = vec![0u8; 1024];
}
```

### Manual Arena Control
For maximum performance, access arenas directly:
```rust
use zk_nalloc::NAlloc;

fn prove() {
    let nalloc = NAlloc::new();
    
    // 1. Allocate witness data
    let witness = nalloc.witness();
    let secret = witness.alloc(1024, 64);
    
    // 2. Compute proof...
    
    // 3. Securely erase traces
    unsafe { witness.secure_wipe(); }
}
```

---

## Platform Support & Verification

`nalloc` provides cross-platform abstractions for low-level memory management:
- **macOS**: `mach_vm_allocate` / `mach_vm_deallocate`
- **Linux**: `mmap` / `munmap` (via `rustix`)
- **Windows**: `VirtualAlloc` / `VirtualFree`

**Current Status**: 49/49 tests passing (Unit, Integration, Doc, and Halo2).

---

## Performance Benchmark

| Task | System Alloc | nalloc | Speedup |
|------|--------------|---------|---------|
| 10k Small Allocs | ~150 μs | ~50 μs | **3x** |
| Large FFT Vector | ~10 μs | ~8 μs | **1.2x** |
| Batch Dealloc | O(N) | **O(1)** | **∞** |

---

## License

Licensed under either of:
- Apache License, Version 2.0
- MIT license

---

## Contributing

Designed with ❤️ for the ZK community. Contributions for Huge Page support or new platform backends are welcome.
