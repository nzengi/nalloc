# nalloc

Zero-Knowledge Proof (ZKP) systems represent one of the heaviest computational burdens in modern cryptography. In these systems, the primary bottleneck is often not just raw CPU cycles, but how data moves and is managed within memory. Conventional memory allocators (like malloc or jemalloc) are built for general-purpose workloads and fail to address the unique demands of a ZK prover—specifically, the handling of massive polynomial vectors and sensitive witness data.

### The Problem: Why General-Purpose Allocators Fail
1. **Fragmentation:** Allocating gigabytes for polynomials shatters the memory map of general-purpose managers, leading to inefficiency and overhead.
2. **Alignment Loss:** FFT and NTT operations require data to perfectly align with processor cache lines. Standard allocators cannot guarantee this alignment in the most cache-efficient way.
3. **Security Overhead:** Cryptographic witness data often leaves traces in memory. Clearing these traces manually post-computation is a performance sink.
4. **Lack of Determinism:** To ensure proof reproducibility, memory layout must be predictable and isolated from the entropy typical of general-purpose pools.

### The nalloc Solution
`nalloc` does not try to be everything to everyone. It manages ZK prover workloads through three core disciplines:

*   **Arena Partitioning:** Memory is pre-reserved in large blocks (Arenas). Polynomials, witness data, and scratch computation spaces are strictly isolated.
*   **Atomic Bump Allocation:** Allocation is reduced to a simple, synchronized pointer increment. This is the fastest theoretical method for batch workloads.
*   **Guaranteed Alignment:** By default, `nalloc` provides 64-byte alignment for FFT data and 4KB alignment for massive vectors, ensuring the CPU always takes the shortest path to the data.
*   **Secure Cleanup:** The Witness Arena can be physically zeroed out in a single pass (`secure_wipe`) once the proof is generated. It leaves no traces and incurs zero per-allocation cleanup cost.

### Objective
Lower prover costs in ZK-Rollups and privacy-centric protocols by shaving down memory management overhead, even by just a few crucial milliseconds.

### Current Status
`nalloc` is fully compatible with Rust's `GlobalAlloc` interface. It has moved past the experimental phase, providing a deterministic and security-focused foundation for high-performance proving.
