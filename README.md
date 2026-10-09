# titan-packet-filter
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![CI](https://github.com/sohamshewani/titan-packet-filter/actions/workflows/ci.yml/badge.svg)](https://github.com/sohamshewani/titan-packet-filter/actions) [![Security: Hardened](https://img.shields.io/badge/Security-Hardened-blue.svg)](https://github.com/sohamshewani/titan-packet-filter) [![Stars](https://img.shields.io/github/stars/sohamshewani/titan-packet-filter?style=flat)](https://github.com/sohamshewani/titan-packet-filter)

## Executive Summary & Problem Space

`titan-packet-filter` is an ultra-low-latency, zero-allocation C++ packet processing and filtering engine engineered for high-throughput network appliances, distributed firewalls, and deep packet inspection (DPI) pipelines. 

Modern high-speed networks face severe throughput bottlenecks when operating at line rate (10GbE to 100GbE+). Standard packet processing frameworks often suffer from micro-architectural penalties:
1. **Dynamic Memory Allocation Overhead:** Traditional heap allocators (`malloc`/`free`) introduce severe lock contention, cache thrashing, and unpredictable tail latencies during packet ingress surges.
2. **Cache Coherency Invalidation:** Cross-core synchronization using locks or unaligned atomic operations triggers cache-line bouncing across Non-Uniform Memory Access (NUMA) nodes.
3. **Branch Mispredictions:** Naive multi-stage rule evaluation architectures introduce deep control-flow dependencies that degrade CPU pipeline throughput.

`titan-packet-filter` resolves these challenges by decoupling packet ingestion from rule execution using a lock-free Single-Producer Single-Consumer (SPSC) ring buffer, backing all hot-path states with a deterministic arena allocator, and evaluating stateful TCP flow windows with branch-optimized evaluation trees.

---

## Structural ASCII Architecture / Dataflow Diagram

The system operates as a pipelined, zero-copy architecture separating kernel-space or NIC-driver polling from user-space stateful filtering.

```
 +-----------------------------------------------------------------------+
 |                        INBOUND NETWORK STREAM                         |
 +-----------------------------------------------------------------------+
                                    |
                                    v
 +-----------------------------------------------------------------------+
 |                      POLL DRIVER (src/poll_driver.cpp)                |
 |  - Epoll / DPDK / Raw Socket polling                                  |
 |  - Non-blocking packet descriptor batching                            |
 +-----------------------------------------------------------------------+
                                    |
                                    v (Zero-copy raw packet payload)
 +-----------------------------------------------------------------------+
 |                 LOCK-FREE SPSC RING BUFFER                            |
 |                 (include/titan/ring_buffer.hpp)                       |
 |  - Atomic Head/Tail pointers with cache-line padding (64-byte aligned) |
 +-----------------------------------------------------------------------+
                                    |
                                    v
 +-----------------------------------------------------------------------+
 |                 ARENA ALLOCATOR (include/titan/arena.hpp)             |
 |  - Bump-pointer allocation (O(1) memory acquisition)                  |
 |  - Pre-allocated backing slab (Zero dynamic syscalls on hot path)      |
 +-----------------------------------------------------------------------+
                                    |
                                    v
 +-----------------------------------------------------------------------+
 |                 FILTER ENGINE (include/titan/filter_engine.hpp)       |
 |  - Layer 2/3/4 inspection pipeline                                    |
 |  - Stateful tracking via Flow Window                                  |
 +-----------------------------------------------------------------------+
          |                                              |
          v (Drop / Malformed)                           v (Pass / Validated)
 +--------------------+                         +------------------------+
 |    DISCARD LOG     |                         | APPLICATION UPSTREAM   |
 +--------------------+                         +------------------------+
```

---

## Concurrency Model & Memory Invariants

### Thread Safety & Lock Contention Prevention
`titan-packet-filter` enforces a strict lock-free concurrency model across core boundaries:
* **Ring Buffer Isolation:** The `ring_buffer.hpp` component implements a wait-free SPSC queue utilizing memory barriers (`std::memory_order_acquire` and `std::memory_order_release`). This eliminates atomic CAS (Compare-And-Swap) retry loops under single-producer/single-consumer conditions.
* **Cache Line Isolation:** Head and tail atomic variables are padded to 64 bytes to eliminate false sharing between the network polling thread and the worker filtering thread.

### Memory Ownership & Arena Allocator
* **Deterministic Lifetimes:** The `arena.hpp` provides continuous memory blocks sized for bounded packet bursts. Temporary rule context blocks, flow metadata, and packet descriptors are allocated via bump-pointer increments.
* **RAII Lifecycle Management:** Individual allocations do not invoke destructors individually. The entire arena is reset atomically between processing batches, guaranteeing zero memory fragmentation and deterministic $O(1)$ memory reclamation.

---

## Performance Characteristics & Algorithmic Complexity Table

| Operation | Component | Time Complexity | Space Complexity | Latency Estimate (P99) |
| :--- | :--- | :--- | :--- | :--- |
| **Packet Ingress** | `ring_buffer.hpp` | $O(1)$ | $O(N)$ fixed capacity | $< 15\text{ ns}$ |
| **Memory Allocation** | `arena.hpp` | $O(1)$ | $O(S)$ slab size | $< 2\text{ ns}$ |
| **Flow Lookup & State Check**| `flow_window.hpp`| $O(1)$ amortized hash | $O(F)$ active flows | $< 45\text{ ns}$ |
| **Rule Engine Evaluation** | `filter_engine.hpp`| $O(R)$ ($R = \text{rules}$) | $O(1)$ auxiliary | $< 120\text{ ns}$ |
| **Batch Reset** | `arena.hpp` | $O(1)$ | $O(1)$ pointer reset | $< 5\text{ ns}$ |

---

## Security Architecture & Threat Model

`titan-packet-filter` is engineered to withstand aggressive Layer 4 denial-of-service (DoS) vectors, malformed frame injections, and memory exhaustion attacks.

### 1. Input Boundaries & Bounds Checking
* **Strict Payload Validation:** All raw packet headers parsed in `include/titan/types.hpp` undergo rigorous length verification against the backing buffer boundary before multi-byte integer extraction.
* **Integer Overflow Mitigation:** Arithmetic operations calculating TCP window sequences and payload offsets utilize safe casting guards to prevent integer wraparound exploitation.

### 2. Memory Corruption Protections
* **No Raw Pointers on Hot Path:** Memory access is governed by strongly-typed views and bounds-checked spans.
* **Bounded Resource Allocation:** The arena allocator operates within hard memory ceilings (`arena.hpp`). Exhaustion triggers safe drop policies rather than unhandled dynamic allocations or segmentation faults.

### 3. Threat Mitigations
* **SYN Flooding / State Exhaustion:** `flow_window.hpp` implements sliding window validation thresholds and eviction policies to prevent state table exhaustion during volumetric connection floods.
* **Malformed Packet Injection:** Packet headers with truncated lengths or invalid IP/TCP checksum indicators are filtered immediately at the engine ingress boundary without exception propagation overhead.

---

## Build, Verification & Benchmarking Recipes

### Prerequisites
* GCC 11+ or Clang 13+ with C++20 support
* GNU Make 4.0+
* POSIX-compliant environment (Linux x86_64 / AArch64)

### 1. Compile the Project & Binaries
To build the static library, test suites, and benchmarking executables in release mode with optimizations (`-O3 -march=native`), run:
```bash
make clean && make all
```

### 2. Run Invariant Verification Tests
To execute the comprehensive test suite validating memory safety, state machine invariants, and edge-case filtering logic:
```bash
make test
```
*Expected Output:* All assertions pass within the test driver (`tests/test_invariants.cpp`), verifying thread safety and protocol conformity.

### 3. Execute Performance Benchmarks
To run the high-resolution micro-benchmarks measuring throughput and latency distributions across the filter engine:
```bash
make benchmark
```
*Expected Output:* Executes `benchmarks/bench_engine.cpp`, outputting nanosecond-scale latency percentiles and packet throughput rates per core.