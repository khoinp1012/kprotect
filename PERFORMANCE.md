# kprotect Performance & Benchmarking

One of the secondary goals of `kprotect` is to provide robust security with **near-zero overhead**. This is achieved through a combination of kernel-level enforcement and optimized userspace state management.

## ⚡ Kernel-Level Efficiency (eBPF-LSM)

By using **BPF LSM** instead of traditional userspace auditing or heavy system-call hooking, kprotect achieves industry-leading performance.

-   **Hook Latency**: Execution of `file_open` and `bprm_committed_creds` hooks adds < 500 nanoseconds to the kernel path.
-   **Static Verification**: All eBPF loops are statically unrolled or bounded, ensuring deterministic execution time.
-   **Lock-Free Maps**: eBPF HashMaps and LPM Tries are optimized for read-heavy workloads (most access attempts are authorized).

## 🏎️ Userspace Optimizations (Rust Daemon)

The `kprotect-daemon` is designed to handle high-frequency event streams (e.g., system boot-up) without dropped packets or memory spikes.

-   **Lock-Free Concurrency**: Uses `dashmap` for high-concurrency access to the Lineage Cache, minimizing thread contention.
-   **Per-CPU Buffers**: eBPF-to-Userspace communication utilizes `PerfEventArray` with per-CPU buffering to prevent "lock-stepping" on multi-core systems.
-   **Batch Processing**: GUI and CLI updates are batched (100ms intervals) to reduce terminal and UI rendering overhead.

## 📊 Verified Benchmarks

> **Test Environment**:
> - **CPU**: Intel(R) Xeon(R) CPU E5-2673 v3 @ 2.40GHz
> - **RAM**: 32GB DDR3 1066 MHz
> - **Kernel**: 6.8.0-52-generic
> - **Methodology**: 20,000 iterations using C `clock_gettime(CLOCK_MONOTONIC)` for nanosecond precision.

### 1. Process Spawning Overhead (`fork` + `exec`)
Measures the latency added to creating a new process. This includes:
-   Allocating kernel structures.
-   **kprotect**: Hashing parent lineage + arguments.
-   **kprotect**: Updating eBPF maps.

| Metric | Result |
| :--- | :--- |
| Baseline (No Security) | 17.14s (Total for 20k) |
| Active (Protected) | 17.40s (Total for 20k) |
| **Overhead per Process** | **+12.84 µs** (+1.50%) |
| **Impact** | **Negligible** |

### 2. File System Overhead (`open` + `close`)
Measures the latency added to opening a file. This includes:
-   Path resolution.
-   **kprotect**: Checking file path against specific "Red Zone" patterns (e.g. `*.pem`, `id_rsa`).

| Metric | Result |
| :--- | :--- |
| Baseline (No Security) | 0.074s (Total for 20k) |
| Active (Protected) | 0.084s (Total for 20k) |
| **Overhead per Op** | **+0.53 µs** (+14.28%) |
| **Impact** | **Imperceptible** (0.0000005s) |

> *Note: While the relative percentage for file ops (14%) appears high in a tight micro-benchmark of pure `open/close` calls (which take nanoseconds), the absolute cost of **0.53 microseconds** is orders of magnitude smaller than disk I/O latency (typically 100-10,000 µs).*

## 🛠️ Performance Tuning

kprotect provides several knobs to optimize for specific hardware:
-   **Event Retention**: Configurable log rotation prevents disk I/O bottlenecks.
-   **Enrichment Filtering**: Users can limit process name enrichment to specific high-risk binaries (Python, Node) to reduce eBPF-to-daemon traffic.
-   **Map Capacity**: eBPF map sizes are tunable to balance memory usage vs. the number of monitored processes.

## 🧪 Verifying Performance

We believe in transparency. You can verify these numbers on your own machine using the included benchmark suite:

```bash
# Run the automated benchmark script
sudo ./scripts/benchmark.sh
```

This script will:
1.  Measure baseline performance (kprotect stopped).
2.  Start kprotect and measure active performance.
3.  Compare file system operations (`stat`, `open`) and process spawning (`fork`, `exec`).
