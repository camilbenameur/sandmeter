Machine: 2 vCPU, 7931 MB RAM, kernel 7.0.0-1019-azure. Image docker.io/library/alpine:3.20 (sha256:c64c687cbea9). 2026-11-11.

| Backend | Start p50 | Start p90 | Start p99 | Snapshot p50 | Restore p50 | CPU loop vs chroot | 128 MiB fsync write vs chroot | Concurrent sandboxes |
|---|---|---|---|---|---|---|---|---|
| native | 5.7 ms | 7.1 ms | 10.5 ms | 0.3 ms | 0.3 ms | 397 ms vs 383 ms (x1.04) | n/a | 20 ok in 2141 ms |
| gvisor (runsc version release-20261019.0) | 53.6 ms | 63.6 ms | 74.5 ms | 0.8 ms | 0.5 ms | 456 ms vs 376 ms (x1.21) | n/a | 20 ok in 2923 ms |

Start = host-side wall time of running `true` in a fresh sandbox (namespaces, cgroup, init, exec, teardown); n=100 per backend. Overhead ratios compare medians of 5 runs against a plain chroot into the same image layers, which still pays process start but no isolation.
