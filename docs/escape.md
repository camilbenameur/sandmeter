| Case | gvisor | native |
|---|---|---|
| 01-proc-root | blocked: no path reached the host canary | blocked: no path reached the host canary |
| 02-host-pids | blocked: pid namespace isolated (1 pids, init=sh) | blocked: pid namespace isolated (1 pids, init=sh) |
| 03-raw-disk | blocked: mknod refused for: 8:0 259:0 252:0 253:0 | blocked: mknod refused for: 259:0 |
| 04-proc-sys-write | blocked: proc/sys entries are read-only or properly namespaced | blocked: proc/sys entries are read-only or properly namespaced |
| 05-sysfs-rw | blocked: /sys stayed read-only | blocked: /sys stayed read-only |
| 06-cgroup-release-agent | blocked: cgroup v1 controller unavailable | blocked: cgroup v1 controller unavailable |
| 07-userns-mount | blocked: start or run child in new user namespace: fork/exec /usr/local/bin/rfprobe: operation not permitted: | blocked: start or run child in new user namespace: fork/exec /usr/local/bin/rfprobe: operation not permitted: |
| 08-kernel-surface | blocked: no probed syscall was reachable | blocked: no probed syscall was reachable |
| 09-shocker | blocked: name_to_handle_at(/): operation not permitted | blocked: name_to_handle_at(/): operation not permitted |
| 10-egress-none | blocked: connect 10.1.0.113:37739: dial tcp 10.1.0.113:37739: connect: network is unreachable | blocked: connect 10.1.0.113:37739: dial tcp 10.1.0.113:37739: connect: network is unreachable |
| 11-egress-allowlist | blocked: no answer on: tcp icmp dns ; could not test: none | blocked: no answer on: tcp dns ; could not test: icmp |
| 12-host-gateway | blocked: connect 10.213.0.1:36795: dial tcp 10.213.0.1:36795: i/o timeout | blocked: connect 10.213.0.1:36795: dial tcp 10.213.0.1:36795: i/o timeout |
| 13-fork-bomb | exposed: no fork was refused: pids.max may not have been enforced | blocked: fork refused with EAGAIN (pids.max) |
| 14-memory-hog | blocked: no RESULT line, killed by oom | blocked: no RESULT line, killed by oom |
| 15-symlink-host-tooling | exposed: planted: /tmp/rf-link-canary /tmp/rf-link-marker /workspace/rf-link-canary /workspace/rf-link-marker  (harness ... | exposed: planted: /tmp/rf-link-canary /tmp/rf-link-marker /workspace/rf-link-canary /workspace/rf-link-marker  (harness ... |

gvisor: blocked 13 / 15
native: blocked 14 / 15
