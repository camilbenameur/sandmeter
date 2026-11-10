# KVM and micro-VM verdict

Question: can this project run a Firecracker backend, and where?

Status on 2026-11-10: **probe only.** No machine I control exposes `/dev/kvm`.
Firecracker stays out of the core; it becomes a backend only if the Actions probe
below boots a guest.

## Measurements

All numbers come from `scripts/probe/host.sh` (read-only) unless noted.

### Development VPS (Contabo, 8 vCPU, 23 GB, Ubuntu 24.04, kernel 6.8.0-149)

| Check | Result |
|---|---|
| `/dev/kvm` | absent |
| `vmx`/`svm` CPU flags | 0: the hypervisor does not pass virtualization through |
| `systemd-detect-virt` | `kvm`: the VPS is itself a KVM guest without nested virtualization |
| cgroup filesystem | `cgroup2fs`, root controllers `cpuset cpu io memory hugetlb pids rdma misc` |
| cgroup delegation to the login user (`user@1001.service`) | `cpu memory pids` |
| `kernel.unprivileged_userns_clone` | 1 |
| `kernel.apparmor_restrict_unprivileged_userns` | **1** |
| `unshare -Ur` as a normal user | **fails**: `write failed /proc/self/uid_map: Operation not permitted` |
| `sudo unshare -Ur` | works |

Firecracker without KVM needs a patched kernel and VMM. Out of scope.

The user namespace result matters more than KVM for this project. On Ubuntu 23.10+
an unprivileged process can still call `unshare(CLONE_NEWUSER)`, but AppArmor moves
it into the `unprivileged_userns` profile, which has `audit deny capability`. The new
namespace exists, but its root has no capabilities, so it cannot even write its own
`uid_map`. Consequences for the `native` backend:

- "rootless" is not available by default on this host. The options are: run as root,
  ship an AppArmor profile for the binary with `userns,` (what Chrome and lxc do in
  `/etc/apparmor.d/`), or flip the sysctl. The last two are host changes.
- The backend will run as root for now and document it. Network setup
  (veth, nftables) needs `CAP_NET_ADMIN` in the host network namespace anyway.
- Tests must check for this condition and report it, not fail silently.

### GitHub Codespace (2-core, Azure, kernel 6.8.0-1064-azure)

Probed through an existing codespace with `gh codespace ssh`, then stopped it.

| Check | Result |
|---|---|
| `/dev/kvm` | absent |
| `vmx` flags in `/proc/cpuinfo` | present (Xeon Platinum 8370C) |
| `/sys/module/kvm_intel/parameters/nested` | `Y` |
| `unshare -Ur` | fails: `unshare failed: Operation not permitted` (the dev container has no `CAP_SYS_ADMIN` and a seccomp filter) |
| cgroup filesystem | `cgroup2fs` |

The Azure VM under the codespace has nested virtualization enabled, but the dev
container does not get the device. A devcontainer with `--device=/dev/kvm` and
`--privileged` might change that; untested, and not something a reader can rely on.
Verdict: no KVM in a standard Codespace. This matches a third-party report
([urunc #953](https://github.com/urunc-dev/urunc/issues/953)).

### GitHub Actions hosted runners

**Not measured yet.** The workflow `.github/workflows/kvm-probe.yml` does it. It runs on
`ubuntu-latest` and `ubuntu-24.04-arm` and:

1. runs `scripts/probe/host.sh` before and after the udev rule
   `KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"`;
2. opens `/dev/kvm` and calls `KVM_GET_API_VERSION`;
3. downloads Firecracker v1.17.0 and a guest kernel from the Firecracker CI bucket
   (`firecracker-ci/v1.15`, the newest one that still publishes kernels), builds a
   busybox initramfs whose `/init` prints `PROBE_GUEST_OK`, boots it, and records
   the wall time.

It needs a public repository: public runners have 4 vCPU and the 2024 changelog about
hardware acceleration targets them. What GitHub documents officially is "hardware
acceleration for Android SDK tools", not KVM for arbitrary VMMs, so a positive result
says "works today on this runner image", not "guaranteed".

Result: _pending first run._

## Decision rule

- Probe boots on `ubuntu-latest`: a `firecracker` backend may be added late in the
  plan, tested only in CI, and labelled that way in the README. No micro-VM number is
  published from any other machine.
- Probe fails: the README says "no micro-VM backend: no KVM on the machines I have".
  gVisor (`runsc`, systrap platform) is the second isolation level. gVisor is a
  user-space kernel, not a micro-VM, and the README says so.
