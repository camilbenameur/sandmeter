# KVM and micro-VM verdict

Question: can this project run a Firecracker backend, and where?

Status on 2026-11-10: **KVM works on GitHub-hosted `ubuntu-latest` runners, and
nowhere else I have.** A Firecracker guest boots there in about one second. Firecracker
stays out of the core: it can become a CI-only backend late in the plan, labelled that way.

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

Measured by `.github/workflows/kvm-probe.yml` on 2026-11-10, run 42904429882, in a
**private** repository (2 vCPU runner). The arm64 job runs only once the repository is
public, since free arm64 runners are public-only.

| Check | Result |
|---|---|
| Runner | `ubuntu-latest`, kernel 7.0.0-1019-azure, AMD EPYC 7763, 2 vCPU, `virt: microsoft` |
| `/dev/kvm` before the udev rule | present, `crw-rw---- root kvm` (the runner user cannot open it) |
| `/dev/kvm` after `KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"` | `crw-rw-rw-` |
| `kvm_amd` nested | `1` |
| `KVM_GET_API_VERSION` | 12 |
| Firecracker v1.17.0, kernel 6.1.155 from `firecracker-ci/v1.15`, busybox initramfs | **guest booted**: `/init` ran at 0.34 s guest time, printed `PROBE_GUEST_OK 6.1.155+` |
| Wall time, VMM start to VMM exit | 1019 ms (one sample, includes kernel boot and reboot) |
| `kernel.apparmor_restrict_unprivileged_userns` | `1`, and `unshare -Ur` fails as on the VPS: CI tests of the native backend run under `sudo` |
| cgroup filesystem | `cgroup2fs`, `cpu memory pids` delegated to the runner user |

Caveats:
- GitHub documents "hardware acceleration for Android SDK tools", not KVM for any
  VMM. This result says "works today on this runner image", not "guaranteed".
- Firecracker v1.17 refuses a config without a `drives` field, even for an
  initramfs-only guest. The probe sets `"drives": []`.
- The guest ends with `reboot -f`: with `reboot=k` Firecracker exits. With
  `poweroff -f` the guest halts and Firecracker keeps running until the timeout.
- One sample on a shared runner is not a benchmark. No micro-VM number goes in the README
  until `bench/` runs it with repetitions.

## Decision rule

- Probe boots on `ubuntu-latest` (the case today): a `firecracker` backend may be added
  late in the plan, tested only in CI, and labelled that way in the README. No micro-VM
  number is published from any other machine. Development of that backend cannot be
  done on the VPS, so it stays the first thing cut if time runs short.
- Probe fails: the README says "no micro-VM backend: no KVM on the machines I have".
  gVisor (`runsc`, systrap platform) is the second isolation level. gVisor is a
  user-space kernel, not a micro-VM, and the README says so. This applies again if a
  later probe run stops booting.
