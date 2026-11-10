#!/usr/bin/env bash
# Prints what this host offers to a sandbox: KVM, user namespaces, cgroups v2, tools.
# Read-only: changes nothing on the host. Safe to run unprivileged.
set -u

section() { printf '\n## %s\n' "$1"; }

section kernel
uname -srm
grep -m1 'model name' /proc/cpuinfo || true
printf 'vcpus: %s\n' "$(nproc)"
printf 'virt: %s\n' "$(systemd-detect-virt 2>/dev/null || echo unknown)"

section kvm
if [ -e /dev/kvm ]; then ls -l /dev/kvm; else echo '/dev/kvm: absent'; fi
printf 'cpu flags vmx/svm: %s\n' "$(grep -cE 'vmx|svm' /proc/cpuinfo)"
for m in kvm_intel kvm_amd; do
  f=/sys/module/$m/parameters/nested
  [ -r "$f" ] && printf '%s nested: %s\n' "$m" "$(cat "$f")"
done
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  python3 - <<'PY' || true
import fcntl, os
fd = os.open("/dev/kvm", os.O_RDWR)
print("KVM_GET_API_VERSION:", fcntl.ioctl(fd, 0xAE00))
PY
fi

section user-namespaces
for k in kernel.unprivileged_userns_clone user.max_user_namespaces \
         kernel.apparmor_restrict_unprivileged_userns; do
  sysctl -n "$k" >/dev/null 2>&1 && printf '%s = %s\n' "$k" "$(sysctl -n "$k")"
done
if out=$(unshare -Ur sh -c 'id -u; cat /proc/self/uid_map' 2>&1); then
  echo "unshare -Ur: ok"; echo "$out" | sed 's/^/  /'
else
  echo "unshare -Ur: FAILED: $out"
fi
if out=$(unshare -Urpmn --fork --mount-proc sh -c 'echo pid=$$' 2>&1); then
  echo "unshare -Urpmn (pid+mnt+net): ok ($out)"
else
  echo "unshare -Urpmn: FAILED: $out"
fi

section cgroups
printf 'fs: %s\n' "$(stat -fc %T /sys/fs/cgroup)"
printf 'root controllers: %s\n' "$(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null)"
printf 'own cgroup: %s\n' "$(cat /proc/self/cgroup)"
uid=$(id -u)
d=/sys/fs/cgroup/user.slice/user-$uid.slice/user@$uid.service
[ -r "$d/cgroup.subtree_control" ] && printf 'delegated to user@%s: %s\n' "$uid" "$(cat "$d/cgroup.subtree_control")"

section seccomp
grep -E '^(Seccomp|NoNewPrivs)' /proc/self/status

section tools
for t in go runsc nft ip unshare firecracker; do
  printf '%-12s %s\n' "$t" "$(command -v "$t" || echo absent)"
done
