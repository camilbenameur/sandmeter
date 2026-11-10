#!/bin/sh
# id: 08-kernel-surface
# title: probe a batch of syscalls that are easy to forget in a seccomp filter
# class: kernel-surface
# expect: blocked
# timeout: 20s
#
# Imitates: an attacker fuzzing the syscall surface left open by a seccomp
# profile, looking for anything with a CVE history (bpf, keyctl, io_uring,
# perf_event_open, userfaultfd) or that reopens isolation already dropped
# (unshare(CLONE_NEWUSER), mount, ptrace(PTRACE_TRACEME)). Each hit is
# EXPOSED, not ESCAPED: reaching the syscall is a wider attack surface
# than a minimal filter would leave, not a host compromise by itself.

command -v rfprobe >/dev/null 2>&1 || { echo "rfprobe missing from the sandbox rootfs" >&2; exit 2; }

out=$(rfprobe syscalls 2>&1) || { echo "rfprobe syscalls failed: $out" >&2; exit 2; }
reachable=$(echo "$out" | grep -c ' reachable')

result="BLOCKED no probed syscall was reachable"
if [ "$reachable" -gt 0 ]; then
	list=$(echo "$out" | grep ' reachable' | tr '\n' ';')
	result="EXPOSED $reachable syscall(s) reachable: $list"
fi

echo "RESULT: $result"
