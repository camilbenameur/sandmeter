#!/bin/sh
# id: 07-userns-mount
# title: regain capabilities in a nested user namespace, then mount tmpfs
# class: namespaces
# expect: blocked
# timeout: 20s
#
# Imitates: an unprivileged process that creates its own user namespace
# (unshare(CLONE_NEWUSER)), where it holds full capabilities by kernel
# definition (uid 0 inside maps to its own unprivileged uid outside), then
# uses that "fake root" to do something the outer sandbox would refuse,
# such as mounting a filesystem. The real risk is a kernel or sandbox that
# treats capabilities-in-a-userns as equivalent to capabilities on the host.

out=$(rfprobe userns-mount 2>&1)
rc=$?

result="BLOCKED $out"
if [ "$rc" -eq 0 ]; then
	result="EXPOSED unshare+mount succeeded in a nested user namespace: $out"
fi

echo "RESULT: $result"
