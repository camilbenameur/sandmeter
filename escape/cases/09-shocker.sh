#!/bin/sh
# id: 09-shocker
# title: open_by_handle_at the handle of the sandbox's own root
# class: filesystem
# expect: blocked
# timeout: 20s
#
# Imitates: "Shocker", the 2014 Docker breakout that used
# open_by_handle_at with a brute-forced file handle to open host inodes
# bypassing mount namespace checks, because at the time the handle lookup
# only checked a capability, not whether the target was reachable through
# the caller's own mount tree. This case only checks whether the
# primitive itself (CAP_DAC_READ_SEARCH plus open_by_handle_at) is
# reachable; it does not attempt the full brute force.

out=$(rfprobe shocker 2>&1)
rc=$?

result="BLOCKED $out"
if [ "$rc" -eq 0 ]; then
	result="EXPOSED open_by_handle_at primitive reachable: $out"
fi

echo "RESULT: $result"
