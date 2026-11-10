#!/bin/sh
# id: 05-sysfs-rw
# title: remount /sys read-write and write a uevent helper
# class: filesystem
# expect: blocked
# timeout: 20s
#
# Imitates: an escape that remounts a read-only /sys from inside the
# sandbox to reach knobs normally hidden from it, such as the deprecated
# /sys/kernel/uevent_helper hook that once let an unprivileged writer run
# an arbitrary host binary on every uevent. The write here puts back the
# same (usually empty) value it read, so it is harmless even if it does
# reach the host.

# Remember whether /sys was read-only, so that it is only put back if this
# script changed it: if the sandbox shares the host's mount, flipping an
# already-writable /sys to read-only would be a change to the host.
was_ro=0
if awk '$2 == "/sys" {print $4}' /proc/self/mounts 2>/dev/null | grep -qE '(^|,)ro(,|$)'; then
	was_ro=1
fi

result="BLOCKED /sys stayed read-only"

if mount -o remount,rw /sys 2>/dev/null; then
	uh=/sys/kernel/uevent_helper
	if [ -w "$uh" ]; then
		old=$(cat "$uh" 2>/dev/null)
		if echo "$old" >"$uh" 2>/dev/null; then
			result="EXPOSED remounted /sys rw and wrote uevent_helper"
		else
			result="EXPOSED remounted /sys rw, uevent_helper write refused"
		fi
	else
		result="EXPOSED remounted /sys rw, uevent_helper absent or read-only"
	fi
	if [ "$was_ro" -eq 1 ]; then
		mount -o remount,ro /sys 2>/dev/null
	fi
fi

echo "RESULT: $result"
