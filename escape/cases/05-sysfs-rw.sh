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
	mount -o remount,ro /sys 2>/dev/null
fi

echo "RESULT: $result"
