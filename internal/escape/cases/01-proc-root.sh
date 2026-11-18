#!/bin/sh
# id: 01-proc-root
# title: read the host canary through /proc/<pid>/root and /proc/<pid>/cwd
# class: proc
# expect: blocked
# timeout: 20s
#
# Imitates: a container escape that walks /proc/<pid>/root (or /cwd) of a
# process whose mount or chroot namespace differs from the caller's, using
# the kernel's per-process root/cwd symlinks as a bind back into the host
# filesystem (the classic "procfs root escape" used against misconfigured
# chroots and some older container runtimes).

result="BLOCKED no path reached the host canary"
found=""

# Try the direct path first: if RF_HOST_CANARY_PATH is visible at all from
# inside the sandbox, isolation already failed before any /proc trick.
if [ -n "$RF_HOST_CANARY_PATH" ] && [ -r "$RF_HOST_CANARY_PATH" ]; then
	found=$(cat "$RF_HOST_CANARY_PATH" 2>/dev/null)
fi

if [ -z "$found" ]; then
	for pid in /proc/[0-9]*; do
		for leaf in root cwd; do
			p="$pid/$leaf$RF_HOST_CANARY_PATH"
			if [ -r "$p" ]; then
				tok=$(cat "$p" 2>/dev/null)
				if [ -n "$tok" ]; then
					found="$tok"
					break 2
				fi
			fi
		done
	done
fi

if [ -n "$found" ]; then
	result="ESCAPED read host canary via proc: $found"
fi

echo "RESULT: $result"
