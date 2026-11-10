#!/bin/sh
# id: 04-proc-sys-write
# title: write to /proc/sys/kernel/core_pattern and hostname
# class: kernel-surface
# expect: blocked
# timeout: 20s
#
# Imitates: a container escape that rewrites core_pattern to a pipe to an
# attacker script (the kernel runs core_pattern as the host, with host
# root), one of the most common real-world breakout primitives. This case
# only writes back the value it just read, or leaves hostname unchanged in
# effect; the harness compares the host's own value before and after to
# see whether the write actually reached the host, not just the sandbox's
# own namespaced view.

changed=""

cp_path=/proc/sys/kernel/core_pattern
if [ -r "$cp_path" ] && [ -w "$cp_path" ]; then
	old=$(cat "$cp_path" 2>/dev/null)
	if echo "$old" >"$cp_path" 2>/dev/null; then
		changed="core_pattern writable"
	fi
fi

hn_path=/proc/sys/kernel/hostname
if [ -r "$hn_path" ] && [ -w "$hn_path" ]; then
	oldhn=$(cat "$hn_path" 2>/dev/null)
	if echo "$oldhn" >"$hn_path" 2>/dev/null; then
		changed="${changed:+$changed, }hostname writable"
	fi
fi

result="BLOCKED proc/sys entries are read-only or properly namespaced"
if [ -n "$changed" ]; then
	result="EXPOSED $changed (harness checks whether the host's own value moved)"
fi

echo "RESULT: $result"
