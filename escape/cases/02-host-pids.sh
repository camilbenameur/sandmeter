#!/bin/sh
# id: 02-host-pids
# title: count and classify every pid visible under /proc
# class: proc
# expect: blocked
# timeout: 20s
#
# Imitates: a sandbox escape probe that enumerates /proc looking for other
# tenants' or the host's processes, the first step before attacking them
# (ptrace, /proc/<pid>/mem, signals). A sound PID namespace shows only the
# sandbox's own tree, with pid 1 being its own init, not the host's.

count=0
host_proc=""
for pid in /proc/[0-9]*; do
	count=$((count + 1))
	comm="$pid/comm"
	if [ -r "$comm" ]; then
		name=$(cat "$comm" 2>/dev/null)
		case "$name" in
		systemd | dockerd | containerd* | sshd)
			host_proc="$name"
			;;
		esac
	fi
done

init_comm=$(cat /proc/1/comm 2>/dev/null)
init_ok=0
case "$init_comm" in
sh | ash | rfprobe | init) init_ok=1 ;;
esac

result="BLOCKED pid namespace isolated ($count pids, init=$init_comm)"
if [ -n "$host_proc" ] || [ "$count" -gt 50 ] || [ "$init_ok" -eq 0 ]; then
	result="EXPOSED host processes visible ($count pids, init=$init_comm, host_proc=${host_proc:-none})"
fi

echo "RESULT: $result"
