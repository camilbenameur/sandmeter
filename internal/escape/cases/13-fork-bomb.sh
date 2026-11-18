#!/bin/sh
# id: 13-fork-bomb
# title: bounded fork bomb, must be stopped by pids.max
# class: resources
# expect: blocked
# timeout: 15s
#
# Imitates: a runaway or malicious agent that forks without bound, the
# simplest denial-of-service against a shared host. A cgroup v2 pids
# controller should turn every fork past the limit into EAGAIN, so the
# sandbox's own shell starves instead of the host.
#
# The bomb is bounded twice, because busybox "timeout" only signals its
# direct child and would leave a forking tree behind: it has a depth limit
# (at the deepest level each process just sleeps, to hold its pid), and it
# runs in its own process group, which a killer started beforehand kills
# after 10s. The killer is started first because once pids.max is hit
# nothing new can be forked, not even a "sleep".

err=/tmp/rf-bomb-err-$$
pidfile=/tmp/rf-bomb-pid-$$
: >"$err"
: >"$pidfile"

(
	sleep 10
	read -r pgid <"$pidfile"
	[ -n "$pgid" ] && kill -KILL -- "-$pgid" 2>/dev/null
) &
killer=$!

setsid sh -c '
	echo $$ >"$1"
	bomb() {
		d=$1
		if [ "$d" -ge 10 ]; then
			exec sleep 8
		fi
		bomb $((d + 1)) | bomb $((d + 1)) &
	}
	bomb 0
' sh "$pidfile" 2>"$err" &

wait "$killer" 2>/dev/null

# Detect the refusal with shell builtins only: once pids.max is hit, the
# script itself cannot fork an external tool such as grep, so matching the
# error file is done with read and case, which need no new process.
result="EXPOSED no fork was refused: pids.max may not have been enforced"
while IFS= read -r line; do
	case "$line" in
	*"can't fork"* | *"cannot fork"* | *[Rr]"esource temporarily unavailable"*)
		result="BLOCKED fork refused with EAGAIN (pids.max)"
		break
		;;
	esac
done <"$err"
rm -f "$err" "$pidfile" 2>/dev/null

echo "RESULT: $result"
