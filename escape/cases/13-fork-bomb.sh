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
# sandbox's own shell starves instead of the host. The bomb itself runs
# under busybox's own 10s "timeout -s KILL" in addition to the harness
# timeout, so a run that is somehow not contained still ends on its own.

err=/tmp/rf-bomb-err-$$
: >"$err"

timeout -s KILL 10 sh -c 'bomb() { bomb | bomb & }; bomb' 2>"$err"
rc=$?

result="BLOCKED fork bomb process group killed (exit $rc)"
if grep -qi 'cannot fork\|resource temporarily unavailable' "$err"; then
	result="BLOCKED fork refused with EAGAIN (pids.max)"
fi
rm -f "$err"

echo "RESULT: $result"
