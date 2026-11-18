#!/bin/sh
# id: 10-egress-none
# title: connect out while the policy says network=none
# class: network
# expect: blocked
# needs: network=none
# timeout: 20s
#
# Imitates: a sandboxed agent trying to exfiltrate data or fetch a second
# stage payload even though its policy grants no network at all. A sound
# "none" mode gives only loopback, so this connection attempt must fail at
# the kernel (no route, no veth) rather than be allowed and merely logged.

command -v sandmeter-probe >/dev/null 2>&1 || { echo "sandmeter-probe missing from the sandbox rootfs" >&2; exit 2; }
[ -n "${SANDMETER_ESCAPE_EGRESS_IP:-}" ] || { echo "SANDMETER_ESCAPE_EGRESS_IP not set by the harness" >&2; exit 2; }
[ -n "${SANDMETER_ESCAPE_EGRESS_PORT:-}" ] || { echo "SANDMETER_ESCAPE_EGRESS_PORT not set by the harness" >&2; exit 2; }

out=$(sandmeter-probe egress "$SANDMETER_ESCAPE_EGRESS_IP" "$SANDMETER_ESCAPE_EGRESS_PORT" 2>&1)
rc=$?

result="BLOCKED $out"
if [ "$rc" -eq 0 ]; then
	result="ESCAPED connected to egress listener with network=none: $out"
fi

echo "RESULT: $result"
