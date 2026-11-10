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

out=$(rfprobe egress "$RF_EGRESS_IP" "$RF_EGRESS_PORT" 2>&1)
rc=$?

result="BLOCKED $out"
if [ "$rc" -eq 0 ]; then
	result="ESCAPED connected to egress listener with network=none: $out"
fi

echo "RESULT: $result"
