#!/bin/sh
# id: 12-host-gateway
# title: connect to the host side of the sandbox's own veth pair
# class: network
# expect: blocked
# timeout: 20s
#
# Imitates: a sandbox that discovers its default route points at a veth
# peer living on the host, and tries to talk to whatever is listening
# there directly, instead of going through the intended egress path. Even
# a sandbox with network=none should not be able to reach a service bound
# to the host-side veth address, since that address exists only for the
# harness's own bookkeeping.

command -v rfprobe >/dev/null 2>&1 || { echo "rfprobe missing from the sandbox rootfs" >&2; exit 2; }
[ -n "${RF_GATEWAY_IP:-}" ] || { echo "RF_GATEWAY_IP not set by the harness" >&2; exit 2; }
[ -n "${RF_GATEWAY_PORT:-}" ] || { echo "RF_GATEWAY_PORT not set by the harness" >&2; exit 2; }

out=$(rfprobe egress "$RF_GATEWAY_IP" "$RF_GATEWAY_PORT" 2>&1)
rc=$?

result="BLOCKED $out"
if [ "$rc" -eq 0 ]; then
	result="ESCAPED connected to the host-side veth gateway: $out"
fi

echo "RESULT: $result"
