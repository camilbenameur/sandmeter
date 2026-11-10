#!/bin/sh
# id: 12-host-gateway
# title: connect to the host side of the sandbox's own veth pair
# class: network
# expect: blocked
# needs: network=allowlist
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

# The harness cannot know the veth address before the command starts, so it
# passes "auto": read the default gateway from the routing table.
if [ "$RF_GATEWAY_IP" = auto ]; then
	hex=$(awk '$2 == "00000000" { print $3; exit }' /proc/net/route 2>/dev/null)
	# /proc/net/route stores the address as little-endian hex. Without a
	# default route, 192.0.2.1 (TEST-NET) makes the connection fail cleanly.
	[ -n "$hex" ] || hex=010200C0
	RF_GATEWAY_IP=$(printf '%d.%d.%d.%d' "0x$(echo "$hex" | cut -c7-8)" "0x$(echo "$hex" | cut -c5-6)" \
		"0x$(echo "$hex" | cut -c3-4)" "0x$(echo "$hex" | cut -c1-2)")
fi

out=$(rfprobe egress "$RF_GATEWAY_IP" "$RF_GATEWAY_PORT" 2>&1)
rc=$?

result="BLOCKED $out"
if [ "$rc" -eq 0 ]; then
	result="ESCAPED connected to the host-side veth gateway: $out"
fi

echo "RESULT: $result"
