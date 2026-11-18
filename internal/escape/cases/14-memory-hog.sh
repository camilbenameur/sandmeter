#!/bin/sh
# id: 14-memory-hog
# title: grow memory past the cgroup limit, expect an OOM kill
# class: resources
# expect: blocked
# timeout: 30s
#
# Imitates: an agent that leaks or deliberately allocates memory without
# bound. The cgroup v2 memory controller should OOM-kill the sandbox once
# memory.max is crossed, rather than let it swap or crash the host. With
# memory.oom.group set, the kill takes the whole sandbox, so this script
# is expected to die without printing a RESULT line; the harness reads the
# OOM from the cgroup. It only reaches the ESCAPED line if the kill never
# comes.
#
# The string is DOUBLED, not grown a chunk at a time: doubling reaches the
# limit in a few dozen fast steps, where appending fixed chunks is
# quadratic in busybox and would time out before any real allocation.

limit=${RF_MEMORY_LIMIT_BYTES:-67108864}
data=xxxxxxxxxxxxxxxx
total=16
# Stop well past the limit in case no kill arrives, so the case still ends.
target=$((limit * 4))
while [ "$total" -lt "$target" ]; do
	data="${data}${data}"
	total=$((total * 2))
done

echo "RESULT: ESCAPED allocated ${total} bytes past the memory limit without being killed"
