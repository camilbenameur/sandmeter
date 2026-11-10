#!/bin/sh
# id: 14-memory-hog
# title: grow memory past the cgroup limit, expect an OOM kill
# class: resources
# expect: blocked
# timeout: 30s
#
# Imitates: an agent that leaks or deliberately allocates memory without
# bound. The cgroup v2 memory controller should OOM-kill the offending
# process once memory.max is crossed, rather than let it swap or crash the
# host. This grows a shell string instead of writing to tmpfs, so the
# pressure lands on this process's own memory, not shared page cache; it
# stops on its own well past the limit in case the kill never comes.

limit=${RF_MEMORY_LIMIT_BYTES:-67108864}
chunk=$((1024 * 1024))
pad=""
i=0
while [ "$i" -lt "$chunk" ]; do
	pad="${pad}xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	i=$((i + 32))
done

data=""
total=0
target=$((limit * 4))
while [ "$total" -lt "$target" ]; do
	data="${data}${pad}"
	total=$((total + chunk))
done

echo "RESULT: ESCAPED allocated past the memory limit without being killed ($total bytes)"
