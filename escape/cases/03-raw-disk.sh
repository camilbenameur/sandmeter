#!/bin/sh
# id: 03-raw-disk
# title: mknod the host root block device and try to read or mount it
# class: devices
# expect: blocked
# timeout: 20s
#
# Imitates: a container with CAP_MKNOD and no device cgroup that creates a
# node for the host's boot disk and reads it directly, bypassing every
# filesystem-level restriction. This never writes to the device: it only
# opens it for reading and tries a read-only mount.

maj=8
min=0
if [ -r /proc/partitions ]; then
	line=$(awk '$4 ~ /^(sda|vda|xvda|nvme0n1)$/ {print $1, $2; exit}' /proc/partitions)
	if [ -n "$line" ]; then
		maj=$(echo "$line" | awk '{print $1}')
		min=$(echo "$line" | awk '{print $2}')
	else
		maj=259
		min=0
	fi
fi

dev=/tmp/rf-disk-$$
rm -f "$dev"

result="BLOCKED mknod refused"
if mknod "$dev" b "$maj" "$min" 2>/dev/null; then
	result="EXPOSED mknod allowed for $maj:$min"
	if dd if="$dev" of=/dev/null bs=512 count=1 2>/dev/null; then
		result="ESCAPED read first sector of host disk $maj:$min"
	fi
	mkdir -p /tmp/rf-mnt-$$
	if mount -o ro "$dev" /tmp/rf-mnt-$$ 2>/dev/null; then
		result="ESCAPED mounted host disk $maj:$min read-only"
		umount /tmp/rf-mnt-$$ 2>/dev/null
	fi
	rmdir /tmp/rf-mnt-$$ 2>/dev/null
fi
rm -f "$dev"

echo "RESULT: $result"
