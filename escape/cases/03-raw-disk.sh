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

# Candidate major:minor pairs. When /proc/partitions is hidden (the normal
# case in a sound sandbox) try the usual host disk numbers for SCSI/SATA,
# NVMe and virtio, since a CI runner may use any of them.
cands=""
if [ -r /proc/partitions ]; then
	cands=$(awk '$4 ~ /^(sda|vda|xvda|nvme0n1)$/ {print $1 ":" $2}' /proc/partitions)
fi
[ -n "$cands" ] || cands="8:0 259:0 252:0 253:0"

dev=/tmp/rf-disk-$$
mnt=/tmp/rf-mnt-$$
result="BLOCKED mknod refused for: $(echo $cands)"

for c in $cands; do
	maj=${c%:*}
	min=${c#*:}
	rm -f "$dev"
	mknod "$dev" b "$maj" "$min" 2>/dev/null || continue

	result="EXPOSED mknod allowed for $maj:$min"
	if dd if="$dev" of=/dev/null bs=512 count=1 2>/dev/null; then
		result="ESCAPED read first sector of host disk $maj:$min"
	fi
	mkdir -p "$mnt"
	if mount -o ro "$dev" "$mnt" 2>/dev/null; then
		result="ESCAPED mounted host disk $maj:$min read-only"
		umount "$mnt" 2>/dev/null
	fi
	rmdir "$mnt" 2>/dev/null
	break
done
rm -f "$dev"

echo "RESULT: $result"
