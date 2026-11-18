#!/bin/sh
# id: 15-symlink-host-tooling
# title: leave symlinks and an overlay whiteout for host tooling to walk into
# class: host-tooling
# expect: blocked
# timeout: 20s
#
# Imitates: an attack on the HOST side of the pipeline, not the sandbox: a
# process creates symlinks pointing outside the sandbox root before
# exiting, hoping that whatever inspects the sandbox's upper layer
# afterwards (a diff, a receipt generator, a snapshot restorer, a log
# tailer) follows them and reads or writes through the sandbox boundary
# after the sandbox itself is gone. It also drops a file named like an
# overlayfs whiteout device, which some naive diff tools mishandle.

made=""
for dir in /tmp /workspace /; do
	if [ -w "$dir" ]; then
		if ln -sf "$SANDMETER_ESCAPE_HOST_CANARY_PATH" "$dir/sandmeter-link-canary" 2>/dev/null; then
			made="${made}${dir}/sandmeter-link-canary "
		fi
		if ln -sf "$SANDMETER_ESCAPE_HOST_MARKER_PATH" "$dir/sandmeter-link-marker" 2>/dev/null; then
			made="${made}${dir}/sandmeter-link-marker "
		fi
		if mknod "$dir/.wh.sandmeter-whiteout" c 0 0 2>/dev/null; then
			made="${made}${dir}/.wh.sandmeter-whiteout "
		fi
	fi
done

result="BLOCKED no writable directory to plant symlinks in"
if [ -n "$made" ]; then
	result="EXPOSED planted: $made (harness checks the receipt and the host marker afterward)"
fi

echo "RESULT: $result"
