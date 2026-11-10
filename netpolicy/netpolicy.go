// Package netpolicy builds the per-sandbox egress firewall and the addressing
// of the veth pair that connects a sandbox to the host.
//
// Generating the nftables script (Ruleset) is pure and unit-tested. Applying
// it shells out to the nft binary and needs CAP_NET_ADMIN.
//
// Design and limits, in short:
//
//   - Every rule is scoped to the host-side veth (iifname/oifname), so the
//     table never touches other traffic on the host.
//   - The sandbox gets IPv4 only. IPv6 from the veth is dropped, and names
//     are resolved to A records only.
//   - There is no DNS inside the sandbox. Names in the allowlist are resolved
//     once on the host and handed to the sandbox as /etc/hosts lines. The
//     allowlist is IP-based from then on: a name whose address changes later
//     is not followed, and an address shared by many sites (a CDN) allows
//     every site on it.
//   - The sandbox cannot reach any service on the host, including the veth
//     gateway address: the input hook drops everything from the veth.
//   - New tcp, udp and other IPv4 flows are recorded, best effort, in dynamic
//     sets split into allowed and denied, so a run receipt can list what the
//     sandbox tried (Attempts). Each set holds at most 4096 entries: a sandbox
//     that scans more distinct destinations fills it and later attempts go
//     unrecorded, though they are still dropped. IPv6 is dropped unrecorded.
//   - Packets from the veth with a source other than the sandbox address are
//     dropped, so a sandbox cannot spoof another address.
//
// Caveat: another table at the same hook can still drop what we accept. An
// accept verdict only ends our own chain. Docker, for one, sets the iptables
// FORWARD policy to DROP, which shows up as a forward base chain with policy
// drop in another nft table. Callers should check ForwardBlockedByOthers and
// CheckForwarding before relying on the allowlist, because a blocked path
// fails closed (the sandbox just cannot connect) but looks like a bug.
package netpolicy

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

var (
	tableRE = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
	// 15 is IFNAMSIZ-1; the character set avoids anything nft would need to quote.
	ifaceRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,15}$`)
)

// runNft runs nft with stdin and returns stdout and stderr. It is a variable
// so tests can replace the binary.
var runNft = func(ctx context.Context, stdin string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, "nft", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	return out.Bytes(), errb.Bytes(), err
}

// nftError wraps a failed nft call with its stderr, which is where the
// useful message is.
func nftError(what string, stderr []byte, err error) error {
	msg := strings.TrimSpace(string(stderr))
	if msg == "" {
		return fmt.Errorf("%s: %w", what, err)
	}
	return fmt.Errorf("%s: %w: %s", what, err, msg)
}

// Apply loads a script produced by Ruleset with "nft -f -". The load is
// atomic: nft applies the whole script or none of it.
func Apply(ctx context.Context, script string) error {
	_, stderr, err := runNft(ctx, script, "-f", "-")
	if err != nil {
		return nftError("nft -f -", stderr, err)
	}
	return nil
}

// Check validates a script with "nft -c -f -" without loading it. nft still
// opens a netlink socket for this, so it usually needs privileges.
func Check(ctx context.Context, script string) error {
	_, stderr, err := runNft(ctx, script, "-c", "-f", "-")
	if err != nil {
		return nftError("nft -c -f -", stderr, err)
	}
	return nil
}

// Delete removes the table and everything in it. A table that is already
// gone is not an error, so cleanup can be called twice.
func Delete(ctx context.Context, table string) error {
	if !tableRE.MatchString(table) {
		return fmt.Errorf("invalid table name %q", table)
	}
	_, stderr, err := runNft(ctx, "", "delete", "table", "inet", table)
	if err != nil {
		if bytes.Contains(stderr, []byte("No such file")) {
			return nil
		}
		return nftError("nft delete table", stderr, err)
	}
	return nil
}
