package engine

import (
	"context"
	"fmt"
	"strings"

	"github.com/camilbenameur/sandmeter/internal/prototype/policy"
	"github.com/camilbenameur/sandmeter/receipt"
)

// ReplayReport compares a fresh run with a recorded receipt.
type ReplayReport struct {
	Original    receipt.Receipt
	Replayed    receipt.Receipt
	ReceiptPath string
	SameExit    bool
	SameDiff    bool
	SameStdout  bool
	// Differences lists every field that differs, in plain words.
	Differences []string
}

// Replay runs the receipt's command again on the same image digest, with
// the same policy and backend, on a fresh sandbox, and compares the exit
// code, the stdout hash and the diff hash. It does not compare timings,
// connections or cgroup counters, which vary between runs. A replay only
// makes sense for commands that start from the image (diff base "image").
func (e *Engine) Replay(ctx context.Context, rec receipt.Receipt) (ReplayReport, error) {
	r := ReplayReport{Original: rec}
	p, err := replayPolicy(rec)
	if err != nil {
		return r, err
	}
	ref := pinnedRef(rec.Image.Ref, rec.Image.Digest)
	s, err := e.Start(ctx, rec.Backend, ref, p)
	if err != nil {
		return r, err
	}
	defer s.Stop(context.Background())
	if s.Image.Digest != rec.Image.Digest {
		return r, fmt.Errorf("replay: image digest %s, receipt has %s", s.Image.Digest, rec.Image.Digest)
	}
	out, err := s.Run(ctx, rec.Argv)
	if err != nil {
		return r, err
	}
	r.Replayed = out.Receipt
	r.ReceiptPath = out.ReceiptPath
	r.SameExit = out.Receipt.ExitCode == rec.ExitCode && out.Receipt.Killed == rec.Killed
	r.SameDiff = out.Receipt.Diff.SHA256 == rec.Diff.SHA256
	r.SameStdout = out.Receipt.StdoutSHA256 == rec.StdoutSHA256
	if !r.SameExit {
		r.Differences = append(r.Differences, fmt.Sprintf("exit %d/%q, recorded %d/%q",
			out.Receipt.ExitCode, out.Receipt.Killed, rec.ExitCode, rec.Killed))
	}
	if !r.SameDiff {
		r.Differences = append(r.Differences, fmt.Sprintf("diff %s (%d entries), recorded %s (%d entries)",
			short(out.Receipt.Diff.SHA256), len(out.Receipt.Diff.Entries), short(rec.Diff.SHA256), len(rec.Diff.Entries)))
	}
	if !r.SameStdout {
		r.Differences = append(r.Differences, "stdout differs")
	}
	return r, nil
}

// replayPolicy returns the policy a v1 receipt says its command ran under.
//
// The policy is decoded into the frozen v1 form by receipt.DecodePolicyV1,
// the one decoder of that form, starting from zero and not from Default():
// the receipt holds the full effective policy, and omitted zero fields must
// stay zero.
//
// The hash is checked on the policy bytes as they were signed, never on a
// struct encoded again. Encoding again answers "does the policy type of this
// build still marshal the way the build that signed did", and the first new
// policy field would then make every receipt written before fail here.
func replayPolicy(rec receipt.Receipt) (policy.Policy, error) {
	signed, err := receipt.DecodePolicyV1(rec.Policy)
	if err != nil {
		return policy.Policy{}, fmt.Errorf("replay: policy in receipt: %w", err)
	}
	if receipt.PolicyHashV1(rec.Policy) != rec.PolicySHA256 {
		return policy.Policy{}, fmt.Errorf("replay: policy hash mismatch in receipt")
	}
	return policyFromV1(signed), nil
}

// policyFromV1 and policyToV1 carry a policy between the form a v1 receipt
// signs and the policy type of this build. Each part is converted whole on
// purpose: when a part of policy.Policy gains, loses, renames or retypes a
// field, its conversion stops compiling. The declaration under the two
// functions does the same for the list of parts. Either way, what a v1
// receipt means for the new shape is then decided here rather than left to
// a zero value.

// policyFromV1 maps the policy of a v1 receipt onto the policy type of this
// build.
func policyFromV1(p receipt.PolicyV1) policy.Policy {
	return policy.Policy{
		Limits:     policy.Limits(p.Limits),
		Network:    policy.Network(p.Network),
		Filesystem: policy.Filesystem(p.Filesystem),
		Syscalls:   policy.Syscalls(p.Syscalls),
	}
}

// policyToV1 gives a policy the form a v1 receipt signs.
func policyToV1(p policy.Policy) receipt.PolicyV1 {
	return receipt.PolicyV1{
		Limits:     receipt.PolicyLimitsV1(p.Limits),
		Network:    receipt.PolicyNetworkV1(p.Network),
		Filesystem: receipt.PolicyFilesystemV1(p.Filesystem),
		Syscalls:   receipt.PolicySyscallsV1(p.Syscalls),
	}
}

// policy.Policy has exactly the parts the two functions above carry, in this
// order: the conversion does not compile otherwise. Their keyed literals
// would compile with a part added to policy.Policy. A replayed v1 receipt
// would then run with that part at its zero value, and a signed one would
// leave it out, without anyone having decided that this is what v1 means.
var _ = struct {
	Limits     policy.Limits
	Network    policy.Network
	Filesystem policy.Filesystem
	Syscalls   policy.Syscalls
}(policy.Policy{})

// pinnedRef turns "docker.io/library/alpine:3.20" and a digest into
// "docker.io/library/alpine@sha256:...", so the replay cannot get a newer image.
func pinnedRef(ref, digest string) string {
	if digest == "" {
		return ref
	}
	name := ref
	if i := strings.Index(name, "@"); i >= 0 {
		name = name[:i]
	}
	// Strip a tag, but not a registry port: the tag colon comes after the last slash.
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		name = name[:i]
	}
	return name + "@" + digest
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
