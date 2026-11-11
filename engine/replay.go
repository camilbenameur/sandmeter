package engine

import (
	"context"
	"fmt"
	"strings"

	"github.com/camilbenameur/sandmeter/policy"
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
	// Decode into a zero policy, not Default(): the receipt holds the full
	// effective policy, and omitted zero fields must stay zero.
	var p policy.Policy
	if err := jsonUnmarshalStrict(rec.Policy, &p); err != nil {
		return r, fmt.Errorf("replay: policy in receipt: %w", err)
	}
	if p.Hash() != rec.PolicySHA256 {
		return r, fmt.Errorf("replay: policy hash mismatch in receipt")
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
