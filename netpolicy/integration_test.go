//go:build integration

package netpolicy

import (
	"bytes"
	"context"
	"os"
	"testing"
)

func needRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, _, err := runNft(context.Background(), "", "--version"); err != nil {
		t.Skip("nft not available")
	}
	// Root without CAP_NET_ADMIN (unprivileged container) fails on netlink.
	if _, stderr, err := runNft(context.Background(), "", "list", "tables"); err != nil &&
		bytes.Contains(stderr, []byte("Operation not permitted")) {
		t.Skip("no CAP_NET_ADMIN")
	}
}

// Every golden script must pass the kernel-side check, which also catches
// syntax that only the real parser rejects.
func TestGoldenScriptsCheck(t *testing.T) {
	needRoot(t)
	for name, plan := range goldenPlans(t) {
		t.Run(name, func(t *testing.T) {
			script, err := Ruleset(plan)
			if err != nil {
				t.Fatal(err)
			}
			if err := Check(context.Background(), script); err != nil {
				t.Fatalf("%v\n%s", err, script)
			}
		})
	}
}

// The interface does not need to exist: iifname/oifname match by name only,
// so a dummy name lets the table load without creating a veth.
func TestApplyAttemptsDelete(t *testing.T) {
	needRoot(t)
	ctx := context.Background()
	plan := goldenPlans(t)["one"]
	plan.Table = "sandmeter_itest"
	plan.HostIface = "rfdummy0"
	script, err := Ruleset(plan)
	if err != nil {
		t.Fatal(err)
	}
	_ = Delete(ctx, plan.Table)
	if err := Apply(ctx, script); err != nil {
		t.Fatal(err)
	}
	defer Delete(ctx, plan.Table) //nolint:errcheck
	conns, err := Attempts(ctx, plan.Table)
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != 0 {
		t.Errorf("fresh table should have no attempts, got %+v", conns)
	}
	if _, _, err := ForwardBlockedByOthers(ctx); err != nil {
		t.Errorf("ForwardBlockedByOthers: %v", err)
	}
	if err := Delete(ctx, plan.Table); err != nil {
		t.Fatal(err)
	}
	if err := Delete(ctx, plan.Table); err != nil {
		t.Errorf("second delete must be a no-op: %v", err)
	}
}
