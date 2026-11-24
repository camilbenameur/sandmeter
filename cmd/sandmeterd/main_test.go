package main

import (
	"strings"
	"testing"
)

// TestSkeletonSaysItIsNotBuilt goes with the skeleton of the command line:
// until the service is written, every visible command fails and says why.
func TestSkeletonSaysItIsNotBuilt(t *testing.T) {
	var stderr strings.Builder
	code := run([]string{"serve"}, &stderr)
	if !strings.Contains(stderr.String(), "not built in this version") {
		t.Skipf("the command line is built: this test goes with the skeleton (exit %d)", code)
	}
	if code == 0 {
		t.Error("a command that is not built exits with success")
	}
}
