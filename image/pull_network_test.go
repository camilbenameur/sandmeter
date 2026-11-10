//go:build network

package image

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// busybox:1.37 multi-arch index, pinned so the test does not drift.
const busyboxRef = "docker.io/library/busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec"

func TestPullBusybox(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	s := &Store{Root: t.TempDir()}
	img, err := s.Pull(ctx, busyboxRef)
	if err != nil {
		t.Fatal(err)
	}
	if len(img.Layers) == 0 {
		t.Fatal("no layers")
	}
	// Pull picks WhiteoutRecord without root, so this works unprivileged.
	fi, err := os.Lstat(filepath.Join(img.Layers[len(img.Layers)-1], "bin/busybox"))
	if err != nil {
		t.Fatalf("bin/busybox: %v", err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		t.Fatalf("bin/busybox mode = %v", fi.Mode())
	}
	if _, err := s.Load(busyboxRef); err != nil {
		t.Fatalf("Load: %v", err)
	}
}
