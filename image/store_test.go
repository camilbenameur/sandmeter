package image

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func tarLayer(t *testing.T, ents ...ent) v1.Layer {
	t.Helper()
	b, err := io.ReadAll(buildTar(t, ents...))
	if err != nil {
		t.Fatal(err)
	}
	l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(b)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// pushTestImage serves a two-layer image from an in-process registry and
// returns its reference. The second layer deletes a file from the first.
func pushTestImage(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)

	img, err := mutate.AppendLayers(empty.Image,
		tarLayer(t, fileE("etc/os", "one", 0o644), fileE("etc/old", "old", 0o644)),
		tarLayer(t, fileE("etc/os", "two", 0o644), fileE("etc/.wh.old", "", 0o644)),
	)
	if err != nil {
		t.Fatal(err)
	}
	img, err = mutate.Config(img, v1.Config{
		Env:        []string{"A=1"},
		Entrypoint: []string{"/bin/sh"},
		Cmd:        []string{"-c", "true"},
		WorkingDir: "/work",
		User:       "1000",
	})
	if err != nil {
		t.Fatal(err)
	}
	ref := strings.TrimPrefix(srv.URL, "http://") + "/test/img:v1"
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(r, img); err != nil {
		t.Fatalf("push: %v", err)
	}
	return ref
}

func TestPullAndLoad(t *testing.T) {
	ref := pushTestImage(t)
	s := &Store{Root: t.TempDir()}

	img, err := s.Pull(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(img.Layers) != 2 || !strings.HasPrefix(img.Digest, "sha256:") || !strings.HasPrefix(img.Platform, "linux/") {
		t.Fatalf("image = %+v", img)
	}
	if img.Config.WorkingDir != "/work" || img.Config.User != "1000" || img.Config.Entrypoint[0] != "/bin/sh" || img.Config.Env[0] != "A=1" {
		t.Fatalf("config = %+v", img.Config)
	}
	for _, d := range img.Layers {
		if !filepath.IsAbs(d) {
			t.Fatalf("layer dir %q is not absolute", d)
		}
	}
	if got := readFile(t, filepath.Join(img.Layers[0], "etc/os")); got != "one" {
		t.Fatalf("bottom layer content = %q", got)
	}
	if got := readFile(t, filepath.Join(img.Layers[1], "etc/os")); got != "two" {
		t.Fatalf("top layer content = %q", got)
	}
	if os.Geteuid() != 0 {
		// Unprivileged pulls record whiteouts in the marker instead.
		m, err := s.readMarker(img.Layers[1])
		if err != nil || len(m.WhiteoutPaths) != 1 || m.WhiteoutPaths[0] != "etc/old" {
			t.Fatalf("marker = %+v, err %v", m, err)
		}
	}

	byRef, err := s.Load(ref)
	if err != nil {
		t.Fatal(err)
	}
	byDigest, err := s.Load("example.invalid/whatever@" + img.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if byRef.Digest != img.Digest || byDigest.Digest != img.Digest || len(byRef.Layers) != 2 {
		t.Fatalf("Load mismatch: %+v / %+v", byRef, byDigest)
	}
}

func TestPullReusesLayers(t *testing.T) {
	ref := pushTestImage(t)
	s := &Store{Root: t.TempDir()}
	img, err := s.Pull(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	// A file added to a cached layer survives a second pull only if the layer
	// was not extracted again.
	sentinel := filepath.Join(img.Layers[0], "sentinel")
	if err := os.WriteFile(sentinel, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pull(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("cached layer was extracted again: %v", err)
	}
	left, _ := filepath.Glob(filepath.Join(s.layersDir(), "*.tmp-*"))
	if len(left) != 0 {
		t.Fatalf("temp dirs left behind: %v", left)
	}
}

func TestPullReextractsIncompleteLayer(t *testing.T) {
	ref := pushTestImage(t)
	s := &Store{Root: t.TempDir()}
	img, err := s.Pull(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a crash between the rename and the marker write.
	if err := os.Remove(img.Layers[0] + ".complete"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ref); err == nil {
		t.Fatal("Load accepted a layer without its marker")
	}
	if _, err := s.Pull(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ref); err != nil {
		t.Fatalf("Load after repair: %v", err)
	}
}

func TestLoadErrors(t *testing.T) {
	s := &Store{Root: t.TempDir()}
	if _, err := s.Load("nope:latest"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("unknown ref: %v", err)
	}
	if _, err := s.Load("x@sha256:../../etc/passwd"); err == nil {
		t.Fatal("bad digest accepted")
	}
	ref := pushTestImage(t)
	img, err := s.Pull(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(img.Layers[1]); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ref); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing layer: %v", err)
	}
}

// lyingLayer reports a DiffID that its content does not have.
type lyingLayer struct {
	v1.Layer
	id v1.Hash
}

func (l lyingLayer) DiffID() (v1.Hash, error) { return l.id, nil }

func TestEnsureLayerRejectsDiffIDMismatch(t *testing.T) {
	good := tarLayer(t, fileE("a", "x", 0o644))
	other := tarLayer(t, fileE("a", "evil", 0o644))
	id, err := good.DiffID()
	if err != nil {
		t.Fatal(err)
	}
	s := &Store{Root: t.TempDir()}
	_, err = s.ensureLayer(context.Background(), lyingLayer{Layer: other, id: id})
	if err == nil || !strings.Contains(err.Error(), "diff id") {
		t.Fatalf("mismatch accepted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.layersDir(), id.Hex)); !os.IsNotExist(err) {
		t.Fatalf("poisoned layer installed: %v", err)
	}
	if _, err := s.ensureLayer(context.Background(), good); err != nil {
		t.Fatalf("good layer: %v", err)
	}
}

func TestEnsureLayerKeepsFinishedLayer(t *testing.T) {
	l := tarLayer(t, fileE("a", "x", 0o644))
	s := &Store{Root: t.TempDir()}
	dir, err := s.ensureLayer(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	// A pull that decided to extract before the first one finished must
	// not replace the finished tree.
	marker := filepath.Join(dir, "sentinel")
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if err := s.install(tmp, dir, ExtractStats{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("finished layer was replaced: %v", err)
	}
}

func TestReusableNeedsDirectory(t *testing.T) {
	l := tarLayer(t, fileE("a", "x", 0o644))
	s := &Store{Root: t.TempDir()}
	dir, err := s.ensureLayer(context.Background(), l)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if s.reusable(dir) {
		t.Fatal("marker without directory reported reusable")
	}
}
