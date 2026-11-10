package image

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Store keeps pulled images on disk.
//
//	Root/layers/sha256/<diffid>/        one extracted layer, an overlayfs lower dir
//	Root/layers/sha256/<diffid>.complete  marker written after the layer is in place
//	Root/images/<manifest digest>.json  image metadata
//	Root/refs.json                      ref -> manifest digest
type Store struct {
	// Root is the store directory, such as /var/lib/ringfence.
	Root string
	// IDShift is the host uid/gid that container uid/gid 0 maps to. Files in
	// layers are owned by uid+IDShift and gid+IDShift. Zero means no shift.
	// A layer cached under one shift is not reused under another.
	IDShift uint32
}

// Image is a pulled image.
type Image struct {
	Ref      string `json:"ref"`
	Digest   string `json:"digest"`
	Platform string `json:"platform"`
	// Layers are absolute directories, bottom layer first.
	Layers []string `json:"layers"`
	Config Config   `json:"config"`
}

// Config is the part of the image config a sandbox needs to start a process.
type Config struct {
	Env        []string `json:"env,omitempty"`
	Entrypoint []string `json:"entrypoint,omitempty"`
	Cmd        []string `json:"cmd,omitempty"`
	WorkingDir string   `json:"working_dir,omitempty"`
	User       string   `json:"user,omitempty"`
}

// layerMarker is the content of a ".complete" file. It records how the layer
// was built so a later run can tell whether the cached copy is usable.
type layerMarker struct {
	IDShift       uint32   `json:"id_shift"`
	Overlay       bool     `json:"overlay_whiteouts"`
	WhiteoutPaths []string `json:"whiteouts,omitempty"`
	OpaquePaths   []string `json:"opaques,omitempty"`
}

// refsMu serializes refs.json updates inside one process. Across processes
// the atomic rename keeps the file valid, but concurrent updates can lose one.
var refsMu sync.Mutex

// Pull fetches ref for linux/<runtime.GOARCH> with anonymous auth and
// extracts any layer that is not cached yet.
func (s *Store) Pull(ctx context.Context, ref string) (Image, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return Image{}, fmt.Errorf("parse reference %q: %w", ref, err)
	}
	plat := v1.Platform{OS: "linux", Architecture: runtime.GOARCH}
	img, err := remote.Image(r,
		remote.WithContext(ctx),
		remote.WithAuth(authn.Anonymous),
		remote.WithPlatform(plat),
	)
	if err != nil {
		return Image{}, fmt.Errorf("fetch image %q: %w", ref, err)
	}
	digest, err := img.Digest()
	if err != nil {
		return Image{}, fmt.Errorf("image digest: %w", err)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		return Image{}, fmt.Errorf("image config: %w", err)
	}
	layers, err := img.Layers()
	if err != nil {
		return Image{}, fmt.Errorf("image layers: %w", err)
	}

	out := Image{
		Ref:      ref,
		Digest:   digest.String(),
		Platform: "linux/" + runtime.GOARCH,
		Config: Config{
			Env:        cfg.Config.Env,
			Entrypoint: cfg.Config.Entrypoint,
			Cmd:        cfg.Config.Cmd,
			WorkingDir: cfg.Config.WorkingDir,
			User:       cfg.Config.User,
		},
	}
	for i, l := range layers {
		dir, err := s.ensureLayer(ctx, l)
		if err != nil {
			return Image{}, fmt.Errorf("layer %d: %w", i, err)
		}
		out.Layers = append(out.Layers, dir)
	}
	if err := s.save(out); err != nil {
		return Image{}, err
	}
	return out, nil
}

// Load returns a previously pulled image without touching the network. ref is
// either a ref known to refs.json or a digest reference such as
// "name@sha256:...".
func (s *Store) Load(ref string) (Image, error) {
	hex, err := s.digestFor(ref)
	if err != nil {
		return Image{}, err
	}
	data, err := os.ReadFile(filepath.Join(s.Root, "images", hex+".json"))
	if err != nil {
		return Image{}, fmt.Errorf("read image metadata for %q: %w", ref, err)
	}
	var img Image
	if err := json.Unmarshal(data, &img); err != nil {
		return Image{}, fmt.Errorf("decode image metadata for %q: %w", ref, err)
	}
	for _, dir := range img.Layers {
		if !s.layerReady(dir) {
			return Image{}, fmt.Errorf("layer %s of %q is missing or incomplete; pull the image again", dir, ref)
		}
	}
	return img, nil
}

func (s *Store) digestFor(ref string) (string, error) {
	// refs.json goes first: a digest ref that names a multi-platform index
	// maps to the digest of the platform manifest that was actually pulled.
	refs, err := s.readRefs()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if d, ok := refs[ref]; ok {
		return validHex(strings.TrimPrefix(d, "sha256:"))
	}
	if i := strings.LastIndex(ref, "@sha256:"); i >= 0 {
		return validHex(ref[i+len("@sha256:"):])
	}
	return "", fmt.Errorf("image %q is not in the store: %w", ref, fs.ErrNotExist)
}

// validHex guards the file names built from digests.
func validHex(h string) (string, error) {
	if len(h) != 64 {
		return "", fmt.Errorf("bad sha256 digest %q", h)
	}
	for _, c := range h {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return "", fmt.Errorf("bad sha256 digest %q", h)
		}
	}
	return h, nil
}

func (s *Store) layersDir() string { return filepath.Join(s.Root, "layers", "sha256") }

func (s *Store) readMarker(dir string) (layerMarker, error) {
	var m layerMarker
	data, err := os.ReadFile(dir + ".complete")
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(data, &m)
}

func (s *Store) layerReady(dir string) bool {
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return false
	}
	_, err := s.readMarker(dir)
	return err == nil
}

// whiteoutMode picks the mode for new extractions: real whiteouts when
// running as root, records otherwise.
func whiteoutMode() WhiteoutMode {
	if os.Geteuid() == 0 {
		return WhiteoutOverlay
	}
	return WhiteoutRecord
}

// reusable reports whether a cached layer matches what this process would
// build. A layer extracted with recorded whiteouts is not a valid overlay
// lower dir, so root does not reuse it.
func (s *Store) reusable(dir string) bool {
	m, err := s.readMarker(dir)
	if err != nil {
		return false
	}
	if m.IDShift != s.IDShift {
		return false
	}
	return m.Overlay || whiteoutMode() == WhiteoutRecord
}

func (s *Store) ensureLayer(ctx context.Context, l v1.Layer) (string, error) {
	diffID, err := l.DiffID()
	if err != nil {
		return "", fmt.Errorf("diff id: %w", err)
	}
	hex, err := validHex(diffID.Hex)
	if err != nil {
		return "", err
	}
	final := filepath.Join(s.layersDir(), hex)
	if s.reusable(final) {
		return final, nil
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	if err := os.MkdirAll(s.layersDir(), 0o755); err != nil {
		return "", fmt.Errorf("create layer store: %w", err)
	}
	// Same parent as the final dir so the rename cannot cross filesystems.
	tmp, err := os.MkdirTemp(s.layersDir(), hex+".tmp-")
	if err != nil {
		return "", fmt.Errorf("create temp layer dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	stats, err := s.extract(l, tmp)
	if err != nil {
		return "", err
	}
	return final, s.install(tmp, final, stats)
}

func (s *Store) extract(l v1.Layer, dst string) (ExtractStats, error) {
	rc, err := l.Uncompressed()
	if err != nil {
		return ExtractStats{}, fmt.Errorf("open layer: %w", err)
	}
	defer rc.Close()
	stats, err := ExtractLayer(rc, dst, ExtractOptions{IDShift: s.IDShift, Whiteouts: whiteoutMode()})
	if err != nil {
		return stats, fmt.Errorf("extract layer: %w", err)
	}
	// Drain so the layer's digest check runs.
	if _, err := io.Copy(io.Discard, rc); err != nil {
		return stats, fmt.Errorf("verify layer: %w", err)
	}
	return stats, nil
}

// install moves tmp to final, then writes the marker. The rename is atomic;
// the marker tells readers the move finished and how the layer was built.
func (s *Store) install(tmp, final string, stats ExtractStats) error {
	// A leftover from a crash, or from a layer built another way, is replaced.
	_ = os.Remove(final + ".complete")
	if err := os.RemoveAll(final); err != nil {
		return fmt.Errorf("clear stale layer: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		// Another process may have installed the same layer meanwhile.
		if s.reusable(final) {
			return nil
		}
		return fmt.Errorf("install layer: %w", err)
	}
	m := layerMarker{
		IDShift:       s.IDShift,
		Overlay:       whiteoutMode() == WhiteoutOverlay,
		WhiteoutPaths: stats.WhiteoutPaths,
		OpaquePaths:   stats.OpaquePaths,
	}
	return writeJSON(final+".complete", m)
}

func (s *Store) save(img Image) error {
	hex, err := validHex(strings.TrimPrefix(img.Digest, "sha256:"))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(s.Root, "images"), 0o755); err != nil {
		return fmt.Errorf("create image dir: %w", err)
	}
	if err := writeJSON(filepath.Join(s.Root, "images", hex+".json"), img); err != nil {
		return fmt.Errorf("save image metadata: %w", err)
	}

	refsMu.Lock()
	defer refsMu.Unlock()
	refs, err := s.readRefs()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if refs == nil {
		refs = map[string]string{}
	}
	refs[img.Ref] = img.Digest
	if err := writeJSON(filepath.Join(s.Root, "refs.json"), refs); err != nil {
		return fmt.Errorf("save refs: %w", err)
	}
	return nil
}

func (s *Store) readRefs() (map[string]string, error) {
	data, err := os.ReadFile(filepath.Join(s.Root, "refs.json"))
	if err != nil {
		return nil, fmt.Errorf("read refs: %w", err)
	}
	var refs map[string]string
	if err := json.Unmarshal(data, &refs); err != nil {
		return nil, fmt.Errorf("decode refs: %w", err)
	}
	return refs, nil
}

// writeJSON replaces path atomically so readers never see a partial file.
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
