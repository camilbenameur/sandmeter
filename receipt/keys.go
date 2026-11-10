package receipt

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// LoadOrCreateKey loads the signing key at path, creating it if absent.
//
// File format: base64 (std) of the 32-byte Ed25519 seed, one line. A new key
// is created with mode 0600 and O_EXCL. An existing file readable by group or
// others is refused. The public key is written next to it at path+".pub" as
// base64 of the 32-byte key, mode 0644.
func LoadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	key, err := loadKey(path)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return createKey(path)
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open key %q: %w", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat key %q: %w", path, err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("key %q has mode %o: it must not be readable by group or others", path, fi.Mode().Perm())
	}
	buf := make([]byte, 256)
	n, _ := f.Read(buf)
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(buf[:n])))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("key %q is not a base64 32-byte seed", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func createKey(path string) (ed25519.PrivateKey, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create key directory: %w", err)
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return loadKey(path) // lost a race with another process
		}
		return nil, fmt.Errorf("create key %q: %w", path, err)
	}
	_, werr := f.WriteString(base64.StdEncoding.EncodeToString(priv.Seed()) + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return nil, fmt.Errorf("write key %q: %w", path, werr)
	}
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)) + "\n"
	if err := writePublic(path+".pub", pub); err != nil {
		return nil, err
	}
	return priv, nil
}

func writePublic(path, content string) error {
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write public key %q: %w", path, err)
	}
	// WriteFile is subject to the umask and keeps the mode of an existing file.
	if err := os.Chmod(path, 0o644); err != nil {
		return fmt.Errorf("chmod public key %q: %w", path, err)
	}
	return nil
}

// LoadPublicKey reads a public key file: base64 (std) of the 32-byte key.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key %q is not a base64 32-byte key", path)
	}
	return ed25519.PublicKey(raw), nil
}
