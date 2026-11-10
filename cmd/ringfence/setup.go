package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/camilbenameur/ringfence/backend/gvisor"
	"github.com/camilbenameur/ringfence/backend/native"
	"github.com/camilbenameur/ringfence/engine"
	"github.com/camilbenameur/ringfence/image"
	"github.com/camilbenameur/ringfence/policy"
	"github.com/camilbenameur/ringfence/receipt"
	"github.com/camilbenameur/ringfence/sandbox"
)

// idShift is the host uid/gid of root inside every sandbox. Image layers
// are extracted with this ownership.
const idShift = 100000

func home() string {
	if h := os.Getenv("RINGFENCE_HOME"); h != "" {
		return h
	}
	return "/var/lib/ringfence"
}

func keyPath() string { return filepath.Join(home(), "receipt.key") }

func store() *image.Store {
	return &image.Store{Root: filepath.Join(home(), "images"), IDShift: idShift}
}

func backends() map[string]sandbox.Backend {
	return map[string]sandbox.Backend{
		"native": native.New(native.Options{IDShift: idShift}),
		"gvisor": gvisor.New(gvisor.Options{IDShift: idShift}),
	}
}

// newEngine builds an engine with the signing key, creating the key on first use.
func newEngine(receiptDir string) (*engine.Engine, error) {
	if err := os.MkdirAll(home(), 0o700); err != nil {
		return nil, err
	}
	key, err := receipt.LoadOrCreateKey(keyPath())
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	if receiptDir == "" {
		receiptDir = filepath.Join(home(), "receipts")
	}
	return &engine.Engine{
		Store:      store(),
		Backends:   backends(),
		Key:        key,
		ReceiptDir: receiptDir,
		Version:    version,
	}, nil
}

func pickBackend(name string) (sandbox.Backend, error) {
	b, ok := backends()[name]
	if !ok {
		return nil, usageError{fmt.Errorf("unknown backend %q (have native, gvisor)", name)}
	}
	return b, nil
}

func loadPolicy(path string) (policy.Policy, error) {
	if path == "" {
		return policy.Default(), nil
	}
	return policy.Load(path)
}

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitError{0}
		}
		return usageError{err}
	}
	return nil
}
