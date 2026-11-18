package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/camilbenameur/sandmeter/internal/escape"
	"github.com/camilbenameur/sandmeter/internal/escape/harness"
)

func cmdEscape(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("escape", flag.ContinueOnError)
	backendsFlag := fs.String("backends", "native,gvisor", "comma-separated backends")
	img := fs.String("image", "docker.io/library/alpine:3.20", "image reference")
	probe := fs.String("probe", "", "static sandmeter-probe binary (build: CGO_ENABLED=0 go build ./cmd/sandmeter-probe)")
	out := fs.String("out", "", "write the verdicts as JSON to this file")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *probe == "" {
		return usageError{errors.New("escape: -probe is required")}
	}
	e, err := newEngine(filepath.Join(home(), "escape-receipts"))
	if err != nil {
		return err
	}
	h := &harness.Harness{
		Engine: e,
		Image:  *img,
		Probe:  *probe,
		// Outside SANDMETER_HOME (0700): see harness.Harness.WorkDir.
		WorkDir: "/run/sandmeter-escape",
		Log:     func(s string) { fmt.Fprintln(os.Stderr, s) },
	}
	verdicts, err := h.Run(ctx, strings.Split(*backendsFlag, ","))
	if err != nil {
		return err
	}
	if *out != "" {
		data, err := json.MarshalIndent(verdicts, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*out, data, 0o644); err != nil {
			return err
		}
	}
	fmt.Fprint(stdout, escape.Markdown(verdicts))
	return nil
}
