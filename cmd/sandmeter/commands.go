package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/camilbenameur/sandmeter/mcpserver"
	"github.com/camilbenameur/sandmeter/receipt"
)

func cmdRun(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	backend := fs.String("backend", "native", "backend: native or gvisor")
	img := fs.String("image", "docker.io/library/alpine:3.20", "image reference")
	pol := fs.String("policy", "", "policy file (TOML); default policy if empty")
	out := fs.String("receipt", "", "also write the signed receipt to this file")
	dir := fs.String("receipt-dir", "", "receipt directory (default $SANDMETER_HOME/receipts)")
	quiet := fs.Bool("q", false, "do not print the receipt summary on stderr")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: sandmeter run [flags] -- command [args...]")
		fs.PrintDefaults()
	}
	if err := parse(fs, args); err != nil {
		return err
	}
	argv := fs.Args()
	if len(argv) == 0 {
		return usageError{errors.New("run: no command given")}
	}
	p, err := loadPolicy(*pol)
	if err != nil {
		return err
	}
	e, err := newEngine(*dir)
	if err != nil {
		return err
	}
	s, err := e.Start(ctx, *backend, *img, p)
	if err != nil {
		return err
	}
	defer s.Stop(context.Background())
	o, err := s.Run(ctx, argv)
	if err != nil {
		return err
	}
	stdout.Write(o.Result.Stdout)
	os.Stderr.Write(o.Result.Stderr)
	if *out != "" {
		if err := os.WriteFile(*out, o.Envelope, 0o644); err != nil {
			return err
		}
	}
	if !*quiet {
		fmt.Fprintf(os.Stderr, "--- sandmeter receipt %s\n%s\n", o.ReceiptPath, receipt.Summary(o.Receipt))
	}
	if o.Result.ExitCode != 0 {
		return exitError{o.Result.ExitCode}
	}
	return nil
}

func cmdPull(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("pull", flag.ContinueOnError)
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageError{errors.New("usage: sandmeter pull <image>")}
	}
	img, err := store().Pull(ctx, fs.Arg(0))
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s %s (%d layers)\n", img.Ref, img.Digest, len(img.Layers))
	return nil
}

func cmdVerify(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pub := fs.String("pub", "", "public key file (default $SANDMETER_HOME/receipt.key.pub)")
	asJSON := fs.Bool("json", false, "print the verified receipt as JSON")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageError{errors.New("usage: sandmeter verify [-pub key.pub] receipt.json")}
	}
	if *pub == "" {
		*pub = keyPath() + ".pub"
	}
	key, err := receipt.LoadPublicKey(*pub)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	r, err := receipt.Verify(data, key)
	if err != nil {
		return fmt.Errorf("verify failed: %w", err)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	fmt.Fprintf(stdout, "signature ok (key %s)\n%s\n", receipt.KeyID(key), receipt.Summary(r))
	return nil
}

func cmdReplay(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	pub := fs.String("pub", "", "public key file (default $SANDMETER_HOME/receipt.key.pub)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageError{errors.New("usage: sandmeter replay [-pub key.pub] receipt.json")}
	}
	if *pub == "" {
		*pub = keyPath() + ".pub"
	}
	key, err := receipt.LoadPublicKey(*pub)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	rec, err := receipt.Verify(data, key)
	if err != nil {
		return fmt.Errorf("verify failed: %w", err)
	}
	e, err := newEngine("")
	if err != nil {
		return err
	}
	rep, err := e.Replay(ctx, rec)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "replayed on %s: exit %v, stdout %v, diff %v\nnew receipt: %s\n",
		rec.Backend, same(rep.SameExit), same(rep.SameStdout), same(rep.SameDiff), rep.ReceiptPath)
	if len(rep.Differences) > 0 {
		fmt.Fprintf(stdout, "differences:\n  %s\n", strings.Join(rep.Differences, "\n  "))
		return exitError{1}
	}
	return nil
}

func same(b bool) string {
	if b {
		return "same"
	}
	return "DIFFERENT"
}

func cmdKeygen(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := os.MkdirAll(home(), 0o700); err != nil {
		return err
	}
	key, err := receipt.LoadOrCreateKey(keyPath())
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "key %s\npublic key: %s.pub\n", receipt.KeyID(key.Public().(ed25519.PublicKey)), keyPath())
	return nil
}

func cmdMCP(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	dir := fs.String("receipt-dir", "", "receipt directory (default $SANDMETER_HOME/receipts)")
	if err := parse(fs, args); err != nil {
		return err
	}
	e, err := newEngine(*dir)
	if err != nil {
		return err
	}
	defer e.StopAll(context.Background())
	return mcpserver.Serve(ctx, &mcpService{e: e}, version)
}

func cmdCaps(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("caps", flag.ContinueOnError)
	name := fs.String("backend", "native", "backend name")
	if err := parse(fs, args); err != nil {
		return err
	}
	b, err := pickBackend(*name)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(b.Capabilities())
}

func cmdCheck(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	name := fs.String("backend", "native", "backend name")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 1 {
		return usageError{errors.New("check takes at most one policy file")}
	}
	p, err := loadPolicy(fs.Arg(0))
	if err != nil {
		return err
	}
	b, err := pickBackend(*name)
	if err != nil {
		return err
	}
	if _, err := p.Validate(b.Capabilities()); err != nil {
		return fmt.Errorf("policy refused by backend %q:\n%w", *name, err)
	}
	fmt.Fprintf(stdout, "ok: backend %q can enforce this policy (sha256 %s)\n", *name, p.Hash())
	return nil
}
