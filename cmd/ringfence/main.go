// Command ringfence runs commands in isolated sandboxes and measures the isolation.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/camilbenameur/ringfence/backend/native"
	"github.com/camilbenameur/ringfence/policy"
	"github.com/camilbenameur/ringfence/sandbox"
)

var version = "dev"

var backends = map[string]func() sandbox.Backend{
	"native": func() sandbox.Backend { return native.New() },
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: ringfence <command> [flags]

commands:
  caps     print what a backend can enforce on this host
  check    validate a policy file against a backend
  version  print the version
`)
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	var err error
	switch args[0] {
	case "caps":
		err = cmdCaps(args[1:], stdout)
	case "check":
		err = cmdCheck(args[1:], stdout)
	case "version":
		fmt.Fprintln(stdout, version)
	case "-h", "-help", "--help", "help":
		usage(stdout)
	default:
		fmt.Fprintf(stderr, "ringfence: unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "ringfence:", err)
		var u usageError
		if errors.As(err, &u) {
			return 2
		}
		return 1
	}
	return 0
}

type usageError struct{ error }

func pickBackend(name string) (sandbox.Backend, error) {
	newB, ok := backends[name]
	if !ok {
		names := make([]string, 0, len(backends))
		for n := range backends {
			names = append(names, n)
		}
		sort.Strings(names)
		return nil, usageError{fmt.Errorf("unknown backend %q (have %v)", name, names)}
	}
	return newB(), nil
}

func cmdCaps(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("caps", flag.ContinueOnError)
	name := fs.String("backend", "native", "backend name")
	if err := fs.Parse(args); err != nil {
		return usageError{err}
	}
	b, err := pickBackend(*name)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(b.Capabilities())
}

func cmdCheck(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	name := fs.String("backend", "native", "backend name")
	if err := fs.Parse(args); err != nil {
		return usageError{err}
	}
	p := policy.Default()
	if fs.NArg() > 1 {
		return usageError{errors.New("check takes at most one policy file")}
	}
	if fs.NArg() == 1 {
		var err error
		if p, err = policy.Load(fs.Arg(0)); err != nil {
			return err
		}
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
