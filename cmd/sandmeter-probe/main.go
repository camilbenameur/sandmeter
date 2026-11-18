// Command sandmeter-probe is the static helper the escape harness copies
// into the sandbox rootfs as /usr/local/bin/sandmeter-probe, where the escape
// cases shell out to it. All of its code is in internal/escape/probe.
//
// Build it without cgo, so that the one file runs in any image:
//
//	CGO_ENABLED=0 go build ./cmd/sandmeter-probe
package main

import "github.com/camilbenameur/sandmeter/internal/escape/probe"

func main() {
	probe.Main()
}
