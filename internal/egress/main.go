// Package egress is the egress proxy: the one way out of a sandbox whose
// policy allows some network. It serves HTTP CONNECT and plain HTTP requests
// on a listener that lives on the loopback of the sandbox's own network
// namespace, forwards those whose destination the policy lists, and records
// every request it receives.
//
// The proxy reads bytes that a program in a sandbox chose. It therefore runs
// in a process of its own, one per command, without privilege and under an
// id that nothing else on the host uses.
//
// Only the entry point of that process is declared so far.
package egress

import "github.com/camilbenameur/sandmeter/internal/hidden/entry"

// Main is the hidden entry point entry.Egress: the proxy process of one
// command. Its parent hands it the listener and its configuration on its
// control descriptor; it has no other input.
//
// It never returns. It refuses to run without the handshake on its control
// descriptor.
//
// Not built yet: after the handshake it exits with a message.
func Main() {
	entry.MustAccept(entry.ControlFD, entry.Egress)
	entry.NotBuilt(entry.Egress)
}
