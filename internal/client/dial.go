package client

import (
	"context"
	"fmt"

	"github.com/camilbenameur/sandmeter/internal/ctl"
)

// DialOptions says how to reach the service.
type DialOptions struct {
	// Socket is the path of the service's socket. Empty means the path in
	// the environment variable layout.EnvSocket when it is set, and
	// layout.Socket otherwise.
	Socket string
	// Build identifies the calling program in the hello.
	Build ctl.Build
}

// Dial connects to the service's socket and returns a client that speaks
// the control protocol over it.
//
// Before it sends a byte it checks, with the credentials the kernel reports
// for the other end, that root serves the socket: a socket somebody else
// listens on is refused, since that somebody could answer with records
// signed by a key of its own choosing. Every failure to connect wraps
// ErrUnavailable and says what to do: install the package, enable the socket
// unit, join the group and log in again.
//
// Not built yet: it returns ErrNotBuilt and touches nothing.
func Dial(ctx context.Context, opts DialOptions) (Client, error) {
	return nil, fmt.Errorf("the client of the service's socket: %w", ErrNotBuilt)
}
