package client

import (
	"context"
	"fmt"

	"github.com/camilbenameur/sandmeter/internal/ctl"
)

// DirectOptions says how root runs without the service.
type DirectOptions struct {
	// Sandmeterd is the path of the root-side program. Empty means the
	// program named sandmeterd in the directory of the running executable.
	// It is never looked up in PATH.
	Sandmeterd string
	// Build identifies the calling program in the hello.
	Build ctl.Build
}

// Direct is for a caller that is root already: it starts one worker of the
// root-side program itself, over a socket pair, and returns a client that
// speaks to it. The worker is the same program, started the same way and
// reading the same operator file as the one the service starts for a
// connection: direct mode is a different way in, not a different path
// through the code, and it does not get around the ceiling.
//
// It refuses to run for a caller that is not root. Each session started
// through the returned client gets a worker of its own.
//
// Not built yet: it returns ErrNotBuilt and touches nothing.
func Direct(ctx context.Context, opts DirectOptions) (Client, error) {
	return nil, fmt.Errorf("direct mode: %w", ErrNotBuilt)
}
