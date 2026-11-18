//go:build integration && linux

package kernelfacts

// children maps the hidden second argument of the test binary to the
// function that runs in the helper process (see childArg). A function
// returns an error only for what prevents the measurement; what the kernel
// answered goes into the reply it prints.
var children = map[string]func(args []string) error{
	"noop":     func([]string) error { return nil },
	"idle":     childIdle,
	"echo":     childEcho,
	"cgreport": childCgroupReport,

	"k1netns": childK1,
}
