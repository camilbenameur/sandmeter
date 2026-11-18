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

	"k2userns":   childK2,
	"k2binotify": childK2b,

	"k3":      childK3,
	"k9tmpfs": childK9,
	"tsyncfs": childSyncfs,

	"k4worker":     childK4Worker,
	"k4probe":      childK4Probe,
	"k4scope":      childK4Scope,
	"k5supervisor": childK5Supervisor,
	"k5init":       childK5Init,
	"k5orphaner":   childK5Orphaner,
	"k5sleep":      childSleep,
	"k8cgns":       childK8,

	"k6worker": childK6Worker,
	"k6probe":  childK6Probe,
}
