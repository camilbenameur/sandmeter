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

	"netns": childNetns,

	"userns":  childUserns,
	"inotify": childInotify,

	"refresh":    childRefresh,
	"tmpfsupper": childTmpfsUpper,
	"unmount":    childUnmount,

	"worker":            childWorker,
	"upperprobe":        childUpperProbe,
	"scope":             childScope,
	"switch-supervisor": childSwitchSupervisor,
	"switch-init":       childSwitchInit,
	"orphaner":          childOrphaner,
	"sleep":             childSleep,
	"cgroupns":          childCgroupns,

	"standin-supervisor": childStandInSupervisor,
	"standin-init":       childStandInInit,
	"forkbomb":           childForkBomb,
	"signaller":          childSignaller,

	"runscworker": childRunscWorker,
	"runscprobe":  childRunscProbe,

	"crash":       childCrash,
	"mounttarget": childMountTarget,

	"idmap":     childIDMap,
	"idmapview": childIDMapView,
	"loop":      childLoop,
}
