//go:build linux

package native

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/camilbenameur/ringfence/internal/seccomp"
)

// InitArg is the hidden first argument that turns the ringfence binary into
// the sandbox init. The parent re-executes /proc/self/exe with it inside the
// new namespaces.
const InitArg = "__ringfence_init"

const (
	configFD = 3 // parent -> init: JSON config; reading it is also the "go" signal
	errorFD  = 4 // init -> parent: setup error text; closed by execve on success
)

// initConfig is everything the init needs. It crosses a pipe as JSON.
type initConfig struct {
	Root         string   `json:"root"`
	ReadOnlyRoot bool     `json:"read_only_root"`
	Hostname     string   `json:"hostname"`
	Argv         []string `json:"argv"`
	Env          []string `json:"env"`
	Workdir      string   `json:"workdir"`
	Seccomp      bool     `json:"seccomp"`
}

// writableDirs stay writable when the root is read-only. They live on the
// overlay, so what is written there appears in the receipt diff.
var writableDirs = []string{"tmp", "workspace"}

// Init runs inside the new namespaces. It never returns: it either execs the
// command or exits with status 127 after reporting the error on errorFD.
func Init() {
	// Capabilities, the bounding set and seccomp filters are per thread.
	// Everything happens on this thread, which then calls execve.
	runtime.LockOSThread()
	errPipe := os.NewFile(errorFD, "error")
	if err := initMain(); err != nil {
		fmt.Fprint(errPipe, err.Error())
		os.Exit(127)
	}
	panic("unreachable: execve returned without error")
}

func initMain() error {
	unix.CloseOnExec(errorFD)
	f := os.NewFile(configFD, "config")
	var cfg initConfig
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return fmt.Errorf("init: read config: %w", err)
	}
	f.Close()

	if err := setupRoot(cfg); err != nil {
		return err
	}
	if err := unix.Sethostname([]byte(cfg.Hostname)); err != nil {
		return fmt.Errorf("init: sethostname: %w", err)
	}
	if err := loopbackUp(); err != nil {
		return err
	}
	if err := pivot(cfg.Root); err != nil {
		return err
	}
	if cfg.Workdir != "" {
		if err := unix.Chdir(cfg.Workdir); err != nil {
			return fmt.Errorf("init: chdir %s: %w", cfg.Workdir, err)
		}
	}
	for _, rl := range []struct {
		res int
		val uint64
	}{{unix.RLIMIT_CORE, 0}, {unix.RLIMIT_NOFILE, 4096}} {
		if err := unix.Setrlimit(rl.res, &unix.Rlimit{Cur: rl.val, Max: rl.val}); err != nil {
			return fmt.Errorf("init: setrlimit: %w", err)
		}
	}

	path, err := lookPath(cfg.Argv[0], cfg.Env)
	if err != nil {
		return err
	}
	if err := dropCapabilities(); err != nil {
		return err
	}
	if cfg.Seccomp {
		prog, err := seccomp.Default().Build()
		if err != nil {
			return fmt.Errorf("init: seccomp: %w", err)
		}
		if err := seccomp.Install(prog); err != nil {
			return fmt.Errorf("init: seccomp: %w", err)
		}
	} else if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("init: no_new_privs: %w", err)
	}
	return fmt.Errorf("init: exec %s: %w", path, unix.Exec(path, cfg.Argv, cfg.Env))
}

// lookPath resolves argv[0] with the sandbox's PATH, after pivot_root.
func lookPath(name string, env []string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	pathEnv := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, "PATH="); ok {
			pathEnv = v
		}
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("init: %s: %w", name, exec.ErrNotFound)
}

func mount(src, dst, fstype string, flags uintptr, data string) error {
	if err := unix.Mount(src, dst, fstype, flags, data); err != nil {
		return fmt.Errorf("init: mount %s on %s (%s): %w", src, dst, fstype, err)
	}
	return nil
}

// setupRoot builds the sandbox filesystem under cfg.Root before pivot_root.
func setupRoot(cfg initConfig) error {
	root := cfg.Root
	// Nothing done here may propagate back to the host mount namespace.
	if err := mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return err
	}
	// pivot_root needs the new root to be a mount point of this namespace.
	if err := mount(root, root, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return err
	}
	if cfg.ReadOnlyRoot {
		for _, d := range writableDirs {
			p := filepath.Join(root, d)
			if err := mount(p, p, "", unix.MS_BIND, ""); err != nil {
				return err
			}
		}
		// Only the top mount becomes read-only; the binds above stay writable.
		if err := mount(root, root, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NODEV, ""); err != nil {
			return err
		}
	}
	if err := mount("proc", filepath.Join(root, "proc"), "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return err
	}
	if err := maskProc(root); err != nil {
		return err
	}
	// Allowed in a user namespace because this namespace owns the network
	// namespace; mounted read-only.
	if err := mount("sysfs", filepath.Join(root, "sys"), "sysfs",
		unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return err
	}
	return setupDev(filepath.Join(root, "dev"))
}

// maskProc hides /proc files that leak host information or accept writes
// that matter, in the same spirit as the default masks of container runtimes.
func maskProc(root string) error {
	proc := filepath.Join(root, "proc")
	for _, f := range []string{"kcore", "keys", "timer_list", "sched_debug", "kallsyms", "sysrq-trigger"} {
		p := filepath.Join(proc, f)
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		if err := mount("/dev/null", p, "", unix.MS_BIND, ""); err != nil {
			return err
		}
	}
	for _, d := range []string{"sys", "irq", "bus", "fs"} {
		p := filepath.Join(proc, d)
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		if err := mount(p, p, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return err
		}
		if err := mount(p, p, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
			return err
		}
	}
	return nil
}

// setupDev mounts a small tmpfs on /dev with the usual character devices.
// A user namespace cannot mknod devices, so they are bind mounts of the
// host's harmless ones.
func setupDev(dev string) error {
	if err := mount("tmpfs", dev, "tmpfs", unix.MS_NOSUID|unix.MS_NOEXEC, "mode=755,size=65536k"); err != nil {
		return err
	}
	for _, name := range []string{"null", "zero", "full", "random", "urandom", "tty"} {
		p := filepath.Join(dev, name)
		f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0o666)
		if err != nil {
			return fmt.Errorf("init: %w", err)
		}
		f.Close()
		if err := mount("/dev/"+name, p, "", unix.MS_BIND, ""); err != nil {
			return err
		}
	}
	for _, d := range []string{"pts", "shm"} {
		if err := os.Mkdir(filepath.Join(dev, d), 0o755); err != nil {
			return fmt.Errorf("init: %w", err)
		}
	}
	if err := mount("devpts", filepath.Join(dev, "pts"), "devpts", unix.MS_NOSUID|unix.MS_NOEXEC,
		"newinstance,ptmxmode=0666,mode=0620"); err != nil {
		return err
	}
	if err := mount("shm", filepath.Join(dev, "shm"), "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=1777,size=65536k"); err != nil {
		return err
	}
	links := map[string]string{
		"ptmx": "pts/ptmx", "fd": "/proc/self/fd",
		"stdin": "/proc/self/fd/0", "stdout": "/proc/self/fd/1", "stderr": "/proc/self/fd/2",
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(dev, name)); err != nil {
			return fmt.Errorf("init: %w", err)
		}
	}
	return nil
}

func loopbackUp() error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("init: loopback: %w", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		return fmt.Errorf("init: loopback up: %w", err)
	}
	return nil
}

// pivot switches the root with the pivot_root(".", ".") idiom: the old root
// is stacked under the new one and detached right away, so no directory is
// needed in a root that may be read-only.
func pivot(root string) error {
	if err := unix.Chdir(root); err != nil {
		return fmt.Errorf("init: chdir root: %w", err)
	}
	if err := unix.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("init: pivot_root: %w", err)
	}
	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("init: detach old root: %w", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return fmt.Errorf("init: chdir /: %w", err)
	}
	return nil
}

var errNoCapLast = errors.New("cannot read /proc/sys/kernel/cap_last_cap")
