//go:build integration && linux

package kernelfacts

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// The tests of this file check the instrument itself: the parts of the
// package that need no privilege. They run wherever the package runs, so a
// broken helper shows up on a developer's machine and not as a puzzling
// fact on a runner.

func TestSelfCatalogue(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range catalogue {
		if seen[d.id] {
			t.Errorf("fact %s is declared twice", d.id)
		}
		seen[d.id] = true
		if strings.TrimSpace(d.name) == "" {
			t.Errorf("fact %s has no statement", d.id)
		}
	}
}

// doc.go is where a reader learns which decision a fact gates. A fact that
// is not listed there is a number nobody can use, and one listed there as
// required while the catalogue says otherwise misleads whoever reads a red
// job. Each fact has one line of the form "<id>  required|recorded  ...".
func TestSelfDocListsEveryFact(t *testing.T) {
	doc, err := os.ReadFile("doc.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range catalogue {
		line := regexp.MustCompile(`(?m)^//\t` + regexp.QuoteMeta(d.id) + ` +(required|recorded) `)
		found := line.FindAllSubmatch(doc, -1)
		want := "recorded"
		if d.required {
			want = "required"
		}
		switch {
		case len(found) != 1:
			t.Errorf("doc.go has %d lines for fact %s, want one", len(found), d.id)
		case string(found[0][1]) != want:
			t.Errorf("doc.go lists fact %s as %s, the catalogue as %s", d.id, found[0][1], want)
		}
	}
}

// The guard that a helper calls before it mounts or configures a network:
// in the namespaces of the test process it refuses.
func TestSelfHelpersRefuseTheHost(t *testing.T) {
	for kind, env := range map[string]string{"mnt": hostMntEnv, "net": hostNetEnv} {
		t.Setenv(env, nsLink(kind))
		if err := outsideHost(kind, env); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Errorf("a helper in the %s namespace of the test process is not refused: %v", kind, err)
		}
		// Nothing to compare with is a refusal too.
		t.Setenv(env, "")
		if err := outsideHost(kind, env); err == nil {
			t.Errorf("a helper that was not told the %s namespace of the test process is not refused", kind)
		}
		t.Setenv(env, kind+":[1]")
		if err := outsideHost(kind, env); err != nil {
			t.Errorf("a helper in another %s namespace is refused: %v", kind, err)
		}
	}
}

// Every helper that mounts or configures a network is started here the way
// a forgotten clone flag would start it, in the namespaces of the test
// process. Each must stop at its guard, before it creates anything.
//
// Under root the helpers run as nobody: a guard that came to be missing
// then meets a refusal of the kernel, and never the host.
func TestSelfHelpersStopAtTheGuard(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	for _, argv := range [][]string{
		{"k1netns", "3128", "3129", "nonce"},
		{"k2userns", "write"},
		{"k2binotify", "4", ""},
		{"k3", work, "replace"},
		{"k4worker", work},
		{"k4probe", work},
		{"k6worker", work, "/nonexistent/runsc", "id"},
		{"k9tmpfs", work, ""},
		{"k11idmap", work, "1000", "1000"},
		{"tloop", work, "/nonexistent/mkfs.ext4", "unmount"},
		{"tmnt", work, work + "-outside"},
		{"tsyncfs", work},
	} {
		var nothing struct{}
		err := runChild(t, spawn{name: argv[0], args: argv[1:], nobody: os.Geteuid() == 0}, &nothing)
		if errors.Is(err, fs.ErrPermission) {
			t.Fatalf("a helper that is not root could not be started (%v): the test binary must leave r-x to others. Until it does, every fact measured in a user namespace reads \"no\" for that reason alone", err)
		}
		// The stand-in for the init checks that it is PID 1 before anything
		// else, which it is not here.
		if err == nil || !(strings.Contains(err.Error(), "refusing to go on") || strings.Contains(err.Error(), "expected to be PID 1")) {
			t.Errorf("helper %s, started in the namespaces of the test process, did not stop at its guard: %v", argv[0], err)
		}
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Errorf("the refused helpers left %d entries in their directory (%v)", len(entries), err)
	}
}

func TestSelfScratch(t *testing.T) {
	for path, want := range map[string]bool{
		"/var/lib":                   true,
		"/var/lib/sandmeter-kf-1234": true,
		"/tmp/a.b_c":                 true,
		"relative":                   false,
		"/":                          false,
		"/with space":                false,
		"/with,comma":                false,
		"/with:colon":                false,
		"/with'quote":                false,
	} {
		if got := plainPath.MatchString(path); got != want {
			t.Errorf("plainPath accepts %q: %v, want %v", path, got, want)
		}
	}
	if scratchRoot == "" {
		t.Skip("no scratch directory without root")
	}
	dir := scratch(t, "self")
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o711 || !plainPath.MatchString(dir) {
		t.Errorf("scratch directory %s: %v, %v; want a plain path with mode 0711", dir, fi, err)
	}
}

func TestSelfDetails(t *testing.T) {
	for _, c := range []struct{ got, want string }{
		{orOK(""), "ok"},
		{orOK("accept: EAGAIN"), "accept: EAGAIN"},
		{orNothing(""), "nothing"},
		{orNothing("+line"), "+line"},
		{errOrOK(nil), "ok"},
		{errOrOK(errors.New("no")), "no"},
		{valueOr("ext4", nil), "ext4"},
		{valueOr("", unix.ENOENT), "not readable: ENOENT"},
		{millis(1500 * time.Microsecond), "1.5 ms"},
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
	if ms := since(time.Now().Add(-time.Second)); ms < 1000 || ms > 1500 {
		t.Errorf("since one second ago = %v ms", ms)
	}
}

func TestSelfCleanDetail(t *testing.T) {
	if got := cleanDetail("a\n\tb   c\n"); got != "a b c" {
		t.Errorf("cleanDetail = %q, want %q", got, "a b c")
	}
	// One byte, then two-byte characters: the limit falls inside one.
	long := "a" + strings.Repeat("é", maxDetail)
	got := cleanDetail(long)
	kept, note, cut := strings.Cut(got, " ... (")
	if !cut || !strings.HasSuffix(note, "more bytes cut)") || !utf8.ValidString(kept) || !strings.HasPrefix(long, kept) || len(kept) > maxDetail {
		t.Errorf("a long detail was not cut at a character boundary with a note: %d bytes kept, note %q", len(kept), note)
	}
	if _, err := json.Marshal(fact{Detail: got}); err != nil {
		t.Errorf("the cut detail does not encode: %v", err)
	}
}

func TestSelfEmit(t *testing.T) {
	out := filepath.Join(t.TempDir(), "facts.jsonl")
	t.Setenv(factsOutEnv, out)
	want := fact{ID: "self", Name: "a statement", Required: true, Outcome: yes, Detail: "a | detail with \"quotes\"", Kernel: kernelRelease()}
	var log strings.Builder
	for range 2 {
		if err := emitTo(&log, want); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.HasPrefix(log.String(), `FACT {"id":"self",`) || strings.Count(log.String(), "\n") != 2 {
		t.Errorf("the log lines are not two lines that start with FACT and the object: %q", log.String())
	}
	recordMu.Lock()
	delete(recorded, "self") // not a fact of the catalogue
	recordMu.Unlock()

	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d lines in the file after two facts: %q", len(lines), b)
	}
	var got fact
	if err := json.Unmarshal([]byte(lines[1]), &got); err != nil {
		t.Fatalf("a line of the file is not a JSON object: %v", err)
	}
	if got != want {
		t.Errorf("read back %+v, want %+v", got, want)
	}
	for _, key := range []string{`"id"`, `"name"`, `"required"`, `"outcome"`, `"detail"`, `"kernel"`} {
		if !strings.Contains(lines[0], key) {
			t.Errorf("the line has no %s key: %s", key, lines[0])
		}
	}
}

func TestSelfRequireLists(t *testing.T) {
	t.Setenv(requireEnv, "root, cgroup2,runsc")
	for name, want := range map[string]bool{"root": true, "cgroup2": true, "runsc": true, "run": false, "": false} {
		if got := requireLists(name); got != want {
			t.Errorf("requireLists(%q) = %v with %s=%q, want %v", name, got, requireEnv, os.Getenv(requireEnv), want)
		}
	}
}

func TestSelfErrnoName(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{nil, "ok"},
		{unix.ENOSPC, "ENOSPC"},
		{fmt.Errorf("mount: %w", unix.ELOOP), "ELOOP"},
		{&os.PathError{Op: "fork/exec", Path: "/proc/self/exe", Err: syscall.EAGAIN}, "EAGAIN"},
		{errors.Join(nil, os.NewSyscallError("connect", unix.ENETUNREACH)), "ENETUNREACH"},
		{errors.New("plain"), "plain"},
	} {
		if got := errnoName(c.err); got != c.want {
			t.Errorf("errnoName(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

const sampleMountinfo = `22 28 0:21 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
28 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,discard,errors=remount-ro
31 22 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:9 - cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot
90 28 0:44 / /mnt/with\040space rw,relatime - tmpfs tmpfs rw,size=1024k
95 28 0:50 / /var/lib/x/merged rw,nosuid,nodev,relatime - overlay overlay rw,lowerdir=/var/lib/x/lower,upperdir=/var/lib/x/upper,workdir=/var/lib/x/work,redirect_dir=nofollow,uuid=on
96 95 0:51 / /var/lib/x/merged rw,relatime - tmpfs tmpfs rw
`

func TestSelfMountinfo(t *testing.T) {
	entries := parseMountinfo(sampleMountinfo)
	if len(entries) != 6 {
		t.Fatalf("%d entries parsed, want 6", len(entries))
	}
	if e, ok := mountAt(entries, "/mnt/with space"); !ok || e.fstype != "tmpfs" {
		t.Errorf("escaped mount point: found %v %+v", ok, e)
	}
	if e, ok := mountAt(entries, "/var/lib/x/merged"); !ok || e.fstype != "tmpfs" {
		t.Errorf("of two mounts stacked on one point the last must win: %+v", e)
	}
	for path, want := range map[string]string{
		"/var/lib":               "ext4",
		"/sys/fs/cgroup/a/b":     "cgroup2",
		"/sys/fs":                "sysfs",
		"/var/lib/x/merged/file": "tmpfs",
		"/var/lib/x/mergedness":  "ext4",
	} {
		if e, ok := mountHolding(entries, path); !ok || e.fstype != want {
			t.Errorf("mountHolding(%s) = %q, want %q", path, e.fstype, want)
		}
	}
	got := overlayExtras(entries[4].superOpts)
	if want := "rw,redirect_dir=nofollow,uuid=on"; got != want {
		t.Errorf("overlayExtras = %q, want %q", got, want)
	}
	if live := parseMountinfo(mountinfoText()); len(live) == 0 {
		t.Errorf("the mount table of this process did not parse")
	} else if _, ok := mountHolding(live, "/"); !ok {
		t.Errorf("no mount holds / in the mount table of this process")
	}
}

func TestSelfLineDiff(t *testing.T) {
	if d := lineDiff("a\nb\nc", "a\nb\nc"); d != "" {
		t.Errorf("equal texts differ: %q", d)
	}
	if d := lineDiff("a\nb", "a\nc\nb\nb"); d != "+c ; +b" {
		t.Errorf("lineDiff = %q", d)
	}
	if d := lineDiff("a\nb", "b"); d != "-a" {
		t.Errorf("lineDiff = %q", d)
	}
}

func TestSelfTrees(t *testing.T) {
	root := t.TempDir()
	want := tree{"d": "d", "d/f.txt": "f:content", "d/l": "l:f.txt", "top.txt": "f:"}
	if err := writeTree(root, want); err != nil {
		t.Fatal(err)
	}
	got := readTree(root)
	if d := diffTrees(want, got); d != "" {
		t.Errorf("a tree read back differs from what was written: %s", d)
	}
	other := maps.Clone(want)
	other["d/f.txt"] = "f:changed"
	delete(other, "top.txt")
	other["new"] = "d"
	d := diffTrees(other, got)
	for _, part := range []string{`d/f.txt: expected "f:changed", found "f:content"`, `new: expected "d", found nothing`, `top.txt: expected nothing, found "f:"`} {
		if !strings.Contains(d, part) {
			t.Errorf("diffTrees misses %q in %q", part, d)
		}
	}
}

func TestSelfFindLine(t *testing.T) {
	data := []byte("noise\nready {\"a\":1}\nresult {\"b\":2}\nresult {\"partial\"")
	if p, ok := findLine(data, "ready "); !ok || string(p) != `{"a":1}` {
		t.Errorf("ready: %q %v", p, ok)
	}
	if p, ok := findLine(data, "result "); !ok || string(p) != `{"b":2}` {
		t.Errorf("result: %q %v", p, ok)
	}
	if _, ok := findLine([]byte("result {\"partial\""), "result "); ok {
		t.Errorf("a line without its newline was taken for a complete one")
	}
}

// The helpers are processes of this binary: start one without any
// namespace, talk to it, let it go.
func TestSelfChildRoundTrip(t *testing.T) {
	c, err := spawnChild(t, spawn{name: "echo", args: []string{"one", "two"}})
	if err != nil {
		t.Fatal(err)
	}
	var rdy struct {
		Args []string `json:"args"`
	}
	if err := c.ready(&rdy); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rdy.Args, []string{"one", "two"}) {
		t.Errorf("the helper saw the arguments %v", rdy.Args)
	}
	select {
	case <-c.exited:
		t.Fatalf("the helper exited before it was released")
	case <-time.After(50 * time.Millisecond):
	}
	c.release()
	var res struct {
		Released bool `json:"released"`
	}
	if err := c.result(&res); err != nil {
		t.Fatal(err)
	}
	if !res.Released {
		t.Errorf("the helper did not report its release")
	}

	// A helper that fails says why, and one that never finishes is killed.
	var nothing struct{}
	err = runChild(t, spawn{name: "echo", args: []string{"fail"}}, &nothing)
	if err == nil || !strings.Contains(err.Error(), "asked to fail") {
		t.Errorf("the error of a failing helper does not carry its stderr: %v", err)
	}
	stuck, err := spawnChild(t, spawn{name: "idle"})
	if err != nil {
		t.Fatal(err)
	}
	if err := stuck.wait(100 * time.Millisecond); err == nil || !strings.Contains(err.Error(), "was killed") {
		t.Errorf("a helper that does not finish must be killed at the timeout: %v", err)
	}
	if _, err := spawnChild(t, spawn{name: "noop", cgroup: filepath.Join(t.TempDir(), "absent")}); err == nil {
		t.Errorf("a cgroup that does not exist must be an error")
	}
}

// The readers of cgroup files and of /proc, on the group of this process.
func TestSelfCgroupReaders(t *testing.T) {
	if !haveCgroup2() {
		t.Skip("cgroup v2 is not mounted at " + cgroupRoot)
	}
	path, err := ownCgroup()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(cgroupRoot, path)
	if !slices.Contains(cgProcs(dir), os.Getpid()) {
		// A cgroup namespace whose root is not the mounted hierarchy's.
		t.Skipf("the cgroup of this process, %q, is not at %s: nothing to read", path, dir)
	}
	// The root group has no cgroup.events.
	if exists(filepath.Join(dir, "cgroup.events")) {
		if got := cgFlat(dir, "cgroup.events"); !strings.Contains(got, "populated=1") {
			t.Errorf("cgFlat(cgroup.events) = %q, want populated=1 in it", got)
		}
		if got := cgCounter(dir, "cgroup.events", "populated"); got != 1 {
			t.Errorf("cgCounter(cgroup.events, populated) = %d, want 1", got)
		}
	}
	if got := cgFlat(dir, "pids.events.of-no-kernel"); got != "absent" {
		t.Errorf("cgFlat of a file that does not exist = %q, want absent", got)
	}
	if got := cgCounter(dir, "pids.events.of-no-kernel", "max"); got != 0 {
		t.Errorf("cgCounter of a file that does not exist = %d, want 0", got)
	}
	// What a kernel without cgroup.kill, or without swap accounting, answers.
	if got := errnoName(cgWrite(dir, "cgroup.file-of-no-kernel", "1")); got != "ENOENT" {
		t.Errorf("cgWrite to a file that does not exist = %s, want ENOENT", got)
	}
	if !slices.Contains(mntNamespaceMembers(nsLink("mnt")), os.Getpid()) {
		t.Errorf("mntNamespaceMembers does not list this process in its own mount namespace %s", nsLink("mnt"))
	}
}

// The clone that puts a process straight into a cgroup, which most root
// tests start with, on the one group that may need no privilege: the group
// this process is in already. Where it is not this user's to write, as in a
// login session, there is nothing to try.
func TestSelfCloneIntoCgroup(t *testing.T) {
	if !haveCgroup2() {
		t.Skip("cgroup v2 is not mounted at " + cgroupRoot)
	}
	path, err := ownCgroup()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(cgroupRoot, path)
	if !slices.Contains(cgProcs(dir), os.Getpid()) {
		t.Skipf("the cgroup of this process, %q, is not at %s: nothing to clone into", path, dir)
	}
	c, err := spawnChild(t, spawn{name: "cgreport", cgroup: dir})
	if errors.Is(err, fs.ErrPermission) {
		t.Skipf("this user may not put a process into %s: %v", dir, err)
	}
	if err != nil {
		t.Fatalf("clone3 with CLONE_INTO_CGROUP into the group this process is in: %v", err)
	}
	var rdy struct {
		Cgroup string `json:"cgroup"`
	}
	if err := c.ready(&rdy); err != nil {
		t.Fatal(err)
	}
	if want := "0::" + path; rdy.Cgroup != want {
		t.Errorf("the cloned process reads %q from /proc/self/cgroup, want %q", rdy.Cgroup, want)
	}
	if !slices.Contains(cgProcs(dir), c.pid()) {
		t.Errorf("cgroup.procs of %s does not list the cloned process %d", dir, c.pid())
	}
}

// A detector that never fires is worth nothing: each comparison of the
// last test is given something to find.
func TestSelfLeakDetectors(t *testing.T) {
	base := snapshotHost()
	for what, d := range map[string]string{
		"mounts":  lineDiff(base.mounts, mountinfoText()),
		"cgroups": base.cgroupsDiffNow(false),
		"loops":   base.loopsDiffNow(),
		"sysctls": base.sysctlsDiff(),
	} {
		if d != "" {
			t.Errorf("%s: a difference on a host nothing touched: %s", what, d)
		}
	}

	doctored := base
	doctored.loops = maps.Clone(base.loops)
	doctored.loops["loop9999"] = "/nowhere/image"
	if d := doctored.loopsDiffNow(); !strings.Contains(d, "loop9999 was attached to /nowhere/image, is detached") {
		t.Errorf("a loop device that changed is not reported: %q", d)
	}
	doctored.sysctls = maps.Clone(base.sysctls)
	doctored.sysctls["kernel/core_pattern"] = "|/gone/handler"
	if d := doctored.sysctlsDiff(); !strings.Contains(d, `kernel/core_pattern: was "|/gone/handler"`) {
		t.Errorf("a sysctl that changed is not reported: %q", d)
	}
	doctored.cgroups = append(slices.Clone(base.cgroups), "ghost.slice")
	if d := doctored.cgroupsDiffNow(false); !strings.Contains(d, "-ghost.slice") {
		t.Errorf("a cgroup that went is not reported: %q", d)
	}
	doctored.subtree = base.subtree + " ghostcontroller"
	if note := doctored.subtreeNote(); !strings.Contains(note, "ghostcontroller") {
		t.Errorf("a controller that changed in the root is not noted: %q", note)
	}
	if note := base.subtreeNote(); note != "unchanged" {
		t.Errorf("subtreeNote on a host nothing touched = %q", note)
	}
	if d := lineDiff(base.mounts+"99 1 0:99 / /ghost rw - tmpfs tmpfs rw\n", mountinfoText()); !strings.Contains(d, "/ghost") {
		t.Errorf("a mount that went is not reported: %q", d)
	}

	// A helper that still runs is found, and no longer once it is gone.
	c, err := spawnChild(t, spawn{name: "idle"})
	if err != nil {
		t.Fatal(err)
	}
	mark := "pid " + strconv.Itoa(c.pid()) + " ("
	if d := helpersNow(); !strings.Contains(d, mark) {
		t.Errorf("a running helper (pid %d) is not reported: %q", c.pid(), d)
	}
	c.stop()
	if d := helpersNow(); strings.Contains(d, mark) {
		t.Errorf("a helper that was reaped is still reported: %q", d)
	}
}

// The readers of files, on files that need no privilege.
func TestSelfFileReaders(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	n, how := fill(file, 100<<10)
	if n < 100<<10 || how != "no error" {
		t.Errorf("fill wrote %d bytes and stopped on %q", n, how)
	}
	if fi, err := os.Stat(file); err != nil || fi.Size() != n {
		t.Errorf("fill reports %d bytes, the file has %v (%v)", n, fi, err)
	}
	want := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
	if got := ownerOf(file); got != want {
		t.Errorf("ownerOf = %q, want %q", got, want)
	}
	if got := ownerOf(filepath.Join(dir, "absent")); got != "ENOENT" {
		t.Errorf("ownerOf of a missing file = %q, want ENOENT", got)
	}
	if got := contentOf(filepath.Join(dir, "absent")); got != "ENOENT" {
		t.Errorf("contentOf of a missing file = %q, want ENOENT", got)
	}
	if got := readOr(filepath.Join(dir, "absent")); got != "unreadable (ENOENT)" {
		t.Errorf("readOr of a missing file = %q", got)
	}
	if got := firstLine("/proc/self/exe", childArg, "echo", "fail"); !strings.Contains(got, "asked to fail") {
		t.Errorf("firstLine of a failing command does not say why: %q", got)
	}
}
