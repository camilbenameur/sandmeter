package seccomp

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// run interprets prog over one seccomp_data and returns the filter verdict.
// It implements only the opcodes Build emits and fails on anything else, so a
// change in the emitted code shows up as a test failure, not a silent pass.
func run(t *testing.T, prog []unix.SockFilter, data []byte) uint32 {
	t.Helper()
	var acc uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.Code {
		case opLoad:
			if int(in.K)+4 > len(data) {
				t.Fatalf("pc %d: load at %d out of range", pc, in.K)
			}
			acc = binary.LittleEndian.Uint32(data[in.K:])
		case opJeq, opJset:
			cond := acc == in.K
			if in.Code == opJset {
				cond = acc&in.K != 0
			}
			if cond {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
			if pc >= len(prog)-1 {
				t.Fatalf("jump past end of program")
			}
		case opRet:
			return in.K
		default:
			t.Fatalf("pc %d: unsupported opcode %#x", pc, in.Code)
		}
	}
	t.Fatal("program fell off the end")
	return 0
}

// seccompData encodes struct seccomp_data little-endian: nr, arch, ip, args[6].
func seccompData(nr uint32, arch uint32, arg0 uint64) []byte {
	b := make([]byte, 64)
	binary.LittleEndian.PutUint32(b[0:], nr)
	binary.LittleEndian.PutUint32(b[4:], arch)
	binary.LittleEndian.PutUint64(b[16:], arg0)
	return b
}

const sigchld = 17 // exit signal in the low byte of clone flags

func buildDefault(t *testing.T) []unix.SockFilter {
	t.Helper()
	prog, err := Default().Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return prog
}

func TestVerdicts(t *testing.T) {
	prog := buildDefault(t)
	nr := func(name string) uint32 { return uint32(syscallNumbers[name]) }

	type verdictCase struct {
		name string
		nr   uint32
		arch uint32
		arg0 uint64
		want uint32
	}
	tests := []verdictCase{
		{"read", unix.SYS_READ, nativeArch, 0, retAllow},
		{"write", unix.SYS_WRITE, nativeArch, 0, retAllow},
		{"getpid", unix.SYS_GETPID, nativeArch, 0, retAllow},
		{"clone plain fork", unix.SYS_CLONE, nativeArch, sigchld, retAllow},
		{"clone thread flags", unix.SYS_CLONE, nativeArch, unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES | unix.CLONE_SIGHAND | unix.CLONE_THREAD, retAllow},
		{"mount", nr("mount"), nativeArch, 0, retEPERM},
		{"unshare", nr("unshare"), nativeArch, 0, retEPERM},
		{"setns", nr("setns"), nativeArch, 0, retEPERM},
		{"keyctl", nr("keyctl"), nativeArch, 0, retEPERM},
		{"ptrace", nr("ptrace"), nativeArch, 0, retEPERM},
		{"io_uring_setup", nr("io_uring_setup"), nativeArch, 0, retEPERM},
		{"bpf", nr("bpf"), nativeArch, 0, retEPERM},
		{"pidfd_getfd", nr("pidfd_getfd"), nativeArch, 0, retEPERM},
		{"process_madvise", nr("process_madvise"), nativeArch, 0, retEPERM},
		{"kcmp", nr("kcmp"), nativeArch, 0, retEPERM},
		{"quotactl_fd", nr("quotactl_fd"), nativeArch, 0, retEPERM},
		{"clone newuser", unix.SYS_CLONE, nativeArch, unix.CLONE_NEWUSER | sigchld, retEPERM},
		{"clone newns", unix.SYS_CLONE, nativeArch, unix.CLONE_NEWNS, retEPERM},
		{"clone newnet", unix.SYS_CLONE, nativeArch, unix.CLONE_NEWNET, retEPERM},
		{"clone newtime", unix.SYS_CLONE, nativeArch, unix.CLONE_NEWTIME, retEPERM},
		// A bit in the high word must not be mistaken for a namespace flag.
		{"clone high word ignored", unix.SYS_CLONE, nativeArch, 1<<40 | sigchld, retAllow},
		{"clone3", unix.SYS_CLONE3, nativeArch, 0, retENOSYS},
		{"wrong arch", unix.SYS_READ, nativeArch ^ 0x40000000, 0, retKillProcess},
		{"arch zero", unix.SYS_READ, 0, 0, retKillProcess},
	}
	if x32Bit != 0 {
		tests = append(tests, verdictCase{"x32 read", x32Bit | unix.SYS_READ, nativeArch, 0, retEPERM})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(t, prog, seccompData(tc.nr, tc.arch, tc.arg0)); got != tc.want {
				t.Errorf("verdict = %#x, want %#x", got, tc.want)
			}
		})
	}
}

func TestEveryDeniedNameIsEPERM(t *testing.T) {
	p := Default()
	prog := buildDefault(t)
	for _, name := range p.Names() {
		nr, ok := syscallNumbers[name]
		if !ok {
			if !archOptional[name] {
				t.Errorf("%s: missing from table and not arch-optional", name)
			}
			continue
		}
		if got := run(t, prog, seccompData(nr, nativeArch, 0)); got != retEPERM {
			t.Errorf("%s: verdict %#x, want EPERM", name, got)
		}
	}
}

func TestProgramShape(t *testing.T) {
	prog := buildDefault(t)
	if len(prog) > 4096 {
		t.Fatalf("%d instructions exceeds the kernel limit", len(prog))
	}
	last := prog[len(prog)-1]
	if last.Code != opRet || last.K != retAllow {
		t.Errorf("last instruction = %+v, want RET ALLOW", last)
	}
	for pc, in := range prog {
		if in.Code != opJeq && in.Code != opJset {
			continue
		}
		// jt/jf are uint8, so the 255 limit holds by type; what can go wrong
		// is a target that lands outside the program or on the wrong line.
		for _, off := range []int{int(in.Jt), int(in.Jf)} {
			if pc+1+off >= len(prog) {
				t.Errorf("pc %d jumps to %d, past end %d", pc, pc+1+off, len(prog))
			}
			if off > 3 {
				t.Errorf("pc %d jumps %d instructions; the generator should never need more than 3", pc, off)
			}
		}
	}
	// No syscall number may crash the interpreter or fall off the program.
	for nr := uint32(0); nr < 1000; nr++ {
		run(t, prog, seccompData(nr, nativeArch, 0))
	}
}

func TestLongListKeepsOffsetsSmall(t *testing.T) {
	// Denying the whole table is the longest program this package can build;
	// offsets must stay small however many entries precede them.
	var names []string
	for n := range syscallNumbers {
		names = append(names, n)
	}
	prog, err := Profile{Denied: names}.Build()
	if err != nil {
		t.Fatal(err)
	}
	for pc, in := range prog {
		if (in.Code == opJeq || in.Code == opJset) && (in.Jt > 3 || in.Jf > 3) {
			t.Errorf("pc %d: jt=%d jf=%d", pc, in.Jt, in.Jf)
		}
	}
}

func TestNoNamespaceFlagsMeansCloneAllowed(t *testing.T) {
	prog, err := Profile{Denied: []string{"mount"}}.Build()
	if err != nil {
		t.Fatal(err)
	}
	if got := run(t, prog, seccompData(unix.SYS_CLONE, nativeArch, unix.CLONE_NEWUSER)); got != retAllow {
		t.Errorf("clone verdict = %#x, want ALLOW", got)
	}
	if got := run(t, prog, seccompData(unix.SYS_CLONE3, nativeArch, 0)); got != retAllow {
		t.Errorf("clone3 verdict = %#x, want ALLOW", got)
	}
}

func TestUnknownName(t *testing.T) {
	_, err := Profile{Denied: []string{"mount", "no_such_syscall"}}.Build()
	if err == nil || !strings.Contains(err.Error(), "no_such_syscall") {
		t.Fatalf("err = %v, want unknown-syscall error naming the syscall", err)
	}
}

func TestArchOptionalSkipped(t *testing.T) {
	prog, err := Profile{Denied: []string{"iopl", "ioperm", "uselib", "_sysctl", "nfsservctl"}}.Build()
	if err != nil {
		t.Fatalf("optional names must not error: %v", err)
	}
	for name := range archOptional {
		nr, ok := syscallNumbers[name]
		if !ok {
			continue
		}
		if got := run(t, prog, seccompData(nr, nativeArch, 0)); got != retEPERM {
			t.Errorf("%s present on %s but not denied", name, runtime.GOARCH)
		}
	}
}

func TestNames(t *testing.T) {
	got := Profile{Denied: []string{"ptrace", "bpf", "mount", "bpf"}}.Names()
	want := []string{"bpf", "mount", "ptrace"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("Names = %v, want %v", got, want)
	}
	if !sort.StringsAreSorted(Default().Names()) {
		t.Error("Default().Names() not sorted")
	}
}

func TestDefaultDoesNotAliasPackageList(t *testing.T) {
	p := Default()
	p.Denied[0] = "changed"
	if Default().Denied[0] == "changed" {
		t.Error("Default shares its backing array across calls")
	}
}

func TestInstallEmpty(t *testing.T) {
	if err := Install(nil); err == nil {
		t.Error("Install(nil) succeeded")
	}
}

func TestInstallTooLong(t *testing.T) {
	// 65537 would wrap to length 1 in the uint16 field if unchecked.
	for _, n := range []int{maxInsns + 1, 65537} {
		if err := Install(make([]unix.SockFilter, n)); err == nil {
			t.Errorf("Install with %d instructions succeeded", n)
		}
	}
}
