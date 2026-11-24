package client

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/camilbenameur/sandmeter/internal/ctl"
	"github.com/camilbenameur/sandmeter/internal/exit"
)

func TestErrorTextAndCode(t *testing.T) {
	err := FromMessage(ctl.Error{
		Code:    ctl.CodePolicyRefused,
		Message: "the policy is refused",
		Reasons: []ctl.Reason{
			{Code: ctl.CodePolicyRefused, Key: "limits.memory", Text: "8GiB is above the ceiling of 512MiB"},
			{Code: ctl.CodePolicyRefused, Key: "network.mode", Text: "proxy is not granted by the ceiling"},
		},
	})
	want := "the policy is refused\n  limits.memory: 8GiB is above the ceiling of 512MiB\n  network.mode: proxy is not granted by the ceiling"
	if err.Error() != want {
		t.Errorf("Error() =\n%s\nwant\n%s", err.Error(), want)
	}
	wrapped := fmt.Errorf("start: %w", err)
	if CodeOf(wrapped) != ctl.CodePolicyRefused {
		t.Errorf("CodeOf through a wrap = %q", CodeOf(wrapped))
	}
	if CodeOf(errors.New("plain")) != "" || CodeOf(nil) != "" {
		t.Error("CodeOf found a code in an error that is not a refusal")
	}

	internal := FromMessage(ctl.Error{Code: ctl.CodeInternal, Incident: "7f3a"})
	if got := internal.Error(); !strings.Contains(got, "internal") || !strings.Contains(got, "incident 7f3a") {
		t.Errorf("an internal error without a message reads %q", got)
	}
}

func TestExitStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, exit.OK},
		{"policy refused", &Error{Code: ctl.CodePolicyRefused}, exit.PolicyRefused},
		{"budget", fmt.Errorf("start: %w", &Error{Code: ctl.CodeBudget}), exit.Denied},
		{"host", &Error{Code: ctl.CodeHost}, exit.HostCannotRun},
		{"invalid", &Error{Code: ctl.CodeInvalid}, exit.Usage},
		{"internal", &Error{Code: ctl.CodeInternal}, exit.Failure},
		{"no service", fmt.Errorf("dial /run/sandmeter/sandmeter.sock: %w: enable the socket unit", ErrUnavailable), exit.HostCannotRun},
		{"connection lost", ErrClosed, exit.Failure},
		{"not built", ErrNotBuilt, exit.Failure},
		{"anything else", context.DeadlineExceeded, exit.Failure},
	} {
		if got := ExitStatus(tc.err); got != tc.want {
			t.Errorf("%s: ExitStatus = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// TestConstructorsAreNotBuiltAndSaySo holds the two constructors to their
// stub: until they are written they return the sentinel, never a client that
// half works. Both are pointed at paths that do not exist, so that the test
// stays harmless once they are written; it then has nothing left to say.
func TestConstructorsAreNotBuiltAndSaySo(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "absent")
	c, err := Dial(context.Background(), DialOptions{Socket: absent})
	if !errors.Is(err, ErrNotBuilt) {
		t.Skipf("Dial is built (%v): this test goes with the stub", err)
	}
	if c != nil {
		t.Error("the stub of Dial returned a client")
	}
	c, err = Direct(context.Background(), DirectOptions{Sandmeterd: absent})
	if !errors.Is(err, ErrNotBuilt) {
		t.Skipf("Direct is built (%v): this test goes with the stub", err)
	}
	if c != nil {
		t.Error("the stub of Direct returned a client")
	}
}

// TestNoHostPathInTheInterfaces states the boundary on the two interfaces:
// no method takes a string or a slice of strings, which is the only shape a
// path chosen by the caller could take. What a caller hands over is a
// request struct, an identifier, a number, a reader or a writer.
func TestNoHostPathInTheInterfaces(t *testing.T) {
	for _, iface := range []reflect.Type{reflect.TypeFor[Client](), reflect.TypeFor[Session]()} {
		for i := range iface.NumMethod() {
			m := iface.Method(i)
			for j := range m.Type.NumIn() {
				in := m.Type.In(j)
				if in.Kind() == reflect.String || (in.Kind() == reflect.Slice && in.Elem().Kind() == reflect.String) {
					t.Errorf("%s.%s takes a %s", iface.Name(), m.Name, in)
				}
			}
		}
	}
	// The requests hold strings; each is one of these, and none is a path
	// on the host.
	reviewed := map[string]bool{
		"StartRequest.Policy": true, "StartRequest.Image": true, "StartRequest.Backend": true,
		"RunRequest.Argv": true, "RunRequest.Workdir": true,
	}
	for _, typ := range []reflect.Type{reflect.TypeFor[StartRequest](), reflect.TypeFor[RunRequest]()} {
		for i := range typ.NumField() {
			f := typ.Field(i)
			leaf := f.Type
			if leaf.Kind() == reflect.Slice {
				leaf = leaf.Elem()
			}
			name := typ.Name() + "." + f.Name
			if leaf.Kind() == reflect.String && !reviewed[name] {
				t.Errorf("%s is a string a caller can send and is not in the reviewed list", name)
			}
		}
	}
}
