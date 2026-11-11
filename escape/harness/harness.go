//go:build linux

// Package harness runs the escape cases of package escape against real
// backends and collects host-side evidence for escape.Judge.
//
// It needs root and changes nothing on the host except temporary files
// under its work directory, two TCP listeners, and the sandboxes themselves.
// Some cases poke at host interfaces from inside the sandbox; if isolation
// fails they could change host state. Run it on a throwaway machine.
package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/camilbenameur/ringfence/engine"
	"github.com/camilbenameur/ringfence/escape"
	"github.com/camilbenameur/ringfence/policy"
)

// Harness runs cases.
type Harness struct {
	Engine *engine.Engine
	Image  string
	// Probe is the path of a static rfprobe binary for the sandbox's arch.
	Probe string
	// WorkDir holds canaries, markers and the probe layer. It must be
	// outside every sandbox root.
	WorkDir string
	// Log receives one line per case run.
	Log func(string)
}

// hostFiles are host values some cases try to change; they are compared
// before and after every case.
var hostFiles = []string{
	"/proc/sys/kernel/core_pattern",
	"/proc/sys/kernel/hostname",
	"/sys/kernel/uevent_helper",
	"/proc/sys/kernel/modprobe",
}

func readHost() map[string]string {
	m := map[string]string{}
	for _, f := range hostFiles {
		if b, err := os.ReadFile(f); err == nil {
			m[f] = string(b)
		}
	}
	return m
}

// primaryIP is the address the host uses to reach the internet. Dialing UDP
// sends no packet; it only selects the route.
func primaryIP() (string, error) {
	c, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		return "", err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String(), nil
}

// Run plays every case on every backend, sequentially.
func (h *Harness) Run(ctx context.Context, backends []string) ([]escape.Verdict, error) {
	cases, err := escape.Cases()
	if err != nil {
		return nil, err
	}
	// The canaries must be readable by the sandbox uid if it ever reached
	// them: the suite measures namespace isolation, not Unix permissions, so
	// an escape must not be scored "blocked" because of a 0600 file. The work
	// directory and its parents are therefore traversable (0711).
	if err := os.MkdirAll(h.WorkDir, 0o711); err != nil {
		return nil, err
	}
	if err := os.Chmod(h.WorkDir, 0o711); err != nil {
		return nil, err
	}
	layer, err := h.probeLayer(cases)
	if err != nil {
		return nil, err
	}
	ip, err := primaryIP()
	if err != nil {
		return nil, fmt.Errorf("find primary address: %w", err)
	}
	egress, err := escape.NewListener(net.JoinHostPort(ip, "0"))
	if err != nil {
		return nil, err
	}
	defer egress.Close()
	// The gateway listener binds every address, including the host side of
	// each sandbox's veth pair, which is only known once a command starts.
	gateway, err := escape.NewListener("0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	defer gateway.Close()

	var out []escape.Verdict
	for _, b := range backends {
		for _, c := range cases {
			v, err := h.runCase(ctx, b, c, layer, ip, egress, gateway)
			if err != nil {
				v = escape.Verdict{CaseID: c.ID, Backend: b, Outcome: "error", Reason: err.Error()}
			}
			if h.Log != nil {
				h.Log(fmt.Sprintf("%-8s %-28s %-8s %s", b, c.ID, v.Outcome, v.Reason))
			}
			out = append(out, v)
		}
	}
	return out, nil
}

// probeLayer builds a read-only layer with /usr/local/bin/rfprobe and
// /escape/<id>.sh, owned by the sandbox's root.
func (h *Harness) probeLayer(cases []escape.Case) (string, error) {
	dir := filepath.Join(h.WorkDir, "layer")
	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	for _, d := range []string{"usr/local/bin", "escape"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			return "", err
		}
	}
	probe, err := os.ReadFile(h.Probe)
	if err != nil {
		return "", fmt.Errorf("read rfprobe: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "usr/local/bin/rfprobe"), probe, 0o755); err != nil {
		return "", err
	}
	for _, c := range cases {
		if err := os.WriteFile(filepath.Join(dir, "escape", c.ID+".sh"), []byte(c.Script), 0o755); err != nil {
			return "", err
		}
	}
	// The layer must be traversable by the sandbox root (host uid 100000);
	// 0755 directories and files are enough, ownership stays root.
	return dir, os.Chmod(dir, 0o755)
}

func (h *Harness) runCase(ctx context.Context, backend string, c escape.Case, layer, ip string,
	egress, gateway *escape.Listener) (escape.Verdict, error) {
	caseDir, err := os.MkdirTemp(h.WorkDir, c.ID+"-")
	if err != nil {
		return escape.Verdict{}, err
	}
	defer os.RemoveAll(caseDir)
	if err := os.Chmod(caseDir, 0o711); err != nil {
		return escape.Verdict{}, err
	}
	canaryPath, token, err := escape.NewCanary(caseDir)
	if err != nil {
		return escape.Verdict{}, err
	}
	if err := os.Chmod(canaryPath, 0o644); err != nil {
		return escape.Verdict{}, err
	}
	marker := filepath.Join(caseDir, "marker")

	p := policy.Default()
	p.Limits.Wall = (c.Timeout + 10*time.Second).String()
	if c.ID == "13-fork-bomb" {
		// A tight pids limit makes the bomb hit EAGAIN after a handful of
		// forks. The default 256 lets it spawn a thousand processes first,
		// which under gVisor exhausts the Sentry's own memory and gets the
		// whole sandbox OOM-killed before it can report the refusal.
		p.Limits.PIDs = 32
	}
	if c.Needs["network"] == "allowlist" {
		// An allowlist that does not contain any listener: TEST-NET-1 discard port.
		p.Network = policy.Network{Mode: "allowlist", Allow: []string{"192.0.2.1:9"}}
	}
	memLimit, err := policy.ParseBytes(p.Limits.Memory)
	if err != nil {
		return escape.Verdict{}, err
	}
	_, egressPort, _ := net.SplitHostPort(egress.Addr().String())
	_, gatewayPort, _ := net.SplitHostPort(gateway.Addr().String())
	env := []string{
		"RF_HOST_CANARY_PATH=" + canaryPath,
		"RF_HOST_MARKER_PATH=" + marker,
		"RF_EGRESS_IP=" + ip,
		"RF_EGRESS_PORT=" + egressPort,
		"RF_GATEWAY_IP=auto",
		"RF_GATEWAY_PORT=" + gatewayPort,
		"RF_PIDS_LIMIT=" + strconv.FormatInt(p.Limits.PIDs, 10),
		"RF_MEMORY_LIMIT_BYTES=" + strconv.FormatInt(memLimit, 10),
	}

	before := readHost()
	egressBefore, gatewayBefore := egress.Hits(), gateway.Hits()
	s, err := h.Engine.Start(ctx, backend, h.Image, p, engine.WithExtraLayer(layer), engine.WithEnv(env...))
	if err != nil {
		return escape.Verdict{}, err
	}
	o, runErr := s.Run(ctx, []string{"sh", "/escape/" + c.ID + ".sh"})
	stopErr := s.Stop(context.Background())
	if runErr != nil {
		return escape.Verdict{}, runErr
	}
	if stopErr != nil {
		return escape.Verdict{}, fmt.Errorf("stop: %w", stopErr)
	}
	// Let late connections reach the listeners before counting.
	time.Sleep(200 * time.Millisecond)

	recJSON, err := json.Marshal(o.Receipt)
	if err != nil {
		return escape.Verdict{}, err
	}
	ev := escape.Evidence{
		ExitCode:         o.Result.ExitCode,
		Killed:           o.Result.Killed,
		Stdout:           string(o.Result.Stdout),
		Stderr:           string(o.Result.Stderr),
		ReceiptJSON:      string(recJSON),
		CanaryToken:      token,
		EgressHits:       egress.Hits() - egressBefore,
		GatewayHits:      gateway.Hits() - gatewayBefore,
		Stats:            o.Result.Stats,
		PIDsLimit:        p.Limits.PIDs,
		MemoryLimitBytes: memLimit,
	}
	if _, err := os.Lstat(marker); err == nil {
		ev.MarkerExists = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return escape.Verdict{}, err
	}
	after := readHost()
	for f, v := range before {
		if after[f] != v {
			ev.HostChanged = append(ev.HostChanged, fmt.Sprintf("%s: %q -> %q", f, strings.TrimSpace(v), strings.TrimSpace(after[f])))
		}
	}
	for _, conn := range o.Result.Connections {
		if conn.Allowed && !allowed(p, conn.DstIP, conn.DstPort) {
			ev.HostChanged = append(ev.HostChanged, fmt.Sprintf("firewall allowed %s %s:%d outside the allowlist", conn.Proto, conn.DstIP, conn.DstPort))
		}
	}
	return escape.Judge(c, backend, ev), nil
}

func allowed(p policy.Policy, ip string, port uint16) bool {
	want := net.JoinHostPort(ip, strconv.Itoa(int(port)))
	for _, a := range p.Network.Allow {
		if a == want {
			return true
		}
	}
	return false
}
