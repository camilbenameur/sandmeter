//go:build integration && linux

package kernelfacts

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// K1: the egress listener of proxy mode.
//
// The sandbox's network namespace has loopback only. The init creates a
// listener on 127.0.0.1 inside it and hands the descriptor to the
// supervisor with SCM_RIGHTS; the supervisor's proxy then accepts in the
// sandbox's namespace and dials from the host's. Nothing is created in the
// host's network namespace. The design rests on one kernel fact that was
// never run: a socket stays in the namespace it was created in, whoever
// holds it.

// k1Ready is what the helper in the namespace saw up to the moment the test
// may look at the host.
type k1Ready struct {
	Links   []string `json:"links"`   // interfaces of the fresh namespace
	Echo    string   `json:"echo"`    // reply read over the listener it passed out, or what went wrong
	Direct4 string   `json:"direct4"` // result of a direct connect to a public IPv4 address
	Direct6 string   `json:"direct6"` // the same over IPv6
}

// k1Result is what it saw of the listener the test created with setns.
type k1Result struct {
	Setns string `json:"setns"` // reply read, "skipped", or what went wrong
}

// The public addresses of a well-known resolver. No packet leaves: the
// namespace has no route to them, which is the fact under test.
const (
	publicV4 = "1.1.1.1:443"
	publicV6 = "[2606:4700:4700::1111]:443"
)

// k1Control is the descriptor of the socket pair in the helper.
const k1Control = 3

// childK1 plays the init: it runs in a new user and network namespace.
func childK1(args []string) error {
	if len(args) != 3 {
		return errors.New("usage: k1netns PORT SETNS-PORT NONCE")
	}
	if err := outsideHost("net", hostNetEnv); err != nil {
		return err
	}
	port, err := strconv.Atoi(args[0])
	if err != nil {
		return err
	}
	setnsPort, err := strconv.Atoi(args[1])
	if err != nil {
		return err
	}
	nonce := args[2]

	var rdy k1Ready
	ifs, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("list the interfaces: %w", err)
	}
	for _, i := range ifs {
		rdy.Links = append(rdy.Links, i.Name)
	}
	if err := loopbackUp(); err != nil {
		return err
	}
	lfd, err := listenLoopback(port)
	if err != nil {
		return err
	}
	// The descriptor goes to the supervisor and this process keeps no copy.
	if err := unix.Sendmsg(k1Control, []byte{'L'}, unix.UnixRights(lfd), nil, 0); err != nil {
		return fmt.Errorf("pass the listener with SCM_RIGHTS: %w", err)
	}
	unix.Close(lfd)

	rdy.Echo = dialEcho(port, nonce)
	rdy.Direct4 = dialOutcome("tcp4", publicV4)
	rdy.Direct6 = dialOutcome("tcp6", publicV6)
	if err := sayReady(rdy); err != nil {
		return err
	}

	// One byte from the test: 'S' when it has a second listener, created by
	// one of its own threads after setns; anything else when it has not.
	res := k1Result{Setns: "skipped"}
	buf := make([]byte, 1)
	if n, err := unix.Read(k1Control, buf); err != nil {
		res.Setns = "read the control socket: " + errnoName(err)
	} else if n == 1 && buf[0] == 'S' {
		res.Setns = dialEcho(setnsPort, nonce)
	}
	return sayResult(res)
}

// loopbackUp brings lo up with one ioctl (netdevice(7)).
func loopbackUp() error {
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer unix.Close(s)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(s, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("read the flags of lo: %w", err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(s, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("bring lo up: %w", err)
	}
	return nil
}

// listenLoopback creates a TCP listener on 127.0.0.1 in the network
// namespace of the calling thread.
func listenLoopback(port int) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("bind 127.0.0.1:%d: %w", port, err)
	}
	if err := unix.Listen(fd, 8); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("listen on 127.0.0.1:%d: %w", port, err)
	}
	return fd, nil
}

// dialEcho connects to 127.0.0.1:port, sends the nonce and returns the line
// it reads back. On failure it returns the step and the errno.
func dialEcho(port int, nonce string) string {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return "connect: " + errnoName(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := fmt.Fprintf(conn, "%s\n", nonce); err != nil {
		return "write: " + errnoName(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "read: " + errnoName(err)
	}
	return strings.TrimSpace(line)
}

// dialOutcome tries a direct connection and names what the kernel answered.
func dialOutcome(network, addr string) string {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.Dial(network, addr)
	if err != nil {
		return errnoName(err)
	}
	conn.Close()
	return "connected"
}

// serveEcho accepts one connection, checks that it carries the nonce and
// answers. It returns "" when all of that happened.
func serveEcho(ln net.Listener, nonce string) string {
	if d, ok := ln.(interface{ SetDeadline(time.Time) error }); ok {
		_ = d.SetDeadline(time.Now().Add(10 * time.Second))
	}
	conn, err := ln.Accept()
	if err != nil {
		return "accept: " + errnoName(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "read: " + errnoName(err)
	}
	if got := strings.TrimSpace(line); got != nonce {
		return fmt.Sprintf("read %q where the nonce %q was expected", got, nonce)
	}
	if _, err := fmt.Fprintf(conn, "ack %s\n", nonce); err != nil {
		return "write: " + errnoName(err)
	}
	return ""
}

// receiveFD reads one message from a Unix socket and returns the descriptor
// it carries.
func receiveFD(sock int) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := unix.Recvmsg(sock, buf, oob, unix.MSG_CMSG_CLOEXEC)
	if err != nil {
		return -1, fmt.Errorf("recvmsg: %w", err)
	}
	if n == 0 {
		return -1, errors.New("the helper closed the control socket without sending anything")
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, fmt.Errorf("parse the control message: %w", err)
	}
	for _, m := range msgs {
		fds, err := unix.ParseUnixRights(&m)
		if err != nil {
			continue
		}
		if len(fds) == 1 {
			return fds[0], nil
		}
		for _, fd := range fds {
			unix.Close(fd)
		}
	}
	return -1, errors.New("the message carried no descriptor")
}

// checkListener is what the supervisor does with a descriptor that comes
// from inside a sandbox: it reads from the kernel what the descriptor is,
// and takes nothing on trust.
func checkListener(fd, port int) (string, error) {
	acc, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	if err != nil {
		return "", fmt.Errorf("SO_ACCEPTCONN: %w", err)
	}
	domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil {
		return "", fmt.Errorf("SO_DOMAIN: %w", err)
	}
	typ, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		return "", fmt.Errorf("SO_TYPE: %w", err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return "", fmt.Errorf("getsockname: %w", err)
	}
	bound := fmt.Sprintf("%T", sa)
	in4, isV4 := sa.(*unix.SockaddrInet4)
	if isV4 {
		bound = fmt.Sprintf("%s:%d", net.IP(in4.Addr[:]), in4.Port)
	}
	what := fmt.Sprintf("the descriptor received is a socket with SO_ACCEPTCONN=%d, domain %d, type %d, bound to %s", acc, domain, typ, bound)
	if acc != 1 || domain != unix.AF_INET || typ != unix.SOCK_STREAM || !isV4 || in4.Port != port || in4.Addr != [4]byte{127, 0, 0, 1} {
		return what, fmt.Errorf("expected a listening AF_INET stream socket bound to 127.0.0.1:%d", port)
	}
	return what, nil
}

// adoptListener turns a listening descriptor into a net.Listener.
func adoptListener(fd int) (net.Listener, error) {
	f := os.NewFile(uintptr(fd), "listener")
	defer f.Close() // FileListener works on a duplicate
	return net.FileListener(f)
}

// listenInNetns is the fallback of K1: a thread of this process enters the
// network namespace of pid and creates the listener there.
//
// The thread is locked and never unlocked, so the runtime ends it when the
// goroutine returns (runtime.LockOSThread): no thread that has been in a
// sandbox's namespace runs anything else afterwards.
func listenInNetns(pid, port int) (int, error) {
	type result struct {
		fd  int
		err error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		ns, err := unix.Open(fmt.Sprintf("/proc/%d/ns/net", pid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			done <- result{-1, fmt.Errorf("open the network namespace of pid %d: %w", pid, err)}
			return
		}
		defer unix.Close(ns)
		if err := unix.Setns(ns, unix.CLONE_NEWNET); err != nil {
			done <- result{-1, fmt.Errorf("setns: %w", err)}
			return
		}
		fd, err := listenLoopback(port)
		done <- result{fd, err}
	}()
	r := <-done
	return r.fd, r.err
}

// netPart is one named piece of the host's network configuration.
type netPart struct{ name, text string }

// expires matches the countdown iproute2 prints for routes learnt from a
// router advertisement; it changes every second and is not configuration.
var expires = regexp.MustCompile(` expires -?[0-9]+sec`)

// snapshotNetwork reads what a sandbox must never change in the host's
// network namespace: links, addresses, routes of every table, the
// forwarding switches and, when nft is installed, the ruleset.
func snapshotNetwork() []netPart {
	var parts []netPart

	var links []string
	ifs, err := net.Interfaces()
	if err != nil {
		links = append(links, "unreadable: "+err.Error())
	}
	for _, i := range ifs {
		line := fmt.Sprintf("%d %s mtu %d %s %s", i.Index, i.Name, i.MTU, i.Flags, i.HardwareAddr)
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			line += " " + a.String()
		}
		links = append(links, line)
	}
	parts = append(parts, netPart{"links and addresses", strings.Join(links, "\n")})

	if ip, err := exec.LookPath("ip"); err == nil {
		for _, family := range []string{"-4", "-6"} {
			out, err := exec.Command(ip, family, "route", "show", "table", "all").CombinedOutput()
			text := expires.ReplaceAllString(string(out), "")
			if err != nil {
				text = fmt.Sprintf("ip %s route failed: %v: %s", family, err, out)
			}
			parts = append(parts, netPart{"routes (ip " + family + " route show table all)", text})
		}
	} else {
		parts = append(parts, netPart{"IPv4 routes (/proc/net/route)", readOr("/proc/net/route")})
	}

	parts = append(parts,
		netPart{"net.ipv4.ip_forward", readOr("/proc/sys/net/ipv4/ip_forward")},
		netPart{"net.ipv6.conf.all.forwarding", readOr("/proc/sys/net/ipv6/conf/all/forwarding")},
	)

	if nft, err := exec.LookPath("nft"); err == nil {
		// -s leaves the packet counters out: they move with any traffic.
		out, err := exec.Command(nft, "-s", "list", "ruleset").CombinedOutput()
		text := string(out)
		if err != nil {
			text = fmt.Sprintf("nft -s list ruleset failed: %v: %s", err, out)
		}
		parts = append(parts, netPart{"nft ruleset", text})
	}
	return parts
}

// diffNetwork says which parts differ between two snapshots.
func diffNetwork(a, b []netPart) string {
	var out []string
	for i := range a {
		if i >= len(b) || a[i].name != b[i].name {
			out = append(out, a[i].name+": not comparable")
			continue
		}
		if d := lineDiff(a[i].text, b[i].text); d != "" {
			out = append(out, a[i].name+": "+d)
		}
	}
	return strings.Join(out, " | ")
}

// describeNetwork says what a snapshot covered, for the detail of the fact.
func describeNetwork(parts []netPart) string {
	var names []string
	hasNft := false
	for _, p := range parts {
		names = append(names, p.name)
		hasNft = hasNft || p.name == "nft ruleset"
	}
	s := "compared: " + strings.Join(names, ", ")
	if !hasNft {
		s += "; nft is not installed, so no ruleset was compared"
	}
	return s
}

func TestK1LoopbackListener(t *testing.T) {
	r := declare(t, "K1", "K1-unreach", "K1-links", "K1-host", "K1-setns")
	r.needRoot()

	// 3128 is the port of the design; the second one is for the fallback.
	const port, setnsPort = 3128, 3129
	nonce := fmt.Sprintf("kf-%d-%d", os.Getpid(), time.Now().UnixNano())

	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	control := pair[0]
	defer unix.Close(control)
	theirs := os.NewFile(uintptr(pair[1]), "control")
	// A helper that stops answering must not hold the test on this socket.
	if err := unix.SetsockoptTimeval(control, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 20}); err != nil {
		t.Fatalf("SO_RCVTIMEO: %v", err)
	}

	before := snapshotNetwork()

	c, err := spawnChild(t, spawn{
		name:   "k1netns",
		args:   []string{strconv.Itoa(port), strconv.Itoa(setnsPort), nonce},
		clone:  unix.CLONE_NEWNET,
		userns: true,
		files:  []*os.File{theirs},
	})
	theirs.Close()
	if err != nil {
		r.no("K1", "a helper in a new user and network namespace did not start: %v", err)
		return
	}

	// The listener arrives, and what arrives is checked.
	lfd, err := receiveFD(control)
	if err != nil {
		r.no("K1", "no listener arrived over the control socket: %v; helper stderr: %q", err, c.stderr())
		return
	}
	what, err := checkListener(lfd, port)
	if err != nil {
		unix.Close(lfd)
		r.no("K1", "%s: %v", what, err)
		return
	}
	ln, err := adoptListener(lfd)
	if err != nil {
		r.no("K1", "%s, but net.FileListener refused it: %v", what, err)
		return
	}
	defer ln.Close()

	// The helper connects from inside; the accept happens here, in the
	// host's network namespace.
	served := serveEcho(ln, nonce)
	var rdy k1Ready
	if err := c.ready(&rdy); err != nil {
		r.no("K1", "%s; accept in the host namespace: %s; then: %v", what, orOK(served), err)
		return
	}
	during := snapshotNetwork()

	want := "ack " + nonce
	r.judge("K1", served == "" && rdy.Echo == want,
		"%s; accept, read and answer in the host namespace: %s; the helper inside read %q (expected %q)", what, orOK(served), rdy.Echo, want)
	r.judge("K1-unreach", rdy.Direct4 == "ENETUNREACH",
		"connect from inside to %s: %s (expected ENETUNREACH); to %s: %s", publicV4, rdy.Direct4, publicV6, rdy.Direct6)
	r.judge("K1-links", slices.Equal(rdy.Links, []string{"lo"}),
		"interfaces of the fresh namespace: %v (expected [lo])", rdy.Links)

	// The fallback, recorded and not required: a thread of this process
	// enters the namespace and creates the listener itself.
	fd2, err := listenInNetns(c.pid(), setnsPort)
	if err != nil {
		_, _ = unix.Write(control, []byte{'N'})
		r.no("K1-setns", "a locked thread could not create the listener: %v", err)
	} else {
		ln2, err := adoptListener(fd2)
		if err != nil {
			_, _ = unix.Write(control, []byte{'N'})
			r.no("K1-setns", "net.FileListener refused the listener created after setns: %v", err)
		} else {
			defer ln2.Close()
			if _, err := unix.Write(control, []byte{'S'}); err != nil {
				t.Errorf("write to the control socket: %v", err)
			}
			served2 := serveEcho(ln2, nonce)
			var res k1Result
			if err := c.result(&res); err != nil {
				r.no("K1-setns", "accept in the host namespace: %s; then: %v", orOK(served2), err)
			} else {
				r.judge("K1-setns", served2 == "" && res.Setns == want,
					"accept, read and answer in the host namespace: %s; the helper inside read %q (expected %q)", orOK(served2), res.Setns, want)
			}
		}
	}
	c.stop()

	after := snapshotNetwork()
	d1, d2 := diffNetwork(before, during), diffNetwork(before, after)
	r.judge("K1-host", d1 == "" && d2 == "",
		"%s; changed while the namespace existed: %s; changed after it was gone: %s", describeNetwork(before), orNothing(d1), orNothing(d2))
}

// The socket half of K1: a listener is passed over a socket pair, examined,
// adopted, and serves one connection.
func TestSelfListenerPassing(t *testing.T) {
	lfd, err := listenLoopback(0) // any free port
	if err != nil {
		t.Fatal(err)
	}
	sa, err := unix.Getsockname(lfd)
	if err != nil {
		t.Fatal(err)
	}
	port := sa.(*unix.SockaddrInet4).Port

	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	if err := unix.Sendmsg(pair[1], []byte{'L'}, unix.UnixRights(lfd), nil, 0); err != nil {
		t.Fatal(err)
	}
	unix.Close(lfd)

	got, err := receiveFD(pair[0])
	if err != nil {
		t.Fatalf("receiveFD: %v", err)
	}
	what, err := checkListener(got, port)
	if err != nil {
		t.Fatalf("checkListener refused a listener on 127.0.0.1:%d: %v (%s)", port, err, what)
	}
	if _, err := checkListener(got, port+1); err == nil {
		t.Errorf("checkListener accepted a listener bound to another port")
	}
	ln, err := adoptListener(got)
	if err != nil {
		t.Fatalf("adoptListener: %v", err)
	}
	defer ln.Close()

	served := make(chan string, 1)
	go func() { served <- serveEcho(ln, "nonce") }()
	if reply := dialEcho(port, "nonce"); reply != "ack nonce" {
		t.Errorf("dialEcho read %q, want %q", reply, "ack nonce")
	}
	if s := <-served; s != "" {
		t.Errorf("serveEcho: %s", s)
	}

	// What is not a listener, and what carries no descriptor, is refused.
	plain, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(plain)
	if _, err := checkListener(plain, port); err == nil {
		t.Errorf("checkListener accepted a socket that does not listen")
	}
	if _, err := unix.Write(pair[1], []byte{'x'}); err != nil {
		t.Fatal(err)
	}
	if fd, err := receiveFD(pair[0]); err == nil {
		unix.Close(fd)
		t.Errorf("receiveFD returned a descriptor for a message that carries none")
	}
	if got := dialOutcome("tcp4", "127.0.0.1:"+strconv.Itoa(port+1)); got == "connected" {
		t.Logf("something listens on port %d: the refusal path of dialOutcome was not exercised", port+1)
	} else if got != "ECONNREFUSED" {
		t.Errorf("dialOutcome on a closed loopback port = %q, want ECONNREFUSED", got)
	}
}

// The comparison of K1-host: two snapshots of an idle host are equal, and a
// link that appears is seen.
func TestSelfNetworkSnapshot(t *testing.T) {
	a, b := snapshotNetwork(), snapshotNetwork()
	if d := diffNetwork(a, b); d != "" {
		t.Errorf("two snapshots taken in a row differ: %s", d)
	}
	changed := slices.Clone(b)
	changed[0].text += "\n99 ghost0 mtu 1500 up 02:00:00:00:00:01"
	if d := diffNetwork(a, changed); !strings.Contains(d, "ghost0") {
		t.Errorf("a new link is not reported: %q", d)
	}
	if got := describeNetwork(a); !strings.Contains(got, "links and addresses") || !strings.Contains(got, "ip_forward") {
		t.Errorf("describeNetwork = %q", got)
	}
	const ra = "default via fe80::1 dev eth0 proto ra metric 100 expires 1795sec pref medium"
	if got, want := expires.ReplaceAllString(ra, ""), "default via fe80::1 dev eth0 proto ra metric 100 pref medium"; got != want {
		t.Errorf("the countdown of a learnt route was not removed: %q", got)
	}
}
