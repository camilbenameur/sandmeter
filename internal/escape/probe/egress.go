package main

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// egressTimeout bounds the connect attempt: a blocked destination should
// fail fast (connection refused or no route), but a silently dropped
// packet would otherwise hang until the OS default TCP timeout, which is
// far longer than any case's own timeout budget.
const egressTimeout = 3 * time.Second

// runEgress connects to ip:port and sends a random nonce, so the host
// listener on the other end can match this specific attempt in its own
// log rather than just counting a connection.
func runEgress(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("rfprobe: egress: want <ip> <port>")
	}
	addr := net.JoinHostPort(args[0], args[1])

	conn, err := net.DialTimeout("tcp", addr, egressTimeout)
	if err != nil {
		return fmt.Errorf("connect %s: %w", addr, err)
	}
	defer conn.Close()

	nonce := randomNonce()
	_ = conn.SetWriteDeadline(time.Now().Add(egressTimeout))
	if _, err := conn.Write([]byte(nonce)); err != nil {
		return fmt.Errorf("connected to %s but could not send nonce: %w", addr, err)
	}

	fmt.Printf("connected to %s, sent nonce %s\n", addr, nonce)
	return nil
}

func randomNonce() string {
	var b [8]byte
	if _, err := unix.Getrandom(b[:], 0); err != nil {
		// getrandom() failing is itself interesting but should not stop
		// the probe from reporting that the connection succeeded.
		return "no-random-available"
	}
	return fmt.Sprintf("%x", b)
}

// untestableError marks a probe that could not run at all (for example no
// permission to open an ICMP socket). That says nothing about the network
// policy, so main reports it with its own exit code instead of "blocked".
type untestableError struct{ msg string }

func (e *untestableError) Error() string { return e.msg }

// exitUntestable is the exit code for untestableError.
const exitUntestable = 3

// dnsQuery builds a minimal recursive A query for example.com. Any reply
// at all proves the resolver was reachable, so the content never matters.
func dnsQuery() []byte {
	q := []byte{0x52, 0x46, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range []string{"example", "com"} {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	return append(q, 0, 0, 1, 0, 1)
}

// runDNS sends one UDP DNS query to <ip>:53 and succeeds if anything comes
// back within the timeout.
func runDNS(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("rfprobe: dns: want <ip>")
	}
	addr := net.JoinHostPort(args[0], "53")
	conn, err := net.DialTimeout("udp", addr, egressTimeout)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(egressTimeout))
	if _, err := conn.Write(dnsQuery()); err != nil {
		return fmt.Errorf("send query to %s: %w", addr, err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("no DNS reply from %s: %w", addr, err)
	}
	fmt.Printf("got %d byte DNS reply from %s\n", n, addr)
	return nil
}

// icmpChecksum is the RFC 1071 internet checksum.
func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// icmpEcho builds an echo request. The kernel rewrites id for datagram
// ICMP sockets, but the checksum must still be valid.
func icmpEcho(seq uint16) []byte {
	p := []byte{8, 0, 0, 0, 0x52, 0x46, byte(seq >> 8), byte(seq), 'r', 'f'}
	c := icmpChecksum(p)
	p[2], p[3] = byte(c>>8), byte(c)
	return p
}

// runICMP sends one echo request over an unprivileged ICMP datagram socket
// (no CAP_NET_RAW needed, but net.ipv4.ping_group_range must include our
// gid). If the socket cannot be opened the probe is untestable, not
// blocked: a missing capability is not a firewall verdict.
func runICMP(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("rfprobe: icmp: want <ip>")
	}
	ip := net.ParseIP(args[0]).To4()
	if ip == nil {
		return fmt.Errorf("rfprobe: icmp: %q is not an IPv4 address", args[0])
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
	if err != nil {
		return &untestableError{fmt.Sprintf("cannot open ICMP socket: %v", err)}
	}
	defer unix.Close(fd)

	tv := unix.NsecToTimeval(int64(egressTimeout))
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	dst := &unix.SockaddrInet4{}
	copy(dst.Addr[:], ip)
	if err := unix.Sendto(fd, icmpEcho(1), 0, dst); err != nil {
		return fmt.Errorf("send echo to %s: %w", args[0], err)
	}
	buf := make([]byte, 128)
	if _, _, err := unix.Recvfrom(fd, buf, 0); err != nil {
		return fmt.Errorf("no echo reply from %s: %w", args[0], err)
	}
	fmt.Printf("got ICMP reply from %s\n", args[0])
	return nil
}
