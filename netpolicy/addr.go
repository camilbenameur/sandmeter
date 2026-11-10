package netpolicy

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// MaxIndex is the highest Allocate index: a /16 holds 16384 /30 blocks.
const MaxIndex = 16383

// Addr is the addressing of one sandbox's veth pair: a /30 carved out of
// 10.213.0.0/16.
type Addr struct {
	Index int
	// Host is the host side of the veth (.1 of the /30), the sandbox's gateway.
	Host netip.Prefix
	// Sandbox is the sandbox side (.2 of the /30).
	Sandbox netip.Prefix
}

// Allocate returns the addresses for a sandbox index. It is deterministic, so
// the caller owns uniqueness by handing out distinct indexes. A /30 leaves
// room for exactly the two ends, which keeps sandboxes on separate subnets.
func Allocate(index int) (Addr, error) {
	if index < 0 || index > MaxIndex {
		return Addr{}, fmt.Errorf("sandbox index %d out of range 0..%d", index, MaxIndex)
	}
	base := index * 4
	host := netip.AddrFrom4([4]byte{10, 213, byte(base >> 8), byte(base&0xff) + 1})
	sb := netip.AddrFrom4([4]byte{10, 213, byte(base >> 8), byte(base&0xff) + 2})
	return Addr{
		Index:   index,
		Host:    netip.PrefixFrom(host, 30),
		Sandbox: netip.PrefixFrom(sb, 30),
	}, nil
}

// ipForwardPath is a variable for tests.
var ipForwardPath = "/proc/sys/net/ipv4/ip_forward"

// CheckForwarding reports an error when IPv4 forwarding is off. It never
// changes the setting: that is a host-wide change the operator must choose.
func CheckForwarding() error {
	b, err := os.ReadFile(ipForwardPath)
	if err != nil {
		return fmt.Errorf("read ip_forward: %w", err)
	}
	if v := strings.TrimSpace(string(b)); v != "1" {
		return fmt.Errorf("IPv4 forwarding is off (%s is %q): enable it with `sysctl -w net.ipv4.ip_forward=1`; ringfence does not change it", ipForwardPath, v)
	}
	return nil
}
