package netpolicy

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"
)

// resolveTimeout bounds each DNS lookup, so one slow name cannot stall a start.
const resolveTimeout = 5 * time.Second

// HostEntry is one line for the sandbox /etc/hosts.
type HostEntry struct {
	Name string
	IP   netip.Addr
}

// Lookuper is the part of *net.Resolver that Resolve uses.
type Lookuper interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Resolve turns "host:port" allowlist entries into firewall destinations and
// /etc/hosts lines. The policy package has already checked the syntax.
//
// Every destination is tcp: the allowlist has no way to say udp. An IP
// literal gives one Dest. A name is resolved once, on the host, with a 5 s
// timeout, and each A record gives a Dest and a HostEntry. IPv6 is dropped
// entirely because the sandbox has no IPv6, so an IPv6 literal is an error and
// AAAA records are never asked for. The results are deduplicated and sorted.
// Addresses in DNS answers that are loopback, link-local, multicast,
// unspecified or private are dropped: a name must not be able to open a path to
// the host's local network or a cloud metadata service. Only an explicit IP
// literal can allow such an address. A name left with no usable address is an
// error.
// A nil r means net.DefaultResolver.
func Resolve(ctx context.Context, allow []string, r Lookuper) ([]Dest, []HostEntry, error) {
	if r == nil {
		r = net.DefaultResolver
	}
	var dests []Dest
	var hosts []HostEntry
	for _, entry := range allow {
		host, portStr, err := net.SplitHostPort(entry)
		if err != nil {
			return nil, nil, fmt.Errorf("allow entry %q: %w", entry, err)
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || port == 0 {
			return nil, nil, fmt.Errorf("allow entry %q: invalid port %q", entry, portStr)
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			ip = ip.Unmap()
			if !ip.Is4() {
				return nil, nil, fmt.Errorf("allow entry %q: IPv6 is not supported in the sandbox", entry)
			}
			dests = append(dests, Dest{IP: ip, Port: uint16(port), Proto: "tcp"})
			continue
		}
		ips, err := lookup4(ctx, r, host)
		if err != nil {
			return nil, nil, fmt.Errorf("allow entry %q: %w", entry, err)
		}
		for _, ip := range ips {
			dests = append(dests, Dest{IP: ip, Port: uint16(port), Proto: "tcp"})
			hosts = append(hosts, HostEntry{Name: host, IP: ip})
		}
	}
	slices.SortFunc(dests, compareDest)
	dests = slices.CompactFunc(dests, func(a, b Dest) bool { return compareDest(a, b) == 0 })
	cmpHost := func(a, b HostEntry) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), a.IP.Compare(b.IP))
	}
	slices.SortFunc(hosts, cmpHost)
	hosts = slices.CompactFunc(hosts, func(a, b HostEntry) bool { return cmpHost(a, b) == 0 })
	return dests, hosts, nil
}

func lookup4(ctx context.Context, r Lookuper, name string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	addrs, err := r.LookupNetIP(ctx, "ip4", name)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", name, err)
	}
	var out []netip.Addr
	for _, a := range addrs {
		if a = a.Unmap(); a.Is4() && !unsafeAnswer(a) {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("resolve %s: no usable public IPv4 address", name)
	}
	return out, nil
}

func unsafeAnswer(a netip.Addr) bool {
	return a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() ||
		a.IsUnspecified() || a.IsPrivate()
}
