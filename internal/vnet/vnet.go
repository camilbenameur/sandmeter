//go:build linux

// Package vnet gives a sandbox network namespace one veth link to the host,
// addresses from netpolicy.Allocate, a default route, and the nftables
// egress ruleset. Both backends use it.
package vnet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/camilbenameur/sandmeter/netpolicy"
)

// maxNetIndex matches the /30 pool of netpolicy.Allocate.
const maxNetIndex = 16384

// Pair is the network of one Exec: a veth pair, an address pair, an
// nftables table, and a lock file reserving the address index.
type Pair struct {
	index int
	lock  string
	host  string
	// Table is the nftables table holding the ruleset and connection log.
	Table   string
	created bool
	applied bool
}

// reserveIndex takes the first free index with an O_EXCL lock file, so two
// sandmeter processes on the same host never share an address pair.
func reserveIndex(stateDir string) (int, string, error) {
	dir := filepath.Join(stateDir, "net")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, "", err
	}
	for i := 0; i < maxNetIndex; i++ {
		p := filepath.Join(dir, strconv.Itoa(i))
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return 0, "", err
		}
		fmt.Fprintf(f, "%d\n", os.Getpid())
		f.Close()
		return i, p, nil
	}
	return 0, "", errors.New("no free network index")
}

// Setup creates the veth pair, moves one end into the network namespace ns
// as eth0, configures addresses and the default route, and applies the
// egress ruleset. On error everything created so far is removed. stateDir
// holds the lock files that reserve address indexes.
func Setup(ctx context.Context, stateDir string, ns netns.NsHandle, dests []netpolicy.Dest) (vp *Pair, err error) {
	idx, lock, err := reserveIndex(stateDir)
	if err != nil {
		return nil, err
	}
	vp = &Pair{
		index: idx,
		lock:  lock,
		host:  fmt.Sprintf("rf%dh", idx),
		Table: fmt.Sprintf("sandmeter_%d", idx),
	}
	defer func() {
		if err != nil {
			vp.Close()
			vp = nil
		}
	}()
	addr, err := netpolicy.Allocate(idx)
	if err != nil {
		return vp, err
	}
	peer := fmt.Sprintf("rf%ds", idx)
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: vp.host, MTU: 1500}, PeerName: peer}
	// A stale pair from a crashed run would make LinkAdd fail; remove it.
	if old, err := netlink.LinkByName(vp.host); err == nil {
		netlink.LinkDel(old)
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return vp, fmt.Errorf("add veth: %w", err)
	}
	vp.created = true
	hostLink, err := netlink.LinkByName(vp.host)
	if err != nil {
		return vp, err
	}
	peerLink, err := netlink.LinkByName(peer)
	if err != nil {
		return vp, err
	}
	if err := netlink.AddrAdd(hostLink, &netlink.Addr{IPNet: prefixToIPNet(addr.Host)}); err != nil {
		return vp, fmt.Errorf("host address: %w", err)
	}
	if err := netlink.LinkSetUp(hostLink); err != nil {
		return vp, err
	}
	if err := netlink.LinkSetNsFd(peerLink, int(ns)); err != nil {
		return vp, fmt.Errorf("move veth into sandbox: %w", err)
	}
	h, err := netlink.NewHandleAt(ns)
	if err != nil {
		return vp, fmt.Errorf("netlink in sandbox netns: %w", err)
	}
	defer h.Close()
	inner, err := h.LinkByName(peer)
	if err != nil {
		return vp, err
	}
	if err := h.LinkSetName(inner, "eth0"); err != nil {
		return vp, err
	}
	if err := h.AddrAdd(inner, &netlink.Addr{IPNet: prefixToIPNet(addr.Sandbox)}); err != nil {
		return vp, fmt.Errorf("sandbox address: %w", err)
	}
	if err := h.LinkSetUp(inner); err != nil {
		return vp, err
	}
	gw := net.IP(addr.Host.Addr().AsSlice())
	if err := h.RouteAdd(&netlink.Route{LinkIndex: inner.Attrs().Index, Gw: gw}); err != nil {
		return vp, fmt.Errorf("default route: %w", err)
	}

	script, err := netpolicy.Ruleset(netpolicy.Plan{Table: vp.Table, HostIface: vp.host, Addr: addr, Allow: dests})
	if err != nil {
		return vp, err
	}
	if err := netpolicy.Apply(ctx, script); err != nil {
		return vp, err
	}
	vp.applied = true
	return vp, nil
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	ip := net.IP(p.Addr().AsSlice())
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(p.Bits(), len(ip)*8)}
}

// Close removes the ruleset, the veth pair and the lock, in that order.
// Deleting the host end deletes both ends.
func (vp *Pair) Close() {
	if vp.applied {
		netpolicy.Delete(context.Background(), vp.Table)
	}
	if vp.created {
		if l, err := netlink.LinkByName(vp.host); err == nil {
			netlink.LinkDel(l)
		}
	}
	if vp.lock != "" {
		os.Remove(vp.lock)
	}
}
