package netpolicy

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Dest is one allowed destination.
type Dest struct {
	IP   netip.Addr
	Port uint16
	// Proto is "tcp" or "udp".
	Proto string
}

// Plan is the input of Ruleset.
type Plan struct {
	// Table is the nft table name, "sandmeter_<id>"; [a-z0-9_]{1,32}.
	Table string
	// HostIface is the host side of the veth pair.
	HostIface string
	Addr      Addr
	Allow     []Dest
}

func (d Dest) validate() error {
	if !d.IP.Is4() {
		return fmt.Errorf("destination %v: only IPv4 is supported", d.IP)
	}
	if d.Proto != "tcp" && d.Proto != "udp" {
		return fmt.Errorf("destination %v: protocol must be tcp or udp, got %q", d.IP, d.Proto)
	}
	if d.Port == 0 {
		return fmt.Errorf("destination %v: port must be 1..65535", d.IP)
	}
	return nil
}

func compareDest(a, b Dest) int {
	return cmp.Or(a.IP.Compare(b.IP), cmp.Compare(a.Proto, b.Proto), cmp.Compare(a.Port, b.Port))
}

func (p Plan) validate() error {
	if !tableRE.MatchString(p.Table) {
		return fmt.Errorf("invalid table name %q: want [a-z0-9_]{1,32}", p.Table)
	}
	if !ifaceRE.MatchString(p.HostIface) {
		return fmt.Errorf("invalid interface name %q: want [A-Za-z0-9_-]{1,15}", p.HostIface)
	}
	if !p.Addr.Sandbox.IsValid() || !p.Addr.Sandbox.Addr().Is4() {
		return fmt.Errorf("plan has no valid IPv4 sandbox address")
	}
	for _, d := range p.Allow {
		if err := d.validate(); err != nil {
			return err
		}
	}
	return nil
}

// flowType is the key of the sets that record tcp and udp flows.
const flowType = "ipv4_addr . inet_proto . inet_service"

// Ruleset renders the nft script for a plan. The output is deterministic:
// the allowlist is sorted and deduplicated.
//
// Recording uses two kinds of dynamic set. tcp and udp flows are keyed by
// address, protocol and port. Other protocols (icmp, ...) have no port, and
// "th dport" on them would read payload bytes that are not a port, so they go
// to a separate set keyed by address and protocol only. Only tcp and udp can
// be allowed, so that set only ever holds denied flows.
//
// A sandbox with CAP_NET_RAW can forge source addresses, and rp_filter is not
// guaranteed to be strict, so both hooks drop anything from the veth whose
// source is not the sandbox address before it is recorded or allowed.
//
// Chain names avoid nft keywords: "fwd" is the fwd statement and fails to parse.
func Ruleset(p Plan) (string, error) {
	if err := p.validate(); err != nil {
		return "", err
	}
	allow := slices.Clone(p.Allow)
	slices.SortFunc(allow, compareDest)
	allow = slices.CompactFunc(allow, func(a, b Dest) bool { return compareDest(a, b) == 0 })

	iface := `"` + p.HostIface + `"`
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	w("table inet %s {\n", p.Table)
	w("\tset allow4 {\n\t\ttype %s\n", flowType)
	if len(allow) > 0 {
		elems := make([]string, len(allow))
		for i, d := range allow {
			elems[i] = fmt.Sprintf("%s . %s . %d", d.IP, d.Proto, d.Port)
		}
		w("\t\telements = { %s }\n", strings.Join(elems, ", "))
	}
	w("\t}\n")
	for _, name := range []string{"seen_ok", "seen_denied"} {
		w("\tset %s {\n\t\ttype %s\n\t\tflags dynamic\n\t\tsize 4096\n\t}\n", name, flowType)
	}
	w("\tset seen_denied_other {\n\t\ttype ipv4_addr . inet_proto\n\t\tflags dynamic\n\t\tsize 4096\n\t}\n")

	const match = "ip daddr . meta l4proto . th dport"
	const other = "ip daddr . meta l4proto"
	w("\tchain egress {\n")
	w("\t\ttype filter hook forward priority filter - 1; policy accept;\n")
	w("\t\tiifname %s meta nfproto ipv6 drop\n", iface)
	w("\t\tiifname %s ip saddr != %s counter drop\n", iface, p.Addr.Sandbox.Addr())
	w("\t\tiifname %s ct state new meta l4proto { tcp, udp } %s @allow4 update @seen_ok { %s }\n", iface, match, match)
	w("\t\tiifname %s meta l4proto { tcp, udp } %s @allow4 accept\n", iface, match)
	w("\t\tiifname %s ct state new meta l4proto { tcp, udp } update @seen_denied { %s }\n", iface, match)
	w("\t\tiifname %s ct state new meta l4proto != { tcp, udp } update @seen_denied_other { %s }\n", iface, other)
	w("\t\tiifname %s counter drop\n", iface)
	w("\t\toifname %s ct state established,related accept\n", iface)
	w("\t\toifname %s counter drop\n", iface)
	w("\t}\n")

	w("\tchain host_in {\n")
	w("\t\ttype filter hook input priority filter - 1; policy accept;\n")
	w("\t\tiifname %s ip saddr != %s counter drop\n", iface, p.Addr.Sandbox.Addr())
	w("\t\tiifname %s ct state new meta l4proto { tcp, udp } update @seen_denied { %s }\n", iface, match)
	w("\t\tiifname %s ct state new meta l4proto != { tcp, udp } update @seen_denied_other { %s }\n", iface, other)
	w("\t\tiifname %s counter drop\n", iface)
	w("\t}\n")

	w("\tchain nat_out {\n")
	w("\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
	w("\t\tip saddr %s oifname != %s masquerade\n", p.Addr.Sandbox.Addr(), iface)
	w("\t}\n")
	w("}\n")
	return b.String(), nil
}
