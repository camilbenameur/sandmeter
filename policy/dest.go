package policy

import (
	"net/netip"
	"strconv"
	"strings"
)

// Dest is one network destination: an entry of an allow list, or the target
// of one request to the egress proxy. ParseDest is the only way to make one
// from text, for the policy, the ceiling and the proxy alike, so that the
// three cannot disagree on what a name is.
//
// A Dest from ParseDest is normalised, and two entries that mean the same
// thing are equal as Go values:
//
//   - Host is either a DNS name or an IPv4 address in dotted form. A name is
//     in lower case, has no trailing dot, and is made of RFC 1123 labels:
//     letters a to z, digits and hyphens, 1 to 63 bytes each, not starting or
//     ending with a hyphen, 253 bytes in all. An internationalised name is
//     written in its ASCII form (labels starting with "xn--"); a name with a
//     byte outside ASCII is refused, never converted. The last label of a
//     name is never all digits, so nothing an address parser would read as an
//     address is ever held as a name.
//   - Wildcard is set for an entry written "*.suffix". It covers every name
//     that ends in ".suffix", at any depth, and never the suffix itself. The
//     suffix has at least two labels. A wildcard never covers an address.
//   - Port is 1 to 65535. An entry written without a port has port 443.
//   - Transport says whether the proxy checks the TLS handshake of a tunnel
//     to this destination (see Transport).
//
// IPv6 addresses are refused: 0.1.0 has no IPv6 egress.
//
// The zero Dest is not a destination; ParseDest never returns it without an
// error.
type Dest struct {
	Host      string
	Wildcard  bool
	Port      uint16
	Transport Transport
}

// Transport is what an allow-list entry says about TLS.
//
// On a tunnel to a destination that requires TLS, the proxy reads the first
// bytes the client sends, which must be a TLS ClientHello whose server name
// equals the host of the request (for an address: a ClientHello without a
// server name). Anything else closes the tunnel. Without that check an
// allowed name on a shared front end is a way to every other site served
// there.
type Transport uint8

const (
	// TransportAuto is an entry with no marker: TLS is required on port 443
	// and on no other port.
	TransportAuto Transport = iota
	// TransportTLS is an entry marked "/tls": TLS is required whatever the
	// port.
	TransportTLS
	// TransportRaw is an entry marked "/raw": TLS is not required, even on
	// port 443, as for SSH offered on that port. A policy may mark an entry
	// raw only where the ceiling has a raw entry that covers it.
	TransportRaw
)

// DefaultPort is the port of an entry written without one.
const DefaultPort = 443

// RequiresTLS reports whether the proxy must see a matching TLS handshake on
// a tunnel that this allow-list entry admits.
func (d Dest) RequiresTLS() bool {
	switch d.Transport {
	case TransportTLS:
		return true
	case TransportRaw:
		return false
	}
	return d.Port == DefaultPort
}

// IsAddr reports whether Host is an IPv4 address and not a name.
func (d Dest) IsAddr() bool {
	_, ok := d.addr()
	return ok
}

func (d Dest) addr() (netip.Addr, bool) {
	a, err := netip.ParseAddr(d.Host)
	return a, err == nil && a.Is4() && !d.Wildcard
}

// String returns the canonical text of d, which ParseDest reads back to the
// same value: "name:port", "*.suffix:port" or "address:port", followed by
// "/tls" or "/raw" when the entry is marked. The port is always written.
func (d Dest) String() string {
	var b strings.Builder
	if d.Wildcard {
		b.WriteString("*.")
	}
	b.WriteString(d.Host)
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(int(d.Port)))
	switch d.Transport {
	case TransportTLS:
		b.WriteString("/tls")
	case TransportRaw:
		b.WriteString("/raw")
	}
	return b.String()
}

// MarshalText implements encoding.TextMarshaler with String, so that a Dest
// is a JSON string.
func (d Dest) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler with ParseDest.
func (d *Dest) UnmarshalText(b []byte) error {
	v, err := ParseDest(string(b))
	if err != nil {
		return err
	}
	*d = v
	return nil
}

// Matches reports whether the allow-list entry d admits a request for
// target. The target is the Dest that ParseDest made from the host and port
// of the request; because it went through the same parser as the entry, the
// comparison is between normalised values and needs no folding here.
//
// The ports must be equal. An entry that is not a wildcard admits its own
// host and no other. A wildcard entry admits a name that ends in "." followed
// by its suffix, and never an address. A target that is itself a wildcard is
// admitted by nothing. The transport markers play no part: once an entry
// admits a request, the entry's own RequiresTLS decides what the proxy checks.
func (d Dest) Matches(target Dest) bool {
	if target.Wildcard || target.Host == "" || d.Host == "" || d.Port != target.Port {
		return false
	}
	if !d.Wildcard {
		return d.Host == target.Host
	}
	return !target.IsAddr() && strings.HasSuffix(target.Host, "."+d.Host)
}

// Covers reports whether the ceiling entry d grants the policy entry o: every
// request o would admit is one d admits, checked at least as strictly.
//
// The ports must be equal. An entry that is not a wildcard covers only an
// entry with the same host that is not a wildcard either. A wildcard covers
// the names under its suffix, and the wildcards on its suffix or on a longer
// one. Where d requires TLS, o must too: a policy cannot switch the TLS check
// off on a destination where the ceiling leaves it on.
func (d Dest) Covers(o Dest) bool {
	if d.Host == "" || o.Host == "" || d.Port != o.Port {
		return false
	}
	if d.RequiresTLS() && !o.RequiresTLS() {
		return false
	}
	if !d.Wildcard {
		return !o.Wildcard && d.Host == o.Host
	}
	if o.IsAddr() {
		return false
	}
	if o.Wildcard && o.Host == d.Host {
		return true
	}
	return strings.HasSuffix(o.Host, "."+d.Host)
}

// Find returns the entry of allow that decides a request for target, and
// whether there is one. When several entries admit the target the most
// specific wins: an entry that names the host itself before any wildcard, and
// among wildcards the one with the longest suffix. Two entries of the same
// specificity can differ only by their marker; the one that requires TLS
// wins. The result therefore does not depend on the order of the list.
func Find(allow []Dest, target Dest) (Dest, bool) {
	var best Dest
	found := false
	for _, d := range allow {
		if !d.Matches(target) {
			continue
		}
		if !found || moreSpecific(d, best) {
			best, found = d, true
		}
	}
	return best, found
}

// moreSpecific reports whether a decides before b, both admitting the same
// target.
func moreSpecific(a, b Dest) bool {
	if a.Wildcard != b.Wildcard {
		return !a.Wildcard
	}
	if len(a.Host) != len(b.Host) {
		return len(a.Host) > len(b.Host)
	}
	return a.RequiresTLS() && !b.RequiresTLS()
}
