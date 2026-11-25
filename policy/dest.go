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
//     name is never a number, in any spelling an address parser accepts: all
//     digits, or "0x" followed by hexadecimal digits. The parsers that take
//     short, octal and hexadecimal addresses read a host as an address only
//     when its last field is such a number, so nothing they would read as an
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

// Covers reports whether the entry d, taken alone, grants the entry o: every
// request o would admit is one d admits, checked at least as strictly.
//
// The ports must be equal. An entry that is not a wildcard covers only an
// entry with the same host that is not a wildcard either. A wildcard covers
// the names under its suffix, and the wildcards on its suffix or on a longer
// one. Where d requires TLS, o must too.
//
// Covers compares two entries and knows nothing of the lists they stand in.
// It is not the check of a policy against a ceiling: a request is decided by
// the most specific entry of a whole list (see Find), so an entry of a
// ceiling can be covered by one ceiling entry and still be stricter than it
// for some names because of another. That check is Uncovered.
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

// Uncovered checks the allow list of a policy against the allow list of a
// ceiling, as whole lists, and returns the positions in allow of the entries
// the ceiling does not grant, in ascending order. An empty result means that
// the policy's list is within the ceiling's:
//
//	for every request, if allow admits it then ceiling admits it, and if
//	the ceiling's deciding entry requires TLS then so does the policy's.
//
// "Admits" and "deciding entry" are those of Find, which is what the proxy
// runs: the most specific entry of a list decides. The check is therefore
// made on decisions and not entry against entry. With a ceiling of
// "*.example.com:443/raw" and "api.example.com:443", a policy that lists
// only the first entry is refused: for api.example.com the ceiling requires
// a TLS handshake that names it, and that policy would not. The same policy
// with both entries is granted, since it then decides as the ceiling does.
//
// The entry returned for a request the ceiling would refuse, or check more
// strictly, is the policy entry that decides that request. The positions
// are those of allow as given: a caller that keeps the place of an entry
// which did not parse puts the zero Dest there, which admits nothing and is
// never returned.
//
// Both lists hold values from ParseDest. The cost grows with the number of
// entries of the two lists times the number of labels of their names, not
// with the product of the two lists.
func Uncovered(allow, ceiling []Dest) []int {
	pol, ceil := indexDests(allow), indexDests(ceiling)
	bad := map[int]bool{}
	judge := func(target Dest) {
		pe, ok := pol.find(target)
		if !ok {
			return
		}
		// Invariant: a policy never decides a request more loosely than the
		// ceiling does. Looser is "admitted where the ceiling refuses" and
		// "without the TLS check where the ceiling has it".
		ce, ok := ceil.find(target)
		if !ok || (ce.dest.RequiresTLS() && !pe.dest.RequiresTLS()) {
			bad[pe.pos] = true
		}
	}
	// The two lists cut the requests into finitely many classes on which
	// both decisions are constant: each host an entry names, and for each
	// wildcard the names under its suffix that no longer suffix and no named
	// host of either list claims. One request per class is judged, and each
	// class once: the lists come from a client, and a suffix repeated many
	// times over many named hosts must not be searched as many times.
	judged := map[hostPort]bool{}
	for _, list := range [][]Dest{allow, ceiling} {
		for _, d := range list {
			if d.Host == "" {
				continue
			}
			class := hostPort{d.Host, d.Port}
			if d.Wildcard {
				class.host = "*." + d.Host
			}
			if judged[class] {
				continue
			}
			judged[class] = true
			if !d.Wildcard {
				judge(Dest{Host: d.Host, Port: d.Port})
				continue
			}
			if name, ok := unclaimedUnder(d.Host, d.Port, pol, ceil); ok {
				judge(Dest{Host: name, Port: d.Port})
			}
		}
	}
	out := make([]int, 0, len(bad))
	for i := range allow {
		if bad[i] {
			out = append(out, i)
		}
	}
	return out
}

// hostPort keys an index of entries.
type hostPort struct {
	host string
	port uint16
}

// placed is an entry with its position in the list it came from.
type placed struct {
	dest Dest
	pos  int
}

// destIndex answers Find for one list in time that does not depend on the
// length of the list.
type destIndex struct {
	exact, wild map[hostPort]placed
}

func indexDests(list []Dest) destIndex {
	ix := destIndex{exact: map[hostPort]placed{}, wild: map[hostPort]placed{}}
	for i, d := range list {
		if d.Host == "" {
			continue
		}
		m := ix.exact
		if d.Wildcard {
			m = ix.wild
		}
		key := hostPort{d.Host, d.Port}
		// Two entries of the same specificity differ only by their marker:
		// the one that requires TLS decides, as in Find, and of two equals
		// the first.
		if cur, ok := m[key]; !ok || moreSpecific(d, cur.dest) {
			m[key] = placed{dest: d, pos: i}
		}
	}
	return ix
}

// find is Find on an index: the entry that names the host itself, or else
// the wildcard with the longest suffix the host lies under.
func (ix destIndex) find(target Dest) (placed, bool) {
	if target.Wildcard || target.Host == "" {
		return placed{}, false
	}
	if e, ok := ix.exact[hostPort{target.Host, target.Port}]; ok {
		return e, true
	}
	if target.IsAddr() {
		return placed{}, false
	}
	for rest := target.Host; ; {
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			return placed{}, false
		}
		rest = rest[dot+1:]
		if e, ok := ix.wild[hostPort{rest, target.Port}]; ok {
			return e, true
		}
	}
}

// unclaimedUnder returns a name directly under suffix that neither list
// names on that port. Being one label longer than the suffix, it lies under
// no longer wildcard of either list, so the wildcard on suffix itself, or a
// shorter one, decides it in each list: it stands for every name of that
// class. ok is false when no such name exists, which takes a suffix so long
// that the lists name every name under it.
//
// Candidates are tried in a fixed order, and among any n+1 of them one is
// not among the n hosts the lists name: the search ends after at most that
// many steps.
func unclaimedUnder(suffix string, port uint16, lists ...destIndex) (name string, ok bool) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	for length := 1; length <= 63 && length+1+len(suffix) <= 253; length++ {
		// digits counts through every label of this length.
		digits := make([]int, length)
		label := make([]byte, length)
		for {
			for i, d := range digits {
				label[i] = alphabet[d]
			}
			candidate := string(label) + "." + suffix
			taken := false
			for _, ix := range lists {
				if _, named := ix.exact[hostPort{candidate, port}]; named {
					taken = true
					break
				}
			}
			if !taken {
				return candidate, true
			}
			i := length - 1
			for ; i >= 0; i-- {
				if digits[i]++; digits[i] < len(alphabet) {
					break
				}
				digits[i] = 0
			}
			if i < 0 {
				break
			}
		}
	}
	return "", false
}
