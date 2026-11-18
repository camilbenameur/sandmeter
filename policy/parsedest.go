package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// maxDestLen bounds the text of one destination. The longest valid one is a
// 253-byte name with "*.", a port and a marker; anything longer is refused
// before it is looked at.
const maxDestLen = 2 + 253 + 1 + 1 + 5 + 4

// ErrDest is the error of ParseDest, wrapped with what was wrong. The message
// never contains the input: a destination can be chosen by the program in the
// sandbox, and what it chose must not appear inside a sentence of sandmeter's
// own.
var ErrDest = errors.New("invalid destination")

// ParseDest parses one destination and returns it normalised (see Dest). It
// is the one parser for the allow list of a policy, the allow list of a
// ceiling and the target of a request to the egress proxy.
//
// The grammar is
//
//	[ "*." ] host [ ":" port ] [ "/tls" | "/raw" ]
//
// and the rules are:
//
//   - Letters are folded to lower case. One trailing dot after the host is
//     dropped. Nothing else is rewritten, trimmed or guessed.
//   - Every byte must be printable ASCII. A name with other characters has to
//     be given in its ASCII form ("xn--...").
//   - host is a name of RFC 1123 labels or an IPv4 address in dotted decimal
//     form with four fields and no leading zero. A name whose last label is
//     all digits is refused: resolvers disagree on whether it is an address.
//     An IPv6 address is refused.
//   - "*." may only come first, only before a name of at least two labels,
//     and "*" may appear nowhere else.
//   - port is decimal, 1 to 65535, without sign, space or leading zero. When
//     it is left out the port is 443.
//   - "/tls" and "/raw" set the transport marker.
//
// The proxy accepts as a request target only a result with no wildcard and
// no marker.
func ParseDest(s string) (Dest, error) {
	bad := func(format string, args ...any) (Dest, error) {
		return Dest{}, fmt.Errorf("%w: %s", ErrDest, fmt.Sprintf(format, args...))
	}
	if s == "" {
		return bad("it is empty")
	}
	if len(s) > maxDestLen {
		return bad("it is %d bytes long, more than any valid destination", len(s))
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c >= 0x7f {
			return bad("byte %d is not a printable ASCII character (write an internationalised name in its xn-- form)", i)
		}
	}

	var d Dest
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		switch s[i+1:] {
		case "tls":
			d.Transport = TransportTLS
		case "raw":
			d.Transport = TransportRaw
		default:
			return bad("the part after \"/\" must be \"tls\" or \"raw\"")
		}
		s = s[:i]
	}
	if strings.HasPrefix(s, "[") || strings.Count(s, ":") > 1 {
		return bad("IPv6 addresses are not supported")
	}

	d.Port = DefaultPort
	if i := strings.IndexByte(s, ':'); i >= 0 {
		port, ok := parsePort(s[i+1:])
		if !ok {
			return bad("the port must be a decimal number from 1 to 65535 without leading zero")
		}
		d.Port = port
		s = s[:i]
	}

	if strings.HasPrefix(s, "*.") {
		d.Wildcard = true
		s = s[2:]
	}
	if strings.Contains(s, "*") {
		return bad("\"*\" is only allowed as a leading \"*.\"")
	}
	host := strings.ToLower(strings.TrimSuffix(s, "."))
	if host == "" {
		return bad("the host is empty")
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		if !addr.Is4() {
			return bad("IPv6 addresses are not supported")
		}
		if d.Wildcard {
			return bad("a wildcard needs a name, not an address")
		}
		d.Host = addr.String()
		return d, nil
	}

	labels := strings.Split(host, ".")
	if len(host) > 253 {
		return bad("the name is longer than 253 bytes")
	}
	for _, label := range labels {
		if !validLabel(label) {
			return bad("a label of the name is not 1 to 63 letters, digits or hyphens with no hyphen at either end")
		}
	}
	if allDigits(labels[len(labels)-1]) {
		return bad("the last label is all digits, which is neither a name nor a dotted IPv4 address")
	}
	if d.Wildcard && len(labels) < 2 {
		return bad("a wildcard needs a suffix of at least two labels")
	}
	d.Host = host
	return d, nil
}

// parsePort accepts 1 to 65535 in strict decimal form.
func parsePort(s string) (uint16, bool) {
	if len(s) == 0 || len(s) > 5 || s[0] == '0' {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	if n < 1 || n > 65535 {
		return 0, false
	}
	return uint16(n), true
}

func validLabel(l string) bool {
	if len(l) < 1 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func allDigits(l string) bool {
	for i := 0; i < len(l); i++ {
		if l[i] < '0' || l[i] > '9' {
			return false
		}
	}
	return true
}
