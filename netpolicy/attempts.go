package netpolicy

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/camilbenameur/ringfence/sandbox"
)

// Conn is one flow seen by the firewall.
type Conn = sandbox.Connection

// nftDoc is the slice of "nft -j" output this package reads.
type nftDoc struct {
	Nftables []struct {
		Set   *nftSet   `json:"set"`
		Chain *nftChain `json:"chain"`
	} `json:"nftables"`
}

type nftSet struct {
	Name string `json:"name"`
	// Elem holds bare values, or {"elem": {"val": ..., ...}} wrappers when an
	// element carries a timeout or counter. Both forms are accepted.
	Elem []json.RawMessage `json:"elem"`
}

type nftChain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Hook   string `json:"hook"`
	Policy string `json:"policy"`
}

// Attempts returns the flows recorded, best effort (sets are capped at 4096
// entries and IPv6 is not recorded), in the table's dynamic sets, allowed
// and denied, sorted by destination. Flows from the veth to the host itself
// are included as denied.
func Attempts(ctx context.Context, table string) ([]sandbox.Connection, error) {
	if !tableRE.MatchString(table) {
		return nil, fmt.Errorf("invalid table name %q", table)
	}
	out, stderr, err := runNft(ctx, "", "-j", "list", "table", "inet", table)
	if err != nil {
		return nil, nftError("nft list table", stderr, err)
	}
	return parseAttempts(out)
}

func parseAttempts(data []byte) ([]sandbox.Connection, error) {
	var doc nftDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse nft json: %w", err)
	}
	var conns []sandbox.Connection
	for _, item := range doc.Nftables {
		if item.Set == nil {
			continue
		}
		var allowed bool
		switch item.Set.Name {
		case "seen_ok":
			allowed = true
		case "seen_denied", "seen_denied_other":
		default:
			continue
		}
		for _, raw := range item.Set.Elem {
			c, err := parseElem(raw)
			if err != nil {
				return nil, fmt.Errorf("set %s: %w", item.Set.Name, err)
			}
			c.Allowed = allowed
			conns = append(conns, c)
		}
	}
	slices.SortFunc(conns, func(a, b sandbox.Connection) int {
		return cmp.Or(cmp.Compare(a.DstIP, b.DstIP), cmp.Compare(a.Proto, b.Proto),
			cmp.Compare(a.DstPort, b.DstPort), cmp.Compare(b2i(a.Allowed), b2i(b.Allowed)))
	})
	return conns, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// parseElem decodes one set element: a {"concat": [addr, proto, port?]}
// object, possibly wrapped in {"elem": {"val": ...}}.
func parseElem(raw json.RawMessage) (sandbox.Connection, error) {
	var w struct {
		Elem *struct {
			Val json.RawMessage `json:"val"`
		} `json:"elem"`
		Concat []json.RawMessage `json:"concat"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return sandbox.Connection{}, fmt.Errorf("element: %w", err)
	}
	concat := w.Concat
	if w.Elem != nil {
		var inner struct {
			Concat []json.RawMessage `json:"concat"`
		}
		if err := json.Unmarshal(w.Elem.Val, &inner); err != nil {
			return sandbox.Connection{}, fmt.Errorf("element value: %w", err)
		}
		concat = inner.Concat
	}
	if len(concat) < 2 || len(concat) > 3 {
		return sandbox.Connection{}, fmt.Errorf("element has %d concatenated fields, want 2 or 3: %s", len(concat), raw)
	}
	var c sandbox.Connection
	if err := json.Unmarshal(concat[0], &c.DstIP); err != nil {
		return c, fmt.Errorf("address in %s: %w", raw, err)
	}
	proto, err := protoName(concat[1])
	if err != nil {
		return c, fmt.Errorf("protocol in %s: %w", raw, err)
	}
	c.Proto = proto
	if len(concat) == 3 {
		if err := json.Unmarshal(concat[2], &c.DstPort); err != nil {
			return c, fmt.Errorf("port in %s: %w", raw, err)
		}
	}
	return c, nil
}

// protoName accepts a name ("tcp") or a number, which nft prints when it has
// no name for the protocol.
func protoName(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.ToLower(s), nil
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		return "", err
	}
	switch n {
	case 1:
		return "icmp", nil
	case 6:
		return "tcp", nil
	case 17:
		return "udp", nil
	}
	return strconv.Itoa(n), nil
}

// ForwardBlockedByOthers reports whether a table other than ours has a
// forward-hook base chain with policy drop. Such a chain drops forwarded
// packets whatever our table accepts; Docker's iptables FORWARD chain is the
// usual one. It is best effort: it looks at policies only, not at rules that
// might accept our traffic, and it skips tables named "ringfence_*".
func ForwardBlockedByOthers(ctx context.Context) (bool, string, error) {
	out, stderr, err := runNft(ctx, "", "-j", "list", "ruleset")
	if err != nil {
		return false, "", nftError("nft list ruleset", stderr, err)
	}
	return findForwardDrop(out)
}

func findForwardDrop(data []byte) (bool, string, error) {
	var doc nftDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return false, "", fmt.Errorf("parse nft json: %w", err)
	}
	for _, item := range doc.Nftables {
		c := item.Chain
		if c == nil || c.Hook != "forward" || c.Policy != "drop" || strings.HasPrefix(c.Table, "ringfence_") {
			continue
		}
		return true, fmt.Sprintf("table %s %s chain %s has hook forward with policy drop", c.Family, c.Table, c.Name), nil
	}
	return false, "", nil
}
