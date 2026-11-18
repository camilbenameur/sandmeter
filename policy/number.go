package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
)

// Number is a numeric limit of a policy or a ceiling: limits.cpu and
// limits.pids. It has three states, and the zero Number is the first:
//
//   - not set: the file leaves the key out;
//   - a value: the file gives a number;
//   - unlimited: the file gives the word "unlimited".
//
// A Number never holds NaN or an infinity: decoding refuses them, so a file
// cannot turn a limit off with a value that compares false with everything.
// Whether a value is in range (positive, a whole number for pids, at least
// the backend's minimum) is for the policy check to say, with the key in its
// message.
type Number struct {
	state numberState
	value float64
}

type numberState uint8

const (
	numberUnset numberState = iota
	numberValue
	numberUnlimited
)

// Num returns the Number that holds v. It panics if v is NaN or an infinity,
// which no Number may hold; values read from a file never reach it.
func Num(v float64) Number {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		panic("policy: a limit must be a finite number")
	}
	return Number{state: numberValue, value: v}
}

// NoLimit returns the Number that says "unlimited".
func NoLimit() Number { return Number{state: numberUnlimited} }

// IsSet reports whether the file gave the key at all.
func (n Number) IsSet() bool { return n.state != numberUnset }

// IsUnlimited reports whether the file gave the word "unlimited".
func (n Number) IsUnlimited() bool { return n.state == numberUnlimited }

// Value returns the number the file gave. ok is false when the key was left
// out or says "unlimited".
func (n Number) Value() (v float64, ok bool) {
	return n.value, n.state == numberValue
}

// IsZero reports whether n is not set. encoding/json consults it for a field
// tagged omitzero.
func (n Number) IsZero() bool { return n.state == numberUnset }

// String returns "" when not set, "unlimited", or the shortest decimal form
// of the value.
func (n Number) String() string {
	switch n.state {
	case numberValue:
		return strconv.FormatFloat(n.value, 'f', -1, 64)
	case numberUnlimited:
		return Unlimited
	}
	return ""
}

// MarshalJSON encodes a value as a JSON number, "unlimited" as that string
// and an unset Number as null.
func (n Number) MarshalJSON() ([]byte, error) {
	switch n.state {
	case numberValue:
		return []byte(n.String()), nil
	case numberUnlimited:
		return json.Marshal(Unlimited)
	}
	return []byte("null"), nil
}

// UnmarshalJSON is the inverse of MarshalJSON. Any other string, and a number
// too large to be finite, is an error.
func (n *Number) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if bytes.Equal(b, []byte("null")) {
		*n = Number{}
		return nil
	}
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		return n.setWord(s)
	}
	v, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		return fmt.Errorf("a limit must be a number or %q", Unlimited)
	}
	return n.setValue(v)
}

// UnmarshalTOML lets a TOML decoder that follows the convention of
// github.com/BurntSushi/toml read the key: an integer, a float, or the string
// "unlimited". "nan" and "inf", which TOML accepts as floats, are refused.
func (n *Number) UnmarshalTOML(v any) error {
	switch v := v.(type) {
	case int64:
		return n.setValue(float64(v))
	case float64:
		return n.setValue(v)
	case string:
		return n.setWord(v)
	}
	return fmt.Errorf("a limit must be a number or %q", Unlimited)
}

// MarshalTOML is the inverse of UnmarshalTOML for an encoder that follows the
// same convention. An unset Number has no TOML form: tag the field omitempty.
func (n Number) MarshalTOML() ([]byte, error) {
	switch n.state {
	case numberValue:
		return []byte(n.String()), nil
	case numberUnlimited:
		return []byte(strconv.Quote(Unlimited)), nil
	}
	return nil, fmt.Errorf("a limit that is not set has no TOML form")
}

func (n *Number) setValue(v float64) error {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return fmt.Errorf("a limit must be a finite number: write %q for no limit", Unlimited)
	}
	*n = Number{state: numberValue, value: v}
	return nil
}

func (n *Number) setWord(s string) error {
	if s != Unlimited {
		return fmt.Errorf("a limit must be a number or %q", Unlimited)
	}
	*n = Number{state: numberUnlimited}
	return nil
}
