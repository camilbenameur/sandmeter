// Package ids defines the identifier sandmeter gives to a session.
//
// The root side generates every identifier itself, from the system's random
// source, and never accepts one it did not generate: a request that names a
// session carries an ID, the service looks it up among the sessions of the
// calling user, and an unknown one is refused. No path is ever built from a
// string a client sent.
//
// Invariant, enforced by Parse and by the type itself: an ID is 128 bits and
// its only text form is 32 lower-case hexadecimal digits. A directory, a
// cgroup or a file named after ID.String() therefore cannot hold a path
// separator, a dot segment, a NUL byte or anything else a kernel interface
// could read as more than a plain name.
package ids

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

// ID identifies one session. The zero ID is "no session": New never returns
// it, Parse refuses it and it has no text form.
type ID [16]byte

// textLen is the length of the text form: two hexadecimal digits per byte.
const textLen = 2 * len(ID{})

// ErrInvalid is the error of Parse, wrapped with what was wrong. The input is
// never echoed back: it may be arbitrarily long and is chosen by the caller.
var ErrInvalid = errors.New("invalid identifier")

// New returns a fresh random ID.
func New() (ID, error) {
	for {
		var id ID
		if _, err := rand.Read(id[:]); err != nil {
			return ID{}, fmt.Errorf("generate identifier: %w", err)
		}
		if !id.IsZero() {
			return id, nil
		}
	}
}

// Parse is the one validating parser of identifiers. It accepts exactly 32
// characters, each a digit or a letter from a to f in lower case, and refuses
// the all-zero value. Upper case, surrounding space, a "0x" prefix and any
// other length are errors, so that one session has one spelling.
func Parse(s string) (ID, error) {
	if len(s) != textLen {
		return ID{}, fmt.Errorf("%w: want %d hexadecimal digits, got %d bytes", ErrInvalid, textLen, len(s))
	}
	var id ID
	for i := 0; i < textLen; i++ {
		c := s[i]
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		default:
			return ID{}, fmt.Errorf("%w: byte %d is not a lower-case hexadecimal digit", ErrInvalid, i)
		}
		if i%2 == 0 {
			id[i/2] = v << 4
		} else {
			id[i/2] |= v
		}
	}
	if id.IsZero() {
		return ID{}, fmt.Errorf("%w: the all-zero identifier names no session", ErrInvalid)
	}
	return id, nil
}

// IsZero reports whether id is the zero ID, which names no session.
func (id ID) IsZero() bool { return id == ID{} }

// String returns the text form: 32 lower-case hexadecimal digits. It is safe
// as a single path component and as a cgroup name. The zero ID prints as 32
// zeros, which Parse refuses.
func (id ID) String() string { return hex.EncodeToString(id[:]) }

// MarshalText implements encoding.TextMarshaler, so that an ID is a JSON
// string. The zero ID has no text form: a message that may leave an ID out
// tags the field omitzero.
func (id ID) MarshalText() ([]byte, error) {
	if id.IsZero() {
		return nil, fmt.Errorf("%w: the zero identifier cannot be encoded", ErrInvalid)
	}
	return []byte(id.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler through Parse.
func (id *ID) UnmarshalText(b []byte) error {
	// The length is checked before the conversion so that a hostile input of
	// many megabytes is not copied just to be refused.
	if len(b) != textLen {
		return fmt.Errorf("%w: want %d hexadecimal digits, got %d bytes", ErrInvalid, textLen, len(b))
	}
	v, err := Parse(string(b))
	if err != nil {
		return err
	}
	*id = v
	return nil
}
