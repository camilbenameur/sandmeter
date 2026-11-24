// Package iox holds the few I/O helpers that several packages of sandmeter
// share: the writers that sit between a command's output and whoever reads
// it.
//
// They have one rule in common. The bytes come from a program in a sandbox
// and the reader may be slow, gone or small. A writer of this package
// therefore never fails and never blocks on behalf of its reader's limits:
// Write always reports that it took everything, so the program never sees a
// broken pipe because a cap was reached, and what could not be kept or
// delivered is counted exactly instead of being dropped in silence.
package iox

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"sync"
	"unicode/utf8"
)

// LimitedBuffer keeps the first Limit bytes written and drops the rest, so a
// sandboxed program cannot exhaust host memory through its output. Writes
// never fail: the program must not see a broken pipe because of the cap.
type LimitedBuffer struct {
	Limit int

	mu        sync.Mutex
	buf       []byte
	truncated bool
}

// Write implements io.Writer.
func (b *LimitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	room := b.Limit - len(b.buf)
	switch {
	case len(p) == 0:
	case room <= 0:
		b.truncated = true
	case len(p) > room:
		b.buf = append(b.buf, p[:room]...)
		b.truncated = true
	default:
		b.buf = append(b.buf, p...)
	}
	return len(p), nil
}

// Bytes returns a copy of what was kept.
func (b *LimitedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf...)
}

// Truncated reports whether bytes were dropped.
func (b *LimitedBuffer) Truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.truncated
}

// StreamSum is the account of one output stream that went through a
// HashingTee.
type StreamSum struct {
	// SHA256 is the lower-case hexadecimal SHA-256 of every byte written,
	// delivered or not.
	SHA256 string
	// Bytes is the number of bytes written.
	Bytes int64
	// Delivered is the number of those bytes the destination took. It is
	// below Bytes when the cap was reached or the destination failed.
	Delivered int64
	// Truncated is true when the cap, and not a failure of the destination,
	// kept bytes from being delivered.
	Truncated bool
	// Err is the first error of the destination, after which nothing more
	// was delivered; nil when it never failed.
	Err error
}

// HashingTee passes what is written to a destination while it hashes and
// counts every byte. The hash and the count cover everything written; the
// destination gets at most a fixed number of bytes and nothing after its
// first error.
//
// Write never fails and never returns a short count. A HashingTee is safe
// for use by several goroutines; the bytes of concurrent writes are hashed
// and delivered in the order the writes are served.
type HashingTee struct {
	mu        sync.Mutex
	dst       io.Writer
	limit     int64
	h         hash.Hash
	bytes     int64
	delivered int64
	truncated bool
	err       error
}

// NewHashingTee returns a tee to dst. A nil dst delivers nothing: the tee
// then only hashes and counts. limit is the largest number of bytes handed to
// dst; zero or less means no cap.
func NewHashingTee(dst io.Writer, limit int64) *HashingTee {
	return &HashingTee{dst: dst, limit: limit, h: sha256.New()}
}

// Write implements io.Writer. It always returns len(p) and a nil error.
func (t *HashingTee) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.h.Write(p)
	t.bytes += int64(len(p))
	if t.dst == nil || t.err != nil || len(p) == 0 {
		return len(p), nil
	}
	out := p
	if t.limit > 0 {
		room := t.limit - t.delivered
		if room <= 0 {
			t.truncated = true
			return len(p), nil
		}
		if int64(len(out)) > room {
			out = out[:room]
			t.truncated = true
		}
	}
	n, err := t.dst.Write(out)
	if n < 0 {
		n = 0
	}
	if n > len(out) {
		n = len(out)
	}
	t.delivered += int64(n)
	if err == nil && n < len(out) {
		err = io.ErrShortWrite
	}
	if err != nil {
		// Invariant: after the first error the destination gets nothing more.
		// A reader that went away must not be written to again, and the
		// command behind this stream keeps running regardless.
		t.err = err
	}
	return len(p), nil
}

// Sum returns the account of the stream so far. It may be called while
// writes go on.
func (t *HashingTee) Sum() StreamSum {
	t.mu.Lock()
	defer t.mu.Unlock()
	return StreamSum{
		SHA256:    hex.EncodeToString(t.h.Sum(nil)),
		Bytes:     t.bytes,
		Delivered: t.delivered,
		Truncated: t.truncated,
		Err:       t.err,
	}
}

// HeadTail keeps the first and the last bytes of a stream and counts the
// bytes it dropped in between, exactly. It is what turns an output of any
// size into something that fits a bounded result: "the first lines, a marker
// saying how much is missing, the last lines".
//
// It also says whether the whole stream, dropped part included, was text:
// valid UTF-8 without a NUL byte. A caller that shows the kept parts as text
// needs to know that, and cannot find out from the parts alone.
//
// Write never fails. A HeadTail is safe for use by several goroutines.
type HeadTail struct {
	mu      sync.Mutex
	headMax int
	tailMax int
	head    []byte
	// ring holds the last tailMax bytes that did not fit in head; start is
	// the index of its oldest byte once it is full.
	ring  []byte
	start int
	total int64

	// Text validation across writes: pending holds the bytes of a UTF-8
	// sequence that is not complete yet.
	pending [utf8.UTFMax]byte
	npend   int
	notText bool
}

// NewHeadTail returns a HeadTail that keeps the first head bytes and the
// last tail bytes. A negative size counts as zero.
func NewHeadTail(head, tail int) *HeadTail {
	if head < 0 {
		head = 0
	}
	if tail < 0 {
		tail = 0
	}
	return &HeadTail{headMax: head, tailMax: tail}
}

// Write implements io.Writer. It always returns len(p) and a nil error.
func (h *HeadTail) Write(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.total += int64(len(p))
	h.validate(p)

	rest := p
	if room := h.headMax - len(h.head); room > 0 {
		n := min(room, len(rest))
		h.head = append(h.head, rest[:n]...)
		rest = rest[n:]
	}
	if h.tailMax == 0 || len(rest) == 0 {
		return len(p), nil
	}
	if len(rest) >= h.tailMax {
		// Only the end of this write can still be in the tail.
		h.ring = append(h.ring[:0], rest[len(rest)-h.tailMax:]...)
		h.start = 0
		return len(p), nil
	}
	for len(rest) > 0 {
		if len(h.ring) < h.tailMax {
			n := min(h.tailMax-len(h.ring), len(rest))
			h.ring = append(h.ring, rest[:n]...)
			rest = rest[n:]
			continue
		}
		n := copy(h.ring[h.start:], rest)
		h.start = (h.start + n) % h.tailMax
		rest = rest[n:]
	}
	return len(p), nil
}

// validate feeds p to the running text check.
func (h *HeadTail) validate(p []byte) {
	if h.notText {
		return
	}
	for len(p) > 0 {
		if h.npend == 0 {
			// Fast path: whole runes inside p.
			r, size := utf8.DecodeRune(p)
			switch {
			case r == 0:
				h.notText = true
				return
			case r != utf8.RuneError || size > 1:
				p = p[size:]
				continue
			case utf8.FullRune(p):
				// A complete sequence that does not decode.
				h.notText = true
				return
			}
			// The start of a sequence that p cuts short.
			h.npend = copy(h.pending[:], p)
			return
		}
		h.pending[h.npend] = p[0]
		h.npend++
		p = p[1:]
		if !utf8.FullRune(h.pending[:h.npend]) {
			continue
		}
		if r, size := utf8.DecodeRune(h.pending[:h.npend]); r == 0 || (r == utf8.RuneError && size == 1) {
			h.notText = true
			return
		}
		h.npend = 0
	}
}

// Kept is what a HeadTail holds at one moment.
type Kept struct {
	// Head is the start of the stream and Tail its end. When nothing was
	// dropped, Head is the whole stream and Tail is empty. Otherwise neither
	// is cut in the middle of a UTF-8 sequence: the bytes of a sequence that
	// the cut would have split are counted as dropped.
	Head, Tail []byte
	// Dropped is the number of bytes of the stream that are in neither.
	Dropped int64
	// Total is the number of bytes written.
	Total int64
	// Text is true when everything written so far is valid UTF-8 without a
	// NUL byte and does not end inside a sequence.
	Text bool
}

// Kept returns a copy of what is held. It may be called while writes go on.
func (h *HeadTail) Kept() Kept {
	h.mu.Lock()
	defer h.mu.Unlock()
	head := append([]byte(nil), h.head...)
	tail := make([]byte, 0, len(h.ring))
	tail = append(tail, h.ring[h.start:]...)
	tail = append(tail, h.ring[:h.start]...)
	k := Kept{Total: h.total, Text: !h.notText && h.npend == 0}
	if dropped := h.total - int64(len(head)) - int64(len(tail)); dropped > 0 {
		// The stream is cut after head and before tail. Give back to the
		// dropped part the pieces of a sequence left on either side. At most
		// three bytes move on each side, whatever the bytes are: a lead byte
		// announces at most three more, and at most three continuation bytes
		// can follow one.
		head = trimPartialEnd(head)
		tail = trimPartialStart(tail)
	} else {
		// Nothing is missing: the two buffers are one piece of text, and the
		// place where one ends and the other starts means nothing.
		head, tail = append(head, tail...), nil
	}
	k.Head, k.Tail = head, tail
	k.Dropped = h.total - int64(len(head)) - int64(len(tail))
	return k
}

// trimPartialEnd removes from the end of b the first bytes of a UTF-8
// sequence whose remaining bytes are missing.
func trimPartialEnd(b []byte) []byte {
	for back := 1; back <= utf8.UTFMax-1 && back <= len(b); back++ {
		c := b[len(b)-back]
		if utf8.RuneStart(c) {
			if c >= utf8.RuneSelf && !utf8.FullRune(b[len(b)-back:]) {
				return b[:len(b)-back]
			}
			return b
		}
	}
	return b
}

// trimPartialStart removes from the start of b the continuation bytes of a
// sequence whose first byte is missing.
func trimPartialStart(b []byte) []byte {
	n := 0
	for n < len(b) && n < utf8.UTFMax-1 && !utf8.RuneStart(b[n]) {
		n++
	}
	return b[n:]
}
