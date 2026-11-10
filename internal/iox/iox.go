// Package iox holds small I/O helpers shared by the backends.
package iox

import "sync"

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
