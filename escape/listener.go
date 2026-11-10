package escape

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Listener is a TCP listener the harness runs on the host to detect
// outbound connections a sandboxed case made, whether or not the policy
// allowed them. It accepts every connection (closing it right away) so a
// case that reaches it at all counts as a hit, even if it sends nothing.
type Listener struct {
	ln   net.Listener
	hits atomic.Int64

	mu     sync.Mutex
	nonces []string
	conns  map[net.Conn]struct{}
	closed bool
	done   chan struct{}
	wg     sync.WaitGroup
}

// drainTimeout bounds how long a silent client can hold a connection. The
// probe sends its nonce right after connecting, so this is generous.
const drainTimeout = 2 * time.Second

// maxNonces caps stored nonces: the client is hostile and could otherwise
// grow the slice without limit.
const maxNonces = 64

// NewListener starts a TCP listener on addr (host:port, or host:0 to pick a
// free port) and begins accepting in the background.
func NewListener(addr string) (*Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("escape: listen on %s: %w", addr, err)
	}
	l := &Listener{ln: ln, done: make(chan struct{}), conns: map[net.Conn]struct{}{}}
	go l.acceptLoop()
	return l, nil
}

// Addr is the address the listener is bound to.
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

func (l *Listener) acceptLoop() {
	defer close(l.done)
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			return
		}
		l.hits.Add(1)
		if !l.track(conn) {
			conn.Close()
			return
		}
		l.wg.Add(1)
		go l.drain(conn)
	}
}

// drain reads whatever nonce the probe sent, then closes the connection. A
// read error just means the peer closed first, which is still a hit.
func (l *Listener) drain(conn net.Conn) {
	defer l.wg.Done()
	defer l.untrack(conn)
	_ = conn.SetReadDeadline(time.Now().Add(drainTimeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 0 {
		l.mu.Lock()
		if len(l.nonces) < maxNonces {
			l.nonces = append(l.nonces, string(buf[:n]))
		}
		l.mu.Unlock()
	}
}

// track registers a live connection so Close can cut it off. It reports
// false when the listener is already closed.
func (l *Listener) track(conn net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return false
	}
	l.conns[conn] = struct{}{}
	return true
}

func (l *Listener) untrack(conn net.Conn) {
	l.mu.Lock()
	delete(l.conns, conn)
	l.mu.Unlock()
	conn.Close()
}

// Hits is the number of connections accepted so far.
func (l *Listener) Hits() int { return int(l.hits.Load()) }

// Nonces returns every nonce received so far, in arrival order.
func (l *Listener) Nonces() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.nonces...)
}

// Close stops accepting and releases the port. Idempotent.
func (l *Listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	for c := range l.conns {
		c.Close()
	}
	l.mu.Unlock()
	err := l.ln.Close()
	<-l.done
	l.wg.Wait()
	return err
}

// NewCanary writes a random token to a new file 0600 under dir and returns
// its path and the token. The harness places this file outside the sandbox
// root, as RF_HOST_CANARY_PATH, and a case passes only if the sandboxed
// process never manages to read it.
func NewCanary(dir string) (path, token string, err error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("escape: generate canary token: %w", err)
	}
	token = hex.EncodeToString(raw)

	path = filepath.Join(dir, "canary-"+token[:8])
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		return "", "", fmt.Errorf("escape: write canary file: %w", err)
	}
	return path, token, nil
}
