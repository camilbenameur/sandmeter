package escape

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestListenerCountsHits(t *testing.T) {
	l, err := NewListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer l.Close()

	addr := l.Addr().String()
	for i := 0; i < 3; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		if _, err := conn.Write([]byte("nonce-" + string(rune('a'+i)))); err != nil {
			t.Fatalf("Write: %v", err)
		}
		conn.Close()
	}

	deadline := time.Now().Add(2 * time.Second)
	for l.Hits() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := l.Hits(); got != 3 {
		t.Errorf("Hits() = %d, want 3", got)
	}

	deadline = time.Now().Add(2 * time.Second)
	for len(l.Nonces()) < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := len(l.Nonces()); got != 3 {
		t.Errorf("len(Nonces()) = %d, want 3", got)
	}
}

func TestListenerCloseIsIdempotent(t *testing.T) {
	l, err := NewListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestNewCanary(t *testing.T) {
	dir := t.TempDir()

	path, token, err := NewCanary(dir)
	if err != nil {
		t.Fatalf("NewCanary: %v", err)
	}
	if filepath.Dir(path) != dir {
		t.Errorf("path %q is not inside %q", path, dir)
	}
	if len(token) != 32 {
		t.Errorf("token %q has length %d, want 32", token, len(token))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s): %v", path, err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %v, want 0600", perm)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != token {
		t.Errorf("file content = %q, want token %q", data, token)
	}

	path2, token2, err := NewCanary(dir)
	if err != nil {
		t.Fatalf("second NewCanary: %v", err)
	}
	if path2 == path || token2 == token {
		t.Errorf("second NewCanary reused the first path/token")
	}
}

// A silent client must not keep Close waiting, nor leave its connection
// open after Close.
func TestListenerCloseCutsSilentClient(t *testing.T) {
	l, err := NewListener("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	for i := 0; i < 100 && l.Hits() == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}

	done := make(chan struct{})
	go func() { l.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close blocked on a silent client")
	}

	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("client connection still open after Close")
	}
}
