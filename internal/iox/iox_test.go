package iox

import "testing"

func TestLimitedBuffer(t *testing.T) {
	b := &LimitedBuffer{Limit: 5}
	for _, s := range []string{"ab", "cde", "fgh", ""} {
		if n, err := b.Write([]byte(s)); n != len(s) || err != nil {
			t.Fatalf("Write(%q) = %d, %v", s, n, err)
		}
	}
	if string(b.Bytes()) != "abcde" || !b.Truncated() {
		t.Fatalf("got %q truncated=%v", b.Bytes(), b.Truncated())
	}
	c := &LimitedBuffer{Limit: 5}
	c.Write([]byte("abcde"))
	if c.Truncated() {
		t.Fatal("exact fit reported as truncated")
	}
}
