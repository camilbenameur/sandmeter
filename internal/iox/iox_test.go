package iox

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

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

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestHashingTeeStreamsHashesAndCounts(t *testing.T) {
	var dst bytes.Buffer
	tee := NewUncappedHashingTee(&dst)
	for _, s := range []string{"hello ", "", "world\n"} {
		if n, err := tee.Write([]byte(s)); n != len(s) || err != nil {
			t.Fatalf("Write(%q) = %d, %v", s, n, err)
		}
		// Output is delivered as it is written, not at the end.
		if !strings.HasSuffix(dst.String(), s) {
			t.Fatalf("after writing %q the destination holds %q", s, dst.String())
		}
	}
	got := tee.Sum()
	want := StreamSum{SHA256: sum("hello world\n"), Bytes: 12, Delivered: 12}
	if got != want {
		t.Errorf("Sum() = %+v, want %+v", got, want)
	}
	if empty := NewUncappedHashingTee(nil).Sum(); empty.SHA256 != sum("") || empty.Bytes != 0 {
		t.Errorf("an unused tee: %+v", empty)
	}
}

func TestHashingTeeCap(t *testing.T) {
	var dst bytes.Buffer
	tee := NewHashingTee(&dst, 5)
	for _, s := range []string{"abc", "defg", "hij"} {
		if n, err := tee.Write([]byte(s)); n != len(s) || err != nil {
			t.Fatalf("Write(%q) = %d, %v: the writer must never see the cap", s, n, err)
		}
	}
	got := tee.Sum()
	// The hash and the count cover everything written, not what was kept.
	if dst.String() != "abcde" || got.SHA256 != sum("abcdefghij") || got.Bytes != 10 || got.Delivered != 5 || !got.Truncated || got.Err != nil {
		t.Errorf("capped tee: destination %q, %+v", dst.String(), got)
	}

	exact := NewHashingTee(io.Discard, 3)
	exact.Write([]byte("abc"))
	if s := exact.Sum(); s.Truncated || s.Delivered != 3 {
		t.Errorf("an exact fit is reported as truncated: %+v", s)
	}
}

// TestHashingTeeWithNothingLeft is the case of a caller that passes what
// remains of a budget: when nothing remains, nothing is delivered. A limit
// of zero used to mean "no cap", which turned a spent budget into an
// unbounded stream of sandbox output.
func TestHashingTeeWithNothingLeft(t *testing.T) {
	const budget = 8
	for _, used := range []int64{8, 9, 1 << 40} {
		var dst bytes.Buffer
		tee := NewHashingTee(&dst, budget-used)
		for _, s := range []string{"abc", strings.Repeat("x", 4096)} {
			if n, err := tee.Write([]byte(s)); n != len(s) || err != nil {
				t.Fatalf("Write = %d, %v: the writer must never see the cap", n, err)
			}
		}
		got := tee.Sum()
		if dst.Len() != 0 || got.Delivered != 0 || !got.Truncated || got.Bytes != 4099 || got.Err != nil {
			t.Errorf("with %d of %d bytes used, the destination got %d bytes: %+v", used, budget, dst.Len(), got)
		}
		if got.SHA256 != sum("abc"+strings.Repeat("x", 4096)) {
			t.Errorf("the hash does not cover what was not delivered")
		}
	}
	// Nothing written, nothing cut.
	if s := NewHashingTee(io.Discard, 0).Sum(); s.Truncated || s.Bytes != 0 {
		t.Errorf("an unused tee with no room: %+v", s)
	}
	// The bounded writers of the package agree on what zero means.
	var buf LimitedBuffer
	buf.Write([]byte("abc"))
	kept := NewHeadTail(0, 0)
	kept.Write([]byte("abc"))
	if len(buf.Bytes()) != 0 || !buf.Truncated() || len(kept.Kept().Head) != 0 || kept.Kept().Dropped != 3 {
		t.Errorf("zero keeps something elsewhere: %q, %+v", buf.Bytes(), kept.Kept())
	}
	// Without a cap, everything goes through.
	var dst bytes.Buffer
	all := NewUncappedHashingTee(&dst)
	all.Write(bytes.Repeat([]byte("y"), 1<<20))
	if s := all.Sum(); dst.Len() != 1<<20 || s.Delivered != 1<<20 || s.Truncated {
		t.Errorf("an uncapped tee delivered %d bytes: %+v", dst.Len(), s)
	}
}

// failAfter accepts n bytes in all, then fails.
type failAfter struct {
	n     int
	calls int
}

var errGone = errors.New("the reader went away")

func (f *failAfter) Write(p []byte) (int, error) {
	f.calls++
	if len(p) <= f.n {
		f.n -= len(p)
		return len(p), nil
	}
	n := f.n
	f.n = 0
	return n, errGone
}

func TestHashingTeeDestinationFailure(t *testing.T) {
	dst := &failAfter{n: 4}
	tee := NewUncappedHashingTee(dst)
	for _, s := range []string{"abc", "def", "ghi", "jkl"} {
		if n, err := tee.Write([]byte(s)); n != len(s) || err != nil {
			t.Fatalf("Write(%q) = %d, %v: a reader that went away must not stop the command", s, n, err)
		}
	}
	got := tee.Sum()
	if got.SHA256 != sum("abcdefghijkl") || got.Bytes != 12 || got.Delivered != 4 || got.Truncated || !errors.Is(got.Err, errGone) {
		t.Errorf("after a failure: %+v", got)
	}
	// "abc" went through, "def" failed after one byte: no write after that.
	if dst.calls != 2 {
		t.Errorf("the destination was written to %d times, want 2: nothing may follow its first error", dst.calls)
	}

	// A destination that takes fewer bytes without an error broke the
	// io.Writer contract: it is treated as failed.
	short := NewUncappedHashingTee(shortWriter{})
	short.Write([]byte("abcdef"))
	if s := short.Sum(); !errors.Is(s.Err, io.ErrShortWrite) || s.Delivered != 1 {
		t.Errorf("a short write: %+v", s)
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return 1, nil }

func TestHashingTeeNilDestination(t *testing.T) {
	tee := NewUncappedHashingTee(nil)
	tee.Write([]byte("abc"))
	if s := tee.Sum(); s.Bytes != 3 || s.Delivered != 0 || s.Truncated || s.SHA256 != sum("abc") {
		t.Errorf("a tee to nothing: %+v", s)
	}
}

func TestHashingTeeConcurrentWrites(t *testing.T) {
	var dst bytes.Buffer
	tee := NewUncappedHashingTee(&dst)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				tee.Write([]byte("0123456789"))
				tee.Sum()
			}
		}()
	}
	wg.Wait()
	s := tee.Sum()
	// Whatever the interleaving, the hash is that of the bytes delivered.
	if s.Bytes != 8000 || s.Delivered != 8000 || s.SHA256 != sum(dst.String()) {
		t.Errorf("concurrent writes: %+v, destination %d bytes", s, dst.Len())
	}
}

func TestHeadTailKeepsEverythingThatFits(t *testing.T) {
	h := NewHeadTail(4, 4)
	h.Write([]byte("abc"))
	h.Write([]byte("defgh"))
	k := h.Kept()
	if string(k.Head) != "abcdefgh" || len(k.Tail) != 0 || k.Dropped != 0 || k.Total != 8 || !k.Text {
		t.Errorf("an exact fit: %+v", k)
	}
	if k := NewHeadTail(4, 4).Kept(); len(k.Head) != 0 || len(k.Tail) != 0 || k.Dropped != 0 || !k.Text {
		t.Errorf("nothing written: %+v", k)
	}
}

func TestHeadTailDropsTheMiddleExactly(t *testing.T) {
	h := NewHeadTail(3, 4)
	in := "0123456789abcdefghij"
	// Written in pieces of every size, the result is the same.
	for size := 1; size <= len(in); size++ {
		h = NewHeadTail(3, 4)
		for i := 0; i < len(in); i += size {
			h.Write([]byte(in[i:min(i+size, len(in))]))
		}
		k := h.Kept()
		if string(k.Head) != "012" || string(k.Tail) != "ghij" || k.Dropped != 13 || k.Total != 20 {
			t.Fatalf("pieces of %d bytes: %+v", size, k)
		}
	}
	// What is returned is a copy.
	k := h.Kept()
	k.Head[0], k.Tail[0] = 'X', 'X'
	if again := h.Kept(); string(again.Head) != "012" || string(again.Tail) != "ghij" {
		t.Errorf("Kept returned the buffers themselves: %+v", again)
	}
}

func TestHeadTailZeroSizes(t *testing.T) {
	for _, tc := range []struct {
		head, tail int
		wantHead   string
		wantTail   string
		dropped    int64
	}{
		{0, 3, "", "hij", 7},
		{3, 0, "abc", "", 7},
		{0, 0, "", "", 10},
		{-1, -5, "", "", 10},
	} {
		h := NewHeadTail(tc.head, tc.tail)
		h.Write([]byte("abcdefghij"))
		if k := h.Kept(); string(k.Head) != tc.wantHead || string(k.Tail) != tc.wantTail || k.Dropped != tc.dropped {
			t.Errorf("NewHeadTail(%d, %d): %+v", tc.head, tc.tail, k)
		}
	}
}

func TestHeadTailDoesNotSplitACharacter(t *testing.T) {
	// "é" is two bytes, "€" three, "😀" four.
	in := "aé€😀" + strings.Repeat("x", 50) + "😀€éz"
	for head := 0; head <= 12; head++ {
		for tail := 0; tail <= 12; tail++ {
			h := NewHeadTail(head, tail)
			h.Write([]byte(in))
			k := h.Kept()
			if !utf8.Valid(k.Head) || !utf8.Valid(k.Tail) {
				t.Errorf("head %d, tail %d: a character was split: %q ... %q", head, tail, k.Head, k.Tail)
			}
			if !strings.HasPrefix(in, string(k.Head)) || !strings.HasSuffix(in, string(k.Tail)) {
				t.Errorf("head %d, tail %d: %q ... %q are not the two ends of the input", head, tail, k.Head, k.Tail)
			}
			if k.Dropped != int64(len(in)-len(k.Head)-len(k.Tail)) || k.Total != int64(len(in)) || !k.Text {
				t.Errorf("head %d, tail %d: dropped %d of %d, text %v", head, tail, k.Dropped, k.Total, k.Text)
			}
		}
	}
}

func TestHeadTailText(t *testing.T) {
	for _, tc := range []struct {
		name   string
		pieces []string
		text   bool
	}{
		{"ascii", []string{"hello\n"}, true},
		{"multi-byte in one piece", []string{"héllo €"}, true},
		{"a character split across writes", []string{"h\xc3", "\xa9llo \xe2\x82", "\xac \xf0", "\x9f", "\x98", "\x80"}, true},
		{"the replacement character itself", []string{"\xef\xbf", "\xbd"}, true},
		{"nul", []string{"a\x00b"}, false},
		{"nul after a split", []string{"\xc3", "\x00"}, false},
		{"stray continuation byte", []string{"a\x80b"}, false},
		{"truncated sequence then ascii", []string{"\xe2\x82", "A"}, false},
		{"overlong encoding", []string{"\xc0\xaf"}, false},
		{"surrogate", []string{"\xed\xa0\x80"}, false},
		{"ends inside a sequence", []string{"abc\xe2\x82"}, false},
		{"binary", []string{"\x7fELF\x02\x01\x01\x00"}, false},
	} {
		h := NewHeadTail(2, 2)
		for _, p := range tc.pieces {
			h.Write([]byte(p))
		}
		if got := h.Kept().Text; got != tc.text {
			t.Errorf("%s: Text = %v, want %v", tc.name, got, tc.text)
		}
		if whole := strings.Join(tc.pieces, ""); (utf8.ValidString(whole) && !strings.ContainsRune(whole, 0)) != tc.text {
			t.Errorf("%s: the expectation of this test is wrong", tc.name)
		}
	}
}

// TestHeadTailAgainstAModel feeds random bytes, text or not, in random
// pieces, and compares with the obvious computation on the whole input.
func TestHeadTailAgainstAModel(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alphabet := []string{"a", "\n", "é", "€", "😀", "\x80", "\xff", "\xe2", "\x00", "\xf0\x9f"}
	for round := 0; round < 2000; round++ {
		var in []byte
		for n := rng.Intn(40); n > 0; n-- {
			in = append(in, alphabet[rng.Intn(len(alphabet))]...)
		}
		headMax, tailMax := rng.Intn(8), rng.Intn(8)
		h := NewHeadTail(headMax, tailMax)
		for rest := in; len(rest) > 0; {
			n := 1 + rng.Intn(len(rest))
			h.Write(rest[:n])
			rest = rest[n:]
		}
		k := h.Kept()
		if !bytes.HasPrefix(in, k.Head) || !bytes.HasSuffix(in, k.Tail) {
			t.Fatalf("input %q, sizes %d and %d: kept %q ... %q", in, headMax, tailMax, k.Head, k.Tail)
		}
		if k.Total != int64(len(in)) || k.Dropped != int64(len(in)-len(k.Head)-len(k.Tail)) || k.Dropped < 0 {
			t.Fatalf("input %q: total %d, dropped %d, kept %d + %d", in, k.Total, k.Dropped, len(k.Head), len(k.Tail))
		}
		if k.Dropped > 0 && (len(k.Head) > headMax || len(k.Tail) > tailMax) {
			t.Fatalf("input %q: kept %d and %d bytes, more than %d and %d", in, len(k.Head), len(k.Tail), headMax, tailMax)
		}
		if k.Dropped == 0 && (!bytes.Equal(k.Head, in) || len(k.Tail) != 0) {
			t.Fatalf("input %q fits and came back as %q ... %q", in, k.Head, k.Tail)
		}
		// At most three bytes are given up on each side of the cut.
		if len(in) > headMax+tailMax && (len(k.Head) < headMax-3 || len(k.Tail) < tailMax-3) {
			t.Fatalf("input %q, sizes %d and %d: kept only %d and %d", in, headMax, tailMax, len(k.Head), len(k.Tail))
		}
		if want := utf8.Valid(in) && !bytes.ContainsRune(in, 0); k.Text != want {
			t.Fatalf("input %q: Text = %v, want %v", in, k.Text, want)
		}
		if k.Text && (!utf8.Valid(k.Head) || !utf8.Valid(k.Tail)) {
			t.Fatalf("input %q is text and the kept parts %q ... %q are not", in, k.Head, k.Tail)
		}
	}
}

func TestHeadTailConcurrentWrites(t *testing.T) {
	h := NewHeadTail(16, 16)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				h.Write([]byte("0123456789"))
				h.Kept()
			}
		}()
	}
	wg.Wait()
	if k := h.Kept(); k.Total != 16000 || k.Dropped != 16000-32 {
		t.Errorf("concurrent writes: total %d, dropped %d", k.Total, k.Dropped)
	}
}
