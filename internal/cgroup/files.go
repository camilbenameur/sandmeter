package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The helpers below take the cgroup directory as an argument instead of a
// Group so unit tests can point them at a fake tree in a temporary directory.

// readFile returns the content of dir/name.
func readFile(dir, name string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return "", fmt.Errorf("read cgroup file: %w", err)
	}
	return string(b), nil
}

// writeFile writes val to dir/name. It never creates the file: cgroup
// interface files are provided by the kernel, and a missing one must show up
// as ENOENT so callers can tell "controller or kernel feature absent".
// O_TRUNC is harmless on cgroupfs and keeps fake-tree tests faithful.
func writeFile(dir, name, val string) error {
	p := filepath.Join(dir, name)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return fmt.Errorf("write cgroup file: %w", err)
	}
	// The kernel parses one write() call as one command, so write once.
	_, werr := f.WriteString(val)
	cerr := f.Close()
	if werr != nil {
		return fmt.Errorf("write %q to %s: %w", val, p, werr)
	}
	if cerr != nil {
		return fmt.Errorf("close %s: %w", p, cerr)
	}
	return nil
}

// readFlat reads and parses a flat-keyed file such as memory.events.
func readFlat(dir, name string) (map[string]int64, error) {
	s, err := readFile(dir, name)
	if err != nil {
		return nil, err
	}
	m, err := parseFlat(s)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", filepath.Join(dir, name), err)
	}
	return m, nil
}

// parseFlat parses "key value" lines as found in memory.events, cpu.stat,
// pids.events and cgroup.events. Blank lines are skipped; any other line that
// is not exactly a key and an integer is an error, so a format change in a
// future kernel is noticed instead of silently reading as zero.
func parseFlat(s string) (map[string]int64, error) {
	m := make(map[string]int64)
	for i, line := range strings.Split(s, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			return nil, fmt.Errorf("line %d: want \"key value\", got %q", i+1, line)
		}
		v, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("line %d: bad value for %q: %w", i+1, fields[0], err)
		}
		m[fields[0]] = v
	}
	return m, nil
}

// readInt reads a file holding a single integer, such as memory.peak.
func readInt(dir, name string) (int64, error) {
	s, err := readFile(dir, name)
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", filepath.Join(dir, name), err)
	}
	return v, nil
}
