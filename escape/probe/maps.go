package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// runMaps prints the process's own uid_map and gid_map (empty in a plain
// sandbox, non-empty once a case has entered a nested user namespace) and
// the effective capability set from /proc/self/status, so a case can show
// what privilege it actually holds without parsing /proc by hand in
// busybox sh.
func runMaps() error {
	for _, path := range []string{"/proc/self/uid_map", "/proc/self/gid_map"} {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("%s: %v\n", path, err)
			continue
		}
		fmt.Printf("%s:\n%s", path, data)
	}

	caps, err := effectiveCaps("/proc/self/status")
	if err != nil {
		return fmt.Errorf("read capabilities: %w", err)
	}
	fmt.Println("CapEff:", caps)
	return nil
}

// effectiveCaps reads the CapEff line of a /proc/<pid>/status file.
func effectiveCaps(statusPath string) (string, error) {
	f, err := os.Open(statusPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if rest, ok := strings.CutPrefix(line, "CapEff:"); ok {
			return strings.TrimSpace(rest), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("CapEff line not found in %s", statusPath)
}
