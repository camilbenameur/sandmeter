// Package deps pins modules that packages under construction will import.
// It is removed once every module is imported by real code.
package deps

import (
	_ "github.com/google/go-containerregistry/pkg/v1/remote"
	_ "github.com/modelcontextprotocol/go-sdk/mcp"
	_ "github.com/vishvananda/netlink"
	_ "golang.org/x/net/bpf"
)
