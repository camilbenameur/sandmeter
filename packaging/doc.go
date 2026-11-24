// Package packaging holds what a distribution package of sandmeter installs
// besides the binaries: the systemd units, the sysusers file and the default
// operator file. It contains no code; this file exists so that the tests
// beside it, which hold those files to what the code expects, have a
// package.
//
// The default operator file, config.toml, is a contract as much as a file to
// install: it writes out every key the operator file has, each with its
// built-in value, and the parser of the operator file accepts exactly those
// keys.
package packaging
