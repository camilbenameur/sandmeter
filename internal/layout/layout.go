// Package layout says where sandmeter keeps things: the directories of the
// root side under its home, the socket, the operator file, and the per-user
// directories of the unprivileged client. It also owns the "format" files
// that give each store a version, and the one rule for reading them.
//
// # The root side
//
// Everything persistent lives under the home directory, which is root's and
// closed to everybody else (mode 0700):
//
//	<home>/images/      the image store
//	<home>/state/       one directory per session, named after its identifier
//	<home>/receipts/    <uid>/<session>/ holding the signed records
//	<home>/keys/        the signing key and its public half
//
// Nothing is kept on /run except the socket. A session directory and a
// receipt directory are named after an identifier the service generated
// (package ids) and after a numeric uid: no name under the home ever comes
// from text a client sent.
//
// # Format files
//
// Each of the four stores has a file named "format" at its top that says
// which version of the store's layout the directory holds. The rule is the
// same for all of them and is implemented once, in Ensure: a directory
// written by a newer sandmeter is refused; one written by an older sandmeter
// is migrated or discarded by the package that owns the store, with a message
// that says which; a build never reads a layout it does not know, and never
// takes for a store a directory that is not one: a link, a directory of
// another user, or one that holds something sandmeter did not write.
//
// # The client
//
// The unprivileged client keeps what it fetched from the service in the
// user's own directories, following the XDG base directory convention: see
// User.
package layout

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/camilbenameur/sandmeter/internal/ids"
)

// Fixed locations and names of an installation.
const (
	// ConfigFile is the operator file. Only root can write it, and it is
	// refused unless every directory above it is root's too.
	ConfigFile = "/etc/sandmeter/config.toml"
	// DefaultHome is the home directory unless the operator file names
	// another.
	DefaultHome = "/var/lib/sandmeter"
	// SocketDir is the directory of the socket, and Socket the socket the
	// service listens on and the client dials.
	SocketDir = "/run/sandmeter"
	Socket    = SocketDir + "/sandmeter.sock"
	// Group is the group whose members may connect to the socket.
	Group = "sandmeter"

	// EnvSocket names the environment variable that makes the client dial
	// another socket path. It is read by the client only.
	EnvSocket = "SANDMETER_SOCKET"
	// EnvLog names the environment variable that sets the log level
	// ("debug", "info", "warn", "error").
	EnvLog = "SANDMETER_LOG"
)

// The default image.
const (
	// DefaultImage is the image a session gets when it names none and the
	// operator file names no other: one small image, pinned by the digest of
	// its multi-architecture index, on a branch its publisher still supports.
	// The tag in the reference is for the reader; the digest is what is
	// pulled.
	//
	// The digest was read from the registry on 2026-11-24 (Alpine 3.24.4). It
	// changes only together with DefaultImageSupportEnds, in a commit that
	// says where the new value was read.
	DefaultImage = "docker.io/library/alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf"
	// DefaultImageSupportEnds is the day the publisher stops supporting the
	// branch of DefaultImage, as it announced it, in the form 2006-01-02. A
	// scheduled check fails well before that day, so that the default is
	// moved to a supported branch before it stops receiving fixes.
	DefaultImageSupportEnds = "2028-06-01"
)

// Modes of what the root side creates under the home.
const (
	// DirMode is the mode of every directory under the home, the home
	// included: root only.
	DirMode os.FileMode = 0o700
	// FileMode is the mode of every file under the home.
	FileMode os.FileMode = 0o600
)

// The ids of sandboxes on the host.
const (
	// DefaultIDBase is the host id that root of a sandbox maps to unless the
	// operator file sets another. It lies in a range that neither the
	// distributions' subordinate-id allocation nor systemd hands out.
	DefaultIDBase uint32 = 1879048192
	// IDCount is the number of ids of one sandbox: ids 0 to IDCount-1 inside
	// are ids base to base+IDCount-1 on the host.
	IDCount = 65536
	// FetchIDOffset and EgressIDOffset place the two service ids just above
	// the sandbox ids: the processes that fetch images and that serve the
	// egress proxy run as base+FetchIDOffset and base+EgressIDOffset, ids
	// that no sandbox maps and no account of the host has.
	FetchIDOffset  = IDCount
	EgressIDOffset = IDCount + 1
	// ReservedIDs is how many host ids an installation takes from its base:
	// the sandbox ids and the two service ids.
	ReservedIDs = IDCount + 2
)

// Home is the directory tree of the root side.
type Home struct {
	// Dir is the home directory.
	Dir string
	// StateDir is the state directory: <Dir>/state unless the operator file
	// puts it on another filesystem.
	StateDir string
}

// NewHome returns the tree rooted at dir. state is the state directory, or
// empty for the default inside dir. Both must be absolute, clean paths
// without a colon or a comma: they end up in mount options, where those two
// characters separate fields.
func NewHome(dir, state string) (Home, error) {
	if state == "" {
		state = filepath.Join(dir, "state")
	}
	for name, p := range map[string]string{"home": dir, "state": state} {
		if err := checkDir(p); err != nil {
			return Home{}, fmt.Errorf("%s directory %s: %w", name, strconv.Quote(p), err)
		}
	}
	return Home{Dir: dir, StateDir: state}, nil
}

func checkDir(p string) error {
	switch {
	case !filepath.IsAbs(p):
		return errors.New("the path must be absolute")
	case filepath.Clean(p) != p:
		return errors.New("the path must be clean: no \".\", \"..\", doubled or trailing slash")
	case strings.ContainsAny(p, ":,"):
		return errors.New("the path must not contain a colon or a comma")
	case strings.ContainsRune(p, 0):
		return errors.New("the path must not contain a NUL byte")
	case p == "/":
		return errors.New("the path must not be the root directory")
	}
	return nil
}

// Images returns the directory of the image store.
func (h Home) Images() string { return filepath.Join(h.Dir, "images") }

// State returns the state directory, which holds one directory per session.
func (h Home) State() string { return h.StateDir }

// Receipts returns the directory of the receipts of every user.
func (h Home) Receipts() string { return filepath.Join(h.Dir, "receipts") }

// Keys returns the directory of the signing key.
func (h Home) Keys() string { return filepath.Join(h.Dir, "keys") }

// Session returns the directory of one session. The name is the text of an
// identifier, which is a plain file name by construction.
func (h Home) Session(id ids.ID) string { return filepath.Join(h.StateDir, id.String()) }

// UserReceipts returns the directory of the receipts of one user.
func (h Home) UserReceipts(uid uint32) string {
	return filepath.Join(h.Receipts(), strconv.FormatUint(uint64(uid), 10))
}

// SessionReceipts returns the directory that holds the records of one
// session of one user.
func (h Home) SessionReceipts(uid uint32, id ids.ID) string {
	return filepath.Join(h.UserReceipts(uid), id.String())
}

// StoreDir returns the directory of a store.
func (h Home) StoreDir(s Store) string {
	switch s {
	case StoreImages:
		return h.Images()
	case StoreState:
		return h.State()
	case StoreReceipts:
		return h.Receipts()
	case StoreKeys:
		return h.Keys()
	}
	panic("layout: no store " + string(s))
}

// seqWidth is the width of a sequence number in a file name: the names of a
// session's records then sort in the order of the chain.
const seqWidth = 10

// RecordFile returns the name of the file that holds the record with the
// given sequence number and kind, inside the directory of its session:
// "0000000003-command.json".
func RecordFile(seq uint64, kind string) string {
	return fmt.Sprintf("%0*d-%s.json", seqWidth, seq, kind)
}

// IntentFile returns the name of the file that holds the intent written
// before the command with the given sequence number starts:
// "0000000003.intent".
func IntentFile(seq uint64) string {
	return fmt.Sprintf("%0*d.intent", seqWidth, seq)
}

// ParseRecordFile reads back a name made by RecordFile. ok is false for any
// other name: a caller that lists a receipt directory skips what it does not
// recognise and never builds a path from it.
func ParseRecordFile(name string) (seq uint64, kind string, ok bool) {
	rest, found := strings.CutSuffix(name, ".json")
	if !found || len(rest) < seqWidth+2 || rest[seqWidth] != '-' {
		return 0, "", false
	}
	seq, ok = parseSeq(rest[:seqWidth])
	kind = rest[seqWidth+1:]
	for i := 0; i < len(kind); i++ {
		if kind[i] < 'a' || kind[i] > 'z' {
			return 0, "", false
		}
	}
	return seq, kind, ok
}

// ParseIntentFile reads back a name made by IntentFile.
func ParseIntentFile(name string) (seq uint64, ok bool) {
	rest, found := strings.CutSuffix(name, ".intent")
	if !found {
		return 0, false
	}
	return parseSeq(rest)
}

func parseSeq(s string) (uint64, bool) {
	if len(s) != seqWidth {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil && n > 0
}

// Store names one of the versioned stores under the home.
type Store string

// The stores.
const (
	StoreImages   Store = "images"
	StoreState    Store = "state"
	StoreReceipts Store = "receipts"
	StoreKeys     Store = "keys"
)

// Stores lists the stores.
var Stores = []Store{StoreImages, StoreState, StoreReceipts, StoreKeys}

// FormatFile is the name of the file, at the top of a store, that holds its
// format version.
const FormatFile = "format"

// CurrentFormat returns the format version this build reads and writes for a
// store. Version 1 is the first that has a format file; what earlier builds
// wrote has none and counts as version 0.
//
// The owner of a store raises its number here, in the same change that
// teaches the store to migrate or discard the previous one.
func CurrentFormat(s Store) int {
	switch s {
	case StoreImages, StoreState, StoreReceipts, StoreKeys:
		return 1
	}
	panic("layout: no store " + string(s))
}

// Errors of the format rule. Each is wrapped with the directory, what was
// found and what to do.
var (
	// ErrNewerFormat: the directory was written by a newer sandmeter. It is
	// refused, and nothing in it is touched.
	ErrNewerFormat = errors.New("written by a newer sandmeter")
	// ErrOlderFormat: the directory was written by an older sandmeter and
	// nothing migrated or discarded it. It is refused, and nothing in it is
	// touched.
	ErrOlderFormat = errors.New("written by an older sandmeter")
	// ErrUnknownContent: the directory has no format file and holds
	// something that no sandmeter wrote there. It is not an older store: it
	// is not a store. It is refused, nothing in it is touched, and it is
	// never handed to an upgrade that could discard it.
	ErrUnknownContent = errors.New("holds files that sandmeter did not write")
	// ErrUnsafeDir: the path is not a directory of its own (it is a symbolic
	// link, or another kind of file), or it belongs to another user. It is
	// refused, untouched.
	ErrUnsafeDir = errors.New("not a directory that belongs to sandmeter")
)

// firstLayout says, for each store, how to recognise what the first release
// of sandmeter wrote there, when stores had no format file yet: the names,
// in the syntax of path.Match, of which one at least is at the top of such a
// directory. That layout is format 0. A store that the first release did not
// keep under this name has no entry: for it, content without a format file
// is never "older".
var firstLayout = map[Store][]string{
	// refs.json and the directories of image configurations and layers.
	StoreImages: {"refs.json", "images", "layers"},
	// One file per receipt, "<session>-<n>.json".
	StoreReceipts: {"*-*.json"},
}

// formatTemp is the pattern of the temporary name under which WriteFormat
// writes the format file before it renames it. A file of that name is what a
// crash in the middle leaves behind.
const formatTemp = ".format-*"

// ReadFormat returns the format version of the store in dir:
//
//   - the number in its format file;
//   - -1 when the directory does not exist or holds nothing, which is a
//     store nobody wrote yet. Two things count as nothing, because they are
//     there on a store that was never used: the lost+found directory of a
//     filesystem made for the store, and the temporary file of a WriteFormat
//     that did not finish;
//   - 0 when there is no format file and the directory holds what the first
//     release of sandmeter wrote, before stores had one;
//   - ErrUnknownContent when there is no format file and the directory holds
//     anything else.
//
// A format file that is not exactly one line "<store> <number>" for this
// store is an error: a build never guesses what a directory holds. ReadFormat
// changes nothing.
func ReadFormat(dir string, s Store) (int, error) {
	// O_NOFOLLOW: the file is ours to write and is never a link. A link here
	// would mean that someone else shaped the directory.
	f, err := os.OpenFile(filepath.Join(dir, FormatFile), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		entries, derr := os.ReadDir(dir)
		if errors.Is(derr, os.ErrNotExist) {
			return -1, nil
		}
		if derr != nil {
			return 0, derr
		}
		content, first := 0, false
		for _, e := range entries {
			if e.Name() == "lost+found" && e.IsDir() {
				continue
			}
			if stale, _ := path.Match(formatTemp, e.Name()); stale && e.Type().IsRegular() {
				continue
			}
			content++
			for _, pattern := range firstLayout[s] {
				if ok, _ := path.Match(pattern, e.Name()); ok {
					first = true
				}
			}
		}
		switch {
		case content == 0:
			return -1, nil
		case first:
			return 0, nil
		}
		return 0, fmt.Errorf("%s has no format file and %w (%s): it is not taken for the %s store. Move the directory away, or give sandmeter an empty one",
			strconv.Quote(dir), ErrUnknownContent, plural(content, "entry", "entries"), s)
	}
	if err != nil {
		return 0, fmt.Errorf("format file of %s: %w", strconv.Quote(dir), err)
	}
	defer f.Close()
	buf := make([]byte, 64)
	n, _ := f.Read(buf)
	line := string(buf[:n])
	name, num, ok := strings.Cut(strings.TrimSuffix(line, "\n"), " ")
	v, perr := strconv.Atoi(num)
	if !ok || name != string(s) || perr != nil || v < 1 || strconv.Itoa(v) != num || !strings.HasSuffix(line, "\n") {
		return 0, fmt.Errorf("format file of %s: want one line %q with a version, found %q", strconv.Quote(dir), string(s)+" <n>", line)
	}
	return v, nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// WriteFormat marks dir as holding the current format of the store. The file
// is written under a temporary name, synced and renamed, so that a crash
// leaves either the old file or the new one.
func WriteFormat(dir string, s Store) error {
	tmp, err := os.CreateTemp(dir, formatTemp)
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := fmt.Fprintf(tmp, "%s %d\n", s, CurrentFormat(s)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(FileMode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, FormatFile)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Ensure applies the format rule to the store in dir and returns nil only
// when dir is a directory of sandmeter's own, closed to everybody else, that
// holds the current format.
//
// First the directory itself. One that does not exist is created with mode
// DirMode. One that exists must be a real directory, not a symbolic link,
// and belong to the user sandmeter runs as: anything else is ErrUnsafeDir
// and nothing is touched. If its mode gives anything to the group or to
// others, it is narrowed to DirMode, on the descriptor the checks were made
// on: a store kept from a release that created it wider, or a directory an
// operator made for it, is closed before it is used and not merely
// reported. The directories above it are not Ensure's: the host probe
// checks them.
//
// Then its content:
//
//   - Nothing in it: it is marked.
//   - The current format: nothing to do. (In both cases, a temporary file
//     that an unfinished write of the format file left behind is removed.)
//   - A newer format: ErrNewerFormat. Nothing in the directory is touched;
//     the message says to upgrade sandmeter or to move the directory away.
//   - An older format, version 0 included: upgrade is called with the
//     version found. It is the store's owner speaking: it migrates the
//     directory in place, or discards what the directory holds, and in both
//     cases logs a message that says which and why. When it returns nil the
//     directory is marked as current. When upgrade is nil, or returns an
//     error, nothing is marked and the error is ErrOlderFormat or the
//     owner's own.
//   - No format file and content that is not a store's: ErrUnknownContent.
//     upgrade is not called: an owner must never be handed, as its own old
//     store, a directory it did not write.
//
// Whether old content may be discarded is the owner's decision and differs
// by store: images can be pulled again, receipts and keys are never
// discarded.
func Ensure(dir string, s Store, upgrade func(found int) error) error {
	if err := closeDir(dir); err != nil {
		return err
	}
	found, err := ReadFormat(dir, s)
	if err != nil {
		return err
	}
	current := CurrentFormat(s)
	switch {
	case found == -1:
	case found == current:
		return removeStaleTemps(dir)
	case found > current:
		return fmt.Errorf("%s holds format %d of the %s store and this sandmeter reads up to %d: %w; upgrade sandmeter, or move the directory away to start from an empty one",
			strconv.Quote(dir), found, s, current, ErrNewerFormat)
	default:
		if upgrade == nil {
			return fmt.Errorf("%s holds format %d of the %s store and this sandmeter reads only %d: %w; move the directory away to start from an empty one",
				strconv.Quote(dir), found, s, current, ErrOlderFormat)
		}
		if err := upgrade(found); err != nil {
			return fmt.Errorf("%s holds format %d of the %s store, older than %d: %w", strconv.Quote(dir), found, s, current, err)
		}
	}
	if err := removeStaleTemps(dir); err != nil {
		return err
	}
	return WriteFormat(dir, s)
}

// closeDir makes sure that dir is a directory of this user that nobody else
// can enter, creating it when it does not exist.
//
// Invariant: a store is a real directory, owned by the user sandmeter runs
// as, with no permission for the group or for others. The checks and the
// change of mode are made on one descriptor opened without following a
// link, so that what was checked is what was narrowed.
func closeDir(dir string) error {
	open := func() (int, error) {
		return unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	fd, err := open()
	if errors.Is(err, unix.ENOENT) {
		if err := os.MkdirAll(dir, DirMode); err != nil {
			return err
		}
		fd, err = open()
	}
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		return fmt.Errorf("%s is a symbolic link or is not a directory: %w; a store is a directory of its own. Remove it, or give sandmeter another path",
			strconv.Quote(dir), ErrUnsafeDir)
	}
	if err != nil {
		return fmt.Errorf("open the store %s: %w", strconv.Quote(dir), err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("stat the store %s: %w", strconv.Quote(dir), err)
	}
	if euid := uint32(os.Geteuid()); st.Uid != euid {
		return fmt.Errorf("%s belongs to uid %d and sandmeter runs as uid %d: %w; give it to that user with chown, or give sandmeter another path",
			strconv.Quote(dir), st.Uid, euid, ErrUnsafeDir)
	}
	if st.Mode&0o077 != 0 {
		if err := unix.Fchmod(fd, uint32(DirMode)); err != nil {
			return fmt.Errorf("close the store %s, which has mode %04o, to other users: %w", strconv.Quote(dir), st.Mode&0o7777, err)
		}
	}
	return nil
}

// removeStaleTemps removes what a WriteFormat that did not finish left in
// dir: regular files under its temporary name, and nothing else.
func removeStaleTemps(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if stale, _ := path.Match(formatTemp, e.Name()); stale && e.Type().IsRegular() {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

// User is the set of directories of the unprivileged client, in the user's
// own home. The client creates them with mode 0700 and refuses to use one
// that someone else owns or can write.
type User struct {
	// Spool holds the change sets fetched from the service, one directory
	// per session, until they are applied or discarded.
	Spool string
	// Receipts holds the client's copies of the records it fetched, one
	// directory per session.
	Receipts string
	// KnownKeys holds the public keys of the services this user has pinned.
	KnownKeys string
}

// UserDirs returns the client's directories from the environment, following
// the XDG base directory convention: state under $XDG_STATE_HOME, or
// $HOME/.local/state; the pinned keys under $XDG_CONFIG_HOME, or
// $HOME/.config. A variable that is not an absolute path is ignored, as the
// convention says. getenv is os.Getenv outside tests.
func UserDirs(getenv func(string) string) (User, error) {
	home := getenv("HOME")
	base := func(xdg string, fallback ...string) (string, error) {
		if v := getenv(xdg); filepath.IsAbs(v) {
			return filepath.Join(filepath.Clean(v), "sandmeter"), nil
		}
		if !filepath.IsAbs(home) {
			return "", fmt.Errorf("cannot place sandmeter's files: neither %s nor HOME is an absolute path", xdg)
		}
		return filepath.Join(append(append([]string{home}, fallback...), "sandmeter")...), nil
	}
	state, err := base("XDG_STATE_HOME", ".local", "state")
	if err != nil {
		return User{}, err
	}
	config, err := base("XDG_CONFIG_HOME", ".config")
	if err != nil {
		return User{}, err
	}
	return User{
		Spool:     filepath.Join(state, "spool"),
		Receipts:  filepath.Join(state, "receipts"),
		KnownKeys: filepath.Join(config, "known-keys"),
	}, nil
}
