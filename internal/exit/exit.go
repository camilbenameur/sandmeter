// Package exit is the table of exit statuses of the sandmeter commands.
//
// One number has one meaning, whatever the command, so that a script or a CI
// job can branch on it. The table follows two conventions people already
// know. For a command run in a sandbox it is the convention of shells and
// container runtimes: the status of the command itself, 126 and 127 when it
// could not be started, 128 plus the signal number when a signal ended it,
// and 125 when sandmeter failed rather than the command. For everything else
// it is the convention of comparison tools: 0 for "yes", a small number for
// "no", another for "could not tell".
//
// The statuses sandmeter adds for a sandboxed command sit just below 125,
// where few programs put their own, so that "the policy was refused" is not
// mistaken for a test suite that failed with status 1. The ambiguity that
// remains is the one every wrapper has: a command may itself exit with any
// of these numbers. The receipt, not the status, is the record of what
// happened.
package exit

import "github.com/camilbenameur/sandmeter/receipt"

// The statuses.
const (
	// OK: the command did what was asked. For a command run in a sandbox:
	// it exited with status 0.
	OK = 0
	// Failed: a command that runs nothing in a sandbox could not do its
	// work: a file that cannot be read, a service that answers with an
	// error, a change set that cannot be applied at all.
	Failed = 1
	// Usage: the command line is wrong. Nothing was done.
	Usage = 2
	// Incomplete: the command did its work and has reservations that a
	// script must not take for success: apply skipped entries or found
	// conflicts, a chain of receipts is interrupted or has lost its tail, a
	// requirement given to verify is not met, a policy could only be checked
	// for syntax because the service did not answer.
	Incomplete = 3
	// VerifyFailed: a signature, a hash or a link of a chain does not
	// verify, or the key is not one the caller pinned. The evidence must not
	// be trusted.
	VerifyFailed = 4
	// EscapeDeviation: the escape suite ran and at least one verdict is not
	// the expected one, or a case escaped.
	EscapeDeviation = 5

	// PolicyRefused: the policy was refused before anything ran. It asks for
	// more than the operator's ceiling grants, or for a control this host
	// does not enforce, or it does not parse.
	PolicyRefused = 120
	// HostCannotRun: this host cannot run a sandbox now: the service is not
	// installed or not reachable, the caller may not use it, or the host
	// probe found a problem. The message says what to do.
	HostCannotRun = 121
	// Denied: the service refused the request for a reason that is not the
	// policy: an image the operator does not allow, a budget of the calling
	// user that is spent, free space under the operator's floor.
	Denied = 122
	// TeardownFailed: the command ran and its sandbox could not be taken
	// down completely. Something may be left on the host; the message names
	// it and the command that reclaims it. This status replaces the
	// command's own, which the receipt still records, because a leak must
	// never be silent.
	TeardownFailed = 123
	// Timeout: the sandbox killed the command because it ran longer than its
	// time limit.
	Timeout = 124
	// Failure: sandmeter failed, not the command: the sandbox could not be
	// set up, the connection to the service was lost, the record of the
	// command could not be signed or stored, the sandbox was killed for a
	// reason that is not the command's doing.
	Failure = 125
	// NotExecutable: the command was found in the sandbox and cannot be
	// executed.
	NotExecutable = 126
	// NotFound: the command, or its working directory, does not exist in the
	// sandbox.
	NotFound = 127
	// SignalBase is added to a signal number: a command ended by signal n,
	// and a sandmeter command itself interrupted by signal n, exit with
	// SignalBase+n.
	SignalBase = 128
)

// Status is one row of the table.
type Status struct {
	Code int
	// Name is the name of the constant.
	Name string
	// Meaning is one sentence for the generated reference.
	Meaning string
}

// Table lists the statuses in ascending order, for the generated command
// reference. A sandboxed command's own status, 0 to 255, is not a row.
var Table = []Status{
	{OK, "OK", "success; for a sandboxed command, it exited with status 0"},
	{Failed, "Failed", "the command could not do its work"},
	{Usage, "Usage", "wrong command line; nothing was done"},
	{Incomplete, "Incomplete", "done, with reservations: skipped or conflicting changes, an interrupted chain, an unmet requirement"},
	{VerifyFailed, "VerifyFailed", "a signature, hash or chain does not verify, or the key is not pinned"},
	{EscapeDeviation, "EscapeDeviation", "an escape verdict is not the expected one"},
	{PolicyRefused, "PolicyRefused", "the policy was refused before anything ran"},
	{HostCannotRun, "HostCannotRun", "this host cannot run a sandbox now"},
	{Denied, "Denied", "the service refused the request: image, budget or free space"},
	{TeardownFailed, "TeardownFailed", "the command ran and its sandbox could not be taken down completely"},
	{Timeout, "Timeout", "the command was killed at its time limit"},
	{Failure, "Failure", "sandmeter failed, not the command"},
	{NotExecutable, "NotExecutable", "the command cannot be executed"},
	{NotFound, "NotFound", "the command or its working directory was not found"},
	{SignalBase, "SignalBase", "added to the number of the signal that ended the command"},
}

// ForSignal returns the status of something ended by signal n.
func ForSignal(n int) int {
	if n <= 0 || n > 127 {
		return Failure
	}
	return SignalBase + n
}

// ForOutcome maps how a sandboxed command ended to the status the run command
// exits with.
//
//   - recordFailed: the record of the command could not be signed or stored.
//     The promise that every command leaves a record is broken: Failure,
//     whatever the command did.
//   - cleanupFailed: the result carries a clean-up error: TeardownFailed.
//   - exited: the command's own status. A status outside 0 to 255 cannot
//     come from a process and maps to Failure.
//   - exec failure: the status recorded, which is NotExecutable or NotFound;
//     anything else maps to Failure.
//   - signalled: SignalBase plus the signal.
//   - killed for exceeding its time limit: Timeout. Killed for exceeding its
//     memory limit: SignalBase+9, as a process killed by the kernel reports
//     it. Killed for any other reason (cancelled, stopped, the free-space
//     floor, a lost supervisor or init): Failure, since the command did not
//     end by its own doing and its real status is unknown.
//   - set-up failure, and any status this build does not know: Failure.
func ForOutcome(o receipt.OutcomeV2, cleanupFailed, recordFailed bool) int {
	if recordFailed {
		return Failure
	}
	if cleanupFailed {
		return TeardownFailed
	}
	switch o.Status {
	case receipt.StatusExited:
		if o.ExitCode == nil || *o.ExitCode < 0 || *o.ExitCode > 255 {
			return Failure
		}
		return *o.ExitCode
	case receipt.StatusExecFailed:
		if o.ExitCode != nil && (*o.ExitCode == NotExecutable || *o.ExitCode == NotFound) {
			return *o.ExitCode
		}
		return Failure
	case receipt.StatusSignalled:
		if o.Signal == nil {
			return Failure
		}
		return ForSignal(*o.Signal)
	case receipt.StatusKilled:
		switch o.KillReason {
		case receipt.KillWallTimeout:
			return Timeout
		case receipt.KillOOM:
			return ForSignal(9)
		}
		return Failure
	}
	return Failure
}
