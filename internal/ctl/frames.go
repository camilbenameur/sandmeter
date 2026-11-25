// Package ctl defines the control protocol: the private conversation between
// the unprivileged sandmeter client and the root worker that serves it, over
// a Unix socket or, when root runs a command directly, over a socket pair.
//
// This file and messages.go are the contract: the frames, the messages, the
// bounds and the order of the conversation. The code that reads and writes
// frames lives beside them.
//
// # What the protocol is not
//
// It is not a stable interface. Both ends come from one release and say so
// in their first message; a number that differs ends the conversation. It
// can therefore be changed whenever a flaw is found, and nothing outside
// sandmeter may speak it.
//
// # What crosses the boundary
//
// The peer of a worker is an unprivileged process that may be hostile, and
// the worker is root. Three rules hold for every message, and the tests of
// this package check the first two on the types themselves:
//
//   - No field is a path on the host. A project arrives as a stream of bytes
//     that the client packed from files it could read itself; changes leave
//     as a stream that the client writes itself. The only paths in a message
//     are paths inside the sandbox.
//   - No field names a thing on the host by a string the client chose. A
//     session, a snapshot or a record is named by an identifier of package
//     ids, which has one parser and no other text form, and which the root
//     side looks up among the things that belong to the calling user; an
//     identifier it does not know and one that belongs to somebody else get
//     the same answer.
//   - No descriptor crosses. Neither end reads ancillary data.
//
// A fourth rule is for the root side's own log. Text that a client chose and
// that the worker writes down (the build identity of a hello, the reason of
// an abort) is bounded here, far below the size of a message, and is logged
// as a quoted string (strconv.Quote), cut at its bound: never pasted into a
// sentence, never able to start a line of its own.
//
// # Frames
//
// The connection carries frames. A frame is one byte of type, four bytes of
// payload length in big-endian order, and the payload:
//
//	+------+-----------------+------------------------+
//	| type | length (uint32) | payload (length bytes) |
//	+------+-----------------+------------------------+
//
// The length is checked against the bound of the frame's type before a byte
// of payload is read or a byte of memory is allocated for it. A frame of an
// unknown type, a frame over its bound and a message frame with an empty
// payload end the conversation. Until an end has read the hello of the
// other, the bound of a message frame is MaxHello: a peer that has not yet
// shown that it speaks this protocol gets a few kilobytes of attention, not
// sixteen megabytes.
//
// A message frame holds one JSON object with exactly two members, "kind" and
// "body" (see Envelope); the body is decoded into the Go type of that kind
// and of no other. Decoding is strict at every level: a member the type does
// not have is an error, and so is anything after the object. Every string is
// valid UTF-8 without a NUL byte; a client whose arguments hold other bytes
// refuses them itself, with the position of the argument.
//
// The other frames carry bytes that are never interpreted as text: the
// output of a command, and the streams that follow certain messages. See
// messages.go for which stream follows what and for the order of the
// conversation.
package ctl

import "time"

// Protocol is the number both ends send in their hello. It changes whenever
// a frame, a message or the order of the conversation changes in any way,
// and it has no compatibility range: the two numbers are equal or the
// conversation ends. The build identity that travels with it is shown in the
// error and in the logs, and decides nothing.
const Protocol = 1

// FrameType is the first byte of a frame.
type FrameType byte

// The frame types. The list is closed.
const (
	// FrameMessage carries one message, in either direction.
	FrameMessage FrameType = 'M'
	// FrameStdout and FrameStderr carry bytes of the output of the running
	// command, from the worker to the client, in the order they were
	// produced on each stream. They are legal only between a run message and
	// its result.
	FrameStdout FrameType = 'O'
	FrameStderr FrameType = 'E'
	// FrameData carries bytes of the one stream that is open: the project
	// or a refresh from the client, a record, a manifest or a change set
	// from the worker. At most one stream is open at a time and the message
	// before it says which.
	FrameData FrameType = 'D'
	// FrameEnd ends the open stream, complete. Its payload is empty. A
	// stream that stops any other way did not complete, and what was
	// received of it is discarded.
	FrameEnd FrameType = 'Z'
)

// Bounds of a frame.
const (
	// FrameHeaderLen is the length of the type and the length field.
	FrameHeaderLen = 5
	// MaxMessage is the largest payload of a message frame, once the hello
	// of the sender has been read.
	MaxMessage = 16 << 20
	// MaxHello is the largest payload of the first message frame an end
	// receives, which must be the hello of the other.
	MaxHello = 4 << 10
	// MaxChunk is the largest payload of an output or data frame. A sender
	// cuts its stream in pieces of at most this size; the pieces mean
	// nothing.
	MaxChunk = 64 << 10
)

// MaxPayload returns the largest payload a frame of the given type may
// carry. helloRead says whether the reader has already read the hello of
// the other end: before that, only a message frame is legal, and a small
// one. ok is false for a type that is not in the list and for a frame that
// may not come before the hello.
func MaxPayload(t FrameType, helloRead bool) (max int, ok bool) {
	if !helloRead {
		if t == FrameMessage {
			return MaxHello, true
		}
		return 0, false
	}
	switch t {
	case FrameMessage:
		return MaxMessage, true
	case FrameStdout, FrameStderr, FrameData:
		return MaxChunk, true
	case FrameEnd:
		return 0, true
	}
	return 0, false
}

// Bounds of what a message may hold. A message beyond one of them is refused
// with CodeInvalid before anything is done with it. They are generous for a
// person and for an agent, and small enough that MaxMessage holds a message
// at every bound at once, even when JSON has to escape every byte of it.
const (
	// MaxPolicyBytes bounds the text of a policy file.
	MaxPolicyBytes = 256 << 10
	// MaxArgs and MaxArgvBytes bound the number of arguments of a command
	// and the sum of their lengths.
	MaxArgs      = 4096
	MaxArgvBytes = 1 << 20
	// MaxEnvVars and MaxEnvBytes bound the variables sent with a message and
	// the sum of the lengths of their names and values. A name is also
	// bounded on its own, by the grammar of names (policy.ValidEnvName).
	MaxEnvVars  = 1024
	MaxEnvBytes = 256 << 10
	// MaxRefBytes bounds an image reference and a backend name.
	MaxRefBytes = 1024
	// MaxWorkdirBytes bounds a working directory inside the sandbox.
	MaxWorkdirBytes = 4096
	// MaxReasons and MaxReasonBytes bound the list of reasons of an error
	// and the text of each one.
	MaxReasons     = 1024
	MaxReasonBytes = 2048
	// MaxBuildBytes bounds each of the two strings of a build identity. The
	// root side logs them.
	MaxBuildBytes = 128
	// MaxAbortReasonBytes bounds the reason a client gives for an abort. The
	// root side logs it.
	MaxAbortReasonBytes = 1024
)

// Deadlines both ends hold.
const (
	// HelloTimeout is how long each end waits for the other's hello before
	// it closes the connection.
	HelloTimeout = 5 * time.Second
	// CancelGrace is how long a client waits for the result after it sent a
	// cancel, before it gives up and closes the connection. Closing ends the
	// session on the root side, which then finishes taking the sandbox down
	// by itself.
	CancelGrace = 10 * time.Second
)
