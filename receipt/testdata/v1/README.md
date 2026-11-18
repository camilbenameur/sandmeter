# Recorded v1 receipts

These files are receipts of schema `sandmeter.receipt/v1`, recorded on
2026-11-18 from the tree at commit `158aec0`, before the packages were
rearranged and before any other schema existed. They stand for the receipts
that earlier builds have already written: `receipt.Verify` and
`receipt.DecodeV1` must keep accepting them, byte for byte, for as long as v1
is supported.

Do not edit them, and do not record them again to make a test pass. A test
that fails on these files has found a change to a published format.

| File | Content |
|---|---|
| `<name>.json` | the DSSE envelope, as the engine wrote it to its receipt directory |
| `<name>.payload.json` | the signed bytes: the base64-decoded `payload` of that envelope, one line, no final newline |
| `key.pub.pem` | the public key, PKIX, PEM |
| `key.pub` | the same key the way the builds that write v1 store it: base64 of the 32 raw bytes |

| Name | Backend | Outcome | In it |
|---|---|---|---|
| `success` | native | exit 0 | twelve diff entries of every kind but `delete` (file, directory, symlink, FIFO, setuid file, opaque directory, a name and a link target that are not UTF-8), four flows, an allowlist policy with two of the four limits |
| `failed` | native | exit 2 | an empty diff, no flow, the default policy, a capability note, refused forks |
| `killed` | gvisor | killed, `wall-timeout`, exit 137 | truncated output, a file over the hashing budget and so a truncated diff, a backend version, the syscall filter off |
| `oom` | native | killed, `oom`, exit 137 | an OOM kill, a policy with one limit |

## How they were made

By the recorder in the engine's tests (the package was `./engine` at the
commit they were recorded from):

    go test ./internal/engine -run TestEngineEmitsTheRecordedV1Receipts -update-v1-fixtures

`Engine.Start` and `Session.Run` wrote them. What ran for real: the policy
validation, the image store lookup, the diff walker over real directories,
the hashing, the DSSE envelope and the Ed25519 signature. What did not: the
recording host has no root, so the backend is a stand-in that starts no
sandbox. It writes into the upper directory what the recorded command wrote
and returns the recorded exit status, output, counters and flows. The image
is a small directory tree under a name that cannot resolve, not a registry
pull. The capabilities are the ones the two backends report as root on a
cgroup v2 host.

There is no `delete` entry: a whiteout is a character device, and creating
one needs root.

Without the flag, the same test runs the commands again and compares what the
engine signs with these files (the id, the two timestamps, the kernel and the
architecture apart). It goes away when the engine stops writing v1; these
files do not.

## The key

The signing key is derived from a label in the recorder
(`sha256("sandmeter receipt v1 fixture key")` is the Ed25519 seed), so anyone
can sign with it. It protects nothing and must never be trusted for anything
but these files.
