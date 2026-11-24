# Threat model

sandmeter is an educational prototype. This document says what it tries to
stop, what it does not try to stop, and where the boundaries are, so that its
measurements can be read correctly. It is not a security guarantee.

## Assets

1. **The host**: its files (secrets, keys, the signing key of receipts), its
   processes, its kernel, its network position, and its availability.
2. **Other sandboxes** on the same host.
3. **The receipts**: their integrity after signing.

## Adversary

Code running inside the sandbox with the sandbox's root user: a coding agent
that was prompt-injected, a malicious package install script, or generated code
that does something unexpected. The adversary can run any binary it can write
into `/tmp` or `/workspace`, and can try for as long as the wall-time limit allows.

Out of scope as adversaries: the person running sandmeter, anyone with root on
the host, the image registry (images are pinned by digest in receipts but their
content is trusted), and the hardware.

## Other principals

Code inside a sandbox is not the only party that acts on a host running
sandmeter. Three more have a stated level of trust, and the design is held to
it. For each, the last paragraph says how far the code of this version is from
that line: a line the code does not hold yet is a known gap, not a guarantee.

### The MCP client

The agent host that calls sandmeter's MCP tools, and the model that drives it.

Trust: none for any choice that widens a sandbox. The agent outside the sandbox
and the code inside it are the same adversary: a prompt-injected model is the
caller of the tools as well as the author of the commands. The person who
registers the server is trusted; the agent that runs under that person's user
is not.

What follows from it:

- The agent chooses the command to run, and nothing that decides what the
  command can reach. The policy, the set of images, the names of environment
  variables passed into a sandbox and the project directory are fixed by a
  person when the server is registered.
- The bound that holds is the operator's ceiling, enforced by the root side
  for the calling user. What the MCP server itself narrows is a convenience
  and not a boundary: the server runs as the same user as the agent host, and
  any process of that user can ask the service for anything the ceiling
  grants.
- No tool writes to the project on the host. What a sandbox changed reaches
  the host only when a person applies it.
- Everything a sandbox chose and a tool returns (output, file names, the
  names of refused destinations) is data. It is never part of a sentence the
  server utters itself, because the reader of that sentence is the model.
- No process that parses what an agent or a model wrote runs as root.

In this version: not held. The MCP server runs as root in the same process as
the engine, and its `start` tool accepts a policy written by the client.

### Other unprivileged users of the host

Anyone else with an account on the same machine: a colleague on a shared
development server, another job on a CI runner.

Trust: none. A member of the group that may use the service is trusted with
what the operator's ceiling grants, which is running commands in sandboxes
within the budgets set for each user, and with nothing more: not with another
member's sessions, not with the host.

What follows from it:

- A session, its copy of a project, its output and its receipts belong to one
  user. No other user can enter, read, list, export or stop them, and a
  request that names something of another user gets the same answer as one
  that names nothing. Receipts hold command lines: they are readable by their
  owner only.
- The directories of the root side cannot be entered by other users, and no
  mount of a sandbox is visible in the mount namespace they live in.
- One user cannot use up what the others need: sessions, running commands,
  imported bytes, stored receipts and connections are budgeted per user, and a
  floor on free space is always on.
- Installing sandmeter gives no user a new way to root: the package sets no
  setuid bit and no file capability, and the entry points the root side
  starts for itself refuse to run when started by hand.

In this version: not held. Every command needs root, state lives under `/run`
in directories other users can traverse, and receipts are written
world-readable under predictable names.

### The network position

Whoever answers the host's DNS queries, serves the image registry, or sits on
the path to either.

Trust: none beyond what TLS and a content digest establish. A name is not an
address, an answer is not the truth, and a registry is a remote party that
sends bytes to be parsed.

What follows from it:

- Egress is decided by name, on the host, at the moment of each connection:
  the name is matched against the policy before anything is resolved, and the
  address is checked when it is dialled, so that no DNS answer can turn an
  allowed name into a way to the host itself, to a private network or to a
  metadata service.
- An image is identified by its digest. The default image is pinned by digest,
  and what a registry sent is checked against the digest before it is used.
- What a registry sends is parsed by an unprivileged process, never by root.

What it does not cover, and no version will: the content of an image that
matches its digest is trusted, and an allowed destination can carry any data
out, in either direction.

In this version: not held. Allowed names are resolved once, when a command
starts, and the answers are trusted; images are pulled and unpacked by the
root process.

## Boundaries, per backend

| Layer | native | gvisor |
|---|---|---|
| What executes the sandboxed program's system calls | the host kernel | the gVisor Sentry, a user-space kernel; the Sentry itself makes a reduced set of host syscalls under its own seccomp filter |
| User namespace | root inside maps to host uid 100000 (unprivileged) | gVisor's own user model; the Sentry runs as an unprivileged host user |
| Mount, PID, UTS, IPC, cgroup namespaces | yes | yes (implemented by the Sentry) |
| Root filesystem | overlayfs on the host, `pivot_root`, read-only except `/tmp` and `/workspace` | same overlay, served to the Sentry through the gofer, read-only except `/tmp` and `/workspace` |
| `/proc`, `/sys` | new procfs with masked files, read-only `/proc/sys` and friends, read-only sysfs | the Sentry's own procfs and sysfs |
| Devices | tmpfs `/dev` with null, zero, full, random, urandom, tty bind-mounted; no mknod (user namespace) | the Sentry's devices |
| Syscall filter | hand-written seccomp-BPF deny list (`internal/seccomp`) | the same list translated to OCI and enforced by the Sentry |
| Capabilities | bounding set reduced to 11 capabilities, valid only in the sandbox's user namespace | same list, enforced by the Sentry |
| Resources | cgroup v2: cpu.max, memory.max (no swap), pids.max, OOM kills the whole group; wall-time kill | same cgroup, configured by runsc |
| Network | own network namespace; `none` = loopback only; `allowlist` = veth pair, nftables table that accepts only listed `ip:port` (TCP), drops everything to the host itself, drops IPv6 | same namespace and nftables table; traffic leaves through gVisor's netstack |

## What sandmeter aims to stop (and measures)

Each line is covered by at least one case of the escape suite in
`internal/escape/cases`; the result table in the README says which cases were
blocked on which backend.

- Reading host files through `/proc/<pid>/root`, `/proc/<pid>/cwd`, file handles
  (`open_by_handle_at`), or direct paths.
- Seeing host processes.
- Mounting host block devices, remounting `/sys` or `/proc` read-write, writing
  host sysctls such as `kernel.core_pattern`.
- The cgroup v1 `release_agent` escape.
- Regaining capabilities in a nested user namespace.
- Reaching kernel attack surface often used in exploits: `bpf`, `io_uring`,
  `userfaultfd`, `keyctl`, `perf_event_open`, kernel modules.
- Network egress outside the allowlist, and connections to services on the host.
- Fork bombs and memory exhaustion affecting the host.
- Tricking host-side tools (the receipt diff, snapshots, cleanup) with symlinks
  or special files planted in the writable layer.

## What sandmeter does not stop

- **Kernel bugs.** The native backend shares the host kernel. A kernel
  vulnerability reachable through the allowed syscalls is an escape. The seccomp
  list is a deny list: any syscall not listed, including ones added by future
  kernels, is allowed. gVisor reduces this surface; it does not remove it.
- **Side channels**: timing, cache, Spectre-class, `/proc` counters that are not
  masked, CPU frequency, power.
- **Resource exhaustion outside the cgroup controllers**: disk space in the
  writable layer (no quota), inodes, entropy, kernel memory not charged to the
  cgroup, the host's conntrack table, and the number of overlay mounts.
- **DNS-based exfiltration through allowed hosts**: an allowed `ip:port` can
  carry any data. Allowed names are resolved once on the host; a CDN address
  allows every site served from it.
- **A dishonest host.** Receipts are signed by the host that ran the command.
  The signature proves the file was not changed after signing and which key
  signed it. It does not prove that the host ran the command honestly or that
  the sandbox held. There is no hardware attestation.
- **Supply-chain attacks on the image or on sandmeter itself.**
- **Anything the escape suite does not test.** The cases were written by the
  author of the sandbox. They form a regression suite, not a red-team audit.

## Privilege of sandmeter itself

Both backends need root on the host: creating cgroups, network devices and
nftables rules, mounting overlayfs, and writing uid maps for other users all
require it. On Ubuntu 23.10 and later, unprivileged user namespaces are also
restricted by AppArmor (`kernel.apparmor_restrict_unprivileged_userns=1`), see
[kvm.md](kvm.md). The sandmeter process is therefore part of the trusted
computing base, and a bug in its host-side code (path handling in the diff,
snapshot renames, cleanup) is a host compromise. Run it on a throwaway VM.

## Known gaps to close

- No disk quota on the writable layer.
- Stale network lock files after a crash are not reclaimed.
- No per-sandbox user namespace ranges: all sandboxes share host uids
  100000-165535, so two concurrent sandboxes could signal each other's processes
  if they could see them (PID namespaces prevent seeing them).
- Allowlist is TCP only.
- Under the gVisor backend, a host cgroup `pids.max` does not limit the number
  of guest processes: they live inside the Sentry and are not host tasks. A
  gVisor fork bomb is bounded by the Sentry's memory limit instead, not by pids.
  The native backend, where guest processes are host tasks, does enforce `pids.max`.
  This is visible in the escape suite (case 13).
