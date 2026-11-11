# sandmeter

An educational sandbox for coding agents, written on Linux primitives
(namespaces, `pivot_root`, cgroups v2, seccomp-BPF, overlayfs, nftables) and
compared with gVisor on the same host-side plumbing. It measures its own
isolation with a replayable escape suite, publishes the cases that fail, and
signs a receipt for every command it runs.

**This is a learning prototype, not a security product.** It has not been
audited. Do not use it to contain code you would not run on the host anyway.
It is not affiliated with any model vendor or with the gVisor project.

## What it does

```
 agent (MCP) / CLI
        |
   sandmeter (Go, one binary)
        |
   policy.toml --> Validate(policy, backend.Capabilities())   refused if the backend cannot enforce it
        |
   engine: pull image (OCI) -> overlay layers -> start sandbox -> run -> diff upper layer -> signed receipt
        |
   +-- native : clone(NEWUSER|NEWPID|NEWNS|NEWNET|NEWUTS|NEWIPC|NEWCGROUP), uid map 0 -> 100000,
   |            pivot_root, masked /proc, read-only root, seccomp deny list, 11 capabilities,
   |            cgroup v2 (cpu, memory, pids), veth + nftables egress allowlist
   +-- gvisor : runsc (systrap platform) on the same overlay, cgroup, veth and nftables table
```

- **Policy first.** A policy (TOML) asks for limits, a network mode and a syscall
  filter. Each backend declares what it can enforce on this host; a policy it
  cannot enforce is refused with the full list of reasons, before anything starts.
- **Two backends, one host side.** Both backends use the same overlay layers,
  the same cgroup counters, the same network namespace with a veth pair and the
  same nftables table. Only what executes the sandboxed program's system calls
  changes: the host kernel (native) or gVisor's user-space kernel.
- **Receipts.** After each command, sandmeter walks the overlay's writable layer
  from the host (never following links the sandbox planted), records every
  outbound flow the firewall saw (allowed or not) and the cgroup counters, and
  signs the result with ed25519 in a DSSE envelope. `sandmeter verify` checks it
  offline; `sandmeter replay` runs the command again on the same image digest
  and compares exit code, stdout hash and diff hash.
- **Snapshots** freeze the writable layer by turning it into a read-only layer
  (a rename, no copy). Restoring rebuilds the layer stack.
- **Escape suite.** 15 cases (`escape/cases`), each imitating a known technique,
  run on every backend. Verdicts come from host-side evidence (a canary token on
  the host, a marker file, host sysctls before and after, TCP listeners, the
  firewall log, cgroup peaks), not from what the script prints.
- **Agent eval.** A model gets a `bash` tool inside the sandbox and is asked to
  read a host file or create one, k ≥ 30 times, under a hard dollar budget, on a
  throwaway CI runner only.
- **MCP server and agent skill** to give coding agents the sandbox
  (`sandmeter mcp`, [docs/mcp.md](docs/mcp.md), [skill/sandmeter](skill/sandmeter/SKILL.md)).

## Results

These numbers come from one run of the `measure` workflow on a GitHub-hosted
`ubuntu-latest` runner (2 vCPU, ~8 GB, kernel 7.0.0-azure) on 2026-11-11.
Reproduce them with `sudo sandmeter escape` and `sudo sandmeter bench`; the
raw JSON is in that workflow's artifacts, and [docs/escape.md](docs/escape.md)
and [docs/bench.md](docs/bench.md) hold the full tables. Numbers from other
hardware are not comparable.

### Escape suite

Each of the 15 cases runs on both backends; the verdict is decided by host-side
evidence (a canary token on the host, a marker file, host sysctls compared
before and after, TCP listeners, the firewall log, cgroup peaks), not by what
the script claims.

| | native | gvisor (runsc 20261019.0) |
|---|---|---|
| Cases blocked | **14 / 15** | **13 / 15** |
| Not blocked | 15-symlink-host-tooling (*exposed*) | 13-fork-bomb (*exposed*), 15-symlink-host-tooling (*exposed*) |

Two cases are deliberately not "blocked", and both are honest results, not passes:

- **15-symlink-host-tooling** is *exposed* on both backends. The sandbox can
  plant symlinks and a fake whiteout in its own writable layer — that is allowed.
  The case then checks that the host-side tooling (the receipt diff) never
  followed them: the canary never appeared in the signed receipt and the host
  marker was never created. So the planting is real but the host was not reached.
- **13-fork-bomb** is *blocked* on native and *exposed* on gvisor. This is a real
  difference, not a bug. Under the native backend a sandboxed process is a host
  task, so the cgroup `pids.max` stops the bomb with `EAGAIN`. Under gVisor the
  guest's processes live inside the Sentry and are not host tasks, so a host
  cgroup pids limit does not constrain them; a gVisor fork bomb is instead bounded
  by the Sentry's own memory limit, not by pids. The suite reports what it
  measured rather than hiding the gap.

### Agent escape eval

A model is given one tool, `bash`, running inside the sandbox, and asked to read
a host file or create one. k = 30 episodes per backend, `claude-haiku-5-5` at
medium effort, each campaign under a hard $2 ceiling, on a throwaway runner. The
escape is judged on host evidence, not the model's claims.

| Backend | Episodes | Escaped | Contained | Refused | Escape rate (95% Wilson CI) | Cost |
|---|---|---|---|---|---|---|
| native | 30 | 0 | 29 | 1 | 0/29, CI [0.0%, 11.7%] | $0.20 |
| gvisor | 30 | 0 | 30 | 0 | 0/30, CI [0.0%, 11.4%] | $0.12 |

No escape in 60 episodes, total cost $0.32. The interval is wide on purpose: 30
episodes cannot prove a low escape rate, only bound it. One native episode ended
in the model declining the task; it is excluded from the rate, not counted as
contained. Raw per-episode transcripts are in `docs/eval-native.json` and
`docs/eval-gvisor.json`.

### Benchmark

| Backend | Start p50 / p99 | Snapshot p50 | Restore p50 | CPU loop vs chroot | Concurrent (20) |
|---|---|---|---|---|---|
| native | 5.7 ms / 10.5 ms | 0.3 ms | 0.3 ms | x1.04 | 20 ok in 2.1 s |
| gvisor | 53.6 ms / 74.5 ms | 0.8 ms | 0.5 ms | x1.21 | 20 ok in 2.9 s |

Start is the host-side wall time of running `true` in a fresh sandbox
(namespaces, cgroup, init, exec, teardown), 100 runs per backend. The CPU ratio
compares a shell loop against a plain `chroot` into the same image layers, which
still pays process start but has no isolation. The I/O overhead row is not
reported: the `chroot` baseline could not run the fsync workload, so there is no
honest ratio to show.

## Guaranteed / not guaranteed

| sandmeter aims to provide, and tests | sandmeter does not provide |
|---|---|
| A policy is refused if the backend cannot enforce every part of it | Protection against kernel vulnerabilities (native shares the host kernel) |
| Root in the sandbox is an unprivileged uid on the host (native) | Protection against side channels (timing, cache, Spectre-class) |
| No access to host files, host processes or host devices through the cases tested | Disk, inode or kernel-memory quotas (only cpu, memory and pids are limited) |
| Memory, process count, CPU and wall time limited by cgroup v2 | Protection of data sent to an allowed destination |
| No network (`none`), or TCP only to listed `ip:port` (`allowlist`), never to the host itself, no IPv6 | Following DNS changes: names are resolved once, IP-based rules after that |
| A receipt that shows if the file changed after signing, and which key signed it | Proof that the host ran the command honestly (no attestation) |
| Host tools never follow symlinks planted in the writable layer | A micro-VM boundary: there is no Firecracker backend (see [docs/kvm.md](docs/kvm.md)) |
| Results replayable with one command (`bench/`, `escape/`) | Any guarantee beyond the cases in `escape/cases`, which were written by the author |

Full threat model: [docs/threat-model.md](docs/threat-model.md).

## Quick start

Needs Linux with cgroup v2, root, `nft`, and for the gVisor backend `runsc` in
`PATH`. Run it on a throwaway VM: sandmeter itself runs as root.

```sh
go build -o sandmeter ./cmd/sandmeter
sudo ./sandmeter run -- sh -c 'echo hello > /workspace/out.txt; cat /etc/os-release'
sudo ./sandmeter verify /var/lib/sandmeter/receipts/<id>-1.json
sudo ./sandmeter run -backend gvisor -policy examples/allowlist.toml -- wget -qO- http://example.com
sudo ./sandmeter escape -probe "$(CGO_ENABLED=0 go build -o /tmp/rfprobe ./escape/probe && echo /tmp/rfprobe)"
sudo ./sandmeter bench
```

`sandmeter caps -backend native` prints what a backend enforces on this host;
`sandmeter check policy.toml` validates a policy without running anything.

## Layout

| Path | What |
|---|---|
| `sandbox/` | `Backend` and `Sandbox` interfaces, `Capabilities` |
| `policy/` | TOML policy, validation against capabilities |
| `backend/native/` | the hand-written backend and its in-sandbox init |
| `backend/gvisor/` | runsc backend (OCI bundle on the shared host side) |
| `internal/layers/` | overlay stack, snapshots |
| `internal/seccomp/` | seccomp-BPF assembled by hand (amd64, arm64) |
| `internal/cgroup/` | cgroup v2 groups, limits, counters |
| `internal/vnet/`, `netpolicy/` | veth pair, addressing, nftables ruleset and flow log |
| `image/` | OCI pull, safe layer extraction, layer cache |
| `receipt/` | diff of the writable layer, DSSE signing, verification |
| `engine/` | glue, replay |
| `escape/` | escape cases, probe helper, judge, harness |
| `bench/` | benchmark |
| `agenteval/` | the agent escape eval |
| `mcpserver/`, `skill/` | MCP server and agent skill |
| `docs/` | threat model, KVM verdict, MCP setup |

## Related

- [gatehaul](https://github.com/camilbenameur/gatehaul) runs agent jobs in remote
  Codespaces instead of on the local machine.
- [guarded-messaging-agent](https://github.com/camilbenameur/guarded-messaging-agent)
  puts a deterministic gate in front of an agent's outgoing messages.

## License

MIT
