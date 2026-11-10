# ringfence

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
   ringfence (Go, one binary)
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
- **Receipts.** After each command, ringfence walks the overlay's writable layer
  from the host (never following links the sandbox planted), records every
  outbound flow the firewall saw (allowed or not) and the cgroup counters, and
  signs the result with ed25519 in a DSSE envelope. `ringfence verify` checks it
  offline; `ringfence replay` runs the command again on the same image digest
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
  (`ringfence mcp`, [docs/mcp.md](docs/mcp.md), [skill/ringfence](skill/ringfence/SKILL.md)).

## Results

RESULTS_PLACEHOLDER

## Guaranteed / not guaranteed

| ringfence aims to provide, and tests | ringfence does not provide |
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
`PATH`. Run it on a throwaway VM: ringfence itself runs as root.

```sh
go build -o ringfence ./cmd/ringfence
sudo ./ringfence run -- sh -c 'echo hello > /workspace/out.txt; cat /etc/os-release'
sudo ./ringfence verify /var/lib/ringfence/receipts/<id>-1.json
sudo ./ringfence run -backend gvisor -policy examples/allowlist.toml -- wget -qO- http://example.com
sudo ./ringfence escape -probe "$(CGO_ENABLED=0 go build -o /tmp/rfprobe ./escape/probe && echo /tmp/rfprobe)"
sudo ./ringfence bench
```

`ringfence caps -backend native` prints what a backend enforces on this host;
`ringfence check policy.toml` validates a policy without running anything.

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
