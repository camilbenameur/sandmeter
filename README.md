# ringfence

An educational sandbox for coding agents, written on Linux primitives
(namespaces, cgroups v2, seccomp, overlayfs, nftables) and compared with gVisor.
It measures the isolation with a replayable escape test suite and publishes the
cases that fail.

**Status: work in progress, not usable yet.** This is a learning prototype, not a
security product. Do not run untrusted code with it.

## What works today

- `ringfence caps` prints what a backend can enforce on this host.
- `ringfence check [policy.toml]` refuses a policy the backend cannot enforce,
  and lists every reason.
- `scripts/probe/host.sh` reports KVM, user namespaces and cgroups v2 on a host.
  Results for the machines I have are in [docs/kvm.md](docs/kvm.md).

The native backend does not start sandboxes yet, so `check` refuses the default
policy on purpose: a capability is switched on only once it is implemented and tested.

## Build

```sh
go build ./cmd/ringfence
./ringfence caps
./ringfence check examples/default.toml
```

## License

MIT
