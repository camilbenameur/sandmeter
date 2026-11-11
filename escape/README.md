# escape

A replayable escape test suite: a fixed set of shell scripts, each trying
one technique a sandboxed process might use to reach the host, run inside
a sandbox on every backend. The result table is published as is, including
every failure.

## What each case imitates

| Case | Imitates |
|---|---|
| `01-proc-root` | Reading a host file through `/proc/<pid>/root` or `/proc/<pid>/cwd`: the classic "procfs root escape" against a chroot or container runtime whose per-process symlinks reach back outside the sandbox. |
| `02-host-pids` | Enumerating `/proc` to see other tenants' or the host's own processes, the usual first step before a ptrace or signal attack. |
| `03-raw-disk` | `mknod`-ing the host's boot disk and reading or mounting it directly, something `CAP_MKNOD` with no device cgroup allows. |
| `04-proc-sys-write` | Rewriting `/proc/sys/kernel/core_pattern` (or `hostname`) so the kernel runs an attacker script as the host on the next crash -- one of the most common real breakout primitives. |
| `05-sysfs-rw` | Remounting a read-only `/sys` read-write to reach a knob like the deprecated `uevent_helper` hook. |
| `06-cgroup-release-agent` | CVE-2022-0492: mounting cgroup v1, writing `release_agent`, and triggering a release event so it runs as the host. |
| `07-userns-mount` | `unshare(CLONE_NEWUSER)` to regain "root" inside a nested user namespace, then using it to mount a filesystem. |
| `08-kernel-surface` | Fuzzing the syscalls a seccomp filter is easiest to forget: `bpf`, `keyctl`, `io_uring_setup`, `perf_event_open`, `userfaultfd`, plus `unshare`/`mount`/`ptrace`. Reporting EXPOSED, not ESCAPED: reachability is a wider attack surface, not a compromise by itself. |
| `09-shocker` | The 2014 Docker "Shocker" breakout: `open_by_handle_at` on a file handle, bypassing mount namespace checks. |
| `10-egress-none` | Exfiltration attempted anyway under a `network=none` policy. |
| `11-egress-allowlist` | Using a network=allowlist exemption as a general tunnel: a second TCP destination, a raw ICMP ping, a DNS query, none of them on the list. |
| `12-host-gateway` | Talking directly to the host side of the sandbox's own veth pair, instead of the intended egress path. |
| `13-fork-bomb` | An unbounded fork bomb, the simplest resource-exhaustion denial of service. |
| `14-memory-hog` | Unbounded memory growth, expecting the cgroup v2 memory controller to OOM-kill the process rather than the host. |
| `15-symlink-host-tooling` | Planting symlinks (and an overlay whiteout look-alike) for host-side tooling -- a receipt generator, a diff, a snapshot restorer -- to walk into after the sandbox itself is gone. |

## How verdicts are computed

`Judge` turns one case's `Evidence` into a `Verdict`. The order matters, and
it is fixed on purpose: evidence the harness measured itself, independent of
the sandboxed process, always outranks whatever the script printed.

1. **Canary leak** -- the random token from `RF_HOST_CANARY_PATH` shows up
   in stdout, stderr, or the signed run receipt.
2. **Marker created** -- `RF_HOST_MARKER_PATH` exists on the host after the
   case ran.
3. **Host state changed** -- a value the harness checked before and after
   (such as `core_pattern`) moved.
4. **Egress or gateway hit** -- the host's own TCP listeners accepted a
   connection from the sandbox.
5. **Resource limits** -- `pids.peak` over the policy's limit, or the
   memory peak over 105% of it.

Any of these makes the case `escaped`, whatever the script's own `RESULT`
line says: a script cannot talk its way out of a canary token that reached
the host.

Only once none of that evidence fires does `Judge` read the script's final
`RESULT: BLOCKED|ESCAPED|EXPOSED <reason>` line. `BLOCKED` and `EXPOSED` are
taken at face value; a self-reported `ESCAPED` is trusted even with no
corroborating host evidence, on the theory that a false positive here only
makes the suite too cautious, never that it missed a real escape.

The script runs inside the sandbox, so its output is not trusted either:
if several `RESULT` lines appear, any `ESCAPED` among them counts, and
otherwise the verdict is `error` instead of a guess. Cells in the published
table are escaped and truncated for the same reason. `13-fork-bomb` and
`14-memory-hog` also give `error` when the harness did not report the
limit it applied, since a peak cannot be judged without it.

Known limits of individual cases: `06-cgroup-release-agent` can only prove a
release agent would run if the harness passes `RF_SANDBOX_ROOT` (the host
path of the sandbox root); without it the case stops at `EXPOSED`.
`11-egress-allowlist` lists any leg it could not run (for example ICMP
without `ping_group_range`) rather than counting it as blocked.

The script runs inside the sandbox, so its output is not trusted either:
if several `RESULT` lines appear, any `ESCAPED` among them counts, and
otherwise the verdict is `error` instead of a guess. Cells in the published
table are escaped and truncated for the same reason. `13-fork-bomb` and
`14-memory-hog` also give `error` when the harness did not report the
limit it applied, since a peak can not be judged without it.

If there is no `RESULT` line at all (the process died first), `Judge` checks
whether it died the way that case expects: `14-memory-hog` expects an OOM
kill, `13-fork-bomb` accepts any kill. Anything else with no `RESULT` line is
`error` -- a bug in the case or the harness, not a judgment about the
backend.

## Bias warning

**This is a regression suite, not a red team.** Every case here was written
by the person who also wrote the sandbox being tested, which is exactly the
wrong vantage point for finding what that sandbox misses: the cases cover
the breakout classes its author already knew to think about. A table where
every row says `blocked` tells you the suite did not find a hole in the
things it checked for -- not that there is no hole.

Known gaps, left out on purpose because this is a prototype, not because
they are not real:

- **Kernel exploits.** Nothing here attempts a privilege-escalation CVE
  against the kernel itself (a UAF, a race, a bad bounds check). Those need
  a specific vulnerable kernel version to demonstrate at all, and exploiting
  one is a different, much larger project than measuring namespace and
  cgroup configuration.
- **Side channels and timing.** Cache timing, Spectre/Meltdown-style
  speculative execution leaks, and other side channels that read data
  without ever making a "forbidden" syscall are entirely out of scope: this
  suite only looks at syscalls, files and network flows.
- **Anything needing a specific kernel build.** A handful of real
  container-escape CVEs only apply to a narrow range of kernel versions or
  configs (a particular LSM, a particular cgroup driver). This suite targets
  what a generic recent Linux does, not a reproduction of any one CVE's
  exact conditions.
- **Multi-step, creative chains.** Every case here is a single, named
  technique run once. A determined attacker combining several small leaks
  (an EXPOSED syscall plus a partial filesystem view, say) into one working
  escape is exactly the kind of thing a fixed suite cannot find; only an
  adversarial human (or a different, adversarial test design) can.

Read every `exposed` row as "worth tightening," not as "safe." Read every
`blocked` row as "this one known technique didn't work today," not as
"this sandbox is secure."

## Backend-specific notes

- **13-fork-bomb, pids under gVisor.** The native backend stops the bomb with
  the cgroup `pids.max` (`EAGAIN`). Under gVisor the guest's processes are not
  host tasks, so a host pids limit does not apply to them; the bomb is bounded by
  the Sentry's memory instead. The suite reports this as *exposed* on gVisor
  rather than pretending the host pids limit took effect.
