# MCP server

`ringfence mcp` runs an MCP server on stdin/stdout, so a coding agent can run
commands in a sandbox through tool calls. The code is in `mcpserver/`.

This is an educational prototype. Do not rely on it to contain hostile code.

## Register the server

Any MCP client that starts stdio servers takes the same block:

```json
{
  "mcpServers": {
    "ringfence": {
      "command": "ringfence",
      "args": ["mcp"]
    }
  }
}
```

The client starts the process and talks to it over stdio. Nothing listens on
a network port.

## Run it as root, on a throwaway VM

The native backend needs root. It creates cgroups under the cgroup v2 tree,
creates and configures network namespaces (veth pairs, nftables rules for the
allowlist), and mounts an overlay filesystem for each session. None of that is
available to an unprivileged process on a typical host.

Because the server runs as root and executes commands chosen by an agent, run
it on a VM you can delete, not on a workstation that holds your credentials or
a browser session. If the sandbox has a flaw, the process that hosts it has
full privileges on that machine. Use `ringfence caps` to see what the backend
can enforce on a given host.

## Tools

All arguments are JSON. Every tool returns a short text and structured
content. A failure inside the sandbox service comes back as a tool error
(`isError: true`) with the message, not as a protocol error. Text results are
capped at 32 KiB; stdout and stderr are also truncated by the service, and the
result says when that happened.

| Tool | Arguments | Result |
| --- | --- | --- |
| `start` | `backend?`, `image?`, `policy_toml?` | Session id, backend, image digest, capabilities. |
| `run` | `argv` (required, 1 to 256 entries), `session_id?`, `image?`, `backend?` | Exit code, `killed` reason if any, stdout, stderr, truncation flags, duration, receipt path, summary. |
| `snapshot` | `session_id` | Snapshot id. |
| `restore` | `session_id`, `snapshot_id` | Confirmation. |
| `stop` | `session_id` | Confirmation. |
| `report` | `receipt_path` | Verifies the receipt signature and returns a summary. Only accepts a path that `run` returned since the server started. |

Defaults: backend `native`, image `docker.io/library/alpine:3.20`, and the
default policy (see `examples/default.toml`), which has no network and mounts the root read-only: set
`[filesystem] read_only_root = false` in `policy_toml` for tasks that install
or write outside `/tmp`.

### `run` without a session

If `session_id` is omitted, `run` starts a throwaway session with the defaults
(or the `image` and `backend` given), runs the command, and stops the session.
The output says so, and warns if the session could not be stopped (the
stop is bounded to 30 seconds). Use `start` first when you need several commands to share
a filesystem, a custom policy, or snapshots. `image` and `backend` are ignored
when `session_id` is set.

`argv` is an argument vector, not a shell string. To use shell syntax, pass
`["sh", "-c", "..."]`.

## Library use

```go
err := mcpserver.Serve(ctx, svc, version)
```

`svc` implements `mcpserver.Service`. The server depends on nothing else, which
is how the tests drive it with a fake.
