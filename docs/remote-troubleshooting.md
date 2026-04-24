# Remote Protocol and Timeout Troubleshooting

This guide covers the most common remote-debugging failures across the CLI and the VS Code extension.

> **Looking for other types of errors?** Check the Troubleshooting Index for a complete list of common symptoms and guides.

## Quick Matrix

| Symptom | Where you see it | Likely cause | What to try |
| --- | --- | --- | --- |
| **Connect timed out** (initial hang) | `soroban-debug remote` hangs before any output | Server is unreachable, firewall drops SYN, slow network, or `--connect-timeout-ms` is too low | Increase `--connect-timeout-ms` (default 10 000 ms). See [Connect timeout](#connect-timeout) below. |
| Request timed out | `soroban-debug remote`, VS Code session stalls, Debug Console | Backend is slow, host is congested, or timeout is too small for the request class | Increase CLI `--timeout-ms`, `--inspect-timeout-ms`, `--storage-timeout-ms`, or VS Code `requestTimeoutMs`. |
| Connect timeout / cannot attach | VS Code startup, remote CLI connect | Server never started, wrong host/port, firewall, loopback restrictions | Confirm the server is running, verify `host:port`, try `127.0.0.1` instead of `localhost`, and increase VS Code `connectTimeoutMs` if the backend starts slowly. |
| Incompatible debugger protocol | CLI remote connect, adapter logs, server handshake failure | Client and server builds are too far apart | Rebuild or reinstall the CLI and extension from the same repo revision or release line. Avoid mixing a newer extension with an older CLI server. |
| Authentication failed / unauthorized | Remote CLI response, VS Code output channel, server logs | Missing token, wrong token, or token mismatch between launcher and server | Make sure the same token is configured on both sides. In CLI use `--token`; in VS Code confirm the launch configuration or wrapper environment is passing the expected token. |
| Ping succeeds but inspect/storage fails | Remote CLI, VS Code Variables panel, paused session fetches | Per-request timeout for Inspect/GetStorage is lower than general execution latency | Increase CLI `--inspect-timeout-ms` and `--storage-timeout-ms`, or raise VS Code `requestTimeoutMs` if the adapter is fetching large payloads. |
| Repeated disconnect/retry loop | Remote CLI logs, VS Code reconnect attempts | Unstable loopback/network path, server crash, or aggressive retry policy | Check server logs first, then reduce network instability, and tune CLI retry flags `--retry-attempts`, `--retry-base-delay-ms`, and `--retry-max-delay-ms`. |
| Loopback bind/connect failures | CI, containers, restricted desktops, sandboxed environments | Localhost networking is restricted or intercepted | Prefer an explicitly allowed interface, check container port publishing, and validate that your environment permits loopback TCP before assuming a protocol bug. |
| TLS or plaintext confusion | Server starts, but clients fail or traffic assumptions are wrong | Server/client expectations do not match deployment topology | If you use `--tls-cert` and `--tls-key`, keep termination consistent. If you do not use TLS, assume plaintext unless you are on a trusted private network or behind external TLS termination. |

---

## Connect Timeout

`--connect-timeout-ms` controls how long the CLI waits for the initial **TCP connection** to succeed — before any protocol bytes are exchanged.  It is deliberately separate from the per-request timeout (`--timeout-ms`) so you can tune the two phases independently.

### When to change it

| Situation | Recommendation |
|---|---|
| Server on a fast local network, connection hangs anyway | Keep default (10 000 ms); investigate firewall or port |
| Server on a slow WAN / VPN | Increase to 30 000–60 000 ms |
| Restricted sandbox / CI where loopback bind fails immediately | You'll see `permission denied`, not a timeout — see [Sandboxed environments](#sandboxed--ci-environments) |
| Quick healthcheck script that should fail fast | Decrease to 1 000–2 000 ms |

### CLI flags

```bash
# Connect to a server on a slow VPN — give the TCP handshake 30 s
soroban-debug remote \
  --remote vpn-host:9229 \
  --connect-timeout-ms 30000 \
  --timeout-ms 45000

# Fast-fail probe (e.g. in a healthcheck script)
soroban-debug remote \
  --remote 10.0.0.5:9229 \
  --connect-timeout-ms 2000
```

### Environment variable

If you cannot change the command line (e.g. in wrapper scripts or CI steps that invoke `soroban-debug`), set:

```bash
export SOROBAN_DEBUG_CONNECT_TIMEOUT_MS=30000
```

This has the same effect as `--connect-timeout-ms 30000` and is overridden by the explicit flag if both are present.

### Error messages

| Error text | Meaning |
|---|---|
| `connect timed out after Nms — use --connect-timeout-ms to extend the window` | TCP handshake did not complete in time; raise `--connect-timeout-ms` |
| `connection refused — verify the server is running and the port is correct` | OS rejected the connection immediately; the server is likely not listening |
| `permission denied — loopback networking may be restricted` | OS blocked the bind/connect syscall; see [Sandboxed environments](#sandboxed--ci-environments) |

---

## CLI Checklist

### Server side

```bash
soroban-debug server --port 9229 --token secret
```

- Confirm the server is actually listening on the port you expect.
- If you enabled auth, verify the client uses the same token.
- If you enabled TLS, make sure your deployment path matches that expectation end to end.

### Client side

```bash
soroban-debug remote \
  --remote 127.0.0.1:9229 \
  --token secret \
  --connect-timeout-ms 10000 \
  --timeout-ms 30000 \
  --inspect-timeout-ms 5000 \
  --storage-timeout-ms 10000
```

- Use `127.0.0.1` when `localhost` resolution or loopback policy is flaky.
- Raise `--connect-timeout-ms` only when the initial TCP handshake is the slow step.
- Raise `--inspect-timeout-ms` for expensive metadata/state fetches before raising every timeout globally.
- Raise `--storage-timeout-ms` if the storage view is the only part failing.
- Use the retry flags only for idempotent reconnect-style problems, not to mask protocol mismatches or auth failures.

## VS Code Checklist

Use these launch settings when the adapter is healthy but the backend is slow:

```json
{
  "type": "soroban",
  "request": "launch",
  "requestTimeoutMs": 45000,
  "connectTimeoutMs": 15000
}
```

- `connectTimeoutMs` covers startup and initial server attach — equivalent to `--connect-timeout-ms` in the CLI.
- `requestTimeoutMs` covers backend request/response health during the session — equivalent to `--timeout-ms`.
- If the session never gets past startup, raise `connectTimeoutMs` first.
- If stepping starts fine but Variables / stack / pause-state fetches fail, raise `requestTimeoutMs`.
- Turn on `"trace": true` and inspect the "Soroban Debugger" output channel for adapter-side phases such as `Spawn`, `Connect`, `Auth`, `Load`, and `Execution`.

## How to Distinguish Common Failures

### Connect timeout vs request timeout

- A **connect timeout** fires before any data is exchanged.  Error text mentions `connect timed out` or `--connect-timeout-ms`.  Raise `--connect-timeout-ms`.
- A **request timeout** fires after the connection is open but a round-trip stalls.  Error text mentions `Request timed out`.  Raise `--timeout-ms` or the relevant per-operation flag.

### Timeout vs protocol mismatch

- Timeouts usually appear after a request is sent and then stalls.
- Protocol mismatches fail early during handshake and usually mention incompatibility or unknown response types.

### Auth failure vs network failure

- Auth failures mean the server was reachable enough to reject your credentials.
- Network failures usually show up as connection refused, connect timeout, or disconnect errors before auth completes.

### Loopback issue vs backend bug

- If both CLI and VS Code fail to reach `localhost`, suspect loopback/firewall/container policy first.
- If the CLI can connect but VS Code cannot, compare `binaryPath`, launch settings, and adapter logs before changing server settings.

## Sandboxed / CI Environments

Some CI runners, containers, and restricted desktops block loopback TCP
(`127.0.0.1`) at the OS level.  Attempts to `bind` or `connect` on these
platforms return `EPERM` (permission denied) rather than a networking error.

**Test skip behaviour**

Tests that require loopback networking check for this condition at startup and
emit a skip message instead of failing hard:

```
⚠️  Loopback bind check failed: EPERM – loopback networking is not permitted
    in this environment (sandbox or container restriction).
Skipping <test-name>: loopback networking restricted (EPERM or equivalent) –
    see docs/remote-troubleshooting.md.
```

A skipped test is **not a failure** — it means the test cannot run in the
current environment.  If you see this on a machine where loopback should work,
check:

- Container port-publishing rules (`-p 127.0.0.1:PORT:PORT` or equivalent).
- Seccomp / AppArmor / SELinux profiles that deny `bind`/`connect` syscalls.
- CI sandbox policies (e.g. GitHub Actions with restricted network access).
- Whether the test runner itself is running inside a Docker-in-Docker context
  that does not share the host loopback interface.

## Recommended Escalation Order

1. Verify the server is running and reachable on the expected host and port.
2. Verify client/server token and build compatibility.
3. If the initial connection hangs, raise `--connect-timeout-ms` first.
4. If individual requests stall after the connection is open, raise `--timeout-ms` or the narrowest per-operation flag.
5. Enable CLI verbose logging or VS Code trace logging.
6. Only after that, broaden global timeouts or retry windows.

## Local and CI Sandbox Failures

These failures typically occur due to permission restrictions or environment configuration in CI runners, Nix shells, or local sandboxes.

### Restricted Environments and `ci-sandbox`

If you are running local checks in CI containers, hardened desktops, or other restricted environments, use the sandbox-safe local gate:

```bash
make ci-sandbox
```

What this does:

- Runs deterministic Rust checks (`fmt`, `clippy`, `test`) in a predictable order.
- Exits successfully when those checks pass.
- Explicitly reports skipped gates that depend on local loopback networking or writable temp-dir behavior.

Use `ci-local` when your environment has full local networking and temp-dir support; use `ci-sandbox` when it does not.

### Troubleshooting Matrix

| Symptom | Likely cause | What to try |
| --- | --- | --- |
| `listen EPERM` | Local network binding is restricted | Run in a non-sandboxed environment or skip network tests using `cargo test -- --skip remote_run_tests`. |
| `mktemp` failure | Restricted `/tmp` or missing write permissions | Override the temp directory by setting `export TMPDIR=$(pwd)/.tmp` (ensure the target exists). |
| `Permission denied` on `/var/...` | Fixed paths in scripts not honoring `TMPDIR` | Verify the script honors the `TMPDIR` environment variable and provide a writable alternative. |
| Socket bind timeout | Fixed port collision or loopback restriction | Prefer tests using ephemeral ports (port 0) or check if another process is using a fixed port like 9245. |

### CI Environment Checklist

- **`TMPDIR`**: Ensure this points to a writable directory within your runner's workspace.
- **Network Policy**: Verify that `127.0.0.1` is available and binding to ports is permitted.
- **Profiles**: Use `make ci-local` locally to match GitHub Action ordering and automated gates.