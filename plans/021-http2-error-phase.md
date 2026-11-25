# Plan 021: HTTP/2 TLS alerts and tunnel timeouts use the shared phase rules

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat a552088..HEAD -- src/http2.odin src/http2_websocket.odin src/http3.odin src/websocket_async.odin`
> Plan 013 may have edited the WebSocket open path. Stop if `h2_tls_error` or `h2_tunnel_stream_error` no longer matches the excerpts.

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: LOW
- **Depends on**: plans/013-websocket-lane-close.md
- **Category**: bug
- **Planned at**: commit `a552088`, 2026-11-25
- **Executor**: `claude:sonnet` — route existing errors through `http_error_classify`
- **Fallback executor**: `codex`

## Why this matters

`h2_tls_error` reports a TLS protocol alert as `.IO_Failed` / `.Read`. `http_error_classify` would set phase `.TLS` for a `Protocol_Error` other than `Close_Notify`. Callers that treat `.TLS` as fatal and a read error as retryable do the wrong thing. `h2_read` and `h2_write_all` both go through `h2_tls_error` and never call `http_error_classify`.

`h2_tunnel_stream_error` returns `.TLS_Failed` whenever `tls_error != nil`, so a socket timeout stored beside a TLS error never reaches the `.Deadline_Failed` arm. That arm also always stores `TCP_Recv_Error.Timeout`, including when the write deadline fired. `h3_tunnel_progress` does the same for read and write. `websocket_async_runtime_error` stores every runtime timeout, including connect, as `TCP_Recv_Error.Timeout`.

`tests/outcomes_test.odin` locks `http_error_classify`: a write `TCP_Send_Error.Connection_Closed` stays phase Write; a read close stays Read; a read timeout is Deadline; `Bad_Record_Mac` on an I/O failure becomes TLS. Do not change those outcomes. Call the classifier. Do not reimplement it.

## Current state

`h2_tls_error` (`src/http2.odin:750`):

```odin
kind := http.Error_Kind.IO_Failed
phase := HTTP_Phase.Read
transport := tls_network(io_error)

if _, write := io_error.(net.TCP_Send_Error); write {
	phase = .Write
}

if http_network_phase(transport) == .Deadline {
	kind = .Deadline_Failed
	phase = .Deadline
}
```

`http_error_classify` (`src/http.odin:1762`) sets phase `.TLS` when `tls_error` is a `Protocol_Error` other than `Close_Notify` and `.None`. It sets `.Cancellation` for `General_Error.Cancelled`. A carried TCP timeout becomes `.Deadline`.

`h2_tunnel_stream_error` (`src/http2_websocket.odin:563`):

```odin
if error.tls_error != nil {
	return {kind = .TLS_Failed, tls = error.tls_error}
}

if error.kind == .Deadline_Failed {
	transport = net.TCP_Recv_Error.Timeout
}
```

`h3_tunnel_progress` is in `src/http3.odin` around line 857. `websocket_async_runtime_error` is in `src/websocket_async.odin` around line 1637. A close-timer expiry at `websocket_async.odin:1065` reports `{kind = .Timeout}` with a nil transport. Leave that close-timer value if it is a `WebSocket_Async_Error` and not an `HTTP_Error`. The finding is the runtime timeout mapped to a recv timeout. Read the procedure before editing. If the close timer is a different enum, do not force a `TCP_Recv_Error` onto it.

Conventions in `AGENTS.md`: one blank line after a closing brace before the next statement. Tabs. One statement per line. Omit an import name that repeats the last element of the path. Do not reformat `h2_field` or `h2_send_body`. Do not push. Do not edit `shared:async/tls`.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Check | `ODIN=$HOME/dev/oss/Odin/odin "$ODIN" check src -collection:shared:$HOME/dev/oss/Odin/shared -no-entry-point` | exit 0 |
| Outcomes | `ODIN=$HOME/dev/oss/Odin/odin task test -- -define:ODIN_TEST_THREADS=1` | exit 0 |

Use `ODIN_TEST_NAMES` with the exact outcome procedure names if the full run is noisy. The full `task test` is the done check.

## Scope

**In scope**:

- `src/http2.odin` — `h2_tls_error`
- `src/http2_websocket.odin` — `h2_tunnel_stream_error`
- `src/http3.odin` — the tunnel progress arm that stores `TCP_Recv_Error.Timeout` for a write deadline
- `src/websocket_async.odin` — `websocket_async_runtime_error`'s timeout arm only
- A unit test in `tests/internal/` that calls `h2_tls_error` and `h2_tunnel_stream_error`

**Out of scope**:

- `http_error_classify` itself and `tests/outcomes_test.odin` expectations
- `http3_map_error` (plan 014)
- Lane close on a failed open (plan 013)
- `websocket_async.odin:1065` if that value is not an HTTP transport error

## Git workflow

- Branch: `advisor/021-http2-error-phase`
- Commit: `fix: classify HTTP/2 TLS alerts and tunnel deadlines`
- Do not push.

## Steps

### Step 1: `h2_tls_error` calls `http_error_classify`

Build the `HTTP_Error` you already build, then return `http_error_classify` of it. Pass the phase you chose (`.Write` for `TCP_Send_Error`, `.Read` otherwise) as the fallback. Pass the `effect` and `status` you already have.

The classifier overwrites phase to `.TLS` for a protocol alert, `.Deadline` for a timeout, and `.Cancellation` for cancel. A non-timeout `TCP_Send_Error` stays Write. Do not clear `tls_error`. The outcomes tests require the protocol error to remain visible.

`Close_Notify` stays a read/write phase, not TLS, because the classifier skips it. Do not special-case it again.

**Verify**: `odin check` exits 0.

### Step 2: Tunnel deadlines keep their direction

`h2_tunnel_stream_error`:

- If `error.kind == .Deadline_Failed`, return `.TCP_Failed` with a timeout transport. Use `TCP_Send_Error.Timeout` when `error.phase == .Write`. Use `Dial_Error.Timeout` when `error.phase == .Connect`. Use `TCP_Recv_Error.Timeout` for `.Read` and `.Deadline`. Do not return `.TLS_Failed` for that kind even if `tls_error != nil`.
- Otherwise, if `tls_error != nil` and `http_error_classify` would set phase `.TLS`, return `.TLS_Failed` with that `tls_error`.
- A non-timeout send error stays a TCP send error, not a TLS failure.

Apply the same Write-versus-Read timeout choice in `h3_tunnel_progress` where it stores `TCP_Recv_Error.Timeout` for both directions. Read the procedure. Change the stored transport, not the QUIC state machine.

`websocket_async_runtime_error`: a timeout whose phase argument is `.Connect` or `.Write` must not be stored as `TCP_Recv_Error.Timeout`. Use `Dial_Error.Timeout` for connect and `TCP_Send_Error.Timeout` for write. A read timeout stays `TCP_Recv_Error.Timeout`. The procedure's signature is `(error: runtime_async.Error, phase: surf.HTTP_Phase)`. Use `phase`.

**Verify**: `odin check` exits 0. Outcome tests exit 0.

### Step 3: Direct assertions

In `tests/internal`:

- `h2_tls_error(tls.Protocol_Error.Bad_Record_Mac, .Unknown, 0)` has phase `.TLS` and kind `.IO_Failed` or `.TLS_Failed` according to what `http_error_classify` actually returns. Call the classifier in the test and expect equality, so the test locks "same as classify" rather than a second copy of the rules.
- `h2_tls_error` of `net.TCP_Send_Error.Connection_Closed` has phase `.Write`.
- `h2_tunnel_stream_error` of `{kind = .Deadline_Failed, phase = .Write, tls_error = tls.Protocol_Error.Bad_Record_Mac}` is `.TCP_Failed` with `TCP_Send_Error.Timeout`, not `.TLS_Failed`.

**Verify**: `PACKAGE=. INTERNAL=1 task test` with those exact names exits 0. Then the full `task test` exits 0.

## Test plan

- The three assertions above.
- `tests/outcomes_test.odin` unchanged and passing.
- No new peer.

## Done criteria

- [ ] `h2_tls_error` returns the `http_error_classify` result
- [ ] A write deadline is `TCP_Send_Error.Timeout`, a connect deadline is `Dial_Error.Timeout`, a read deadline is `TCP_Recv_Error.Timeout`
- [ ] A deadline is not reported as `.TLS_Failed` just because `tls_error` is set
- [ ] Outcome tests pass
- [ ] `plans/README.md` status row updated

## STOP conditions

- `http_error_classify` rewrites a Write close into Read. It must not. Stop and report. Do not "fix" the classifier in this plan.
- The HTTP/3 tunnel procedure does not store a recv timeout for a write. Leave it, and say so in the commit.
- You would need a new error enum.

## Maintenance notes

- Plan 014's HTTP/3 exchange deadline and this plan's tunnel timeout are different procedures. Do not merge them.
- Reviewers should check `Close_Notify` still follows `http_error_classify` and is not forced to `.TLS`.
