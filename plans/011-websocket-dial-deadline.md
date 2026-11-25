# Plan 011: The blocking WebSocket dial honors `handshake_timeout` and rejects `h2`

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat a552088..HEAD -- src/websocket.odin tests/internal/websocket_policy_test.odin`
> On a mismatch of `websocket_dial`, stop.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: LOW
- **Depends on**: plans/009-step-import.md
- **Category**: bug
- **Planned at**: commit `a552088`, 2026-11-25
- **Executor**: `claude:sonnet` — one procedure, two call-site changes, one loopback-style test
- **Fallback executor**: `codex`

## Why this matters

`websocket_dial` resolves and connects with an empty deadline, then calls blocking `handshake`. `handshake_timeout` starts only when the HTTP upgrade begins (`websocket_upgrade_deadline_start`). A blackholed address never returns. If the caller's TLS config offers `h2` and the peer selects it, the HTTP/1 upgrade is written onto an HTTP/2 connection. `execute_tls` already rejects any selected protocol other than `h2` or `http/1.1`.

## Current state

`websocket_dial` in `src/websocket.odin`:

```odin
endpoints, resolve_error := tcp_api.resolve_endpoints_until(host, port, {}, options.resolver)
```

```odin
socket, connect_error := tcp_api.dial_tcp_candidates_until(endpoints, {})
```

```odin
if err := tls_api.handshake(&conn.tls_client); err != nil {
```

Offered `h3` is rejected before the socket, at the loop that calls `websocket_dial_fail` with `tls_api.General_Error.Invalid_Config`. Nothing after the handshake reads `negotiated_protocol`.

`websocket_upgrade_deadline_start` (`src/websocket.odin` around line 153) uses `conn.config.handshake_timeout` and substitutes `10 * time.Second` when it is zero. That runs after the handshake.

`shared:async/tls` exports `handshake_until :: proc(conn: ^Conn, deadline: time.Time) -> Error` (`api.odin:437`). `execute_tls` reads `tls.connection_state(connection).negotiated_protocol` (`src/http.odin:379`).

`tests/internal/` is package `surf` once `tools/test` overlays it. Public files under `tests/` are package `tests` and cannot call unexported helpers. Put the new test in `tests/internal/`.

Conventions in `AGENTS.md`: one blank line after the closing brace of a struct, procedure, `switch`, `for`, or `if`, before the next statement. No blank line before `else`. The disposal-`defer` exception is the `defer` on the line after the `if` that checked the allocation. Tabs. One statement per line. Omit an import name that repeats the last element of the path. Do not reformat `websocket_dial` beyond the lines you change. Do not edit sibling repositories. Do not push. Do not pass `-strict-style` or `-vet`.

`ODIN=$HOME/dev/oss/Odin/odin task test` is the suite command. Flags after `--` reach `odin test`. `ODIN_TEST_NAMES` is an exact procedure name. `task` exits 201 when the child exits 1.

Plan 012 also edits `websocket_dial_network` in this file. Land this plan first. Do not change the `Name_Resolution_Failed` return in this plan.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Check | `ODIN=$HOME/dev/oss/Odin/odin "$ODIN" check src -collection:shared:$HOME/dev/oss/Odin/shared -no-entry-point` | exit 0 |
| New test | `ODIN=$HOME/dev/oss/Odin/odin PACKAGE=. INTERNAL=1 task test -- -define:ODIN_TEST_NAMES=websocket_dial_returns_within_handshake_timeout -define:ODIN_TEST_THREADS=1` | exit 0 |

`INTERNAL=1` runs private suites. The overlay puts `tests/internal` onto `src/`, so the owner is `.`.

## Scope

**In scope**:

- `src/websocket.odin` — `websocket_dial` only
- `tests/internal/websocket_policy_test.odin` — one new test, or a new `tests/internal/websocket_dial_test.odin` if the policy file is the wrong package shape

**Out of scope**:

- `websocket_dial_network` and `websocket_dial_fail` (plan 012)
- `src/websocket_async.odin` (it already defaults `handshake_timeout` to 10s and passes that to `begin_connect`)
- `src/http.odin` ALPN selection
- Gates and testdata

## Git workflow

- Branch: `advisor/011-websocket-dial-deadline`
- Commit: `fix: bound the blocking WebSocket dial by handshake_timeout`
- Do not push.

## Steps

### Step 1: One deadline for resolve, connect, and handshake

In `websocket_dial`, after `settings` is copied from `config`:

- If `settings.handshake_timeout <= 0`, set it to `10 * time.Second`. That matches `websocket_upgrade_deadline_start`.
- `deadline := time.time_add(time.now(), settings.handshake_timeout)`.
- Pass `deadline` to `resolve_endpoints_until` and to `dial_tcp_candidates_until` in place of `{}`.
- Replace `tls_api.handshake(&conn.tls_client)` with `tls_api.handshake_until(&conn.tls_client, deadline)`.
- On a non-nil handshake error, keep the existing `websocket_dial_fail` path.

**Verify**: `rg -n 'resolve_endpoints_until\\(host, port, \\{\\}' src/websocket.odin` prints nothing. `rg -n 'dial_tcp_candidates_until\\(endpoints, \\{\\}' src/websocket.odin` prints nothing. `rg -n 'tls_api.handshake\\(&' src/websocket.odin` prints nothing.

### Step 2: Reject a negotiated protocol other than HTTP/1.1

After a successful `handshake_until`, before `websocket_upgrade`:

```odin
selected := tls_api.connection_state(&conn.tls_client).negotiated_protocol

if selected != "" && selected != "http/1.1" {
	_ = tls_api.conn_close(&conn.tls_client)
	return websocket_dial_fail(conn, tls_api.General_Error.Invalid_Config)
}
```

Match the existing `h3` rejection, which uses `websocket_dial_fail` and `Invalid_Config`. Close the connection you just opened. `websocket_dial_fail` already marks the conn failed and closed.

**Verify**: `odin check` from the table exits 0.

### Step 3: A dial that cannot finish returns inside the timeout

Add `websocket_dial_returns_within_handshake_timeout` in `tests/internal/`.

- Build a `WebSocket_Conn` in `.Uninitialized` the way `tests/address_policy_dial_test.odin` builds one for `websocket_dial`.
- Host `blackhole.invalid`, port 9, `handshake_timeout` of `300 * time.Millisecond`.
- Resolver `name_servers` is one endpoint, `203.0.113.1` port 53. That address is documentation space and is not a DNS server.
- Record `time.now()` before the call and `time.diff` after.
- Expect a non-`None` `WebSocket_Dial_Error` and a duration under 2 seconds.
- Expect `conn.phase != .Open`.

**Verify**: the filtered `task test` command exits 0.

## Test plan

- The new procedure is the regression. It must fail by hanging if the empty deadline returns.
- Model conn setup on the existing `websocket_dial` call in `tests/address_policy_dial_test.odin`. That file is package `tests`, so the new procedure stays in `tests/internal` (package `surf` after overlay).
- No ALPN peer is required if `tests/loopback/tls.odin` cannot select `h2`. The branch is still required. If a loopback helper can negotiate `h2`, add a second test that expects `Invalid_Config` and `phase != .Open`. If it cannot, do not invent a peer.

## Done criteria

- [ ] Resolve, TCP connect, and the TLS handshake in `websocket_dial` all receive the same absolute deadline
- [ ] A zero `handshake_timeout` becomes 10 seconds for that deadline
- [ ] A negotiated protocol other than `""` or `http/1.1` fails with `websocket_dial_fail` and `Invalid_Config` before `websocket_upgrade`
- [ ] `websocket_dial_returns_within_handshake_timeout` passes under `task test`
- [ ] `websocket_dial_network` is unchanged
- [ ] `plans/README.md` status row updated

## STOP conditions

- `tls_api.handshake_until` or `tls_api.connection_state` is missing or has a different signature. Stop. Do not write a local timer around blocking `handshake`.
- The documentation resolver answers `blackhole.invalid` and the dial proceeds into a real handshake. Stop and report the observed error. Do not point the test at a public DNS server.
- The fix seems to require editing `src/websocket_async.odin` or `shared:async/tls`.

## Maintenance notes

- Plan 012 changes the value returned for resolve and connect failures. Its tests must still finish inside this deadline.
- A caller that depended on a hung dial to mean "still connecting" will now see a timeout. That is the fix.
