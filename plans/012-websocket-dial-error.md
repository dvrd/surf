# Plan 012: `websocket_dial` returns the DNS or TCP error it already stored

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat a552088..HEAD -- src/websocket.odin`
> Plan 011 may already have changed `websocket_dial`. That is expected. Stop only if `websocket_dial_network` no longer matches the excerpt.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: LOW
- **Depends on**: plans/011-websocket-dial-deadline.md
- **Category**: bug
- **Planned at**: commit `a552088`, 2026-11-25
- **Executor**: `claude:sonnet` — add one struct field and return the error already in hand
- **Fallback executor**: `codex`

## Why this matters

`websocket_dial_network` stores the real `net.Network_Error` on `conn.last_error` and then returns `tls.General_Error.Name_Resolution_Failed` for every failure. Resolve (`websocket_dial` when `resolve_error != nil`) and TCP connect (`dial_tcp_candidates_until`) both use that procedure. Callers cannot tell a DNS failure from a refused or timed-out connect. The distinct error is only on a conn already marked `.Failed`.

## Current state

```odin
WebSocket_Dial_Error_Kind :: enum {
	None,
	Invalid_State,
	Invalid_Config,
	TLS_Failed,
	Upgrade_Failed,
	Address_Rejected,
}

WebSocket_Dial_Error :: struct {
	kind:      WebSocket_Dial_Error_Kind,
	client:    WebSocket_Client_Error,
	tls:       tls.Error,
	websocket: WebSocket_Error,
}
```

```odin
websocket_dial_network :: proc(conn: ^WebSocket_Conn, err: tcp_api.Network_Error) -> WebSocket_Dial_Error {
	conn.phase = .Failed
	conn.transport_closed = true
	conn.last_error = {
		kind = .Upgrade_Failed,
		stream = {kind = .TCP_Failed, transport = err},
	}

	return {kind = .TLS_Failed, tls = tls_api.General_Error.Name_Resolution_Failed}
}
```

`websocket_dial_fail` is the TLS path. It returns `{kind = .TLS_Failed, tls = err}` and must keep doing that.

`net.Network_Error` is a `#shared_nil` union. Success is nil. There is no `.kind` on the union. DNS failures are `Resolve_Error` or `DNS_Error`. Connect failures are `Dial_Error`. Compare with `!= nil` and a type switch.

`tests/internal/` becomes package `surf` under `tools/test`, so it can call `websocket_dial_network`.

Conventions in `AGENTS.md`: one blank line after a closing brace before the next statement, except a disposal `defer` glued to the `if` that checked the allocation. Tabs. One statement per line. Omit an import name that repeats the last element of the path. Do not reformat the whole file. Do not push. Do not edit sibling repositories.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Check | `ODIN=$HOME/dev/oss/Odin/odin "$ODIN" check src -collection:shared:$HOME/dev/oss/Odin/shared -no-entry-point` | exit 0 |
| Test | `ODIN=$HOME/dev/oss/Odin/odin PACKAGE=. INTERNAL=1 task test -- -define:ODIN_TEST_NAMES=websocket_dial_network_returns_the_transport_error -define:ODIN_TEST_THREADS=1` | exit 0 |

## Scope

**In scope**:

- `src/websocket.odin` — `WebSocket_Dial_Error`, `WebSocket_Dial_Error_Kind`, `websocket_dial_network`
- `tests/internal/websocket_policy_test.odin` or a new `tests/internal/websocket_dial_test.odin`

**Out of scope**:

- `websocket_dial_fail`
- Mapping the network error onto `Name_Resolution_Failed` when it really is a resolve error. Return the `Network_Error` unchanged in every case.
- `src/websocket_async.odin`
- Plan 011's deadline logic. Do not revert it.

## Git workflow

- Branch: `advisor/012-websocket-dial-error`
- Commit: `fix: return the WebSocket dial's network error`
- Do not push.

## Steps

### Step 1: Add a network kind and field

Add `Network_Failed` to `WebSocket_Dial_Error_Kind` after `Address_Rejected`.

Add `transport: tcp_api.Network_Error` as the last field of `WebSocket_Dial_Error`. Named composite literals stay valid. A zero `transport` is nil.

### Step 2: Return that field

`websocket_dial_network` still stores the transport on `last_error` exactly as it does now. Its return becomes:

```odin
return {kind = .Network_Failed, transport = err}
```

Do not put `Name_Resolution_Failed` on this path.

**Verify**: `rg -n 'Name_Resolution_Failed' src/websocket.odin` prints nothing.

### Step 3: Test both shapes

`websocket_dial_network_returns_the_transport_error`:

- A zero `WebSocket_Conn` is not enough if `websocket_dial_network` only writes fields. Call it twice on a conn whose `phase` you set to whatever the procedure requires. The procedure does not read `phase`. A zero conn is fine.
- First call: `err` is `net.Resolve_Error.Unable_To_Resolve`. Expect `kind == .Network_Failed`, `transport` equals that resolve error, `tls` is nil, and `last_error.stream.transport` equals the same value.
- Second call: `err` is `net.Dial_Error.Timeout`. Expect the same shape with that dial error, not `Name_Resolution_Failed`.

Use a type switch or `reflect` only if equality on the union does not compile. `testing.expect_value` works for the enum kind. For the union, assign it and type-switch in the test.

**Verify**: the filtered `task test` exits 0. Then `ODIN=$HOME/dev/oss/Odin/odin PACKAGE=. INTERNAL=1 task test -- -define:ODIN_TEST_NAMES=websocket_dial_returns_within_handshake_timeout,websocket_dial_network_returns_the_transport_error -define:ODIN_TEST_THREADS=1` exits 0.

## Test plan

- The new procedure covers a resolve error and a dial timeout.
- Existing address-policy dial tests must still pass. Run `PACKAGE=. task test -- -define:ODIN_TEST_NAMES=websocket_dial_rejects_before_connect_and_leaves_the_connection_uninitialized,websocket_dial_connects_to_the_endpoint_the_policy_checked,websocket_dial_does_not_connect_when_the_hostname_is_refused -define:ODIN_TEST_THREADS=1`. Those names are in package `tests`, so `INTERNAL` stays unset and `PACKAGE` stays `.` or `all`. If `PACKAGE=.` skips `tests/internal` and also skips package `tests`, run without `PACKAGE` and with `ODIN_TEST_NAMES` set. `tools/test` matches exact names across the suites it selects.

## Done criteria

- [ ] `websocket_dial_network` returns `.Network_Failed` and the same `Network_Error` it stored
- [ ] `Name_Resolution_Failed` does not appear in `src/websocket.odin`
- [ ] `websocket_dial_fail` still returns `.TLS_Failed`
- [ ] The new test and the plan 011 timeout test pass
- [ ] `plans/README.md` status row updated

## STOP conditions

- Callers in `src/` match on `General_Error.Name_Resolution_Failed` for a dial result. Update those callers in this file only. If a test outside `src/websocket.odin` and `tests/internal/` requires the old value, update that test and list it in the commit. Do not keep the wrong return.
- Adding `transport` collides with an existing field. Stop and report the struct.
- The change seems to require a new error package.

## Maintenance notes

- `last_error` remains `.Upgrade_Failed` / `.TCP_Failed` so existing conn inspection still sees the transport. The dial result is the value callers branch on.
- A positional composite literal of `WebSocket_Dial_Error` that listed every field would break. The tree uses named fields. If `odin check` reports a positional literal, update it.
