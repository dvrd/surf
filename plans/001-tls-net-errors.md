# Plan 001: The library type-checks against public tls.Error and net.Network_Error

> **STALE at `a552088`.** Do not execute this plan until `plans/010-stale-plan-text.md` rewrites the STOP conditions and done criteria below. The library already uses `shared:async/tls`. HTTP/3 forwards `session_cache`, `client_credentials`, and `client_credential_lease` (`src/http3.odin:136`). Following the STOP text would undo that. What remains is the gate and testdata port, and it waits on `plans/009-step-import.md` because `core:compress/step` no longer exists.

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: The excerpts below were taken from the
> uncommitted working tree on 2026-11-24, while `HEAD` was `6209fc3`. A
> clean `git diff 6209fc3..HEAD` does not mean the excerpts match: the
> working tree already differs from that commit.
>
> ```
> git diff --stat 6209fc3..HEAD -- src tests/outcomes_test.odin tests/upload_test.odin tests/head_exchange_test.odin tests/address_policy_dial_test.odin tests/internal tests/testdata tests/stream104
> git diff --stat -- src/http.odin src/http2.odin src/websocket.odin src/async/session.odin
> ```
>
> Open `src/http.odin` and confirm the `HTTP_Error` excerpt below is still
> there before editing. If `tls_dial` is already gone and the tree already
> type-checks, stop and report that this plan is already done.

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: MED
- **Depends on**: plans/008-async-http.md

Plan 008 lands first and rewrites `shared:http` to `shared:async/http`.
The excerpts below still show the old paths. Treat that as expected, not
drift. Do not rewrite an import back to `shared:http`. Do not assign
`config.tls.client_credentials` or `config.tls.session_cache` into an
HTTP/3 `Client_Request`. 008 leaves those fields nil because the request
type is `shared:async/tls` and `Config.tls` stays `core:crypto/tls`.
Do not switch `Config.tls` to `shared:async/tls` in this plan.
- **Category**: migration
- **Planned at**: commit `6209fc3`, 2026-11-24

## Why this matters

`task test` compiles package `surf` before any suite runs. The current Odin
tree at `/Users/kakurega/dev/oss/Odin` (`core` commit prefix `e1a6ad49d`)
returns one public `tls.Error` from TLS calls, and `net.Network_Error` is a
nil-union of enums. Surf still names the private structs `tls.Dial_Error`,
`tls.IO_Error`, and `tls.Handshake_Error`, and it still builds
`{kind = .Timeout}` values into `Network_Error`. The package does not
type-check, so the address-policy, redirect, body-limit, and TLS tests never
run. This plan finishes that migration and nothing else.

## Current state

SDK facts, read these and do not edit them:

- `/Users/kakurega/dev/oss/Odin/core/crypto/tls/api.odin` — `Error :: union #shared_nil` of `runtime.Allocator_Error`, `io.Error`, `net.TCP_Send_Error`, `net.TCP_Recv_Error`, `net.Dial_Error`, `General_Error`, `Protocol_Error`. Success is `nil`. There is no `.kind` on this union.
- `/Users/kakurega/dev/oss/Odin/core/crypto/tls/tls_conn.odin` — `config_validate`, `client`, `dial`, `read`, `write`, `set_deadline`, `conn_close`, and `abort` return `Error`. `read`'s note says `Protocol_Error.Close_Notify` means the peer will send no more data.
- `/Users/kakurega/dev/oss/Odin/core/crypto/tls/tls_roots.odin` — `root_pool_parse` and `root_pool_load_file` return `Error`. `nil` is success (`root_error` returns `nil` for `Root_Error_Kind.None`). `.kind` exists only on the private `Root_Error`.
- `/Users/kakurega/dev/oss/Odin/core/crypto/tls/tls_application.odin` — `IO_Error` is `@(private)`.
- `/Users/kakurega/dev/oss/Odin/core/crypto/tls/tls_connection.odin` — `Dial_Error` is `@(private)`. `Async_Handshake_Operation.result` is the private `Handshake_Error`. `Async_Handshake_Operation.err` is `net.Network_Error`. Do not read `.result`.
- `/Users/kakurega/dev/oss/Odin/core/crypto/tls/tls_async.odin` — `async_client`, `async_handshake`, and `async_failure` return `Error`.
- `/Users/kakurega/dev/oss/Odin/core/crypto/tls/tls_handshake.odin` — `Handshake_Error` and `Handshake_Error_Kind` are `@(private)`.
- `/Users/kakurega/dev/oss/Odin/core/net/common.odin` — `Network_Error :: union #shared_nil` of enums. No `.kind`.
- `/Users/kakurega/dev/oss/Odin/core/net/errors.odin` — `Connection_Error` has `Cancelled`, `Peer_Closed`, `Invalid_Count`, `Protocol_Failed`. It has no `Timeout`, `Read_Failed`, or `Write_Failed`. Timeouts are `Dial_Error.Timeout`, `TCP_Recv_Error.Timeout`, and `TCP_Send_Error.Timeout`.
- `/Users/kakurega/dev/oss/Odin/core/net/connection.odin` — `Connection.read` and `Connection.write` return `(int, Network_Error)`. `write_all` returns `(int, Network_Error)`.

Surf today:

```odin
// src/http.odin:17
HTTP_Error :: struct {
	kind:          http.Error_Kind,
	transport:     trans.Network_Error,
	network:       trans.Network_Error,
	tls_dial:      tls.Dial_Error,
	tls_io:        tls.IO_Error,
	...
}
```

```odin
// src/http.odin:1154
TLS_Adapter :: struct {
	connection: ^tls.Conn,
	last_error: tls.IO_Error,
}
tls_read :: proc(data: rawptr, dst: []u8) -> (int, trans.Network_Error) {
	a := cast(^TLS_Adapter)data
	n, e := tls.read(a.connection, dst)
	a.last_error = e
	if e.kind == .EOF {
		return n, trans.Connection_Error.Peer_Closed
	}
	if e != nil {
		return n, {kind = .Read_Failed}
	}
	return n, {}
}
```

```odin
// src/async/session.odin:82
session_runtime_error :: proc(error: runtime_async.Error, phase: surf.HTTP_Phase) -> surf.HTTP_Error {
	if error.kind == .Timeout {
		return {kind = .Deadline_Failed, transport = {kind = .Timeout}, phase = .Deadline, write_effect = .Not_Sent}
	}
	if error.kind == .Cancelled || error.kind == .Stopping {
		return {kind = .IO_Failed, transport = {kind = .Cancelled}, phase = .Cancellation, write_effect = .Not_Sent}
	}
	...
}
```

`http_error_classify` (`src/http.odin:1730`) still switches on `result.tls_dial.kind`, `result.tls_io.kind`, and `transport.kind`. `http_network_phase` (`src/http.odin:1825`) already switches on the union for `Resolve_Error`, `DNS_Error`, and `Dial_Error`. Match that switch. Do not add a `.kind` helper.

`src/buffered.odin:352` is the pattern already used for a trust-root load: `loaded := tls_api.root_pool_load_file(...)` then `if loaded != nil`.

`tests/outcomes_test.odin` is the classification contract. Its fault stream still returns `net.Connection_Error` and uses `{kind = .Write_Failed}`, `{kind = .Read_Failed}`, `{kind = .Timeout}`, `{kind = .Cancelled}`, and `{kind = .Peer_Closed}`. The TLS samples at lines 152–171 build private `tls_io` literals and expect:

- a record failure keeps phase `.TLS`
- a transport read failure keeps the fallback phase `.Read`
- a transport timeout becomes phase `.Deadline`

Style: tabs, one statement per line, a comment only for a constraint the code does not show. See `http_network_phase` in `src/http.odin`. Commit subjects look like `fix: close TLS WebSocket streams with tls.conn_close`. No trailer line.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Typecheck the library | `odin check src -collection:shared:$HOME/dev/oss/Odin/shared -warnings-as-errors` | exit 0 |
| Suites | `task test` from the repo root | exit 0, and each suite prints `All tests were successful` |
| One package | `task test PACKAGE=async` | exit 0 |

`task test` runs `odin run tools/test`. `tools/test` is part of this working tree. If that directory is missing, STOP. Do not recreate the old bash runner in `Taskfile.yml`.

## Scope

**In scope**

- `src/**/*.odin`
- `tests/**/*.odin` that does not live under `tests/gates/`
- `tests/stream104/main.odin` and `tests/testdata/**/*.odin` are in scope when they call `.kind` on a `tls.Error` or build a `{kind = ...}` `Network_Error`

**Out of scope**

- `tests/gates/**` — plan 004
- `tools/test/**` and `Taskfile.yml`
- `/Users/kakurega/dev/oss/Odin/**`
- `/Users/kakurega/dev/projects/http`, `async`, and `websocket`
- Header policy, certificates, docs, and `.krs/packages.json`
- Any behavior change besides the types and the phase rules in this plan

## Git workflow

- Branch: `advisor/001-tls-net-errors`
- The worktree is already dirty. Do not `git restore`, `git checkout --`, or `git clean`.
- Commit only the files this plan changes. Leave `tools/`, `tests/gates/`, Python deletions, and `Taskfile.yml` unstaged if you did not need to edit them.
- Subject: `fix: classify TLS and net failures through the public error unions`
- Do not push. Do not mention an AI tool in the message.

## Steps

### Step 1: Replace the private TLS fields on HTTP_Error

In `src/http.odin`, remove `tls_dial` and `tls_io`. Add one field:

```odin
tls_error: tls.Error,
```

`tls.Error` nil means no TLS failure. Update `TLS_Adapter.last_error` to `tls.Error`.

Rewrite `tls_read` and `tls_write` to this shape. `e` is the `tls.Error` from `tls.read` or `tls.write`.

```odin
a.last_error = e
if e == nil {
	return n, nil
}
#partial switch err in e {
case tls.Protocol_Error:
	if err == .Close_Notify {
		return n, trans.Connection_Error.Peer_Closed
	}
	return n, trans.Connection_Error.Protocol_Failed
case trans.TCP_Recv_Error:
	return n, err
case trans.TCP_Send_Error:
	return n, err
case trans.Dial_Error:
	return n, err
case:
	return n, trans.Connection_Error.Protocol_Failed
}
```

A write never treats `Close_Notify` as a short success. A write error returns `trans.Connection_Error.Protocol_Failed` unless the union value is already a `TCP_Send_Error`, `TCP_Recv_Error`, or `Dial_Error`.

**Verify**: `odin check src -collection:shared:$HOME/dev/oss/Odin/shared -warnings-as-errors` may still fail in other files. It must no longer report `tls.Dial_Error` or `tls.IO_Error` inside `src/http.odin`.

### Step 2: Classify with a union switch

Rewrite the TLS and transport half of `http_error_classify` so it no longer reads `.kind` on `tls_error` or on `transport`. Keep the existing kind/phase table for surf's own `HTTP_Error.kind` (the `#partial switch result.kind` block). After that block, apply only these rules, in order:

1. If `tls_error` is `tls.Protocol_Error` and the value is not `.Close_Notify`, set phase `.TLS`.
2. If `tls_error` is `tls.General_Error` and the value is `.Invalid_Config`, `.Invalid_State`, or `.Invalid_Trust_Roots`, and `kind` is `.TLS_Failed`, set phase `.Configuration`.
3. If `tls_error` is `tls.General_Error.Cancelled`, or `transport` is `trans.Connection_Error.Cancelled`, set phase `.Cancellation`.
4. If `tls_error` or `transport` is `trans.Dial_Error.Timeout`, `trans.TCP_Recv_Error.Timeout`, `trans.TCP_Send_Error.Timeout`, or `trans.DNS_Error.Timeout`, set phase `.Deadline`.
5. Otherwise leave the phase already chosen.

Extend `http_network_phase` with:

- `trans.Dial_Error` where the value is `.Timeout` → `.Deadline`, any other dial error → `.Connect`
- `trans.TCP_Recv_Error` or `trans.TCP_Send_Error` where the value is `.Timeout` → `.Deadline`, otherwise `.Unknown` so the caller's fallback stands
- `trans.Connection_Error` where the value is `.Cancelled` → `.Cancellation`

Delete the walk over `tls_dial.handshake.client_hello.transport` and the other private handshake fields. Those fields are not on `tls.Error`.

Every `{kind = .Timeout}`, `{kind = .Cancelled}`, `{kind = .Read_Failed}`, `{kind = .Write_Failed}`, and `{kind = .Invalid_Count}` that is stored in `HTTP_Error.transport`, `HTTP_Error.network`, or returned as `net.Network_Error` becomes one of:

| Old literal | Replacement |
|---|---|
| timeout on connect | `trans.Dial_Error.Timeout` |
| timeout on read or a general wait | `trans.TCP_Recv_Error.Timeout` |
| timeout on write | `trans.TCP_Send_Error.Timeout` |
| cancelled | `trans.Connection_Error.Cancelled` |
| peer closed | `trans.Connection_Error.Peer_Closed` |
| bad count | `trans.Connection_Error.Invalid_Count` |
| TLS record or alert, transport slot only | `trans.Connection_Error.Protocol_Failed` |

`session_runtime_error` keeps `kind = .Deadline_Failed` and `phase = .Deadline`. Its `transport` becomes `trans.TCP_Recv_Error.Timeout`. Its cancel arm uses `trans.Connection_Error.Cancelled`.

**Verify**: `rg -n "tls_dial|tls_io" src/http.odin` prints nothing. `rg -n "transport = \{kind =" src` prints nothing.

### Step 3: Move the other library files onto the same types

Apply the same replacements in:

- `src/http2.odin` — `h2_tls_error` must take `tls.Error`, not `tls.IO_Error`. `config_validate` and `client` are compared to `nil`, not `.None`.
- `src/http2_websocket.odin` — `tls.set_deadline(...).kind` becomes `!= nil`. The `Network_Error` it stores is the switch from step 1, not `{kind = ...}`.
- `src/http3.odin`, `src/upload.odin` — `net.write_all(...).kind` and `{kind = .Invalid_Count}` become `!= nil` and `net.Connection_Error.Invalid_Count`.
- `src/websocket.odin` and `src/websocket_async.odin` — private `Dial_Error`, `IO_Error`, `Handshake_Error`, and `Handshake_Error_Kind` fields become `tls.Error` under the name `tls_error`. Update literals in this repo. `tls.read`'s `Close_Notify` is the clean end, as in step 1.
- `src/async/session.odin`, `src/async/stream.odin`, `src/async/redirect.odin`, `src/async/coordinator.odin`, `src/async/exchange/exchange.odin` — `async_client(...) != .None` becomes `!= nil`. `async_handshake(...).kind` becomes `!= nil`. `async_failure` returns `tls.Error`; store it in `tls_error`. Do not read `Async_Handshake_Operation.result`. `handshake.err` is `net.Network_Error`; compare it to `nil`.

`src/buffered.odin` already uses `loaded != nil` for `root_pool_load_file`. Leave that check. Update any remaining `tls_io = adapter.last_error` so it assigns `tls_error`.

**Verify**: `odin check src -collection:shared:$HOME/dev/oss/Odin/shared -warnings-as-errors` → exit 0.

### Step 4: Update tests to the same unions

`tests/outcomes_test.odin`:

- `Fault_Stream.write_error` and `read_error` become `net.Network_Error`.
- `fault_read`, `fault_write`, and `fault_close` return `net.Network_Error`.
- `write_error.kind != .None` becomes `write_error != nil`.
- The four samples in `public_exchange_distinguishes_write_read_timeout_and_cancel` become:
  - write `net.TCP_Send_Error.Connection_Closed`, read `nil`, phase `.Write`
  - read `net.TCP_Recv_Error.Connection_Closed`, phase `.Read`
  - read `net.TCP_Recv_Error.Timeout`, phase `.Deadline`
  - read `net.Connection_Error.Cancelled`, phase `.Cancellation`
- `read_error = {kind = .Peer_Closed}` becomes `net.Connection_Error.Peer_Closed`.
- The three `http_error_classify` samples become:
  - `{kind = .IO_Failed, tls_error = tls.Protocol_Error.Bad_Record_Mac}` expects phase `.TLS`
  - `{kind = .IO_Failed, tls_error = net.TCP_Recv_Error.Connection_Closed}` expects phase `.Read`
  - `{kind = .IO_Failed, tls_error = net.TCP_Recv_Error.Timeout}` expects phase `.Deadline`

Every `tls.root_pool_parse(...).kind` and `tls.root_pool_load_file(...).kind` in `tests/` becomes `!= nil` for failure and `== nil` for success. This includes `tests/internal/http3_request_test.odin`, `tests/internal/http3_capacity_test.odin`, `tests/stream104/main.odin`, `tests/address_policy_dial_test.odin`, and the `tests/testdata/**` fixtures. `tests/upload_test.odin` and `tests/head_exchange_test.odin` lose `{kind = ...}` network literals the same way as step 2.

Do not edit `tests/gates/`.

**Verify**:

```
rg -n "tls\.(Dial_Error|IO_Error|Handshake_Error)|Handshake_Error_Kind" src tests --glob '!tests/gates/**'
rg -n "root_pool_(parse|load_file)\(.*\)\.kind" src tests --glob '!tests/gates/**'
rg -n "\{kind = \.(Timeout|Read_Failed|Write_Failed|Cancelled|Peer_Closed|Invalid_Count)\}" src tests --glob '!tests/gates/**'
```

All three print nothing. Then `task test` from the repo root → exit 0.

## Test plan

- Update `tests/outcomes_test.odin` as in step 4. That file is the regression for phase `.TLS`, `.Read`, `.Deadline`, and `.Cancellation`.
- Do not add a new test file. The existing `native_dns_failure_classifies_as_dns` test stays, with `network = net.Resolve_Error.Unable_To_Resolve` unchanged if that enum value still exists. If the enumerator was renamed, use the current name and keep the expected phase `.DNS`.
- `task test` → exit 0.

## Done criteria

- [ ] `odin check src -collection:shared:$HOME/dev/oss/Odin/shared -warnings-as-errors` exits 0
- [ ] `task test` exits 0
- [ ] The three `rg` commands in step 4 print nothing outside `tests/gates/`
- [ ] `HTTP_Error` has `tls_error: tls.Error` and does not have `tls_dial` or `tls_io`
- [ ] No file outside the in-scope list is modified
- [ ] `plans/README.md` status row updated

## STOP conditions

- The `HTTP_Error` excerpt is gone and the tree already type-checks: report "already done".
- A public TLS procedure no longer returns `tls.Error`, or `Close_Notify` is no longer the read-EOF value. Report the procedure and the type you found.
- `Async_Handshake_Operation` no longer has an `err` field of type `net.Network_Error`. Report the struct. Do not read `.result` to compensate.
- `h2_open` returns a different type than `h2_fields` for a reason other than the private TLS structs. Report both type names. Do not add a cast.
- `task test` compiles and then a suite fails on an assertion you did not change. Report the suite name and the first assertion. Do not edit the expected value.
- The fix seems to require editing `/Users/kakurega/dev/oss/Odin` or a sibling library.
- `tools/test` is missing.

## Maintenance notes

- New I/O failures use a `net` enum value or a `tls.Error` value. A `{kind = ...}` literal is the surf `HTTP_Error` / `http.Error_Kind` shape, and it is the wrong shape for `transport`.
- Reviewers should check the phase table against `tests/outcomes_test.odin`, especially that a timeout does not stay `.Read` and a record failure does not become `.Read`.
- `tests/gates/` still has its own copies of these mistakes if any gate fixture constructs `HTTP_Error`. That is plan 004's territory only when a gate stops building. Do not preempt it here.
- Pool reuse still skips the address policy. That comment on `Config` stays.
