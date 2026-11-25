# Plan 002: HTTP/3 uses the same header and handshake-failure contract as HTTP/2

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: Excerpts are from the working tree on
> 2026-11-24, `HEAD` `6209fc3`, plus plan 001 if it has landed. Confirm the
> `execute_http3` header loop and the HTTP/3 WebSocket returns below still
> match before editing. If plan 001 renamed `tls_dial` / `tls_io`, do not
> put those fields back.
>
> ```
> git diff --stat 6209fc3..HEAD -- src/http3.odin src/http2.odin src/http2_websocket.odin
> ```

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: plans/001-tls-net-errors.md

Plan 008 runs before 001 and rewrites `shared:http` to
`shared:async/http`. `section_check` is
`/Users/kakurega/dev/projects/async/src/http/v3/frame.odin:491`. Do not
edit that file, and do not edit `/Users/kakurega/dev/projects/http` if it
is still on disk. HTTP/3 credential fields on `Client_Request` stay nil
after 008. Do not fill them from `config.tls`.
- **Category**: bug
- **Planned at**: commit `6209fc3`, 2026-11-24

## Why this matters

HTTP/2 drops a caller `Host` and `Content-Length` and rejects the
connection-specific names before `h2.connection_open`. HTTP/3 copies every
caller header onto the request. `shared:async/http` rejects `connection`,
`keep-alive`, `proxy-connection`, `transfer-encoding`, `upgrade`, and a bad
`te` inside `section_check`, so those names do not become a successful
encode. `host` is not in that set, so a caller `Host` is sent beside
`:authority`. The HTTP/3 WebSocket opener also returns `Header_Limit` and
some `Invalid_Header` values with a zero phase and a zero `write_effect`.
`HTTP_Write_Effect.Unknown` is the zero value and, by the comment on that
enum, must not be read as evidence about whether bytes were sent.

## Current state

HTTP/2 request headers, `src/http2.odin`:

```odin
// h2_fields, around line 1083
for header in job.request.headers {
	name := header.name
	if len(name) == 0 {
		return {kind = .Invalid_Input}
	}
	if strings.equal_fold(name, "host") || strings.equal_fold(name, "content-length") {
		continue
	}
	if h2_name_forbidden(name) {
		return {kind = .Invalid_Input}
	}
	...
}
```

`h2_name_forbidden` (`src/http2.odin:1735`) is true for `te`, `upgrade`,
`keep-alive`, `connection`, `proxy-connection`, and `transfer-encoding`.

HTTP/3 request headers, `src/http3.odin` inside `execute_http3`:

```odin
for header, i in request.headers {
	name, fits := field_name_lower(names[:], &names_n, header.name)
	if !fits {
		return {}, {kind = .Header_Limit, phase = .Configuration, write_effect = .Not_Sent}
	}
	fields[i] = {
		name  = name,
		value = header.value,
	}
}
```

The index `i` is the caller's index. Skipping a header requires a separate
counter. Do not leave a hole in `fields`.

`shared:http` `client_application_request` adds `content-length` when the
caller did not supply one, and rejects a caller `content-length` that
disagrees with the body. Leave that behavior. This plan does not drop
`content-length` on HTTP/3.

HTTP/3 WebSocket, `src/http3.odin` around 726–816, returns
`{kind = .Header_Limit}` with no phase at the protocol-join failure, the
field-count failure, and the name-buffer failure. It returns
`{kind = .Invalid_Header}` with no phase when the response repeats
`sec-websocket-protocol` or carries `sec-websocket-extensions` or
`sec-websocket-accept`. The request-header rejection just below those
returns already sets `phase = .Configuration` and `write_effect = .Not_Sent`.

HTTP/2 WebSocket, `src/http2_websocket.odin:97` and `:107`, sets
`phase = .Configuration` and `write_effect = .Not_Sent` on `Header_Limit`.
Response failures at `:189` and `:195` set `phase = .Protocol` and
`write_effect = .Response_Received`.

HTTP/3 rejects a caller `origin` or `sec-websocket-*` header (`src/http3.odin:751`).
HTTP/2 copies caller headers and then calls `h2.headers_validate`
(`src/http2_websocket.odin:105`). A second `origin` can therefore be sent on
HTTP/2 when `options.origin` is also set.

Style: tabs, one statement per line. Match `h2_fields`.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Library | `odin check src -collection:shared:$HOME/dev/oss/Odin/shared -warnings-as-errors` | exit 0 |
| HTTP/3 unit tests | `task test PACKAGE=.` from the repo root | exit 0 |
| Private HTTP/3 tests | `task test INTERNAL=1 PACKAGE=.` | exit 0, including the `tests/internal` http3 files |

Plan 001 must already have made `task test` compile. If `task test` fails
before any assertion, with a type error, stop and finish plan 001. Do not
re-fix TLS types here.

## Scope

**In scope**

- `src/http3.odin`
- `src/http2_websocket.odin`
- `tests/internal/http3_request_test.odin` and `tests/internal/http3_websocket_test.odin` only if a new assertion needs a home. Prefer extending an existing test over a new file.

**Out of scope**

- `src/http.odin`, `src/http2.odin` except you may call `h2_name_forbidden` only if you move that helper to a file both packages already share. Do not do that move. Duplicate the six-name check as a local proc in `src/http3.odin` instead of exporting a new cross-file helper.
- `shared:async/http` (`/Users/kakurega/dev/projects/async/src/http`) and the old tree at `/Users/kakurega/dev/projects/http`
- Alt-Svc, the HTTP/3 pool, and early data
- `tests/gates/**`

## Git workflow

- Branch: `advisor/002-http3-header-contract`
- Do not revert plan 001's error-union edits if they are in the same worktree.
- Commit only the files this plan changes.
- Subject: `fix: reject HTTP/3 hop-by-hop headers and classify websocket failures`
- Do not push.

## Steps

### Step 1: Filter HTTP/3 request headers before they are copied

In `execute_http3`, replace the loop that assigns `fields[i] = header` with a
loop that appends through a `count` starting at 0.

- Lowercase the name with the existing `field_name_lower` call.
- If the lowered name is `host`, skip it.
- If the lowered name is `connection`, `keep-alive`, `proxy-connection`,
  `transfer-encoding`, `upgrade`, or `te`, return
  `{kind = .Invalid_Input, phase = .Configuration, write_effect = .Not_Sent}`.
- Otherwise store the field at `fields[count]` and increment `count`.
- Pass `fields[:count]` as `wire.headers`, not `fields[:len(request.headers)]`.

Do not skip `content-length`. A mismatched length must still fail inside
`shared:async/http`, where it fails today. Do not edit that library.

Apply the same skip and the same rejection to trailer fields if
`http3_trailer_fields` copies caller names through unchanged. Read that proc.
If it already rejects these names, leave it.

**Verify**: `odin check src -collection:shared:$HOME/dev/oss/Odin/shared -warnings-as-errors` → exit 0.

### Step 2: Set phase and write_effect on the HTTP/3 WebSocket returns

In the HTTP/3 WebSocket opener in `src/http3.odin`:

- Each `{kind = .Header_Limit}` that has no phase becomes
  `{kind = .Header_Limit, phase = .Configuration, write_effect = .Not_Sent}`.
  These are the failures before `pool_connect_open`.
- Each `{kind = .Invalid_Header}` after `pool_connect_open` returns becomes
  `{kind = .Invalid_Header, phase = .Protocol, write_effect = .Response_Received}`.
  The response was received. Do not use `.Not_Sent` there.
- Leave the existing caller-header rejection
  (`sec-websocket-key`, `sec-websocket-accept`, `sec-websocket-version`,
  `sec-websocket-extensions`, `sec-websocket-protocol`, `origin`) as it is.
  It already sets phase and write effect.

In `src/http2_websocket.odin`, reject those same six caller header names
before `h2.headers_validate`, with
`{kind = .Invalid_Header, phase = .Configuration, write_effect = .Not_Sent}`.
`options.origin` and `options.subprotocols` remain the only way to send
`origin` and `sec-websocket-protocol`. Do not reject the fields this function
itself just appended.

**Verify**: `odin check src -collection:shared:$HOME/dev/oss/Odin/shared -warnings-as-errors` → exit 0.

### Step 3: Cover the header rejection with a unit test

Add one `@(test)` proc to `tests/internal/http3_request_test.odin`, or to the
existing HTTP/3 test file that already builds a `surf.Config` with `http3 =
true` and a loopback or a refused dial. The test's job is the header filter,
so a dial must not be required.

Call the smallest surf entry that runs `execute_http3`'s header loop. If the
only entry dials, construct the request and call that entry against
`127.0.0.1` with `timeout` of one second and `allow_http = false` only if the
URL is `https`. Use a `Host` header whose value is not the URL host, plus a
`Connection: close` header.

Expect `error.kind == .Invalid_Input` and `error.phase == .Configuration`
and `error.write_effect == .Not_Sent`. The `Connection` header is what
produces `Invalid_Input`. A request with only `Host: evil.example` must not
return `Invalid_Input`; it must fail later at dial, TLS, or
`Insecure_URL`, and it must not report `write_effect == .Unknown` when
`kind != .None`.

If you cannot reach the header loop without a live QUIC peer, STOP and
report that. Do not weaken the assertion to "the call returns".

**Verify**: `task test INTERNAL=1 PACKAGE=.` → exit 0, and the new test name
appears in the output.

## Test plan

- One new test, as in step 3, for `Connection` rejected and `Host` not
  turned into `Invalid_Input`.
- No new WebSocket integration test. The phase fields are set on returns
  that the existing `tests/internal/http3_websocket_test.odin` already
  reaches only with a peer. Do not start a peer for this plan.
- Pattern: the existing `@(test)` procs in `tests/internal/http3_request_test.odin`.

## Done criteria

- [ ] `odin check src ...` exits 0
- [ ] `task test INTERNAL=1 PACKAGE=.` exits 0
- [ ] `rg -n "kind = \.Header_Limit\}" src/http3.odin` prints nothing (every `Header_Limit` sets phase and write_effect)
- [ ] A caller `Connection` header on the HTTP/3 execute path returns `Invalid_Input` before a successful encode
- [ ] `content-length` is still forwarded
- [ ] `plans/README.md` status row updated

## STOP conditions

- Plan 001 has not landed and `odin check src` fails on `tls.Dial_Error` or `Network_Error`. Finish 001 first.
- `shared:async/http` has started stripping `host` itself, so the skip would be redundant and you cannot tell. Still skip it in surf. Do not edit `shared:async/http` or the old `shared:http` tree.
- The header loop is no longer in `execute_http3`. Report the new procedure name.
- The new test can only pass by dialing a real network host. Stop.

## Maintenance notes

- A later HTTP/3 trailers or WebSocket header change has to use the same
  six-name list and the same phase pairs: configuration failures are
  `.Not_Sent`, failures after the peer answered are `.Response_Received`.
- Reviewers should check that `fields[:count]` has no zero holes, and that
  `Host` is omitted rather than rewritten to the URL host.
- Dropping `content-length` was considered and rejected. The HTTP/3 stack
  already checks it against the body.
