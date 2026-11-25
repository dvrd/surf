# Plan 013: A failed HTTP/2 WebSocket open releases the lane

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat a552088..HEAD -- src/http2_websocket.odin src/http2.odin`
> Stop if `http_lane_prepare` or `http_lane_close` no longer has the shape in the excerpts.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: MED
- **Depends on**: plans/009-step-import.md
- **Category**: bug
- **Planned at**: commit `a552088`, 2026-11-25
- **Executor**: `claude:sonnet` — add `http_lane_close` on the failure returns that already exist
- **Fallback executor**: `codex`

## Why this matters

`HTTP_ORIGIN_SLOTS` is 4 (`src/http2.odin:23`). `http2_websocket` returns after `http_lane_prepare` without `http_lane_close` when `set_deadline` fails, `h2_boot` fails, extended CONNECT is off, admission fails, or `connection_open` fails. The multiplex path closes the lane on those same failures (`src/http2.odin:255` and `:292`). Each leaked lane stays in `c.lanes` with `tls` set, so `http_lane_prepare` will not reuse the slot (`src/http2.odin:457`). Four failed opens to different hosts make later origins fail with `.Invalid_Config` until `http_client_close`.

`h2_tunnel_detach` stores a closed stream handle in `lane.closed_tunnels` (`[HTTP_STREAM_SLOTS]`, 8 entries). If every slot is taken it drops the handle and leaves `lane.reusable` true. `h2_retire_request` sets `reusable = false` when it cannot keep a handle (`src/http2.odin:1880`).

## Current state

The open path in `src/http2_websocket.odin`:

```odin
lane, reused, e := http_lane_prepare(client, parsed, deadline)
if e.kind != .None {
	return e
}
if lane.protocol != .HTTP2 {
	http_lane_close(client, lane)
	return {kind = .Invalid_Config, phase = .Protocol, write_effect = .Not_Sent}
}
if de := tls.set_deadline(lane.tls, deadline); de != nil {
	return {kind = .IO_Failed, phase = .Deadline, write_effect = .Not_Sent, tls_error = de, transport = tls_network(de)}
}
if !reused {
	if e = h2_boot(lane, deadline, &client.cancel); e.kind != .None {
		return e
	}
}
```

Later returns before `success` is set:

- extended CONNECT not allowed
- no free `lane.tunnels` slot
- `h2.connection_open` fails
- `h2_tunnel_progress` fails after the tunnel is assigned (a `defer` calls `h2_tunnel_abort`)

`http_lane_close(c, lane)` is the procedure the multiplex path uses. Call it with the same `HTTP_Client` pointer `http_lane_prepare` received.

`h2_tunnel_detach` (`src/http2_websocket.odin` around line 468) ends with a loop that copies `stream._handle` into the first empty `closed_tunnels` slot and does nothing when the array is full.

Closing a reused lane drops that pooled connection. The multiplex path does the same on boot failure. Match it. Do not leave the failed lane in the table.

Conventions in `AGENTS.md`: one blank line after a closing brace before the next statement. No blank line before `else`. Disposal `defer` stays on the line after the `if` that checked the allocation. Tabs. One statement per line. Omit an import name that repeats the last element of the path. Do not reformat untouched procedures. Do not push. Do not edit sibling repositories.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Check | `ODIN=$HOME/dev/oss/Odin/odin "$ODIN" check src -collection:shared:$HOME/dev/oss/Odin/shared -no-entry-point` | exit 0 |
| Existing opens | `ODIN=$HOME/dev/oss/Odin/odin PACKAGE=. INTERNAL=1 task test -- -define:ODIN_TEST_NAMES=http2_websocket_rejects_a_peer_without_extended_connect,http2_websocket_rejects_a_nil_client -define:ODIN_TEST_THREADS=1` | exit 0, or "No test found" if those exact names differ |

If the names differ, `rg -n '^\\w+ :: proc\\(t: \\^testing.T\\)' tests/internal/http2_websocket_test.odin` and run the procedures that already exist. Do not skip them.

## Scope

**In scope**:

- `src/http2_websocket.odin` — the open procedure that calls `http_lane_prepare`, and `h2_tunnel_detach`
- `tests/internal/http2_websocket_test.odin` — one regression if you can fail an open without a new peer mode

**Out of scope**:

- `h2_tls_error` and tunnel timeout classification (plan 021)
- `src/http2.odin` except reading `http_lane_close`. Do not change multiplex.
- HTTP/3 tunnel open (`src/http3.odin`). If you find the same missing close there, stop and report it. Do not fix it in this plan.
- Teaching the lane to follow redirects

## Git workflow

- Branch: `advisor/013-websocket-lane-close`
- Commit: `fix: close the HTTP/2 lane when a WebSocket open fails`
- Do not push.

## Steps

### Step 1: Close the lane on every failed open

After `http_lane_prepare` has returned a lane, every return with `e.kind != .None` or an `HTTP_Error` you construct must call `http_lane_close(client, lane)` first.

The `.HTTP2` mismatch branch already closes. Leave it.

The `defer` that calls `h2_tunnel_abort` runs when the tunnel was published onto the lane. Abort still runs. Then close the lane on that failure path too, so the slot's `tls` is cleared. Read `http_lane_close` before calling it after abort. If abort already nils `lane.tls`, `http_lane_close` must tolerate that. If it does not, nil-check and still clear the slot the way `http_lane_close` does. Do not return with `lane.tls` still set on a failed open.

The success return, after status 200 and protocol checks, must not close the lane. The tunnel holds it.

**Verify**: `odin check` exits 0. Re-read the procedure and count error returns after `http_lane_prepare`. Each one calls `http_lane_close` or returns before a lane exists.

### Step 2: Do not forget a closed tunnel handle

In `h2_tunnel_detach`, if the `closed_tunnels` loop finishes without storing `stream._handle`, set `lane.reusable = false`. That matches the comment on `h2_retire_request`: no handle may be forgotten at capacity.

**Verify**: `rg -n 'reusable = false' src/http2_websocket.odin` shows the new assignment.

### Step 3: Keep the existing rejection tests

Run the internal HTTP/2 WebSocket tests named in the table, with the real procedure names if they differ.

If `tests/internal/http2_websocket_test.odin` can open a client, force `set_deadline` or boot to fail, and count lanes, add one test that four failed opens leave a later `http_lane_prepare` able to take a slot. If that fixture does not exist, do not build a new peer. The close calls are the change. Say in the commit message that no new peer was added.

## Test plan

- Existing `tests/internal/http2_websocket_test.odin` procedures must still pass.
- A new test is required only when the file already has a client and a way to fail after `http_lane_prepare`. Otherwise do not add a skipped test.

## Done criteria

- [ ] Every error return after a successful `http_lane_prepare` calls `http_lane_close`
- [ ] The successful open does not call `http_lane_close`
- [ ] A full `closed_tunnels` array sets `lane.reusable = false`
- [ ] `odin check src -no-entry-point` exits 0
- [ ] Existing internal HTTP/2 WebSocket tests pass
- [ ] `plans/README.md` status row updated

## STOP conditions

- `http_lane_close` on a reused lane would skip the close when other streams are active, and you cannot tell whether any other stream is active. Close anyway, matching multiplex, unless the procedure's own comment says a shared lane must stay up. Then stop and report the comment.
- The open procedure has already been changed to close these paths. Report that the plan is done.
- You would need to edit `src/http2.odin` to make `http_lane_close` safe. Stop.

## Maintenance notes

- A failed open now drops a pooled HTTP/2 connection that was reused for the attempt. The next request to that origin dials again. That matches boot failure in `http_client_multiplex`.
- Plan 021 edits `h2_tunnel_stream_error` in this file. It does not need to touch the open procedure if this plan is done first.
