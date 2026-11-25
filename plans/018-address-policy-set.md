# Plan 018: `address_policy` sees every resolved address

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat a552088..HEAD -- src/http3.odin src/async/session.odin src/http.odin`
> Plan 014 may have changed `http3_map_error`. Plan 016 may have changed `session_dial_unresolved`. Stop if `http3_resolve`, `session_policy_gate`, or `address_policy_public_only` no longer matches the excerpts.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: plans/016-dns-id-bank.md
- **Category**: security
- **Planned at**: commit `a552088`, 2026-11-25
- **Executor**: `claude:opus` — DNS-family ordering and a trust boundary; connecting early reopens the gap
- **Fallback executor**: `codex`

## Why this matters

`address_policy_public_only` refuses the whole set when any address is refused (`src/http.odin:1446`). Blocking TCP shows the policy that full set and dials only those addresses (`src/http.odin:1578`). Async HTTP queries A, then maybe AAAA, and `session_policy_gate` shows the policy only the current query's results. A public A is enough to connect, so a non-global AAAA is never shown. HTTP/3 keeps `endpoints.items[0]` and checks that one address. A public first address hides a non-global later one. The dialed address is one the policy saw. The name is still allowed when blocking TCP would refuse it.

A nil policy still allows every address. That is documented on `Config`. Do not change it. `fec0::1`, `64:ff9b:1::/48`, and `203.0.113.1` stay allowed. Do not add ranges.

## Current state

Blocking check (`src/http.odin`):

```odin
if rejected := address_policy_check(config, url.host, endpoints.items[:endpoints.count]);
   rejected.kind != .None {
```

HTTP/3 (`src/http3.odin`):

```odin
return endpoints.items[0], {}
```

and

```odin
if rejected := address_policy_check(config, url.host, []net.Endpoint{endpoint}); rejected.kind != .None {
```

Async (`src/async/session.odin`):

```odin
error := session_query_begin(
	a,
	origin.host,
	int(origin.port),
	.A_Only,
	a.owner.profile.config.http.address_policy == nil,
)
```

The last argument connects inside the DNS call when the policy is nil. Keep that.

`session_policy_gate` (`session.odin:1308`) checks `runtime_async.dns_results` of the current query and then `begin_dns_connect`.

Blocking WebSocket already checks `endpoints.items[:endpoints.count]` (`src/websocket.odin`). Async WebSocket is given one `endpoint` by its caller and checks that one (`src/websocket_async.odin:583`). Do not make async WebSocket resolve.

Pooled reuse is not rechecked. The HTTP/3 comment at `execute_http3` and the HTTP/2 comment in `http_lane_prepare` say so. Leave reuse alone. Plan 019 skips DNS only on a reuse hit after this plan's full-set check exists for a new dial.

Conventions in `AGENTS.md`: one blank line after a closing brace before the next statement. No blank line before `else`. Tabs. One statement per line. Omit an import name that repeats the last element of the path. Do not reformat untouched procedures. Do not push. Do not edit sibling repositories.

Tests that lock today's allow list: `tests/address_policy_dial_test.odin` procedure `address_policy_public_only_refuses_non_global_ranges`. Do not move `203.0.113.1`, `fec0::1`, or `64:ff9b:1::` into the refused list.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Public policy | `ODIN=$HOME/dev/oss/Odin/odin task test -- -define:ODIN_TEST_NAMES=address_policy_public_only_refuses_non_global_ranges,address_policy_rejects_resolved_loopback_before_dial,address_policy_allows_the_checked_address_to_be_dialed -define:ODIN_TEST_THREADS=1` | exit 0 |
| Async policy | `ODIN=$HOME/dev/oss/Odin/odin PACKAGE=async INTERNAL=1 task test -- -define:ODIN_TEST_NAMES=address_policy_never_dials_a_refused_address_beside_an_allowed_one,address_policy_dials_the_address_the_policy_saw -define:ODIN_TEST_THREADS=1` | exit 0 |

If a name is wrong, `rg -n 'address_policy_.* :: proc\\(t:' tests src` and use the exact procedure names. `ODIN_TEST_NAMES` is exact.

## Scope

**In scope**:

- `src/http3.odin` — `http3_resolve` and the single call that checks one endpoint
- `src/async/session.odin` — `session_policy_gate` and the A-then-AAAA transition when a policy is set
- Tests under `tests/address_policy_dial_test.odin`, `tests/internal/`, and `tests/async/internal/address_policy_test.odin` that encode one-address behavior you must change

**Out of scope**:

- `address_policy_public_only`'s range list
- Nil policy, pool-reuse skip, `fec0::`, `64:ff9b:1::/48`
- Blocking WebSocket and async WebSocket
- Plan 019's "skip DNS when the lane is already live"
- `src/http.odin` except reading `address_policy_check`

## Git workflow

- Branch: `advisor/018-address-policy-set`
- Commit: `fix: show address_policy every resolved address`
- Do not push.

## Steps

### Step 1: HTTP/3 checks the full set, then dials the first

`http3_resolve` must return the full `[]net.Endpoint` (or the existing endpoint array and a count), not `items[0]` alone.

`execute_http3` calls `address_policy_check` with that full slice. One refusal returns `.Address_Rejected` and dials nothing. On success, the QUIC dial still uses `items[0]` only. HTTP/3 has one path. Do not dial a second address.

A resolve error or an empty set stays `.Dial_Failed` / phase `.DNS` / `.Not_Sent`.

**Verify**: `rg -n 'endpoints.items\\[0\\]' src/http3.odin` shows the dial selection after the policy check, and the policy check does not use a one-element slice.

### Step 2: Async HTTP waits for both families when a policy is set

When `address_policy != nil`:

- A successful A query must not call `begin_dns_connect` yet.
- Start the AAAA query the same way `session_dial_unresolved` does on A failure.
- When AAAA completes, build one slice of the A results plus the AAAA results. If AAAA has no records, the slice is the A results only. A timeout or cancel on AAAA is still that error, not a silent skip.
- `address_policy_check` sees the combined slice. Any refusal burns the DNS ids, closes the query, and `session_error`s `.Address_Rejected`. No connect.
- On acceptance, connect with the combined results. Use the existing `begin_dns_connect` path if it can take that combined set. If it can only dial the query that just finished, stop and report. Do not connect to the A records alone while an unchecked AAAA exists.

When `address_policy == nil`, keep connecting inside the A query. Do not add an AAAA wait on that path.

**Verify**: `odin check src/async -collection:shared:$HOME/dev/oss/Odin/shared -no-entry-point` exits 0.

### Step 3: Tests for a mixed set

Add or extend tests:

- Blocking TCP already refuses a set that contains `127.0.0.1` beside `1.1.1.1` (`address_policy_dial_test.odin` `mixed`). Leave it.
- Async: a hostname whose A is `1.1.1.1` and whose AAAA is `::1` or `fe80::1` is `.Address_Rejected` and the dial counter stays 0. The existing test `address_policy_never_dials_a_refused_address_beside_an_allowed_one` may already cover one family. Extend it, or add a sibling, so the refused address is in the other family.
- HTTP/3: a resolver result of `[203.0.113.1, 127.0.0.1]` is refused before a datagram. Use the stub resolver the HTTP/3 policy tests already use. Do not query the network. `203.0.113.1` remains allowed when it is the only address.

**Verify**: the commands in the table exit 0, plus the new procedure names.

## Test plan

- Mixed-family async refusal, no dial.
- HTTP/3 two-address refusal, no datagram.
- Existing allow list, including `fec0::1`, `64:ff9b:1::`, and `203.0.113.1`, still passes.
- A nil async policy still dials without waiting for a second family. If a test already covers that, do not duplicate it. If you change the nil path, stop.

## Done criteria

- [ ] HTTP/3 policy check receives every address `http3_resolve` got
- [ ] HTTP/3 dials `items[0]` only after the full set is accepted
- [ ] With a policy set, async HTTP does not connect on A success before AAAA has been included or has returned no records
- [ ] A nil policy still connects from the A query
- [ ] `fec0::1`, `64:ff9b:1::`, and `203.0.113.1` stay allowed
- [ ] `plans/README.md` status row updated

## STOP conditions

- `begin_dns_connect` cannot dial a combined A+AAAA set. Stop and report the signature. Do not connect early.
- The change would refuse `fec0::1`, `64:ff9b:1::/48`, or documentation `203.0.113.1`.
- You would need to edit `shared:async` DNS to gather both families. If the session actor can run the two queries it already runs, stay in `session.odin`.

## Maintenance notes

- Plan 019 may skip resolve when an HTTP/3 lane is already live. A new dial still uses this full-set check.
- Reviewers should look for an A-success path that still calls `begin_dns_connect` while `address_policy != nil`.
