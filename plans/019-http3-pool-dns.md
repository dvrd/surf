# Plan 019: A live HTTP/3 lane does not resolve again

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat a552088..HEAD -- src/http3.odin`
> Plans 014 and 018 edit this file. Stop if `execute_http3` no longer resolves before `pool_exchange_request`, or if plan 018's full-set check is missing.

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: MED
- **Depends on**: plans/014-http3-deadline-error.md, plans/018-address-policy-set.md
- **Category**: perf
- **Planned at**: commit `a552088`, 2026-11-25
- **Executor**: `claude:sonnet` — a reuse check in front of resolve, with a fallback dial if the lane died
- **Fallback executor**: `codex`

## Why this matters

`execute_http3` always calls `http3_resolve` before `pool_exchange_request`. `pool_pick` matches origin, port, QPACK, ECN, credentials, and root identity. It does not match the resolved IP (`shared:async/http/v3/client.odin` `pool_pick`). A pooled call pays a full lookup even when the QUIC lane is reused. A new dial must still resolve and run `address_policy_check` on the full set from plan 018.

## Current state

`execute_http3` resolves, checks one endpoint (plan 018 changes that to the full set), then:

```odin
if config.http3_pool != nil {
	result = http3.pool_exchange_request(
		config.http3_pool,
		endpoint,
		url.host,
		wire,
		config.tls.root_cas,
		deadline,
	)
}
```

`pool_exchange_request` rejects `address.port <= 0` before admit. On a reuse hit, `client_exchange` does not call `client_start` (`client.odin` `if !reuse`). The IP is unused on that branch. A placeholder IP is safe only when admit also reports reuse. A race can retire the lane after a pick and dial the placeholder. That race is why this plan retries a real resolve once.

`pool_pick` is in package `http3` (the import in `src/http3.odin` is `h3` or `http3`; read the import and call that name). It is callable from surf. Odin does not hide lowercase names across packages.

Do not edit `/Users/kakurega/dev/projects/async`.

The comment above the pool call already says a pooled lane is not checked again. Keep that for the reuse hit. A new dial still checks the full set.

Conventions in `AGENTS.md`: one blank line after a closing brace before the next statement. Tabs. One statement per line. Omit an import name that repeats the last element of the path. Do not reformat `http3_map_error`. Do not push.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Check | `ODIN=$HOME/dev/oss/Odin/odin "$ODIN" check src -collection:shared:$HOME/dev/oss/Odin/shared -no-entry-point` | exit 0 |
| HTTP/3 tests | `ODIN=$HOME/dev/oss/Odin/odin PACKAGE=. INTERNAL=1 task test -- -define:ODIN_TEST_THREADS=1` | exit 0. If that runs more than the internal surf package, it is still the right gate. A failure outside HTTP/3 that this plan did not cause is a stop. |

## Scope

**In scope**:

- `src/http3.odin` — `execute_http3` only
- An existing HTTP/3 pool test under `tests/internal/` if one counts resolver calls. Otherwise a small test that a second request on a live lane does not call the stub resolver.

**Out of scope**:

- `shared:async/http/v3` `pool_pick` / `pool_admit`
- Address-policy ranges and the full-set rule (plan 018). Call the helper plan 018 left behind.
- The half-budget and `http3_map_error` (plan 014)
- Async TCP pool DNS. It already skips lookup for an idle connection.

## Git workflow

- Branch: `advisor/019-http3-pool-dns`
- Commit: `fix: skip DNS when an HTTP/3 lane is already live`
- Do not push.

## Steps

### Step 1: Pick before resolve

When `config.http3_pool != nil`:

- Compute the port with `http3_dial_port` as today.
- Call `pool_pick` with that port, `url.host`, and the same QPACK, ECN, credential, generation, and root-identity inputs `pool_admit` passes. Read `pool_admit` (`shared:async/http/v3/client.odin` around line 431) and copy the key. Do not reimplement matching.
- If `pool_pick` returns `reuse == false`, resolve, run the plan 018 policy check on the full set, and call `pool_exchange_request` with `items[0]`.
- If `reuse == true`, call `pool_exchange_request` with an endpoint whose port is that port and whose address is `net.IP4_Address{0, 0, 0, 0}`. Do not resolve. Do not run the policy.
- If that call returns an error and `result.sent` is false, the lane died. Resolve and policy-check for real, then call `pool_exchange_request` once more with `items[0]`. Do not loop. If `result.sent` is true, return that error through `http3_map_error`.

When `config.http3_pool` is nil, keep today's resolve-then-`client_exchange_request` path, including the full-set policy check.

**Verify**: `odin check` exits 0. A comment at the placeholder says the zero address is used only because the reuse branch does not dial it.

### Step 2: A test that the second call does not resolve

Use the HTTP/3 pool fixture in `tests/internal/http3_policy_test.odin` or `http3_request_test.odin`. If the stub resolver counts lookups, expect the second exchange on the same origin to leave the count unchanged. If there is no counter, add one on the test resolver only. A new dial (empty pool) still increments it and still refuses `127.0.0.1` before a datagram.

**Verify**: internal surf tests exit 0.

## Test plan

- Reuse hit: lookup count stays 0 or stays at the first dial's count.
- Empty pool: one lookup, policy still applied, including the two-address refusal from plan 018.
- No test dials the placeholder as a successful new connection. If you can force the lane to die between pick and admit, expect the fallback lookup. If you cannot force it, the fallback code still has to be there.

## Done criteria

- [ ] A `pool_pick` reuse hit does not call `http3_resolve`
- [ ] A miss still resolves and runs `address_policy_check` on the full set
- [ ] A failed reuse attempt with `sent == false` resolves once and exchanges once more
- [ ] `http3_map_error` is unchanged
- [ ] `plans/README.md` status row updated

## STOP conditions

- `client_exchange` or `pool_admit` reads `address.address` on the reuse path. Do not pass the placeholder. Stop and report the line.
- `pool_pick` is not callable from surf. Stop. Do not copy the matching loop into surf.
- Plan 018's full-set check is not in the file yet. Stop and do 018 first.

## Maintenance notes

- The zero address must not leak into a new dial. Reviewers should check there is no `client_exchange_request` of the placeholder.
- A custom resolver with no cache is the case this saves. The platform resolver may already cache. The skip is still correct.
