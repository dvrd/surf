# Plan 016: An empty async DNS ID bank is a DNS failure, not a timeout

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat a552088..HEAD -- src/async/pool.odin src/async/coordinator.odin src/async/session.odin`
> Stop if `network_dns_reserve`, `network_dns_burn`, or `network_dns_refill` no longer matches the excerpts.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: plans/009-step-import.md
- **Category**: bug
- **Planned at**: commit `a552088`, 2026-11-25
- **Executor**: `claude:opus` — ID-bank lifetime and the coordinator scan; a wrong change deadlocks admission or hides DNS failures
- **Fallback executor**: `codex`

## Why this matters

The default bank is 256 IDs (`DEFAULT_CAPACITIES` in `src/async/client.odin`). `network_prepare` fills it once with `runtime_async.prepare_dns_ids`. `network_dns_burn` counts the draw and does not return the IDs. `network_dns_refill` is called only from tests. Each lookup takes up to 16 IDs (`DNS_IDS_PER_QUERY`), and an A-then-AAAA lookup takes 32. After the bank is empty, `network_dns_reserve` returns `.Pending`. Admission still queues the request as `Awaiting_DNS_IDs` at the origin head. The coordinator leaves it there (`coordinator.odin` returns false on a reserve error) until the request deadline, then completes it as `.Deadline_Failed`. Later requests for that origin wait behind it. Idle reuse and IP literals still proceed. A client built with `dns_ids == 0` is `Numeric_Only` and must stay that way.

`prepare_dns_ids` returns `Current_Worker_Active` when called on the worker, so the coordinator cannot refill itself.

## Current state

`network_dns_reserve` (`src/async/pool.odin:522`): under `s.mu`, `dns_count == 0` returns `{kind = .Pending}`. Otherwise it pops up to `maximum` IDs and decrements `dns_count`.

`network_dns_burn` (`pool.odin:560`): clears the block and adds to `dns_draws_burned`. It does not push IDs back. Keep that. The comment says used IDs must not re-enter the bank.

`network_dns_refill` (`pool.odin:472`): appends caller-supplied IDs and wakes the coordinator.

Admission (`pool.odin` around 1004):

```odin
reserved, error := network_dns_reserve(s, min(DNS_IDS_PER_QUERY, total_queries_remaining))

if error.kind != .None && error.kind != .Pending {
	return {}, error
}
```

`.Pending` falls through. `metadata.awaiting_ids` becomes true when DNS is required and the block is empty (`pool.odin:1043`). `network_queue_committed_locked` sets `request.stage = .Awaiting_DNS_IDs`.

`pool_head_locked` will not dispatch that head unless `allow_waiting_dns` is set. Idle reuse passes true (`pool.odin:1265`). A new dial does not.

`network_coordinator_request_step` (`coordinator.odin:128`): a queued request whose deadline has passed is completed as `.Deadline_Failed`. The reserve attempt around line 243 returns false on any error, including `.Pending`, and does not complete the head.

`session_dns_block` (`session.odin:1156`) returns false when `network_dns_reserve` fails. `session_dial_unresolved` then reports the original A error instead of the failed AAAA draw.

Tests that observe `.Awaiting_DNS_IDs` and then call `network_dns_refill`:

- `tests/async/internal/coordinator_test.odin` around lines 403, 541, and 682
- `tests/async/internal/redirect_queue_test.odin` around line 314
- `tests/async/internal/dns_bank_test.odin` expects `.Pending` from `network_dns_reserve` on an empty bank

`dns_ids == 0` selects `Numeric_Only` (`pool.odin:806`). That path does not draw IDs.

Conventions in `AGENTS.md`: one blank line after a closing brace before the next statement. No blank line before `else`. Disposal `defer` stays attached to its check. Tabs. One statement per line. Omit an import name that repeats the last element of the path. Do not reformat whole procedures. Do not push. Do not edit `shared:async` or the Odin core. Do not return burned IDs to the bank.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Async private | `ODIN=$HOME/dev/oss/Odin/odin PACKAGE=async INTERNAL=1 task test -- -define:ODIN_TEST_THREADS=1` | exit 0 |

## Scope

**In scope**:

- `src/async/pool.odin`
- `src/async/coordinator.odin`
- `src/async/session.odin` — the AAAA draw failure only
- The three test files named above, and any other async test whose assertion breaks because an empty bank no longer waits out the deadline

**Out of scope**:

- `network_snapshot_error` (plan 017). It is in `coordinator.odin`. Do not restyle it.
- Address-policy family checks (plan 018)
- Changing `DNS_IDS_PER_QUERY`, the default 256, or `Numeric_Only`
- A background refill thread

## Git workflow

- Branch: `advisor/016-dns-id-bank`
- Commit: `fix: fail a hostname when the DNS ID bank is empty`
- Do not push.

## Steps

### Step 1: Refill from the caller once, then fail closed

Add `network_dns_refill_fresh` next to `network_dns_refill`. It allocates no heap. It fills a stack array of `DNS_IDS_PER_QUERY` `u16` values by calling `runtime_async.prepare_dns_ids` on that array, then `network_dns_refill`. If `prepare_dns_ids` returns `Current_Worker_Active` or any other error, return that `runtime_async.Error` and do not call refill.

On the admission path, when `network_dns_reserve` returns `.Pending`:

- Call `network_dns_refill_fresh` once.
- Reserve again.
- If the second reserve is `.Pending`, or the fresh refill could not run, return `{kind = .Capacity, http = {kind = .Dial_Failed, phase = .DNS, network = net.Resolve_Error.Unable_To_Resolve, write_effect = .Not_Sent}}`. Do not set `awaiting_ids`. Do not queue the head.

If the first reserve succeeds, do not refill.

`network_dns_reserve` itself still returns `.Pending` on an empty bank. `dns_bank_test.odin` asserts that. Leave the procedure's return value alone.

### Step 2: The coordinator does not turn an empty bank into a deadline

In the coordinator scan that tries `network_dns_reserve` for an `Awaiting_DNS_IDs` head: on `.Pending`, try `network_dns_refill_fresh` once if the runtime error is not `Current_Worker_Active`. If the bank is still empty, or refill reports `Current_Worker_Active`, complete that queued head with the same dial error as step 1 (`.Dial_Failed`, phase `.DNS`, `Resolve_Error.Unable_To_Resolve`, `.Not_Sent`). Do not leave it queued for `network_coordinator_request_step` to complete as `.Deadline_Failed`.

A head that already has IDs is unchanged.

Update `coordinator_test.odin` and `redirect_queue_test.odin` where they expect a head to stay `.Awaiting_DNS_IDs` after the coordinator has run against an empty bank. A test that refills before the coordinator runs may still observe the waiter. A test that runs the coordinator with an empty bank must now observe the dial error. Do not delete coverage of `network_dns_refill` unparking a head that was queued before the refill. If step 1 means production no longer queues that head, keep one test that calls the lower-level queue helper, refills, and sees the head leave `.Awaiting_DNS_IDs`. Read the test before deciding which assertion moves.

### Step 3: An AAAA draw that cannot get IDs reports that failure

`session_dial_unresolved` calls `session_dns_block` before starting AAAA. When `session_dns_block` returns false because `network_dns_reserve` failed, set the cause to the dial error from step 1 instead of the previous A error, then `session_error` with that cause. Do this only for the reserve failure. A timeout or cancel on the A query still uses `session_dns_error` of that A error.

`session_dns_block` must tell the caller why it returned false. Returning a `Client_Error` or a bool plus an error is fine. Do not report `Unable_To_Resolve` when the remaining query budget is zero. That path already means the allowance is spent (`pool.odin` comment at line 988). Keep the budget-zero rejection as it is.

**Verify**: `PACKAGE=async INTERNAL=1 task test` exits 0.

## Test plan

- `dns_bank_test.odin` still expects `.Pending` from a direct `network_dns_reserve` on an empty bank, and still expects `network_dns_refill` to make a later reserve succeed.
- Add one admission test, in `tests/async/internal/dns_bank_test.odin` or `coordinator_test.odin`, that empties the bank, submits a hostname, and expects `.Dial_Failed` / phase `.DNS` / `Unable_To_Resolve` without waiting for the request deadline. Use a deadline long enough that a bug which still waits would fail the test's own time bound (a couple of seconds). An IP literal in the same client still succeeds.
- `session` AAAA: if an existing test fails a name with only an A error while the bank is empty, update it to the bank error.

## Done criteria

- [ ] Burned IDs are not pushed back onto the bank
- [ ] `dns_ids == 0` still means `Numeric_Only` and does not draw
- [ ] A hostname admission against an empty bank returns `.Dial_Failed` / `.DNS` / `Unable_To_Resolve` after one refill attempt
- [ ] The coordinator does not complete that head as `.Deadline_Failed`
- [ ] An AAAA fallback that cannot draw IDs does not report the stale A error
- [ ] `PACKAGE=async INTERNAL=1 task test` exits 0
- [ ] `plans/README.md` status row updated

## STOP conditions

- `prepare_dns_ids` cannot be called off the worker either. Stop and report the error. Do not add a thread.
- Failing closed breaks a test that is the supported way a caller refills the bank through a public `Client` API. If that public API exists and is documented on `Client`, keep the waiter only for that API and say so. A test-only `network_dns_refill` is not a public API.
- The fix seems to require editing `shared:async` `prepare_dns_ids`.

## Maintenance notes

- Plan 017 edits `network_snapshot_error` in `coordinator.odin`. Stay out of that procedure.
- Plan 018 edits `session_policy_gate` in `session.odin`. Stay out of it except the AAAA-draw error in `session_dial_unresolved`.
- A long-lived client can now resolve more than 256 names because admission refills. IDs still are not reused while a query holds them. Reviewers should check that refill uses fresh `prepare_dns_ids` output and not `dns_draws_burned` values.
