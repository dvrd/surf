# Plan 014: An HTTP/3 budget expiry stays a deadline

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat a552088..HEAD -- src/http3.odin src/http.odin`
> Stop if `http3_map_error` or the fallback in `execute_internal` no longer matches the excerpts.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: LOW
- **Depends on**: plans/009-step-import.md
- **Category**: bug
- **Planned at**: commit `a552088`, 2026-11-25
- **Executor**: `claude:sonnet` — one error mapping, with the existing fallback left in place
- **Fallback executor**: `codex`

## Why this matters

`execute_http3` spends half of the remaining caller deadline on HTTP/3, with a 50ms floor. `http3_map_error` returns `.Deadline_Failed` only when that total deadline has also passed. Any earlier `Client_Result.error == .Deadline` falls through to `.IO_Failed` / `.Protocol`. A POST, PUT, or upload that already left the client then looks like a protocol failure. `execute_internal` will not rewrite the error once `write_effect != .Not_Sent`, and it will not replay that request on TCP. GET and HEAD that have not been sent still fall back. Deadline handling never sees `.Deadline_Failed` for the methods that must not be replayed.

## Current state

`execute_http3` (`src/http3.odin`):

```odin
remain := time.diff(time.now(), total_deadline)
if remain <= 0 {
	return {}, {kind = .Deadline_Failed, phase = .Deadline, write_effect = .Not_Sent}
}
budget := remain / 2
if budget < 50 * time.Millisecond && remain >= 100 * time.Millisecond {
	budget = 50 * time.Millisecond
}
```

`http3_map_error`:

```odin
effect := HTTP_Write_Effect.Not_Sent
if result.sent {
	effect = .Unknown
}

if result.error == .Deadline && time.diff(time.now(), total_deadline) <= 0 {
	return {kind = .Deadline_Failed, phase = .Deadline, write_effect = effect}
}
```

The final line of the procedure is:

```odin
return {kind = .IO_Failed, phase = .Protocol, write_effect = effect}
```

`execute_internal` (`src/http.odin` around line 266) returns a cancellation as-is, rewrites the error to `.Deadline_Failed` only when the total deadline has passed, and returns immediately when `err.write_effect != .Not_Sent`. Unsent GET and HEAD may fall back to TCP. Do not change that fallback.

`tests/outcomes_test.odin` locks the blocking classifier: a dial timeout is `.Dial_Failed` with phase `.Deadline`. Do not change `http_error_classify` in this plan.

Conventions in `AGENTS.md`: one blank line after a closing brace before the next statement. No blank line before `else`. Tabs. One statement per line. Omit an import name that repeats the last element of the path. Do not reformat `http3_map_error` beyond the branch you change. Do not push. Do not edit `shared:async/http`.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Check | `ODIN=$HOME/dev/oss/Odin/odin "$ODIN" check src -collection:shared:$HOME/dev/oss/Odin/shared -no-entry-point` | exit 0 |
| Outcomes | `ODIN=$HOME/dev/oss/Odin/odin PACKAGE=. task test -- -define:ODIN_TEST_THREADS=1` | exit 0 for the public suite. If the full public suite is too broad, `rg -n '@\\(test\\)' tests/outcomes_test.odin` and pass those exact names in `ODIN_TEST_NAMES` |

Package `tests` is the public owner `.`. `INTERNAL` stays unset so the public files run. `tools/test` also overlays `tests/internal` onto that package. Both compile together.

## Scope

**In scope**:

- `src/http3.odin` — `http3_map_error` only
- `tests/internal/http3_request_test.odin` — extend an existing deadline test if one already expects `.IO_Failed` for a short HTTP/3 budget. If none does, add one procedure.

**Out of scope**:

- The half-budget split itself. Keep it.
- `execute_internal` fallback rules
- `http_error_classify` and `tests/outcomes_test.odin`
- Async DNS errors (plan 016) and HTTP/2 phases (plan 021)
- Skipping DNS on pool reuse (plan 019)

## Git workflow

- Branch: `advisor/014-http3-deadline-error`
- Commit: `fix: report an HTTP/3 budget expiry as a deadline`
- Do not push.

## Steps

### Step 1: Map `.Deadline` before the protocol fallback

In `http3_map_error`, when `result.error == .Deadline`, return `.Deadline_Failed`, phase `.Deadline`, and the `effect` already computed from `result.sent`. Do this whether or not `total_deadline` has passed.

Leave the total-deadline check in `execute_http3` that returns `.Deadline_Failed` before any work. Leave every other `result.error` arm as it is, including `.Certificate`, `.Cancelled`, and `.Body_Limit`.

**Verify**: `rg -n 'result.error == .Deadline' src/http3.odin` shows one arm, and that arm does not also require `time.diff(...) <= 0`.

### Step 2: Keep unsent GET and HEAD able to fall back

Read `execute_internal` after your edit. An HTTP/3 `.Deadline_Failed` with `write_effect == .Not_Sent` may still be rewritten or followed by the TCP fallback. Do not special-case it. An error with `write_effect == .Unknown` because `result.sent` is true must remain `.Deadline_Failed` and must not fall back.

If a test asserts `.IO_Failed` or `.Protocol` for an HTTP/3 deadline that fired before the total deadline, update the assertion to `.Deadline_Failed` and phase `.Deadline`. Do not weaken a test that expects fallback of an unsent GET.

**Verify**: `odin check` exits 0. The outcomes suite, or the named outcome procedures, exits 0.

## Test plan

- Find the HTTP/3 test that uses a short timeout (`tests/internal/http3_request_test.odin` around the 500ms client / slow upload). If it expects a protocol error for a deadline, change it to `.Deadline_Failed` / `.Deadline`.
- If no test covers a sent request that hits the half-budget, add one only when the in-process HTTP/3 listener in that file can stall after the request is sent. Expect `.Deadline_Failed`, not `.Protocol`, and expect no second TCP dial. If the listener cannot stall after send, do not add a flake. The mapping change and the updated assertion are enough.
- Model assertions on `tests/outcomes_test.odin` (`testing.expect_value` on `kind` and `phase`).

## Done criteria

- [ ] `result.error == .Deadline` maps to `.Deadline_Failed` / `.Deadline` with the existing `write_effect`
- [ ] Other `http3_map_error` arms are unchanged
- [ ] `execute_internal` is unchanged
- [ ] Outcome tests still pass
- [ ] `plans/README.md` status row updated

## STOP conditions

- The half-budget is the only deadline and removing the total-deadline conjunct changes a test you cannot explain. Stop and quote the test.
- You need to change `shared:async/http/v3` `Client_Result` to know that a deadline happened. The `.Deadline` arm already exists.
- A sent POST starts falling back to TCP after your edit. Re-read `execute_internal`. Do not "fix" that by replaying the POST.

## Maintenance notes

- Callers that retried `.Protocol` and refused to retry `.Deadline_Failed` will stop retrying this case. That is the intended distinction.
- Plan 019 also edits `src/http3.odin`. It skips DNS on a pool hit and must not undo this mapping.
