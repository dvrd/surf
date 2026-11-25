# Plan 024: A redirect hop does not copy the request body

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat a552088..HEAD -- src/async/session.odin src/async/redirect.odin src/async/client.odin src/async/coordinator.odin`
> Plan 016 and plan 018 may have edited `session.odin`. Stop if `request_clone` or `redirect_prepare`'s clone call no longer matches the excerpts.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED
- **Depends on**: plans/018-address-policy-set.md
- **Category**: perf
- **Planned at**: commit `a552088`, 2026-11-25
- **Executor**: `claude:opus` — the body has to move between owners; an alias of a freed slab is a use-after-free
- **Fallback executor**: `codex`

## Why this matters

`redirect_prepare` calls `request_clone` for the next hop (`src/async/redirect.odin:1030`). `request_clone` copies `request.body` into a new slab (`src/async/session.odin:1536`). Non-GET redirects that resend a body are 307 and 308. The body bytes do not change. The cap is 64 MiB and five hops, so one large POST can be copied five extra times. 301, 302, and 303 do not need that copy when the next request's body is empty.

`Request_Owner` says every body byte points into `storage`, and no caller slice remains borrowed (`src/async/client.odin:178`). Aliasing the caller's slice is not allowed. The first clone, from `coordinator.odin:2083`, must still copy the caller's body once.

## Current state

```odin
Request_Owner :: struct {
	request:   http.Request,
	storage:   []byte,
	allocator: mem.Allocator,
}
```

The comment above it says the body points into `storage`. `request_owner_destroy` frees that one slab (`session.odin:1541`).

`request_clone` adds `len(request.body)` to the grant, then:

```odin
n = copy(storage[at:], request.body)
result.request.body = storage[at:at + n]
```

`redirect_prepare` sets `next := current` and `next.url = url`, then `request_clone(next, allocator)`. On failure the defer destroys `input`. On success `input` is the clone and the old owner is the caller's. `current` came from `session_borrow` (`redirect.odin:99`). Its body lives in the admission request's `Request_Owner`.

`request_clone` has two callers: `coordinator.odin:2083` and `redirect.odin:1030`.

Conventions in `AGENTS.md`: one blank line after a closing brace before the next statement. No blank line before `else`. Disposal `defer` stays on the line after the allocation check. Tabs. One statement per line. Omit an import name that repeats the last element of the path. Do not reformat `session_policy_gate` or the DNS bank. Do not push. Do not edit `shared:async/http`.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Redirect tests | `ODIN=$HOME/dev/oss/Odin/odin PACKAGE=async INTERNAL=1 task test -- -define:ODIN_TEST_THREADS=1` | exit 0 |

## Scope

**In scope**:

- `src/async/client.odin` — `Request_Owner` only if a second owned buffer is required
- `src/async/session.odin` — `request_clone` and `request_owner_destroy`
- `src/async/redirect.odin` — the clone at the hop
- `src/async/coordinator.odin` — the call at line 2083 only if the signature gains a parameter
- `tests/async/internal/redirect_prepare_test.odin` and `ownership_test.odin` if they assert one slab or a copied body

**Out of scope**:

- Blocking `execute` redirects in `src/http.odin`. Those open a new connection and may keep their copy.
- The streamed identity-body copy in plan 005
- Changing which statuses follow, or header stripping in `execute_redirect`
- Aliasing a `[]byte` the caller still owns

## Git workflow

- Branch: `advisor/024-redirect-body-move`
- Commit: `fix: move the request body across a redirect hop`
- Do not push.

## Steps

### Step 1: Give the owner a body buffer it can hand off

Add `body_storage: []byte` to `Request_Owner`. Nil means the body still lives inside `storage`, which is today's layout.

`request_owner_destroy` frees `storage` as it does now. If `len(body_storage) > 0`, free `body_storage` with the same allocator and the alignment `request_clone` used. Do not free it when its `raw_data` is inside `storage`. That would double-free the old layout.

`request_clone` keeps copying the body for the coordinator call. Put that copy in `body_storage` (its own `kernel_grant`) and point `request.body` at it. Header and URL bytes stay in `storage`. The coordinator still copies once from the caller. That satisfies "no borrowed caller slice."

Add `request_clone_move_body(request, allocator, body: []byte) -> (Request_Owner, Client_Error)`. It clones URL and headers the same way and does not copy `body`. It sets `result.body_storage = body` and `result.request.body = body`. The caller must not free `body` afterward. Reject when `raw_data(body) != raw_data(request.body)` or the lengths differ, with `.Invalid_Config`. An empty body uses `request_clone` and leaves `body_storage` nil.

**Verify**: `odin check src/async -collection:shared:$HOME/dev/oss/Odin/shared -no-entry-point` exits 0.

### Step 2: The redirect hop moves the body

In `redirect_prepare`, after `next.url = url`:

- If `len(next.body) == 0`, call `request_clone` as today (no body copy of consequence).
- If `len(next.body) > 0`, the status is 307 or 308 (the earlier status check already limited the procedure to 301–308; 301/302/303 should already have an empty body after `execute_redirect` — read that result). When the body is non-empty, take the `Request_Owner` that `session_borrow` reads. Move its `body_storage` into `request_clone_move_body` and set the old owner's `body_storage` to nil and its `request.body` to nil before any destroy of that owner. If the body still lives inside `storage` rather than `body_storage` (a clone from before this plan, or the coordinator clone if you left the body inside `storage`), do not slice `storage` and free the header part. Copy once in that case. The steady state after step 1 is that new clones put the body in `body_storage`, so the hop moves it.

Do not destroy the old owner while the new owner aliases its `storage`. The move is a pointer transfer. Exactly one owner frees `body_storage`.

**Verify**: async private tests exit 0. Fix ownership tests that assumed a single slab by expecting `body_storage` to hold the body and `storage` to hold the URL.

### Step 3: A test that the hop does not allocate a second body

In `tests/async/internal/redirect_prepare_test.odin`, build a 307 with a body of at least 64 bytes owned by a `Request_Owner` whose `body_storage` is that body. After a successful prepare, the handoff's input `request.body` has the same `raw_data` as the original `body_storage`, and the original owner's `body_storage` is nil. A 302 with an empty body still succeeds and has an empty body. A failure path still frees both buffers: the ownership test's existing leak detector must stay green.

**Verify**: `PACKAGE=async INTERNAL=1 task test` exits 0.

## Test plan

- 307 moves the pointer. One free at the end, no double-free.
- 302 with an empty body does not require `body_storage`.
- Coordinator submit still copies the caller's slice. The caller can mutate its buffer after submit without changing the in-flight body. `tests/async/internal/ownership_test.odin` is the pattern if it already checks that.
- Existing redirect method, origin, and hop-limit tests stay green.

## Done criteria

- [ ] `request_clone_move_body` does not `copy` the body
- [ ] 307/308 redirect of an owned `body_storage` keeps `raw_data(request.body)`
- [ ] The old owner does not free that buffer
- [ ] `request_owner_destroy` frees `body_storage` exactly once when it is set
- [ ] The coordinator path still copies the caller slice once
- [ ] Async private tests pass
- [ ] `plans/README.md` status row updated

## STOP conditions

- `session_borrow` does not expose the `Request_Owner`, and there is no locked way to reach `requests[slot].input`. Stop and report. Do not stash the body in a global.
- 301/302/303 still carry the original body after `execute_redirect`. Then they must move it too, or you must show the body is replaced with an empty slice before `request_clone`. Do not copy a body the next method will not send.
- A test detects a leak or a double-free you cannot explain by one owner. Stop. Do not leak the old slab to make the test pass.

## Maintenance notes

- Plan 005 is a different extra copy, on the streamed identity body inside the exchange. Do not remove that copy here.
- Reviewers should check failure paths in `redirect_prepare`: the defer destroys `input` only when `success` is false, and a moved `body_storage` is either on `input` or still on the old owner, never on both and never on neither.
