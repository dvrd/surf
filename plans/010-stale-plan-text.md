# Plan 010: Plans 001 and 008 no longer contradict `a552088`

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat a552088..HEAD -- plans/001-tls-net-errors.md plans/008-async-http.md src/http.odin src/http3.odin`
> On a mismatch in `src/http3.odin` around the credential fields, stop. A banner already at the top of 001 or 008 is expected.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: docs
- **Planned at**: commit `a552088`, 2026-11-25
- **Executor**: `claude:haiku` — replace contradicted sentences with the text in this plan
- **Fallback executor**: `grok:fast`

## Why this matters

`plans/001-tls-net-errors.md` and `plans/008-async-http.md` still tell an executor to keep `Config.tls` on core TLS and to leave HTTP/3 client credentials nil. Commit `a552088` did the opposite, and that is the code that type-checks. An executor who honors those STOP conditions will revert a working port. This plan rewrites the prose. It does not change `src/`.

## Current state

`src/http.odin` imports `shared:async/tls`. `Config.tls` is that package's `Config`.

`src/http3.odin` builds the wire request like this:

```odin
wire := http3.Client_Request {
	cancel                  = config._http3_cancel,
	cancel_data             = config._http3_cancel_data,
	session_cache           = config.tls.session_cache,
	qpack                   = config.http3_qpack,
	ecn                     = config.http3_ecn,
	client_credentials      = config.tls.client_credentials,
	client_credential_lease = config.tls.client_credential_lease,
```

`plans/008-async-http.md` done criteria still require all three of these to be false:

- `Config.tls` is still `core:crypto/tls.Config`
- `src/http3.odin` does not read `session_cache`, `client_credentials`, or `client_credential_lease`
- `src/http.odin` still imports `core:mem/owned`, `core:mem/budget`, and `core:sync/budget`

Its maintenance note says HTTP/3 client certificates and session resumption are no longer forwarded. Its STOP says not to switch `Config.tls` to `shared:async/tls`.

`plans/001-tls-net-errors.md` says: do not assign `config.tls.client_credentials` or `config.tls.session_cache` into an HTTP/3 `Client_Request`, and do not switch `Config.tls`. It also says to stop if `tls_dial` is already gone and the tree type-checks. `tls_dial` is gone. The library type-checks once plan 009 lands. Gates, `tests/testdata/`, and `tests/stream104/` still use `Connection_Error` callback results and TLS `.kind` checks. That residue stays in scope for 001.

Both files already have a STALE banner at the top. Keep one banner. Do not add a second.

`plans/README.md` is maintained with these plans. If its 001 and 008 rows already say the code landed, do not invent a different status. After this plan, 008 is DONE and 001 stays blocked on the gate residue plus plan 009.

Conventions: this plan edits Markdown only. Do not reformat `src/`. Do not push. Commit style: `docs: record the async TLS port in plans 001 and 008`.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| No contradicted requirement | `rg -n 'still \`core:crypto/tls|leaves those fields nil|no longer forwarded|Do not switch \`Config.tls\`' plans/001-tls-net-errors.md plans/008-async-http.md` | exit 1, no matches |
| Credentials still forwarded | `rg -n 'client_credentials' src/http3.odin` | a match on the `Client_Request` field |

## Scope

**In scope**:

- `plans/001-tls-net-errors.md`
- `plans/008-async-http.md`
- `plans/README.md` (status rows only, if they still say 008 is TODO or that 001 must not switch `Config.tls`)

**Out of scope**:

- Every file under `src/`, `tests/`, and `tools/`.
- Plans 002 through 007, except a one-line note in 001 that 004 still depends on the gate port.
- Rewriting 001 into a finished gate plan. Leave the gate steps. Delete only the sentences that forbid the TLS switch.

## Git workflow

- Branch: `advisor/010-stale-plan-text`
- One commit: `docs: record the async TLS port in plans 001 and 008`
- Do not push.

## Steps

### Step 1: Close plan 008

Replace the done criteria, STOP conditions, and maintenance note that forbid `shared:async/tls` or claim credentials are not forwarded. The replacement facts are:

- Status of the work: done at `a552088`. An executor must not revert `src/`.
- `Config.tls` is `shared:async/tls.Config`.
- `src/http3.odin` forwards `session_cache`, `client_credentials`, and `client_credential_lease`. That forwarding stays.
- `src/http.odin` imports `shared:async/mem/owned`, `shared:async/mem/budget`, and `shared:async/sync/budget`. It does not import `core:mem/owned`, `core:mem/budget`, or `core:sync/budget`.
- Keep the historical steps below the banner so a reader can see what landed. Mark them done in prose. Delete any instruction to undo them.

Keep the single STALE banner, and change its last sentence so it says the contradiction has been removed and the plan must not be re-executed.

**Verify**: the search in the command table finds none of those phrases in `plans/008-async-http.md`.

### Step 2: Narrow plan 001 to the gate residue

Delete the sentences that say:

- do not switch `Config.tls` to `shared:async/tls`
- do not assign `client_credentials` or `session_cache` onto an HTTP/3 `Client_Request`
- 008 leaves those pointers nil
- stop when `tls_dial` is gone

Replace them with:

- The library port landed at `a552088`. Do not revert `src/` to core TLS, `tls_dial`, or `Connection_Error` callback results.
- Remaining files are under `tests/gates/`, `tests/testdata/`, and `tests/stream104/`. They still pass `.kind` on `tls.Error` and return `net.Connection_Error` from callbacks whose result is `net.Network_Error`.
- Do not start that residue until plan 009 is done. `task test` is not the gate command. The gate programs build with `odin build tests/testdata/<name>`.
- Plan 004 still owns the shared gate build helper. 001 owns the type errors in those programs.

Keep the single STALE banner, and change it so it says the forbidden STOP text is gone and the remaining work is the gate residue after plan 009.

**Verify**: `rg -n 'tls_dial|leaves those fields nil|Do not switch' plans/001-tls-net-errors.md` prints nothing.

### Step 3: Point the index at the revised prose

In `plans/README.md`, plan 008 is DONE at `a552088`. Plan 001 is BLOCKED on the gate and testdata residue, and that residue depends on 009. Remove any dependency note that says 001 must not switch `Config.tls` or must leave HTTP/3 credentials nil.

**Verify**: `rg -n 'leaves those pointers nil|must not switch' plans/README.md` prints nothing.

## Test plan

- No code test. The verification commands are the searches above.
- `git diff --stat -- src tests tools` prints nothing.

## Done criteria

- [ ] `plans/008-async-http.md` says the import and the credential forwarding landed, and tells the reader not to revert them
- [ ] `plans/001-tls-net-errors.md` no longer forbids `shared:async/tls` or nil HTTP/3 credentials, and its remaining scope is gates, testdata, and `tests/stream104`
- [ ] Each of those files has one STALE banner, not two
- [ ] `plans/README.md` shows 008 DONE and 001 blocked on the residue
- [ ] `git diff --stat -- src tests tools` is empty
- [ ] `plans/README.md` status row for 010 updated

## STOP conditions

- `src/http3.odin` does not forward `client_credentials`. Stop and report. Do not "restore" the old nil behavior.
- Editing the plan seems to require changing `src/`. Stop.
- The gate residue was already ported and those programs type-check. Report that 001 is done instead of inventing new gate work.

## Maintenance notes

- Plan 006 still deletes the standalone `http` pin after a green `task test`. That instruction stays.
- A later audit must not re-file "HTTP/3 dropped client certificates" as a bug. The forward is intentional.
