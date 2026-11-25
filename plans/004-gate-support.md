# Plan 004: The seven older gates share one build and one failure path

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: Excerpts are from the working tree on
> 2026-11-24, `HEAD` `6209fc3`. Confirm `support.build` still kills the
> compiler on timeout and that `client101` `build` still does not.
>
> ```
> git diff --stat 6209fc3..HEAD -- tests/gates/client101 tests/gates/exchange101 tests/gates/concurrency101 tests/gates/budgets tests/gates/setup tests/gates/uploads tests/gates/outcomes tests/gates/support
> ```

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED
- **Depends on**: plans/001-tls-net-errors.md
- **Category**: tech-debt
- **Planned at**: commit `6209fc3`, 2026-11-24

## Why this matters

Seven tracked gates each start `odin build` and wait up to 180 seconds.
`tests/gates/support/gate.odin` `build` kills the compiler when the wait
times out. `tests/gates/client101/main.odin` `build` returns false and
leaves that process running. The same no-kill wait is in exchange101,
concurrency101, setup, uploads, and budgets. `setup` and `outcomes` call
`os.exit` from `fail`, and `os.exit` skips `defer`, so a failed run leaves
`/tmp/okami-*` behind. `client101` `object` keeps the span from the last
`{` to the next `}`, so a nested `}` drops the surrounding fields.
`support/json.odin` already unmarshals with `core:encoding/json`.

These gates stay separate `package main` programs. Nothing in this plan
adds them to `task test` or `tools/test`.

## Current state

`support.build` (`tests/gates/support/gate.odin:91`) waits 180 seconds and,
on `wait_error != nil`, calls `os.process_kill` and `os.process_wait` for
2 seconds. `support.fail` (`:75`) calls `end`, which `remove_all`s the temp
dir, and only then `os.exit(1)`. `support.begin` (`:23`) requires `--odin`,
`--shared`, and `--report`, and defaults the sanitizer to `none`. Its
`--sanitize` flag takes the next argument (`address`, `thread`, or `none`).

Flag defaults that must stay:

| Gate | Default sanitizer | Argv |
|---|---|---|
| client101, exchange101, concurrency101 | `none` | `--odin`, `--shared`, `--report`, `--sanitize address\|none` |
| budgets | rejects the token `none`; read `parse_args` before changing it | same three required flags |
| setup | `address` (`tests/gates/setup/main.odin:431`) | same three required flags, usage text says `address\|none` |
| outcomes | boolean `--sanitize`, no value (`tests/gates/outcomes/main.odin:432`) | `--odin` and optional `--sanitize`. No `--shared`, no `--report` |

`client101` `object` (`tests/gates/client101/main.odin:449`) walks backward
to the last `{` and forward to the first `}`. `check` (`:207`) reads
top-level keys `completed`, `tls`, `workers`, and several bool facts.
`support.only` returns one `json.Value`. `int_field`, `bool_field`, and
`is_true` are the replacements.

`outcomes` does not parse a JSON report. Its `fail` is `os.exit(1)` with
no `remove_all`. Its `main` `defer delete(root)` does not run on that exit.
It also `defer`s a directory remove only if one is registered before `fail`.
Read `main` before editing. The temp directory variable is `root`.

Style: tabs, one statement per line, no comment that restates the next
line. Match `tests/gates/support/gate.odin`.

## Commands you will need

Run from the repo root. `ODIN` is `odin` unless the environment says
otherwise. `SHARED` is `$HOME/dev/oss/Odin/shared`.

| Purpose | Command | Expected on success |
|---|---|---|
| Build one gate | `odin build tests/gates/client101 -out:/tmp/gate-client101 -warnings-as-errors -collection:shared:$HOME/dev/oss/Odin/shared` | exit 0 |
| Usage | `/tmp/gate-client101` | exit 2, stderr contains `--odin` |
| Setup default | build `tests/gates/setup` the same way, run it with `--odin odin --shared $HOME/dev/oss/Odin/shared --report /tmp/setup-report.json` and no `--sanitize` | the compiler line in stderr contains `-sanitize:address` |

Do not run a full matrix unless a build fails. A full client101 matrix
needs peers and a long timeout. The build and the usage check are the gate.

## Scope

**In scope**

- `tests/gates/support/gate.odin`
- `tests/gates/support/json.odin` only to add a helper that these gates need and that is not already there
- `tests/gates/client101/main.odin`
- `tests/gates/exchange101/main.odin`
- `tests/gates/concurrency101/main.odin`
- `tests/gates/budgets/main.odin`
- `tests/gates/setup/main.odin`
- `tests/gates/uploads/main.odin`
- `tests/gates/outcomes/main.odin`

**Out of scope**

- `tests/gates/cancel101`, `compatibility`, `consumer101`, `failure101`, `kernel101`, `pool101`, `redirect101`, `redirect_foundations101`, `session_actor101`, `stream104` — they already import `support`
- `Taskfile.yml`, `tools/test/**` — do not register these gates
- `src/**`
- Changing a scenario assertion (`completed == 4`, cell counts, expected status codes)

## Git workflow

- Branch: `advisor/004-gate-support`
- Commit subject: `test: share the gate build and failure path`
- Do not push. Do not stage `src/` or `tools/`.

## Steps

### Step 1: Add a build helper that does not require support.begin

`support.build` needs a `Gate` produced by `support.begin`. Outcomes cannot
call `begin`: its `--sanitize` is a boolean, and it has no `--shared` or
`--report`.

Add this proc next to `build` in `tests/gates/support/gate.odin`:

```odin
build_at :: proc(compiler, shared, pkg, binary, sanitizer: string, extra: ..string) -> bool
```

Copy the command construction from `build`. Pass `sanitizer` through the
same `none` means omit `-sanitize` rule. On wait timeout, kill and wait 2
seconds, then return false. On start failure, return false. Do not call
`fail` and do not exit.

Add:

```odin
exit_fail :: proc(root, name, reason: string)
```

If `root` is not `""`, `os.remove_all(root)` before `os.exit(1)`. Print
`name: reason` to stderr and flush first. This is the `support.fail` body
without requiring `begin` to have stored the directory.

Do not change `begin`'s required flags or its default sanitizer `none`.

**Verify**: `odin build tests/gates/support -out:/tmp/gate-support -warnings-as-errors -collection:shared:$HOME/dev/oss/Odin/shared` will fail because `support` is not `package main`. Instead: `odin check tests/gates/client101 -collection:shared:$HOME/dev/oss/Odin/shared` after step 2. For this step alone, `odin check` is not available until a main package imports the new procs. Proceed to step 2 and use its verify.

### Step 2: Replace the six local build procs

In client101, exchange101, concurrency101, budgets, setup, and uploads:

- Delete the local `build` proc.
- Call `support.build_at` with the same arguments the local proc received.
  budgets and some others omit `pkg` and build one path; pass that path as
  `pkg`. Read the deleted proc's `odin build` arguments and pass those
  strings. Do not add `-sanitize` when the gate's sanitizer is `none`.
- Keep each file's `parse_args`. setup must still default `sanitizer` to
  `address`. budgets must still reject a sanitizer token it rejects today.
  Read the current `parse_args` and preserve its accepted tokens.
- Replace `fail` so that once `root` exists it calls `support.exit_fail(root, "<gate name>", reason)`. Usage failures before the directory exists call `support.exit_fail("", "<gate name>", reason)`.
- Add `import support "../support"` if the file does not import it.

In outcomes:

- Keep `parse_args` and the boolean `--sanitize`.
- Find the `os.process_wait` on the compiler. On timeout, `os.process_kill` and wait 2 seconds, matching `support.build`. You may call a small `support.wait_kill` extracted from `build_at` if that avoids a second copy. Outcomes does not have a `shared` collection flag today. Read its build argv before inventing `-collection:shared`. If it has no collection flag, do not add one.
- Replace `fail` with `support.exit_fail` and the temp `root`, same rule as above.

**Verify**:

```
odin build tests/gates/client101 -out:/tmp/gate-client101 -warnings-as-errors -collection:shared:$HOME/dev/oss/Odin/shared
odin build tests/gates/setup -out:/tmp/gate-setup -warnings-as-errors -collection:shared:$HOME/dev/oss/Odin/shared
odin build tests/gates/outcomes -out:/tmp/gate-outcomes -warnings-as-errors -collection:shared:$HOME/dev/oss/Odin/shared
odin build tests/gates/exchange101 -out:/tmp/gate-exchange101 -warnings-as-errors -collection:shared:$HOME/dev/oss/Odin/shared
odin build tests/gates/concurrency101 -out:/tmp/gate-concurrency101 -warnings-as-errors -collection:shared:$HOME/dev/oss/Odin/shared
odin build tests/gates/budgets -out:/tmp/gate-budgets -warnings-as-errors -collection:shared:$HOME/dev/oss/Odin/shared
odin build tests/gates/uploads -out:/tmp/gate-uploads -warnings-as-errors -collection:shared:$HOME/dev/oss/Odin/shared
```

Each exit 0. `/tmp/gate-client101` with no args exits 2.
`/tmp/gate-outcomes --sanitize` exits 2 or prints `odin required` because
`--odin` is missing. It must not require `--shared`.

### Step 3: Parse client101, exchange101, and concurrency101 JSON with support

Replace `object` / `field_at` in those three files with `support.only` and
`int_field` / `bool_field` / `is_true`. Keep every expected number and every
key string. `defer support.release` is wrong for `only`: `only` returns one
`json.Value`. Destroy it with `json.destroy_value` from `core:encoding/json`
the way `support/json.odin` releases a value. Read `only` and `release`
before choosing the free call. If `only` fails, fail the gate with the same
reason string the old `json` abort used.

Do not change budgets, setup, uploads, or outcomes JSON handling if they
do not use `object`.

**Verify**: the seven `odin build` commands from step 2 still exit 0.
`rg -n "^object :: proc" tests/gates/client101 tests/gates/exchange101 tests/gates/concurrency101` prints nothing.

## Test plan

- No new test package. The verification is that each gate still builds with
  `-warnings-as-errors` and that usage text and defaults survived.
- After the builds, run setup with the three required flags and no
  `--sanitize`. Stderr must contain `-sanitize:address`. Then kill the run
  if it proceeds into a long matrix. A usage-level check is enough if the
  build line is printed before the matrix. If setup builds quietly, add a
  one-line `fmt.eprintf` only if one already exists. Do not add a new log
  line just for this check. Read the build proc's existing note.
- Do not point `task test` at these programs.

## Done criteria

- [ ] The seven `odin build` commands exit 0
- [ ] client101 with no args exits 2
- [ ] outcomes does not require `--shared` or `--report`
- [ ] setup's default sanitizer string is still `address`
- [ ] `support.build_at` kills the compiler when `process_wait` returns an error
- [ ] `rg -n "os\.exit\(1\)" tests/gates/client101 tests/gates/setup tests/gates/outcomes tests/gates/exchange101 tests/gates/concurrency101 tests/gates/budgets tests/gates/uploads` prints nothing (exit goes through `support.exit_fail` or `support.fail`)
- [ ] `Taskfile.yml` and `tools/test` are unchanged
- [ ] `plans/README.md` status row updated

## STOP conditions

- A gate's `parse_args` accepts a sanitizer token the table above does not list. Preserve it and report the token. Do not drop it.
- outcomes' compiler invocation has no analogue of `process_wait`. Report the wait proc. Do not add `--shared`.
- `support.only` cannot read a key the gate asserts, and adding a helper would change JSON semantics. Report the key.
- The scenario checks (`completed`, cell counts) cannot be expressed with `int_field` / `bool_field` without changing an expected value. Stop. Do not change the expected value.

## Maintenance notes

- A new gate imports `support` and does not copy `build`.
- `support.begin` stays the strict CLI. Gates with a different CLI use `build_at` and `exit_fail`.
- Reviewers should check setup still defaults to address sanitizer and outcomes still has a boolean `--sanitize`.
- These programs remain outside `task test` on purpose.
