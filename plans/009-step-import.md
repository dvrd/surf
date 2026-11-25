# Plan 009: `task test` compiles against `shared:async/compress/step`

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat a552088..HEAD -- src/http.odin src/async/exchange/exchange.odin tests/async/exchange/internal/stream_footer_test.odin`
> If any of those files changed, compare the excerpts below to the live code before editing. On a mismatch, stop.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: tests
- **Planned at**: commit `a552088`, 2026-11-25
- **Executor**: `claude:haiku` — three import-path edits with the alias unchanged
- **Fallback executor**: `grok:fast`

## Why this matters

`task test` compiles `src/` before any assertion runs. Three files still import `core:compress/step`. That directory is gone from `/Users/kakurega/dev/oss/Odin/core/compress`. The decoder now lives at `shared:async/compress/step`. Until the imports move, no suite runs, including dial, TLS, redirect, HTTP/2, HTTP/3, WebSocket, cancel, body, and budget tests. A throwaway copy that changed only these strings compiled, and the private surf suite passed 35 tests.

## Current state

- `src/http.odin` — package `surf`. Line 3 is `import step "core:compress/step"`. Line 34 uses `step.Decode_Error`.
- `src/async/exchange/exchange.odin` — package `surf_exchange`. Line 10 is `import deflate "core:compress/step"`. `deflate.inflate_gzip_decoder_init` is called at line 962 and `deflate.inflate_gzip_decoder_step` at line 1308.
- `tests/async/exchange/internal/stream_footer_test.odin` — overlaid onto the exchange package by `tools/test`. Line 5 is `import deflate "core:compress/step"`.
- `/Users/kakurega/dev/oss/Odin/shared/async/compress/step/step.odin` exports `inflate_gzip_decoder_init` (line 317) and `inflate_gzip_decoder_step` (line 340). The init call passes a config struct with `max_encoded_bytes`, `max_decoded_bytes`, `max_header_bytes`, and `max_members`. Leave that call as it is.
- `core:compress/step` does not exist. `ls $HOME/dev/oss/Odin/core/compress/step` fails.

Conventions in `AGENTS.md`:

After the closing brace of a struct, procedure, `switch`, `for`, or `if`, leave one blank line before the next statement. Do not put that blank line before `else`. The only exception is the `defer` that frees an allocation checked by the `if` immediately above it. This plan only changes import lines, so do not reformat anything.

On an import you change, omit the name when it repeats the last element of the path. `import step "shared:async/compress/step"` repeats `step`. Write `import "shared:async/compress/step"`. Keep `deflate`: that name is not the last element of the path.

Tabs. One statement per line. Do not edit `/Users/kakurega/dev/projects/async`, `/Users/kakurega/dev/projects/http`, `/Users/kakurega/dev/projects/websocket`, or `/Users/kakurega/dev/oss/Odin`. Do not push. Do not pass `-strict-style` or `-vet`. `odin check` of a library needs `-no-entry-point`. `odin test` must use `-out:` under `/tmp`.

`ODIN=$HOME/dev/oss/Odin/odin task test` runs `tools/test`. Flags after `--` reach `odin test`. A passing run exits 0. `task` exits 201 when the child exits 1. That wrapper code is not a bug.

Commit messages match `fix: follow shared:async for http, tls, and budgets`. No trailer that names an assistant or a generator.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Check surf | `ODIN=$HOME/dev/oss/Odin/odin "$ODIN" check src -collection:shared:$HOME/dev/oss/Odin/shared -no-entry-point` | exit 0 |
| Check exchange | `ODIN=$HOME/dev/oss/Odin/odin "$ODIN" check src/async/exchange -collection:shared:$HOME/dev/oss/Odin/shared -no-entry-point` | exit 0 |
| Suites | `ODIN=$HOME/dev/oss/Odin/odin task test -- -define:ODIN_TEST_THREADS=1` | exit 0 |

## Scope

**In scope**:

- `src/http.odin`
- `src/async/exchange/exchange.odin`
- `tests/async/exchange/internal/stream_footer_test.odin`

**Out of scope**:

- Every other import. `shared:async/http`, `shared:async/tls`, and `shared:async/mem` are already correct.
- `tests/gates/`, `tests/testdata/`, and `tests/stream104/`. They still fail for `Connection_Error` and TLS `.kind` reasons owned by plans 001 and 004.
- Sibling repositories and the Odin SDK.
- `.krs/packages.json`. Plan 006 owns pins.

## Git workflow

- Branch: `advisor/009-step-import`
- One commit: `fix: import gzip from shared:async/compress/step`
- Do not push or open a PR.

## Steps

### Step 1: Retarget the three imports

Replace the import path. Drop a name that repeats the last element of the new path. Keep a name that differs from it:

- `src/http.odin`: `import "shared:async/compress/step"`. Call sites already use `step.`, which is the name Odin takes from the path.
- `src/async/exchange/exchange.odin`: `import deflate "shared:async/compress/step"`
- `tests/async/exchange/internal/stream_footer_test.odin`: `import deflate "shared:async/compress/step"`

Do not edit the `inflate_gzip_decoder_init` or `inflate_gzip_decoder_step` call sites.

**Verify**: `rg -n 'core:compress/step' --glob '*.odin'` prints nothing. `rg -n 'shared:async/compress/step' --glob '*.odin'` prints exactly those three lines.

### Step 2: Type-check and run the suites

Run the three commands in the table, in order.

**Verify**: each exits 0. The suite run prints `All tests were successful` for every suite `tools/test` starts. Gates are not part of `task test`.

## Test plan

- No new test. The existing gzip footer test and the body-decode paths are the regression.
- `ODIN=$HOME/dev/oss/Odin/odin task test -- -define:ODIN_TEST_THREADS=1` exits 0.

## Done criteria

- [ ] `rg -n 'core:compress/step' --glob '*.odin'` prints nothing
- [ ] The three files import `shared:async/compress/step`. `src/http.odin` has no import name. The two exchange files keep the name `deflate`
- [ ] `odin check src` and `odin check src/async/exchange`, both with `-no-entry-point` and the shared collection, exit 0
- [ ] `ODIN=$HOME/dev/oss/Odin/odin task test -- -define:ODIN_TEST_THREADS=1` exits 0
- [ ] `git status` shows no file outside the in-scope list
- [ ] `plans/README.md` status row updated

## STOP conditions

- The three excerpts no longer match.
- `shared:async/compress/step` does not export `inflate_gzip_decoder_init` or `inflate_gzip_decoder_step` with the call shape already in `exchange.odin`.
- A check error is not this missing import. Do not "fix" unrelated types.
- You would edit a sibling repository, a gate, or a testdata program.

## Maintenance notes

- Plans 002, 003, 005, and 006 use `task test` as a done check. They stay blocked until this plan is done.
- Plan 001's remaining gate work is separate. A green `task test` does not mean the gates compile.
- Reviewers should see three import lines and no call-site diff.
