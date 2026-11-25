# Plan 007: A short note names the clients and how to run a gate

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**:
>
> ```
> git diff --stat 6209fc3..HEAD -- README.md AGENTS.md Taskfile.yml src/http.odin src/buffered.odin src/http2.odin src/async/client.odin src/websocket.odin
> ```
>
> If a `README.md` already documents these entry points, stop and report
> that this plan is done. Do not add a second guide.

## Status

- **Priority**: P3
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: docs
- **Planned at**: commit `6209fc3`, 2026-11-24

## Why this matters

The repository has no README, no AGENTS.md, and no docs directory. The
only command note is the comment at the top of `Taskfile.yml`, and it
covers `task test` only. The library is four packages and several public
entry points. Acceptance programs under `tests/gates/` are not run by
`task test`. A newcomer cannot tell which proc is the blocking client, or
how to build one gate.

## Current state

Packages, from the first line of each file:

- `src/http.odin` and the other files in `src/` except `src/async/` — `package surf`
- `src/async/client.odin` — `package surf_async`
- `src/async/exchange/exchange.odin` — `package surf_exchange`
- `src/async/stream/stream.odin` — `package surf_stream`

Entry points and their locations on 2026-11-24:

- `execute` — `src/http.odin:131` — blocking HTTP exchange, package `surf`
- `buffered_http_execute` — `src/buffered.odin:32` — package `surf`
- `http_client_init` — `src/http2.odin:91` — package `surf`
- `http_client_exchange` — `src/http2.odin:160` — package `surf`
- `client_init` — `src/async/client.odin:399` — package `surf_async`
- `websocket_dial` — `src/websocket.odin:328` — package `surf`

`Taskfile.yml` task `test` sets `SURF_ROOT`, `SURF_ODIN`, `SURF_SHARED`,
`SURF_PACKAGE`, and `SURF_INTERNAL`, then runs `odin run tools/test`.
`ODIN` defaults to `odin`. `WEBTOOLS_SHARED` defaults to
`$HOME/dev/oss/Odin/shared`. `PACKAGE` defaults to `all`. `INTERNAL`
defaults to `0`. Flags after `--` are odin test flags. The comment at
`Taskfile.yml:3` is the source for those names. Quote it. Do not invent
more variables.

`tests/gates/support/gate.odin` `begin` requires:

```
--odin <compiler> --shared <collection> --report <path> [--sanitize address|thread|none]
```

`tests/gates/outcomes` does not use that CLI. It takes `--odin` and an
optional boolean `--sanitize`. `tests/gates/setup` defaults the sanitizer
to `address`. Say that the gates are separate programs, and give one
command line for `client101` using `support.begin`'s flags. Mention that
`outcomes` and `setup` differ. Do not document every gate.

`task test` does not build or run `tests/gates/`. Write that sentence.

There is no CI config and no formatter config. Do not add either in this
plan.

Style of the note: short prose, the same words the code uses (`execute`,
`PACKAGE`, `WEBTOOLS_SHARED`). No marketing paragraph. No table of every
source file.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| The test task exists | `task --list` | output contains `test` |
| The note has the entry points | `rg -n "execute|buffered_http_execute|http_client_exchange|client_init|websocket_dial|tests/gates" README.md` | each name matches |

`task test` is not required to pass for this plan. If you run it and it
fails, do not "fix" the library while writing the note.

## Scope

**In scope**

- `README.md` (create)

**Out of scope**

- `AGENTS.md`, `Taskfile.yml`, `src/**`, `tests/**`, `tools/**`, `.github/**`
- A changelog, a design doc, or an API reference that restates every field of `Config`
- Editing comments in `src/http.odin`

## Git workflow

- Branch: `advisor/007-entry-points`
- Commit subject: `docs: name the clients and the gate command`
- Do not push.

## Steps

### Step 1: Write README.md

Create `README.md` at the repo root with these sections and no others:

1. One sentence: surf is an Odin HTTP client. Name the four packages and
   the directory of each.
2. "Entry points" — the six procs above, each with its package and file.
   One line each. Say `execute` is the blocking client. Say `client_init`
   is the async client and that the async session speaks HTTP/1. Do not
   claim HTTP/2 or HTTP/3 on the async client. Those are not wired
   (`src/async` has no `http3` reference).
3. "Tests" — the `task test` variables from `Taskfile.yml`, including
   `PACKAGE` and `INTERNAL=1`. One example: `task test PACKAGE=async`.
   State that this does not run `tests/gates/`.
4. "Gates" — one example command:
   ```
   odin run tests/gates/client101 -- --odin odin --shared "$HOME/dev/oss/Odin/shared" --report /tmp/client101.json
   ```
   One sentence that `setup` defaults `--sanitize` to `address`, and that
   `outcomes` takes `--odin` and a boolean `--sanitize` and does not take
   `--shared` or `--report`. One sentence that a gate is a separate
   program.

Do not document `Address_Policy`, redirects, or TLS fields. Plan 001 may
rename `tls_dial`. The note must not mention `tls_dial` or `tls_io`.

**Verify**: `rg -n "execute|buffered_http_execute|http_client_exchange|client_init|websocket_dial|task test|tests/gates" README.md` matches all of those strings. `wc -l README.md` is under 80.

## Test plan

- No code test. Re-read the six proc lines in the source and confirm the
  README names the same procs. If a proc moved, cite the new file and line
  in the README and do not invent a proc.

## Done criteria

- [ ] `README.md` exists and is the only new file
- [ ] It names the four packages, the six procs, `task test`, and one gate command
- [ ] It says `task test` does not run `tests/gates/`
- [ ] It does not mention `tls_dial`, `tls_io`, or a private key
- [ ] `Taskfile.yml` is unchanged
- [ ] `plans/README.md` status row updated

## STOP conditions

- A README already exists with these entry points.
- `execute` or `client_init` is no longer the name in source. Use the name
  you found, and report the rename. Do not keep the old name.
- You are about to document an async HTTP/2 or HTTP/3 API. Stop. The async
  tree does not call it.

## Maintenance notes

- When a public proc is renamed, this file is the one to update. It is not
  a field-by-field reference.
- Reviewers should check the gate example against `support.begin` and the
  two exceptions (`setup`, `outcomes`).
- CI and `odinfmt` were left out. Add them only after `task test` is the
  command a workflow can run.
