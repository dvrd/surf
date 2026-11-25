# Plan 006: The pin file records the shared commits task test compiles

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
> git diff --stat 6209fc3..HEAD -- .krs/packages.json .gitignore Taskfile.yml tools/test
> ```
>
> Confirm `.krs/packages.json` still lists async `b92c05f`, http `0670b9a`,
> and websocket `4953c3a`. If those commits were already replaced with the
> live symlink HEADs, stop and report that this plan is done.

## Status

- **Priority**: P3
- **Effort**: S
- **Risk**: LOW
- **Depends on**: plans/001-tls-net-errors.md (and plans/008-async-http.md, which 001 already requires)

If plan 008 has landed, `rg -n '"shared:http' --glob '*.odin'` prints
nothing. Delete the `http` object from `.krs/packages.json` instead of
writing a new commit for the standalone http repo. The async object is
the pin for `shared:async/http`. Keep the websocket object. If that `rg`
still prints a `shared:http` import that is not `shared:async/http`,
stop. The 2026-11-24 async prefix `0ca47a7` is a check, not a value to
write. Write the live HEAD, as the step below already says.
- **Category**: dx
- **Planned at**: commit `6209fc3`, 2026-11-24

## Why this matters

`.krs/packages.json` is tracked and records async, http, and websocket
commits. `.gitignore` ignores the whole `.krs/` directory, so a new file
next to the pin does not show up in `git status`. `task test` never reads
the pin. It compiles `-collection:shared=` from `WEBTOOLS_SHARED`, which
defaults to `$HOME/dev/oss/Odin/shared`. On 2026-11-24 those symlinks were
not the pinned commits. The pin file was describing a different tree from
the one the tests compile.

## Current state

`.gitignore` line 15 is `.krs/`. `git ls-files .krs/packages.json` prints
the path. `git check-ignore -v --no-index .krs/packages.json` reports the
`.krs/` rule.

The pin file, commit `65cc877`, contains three objects with `name`,
`source`, `tag`, `commit`, and `hash`. The commits recorded there are:

- async `b92c05f45e552f07923abfb265360001e82d5471`
- http `0670b9a30bbcd3cb7fce4ec33636786fe1f6de26`
- websocket `4953c3a5fa99c57bbf66815e0fe96be3d8ff1e4f`

Nothing under `Taskfile.yml` or `tools/test` reads this file. Do not teach
the harness to read it.

On 2026-11-24 the symlinks were:

- `$HOME/dev/oss/Odin/shared/async` → `/Users/kakurega/dev/projects/async/src`, HEAD prefix `6586bb2`
- `$HOME/dev/oss/Odin/shared/http` → `/Users/kakurega/dev/projects/http/src`, HEAD prefix `3e9c009`
- `$HOME/dev/oss/Odin/shared/websocket` → `/Users/kakurega/dev/projects/websocket/src`, HEAD prefix `bf9a07e`

Those prefixes are a check, not a value to write if the clones have moved.
The value to write is the full `git rev-parse HEAD` of each symlink target
at the time you run this plan, after plan 001's `task test` has passed
against those same symlinks.

`hash` is 64 hex digits. No file in this repo computes it. Do not invent a
new hash.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Symlink HEAD | `git -C "$(dirname "$(readlink "$HOME/dev/oss/Odin/shared/async")")" rev-parse HEAD` | one full hex sha, and the same command for `http` and `websocket` |
| Ignore rule | `git check-ignore -v --no-index .krs/packages.json ; echo exit:$?` | exit 1 after the gitignore exception (the path is not ignored) |
| Suites | `task test` | exit 0 |

`dirname` of the symlink is the package `src` directory. `git -C` on `src`
still finds the parent repository. If it does not, `git -C` the parent.

## Scope

**In scope**

- `.krs/packages.json`
- `.gitignore`

**Out of scope**

- `tools/test/**`, `Taskfile.yml`
- The sibling clones. Do not commit in async, http, or websocket.
- `src/**` and `tests/**`
- Recomputing `hash`

## Git workflow

- Branch: `advisor/006-dependency-pins`
- Commit subject: `chore: record the shared commits the tests compile`
- Do not push.
- `.krs/` is ignored. After the gitignore exception, `git add .krs/packages.json` must succeed without `-f`. If it still needs `-f`, the exception is wrong. Fix the exception. Do not use `-f`.

## Steps

### Step 1: Let the pin file be seen

In `.gitignore`, directly under the `.krs/` line, add:

```
!.krs/packages.json
```

**Verify**: `git check-ignore -v --no-index .krs/packages.json` exits 1
(no output, not ignored). `git status --short -- .krs/packages.json` shows
the file when you modify it.

### Step 2: Write the commits task test just used

Run `task test` once if plan 001's run was against a different machine.
Then read the three symlink HEADs with the command in the table.

For each package object:

- Set `commit` to that full HEAD.
- If `git -C <repo> describe --tags --exact-match` prints a tag, set `tag`
  to it. If it fails, leave `tag` as it is.
- Leave `hash` unchanged.
- Leave `name` and `source` unchanged.

STOP if a symlink HEAD does not exist, or if `task test` fails. Do not
write a commit you did not just compile against. The 2026-11-24 prefixes
(`6586bb2`, `3e9c009`, `bf9a07e`) are what you should see if those clones
have not moved. If the prefix differs, write the new HEAD anyway, and name
the new prefix in the commit body. That is not a STOP, as long as `task test`
passed against it.

**Verify**: `git diff -- .krs/packages.json` shows only `commit` lines and,
if a tag matched, `tag` lines. `hash` lines are unchanged.
`task test` → exit 0.

## Test plan

- No new test. The pin is not read by the harness.
- `task test` → exit 0, to prove the commits you wrote are the ones that
  just compiled.

## Done criteria

- [ ] `.gitignore` contains `!.krs/packages.json` under `.krs/`
- [ ] `git check-ignore -v --no-index .krs/packages.json` exits 1
- [ ] Each `commit` equals `git rev-parse HEAD` of that symlink's repo
- [ ] `hash` is byte-for-byte the previous value
- [ ] `tools/test` does not mention `packages.json`
- [ ] `task test` exits 0
- [ ] `plans/README.md` status row updated

## STOP conditions

- Plan 001 has not landed and `task test` does not compile.
- A symlink target is dirty (`git -C <repo> status --short` prints
  anything). Report the repo. Do not pin a dirty tree.
- `git add .krs/packages.json` is ignored after the exception. Fix the
  exception only. Do not `git add -f`.
- You cannot find the three `name` keys. Report the file's keys. Do not
  rewrite the JSON shape.

## Maintenance notes

- The next time a sibling library moves, this file is updated only after
  `task test` passes. The harness will not notice a stale pin.
- Reviewers should check `hash` was not regenerated by guesswork, and that
  the three commits match the symlinks.
- Making `task test` check out these commits is a different change. Do not
  start it here.
