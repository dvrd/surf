# Plan 017: Resolver-snapshot failures keep their own DNS errors

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat a552088..HEAD -- src/async/coordinator.odin`
> Plan 016 may have edited other procedures in this file. Stop only if `network_snapshot_error` no longer matches the excerpt.

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: LOW
- **Depends on**: plans/016-dns-id-bank.md
- **Category**: bug
- **Planned at**: commit `a552088`, 2026-11-25
- **Executor**: `claude:sonnet` — one type switch with a fixed mapping
- **Fallback executor**: `codex`

## Why this matters

`network_snapshot_error` turns an `os.Error` and almost every `Resolver_Snapshot_General_Error` into `DNS_Error.Invalid_Resolv_Config_Error`. A hosts file that cannot be read is reported as a bad `resolv.conf`. A bad hostname, a parse failure, and a destination that cannot hold 65 addresses share that same label, and the last of those fails admission as `.Invalid_Config` before DNS. `DNS_RESULT_CAPACITY` is 64 (`src/async/pool.odin:585`). `resolver_snapshot_lookup` returns `Destination_Undersized` without writing the destination when the name needs more addresses than `len(dst)` (`core/net/resolver_snapshot.odin:311`).

## Current state

`network_snapshot_error` (`src/async/coordinator.odin:1057`):

- `mem.Allocator_Error` → `.Allocation_Failed`. Keep this.
- `Resolver_Snapshot_General_Error.Unsupported` → `.Runtime_Error` / `.Unsupported` and `DNS_Error.Unsupported`. Keep this.
- `os.Error` → runtime `.System_Error` with `os.is_platform_error` code, and `http.network = DNS_Error.Invalid_Resolv_Config_Error`. The network code is wrong.
- Every other value → `.Invalid_Config` and `DNS_Error.Invalid_Resolv_Config_Error`.

`DNS_Error` (`core/net/common.odin`) is `Invalid_Hostname_Error`, `Invalid_Hosts_Config_Error`, `Invalid_Resolv_Config_Error`, `Connection_Error`, `Server_Error`, `System_Error`, `Timeout`, `Unsupported`. There is no `Parse_Failed` or `Destination_Undersized` variant. Do not add one to the Odin core.

`Resolver_Snapshot_General_Error` is `None`, `Invalid_Config`, `Invalid_State`, `Invalid_Hostname`, `No_Servers`, `Unsupported`, `Parse_Failed`, `Limit_Exceeded`, `Destination_Undersized`, `Overlapping_Buffers`.

`Parse_Failed` is returned both for a bad resolv endpoint (`resolver_snapshot_parse.odin:119`) and for a bad hosts file (`:129`). One `DNS_Error` cannot name both. Use `Invalid_Hosts_Config_Error` for `Parse_Failed` and say so in a one-line comment. Do not edit core to split the enum.

`network_queue_claim_budget` (`pool.odin:951`) returns `network_snapshot_error` immediately when lookup fails. For `Destination_Undersized`, do not treat the name as absent and do not truncate. Admission fails. The caller can still use DNS only if you explicitly continue when lookup returns that error. This plan fails admission with a dial error rather than `.Invalid_Config`, and does not continue to DNS. Continuing would hide a hosts file that intended to answer the name.

Conventions in `AGENTS.md`: one blank line after a closing brace before the next statement. The `switch` arms do not get blank lines between them. Tabs. One statement per line. Omit an import name that repeats the last element of the path. Do not reformat the rest of `coordinator.odin`. Do not push. Do not edit `core/net`.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Check | `ODIN=$HOME/dev/oss/Odin/odin "$ODIN" check src/async -collection:shared:$HOME/dev/oss/Odin/shared -no-entry-point` | exit 0 |
| Tests | `ODIN=$HOME/dev/oss/Odin/odin PACKAGE=async INTERNAL=1 task test -- -define:ODIN_TEST_THREADS=1` | exit 0 |

## Scope

**In scope**:

- `src/async/coordinator.odin` — `network_snapshot_error` only
- `tests/async/internal/network_config_test.odin` or `bootstrap_test.odin` — one direct call of `network_snapshot_error` per mapping you can construct without reading a real `/etc/hosts`

**Out of scope**:

- The DNS ID bank (plan 016)
- `resolver_snapshot_lookup` in the Odin core
- Raising `DNS_RESULT_CAPACITY`

## Git workflow

- Branch: `advisor/017-snapshot-errors`
- Commit: `fix: map resolver snapshot errors onto their DNS codes`
- Do not push.

## Steps

### Step 1: Switch on the general error

Keep the allocator arm and the `.Unsupported` arm.

`os.Error`: keep `runtime.kind = .System_Error` and `system_code`. Set `http.network` to `net.DNS_Error.System_Error`. `http.kind` stays `.Dial_Failed`.

For `Resolver_Snapshot_General_Error`, set `http.kind` and `http.network` as follows. `Client_Error.kind` is `.Invalid_Config` unless the row says otherwise. `write_effect` is `.Not_Sent`. Phase is `.DNS` when `http.kind` is `.Dial_Failed`.

| Snapshot error | Client_Error.kind | http.kind | http.network |
|----------------|-------------------|-----------|--------------|
| `.Invalid_Hostname` | `.Invalid_Config` | `.Dial_Failed` | `.Invalid_Hostname_Error` |
| `.No_Servers`, `.Invalid_Config` | `.Invalid_Config` | `.Dial_Failed` | `.Invalid_Resolv_Config_Error` |
| `.Parse_Failed` | `.Invalid_Config` | `.Dial_Failed` | `.Invalid_Hosts_Config_Error` |
| `.Destination_Undersized`, `.Limit_Exceeded` | `.Capacity` | `.Dial_Failed` | nil |
| `.Invalid_State`, `.Overlapping_Buffers`, `.None` | `.Invalid_State` | `.Invalid_Config` | nil |

The switch on `Resolver_Snapshot_General_Error` must be exhaustive. Do not use `#partial` unless the enum cannot be exhaustive in this compiler. A new enumerator should fail the build.

**Verify**: `odin check src/async -no-entry-point` exits 0.

### Step 2: Assert the mapping without a live hosts file

In an async internal test, call `network_snapshot_error` with:

- `net.Resolver_Snapshot_General_Error.Invalid_Hostname` → network `.Invalid_Hostname_Error`
- `.No_Servers` → `.Invalid_Resolv_Config_Error`
- `.Parse_Failed` → `.Invalid_Hosts_Config_Error`
- `.Destination_Undersized` → `Client_Error.kind == .Capacity` and `http.network == nil`
- an `os.Error` you can construct, or skip the `os.Error` case if the SDK has no public constructor other than a real file failure. Do not read `/etc/hosts` or `/etc/resolv.conf` in the test.

`testing.expect_value` on the enum. For the union, type-switch `http.network`.

**Verify**: `PACKAGE=async INTERNAL=1 task test` exits 0.

## Test plan

- The five calls above, in the existing network-config or bootstrap test file.
- Do not add a 65-address hosts fixture. The mapping test is the regression. A later change that sends `Destination_Undersized` back to `.Invalid_Config` fails the capacity assertion.

## Done criteria

- [ ] `os.Error` maps to `DNS_Error.System_Error`
- [ ] `Invalid_Hostname`, `No_Servers`, and `Parse_Failed` use the three DNS codes in the table
- [ ] `Destination_Undersized` is `.Capacity`, not `.Invalid_Config` with `Invalid_Resolv_Config_Error`
- [ ] The general-error switch is exhaustive
- [ ] Async private tests pass
- [ ] `plans/README.md` status row updated

## STOP conditions

- `DNS_Error` has gained a closer enumerator than the table. Use it and note the name in the commit. Do not edit core to add one.
- `network_snapshot_error` is no longer the only mapper. If `pool.odin` maps the same union itself, stop and report. Do not fork a second mapping.
- An existing test requires every snapshot failure to be `Invalid_Resolv_Config_Error`. Update the test. Do not keep the collapsed mapping.

## Maintenance notes

- `Parse_Failed` covers one resolv-endpoint failure and the hosts parser. The comment on that arm should say both, so nobody "corrects" it to `Invalid_Resolv_Config_Error` without splitting core.
- Plan 016's dial error for an empty ID bank stays `Resolve_Error.Unable_To_Resolve`. Do not route that through `network_snapshot_error`.
