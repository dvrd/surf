# Plan 020: HTTP/2 does not index authorization or cookie

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat a552088..HEAD -- src/http2.odin src/http2_websocket.odin`
> Stop if `h2_field` no longer matches the excerpt.

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: LOW
- **Depends on**: plans/009-step-import.md
- **Category**: security
- **Planned at**: commit `a552088`, 2026-11-25
- **Executor**: `claude:sonnet` — set one flag on four header names
- **Fallback executor**: `codex`

## Why this matters

`h2_field` leaves `never_indexed` false. The HTTP/2 encoder's default indexing is incremental, and it inserts a field unless `never_indexed` is set. Cookie and Authorization values then sit in the connection dynamic table and can be referenced by later requests on that lane. RFC 7541 says not to use that for those fields. The HTTP/2 WebSocket opener already sets the flag for `authorization` and `cookie` (`src/http2_websocket.odin:117`). QPACK sets it for those names plus `proxy-authorization` and `set-cookie` (`qpack_sensitive` in `shared:async/http/v3/qpack.odin`). Ordinary HTTP/3 requests are not this bug.

## Current state

`h2_field` (`src/http2.odin:1110`):

```odin
job.fields[job.field_n] = {
	name  = stored,
	value = value,
}
```

`stored` is lowercase unless the name starts with `:`.

The HPACK `Field` (`shared:async/http/v2/hpack/hpack.odin:1198`) is `name`, `value`, `never_indexed`.

The WebSocket opener writes:

```odin
fields[count] = {name, header.value, name == "authorization" || name == "cookie"}
```

`qpack_sensitive` also matches `proxy-authorization` and `set-cookie` with `strings.equal_fold`.

Do not edit `shared:async/http`. Set the flag in surf before encode.

Conventions in `AGENTS.md`: one blank line after a closing brace before the next statement. Tabs. One statement per line. Omit an import name that repeats the last element of the path. Do not reformat `h2_send_body` (plan 022) or `h2_tls_error` (plan 021). Do not push.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Check | `ODIN=$HOME/dev/oss/Odin/odin "$ODIN" check src -collection:shared:$HOME/dev/oss/Odin/shared -no-entry-point` | exit 0 |
| Internal HTTP/2 | `ODIN=$HOME/dev/oss/Odin/odin PACKAGE=. INTERNAL=1 task test -- -define:ODIN_TEST_THREADS=1` | exit 0 |

## Scope

**In scope**:

- `src/http2.odin` — `h2_field` only
- `tests/internal/http2_test.odin` or `tests/internal/buffered_h2_headers_test.odin` — one assertion that the flag is set

**Out of scope**:

- The WebSocket opener's existing flag. You may extend it to the same four names if it builds fields itself and does not call `h2_field`. If it does not call `h2_field`, update that literal too so the two paths match.
- QPACK. It already sets the flag.
- Header compression size as a behavior change beyond those four names

## Git workflow

- Branch: `advisor/020-hpack-sensitive`
- Commit: `fix: keep authorization and cookie out of the HPACK dynamic table`
- Do not push.

## Steps

### Step 1: Set `never_indexed` in `h2_field`

After `stored` is known, set `never_indexed` when `stored` is `authorization`, `proxy-authorization`, `cookie`, or `set-cookie`. Compare with `==` after lowercasing, or `strings.equal_fold` if a pseudo-header could reach this with mixed case. Pseudo-headers start with `:` and are not in the list.

```odin
job.fields[job.field_n] = {
	name          = stored,
	value         = value,
	never_indexed = stored == "authorization" ||
		stored == "proxy-authorization" ||
		stored == "cookie" ||
		stored == "set-cookie",
}
```

If the WebSocket opener does not go through `h2_field`, add `proxy-authorization` and `set-cookie` to its boolean as well.

**Verify**: `odin check` exits 0.

### Step 2: A test that reads the flag

The smallest test calls `h2_field` on a zero `H2_Job` with `Authorization` and `Cookie` and `X-Test`, then expects `never_indexed` true, true, and false. `h2_field` is in package `surf`. Put the test in `tests/internal`. If `h2_field` requires a non-zero job (name storage), follow the existing `H2_Job` setup in `http2_test.odin`.

Do not assert on encoded bytes unless the internal test already has an HPACK decoder. The flag is the contract.

**Verify**: internal surf tests exit 0.

## Test plan

- `Authorization`, `Cookie`, `Proxy-Authorization`, and `Set-Cookie` set the flag.
- `X-Test` and `:method` do not.
- Existing HTTP/2 tests still pass. A header-block size assertion that assumed these fields were indexed must be updated to the larger literal form.

## Done criteria

- [ ] `h2_field` sets `never_indexed` for those four names
- [ ] Other fields stay indexable
- [ ] The WebSocket path sets the same four if it does not call `h2_field`
- [ ] `plans/README.md` status row updated

## STOP conditions

- `Field` no longer has `never_indexed`. Stop and report the struct. Do not invent a parallel flag.
- `h2_field` is not the procedure that feeds the encoder. Find the real writer in `src/http2.odin` and change that. Do not edit `shared:async/http/v2`.

## Maintenance notes

- A new sensitive name belongs next to this boolean and in `qpack_sensitive`. This plan does not change QPACK.
- Indexed cookies are a compression side channel on a connection that also carries attacker-influenced headers. Reviewers should check the flag is set on the stored field, not only on a copy the encoder never sees.
