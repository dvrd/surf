# Plan 022: An HTTP/2 upload rejects a count outside the buffer

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat a552088..HEAD -- src/http2.odin src/upload.odin src/http3.odin`
> Plans 020 and 021 may have edited other procedures in `src/http2.odin`. Stop if the `h2_send_body` loop no longer matches the excerpt.

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: LOW
- **Depends on**: plans/020-hpack-sensitive.md, plans/021-http2-error-phase.md
- **Category**: bug
- **Planned at**: commit `a552088`, 2026-11-25
- **Executor**: `claude:sonnet` — one bounds check copied from the HTTP/1 upload path
- **Fallback executor**: `codex`

## Why this matters

`h2_send_body` adds `got` from `io.read` with no check that `0 <= got <= len(chunk.data[filled:])`. A source that returns a count outside the buffer is not rejected before `filled` passes the chunk. The next slice panics or reads off the end when bounds checks are off. The HTTP/1 path rejects `count < 0` or `count > wanted` as `.IO_Failed`, phase `.Write`, `Connection_Error.Invalid_Count` (`src/upload.odin:120`). The HTTP/2 failure arm uses phase `.Read`. `http3_map_error` maps an upload `.Source` failure to phase `.Read` as well (`src/http3.odin:304`). A short upload is then reported as a response read, so retry logic treats a request body that never produced a response as a read failure.

## Current state

`h2_send_body` (`src/http2.odin` around 1207):

```odin
for filled < amount {
	got, read_error := io.read(job.upload.stream, chunk.data[filled:])

	if got > 0 {
		filled += got
	}

	if read_error != nil && read_error != io.Error.EOF || got == 0 {
		owned.destroy(&chunk)
		fail := HTTP_Error {
			kind      = .IO_Failed,
			phase     = .Read,
			source_io = read_error,
		}

		h2_fail(job, fail)
		lane.reusable = false
		return
	}
}
```

HTTP/1 (`src/upload.odin:120`):

```odin
if count < 0 || count > i64(wanted) {
	return {}, {kind = .IO_Failed, phase = .Write, transport = net.Connection_Error.Invalid_Count, source_io = read_error}
}
```

`io.read` returns `(int, io.Error)`. Compare `got` to `len(chunk.data[filled:])`.

`http3_map_error` `.Source` arm returns phase `.Read`. Change that phase to `.Write` only when the HTTP/3 result has no response status. Read `Client_Result` for a status field. If `result.status == 0`, phase is `.Write`. If a status was received, keep `.Read`. If there is no status field, use `.Write` when `result.sent` is true and no status is available, and say which field you used in the commit. Do not guess a field that is not on the struct.

Conventions in `AGENTS.md`: one blank line after a closing brace before the next statement. Tabs. One statement per line. Omit an import name that repeats the last element of the path. Do not reformat the HPACK change or `h2_tls_error`. Do not push.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Check | `ODIN=$HOME/dev/oss/Odin/odin "$ODIN" check src -collection:shared:$HOME/dev/oss/Odin/shared -no-entry-point` | exit 0 |
| Upload tests | `ODIN=$HOME/dev/oss/Odin/odin task test -- -define:ODIN_TEST_THREADS=1` | exit 0 |

## Scope

**In scope**:

- `src/http2.odin` — the read loop in `h2_send_body`
- `src/http3.odin` — the `.Source` arm of `http3_map_error` only
- `tests/internal/` — one source that returns a negative or oversized count, if the HTTP/2 test file can drive `h2_send_body` without a peer. Otherwise a direct call.

**Out of scope**:

- `exchange_upload_internal` and `buffered_http_upload`. They already check the count.
- Adding `Upload_Source` to `http_client_multiplex`. That was not selected.
- Redirects on the pooled lane

## Git workflow

- Branch: `advisor/022-http2-upload-count`
- Commit: `fix: reject an HTTP/2 upload read outside the buffer`
- Do not push.

## Steps

### Step 1: Reject a bad count before adding it

Immediately after `io.read`:

```odin
if got < 0 || got > len(chunk.data[filled:]) {
	owned.destroy(&chunk)
	h2_fail(job, {
		kind = .IO_Failed,
		phase = .Write,
		transport = net.Connection_Error.Invalid_Count,
		source_io = read_error,
	})
	lane.reusable = false
	return
}
```

Then the existing `got > 0` add. Change the existing failure arm's phase from `.Read` to `.Write`. A source error while producing the request body is a write. Keep `lane.reusable = false` and `owned.destroy`.

**Verify**: `odin check` exits 0.

### Step 2: HTTP/3 source phase

In `http3_map_error`, the `.Source` arm's phase is `.Write` when no response status has been observed, and `.Read` when a status exists. Use the field you found on `Client_Result`. Keep `kind = .IO_Failed` and the existing `write_effect`.

**Verify**: `rg -n 'result.error == .Source' -A 6 src/http3.odin` shows `.Write` on the no-status path.

### Step 3: A direct test

In `tests/internal`, drive the read loop with an `io.Stream` whose read returns `-1` or `len(buf)+1`. Expect `.IO_Failed`, phase `.Write`, transport `Invalid_Count`, and no panic. If `h2_send_body` needs a live lane, construct the minimum `H2_Job` the procedure reads (`upload`, `upload_left`, `chunk`) and a lane whose `reusable` flag you can observe. Read the procedure's other uses of `lane` before calling it. If it writes to the connection, stop and cover the check with a package-level test helper rather than a socket. Do not skip the assertion.

**Verify**: full `task test` exits 0.

## Test plan

- Negative count and count greater than the destination: `.Write`, `Invalid_Count`, chunk destroyed (`reusable == false`).
- A short valid read still advances `filled`. Existing upload tests in `tests/upload_test.odin` pass.
- HTTP/3 `.Source` with status 0 is phase `.Write`. If a test expected `.Read`, update it.

## Done criteria

- [ ] `got < 0` or `got > len(remaining)` fails before `filled += got`
- [ ] That failure is phase `.Write` and `Connection_Error.Invalid_Count`
- [ ] The HTTP/1 upload check is unchanged
- [ ] HTTP/3 `.Source` uses `.Write` when no response status exists
- [ ] `plans/README.md` status row updated

## STOP conditions

- `io.read` cannot return a count larger than the buffer because the interface forbids it. Still reject `got < 0` and `got > len(...)`. The check is the contract the HTTP/1 path already enforces.
- `h2_send_body` does not own `chunk` on this path. Match the existing `owned.destroy` on the error arm. If that destroy double-frees, stop and report.
- You would need to change `Upload_Source`.

## Maintenance notes

- Plan 020 and plan 021 touch the same file in different procedures. This plan should not need to edit them.
- A caller-supplied stream that lies about its count is the bug. Network peers do not pass this count.
