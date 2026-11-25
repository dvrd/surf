# Plan 015: The buffered HTTP/1 encoder rejects caller framing

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat a552088..HEAD -- src/buffered.odin`
> Stop if `buffered_http_encode` no longer matches the excerpts.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: MED
- **Depends on**: plans/009-step-import.md
- **Category**: security
- **Planned at**: commit `a552088`, 2026-11-25
- **Executor**: `claude:opus` — request-framing rules; a wrong exception reintroduces request smuggling
- **Fallback executor**: `codex`

## Why this matters

`buffered_http_execute` is a public one-shot HTTP/1 client. `buffered_http_encode` lets a caller replace `Content-Length` with an arbitrary string and copies every other header, including `Transfer-Encoding` and `Connection`. The full body is then written (`buffered_http_exchange`). The socket is closed afterward (`defer net.close` in `buffered_http_perform`). A peer that honors a short `Content-Length` can still read the rest of the bytes as a second request before the FIN. The strict client rejects those names in `http1.request_encode` before any socket (`src/http.odin` preflight, `shared:async/http/v1/codec.odin` `reserved_header`). The buffered HTTP/2 path already drops caller `content-length`. This gap is the HTTP/1 encoder.

CRLF and NUL in a raw header line are already rejected by `buffered_http_validate`.

## Current state

`buffered_http_encode` (`src/buffered.odin` around line 883):

- A caller `Host` replaces the URL authority (`host.value = value`).
- A caller `Content-Length` replaces the length computed from the body or the upload file (`length_text = value`).
- Every other present header is appended in `custom` and written with `buffered_http_put`.
- The computed or replaced `Content-Length` is then appended when `length_on` is set.

`buffered_http_exchange` writes `encoded[:count]`, then the file or the full `body`.

`reserved_header` in `shared:async/http/v1/codec.odin` rejects `Host`, `Connection`, `Content-Length`, `Transfer-Encoding`, `Accept-Encoding`, `Expect`, `Upgrade`, `Trailer`, and `TE`.

`header_reserved` in `src/http.odin` forwards that list. A `Host` override is a separate, intentional path for this callback-style client. Keep one `Host` value. Dial and certificate name stay on the URL host. Do not reject `Host`.

`buffered_http_h2_headers` already calls `http.header_value_valid`. The HTTP/1 encoder checks `http.header_name_valid` and does not check the value beyond the CRLF scan in `buffered_http_validate`.

Conventions in `AGENTS.md`: one blank line after a closing brace before the next statement. No blank line before `else`. Tabs. One statement per line. Omit an import name that repeats the last element of the path. Do not reformat the whole encoder. Do not push. Do not edit `shared:async/http`.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Check | `ODIN=$HOME/dev/oss/Odin/odin "$ODIN" check src -collection:shared:$HOME/dev/oss/Odin/shared -no-entry-point` | exit 0 |
| Test | `ODIN=$HOME/dev/oss/Odin/odin PACKAGE=. INTERNAL=1 task test -- -define:ODIN_TEST_NAMES=buffered_http_encode_rejects_transfer_encoding,buffered_http_encode_uses_the_body_length -define:ODIN_TEST_THREADS=1` | exit 0 |

## Scope

**In scope**:

- `src/buffered.odin` — `buffered_http_encode` and, if the value check fits more cleanly, the loop that already walks headers
- `tests/internal/buffered_h2_headers_test.odin` or a new `tests/internal/buffered_http1_test.odin`

**Out of scope**:

- The HTTP/2 buffered header path, except not weakening it
- `src/http.odin` `request_encode` preflight
- Adding `Connection: close` is allowed and small. Do it in this encoder so a one-shot request does not look like a kept-alive pipeline. Do not add it twice when the caller already passed `Connection`.
- Changing which host is dialed or which name is sent as SNI

## Git workflow

- Branch: `advisor/015-buffered-framing`
- Commit: `fix: reject caller framing on the buffered HTTP/1 encoder`
- Do not push.

## Steps

### Step 1: Reject hop-by-hop names and ignore a caller length

In the header loop of `buffered_http_encode`:

- Keep the `Host` arm. The value must pass `http.header_value_valid`. A failure returns `{kind = .Invalid_Header, phase = .Configuration, write_effect = .Not_Sent}`.
- Delete the arm that copies a caller `Content-Length` into `length_text`. A caller `Content-Length` is rejected with `.Reserved_Header`, phase `.Configuration`, write effect `.Not_Sent`. The length on the wire stays the length computed from `len(body)` or `upload_size`.
- For every other header that would be stored in `custom`, if `header_reserved(name)` is true, return `.Reserved_Header` the same way. That covers `Transfer-Encoding`, `Connection`, `Accept-Encoding`, `Expect`, `Upgrade`, `Trailer`, and `TE`. `Host` and the removed `Content-Length` arm are handled above, so they do not fall through to this check.
- Run `http.header_value_valid` on every value that will be written, including `Accept`.

After the header block, write `Connection: close` unless you already returned. One line. The one-shot client closes the socket anyway.

**Verify**: `odin check` exits 0. `rg -n 'length_text = value' src/buffered.odin` prints nothing.

### Step 2: Tests that stop before a socket

`buffered_http_encode` is in package `surf`. Call it from `tests/internal` with a parsed URL, method `POST`, a body of 4 bytes, and headers:

- `"Transfer-Encoding: chunked"` → `.Reserved_Header`, and the procedure returns before you need a connection.
- `"Content-Length: 0"` → `.Reserved_Header`.
- `"Content-Length: 4"` → `.Reserved_Header` as well. The encoder's own length is the only length. Do not accept a matching caller length.
- `"X-Test: ok"` → success, and the encoded bytes contain `Content-Length: 4` and `Connection: close` and do not contain `X-Test` twice. They contain `X-Test: ok`.
- `"Host: bucket.example"` → success, `Host: bucket.example` in the bytes, and no second `Host`.

If `buffered_http_encode` is not visible from the test file's package after overlay, the test file is package `surf` and the proc is lowercase, so it is visible. Do not export a new wrapper.

**Verify**: the filtered `task test` exits 0.

## Test plan

- The five cases above. No live socket. `write_effect` is `.Not_Sent` on every rejection.
- Model `testing.expect_value` on `tests/internal/buffered_h2_headers_test.odin`.

## Done criteria

- [ ] A caller `Content-Length`, `Transfer-Encoding`, or `Connection` is `.Reserved_Header` and produces no encoded bytes
- [ ] The encoded `Content-Length` is the body or upload size the procedure already computed
- [ ] `Connection: close` is on every successful HTTP/1 encoding
- [ ] One caller `Host` that passes `header_value_valid` is still written
- [ ] `plans/README.md` status row updated

## STOP conditions

- A test or in-tree caller depends on setting `Content-Length` or `Transfer-Encoding` through this encoder. Update that caller to pass the body and let the encoder set the length. If the caller needs a real chunked body, stop and report. Do not keep the caller-controlled length.
- Rejecting `Host` looks necessary. It is not. Keep the override.
- You would need to change `reserved_header` in `shared:async/http`. Call `header_reserved` from surf instead.

## Maintenance notes

- Reviewers should check that the body write in `buffered_http_exchange` is unchanged and that the length digits match `len(body)` or `upload_size`.
- A callback that sent its own `Content-Length` will now get `.Reserved_Header`. That is the security fix.
