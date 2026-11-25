# Plan 023: Tests cover certificate-name rejection and HTTP/3 cancel

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat a552088..HEAD -- src/http2.odin src/http3.odin tests/internal/http2_test.odin tests/internal/http3_request_test.odin tests/internal/http3_policy_test.odin`
> Plan 014 may have changed HTTP/3 deadline assertions. Keep those. Stop if `http_client_cancel` or `server_name = url.host` no longer exists.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED
- **Depends on**: plans/009-step-import.md, plans/014-http3-deadline-error.md
- **Category**: tests
- **Planned at**: commit `a552088`, 2026-11-25
- **Executor**: `claude:sonnet` — tests around the existing loopback peers
- **Fallback executor**: `codex`

## Why this matters

`execute_tls` sets `server_name` to the URL host before the handshake (`src/http2.odin` around line 380). `tests/internal/http2_test.odin` asserts an untrusted root (`wrong-root.pem` → `.TLS_Failed`, `.Not_Sent`) and never presents a trusted certificate whose name is not the URL host. HTTP/3 tests use the matching localhost certificate. `tests/internal/http3_policy_test.odin` returns success with no `testing.expect` when `H3_PEER_PORT`, `H3_PEER_CERT`, and the body env vars are unset, so those procedures pass under `task test` without running. Hostname mismatch is asserted only for async WebSocket (`tests/internal/websocket_async_test.odin` around line 492).

`http_client_cancel` is asserted on an HTTP/2 `/cancel` peer (`tests/internal/http2_test.odin` around line 182). Nothing sets `http3 = true` and cancels. A cancel that never reaches QUIC, or that is reported as a dial or TLS failure, stays green.

## Current state

- `src/http2.odin` sets `settings.server_name = url.host` before `http_tls_connect`.
- `src/http3.odin` passes `url.host` into the client exchange. `execute_internal` installs `http_client_h3_cancelled` when the call came from `http_client_multiplex` (`src/http2.odin` around line 206). `Client_Request.cancel` is `config._http3_cancel` (`src/http3.odin:134`).
- `tests/internal/http3_policy_test.odin` early-returns when the peer env is unset (around lines 144, 172, and 205).
- Plan 003 deletes tracked private keys and mints them in process. Do not add a new `.pem` private key. Use `tests/loopback/cert.odin` or the mint helper the HTTP/3 tests already use. `tests/testdata/credentials/key.pem` and `tests/http3/rsa2048.pem` are PKCS#8 private keys. Do not print them. Do not copy them into a new file.
- `tests/internal/` is package `surf` under the `tools/test` overlay.

Conventions in `AGENTS.md`: one blank line after a closing brace before the next statement. No blank line before `else`. A disposal `defer` stays on the line after the `if` that checked the allocation. The existing tests use that shape (`if bare == nil` then `defer free(bare)`). Match it. Tabs. One statement per line. Omit an import name that repeats the last element of the path. Do not reformat unrelated tests. Do not push. Do not add gates to `task test`.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| New tests | `ODIN=$HOME/dev/oss/Odin/odin PACKAGE=. INTERNAL=1 task test -- -define:ODIN_TEST_NAMES=http_execute_rejects_a_certificate_for_another_name,http3_exchange_rejects_a_different_anchor,http_client_cancel_aborts_http3 -define:ODIN_TEST_THREADS=1` | exit 0 |
| No silent skip | `rg -n 'H3_PEER_PORT' tests/internal/http3_policy_test.odin` | either no early `return` that skips `testing.expect`, or the procedure calls `testing.fail` |

## Scope

**In scope**:

- `tests/internal/http2_test.odin`
- `tests/internal/http3_request_test.odin`
- `tests/internal/http3_policy_test.odin`
- `tests/loopback/` only if a mint helper needs a name parameter it already almost has

**Out of scope**:

- `src/` production code. If a test fails because the client accepts the wrong name, stop and report. Do not "fix" the handshake in this plan.
- A new tracked private key
- Sync WebSocket frame coverage and an HTTP/2 or HTTP/3 tunnel peer. That was a separate, larger gap and is not this plan.
- Folding `tests/gates` into `task test`
- Wall-clock sleeps tighter than the client timeout. The existing 1500ms / 4s bound is not yours to rewrite unless your new test would be flaky without a stub resolver.

## Git workflow

- Branch: `advisor/023-tls-cancel-tests`
- Commit: `test: reject the wrong certificate name and a cancelled HTTP/3 exchange`
- Do not push.

## Steps

### Step 1: Certificate name on the blocking client

Add `http_execute_rejects_a_certificate_for_another_name` next to the wrong-root test in `tests/internal/http2_test.odin`.

Mint a certificate whose DNS name is `other.example` and whose key stays in process. Trust that certificate. `execute` a URL whose host is `localhost` (or the loopback name the peer actually presents) against the existing loopback peer, with that trust anchor and `server_name` left empty so the client sets it from the URL host. Expect `.TLS_Failed`, `write_effect == .Not_Sent`, and no request recorded by the peer.

If the loopback peer's certificate is hardcoded to `localhost` and the client connects to `127.0.0.1`, use a hostname the dialer can resolve to the peer without the public DNS. The address-policy tests already have a stub resolver. Use it. Do not depend on `localhost` being special in the system hosts file beyond what the existing HTTP/2 tests already assume. If those tests use `localhost`, you may too.

**Verify**: the filtered test exits 0. Temporarily pointing trust at the peer's own anchor should make this test fail. You do not have to leave it failing. Run it once the right way before you finish.

### Step 2: HTTP/3 anchor mismatch, and no skipped success

Add `http3_exchange_rejects_a_different_anchor`. Trust a minted anchor that is not the listener's. Expect `.IO_Failed` and phase `.TLS` (`http3_map_error` maps `.Certificate` that way). `write_effect` is `.Not_Sent` if the handshake fails before send.

In `http3_policy_test.odin`, replace each early `return` that skips the body when `H3_PEER_PORT` or `H3_PEER_CERT` is unset. Call `testing.fail(t, "H3_PEER_PORT is required")` or, better, use the in-process listener the other HTTP/3 tests use and delete the env dependency. A pass with no `testing.expect` is not allowed. If the in-process listener cannot serve that case, `testing.fail` is the temporary result and you must say so in the commit. Prefer the in-process listener.

**Verify**: `rg -n 'return$' tests/internal/http3_policy_test.odin` does not show a return that happens before any `testing.expect` solely because an env var is missing.

### Step 3: Cancel an in-flight HTTP/3 exchange

Add `http_client_cancel_aborts_http3`. Start one `http_client_exchange` with `http3 = true` against the in-process listener. Set the cancel flag from the listener once the handler is entered (`http_client_cancel`). Expect `.IO_Failed`, phase `.Cancellation`, and `net.Connection_Error.Cancelled`.

The pre-dial check at `src/http.odin:197` returns that error if the flag is already set. The test must set the flag after the exchange has started, not before `http_client_exchange` is called. Use the listener's entry as the signal. A short client timeout is a backstop so a missed cancel fails as a deadline rather than hanging the suite. Do not assert on that deadline. If you only observe `.Deadline_Failed`, the cancel did not land. Fix the test.

**Verify**: the three named tests exit 0 under `task test`.

## Test plan

- Wrong name, trusted anchor, no request bytes: `.TLS_Failed`, `.Not_Sent`.
- HTTP/3 different anchor: `.IO_Failed`, phase `.TLS`.
- HTTP/3 cancel after the handler starts: `.Cancellation` and `Connection_Error.Cancelled`.
- The env-gated procedures no longer pass by returning.

## Done criteria

- [ ] The three procedures exist and pass
- [ ] No new private-key file
- [ ] `http3_policy_test.odin` does not return success when the peer env is unset
- [ ] `src/` is unchanged
- [ ] `plans/README.md` status row updated

## STOP conditions

- The wrong-name handshake succeeds. Stop and report the negotiated name and the URL host. Do not weaken the assertion to the untrusted-root case. That case already exists.
- Cancel before any QUIC packet is the only signal you can find. That only tests `src/http.odin:197`. Stop and report. Do not rename that test to claim an in-flight cancel.
- The in-process HTTP/3 listener is too flaky to finish a handshake. One retry inside the test is enough. Do not loop.

## Maintenance notes

- Plan 003 may replace on-disk keys with in-process keys. Use the mint helper, not `key.pem`.
- A future change that clears `server_name` or maps HTTP/3 `.Certificate` to `.Protocol` fails these tests.
