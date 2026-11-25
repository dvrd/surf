# Plan 008: Surf imports HTTP from shared:async/http

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: Excerpts are from the working tree on
> 2026-11-24, while `HEAD` was `6209fc3`. A clean
> `git diff 6209fc3..HEAD` does not mean the excerpts match.
>
> ```
> git diff --stat 6209fc3..HEAD -- src tests tools/test
> git diff --stat -- src/http.odin src/http2.odin src/http3.odin src/http2_websocket.odin
> ```
>
> Confirm `src/http.odin` still imports `shared:http` and `Config.tls` is
> still `tls.Config` from `core:crypto/tls`. If every `*.odin` import already
> says `shared:async/http` and `odin check src` has no error except the
> plan 001 shapes listed in Done criteria, stop and report that this plan
> is already done.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: none
- **Category**: migration
- **Planned at**: commit `6209fc3`, 2026-11-24

## Why this matters

`shared:http` is going away. The HTTP library now lives inside the async
checkout, at `shared:async/http`. Surf, its tests, and its gates still
import `shared:http`, `shared:http/v1`, `shared:http/v2`,
`shared:http/v2/hpack`, `shared:http/v3`, and `shared:http/exchange`.
Those paths will not resolve once the standalone collection entry is
removed.

The moved tree is the same HTTP code with different imports. Procedure
names are unchanged. A few parameter and field types are not: HTTP/2 data
chunks and the `shared:http/exchange` scope are the async budget packages,
and HTTP/3 credential and session-cache fields are `shared:async/tls`.
Surf's own `Config.tls` stays `core:crypto/tls`. This plan retargets the
imports and the values that cross that boundary. It does not retarget
surf's HTTP/1 TLS stack, and it does not repair the private TLS `.kind`
errors. Those belong to plan 001.

## Current state

Collection layout on 2026-11-24:

- `$HOME/dev/oss/Odin/shared/async` → `/Users/kakurega/dev/projects/async/src`
- That repo's HEAD prefix was `0ca47a7` (`Merge pull request #2 from dvrd/develop`). The HTTP sources are `src/http/`, brought in by `b494666`. If the clone has moved, use the tree you have. Do not edit it.
- `$HOME/dev/oss/Odin/shared/http` → `/Users/kakurega/dev/projects/http/src`, HEAD prefix `3e9c009`.
- `diff -rq` of those two `src` trees: 16 files differ, and every changed line is an import. Package names stay `http`, `v1`, `http2`, `hpack`, `http3`, `exchange`.

Imports the moved files use, where the old files used `core`:

- `shared:async/http` and `shared:async/http/v2/hpack`
- `shared:async/mem/budget`, `shared:async/mem/owned`, `shared:async/sync/budget`
- `shared:async/tls`, `shared:async/tls/credentials/store`
- `shared:async/quic`, `shared:async/quic/conn`, `shared:async/quic/ecn`, `shared:async/quic/idle`

`http.odin`, `v2/frame.odin`, `v2/headers.odin`, `v2/ascii.odin`, and `hpack` did not differ. `section_check` is still `async/src/http/v3/frame.odin:491`. Do not edit it.

Surf imports to retarget. On 2026-11-24 `rg -n '"shared:http' --glob '*.odin'` listed these files. If the command lists more, retarget those too. If it lists fewer because a file was deleted, skip the missing file.

- `src/http.odin`, `src/buffered.odin`, `src/upload.odin`, `src/http2.odin`, `src/http2_websocket.odin`, `src/http3.odin`
- `src/async/pool.odin`, `src/async/stream.odin`, `src/async/coordinator.odin`, `src/async/redirect.odin`, `src/async/client.odin`, `src/async/session.odin`, `src/async/stream/stream.odin`, `src/async/exchange/exchange.odin`
- `tests/address_policy_dial_test.odin`, `tests/address_policy_test.odin`, `tests/outcomes_test.odin`, `tests/budget_test.odin`
- `tests/async/exchange/internal/exchange_test.odin`, `stream_footer_test.odin`, `stream_encoding_test.odin`
- `tests/async/internal/redirect_prepare_test.odin`, `ownership_test.odin`, `concurrency_test.odin`, `client_test.odin`, `config_test.odin`
- `tests/internal/http2_retirement_test.odin`, `http3_request_test.odin`, `buffered_h2_headers_test.odin`, `http3_capacity_test.odin`, `http2_test.odin`, `http3_policy_test.odin`, `http3_websocket_test.odin`
- `tests/stream104/main.odin`
- `tests/testdata/session_actor101/main.odin`, `kernel101/main.odin`, `consumer101/main.odin`, `client101/main.odin`, `pool101/main.odin`, `uploads/main.odin`, `budgets/main.odin`, `redirect101/main.odin`

`tools/test/stage.odin` records a `shared:` import by the identifier
characters after `shared:` (`is_ident` allows letters, digits, and `_`,
so it stops at `/`). `shared:async/http` is library `async`. Surf already
imports `shared:async`, and the staged `async` directory contains `http/`.
Do not edit `tools/test`.

Types that will not assign after the path rewrite:

```odin
// src/http2.odin:11 and src/http2_websocket.odin
import owned "core:mem/owned"
```

`h2.connection_send_data` (`async/src/http/v2/send.odin:195`) takes
`source: ^owned.Chunk` where that `owned` is `shared:async/mem/owned`.
Surf passes `&job.chunk` (`src/http2.odin:1158`) and the websocket chunks
(`src/http2_websocket.odin:422` and `:504`). `H2_Job.chunk` is
`owned.Chunk` (`src/http2.odin:86`). `connection_init` is called without
a scope (`src/http2.odin:642`). Leave that call as it is. The zero scope
is the http2 package's own `shared:async/sync/budget.Scope`.

```odin
// async/src/http/v3/application.odin:66
Client_Request :: struct {
	session_cache:             ^tls.Session_Cache,          // shared:async/tls
	client_credentials:        ^credential_store.Store,     // shared:async/tls/credentials/store
	client_credential_lease:   ^credential_store.Lease,
	...
}
```

Surf fills those from core TLS:

```odin
// src/http3.odin:133
wire := http3.Client_Request {
	session_cache           = config.tls.session_cache,
	...
	client_credentials      = config.tls.client_credentials,
	client_credential_lease = config.tls.client_credential_lease,
	...
}
```

The websocket opener repeats the credential pair at `src/http3.odin:788`.
`Config.tls` is `tls.Config` from `core:crypto/tls` (`src/http.odin:44`).
No file in this repo sets `client_credentials` on a surf `Config` that
also sets `http3 = true`. HTTP/2 still reads the core store through
`http_identity_acquire` (`src/http2.odin:1761`). Do not change that.

`http3.Live_Config.credentials` is `^credential_store.Store` from
`shared:async/tls/credentials/store` (`async/src/http/v3/server.odin:114`).
`tests/internal/http3_request_test.odin:70` and
`tests/internal/http3_capacity_test.odin:37` build that store with
`core:crypto/tls/credentials` and `core:crypto/tls/credentials/store`,
then assign `credentials = owner`. `pool_connect_open` still takes
`roots: []^x509.Certificate` from `core:crypto/x509`
(`async/src/http/v3/client.odin:2715`). `config.tls.root_cas` stays core.
`credentials.create` in the async package has the same shape: chain PEM,
key PEM, limits, allocator, returning `(^Credential, Error)`.

`tests/budget_test.odin` is the only surf file that imports
`shared:http/exchange`. `exchange.init` takes `exchange.Config.scope` of
type `shared:async/sync/budget.Scope` (`async/src/http/exchange/exchange.odin:45`).
`exchange.submit` (`:239`) takes `^owned.Chunk` from `shared:async/mem/owned`.
`surf.exchange` takes `core:sync/budget.Scope` (`src/http.odin:617`).
`response_take_body` returns `core:mem/owned.Chunk` (`src/http.odin:1387`).
The third test in `tests/budget_test.odin` submits that core chunk into
the exchange package and asserts one scope hierarchy was not charged
twice. Those two budget packages are no longer the same package. Do not
change `Config.scope` or `response_take_body` to paper over that.

Odin style in this repo: tabs, one statement per line, a comment only for
a constraint the next reader cannot see. `src/http2.odin` is the file
whose `owned` import you are switching. Match its import block. Do not
reformat unrelated lines.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Old imports | `rg -n '"shared:http' --glob '*.odin'` | no output, exit 1 |
| Check src | `odin check src tests/internal -collection:shared:$HOME/dev/oss/Odin/shared -warnings-as-errors` | exit 0, or only the plan 001 errors named in Done criteria |
| Package tests | `odin check tests -collection:shared:$HOME/dev/oss/Odin/shared -warnings-as-errors` | exit 0, or the same plan 001 errors only. If `shared:surf` does not resolve, stop this command and report that. Do not create a symlink. |

`odin check` writes under the default build cache. That is fine. Do not
pass `-build-mode:exe` or an `-out:` path. Do not run `task test`. It
cannot pass until plan 001, and a failure there is not a signal to edit
TLS types.

## Scope

**In scope**

- Every `*.odin` file under `src/`, `tests/`, and `tests/testdata/` whose import path contains `shared:http`.
- `src/http2.odin` and `src/http2_websocket.odin`, the `owned` import only, plus any compile error in those files that names `owned.Chunk`.
- `src/http3.odin`, the two `Client_Request` literals only.
- `tests/internal/http3_request_test.odin` and `tests/internal/http3_capacity_test.odin`, the credential imports and the `credentials = owner` assignment only.
- `tests/budget_test.odin`, the exchange import and the third test procedure only.

**Out of scope**

- `/Users/kakurega/dev/projects/async` and `/Users/kakurega/dev/projects/http`. Do not edit either HTTP tree.
- `/Users/kakurega/dev/oss/Odin`.
- `Config.tls`, `core:crypto/tls`, `http_identity_acquire`, `tls_read`, `tls_write`, `HTTP_Error.tls_dial`, `HTTP_Error.tls_io`. Plan 001 owns those.
- `Config.scope`, `response_take_body`, and the `core:mem/budget`, `core:mem/owned`, and `core:sync/budget` imports in `src/http.odin` and under `src/async/`.
- `tools/test/**`, `Taskfile.yml`, `.krs/packages.json`, `.gitignore`.
- `tests/gates/**` except an import line that still says `shared:http`. Do not change gate assertions or flags.
- Header filtering, private-key fixtures, stream copies, and the README. Other plans own those.

## Git workflow

- Branch: `advisor/008-async-http`
- The worktree is already dirty with unrelated edits (`src/*.odin` TLS fields, `Taskfile.yml`, deleted Python, untracked `tools/` and `tests/gates/`). Do not `git restore`, `git clean`, or `git add -A`. Commit only the files this plan changed.
- Subject: `fix: import HTTP from shared:async/http`
- Do not push. Do not commit inside the async or http clones.

## Steps

### Step 1: Retarget the import paths

In every in-scope `*.odin` file, replace import paths longest-first so a
short prefix is not applied twice:

- `shared:http/v2/hpack` → `shared:async/http/v2/hpack`
- `shared:http/exchange` → `shared:async/http/exchange`
- `shared:http/v1` → `shared:async/http/v1`
- `shared:http/v2` → `shared:async/http/v2`
- `shared:http/v3` → `shared:async/http/v3`
- `shared:http` → `shared:async/http`

Replace only the path string. Keep the local alias (`http`, `h2`, `hpack`,
`http1`, `h3`, `http3`, `exchange`). Do not rewrite `shared:async` or
`shared:async/connection`. Those already point at the runtime.

**Verify**: `rg -n '"shared:http' --glob '*.odin'` prints nothing.
`rg -n 'shared:http' --glob '*.odin'` may print `shared:async/http` lines.
Every printed line must contain `shared:async/http`. A line that contains
`shared:http` and does not contain `shared:async/http` is a miss. Fix it
before step 2.

### Step 2: Pass HTTP/2 body chunks as shared:async/mem/owned

In `src/http2.odin` and `src/http2_websocket.odin`, change

```odin
import owned "core:mem/owned"
```

to

```odin
import owned "shared:async/mem/owned"
```

Leave every call the same, including `owned.allocate`, `owned.copy_bounded`,
`owned.destroy`, and `h2.connection_send_data(..., &chunk, ...)`. Both
files must use the same `owned`. Do not switch `tls_api "core:crypto/tls"`
in `src/http2.odin`.

**Verify**: `rg -n 'core:mem/owned' src/http2.odin src/http2_websocket.odin`
prints nothing. The `odin check` command in the table is run in step 5,
not here.

### Step 3: Stop copying core TLS credentials into HTTP/3 requests

In both `http3.Client_Request` literals in `src/http3.odin` (the one in
`execute_http3` and the one in the websocket opener), delete the
assignments from `config.tls.session_cache`,
`config.tls.client_credentials`, and
`config.tls.client_credential_lease`. Omitting them leaves the async
pointers nil. Above each literal, add this comment and no other:

```odin
// HTTP/3 credentials and the session cache are shared:async/tls. Config.tls is still core.
```

Do not add new fields to `Config`. Do not cast the core pointers. Do not
change `root_cas`, `http3_qpack`, or `http3_ecn`.

**Verify**: `rg -n 'config\.tls\.(session_cache|client_credentials|client_credential_lease)' src/http3.odin`
prints nothing. `rg -n 'client_credentials' src/http2.odin` still prints
`http_identity_acquire`.

### Step 4: Build the HTTP/3 test listener credentials with the async store

In `tests/internal/http3_request_test.odin` and
`tests/internal/http3_capacity_test.odin`, change the credential imports
from `core:crypto/tls/credentials` and `core:crypto/tls/credentials/store`
to `shared:async/tls/credentials` and
`shared:async/tls/credentials/store`. Keep the alias `store` and the
unaliased `credentials` name. Leave `import "core:crypto/tls"` in place.
Leave `tls.root_pool_parse` and the `.kind` comparison on its result
alone. That comparison is plan 001.

Keep `credentials.create(#load(...), #load(...), {}, context.allocator)`
and `store.create({}, context.allocator)`. Keep `credentials = owner` on
the listener config.

**Verify**: `rg -n 'core:crypto/tls/credentials' tests/internal/http3_request_test.odin tests/internal/http3_capacity_test.odin`
prints nothing. `rg -n 'core:crypto/tls"' tests/internal/http3_request_test.odin` still prints the core TLS import.

### Step 5: Keep the budget handoff compiling without merging the two scope packages

In `tests/budget_test.odin`, the import from step 1 is
`import exchange "shared:async/http/exchange"`. Add:

```odin
import http_owned "shared:async/mem/owned"
import http_scopes "shared:async/sync/budget"
```

Do not edit the first two test procedures. They use `surf.exchange` and
`response_take_body` only.

In `surf_body_moves_to_sibling_http_exchange_without_charging_common_ancestors_twice`:

- Keep the surf fetch on core scope `a`, the `response_take_body`, and the `charged.allocation_info` check.
- Drop core scope `b`. It existed to receive the surf chunk. Drop its `create_child` and its `release_scope`. Leave `root`, `conn`, and `a`.
- After the surf chunk is taken, copy its bytes and submit the copy:

```odin
moved, copy_error := http_owned.copy_bounded(chunk.data, len(chunk.data), allocator)
assert(copy_error.kind == .None)
http_root, http_root_error := http_scopes.create_root({bytes = 65536, streams = 1}, allocator)
assert(http_root_error == .None)
http_scope, http_scope_error := http_scopes.create_child(http_root, {bytes = 65536, streams = 1})
assert(http_scope_error == .None)
ex: exchange.Exchange
assert(exchange.init(&ex, .GET, {scope = http_scope}, allocator).kind == .None)
assert(exchange.respond(&ex, {status = 200, content_length = 4}).kind == .None)
assert(exchange.submit(&ex, &moved) == .Accepted)
testing.expect(t, moved.allocator.procedure == nil && moved.data == nil)
bytes, available := exchange.body(&ex)
assert(available)
testing.expect_value(t, string(bytes), "body")
assert(exchange.finish(&ex).kind == .None)
assert(exchange.release_body(&ex))
assert(exchange.complete(&ex).kind == .None)
exchange.destroy(&ex)
http_scopes.release_scope(&http_scope)
http_scopes.release_scope(&http_root)
owned.destroy(&chunk)
```

- Delete the assertions that `budget_usage(root)`, `budget_usage(conn)`, `budget_usage(a)`, or `budget_usage(b)` stay flat across `exchange.submit`. Those scopes are not the exchange scope anymore.
- Keep the final `budget_usage(root)` zero checks and the tracking-allocator zero check, after the core scopes are released.
- Rename the procedure to `surf_body_bytes_round_trip_through_the_async_http_exchange`. The old name describes a shared ancestor this package split no longer has.

Use the file's existing core `owned` import for `owned.destroy(&chunk)`.
Do not pass `&chunk` to `exchange.submit`.

**Verify**: `rg -n 'exchange.submit\(&ex, &chunk\)' tests/budget_test.odin` prints nothing.

### Step 6: Type-check

Run the `odin check src tests/internal` command from the table, then the
`odin check tests` command.

Plan 001 errors, which you must not fix in this plan:

- a field or variable typed `tls.Dial_Error`, `tls.IO_Error`, or `tls.Handshake_Error`
- `.kind` on the result of `root_pool_parse`, `root_pool_load_file`, `tls.dial`, `tls.read`, `tls.write`, or any other `tls.Error`
- `{kind = .Timeout}`, `{kind = .Read_Failed}`, or `{kind = .Write_Failed}` where the destination is `net.Network_Error`

Any other error is in scope. Fix it only when it is one of these, and
only in the way the earlier step said:

- `owned.Chunk` mismatch on an HTTP/2 send: the `owned` import in that file must be `shared:async/mem/owned`
- `credential_store.Store`, `Lease`, or `Session_Cache` mismatch on a `Client_Request` or `Live_Config`: steps 3 and 4
- `exchange.Config.scope` or `exchange.submit` chunk mismatch in `tests/budget_test.odin`: step 5

**Verify**: the check commands match the table. Save nothing into the repo from the compiler output.

## Test plan

- No new test file.
- The renamed procedure in `tests/budget_test.odin` is the regression for the exchange import: an async-owned copy of the surf body is accepted by `exchange.submit` and `exchange.body` returns `body`.
- The two HTTP/3 listener tests keep their existing assertions. They now construct the listener store with `shared:async/tls/credentials/store`.
- Do not run the gates. Do not run `task test`.

## Done criteria

- [ ] `rg -n '"shared:http' --glob '*.odin'` prints nothing
- [ ] Every `rg -n 'shared:http' --glob '*.odin'` hit contains `shared:async/http`
- [ ] `src/http2.odin` and `src/http2_websocket.odin` import `owned` from `shared:async/mem/owned`
- [ ] `src/http3.odin` does not read `config.tls.session_cache`, `config.tls.client_credentials`, or `config.tls.client_credential_lease`
- [ ] `Config.tls` in `src/http.odin` is still `core:crypto/tls.Config`
- [ ] `src/http.odin` still imports `core:mem/owned`, `core:mem/budget`, and `core:sync/budget`
- [ ] `odin check src tests/internal -collection:shared:$HOME/dev/oss/Odin/shared -warnings-as-errors` exits 0, or its only errors are the plan 001 shapes listed in step 6
- [ ] `tools/test` is unmodified
- [ ] No file under `/Users/kakurega/dev/projects/async` or `/Users/kakurega/dev/projects/http` is modified
- [ ] `plans/README.md` status row updated

## STOP conditions

- `Config.tls` would have to become `shared:async/tls.Config` for a call to compile. Report the call. Do not switch the package.
- A fix would retarget `core:mem/budget`, `core:mem/owned`, or `core:sync/budget` in `src/http.odin` or anywhere under `src/async/`.
- `h2.connection_init` no longer accepts a composite literal that omits `scope`.
- `credentials.create` or `store.create` in `shared:async/tls` does not accept the call shape this plan quotes.
- An `odin check` error is not a plan 001 shape and is not one of the three mismatches in step 6.
- The code at the excerpts does not match, other than import paths you already rewrote in an earlier step of this plan.
- You would edit `tools/test`, `Taskfile.yml`, or a sibling repository.

## Maintenance notes

- HTTP/3 client certificates and session resumption configured on `Config.tls` are no longer forwarded. HTTP/2 still uses that core store. Wiring HTTP/3 client auth means a later change of `Config.tls` to `shared:async/tls`, which plan 001 must then target. Do not do that here.
- `tests/budget_test.odin` no longer proves that a surf body allocation and `shared:async/http/exchange` share one scope ancestor. The packages no longer share a budget implementation. A later plan can move `Config.scope` to `shared:async/sync/budget` if that proof is required again.
- Plan 006 records pins after `task test` passes. The standalone `http` object in `.krs/packages.json` describes the library this plan stops importing. Plan 006 deletes that object once `rg` shows no `shared:http` import outside `shared:async/http`. The async pin covers `http/`, `tls/`, `quic/`, `mem/`, and `sync/`.
- Reviewers should check that `shared:http` was not rewritten twice (`shared:async/async/http`) and that `core:crypto/tls` imports outside the two HTTP/3 listener tests are still core.
