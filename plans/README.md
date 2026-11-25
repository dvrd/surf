# Implementation Plans

Plans 001–008 were written on 2026-11-24 against commit `6209fc3` and the dirty tree of that day. Plans 009–024 were written on 2026-11-25 against commit `a552088` (`a552088ff92067c07fca5c87868933eb8057de22`). Read the plan you are executing. Its drift check is the one that applies.

`AGENTS.md` holds the layout rule and the import rule for every code edit. Each of 009–024 repeats them. Follow the copy inside the plan you are executing. An import name that repeats the last element of its path is omitted. `import "core:path"` is the form. A name that differs from that element stays, as in `import deflate "shared:async/compress/step"`.

Do not push. Do not restore the deleted Python or Go harnesses. Do not add `tests/gates/` to `task test`. Do not pass `-strict-style` or `-vet`. A `task test` child that exits 1 or 2 makes go-task exit 201. That wrapper status is expected. A passing run exits 0.

## Execution order and status

Run 009 and 010 first. They do not share files. After 009, plans that name different files may run together. Plans that name the same file run in the order in the dependency notes.

| Plan | Title | Pri | Effort | Depends on | Executor | Status |
|------|-------|-----|--------|------------|----------|--------|
| 009 | `task test` compiles against `shared:async/compress/step` | P1 | S | — | `claude:haiku` (`grok:fast`) | DONE |
| 010 | Plans 001 and 008 no longer contradict `a552088` | P1 | S | — | `claude:haiku` (`grok:fast`) | DONE |
| 011 | Blocking WebSocket dial honors `handshake_timeout` and rejects `h2` | P1 | S | 009 | `claude:sonnet` (`codex`) | DONE |
| 012 | `websocket_dial` returns the DNS or TCP error it stored | P1 | S | 011 | `claude:sonnet` (`codex`) | DONE |
| 013 | A failed HTTP/2 WebSocket open releases the lane | P1 | S | 009 | `claude:sonnet` (`codex`) | DONE |
| 014 | An HTTP/3 budget expiry stays a deadline | P1 | S | 009 | `claude:sonnet` (`codex`) | DONE |
| 015 | The buffered HTTP/1 encoder rejects caller framing | P1 | S | 009 | `claude:opus` (`codex`) | DONE |
| 016 | An empty async DNS ID bank is a DNS failure | P1 | M | 009 | `claude:opus` (`codex`) | DONE |
| 018 | `address_policy` sees every resolved address | P1 | M | 016 | `claude:opus` (`codex`) | DONE |
| 017 | Resolver-snapshot failures keep their own DNS errors | P2 | S | 016 | `claude:sonnet` (`codex`) | DONE |
| 020 | HTTP/2 does not index authorization or cookie | P2 | S | 009 | `claude:sonnet` (`codex`) | TODO |
| 021 | HTTP/2 TLS alerts and tunnel timeouts use the shared phase rules | P2 | S | 013 | `claude:sonnet` (`codex`) | TODO |
| 019 | A live HTTP/3 lane does not resolve again | P2 | S | 014, 018 | `claude:sonnet` (`codex`) | DONE |
| 022 | An HTTP/2 upload rejects a count outside the buffer | P2 | S | 020, 021 | `claude:sonnet` (`codex`) | TODO |
| 023 | Tests cover certificate-name rejection and HTTP/3 cancel | P2 | M | 009, 014 | `claude:sonnet` (`codex`) | TODO |
| 024 | A redirect hop does not copy the request body | P2 | M | 018 | `claude:opus` (`codex`) | TODO |
| 008 | Surf imports HTTP from `shared:async/http` | P1 | M | — | — | DONE |
| 001 | The library type-checks against public `tls.Error` and `net.Network_Error` | P1 | L | 009, 010 | — | BLOCKED |
| 002 | HTTP/3 uses the same header and handshake-failure contract as HTTP/2 | P1 | M | 009, 013, 019, 021 | — | TODO |
| 003 | Test private keys are minted in the process | P1 | M | 009 | — | TODO |
| 005 | A streamed identity body is copied once | P2 | M | 009 | — | TODO |
| 004 | The seven older gates share one build and one failure path | P2 | M | 001, 009 | — | TODO |
| 006 | The pin file records the shared commits `task test` compiles | P3 | S | 009 | — | TODO |
| 007 | A short note names the clients and how to run a gate | P3 | S | — | — | TODO |

Status values: TODO | IN PROGRESS | DONE | BLOCKED (with one-line reason) | REJECTED (with one-line rationale).

The parenthetical after an executor is the fallback. Plans 001–008 do not name an executor in the plan file. 008 is not re-executed. For 001–007, use `claude:sonnet` with fallback `codex`, except 006 and 007, which are `claude:haiku` with fallback `grok:fast`.

008 is done at `a552088`. The contradiction has been removed. Do not re-execute 008 and do not revert `src/`.

001 is blocked on the gate, testdata, and `tests/stream104` residue. The library port is already in `a552088`. Plan 009 is done. Plan 004 owns the shared gate helper. 001 owns the type errors in those programs.

## Dependency notes

- 009 is the compile gate. Any plan whose done criteria run `task test` waits on it, including the residue of 001 and plans 002, 003, 004, 005, and 006. 010 is prose only and can run beside 009.
- 010 lands before anyone executes 001. It also rewrites 008 so the file matches HEAD. After 010, 008 stays DONE and is not a work item.
- 001 and 008 record the port at `a552088`. `Config.tls` is `shared:async/tls.Config`, and HTTP/3 forwards `session_cache`, `client_credentials`, and `client_credential_lease`. Do not revert `src/`.
- Same file, in this order, and never at the same time:
  - `src/websocket.odin`: 011, then 012.
  - `src/async/coordinator.odin`: 016, then 017.
  - `src/async/session.odin`: 016, then 018, then 024.
  - `src/http3.odin`: 014, then 018, then 019. Plan 002 edits this file too, so it runs after 019.
  - `src/http2_websocket.odin`: 013, then 021. Plan 002 edits this file too, so it runs after 021.
  - `src/http2.odin`: 020, then 021, then 022. 021's lane work is in `src/http2_websocket.odin`; its phase change is `h2_tls_error` in `src/http2.odin`.
- 015 edits `src/buffered.odin` only. It can run beside the chains above once 009 has landed.
- 023 adds tests. It can run beside other plans once 009 and 014 have landed. It must not edit the production mapping that 014 owns.
- 002, 003, and 005 no longer wait on the library half of 001. They still wait on 009 before `task test` can pass. 002 also waits on 013, 019, and 021 so it does not land on top of excerpts those plans were written against.
- 004 builds gates that import `surf`. It waits on 001's remaining gate port and on 009. It does not edit `src/`.
- 006 runs after 009 and after a passing `task test` on the machine whose symlinks you pin. Delete the standalone `http` object in `.krs/packages.json`. The async pin covers that library. Keep websocket. If any `*.odin` file still imports `shared:http` without `shared:async/http`, stop.
- 007 creates `README.md` only. It does not edit `AGENTS.md`. It must not mention `tls_dial` or `tls_io`. It can be written at any time. `task test` is not its done check.

## Findings considered and rejected

Recorded on 2026-11-24, still in force:

- `fec0::1`, a nil `address_policy`, and the pool-reuse skip are deliberate. The nil policy and the pool-reuse skip are documented on `Config`.
- Scanning HTTP/1 headers one byte at a time in `response_read_header`. The header cap is 16 KiB.
- Folding `tests/gates/` into `task test`, restoring Python or Go harnesses, porting `foundations101`, or adding a TLS 1.2 compatibility cell.
- Treating HTTP/3 `connection` and `transfer-encoding` as bytes on the wire. `section_check` in `shared:async/http` rejects them before a successful encode. Plan 002 still rejects them in surf so the error is `Invalid_Input`, and it stops `host`, which `section_check` does not reject.
- Adding CI or `odinfmt` as its own plan. Plan 007 records that neither config exists.

The four ranges widened in `a552088` are already refused by `address_policy_public_only`: `0.0.0.0/8`, `100.64.0.0/10`, `224.0.0.0/4` (which covers `240.0.0.0/4`), and `64:ff9b::/96`. Do not file them again. The older note that listed `240.0.0.1`, `0.0.0.1`, and `100.64.0.1` as allowed is out of date.

Recorded on 2026-11-25 and rejected:

- Refusing more addresses than the policy refuses today: `64:ff9b:1::/48`, `2002::/16`, `192.0.0.0/24`, `198.18.0.0/15`, and documentation prefixes. `203.0.113.1`, `fec0::1`, and `64:ff9b:1::` stay allowed. `tests/address_policy_dial_test.odin` locks that list.
- A geometric resize inside `websocket.message_prepare`. That procedure is not in this repository.
- The copy of the tree inside `tools/test` (about 4.6 MB). The overlay is how private tests compile.
- The second 64 KiB copy on the buffered reply path.
- Another test suite for dial policy, redirects, HTTP/2, body ownership, budgets, or async WebSocket frames. Those behaviors already have tests. Plans 011, 012, and 023 add the cases that do not.
- Deleting `session_tls_network`, or folding `budget_tick` and `websocket_async_deadline_tick` into one helper.
- A deadline-sleep flake in the internal suite. The internal overlay passed 35 tests.

Offered as direction on 2026-11-25 and not selected. Do not write a plan for these unless the maintainer asks:

- Let a pooled `HTTP_Client` send one `Upload_Source` through the existing `h2_exchange_once`. Keep `max_redirects == 0`. Leave multiplex without upload.
- Honor `max_redirects` on pooled TCP and TLS lanes. It is honored on the HTTP/3 branch today and ignored on those lanes. Multiplex stays one origin and does not follow redirects.
- Store the trailers HTTP/1 and HTTP/2 already parse onto `Response.trailers`. Request trailers stay HTTP/3-only.
- Refuse `http3` when an async client is created. The knobs are stored and then ignored. A real async QUIC exchange is separate work.

Also left as designed, from the earlier pass: an opt-in public-only address policy as the default, async HTTP/2, and an HTTP/3 pool owned by `HTTP_Client`.
