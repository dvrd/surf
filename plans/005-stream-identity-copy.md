# Plan 005: A streamed identity body is copied once

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: Excerpts are from the working tree on
> 2026-11-24, `HEAD` `6209fc3`. Confirm `stream_entity_step` still copies
> identity bytes into `x.encoded` and that `stream_body_step` copies
> `x.encoded` into the channel output.
>
> ```
> git diff --stat 6209fc3..HEAD -- src/async/exchange/exchange.odin
> ```

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED
- **Depends on**: plans/001-tls-net-errors.md
- **Category**: perf
- **Planned at**: commit `6209fc3`, 2026-11-24

## Why this matters

On a content-length or EOF body, `stream_entity_step` copies the filled
read buffer into `x.encoded`. `stream_body_step` then copies that slice
into the channel output. The buffered sibling `exchange_append_body` copies
once. Chunked framing and gzip need `x.encoded` because the decoder output
is not the raw buffer. Identity framing does not. The cap on a streamed
body is large enough that the extra copy is the whole payload.

## Current state

`src/async/exchange/exchange.odin`:

`stream_entity_step` (`:1153`) returns immediately when
`x.encoded_at < x.encoded_used` or `x.entity_done`. That is what keeps a
staged slice alive across a `.Waiting` return. It refills `_read_buffer`
only when `_read_at == _read_used`. The identity arm (`:1195`) does
`copy(x.encoded[:], source[:count])` and sets `x.encoded_used`.

`stream_body_step` (`:1260`) calls `stream_entity_step` first. The comment
at `:1272` says entity step stops while any payload remains staged. The
identity arm (`:1326`) copies `source` (`x.encoded[x.encoded_at:x.encoded_used]`)
into `destination`, which is the reserved channel output or `x.discard`.

`exchange_append_body` (`:606`) is the one-copy path. Do not change it.

Gzip uses `x.decoded` and `deflate.inflate_gzip_decoder_step` on `x.encoded`.
Chunked uses `h1.chunk_decoder_feed` into `x.encoded`. Leave both.

Style: tabs, one statement per line. Match the surrounding procs. No
comment that only says a copy was removed.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Library | `odin check src -collection:shared:$HOME/dev/oss/Odin/shared -warnings-as-errors` | exit 0 |
| Async exchange tests | `task test INTERNAL=1 PACKAGE=async` from the repo root | exit 0 |

Plan 001 must have landed. If the check fails on `tls.Error` or
`Network_Error`, stop and finish 001.

## Scope

**In scope**

- `src/async/exchange/exchange.odin`
- An existing test under `tests/async/exchange/internal/` only if you can
  extend it without a new fixture program. If no test reads a streamed
  identity body, do not create a gate. The done check is the unit suite
  plus the structural rules below.

**Out of scope**

- `src/http.odin` `response_read_header` and `reader_byte`. A per-byte
  header scan was considered and rejected. Headers are capped at 16 KiB.
- Chunked decoding, gzip, and `exchange_append_body`
- `src/async/stream/stream.odin` and the channel package
- Changing `max_encoded_bytes` or `max_decoded_bytes`

## Git workflow

- Branch: `advisor/005-stream-identity-copy`
- Commit subject: `perf: copy a streamed identity body once`
- Do not push.

## Steps

### Step 1: Keep identity bytes in the read buffer until they are published

For framing that is not chunked and not decoded (`x.decoded` is false and
`base._head.framing != .Chunked`):

- Do not copy into `x.encoded`.
- Do not advance `_read_at` inside `stream_entity_step`.
- Stage the pending identity range as the unread slice
  `_read_buffer[_read_at:_read_used]`, bounded by `_body_remaining` when
  framing is `.Length`.

`stream_body_step`, when `!x.decoded` and framing is not chunked, copies
from that read-buffer slice into `destination`, then advances `_read_at`
by the number of bytes copied. `_read_at` moves only after the copy into
`destination` succeeds. A `.Waiting` return (no output slot, or a zero
destination with bytes still pending) leaves `_read_at` unchanged.

`stream_entity_step` must not call `exchange_fill` while identity bytes
are still unpublished. The existing guard is `encoded_at < encoded_used`.
Add the read-buffer equivalent for this path: if identity bytes remain
between `_read_at` and the staged end, return `.Continue` without filling.

When the staged identity slice is exhausted and framing is `.Length`,
subtract from `_body_remaining` as the current code does, and set
`entity_done` when the remainder hits zero. For EOF framing, `entity_done`
follows the existing fill result (`_phase == .Draining`).

Chunked and gzip keep the current `x.encoded` path, including the early
return when `encoded_at < encoded_used`.

**Verify**: `odin check src -collection:shared:$HOME/dev/oss/Odin/shared -warnings-as-errors` → exit 0.

### Step 2: Prove the unread bytes survive a waiting output

Read `stream_body_step` after the edit. Confirm both of these by inspection
and by a test if one already drives this exchange:

- `reserve_output` returning nil does not call `exchange_fill` on the next
  `stream_body_step` while identity bytes remain.
- The bytes copied into `destination` are the bytes that were in
  `_read_buffer`, and `_read_buffer` may be refilled only after `_read_at`
  catches the staged end.

If `tests/async/exchange/internal` has a stream or body test that feeds a
known payload, extend it to a content-length body of at least two read
buffers (the read buffer size is `READ_BUFFER_SIZE` in this file). Expect
the delivered bytes to equal the payload. If no such test exists, do not
create a network fixture. Say so in the commit body in one line.

**Verify**: `task test INTERNAL=1 PACKAGE=async` → exit 0.

## Test plan

- Extend an existing exchange internal test when it already feeds a body.
  Pattern: the file's current `@(test)` proc, not a new gate.
- If no test feeds a streamed identity body, the verification is
  `task test INTERNAL=1 PACKAGE=async` plus the structural rule that
  identity framing has one `copy` into `destination` and no `copy` into
  `x.encoded`.
- Do not change chunked or gzip tests.

## Done criteria

- [ ] `odin check src -collection:shared:$HOME/dev/oss/Odin/shared -warnings-as-errors` exits 0
- [ ] `task test INTERNAL=1 PACKAGE=async` exits 0
- [ ] The identity arm of `stream_entity_step` does not call `copy` into `x.encoded`
- [ ] The chunked arm still calls `chunk_decoder_feed` into `x.encoded`
- [ ] The gzip arm still calls `inflate_gzip_decoder_step`
- [ ] `plans/README.md` status row updated

## STOP conditions

- Identity framing also parses trailers out of `x.encoded`. Report the
  procedure. Do not drop that parse.
- `exchange_fill` can run on another thread while `stream_body_step` is
  copying `_read_buffer`. Report the caller. The read buffer is only safe
  if the same owner loop fills and publishes.
- Plan 001 has not landed and this file does not type-check for TLS or
  net error reasons.
- The only way to test is a multi-minute gate. Skip the new test and say
  so. Do not weaken an existing assertion.

## Maintenance notes

- A future change that refills `_read_buffer` before `stream_body_step`
  returns must not do so while `_read_at` is behind the staged identity end.
- Reviewers should check the `.Waiting` path leaves `_read_at` unchanged,
  and that `.Length` still sets `entity_done` only when the remainder is zero.
- The per-byte HTTP/1 header reader in `src/http.odin` is out of scope on
  purpose.
