# Public HTTP1/TLS idle checkout

Status: approved

A completed Exchange certifies the HTTP boundary only. At idle entry, all
accepted Exchange operations and callbacks must have retired, the response must
have been taken, and `reuse_eligible` must be true. On its pinned owner thread,
the actor requires `tls.async_idle_state == Ready`. Before assigning the next
request it repeats that local observation, replaces the request cap with
`connection.set_request_budget(B)`, and calls `async.probe_stream` on the
retained socket. Only `Empty` permits B. `Data`, `Closed`, any error, or any local
TLS state other than Ready retires the physical connection. No speculative read
or cancellation probe occurs; partial ciphertext and KeyUpdate records already
queued therefore cause conservative retirement without consuming old bytes.

These are point-in-time observations. A peer can close or send unsolicited data
later. The protocol assumes compliant HTTP1 response ordering and never retries
an ambiguous write. The policy does not treat a poll/readiness hint, an expired
old request cap, closed-only adapter quiescence, or private TLS fields as health.
The executor lifetime cap remains unlimited for this harness; request A and B
have separate finite caps. B is actually executed after A's old cutoff.

The independent peer uses Go's TLS13 handshake and normal application writer.
For KeyUpdate fixtures only, it obtains its own SERVER_TRAFFIC_SECRET_0 via
KeyLogWriter, independently authenticates outgoing records to establish the
application sequence, and uses RFC8446 HKDF-Expand-Label/AES128GCM records. A
KeyUpdate uses handshake bytes 18 00 00 01 01, requests a reciprocal update, updates `traffic upd`, and resets
the outbound sequence. No secret is printed or persisted. The client uses public
TLS operations and its opaque idle classifier exclusively. Healthy and inline
KeyUpdate cases require A then B on one authenticated connection; queued old
plaintext, separate ciphertext, split record, queued KeyUpdate, and peer close
must suppress B and drain close callbacks. Same-read surplus retires as well.

The executable gate requires explicit --core-root and --shared-root, copies its
consumer closure physically, binds source/copy/compiler hashes before and after,
and runs native ASan/TSan consumers. --require-idle-policy fails until this
record is approved after the actual observations and review are available.

Approval basis: root source/algorithm review and the actual14-cell ASan draft8
receipt SHA256 `0a1415fdf4a1e577b293ec78db8af59cd5590edc5f127b81ca32f50bef2cd007`.
Inline KeyUpdate showed peer/client updates1/1 with server record sequences
[0,0,1], Ready/Empty, and A then B after A cutoff. Queued KeyUpdate showed
peer/client updates1/0 with sequence[1], Data and retirement. Full paired
certification remains conditional on the required final28-cell ASan/TSan gate.
