# Owned upload and response streaming

`surf/async` exposes an opt-in pull API on the existing Client connection actors.
It requires the matching experimental Core including `18bd5dad0` (incremental
DEFLATE/gzip plus owned-length guards) and HTTP `f557430` (additive content negotiation). It creates no
blocking workers, curl calls or aggregate response-body allocation. Existing
buffered submission, response ownership, identity headers and redirects remain
unchanged. The `stream` implementation dependency is not a second public Client.

## Enable finite admission

Set `Client_Config.streaming` to `Stream_Client_Limits{}` to select defaults:

- At most eight live stream control entries, capped by request capacity.
- Two response slots and two upload slots per stream.
- 16 KiB maximum chunk payload **and full backing storage**.
- 64 KiB retained payload-bank budget per stream: 32 KiB response-slot storage
  plus at most 32 KiB accepted upload backing by default.

Nil streaming config preserves the existing initialization allocation path.
Limits are independent: count exhaustion and backing-byte exhaustion both apply.
Controls are bounded by request capacity (at most 4,096), slots by 16 per
 direction, chunks by 64 KiB and retained payload by 64 MiB per stream. Checked
normalization precedes allocation. A positive owned upload requires at least one
byte of upload credit beyond reserved response buffers.

Headers/descriptors, the fixed decoder/history state, one 16 KiB raw read and one
16 KiB encoded lookahead, connection/TLS storage and bookkeeping are separately
bounded and charged through the allocator/scope. The payload-bank limit is not a
claim about all Client memory. Caller-supplied allocator state must outlive its
returned owners, as with existing owned Responses.

## Submit, receive and destroy

`client_submit_stream(client, request, options, deadline)` returns the existing
Request_Handle. Stream_Options has `upload_length: Maybe(i64)`,
`max_encoded_bytes`, `max_decoded_bytes` and `decoding: Content_Decoding`.
Zero byte limits inherit normalized `http.max_body_size` (8 MiB by default);
explicit limits are 1..64 MiB. They count entity bytes after HTTP dechunking and
delivered bytes respectively, across all decoder calls. Limits reset per redirect
hop; the original total deadline, five-hop ceiling and resource owners do not.

`client_stream_take_head(client, handle, &head)` returns Pending until a final
head is available. Stream_Head owns a bodyless Response with the original wire
headers, `wire_content_length` (-1 when not declared) and `delivery` (`Wire` or
`Decoded_Gzip`). Wire length/coding never describe the decoded chunk length.
Destroy it with `stream_head_destroy(&head)`, including after Client/Runtime
teardown. A Head itself retains a control credit; retaining arbitrary heads
cannot evade the finite stream admission limit.

`client_stream_next(client, handle, &chunk)` returns `(Pending|Chunk|End, error)`.
Chunk moves an existing `core:mem/owned.Chunk` into an empty destination. Destroy
it with `owned.destroy(&chunk)`. Taking it does **not** return slot credit;
destruction does. Full backing remains charged. End means validated framing and
coding termination, not merely exhaustion of a currently empty queue. Pending
is not EOF. Errors are typed Client_Error/HTTP_Error, with `decoding` retaining
the exact Core Decode_Error enum for coding failures.

Both destination owners must be empty. Rejection preserves them. IO buffers and
internal metadata cannot be used as destinations. Already transferred heads and
chunks remain valid after later errors/cancellation; they are independent of the
public Client header, request slot and Runtime. Their last destructor may free
the detached bank. No late destructor dereferences a former actor or Runtime.
Do not copy an owned Head/Chunk or retain aliases after moving its owner.

A head or prefix may precede a later framing, CRC/ISIZE, EOF or limit failure.
Treat every prefix as provisional until successful End. Only buffered APIs keep
all data private and return an empty response on error. `client_take` rejects a
streaming handle instead of constructing a hidden aggregate body.

## Owned uploads and duplex responses

Some(upload_length) requires an empty request.body and a nonnegative known wire
length. Submit owned sources with `client_upload_submit(client, handle, &chunk)`.
Accepted moves/clears the whole source; Backpressure, Closed, Invalid,
Limit_Exceeded and failures preserve it. Empty sources are rejected; call
`client_upload_finish` for EOF, including zero-length uploads. Finish validates
exact accepted length. An explicit source error retains `HTTP_Error.source_io`;
underflow, overflow, deadlines and cancellation remain distinct typed outcomes.
A fresh registered-witness clock and cancellation check precede ownership moves.

Accepted upload backing remains charged while queued, throughout partial writes,
and until the accepted write callback and source destructor both retire. Source
release callbacks run outside internal locks and may reenter Client operations.
No producer memory is replayed, rewound or copied into a complete upload buffer.

With nil upload_length the normal cloned request.body path remains available
while the response streams. Only owned uploads reject automatic redirects before
admission. Response-only streaming retains the existing configured method,
credential/origin, downgrade, loop and total-deadline policy. Followed intermediate
heads/bodies stay private and are validated with the same finite limits.

Receive progress starts after the request head and continues independently of a
blocked producer/write. A valid early final response stops upload admission,
cancels/drains accepted writes and releases queued owners; incomplete uploads
prevent reuse. The response remains readable. A stalled producer/consumer still
arms the immutable total watchdog. Progress never extends that cutoff.

## Optional gzip and completion

Identity is the default and retains wire bytes. Gzip advertises `gzip, identity`
only through the additive request codec. A single gzip coding selects decoding;
absent/single identity remains Wire. Repeated, chained or unsupported codings are
rejected with Unsupported_Content_Encoding. HTTP OWS is SP/HTAB only. Original
headers are retained. HEAD/204/304 never feed a decoder or require an empty gzip
member; they preserve representation metadata and finish bodyless as Wire.

The fixed resumable decoder validates header limits/FHCRC, DEFLATE, payload CRC,
ISIZE and exact entity termination. One gzip member is accepted; trailing data or
extra members fail explicitly. Decoder calls retain no input/output borrows and
have finite work budgets. A failing call's produced bytes are never published.
When all payload slots are held, zero-output decoder progress can validate the
trailer; final chunks can therefore outlive successful network completion.

Use existing poll/cancel/release/close APIs. Early caller release requires cancel
and physical completion before request release. Queued chunks are discarded;
taken owners survive. Client destruction requires its request handles released,
but not already transferred heads/chunks. Reuse requires complete framing/coding,
finished upload, quiescent callbacks and existing TLS-idle/raw-health checks.
EOF-delimited, surplus, failed or incompletely uploaded streams retire physically.
