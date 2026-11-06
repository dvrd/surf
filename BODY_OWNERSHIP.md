# Taking ownership of a response body

`response_take_body(&response)` moves an ordinary Surf response's complete
`body_storage` allocation into a `core:mem/owned.Chunk`. It preserves the original
allocator and allocated capacity without allocating per-body metadata or copying
the payload. It clears `response.body` and `response.body_storage` only after
successful adoption. Headers stay owned by the response, so
`response_destroy(&response)` remains necessary and safe after the move.

The chunk can outlive the response but cannot outlive its allocator/pool. Do not
reset a response allocator arena until every transferred chunk has been released.
The caller can destroy the chunk or submit it to an explicitly bounded queue.
Queue rejection leaves ownership with the caller; successful admission clears it.

A manually constructed borrowed body, mismatched body view, nil response, or
invalid backing allocator returns `Invalid_Input` without changing the response.
Repeated extraction after a successful move is rejected. Both the cleared
response and cleared chunk may be destroyed repeatedly, but previously copied
aliases must never be used or separately freed.

This operation does not change Surf's existing buffered HTTP behavior, add an
asynchronous client, or integrate QUIC. It supplies the explicit ownership seam
those implementations can use. See `core/mem/owned/README.md` for release versus
acknowledgment, allocation/copy/adoption helpers, and serialized queue semantics.

Tests use Surf's real exchange path over an offline injected connection and
verify that moved bytes remain live after `response_destroy`, are freed with the
original allocator exactly once, and are preserved on failed extraction.
