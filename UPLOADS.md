# Native fixed-length uploads

`execute_upload(request, source, config)` sends a request through native TCP or authenticated TLS. `exchange_upload(connection, request, source)` uses an already connected caller-owned transport. Both reuse the existing response codec, limits, HEAD handling and typed outcomes.

An `Upload_Source` borrows a `core:io.Stream` plus a signed 64-bit `content_length`. For an already opened regular file positioned at the desired starting offset:

```odin
source := surf.Upload_Source{
    stream = os.to_stream(file),
    content_length = length,
}
response, error := surf.execute_upload(request, source, config)
defer surf.response_destroy(&response)
```

The caller retains source/file ownership and closes it. Surf neither closes nor rewinds the source, and an error may leave its cursor advanced. Do not read the source concurrently. `request.body` must be empty: buffered and streaming bodies cannot be combined. Positive source lengths require a method supporting request content; PUT, POST and DELETE use the shared HTTP/1 header codec. Explicit stream lengths can exceed the buffered request-body cap without allocating a matching slice.

## Consumption and resource bounds

Exactly the declared prefix is consumed and transmitted. Extra bytes remain unread; there is no EOF probe after the declared count. A zero-length upload does not call the source. This permits file ranges and open streams without waiting for an unnecessary EOF. A source that ends early fails with `Unexpected_EOF`, phase `Write`, and `source_io = .EOF`. Invalid source counts, read failures and no progress also fail rather than spin, pad or transmit uninitialized bytes.

The request driver uses one fixed 32 KiB scratch buffer, completes each transport write before reading another chunk, and handles partial writes. It does not buffer the file or retain a producer queue. Header, response and TLS state retain their existing bounds; response buffering is independently controlled by `Config.max_body_size`. Scratch buffers, kernel socket buffers, preloaded trust roots and allocator tracking are distinct resource measurements.

The source's `io.Error` is retained in `HTTP_Error.source_io`; no file path or payload is put into errors. Failures after attempting request bytes conservatively report unknown write effect unless a validated response was observed. This API adds no retry. A short source or network failure does not establish that a remote write had no effect.

## Redirects, deadlines and cancellation

`execute_upload` rejects a nonzero `max_redirects` before source/network I/O. It never rewinds or replays a consumed source. With redirects disabled, a 3xx is returned as an ordinary response for the caller to handle explicitly.

Once connected, native transport deadlines bound socket I/O. The upload driver also checks the absolute deadline around source reads. It cannot interrupt an arbitrary synchronous source callback: readers must provide their own cooperative bounds. Caller-owned transports can report cancellation through `net.Connection_Error.Cancelled`; the error retains its cancellation category and conservative write effect. These blocking APIs do not introduce an external cancellation mechanism.

Connection establishment now uses the [bounded setup prerequisite](SETUP.md) for DNS, TCP and TLS on supported platforms. `buffered_http_execute` is that native client: a file upload sends exactly `upload_size` bytes for any HTTP/1 method, and a short file is phase `Write` with effect `Unknown`. HTTP/2 file upload follows the native method set. Consumer migration (OKAMI-134) and the parent migration (OKAMI-124) are separate from this adapter switch.

## Offline verification

```sh
odin test tests -thread-count:1 -warnings-as-errors \
  -define:ODIN_TEST_THREADS=1 -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true -sanitize:address
python3 tests/uploads_loopback.py --odin /path/to/odin --sanitize
```

The unit suite covers partial transport writes, one-chunk prefetch bounds, unread excess/no EOF probe, short/broken sources, invalid counts, no progress, preflight rejection, deadlines and cancellation. The loopback fixture generates its own test certificate, owns cleartext/TLS listeners and synthetic files, and verifies PUT/POST/DELETE, SHA-256 payloads, exact cursor positions, prefix behavior, short files, stalled-reader deadlines, no redirect replay and cleanup.

A local Darwin run transfers a 65 MiB cleartext prefix and a 2 MiB authenticated TLS prefix while keeping tracked transfer heap allocations below 4 MiB; this is a resource guard, not an RSS or throughput benchmark. Actual observed tracked peaks were 129 bytes for the large cleartext transfer and approximately 1.21 MB for TLS, excluding stack scratch, socket memory and preloaded roots. Linux execution has not been certified by that local run.
