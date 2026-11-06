# HTTP outcomes and write effects

`execute` and `exchange` keep returning the existing `HTTP_Error`. Its existing `kind`, native transport/TLS causes and allocation diagnostics remain available. New fields add observable `phase`, `write_effect`, HTTP `status`, and a numeric `provider_code` for the legacy curl path. No URL, header, credential, token, or server response body is copied into these diagnostics.

The phases distinguish configuration, DNS, connect, TLS, write, read, protocol, body limit, deadline and cancellation. `Unknown` means the provider lacks enough information. Underlying timeout/cancellation causes override a generic I/O phase; TLS handshake and transport causes are retained. Deadline is a failure category, not a claim that the provider knows which internal stage consumed its time budget. This change does not make the existing blocking resolver/connect operations cancellable or fully deadline-bounded.

`write_effect` describes the HTTP request, not TLS handshake bytes:

- `Unknown` is the conservative zero value. A send attempt may have affected the remote operation even when no response arrived. A zero/legacy named aggregate must never imply retry safety.
- `Not_Sent` means failure occurred before attempting HTTP request bytes, such as rejected configuration, DNS/connect failure, or failed TLS authentication.
- `Response_Received` means a response status was observed. It does not establish business success, transaction commit, delivery of an email, or safety of replay. Body transfer may still fail.

Native `exchange` reports a status after validating the response head, even if body allocation, framing or transfer fails. `execute` preserves the last observed status across redirect failures; an earlier completed attempt prevents a later pre-send error from claiming the whole operation was never sent. The library adds no retries. Operation-aware callers decide whether to reconcile, retry with an idempotency mechanism, or stop; POST/PATCH/email writes must not be replayed merely because an I/O error occurred.

## Legacy buffered adapter

`Buffered_HTTP_Result.ok` retains its existing success rule. Successful responses retain their status; failed transfers now preserve an observed status where the old adapter returned zero. Added `transport_ok` means the complete response was returned successfully. For example, a completed HTTP 503 has `transport_ok = true`, `ok = false`, `status = 503`, and `error.kind = .None`. On transport/protocol/limit failures, `error` contains the typed failure and `status` retains an observed response code where available.

libcurl's response-code query works independently of transfer success. Its error codes identify DNS/connect/TLS failures and send/receive errors, but a timeout does not identify the exact stalled stage. HTTP/0.9-style malformed replies can share `CURLE_UNSUPPORTED_PROTOCOL` with local protocol rejection. A positive issued-request size can establish a response-protocol failure; absent such evidence its phase/effect remain `Unknown`. A zero counter is never used as proof that replay is safe. A callback abort from the file reader is not mislabeled as user cancellation: this adapter currently exposes no cancellation callback. Native caller-owned streams can report `net.Connection_Error.Cancelled` through `exchange`.

Sources: [curl response code](https://curl.se/libcurl/c/CURLINFO_RESPONSE_CODE.html), [request size](https://curl.se/libcurl/c/CURLINFO_REQUEST_SIZE.html), [provider error codes](https://curl.se/libcurl/c/libcurl-errors.html).

## Verification

```sh
odin test tests -thread-count:1 -warnings-as-errors \
  -define:ODIN_TEST_THREADS=1 -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true
python3 tests/outcomes_loopback.py --odin /path/to/odin --sanitize
```

The unit suite injects failures through public `exchange`, checks legacy zero/named results, classification mappings, status retention and no hidden retries. The separate loopback suite owns its servers and a bound non-listening port; it exercises native/curl resets after POST, response limits, malformed replies, timeouts, non-2xx responses and wrong-root TLS. Native DNS failure uses a process-local empty resolver file, never an external resolver. DNS/cancellation/provider ambiguities also have deterministic typed-cause fixtures. Connect attempts may be surfaced as connect failures or timeouts by the platform/provider; tests preserve the reported distinction. No live credentials, provider requests, global network settings, or unrelated processes are used.
